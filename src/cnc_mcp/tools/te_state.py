"""Traffic-engineering state tools — SR policies, Tree-SID (P2MP) policies, RSVP-TE
tunnels and their performance metrics, read from the topology NBI.

Data source. Everything in this module is what Crosswork learned from its
**SR-PCE provider over gRPC** (the XR ``lslib-server`` / service-layer feed —
see the platform notes, "RESOLVED 2026-09-13"): the L3 topology, SR-MPLS data
and the SR policies come over that channel; RSVP-TE tunnels, Tree-SID trees
and PCEP-session data come over the PCE's HTTP/8080 leg. SR policies are
visible only while that feed is up **and** the head-end (the PCC) reports them
to the PCE — on IOS-XR that is ``segment-routing traffic-eng pcc ... report-
all``; a policy the PCC does not report is simply absent here, not an error.
L2 (``… : ETHERNET``) links, by contrast, come from LLDP device collection and
carry no performance metrics. Performance metrics are Crosswork's per-object
PM (bandwidth utilisation, delay, interface counters), refreshed on the
collection cadence — a policy that appeared a moment ago may not have a PM
entry yet.

Wire facts (verified live on Crosswork 7.2, 2026-09-13; base
:data:`cnc_mcp.restconf.TOPOLOGY_NBI` ``/data``):

- Every call is a GET with ``Accept: application/yang-data+json``.
- Keys are RESTCONF list keys and **must be fully percent-encoded** —
  :func:`cnc_mcp.restconf.encode_key` — because link ids carry spaces, ``:``
  and ``/`` (``"P2 : GigabitEthernet0/0/0/0 : PE2 : GigabitEthernet0/0/0/1 :
  ISIS_IPV4_L2"``). Multi-part keys are comma-joined:
  ``policy=<headend>,<endpoint>,<color>`` and
  ``rsvp-te-tunnel=<headend>,<endpoint>,<tunnel-id>``. ``headend`` /
  ``endpoint`` are **TE router-ids** (the loopbacks, e.g. ``10.0.0.1``), not
  host names.
- Not-found is spelled **409 ``data-missing``** (``{"errors": {"error":
  [{"error-tag": "data-missing", ...}]}}`` — the bare ``errors`` key), for a
  policy, a tunnel and a PM entry alike; :func:`cnc_mcp.restconf.is_not_found`
  recognises it, and the tools accept **only** that spelling. A **404 is never
  "no such object"** on this NBI — a plain one is a malformed (unencoded) key
  or an unrouted path (verified), and a 404 carrying a RESTCONF document (the
  NSO proxy's not-found spelling, which ``is_not_found`` also accepts) has
  never been observed here — so every 404 is left to
  :func:`cnc_mcp.errors.http_error` to explain.
- The list containers answer ``{}`` when empty (``p2mp-policies`` and
  ``rsvp-te-tunnels`` on the lab); the tools render that as a normal "none
  reported" result.
- **The PM containers cannot be listed**: an unkeyed GET on
  ``igp-links-performance-metrics`` / ``rsvp-policies-performance-metrics``
  answers 409 ``data-missing`` — only keyed reads exist, so the PM tools take
  the object key and nothing else.
- Shapes as observed (they differ from the OpenAPI documents in places):
  ``pce-controlled`` is a JSON boolean, ``update-time`` an epoch-milliseconds
  string, the PM numbers (``max-bandwidth-kbps``, ``bandwidth-utilization-kbps``,
  the ``interfaces`` counters) are strings while ``delay`` is an int, and a
  path carries its hops both as ``segment-list[].hop[]`` (with ``weight``)
  and as a flat ``hop[]``; a hop is ``{type, local-ip-addr, label}`` (the
  document's ``sid-value`` / ``local-address`` objects are tolerated too).
  The keyed policy GET answers ``{"<module>:policy": [<one entry>]}``.
- Keyed GETs are re-checked client-side on their key fields (a top-level list
  key may be ignored on this NBI — verified on ``network=<unknown>``), so an
  answer that does not carry the requested key is reported as not found. The
  re-check compares key leaves as text in both directions (:func:`key_matches`):
  ``color`` arrived as an int live, but this NBI serialises other numeric
  leaves as strings, so a ``"tunnel-id": "7"`` on the wire still matches the
  tool's ``tunnel_id=7``.
- The NBI type-checks key parts: a host name where a router-id is expected
  (``policy=PE1,PE2,100``) answers **400 ``invalid-value``** ("Invalid value
  'PE1' for (...)headend", verified live) — reported with the key rule, not
  as "not found".

Host names (added 2026-09-14, agent scenario 10). The SR policy tools here
(``cnc_list_sr_policies`` filters, ``cnc_get_sr_policy``,
``cnc_get_sr_policy_performance_metrics``) accept a **host name or a TE
router-id** for headend/endpoint, exactly as the SR-TE operations tools do,
so an agent can carry ``PE2`` through a whole create → get → delete workflow.
The resolver is THE one every SR-TE tool uses — :func:`find_node` /
:func:`select_router_id` / :func:`fetch_topology_nodes` live in this module
(the read side, which :mod:`cnc_mcp.tools.sr_te_operations` imports) so there
is exactly one implementation and no import cycle. An IP literal goes on the
wire as given (no topology read — the fast path every existing caller took);
anything else is looked up in the topology's ``networks`` collection (one
GET) and refused client-side with "no node 'X' in the topology" when unknown,
before any NBI call. The RSVP-TE tunnel tools still take router-ids only
(nothing was available live to verify them with). The nodes read for that
resolution double as the router-id -> host name map (:func:`router_id_names`
— a topology node carries both ``node-id`` = host name and its router-ids, so
no inventory call is needed), and the SR policy headers / rows then read
``PE2 (10.0.0.3) -> PE1 (10.0.0.1) color 100`` (agent findings round 2, 2026-
09-14: with the names as inputs the tools still printed router-ids only, and
the agent kept its own name map). No request is made just to decorate a
router-id-only call.

Origin vs delegation (agent scenario 3). Two independent flags describe an SR
policy: ``policy-details.pcep-info.pcep-flag-c`` says WHO INSTANTIATED it
(1 = PCE-initiated, e.g. by cnc_create_sr_policy; 0 = PCC-initiated, i.e.
configured on the head-end router) and ``policy-details.pce-controlled`` says
whether it is DELEGATED to the PCE for (re)optimisation. The lab's colour-100
policies are ``pcep-flag-c 0`` + ``pce-controlled true``: router-configured
policies delegated to the PCE (verified live). The renderers spell this out
as ``origin=`` so agents do not have to infer it.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.client import ApiClient
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, epoch_iso, finalize, to_json
from cnc_mcp.restconf import (
    TOPOLOGY_NBI,
    YANG_ACCEPT,
    encode_key,
    is_not_found,
    parse_restconf_errors,
    unwrap_list,
)
from cnc_mcp.safety import AppContext, register_tool
from cnc_mcp.tools.topology import (
    DEFAULT_NETWORK,
    NETWORK_MODULE,
    NETWORKS_URL,
    network_id_of,
    network_nodes,
    node_id_of,
    node_l3,
    router_ids,
    select_by_field,
)

TE_DATA = f"{TOPOLOGY_NBI}/data"

SR_POLICY_MODULE = "cisco-crosswork-segment-routing-policy"
SR_POLICIES_URL = f"{TE_DATA}/{SR_POLICY_MODULE}:sr-policies"
P2MP_MODULE = "cisco-crosswork-segment-routing-p2mp-policy"
P2MP_POLICIES_URL = f"{TE_DATA}/{P2MP_MODULE}:p2mp-policies"
RSVP_MODULE = "cisco-crosswork-rsvp-te-tunnel"
RSVP_TUNNELS_URL = f"{TE_DATA}/{RSVP_MODULE}:rsvp-te-tunnels"
PM_MODULE = "cisco-crosswork-performance-metrics"
IGP_LINK_PM_URL = f"{TE_DATA}/{PM_MODULE}:igp-links-performance-metrics/igp-link-pm"
SR_POLICY_PM_URL = f"{TE_DATA}/{PM_MODULE}:sr-policies-performance-metrics/sr-policy-pm"
RSVP_PM_URL = f"{TE_DATA}/{PM_MODULE}:rsvp-policies-performance-metrics/rsvp-policy-pm"

OPER_STATES = ("UP", "DOWN")
TAG_INVALID_VALUE = "invalid-value"  # 400: a key part of the wrong YANG type (verified live)

_KEY_RULE = (
    "Keys are (headend, endpoint, color) with headend/endpoint the TE router-ids (the "
    "loopbacks, e.g. 10.0.0.1) on the wire, not host names — a host name given to the tool "
    "is resolved to its router-id through the topology first"
)
_FEED_RULE = (
    "a policy is visible only while the SR-PCE gRPC feed is up and the head-end PCC "
    "reports it to the PCE (IOS-XR 'segment-routing traffic-eng pcc ... report-all')"
)
_ORIGIN_RULE = (
    "origin comes from pcep-info.pcep-flag-c (1 = PCE-initiated, e.g. by "
    "cnc_create_sr_policy; 0 = PCC-initiated, configured on the head-end router) and "
    "pce-controlled = delegated to the PCE for (re)optimisation — PCC-initiated + "
    "pce-controlled is a router-configured policy delegated to the PCE"
)
_RESPONSE_FORMAT_DESC = "'markdown' for human-readable output, 'json' for the raw platform data."
# RSVP-TE tunnel tools: router-ids only (no tunnel was available live to verify names with).
_HEADEND_DESC = (
    "Head-end TE router-id — the loopback address the PCE knows the node by (e.g. "
    "'10.0.0.1'), NOT the host name."
)
_ENDPOINT_DESC = "Tail-end TE router-id, the policy's endpoint loopback (e.g. '10.0.0.3')."
# SR policy tools: host name or router-id (resolved through the topology, as sr_te_operations).
_NODE_HELP = (
    "a host name (the topology node id, case-insensitive, e.g. 'PE1') or its TE router-id "
    "(the loopback, e.g. '10.0.0.1')"
)
_SR_HEADEND_DESC = (
    f"Head-end of the policy: {_NODE_HELP}. A host name is resolved through the topology; a "
    "router-id is used as given (the key on the wire is always the router-id)."
)
_SR_ENDPOINT_DESC = f"Endpoint (tail-end) of the policy: {_NODE_HELP}; e.g. 'PE2' or '10.0.0.3'."
_NETWORK_DESC = (
    f"Topology network id host names are resolved against (e.g. '{DEFAULT_NETWORK}', the "
    "only network on a standard deployment). Not read when every name is a router-id."
)


# --- URL builders (every key through encode_key) ---------------------------------


def sr_policy_url(headend: str, endpoint: str, color: int) -> str:
    """``.../sr-policies/policy=<headend>,<endpoint>,<color>`` (each part percent-encoded)."""
    return f"{SR_POLICIES_URL}/policy={encode_key(headend, endpoint, color)}"


def p2mp_policy_url(name: str) -> str:
    """``.../p2mp-policies/p2mp-policy=<name>`` (name percent-encoded as one key)."""
    return f"{P2MP_POLICIES_URL}/p2mp-policy={encode_key(name)}"


def rsvp_tunnel_url(headend: str, endpoint: str, tunnel_id: int) -> str:
    """``.../rsvp-te-tunnels/rsvp-te-tunnel=<headend>,<endpoint>,<tunnel-id>``."""
    return f"{RSVP_TUNNELS_URL}/rsvp-te-tunnel={encode_key(headend, endpoint, tunnel_id)}"


def igp_link_pm_url(link_id: str) -> str:
    """``.../igp-links-performance-metrics/igp-link-pm=<link-id>`` — spaces, ':' and '/' encoded."""
    return f"{IGP_LINK_PM_URL}={encode_key(link_id)}"


def sr_policy_pm_url(headend: str, endpoint: str, color: int) -> str:
    """``.../sr-policies-performance-metrics/sr-policy-pm=<headend>,<endpoint>,<color>``."""
    return f"{SR_POLICY_PM_URL}={encode_key(headend, endpoint, color)}"


def rsvp_pm_url(headend: str, endpoint: str, tunnel_id: int) -> str:
    """``.../rsvp-policies-performance-metrics/rsvp-policy-pm=<headend>,<endpoint>,<tunnel-id>``."""
    return f"{RSVP_PM_URL}={encode_key(headend, endpoint, tunnel_id)}"


# --- pure helpers ----------------------------------------------------------------


def as_bool(value: Any) -> bool | None:
    """Coerce a YANG boolean that may arrive as JSON bool or as a string.

    ``pce-controlled`` is a JSON ``true`` live while the OpenAPI document types
    it as a string; both spellings (and ``1``/``0``) are accepted. Returns
    ``None`` when the value is absent or unrecognisable so a filter never
    matches on a guess.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("true", "yes", "1"):
            return True
        if text in ("false", "no", "0"):
            return False
    return None


def normalize_oper_state(value: str | None) -> str | None:
    """``'up'`` -> ``'UP'``; ``None``/blank -> ``None``; PlatformError for anything else."""
    if value is None:
        return None
    text = value.strip().upper()
    if not text:
        return None
    if text not in OPER_STATES:
        raise PlatformError(
            f"oper_state must be one of {', '.join(OPER_STATES)} (case-insensitive), got '{value}'."
        )
    return text


def is_invalid_key(status: int, data: Any) -> bool:
    """True for the NBI's 400 ``invalid-value``: a key part failed its YANG type check.

    Verified live: ``policy=PE1,PE2,100`` (host names where ``inet:ip-address``
    router-ids are expected) answers 400 with error-tag ``invalid-value`` and
    the message "Invalid value 'PE1' for (...)headend". It is neither "not
    found" nor a malformed URL, so the get tools explain the key rule instead.
    """
    if status != 400:
        return False
    return any((e["tag"] or "").lower() == TAG_INVALID_VALUE for e in parse_restconf_errors(data))


def _int_or(value: Any, default: int = -1) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# --- name -> router-id resolution (shared with sr_te_operations) -------------------


def is_ip_address(text: str) -> bool:
    """True for an IPv4/IPv6 literal — a value that goes on the wire as a key without lookup."""
    try:
        ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    return True


def _is_ipv4(text: str) -> bool:
    try:
        return ipaddress.ip_address(text.strip()).version == 4
    except ValueError:
        return False


def find_node(nodes: list[dict[str, Any]], name_or_ip: str) -> dict[str, Any]:
    """The topology ``node`` entry for a node id (case-insensitive) or one of its router-ids.

    An exact node id wins, then a case-insensitive one, then a router-id
    match (``l3-node-attributes.router-id[]``). PlatformError, with the
    naming rule and the listing tool, when nothing matches.
    """
    key = name_or_ip.strip()
    if not key:
        raise PlatformError(f"node name is empty: give {_NODE_HELP}.")
    for node in nodes:
        if node_id_of(node) == key:
            return node
    lowered = key.lower()
    for node in nodes:
        if node_id_of(node).lower() == lowered:
            return node
    for node in nodes:
        if key in router_ids(node_l3(node)):
            return node
    raise PlatformError(
        f"no node '{key}' in the topology (node ids are inventory host names; router-ids are "
        "TE loopbacks) — list with cnc_list_topology_nodes"
    )


def select_router_id(ids: list[str], name_or_ip: str) -> str | None:
    """The router-id to put on the wire for a node with ``router-id`` entries ``ids``.

    ``router-id`` is a leaf-list, so a node may carry several (an IPv6 one
    first is possible). The RPC fields are ``node-ipv4-*`` / ``head-end`` in
    IPv4 form, so: the input itself when it is one of the node's router-ids
    (the caller named that address explicitly), else the first IPv4 router-id,
    else the first entry; ``None`` when the node has none.
    """
    key = name_or_ip.strip()
    if key in ids:
        return key
    for candidate in ids:
        if _is_ipv4(candidate):
            return candidate
    return ids[0] if ids else None


def node_router_id(nodes: list[dict[str, Any]], name_or_ip: str) -> str:
    """A host name or router-id -> the TE router-id on the wire; PlatformError when unknown.

    :func:`find_node` then :func:`select_router_id`. A node the topology lists
    without a router-id (an LLDP-only node, or the SR-PCE feed being down)
    cannot key an SR policy and is refused with that explanation.
    """
    node = find_node(nodes, name_or_ip)
    router_id = select_router_id(router_ids(node_l3(node)), name_or_ip)
    if router_id is None:
        raise PlatformError(
            f"node '{node_id_of(node)}' has no TE router-id in the topology: the SR-PCE gRPC "
            "feed may be down, or the node advertises no segment routing — check "
            "cnc_list_providers (SR-PCE) and cnc_get_topology_node."
        )
    return router_id


async def fetch_topology_nodes(client: ApiClient, network: str) -> list[dict[str, Any]]:
    """The ``node`` entries of one network, from the ``networks`` COLLECTION GET.

    The collection is fetched and the network selected client-side because
    the keyed ``network=<id>`` GET is shallow (no SR data — verified) and an
    unknown key answers the whole list. An empty container or a network
    without nodes is an error here: there is nothing to resolve a name
    against (and the Optimization Engine would answer every unresolved name
    with its ambiguous empty 500).
    """
    key = network.strip() or DEFAULT_NETWORK
    data = await client.request_json("GET", NETWORKS_URL, headers=YANG_ACCEPT)
    networks = unwrap_list(data, NETWORK_MODULE, "network")
    matches = select_by_field(networks, "network-id", key)
    if matches:
        nodes = network_nodes(matches[0])
        if nodes:
            return nodes
        raise PlatformError(
            f"the topology network '{key}' has no nodes yet, so no node name can be resolved. "
            "Nodes appear once devices are onboarded and the SR-PCE gRPC feed is up "
            "(cnc_get_topology_summary)."
        )
    present = [network_id_of(n) for n in networks if isinstance(n, dict)]
    if present:
        raise PlatformError(
            f"no network '{key}' on the topology NBI. Networks present: "
            f"{', '.join(present)}. The default is '{DEFAULT_NETWORK}'."
        )
    raise PlatformError(
        "the topology NBI reports no networks yet, so no node name can be resolved. The "
        "networks container is populated once devices are onboarded and the SR-PCE gRPC feed "
        "is up (cnc_get_topology_summary, cnc_list_providers)."
    )


async def resolve_router_ids_and_nodes(
    client: ApiClient, network: str, *names: str | None
) -> tuple[list[str | None], list[dict[str, Any]] | None]:
    """Each name -> its TE router-id, plus the topology nodes read to resolve them.

    ``None`` and IP literals pass through untouched. The topology is read at
    most once, and only when some name is not an IP literal — so a caller
    passing router-ids (the form every key uses on the wire) costs no extra
    request, exactly as before host names were accepted; the nodes are then
    ``None``. When it WAS read, the nodes come back too, so the caller can
    render host names next to router-ids (:func:`router_id_names`) without
    a second request. A host name that is unknown, or a node without a
    router-id, raises PlatformError (:func:`node_router_id`) before anything
    else is sent.
    """
    cleaned = [name.strip() if isinstance(name, str) and name.strip() else None for name in names]
    if all(value is None or is_ip_address(value) for value in cleaned):
        return cleaned, None
    nodes = await fetch_topology_nodes(client, network)
    resolved = [
        value if value is None or is_ip_address(value) else node_router_id(nodes, value)
        for value in cleaned
    ]
    return resolved, nodes


async def resolve_router_ids(
    client: ApiClient, network: str, *names: str | None
) -> list[str | None]:
    """Each name -> its TE router-id (:func:`resolve_router_ids_and_nodes` without the nodes)."""
    resolved, _nodes = await resolve_router_ids_and_nodes(client, network, *names)
    return resolved


async def resolve_policy_ends(
    client: ApiClient, network: str, headend: str, endpoint: str
) -> tuple[str, str, dict[str, str]]:
    """``(headend router-id, endpoint router-id, router-id -> host name)`` for a policy key.

    Blank names are refused before anything is read. The name map is built
    from the topology nodes the resolution read (:func:`router_id_names`);
    it is empty when both ends were router-ids (no topology read — the fast
    path), so the labels then show router-ids only.
    """
    if not headend.strip() or not endpoint.strip():
        raise PlatformError(f"headend and endpoint must not be blank: give {_NODE_HELP}.")
    (head, end), nodes = await resolve_router_ids_and_nodes(client, network, headend, endpoint)
    return str(head), str(end), router_id_names(nodes)


def router_id_names(nodes: list[dict[str, Any]] | None) -> dict[str, str]:
    """``{router-id: node-id}`` for every topology node carrying router-ids.

    The topology node record already carries both spellings — ``node-id`` is
    the inventory host name and ``l3-node-attributes.router-id[]`` the TE
    loopbacks — so a name map costs no inventory call. ``{}`` for ``None``
    (no topology was read) or nodes without SR data.
    """
    names: dict[str, str] = {}
    for node in nodes or []:
        name = node_id_of(node)
        if not name or name == "?":
            continue
        for router_id in router_ids(node_l3(node)):
            names.setdefault(str(router_id), name)
    return names


def node_text(router_id: Any, names: dict[str, str] | None = None) -> str:
    """``PE2 (10.0.0.3)`` when the router-id's host name is known, else the router-id alone."""
    text = "?" if router_id is None else str(router_id)
    name = (names or {}).get(text)
    if name and name.lower() != text.lower():
        return f"{name} ({text})"
    return text


def end_label(given: str, router_id: str, names: dict[str, str] | None = None) -> str:
    """``PE2 (10.0.0.3)`` when the host name is known, else the router-id alone.

    The topology's own node id wins (:func:`node_text`, exact spelling for
    cnc_get_topology_node); without a name map the spelling the caller gave
    is used, so a resolved host name still shows next to its router-id.
    """
    if names and router_id in names:
        return node_text(router_id, names)
    if given.strip().lower() != router_id.lower():
        return f"{given.strip()} ({router_id})"
    return router_id


def _scalar(value: Any) -> Any:
    """The single meaningful value inside a one-field wrapper object (or the value itself).

    The OpenAPI document types a hop's ``sid-value`` / ``local-address`` as
    objects; the live feed sends flat ``label`` / ``local-ip-addr`` leaves.
    """
    if isinstance(value, dict):
        for inner in value.values():
            if inner not in (None, "", {}, []):
                return inner
        return None
    return value


def _compact(value: Any) -> str:
    """A scalar as text; a dict/list as compact JSON — for one-line ``k=v`` renderings."""
    if isinstance(value, dict | list):
        return json.dumps(value, separators=(",", ":"), default=str)
    if value is None:
        return "-"
    return str(value)


def kv_text(data: Any) -> str:
    """``k=v k2=v2`` for a dict (nested values as compact JSON); '-' when empty/not a dict."""
    if not isinstance(data, dict) or not data:
        return "-"
    return " ".join(f"{k}={_compact(v)}" for k, v in data.items())


def _leftover(data: dict[str, Any], rendered: tuple[str, ...]) -> dict[str, Any]:
    """Keys of ``data`` the markdown did not render (so nothing is silently dropped)."""
    return {k: v for k, v in data.items() if k not in rendered}


def hop_text(hop: Any) -> str:
    """``<label>(<type>/<local-ip-addr>)`` for one segment/hop, tolerant of both shapes."""
    if not isinstance(hop, dict):
        return str(hop)
    label = hop.get("label", _scalar(hop.get("sid-value")))
    local = hop.get("local-ip-addr") or _scalar(hop.get("local-address"))
    remote = hop.get("remote-ip-addr") or _scalar(hop.get("remote-address"))
    text = f"{label if label is not None else '?'}({hop.get('type') or '?'}/{local or '?'}"
    if remote:
        text += f"->{remote}"
    text += ")"
    if as_bool(hop.get("protected-flag")):
        text += "[protected]"
    return text


def hops_text(hops: Any) -> str:
    if not isinstance(hops, list) or not hops:
        return "-"
    return " > ".join(hop_text(h) for h in hops)


def path_hops(path: dict[str, Any]) -> list[Any]:
    """The hop list of a path: the flat ``hop[]`` when present, else the first segment-list's."""
    hops = path.get("hop")
    if isinstance(hops, list) and hops:
        return hops
    segment_lists = path.get("segment-list")
    if isinstance(segment_lists, list):
        for segment_list in segment_lists:
            if isinstance(segment_list, dict) and isinstance(segment_list.get("hop"), list):
                return segment_list["hop"]
    return []


def policy_paths(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """The ``policy-details.path`` list of an SR policy (``[]`` when absent)."""
    details = policy.get("policy-details")
    if not isinstance(details, dict):
        return []
    paths = details.get("path")
    if not isinstance(paths, list):
        return []
    return [p for p in paths if isinstance(p, dict)]


def active_path(paths: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The path with ``oper-state`` UP and the highest ``preference``; else the first path.

    Crosswork lists every candidate path of a policy; the one carrying traffic
    is the operationally-UP path of highest preference. A policy with no UP
    path falls back to its first listed path so the summary line still shows
    what the head-end configured.
    """
    up = [p for p in paths if str(p.get("oper-state") or "").upper() == "UP"]
    if up:
        return max(up, key=lambda p: _int_or(p.get("preference")))
    return paths[0] if paths else None


def policy_details(policy: dict[str, Any]) -> dict[str, Any]:
    details = policy.get("policy-details")
    return details if isinstance(details, dict) else {}


def pcep_flag_c(policy: dict[str, Any]) -> int | None:
    """``policy-details.pcep-info.pcep-flag-c`` as an int (1 = PCE-initiated, 0 = PCC-initiated).

    ``None`` when the policy carries no PCEP info at all.
    """
    info = policy_details(policy).get("pcep-info")
    if not isinstance(info, dict):
        return None
    return _int_or_none(info.get("pcep-flag-c"))


def policy_origin(policy: dict[str, Any]) -> str:
    """``PCE-initiated`` / ``PCC-initiated`` / ``unknown`` from ``pcep-flag-c`` (1 / 0 / absent).

    Who instantiated the policy — independent of ``pce-controlled``, which
    says whether it is delegated to the PCE. Verified live: a policy created
    through cnc_create_sr_policy carries ``pcep-flag-c 1``; the lab's
    router-configured colour-100 policies carry ``0`` (and ``pce-controlled
    true`` — delegated).
    """
    flag = pcep_flag_c(policy)
    if flag == 1:
        return "PCE-initiated"
    if flag == 0:
        return "PCC-initiated"
    return "unknown"


def policy_origin_line(policy: dict[str, Any]) -> str:
    """The get view's ``- origin: ...`` line — origin and delegation in words."""
    flag = pcep_flag_c(policy)
    if flag == 1:
        origin = "PCE-initiated (pcep-flag-c 1: instantiated by the SR-PCE over PCEP)"
    elif flag == 0:
        origin = "PCC-initiated (pcep-flag-c 0: configured on the head-end router)"
    else:
        origin = "unknown (no pcep-flag-c reported)"
    delegated = as_bool(policy_details(policy).get("pce-controlled"))
    if delegated is True:
        control = "delegated to the PCE for (re)optimisation (pce-controlled true)"
    elif delegated is False:
        control = "not delegated to the PCE (pce-controlled false)"
    else:
        control = "delegation unknown (no pce-controlled reported)"
    line = f"- origin: {origin}; {control}"
    if flag == 0 and delegated is True:
        line += " — a router-configured policy the PCE may re-optimise"
    return line


def policy_key_text(policy: dict[str, Any], names: dict[str, str] | None = None) -> str:
    """``PE2 (10.0.0.3) -> PE1 (10.0.0.1) color 100`` with a name map, else router-ids only."""
    return (
        f"{node_text(policy.get('headend'), names)} -> {node_text(policy.get('endpoint'), names)} "
        f"color {policy.get('color', '?')}"
    )


def matches_policy_filter(
    policy: dict[str, Any],
    *,
    headend: str | None,
    endpoint: str | None,
    color: int | None,
    oper_state: str | None,
    pce_controlled: bool | None,
) -> bool:
    """Client-side filter for cnc_list_sr_policies (the NBI has no server-side filter).

    headend/endpoint are exact (case-insensitive) matches on the TE router-id;
    color is numeric (int or numeric string on the wire); oper_state compares
    upper-cased; pce_controlled compares through :func:`as_bool`.
    """
    if headend is not None and str(policy.get("headend") or "").lower() != headend.lower():
        return False
    if endpoint is not None and str(policy.get("endpoint") or "").lower() != endpoint.lower():
        return False
    if color is not None and _int_or(policy.get("color")) != color:
        return False
    if oper_state is not None and str(policy.get("oper-state") or "").upper() != oper_state:
        return False
    if pce_controlled is not None:
        if as_bool(policy_details(policy).get("pce-controlled")) is not pce_controlled:
            return False
    return True


def key_matches(stored: Any, wanted: Any) -> bool:
    """True when a key leaf on the wire equals the requested key, int/str tolerant both ways.

    The comparison is on the text form of both sides: ``color`` arrived as a
    JSON int live while the tool argument may be a numeric string, and this
    NBI verifiably serialises other numeric leaves as strings
    (``update-time``, ``max-bandwidth-kbps``), so a stringified ``tunnel-id``
    / ``color`` against the tool's int argument must match too (only
    :func:`cnc_mcp.restconf.select_key` — one direction — did not). An absent
    leaf never matches. Text matching is exact and case-sensitive.
    """
    if stored is None:
        return False
    return stored == wanted or str(stored) == str(wanted)


def entries_matching(items: list[Any], keys: dict[str, Any]) -> list[dict[str, Any]]:
    """Client-side key check for a keyed GET: every key field must :func:`key_matches`.

    Non-dict entries are dropped; an entry missing any key field never matches.
    """
    return [
        item
        for item in items
        if isinstance(item, dict)
        and all(key_matches(item.get(field), value) for field, value in keys.items())
    ]


def sr_policy_summary(policies: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts for cnc_get_te_summary: total / up / down / pce_controlled / by_type."""
    up = down = pce = 0
    by_type: dict[str, int] = {}
    down_keys: list[str] = []
    for policy in policies:
        state = str(policy.get("oper-state") or "").upper()
        if state == "UP":
            up += 1
        elif state == "DOWN":
            down += 1
            down_keys.append(policy_key_text(policy))
        if as_bool(policy_details(policy).get("pce-controlled")):
            pce += 1
        kind = str(policy.get("sr-policy-type") or "UNKNOWN")
        by_type[kind] = by_type.get(kind, 0) + 1
    return {
        "total": len(policies),
        "up": up,
        "down": down,
        "pce_controlled": pce,
        "by_type": by_type,
        "down_policies": down_keys,
    }


# --- markdown renderers ----------------------------------------------------------

_POLICY_KEYS = (
    "headend",
    "endpoint",
    "color",
    "description",
    "admin-state",
    "oper-state",
    "sr-policy-type",
    "policy-protection-status",
    "policy-details",
)
_POLICY_DETAIL_KEYS = (
    "binding-sid",
    "srv6-binding-sid",
    "msd",
    "pce-controlled",
    "delegated-pce",
    "sub-delegated-pce",
    "pcc-address",
    "non-delegated-pces",
    "pcep-info",
    "update-time",
    "path",
)
_PATH_KEYS = (
    "path-name",
    "path-type",
    "preference",
    "oper-state",
    "optimization-metric",
    "constraints",
    "computed-time",
    "profile-id",
    "segment-list",
    "hop",
)


def _metric_text(path: dict[str, Any]) -> str:
    metric = path.get("optimization-metric")
    if not isinstance(metric, dict):
        return "-"
    return f"{metric.get('metric-type', '?')}:{metric.get('metric-value', '?')}"


def sr_policy_line(policy: dict[str, Any], names: dict[str, str] | None = None) -> str:
    """One markdown line per SR policy (the list view); ``names`` adds host names to the key."""
    details = policy_details(policy)
    paths = policy_paths(policy)
    head = (
        f"- **{policy_key_text(policy, names)}** admin={policy.get('admin-state', '?')} "
        f"oper={policy.get('oper-state', '?')} type={policy.get('sr-policy-type', '?')} "
        f"bsid={details.get('binding-sid', '-')} origin={policy_origin(policy)} "
        f"pce-controlled={as_bool(details.get('pce-controlled'))} "
        f"pcc={details.get('pcc-address', '-')}"
    )
    path = active_path(paths)
    if path is None:
        tail = "no path reported"
    else:
        tail = (
            f"active path: {path.get('path-name', '?')} pref={path.get('preference', '-')} "
            f"{path.get('path-type', '?')} metric={_metric_text(path)} "
            f"hops={hops_text(path_hops(path))}"
        )
        if len(paths) > 1:
            tail += f" (+{len(paths) - 1} more path(s))"
    return f"{head} | {tail} updated={epoch_iso(details.get('update-time'))}"


def _path_lines(path: dict[str, Any]) -> list[str]:
    lines = [
        f"- **{path.get('path-name', '?')}** pref={path.get('preference', '-')} "
        f"{path.get('path-type', '?')} oper={path.get('oper-state', '?')} "
        f"metric={_metric_text(path)} computed={epoch_iso(path.get('computed-time'))}"
        + (f" profile-id={path['profile-id']}" if path.get("profile-id") is not None else "")
    ]
    lines.append(f"  constraints: {kv_text(path.get('constraints'))}")
    segment_lists = path.get("segment-list")
    if isinstance(segment_lists, list) and segment_lists:
        for index, segment_list in enumerate(segment_lists, start=1):
            if not isinstance(segment_list, dict):
                continue
            lines.append(
                f"  segment-list {index} (weight {segment_list.get('weight', '-')}): "
                f"{hops_text(segment_list.get('hop'))}"
            )
    else:
        lines.append(f"  hops: {hops_text(path.get('hop'))}")
    other = _leftover(path, _PATH_KEYS)
    if other:
        lines.append(f"  other: {kv_text(other)}")
    return lines


def sr_policy_markdown(policy: dict[str, Any], names: dict[str, str] | None = None) -> str:
    """The full markdown for one SR policy; ``names`` adds host names to the header key."""
    details = policy_details(policy)
    lines = [
        f"# SR policy {policy_key_text(policy, names)}",
        "",
        f"- admin-state={policy.get('admin-state', '?')} "
        f"oper-state={policy.get('oper-state', '?')} type={policy.get('sr-policy-type', '?')} "
        f"description={policy.get('description') or '-'}",
        f"- binding-sid={details.get('binding-sid', '-')} "
        f"pce-controlled={as_bool(details.get('pce-controlled'))} "
        f"pcc-address={details.get('pcc-address', '-')} "
        f"delegated-pce={details.get('delegated-pce', '-')} msd={details.get('msd', '-')} "
        f"updated={epoch_iso(details.get('update-time'))}",
        f"- pcep-info: {kv_text(details.get('pcep-info'))}",
        policy_origin_line(policy),
    ]
    if policy.get("policy-protection-status"):
        lines.append(f"- protection-status: {kv_text(policy['policy-protection-status'])}")
    if details.get("srv6-binding-sid"):
        lines.append(f"- srv6-binding-sid: {kv_text(details['srv6-binding-sid'])}")
    if details.get("non-delegated-pces"):
        lines.append(f"- non-delegated-pces: {_compact(details['non-delegated-pces'])}")
    other = {
        **_leftover(policy, _POLICY_KEYS),
        **_leftover(details, _POLICY_DETAIL_KEYS),
    }
    if other:
        lines.append(f"- other: {kv_text(other)}")
    paths = policy_paths(policy)
    lines.extend(["", f"Paths ({len(paths)}):"])
    if not paths:
        lines.append("- (no path reported)")
    for path in paths:
        lines.extend(_path_lines(path))
    return "\n".join(lines)


_P2MP_KEYS = (
    "name",
    "root-address",
    "pcc-address",
    "pce-address",
    "initiation-type",
    "admin-state",
    "oper-state",
    "tree-id",
    "destination",
    "candidate-path",
)
_P2MP_PATH_KEYS = (
    "name",
    "oper-state",
    "path-type",
    "label",
    "metric-type",
    "preference",
    "programming-state",
    "path-constraints",
    "p2mp-node",
)


def _p2mp_destinations(policy: dict[str, Any]) -> list[str]:
    destinations = policy.get("destination")
    if not isinstance(destinations, list):
        return []
    out = []
    for entry in destinations:
        if isinstance(entry, dict):
            out.append(str(entry.get("destination-address", "?")))
        else:
            out.append(str(entry))
    return out


def _p2mp_paths(policy: dict[str, Any]) -> list[dict[str, Any]]:
    paths = policy.get("candidate-path")
    if not isinstance(paths, list):
        return []
    return [p for p in paths if isinstance(p, dict)]


def p2mp_policy_line(policy: dict[str, Any]) -> str:
    destinations = _p2mp_destinations(policy)
    line = (
        f"- **{policy.get('name', '?')}** root={policy.get('root-address', '-')} "
        f"tree-id={policy.get('tree-id', '-')} admin={policy.get('admin-state', '?')} "
        f"oper={policy.get('oper-state', '?')} initiation={policy.get('initiation-type', '-')} "
        f"pcc={policy.get('pcc-address', '-')} pce={policy.get('pce-address', '-')} "
        f"destinations={len(destinations)}"
    )
    if destinations:
        line += f" [{', '.join(destinations)}]"
    line += f" candidate-paths={len(_p2mp_paths(policy))}"
    other = _leftover(policy, _P2MP_KEYS)
    if other:
        line += f" other={_compact(other)}"
    return line


def _next_hop_text(hop: Any) -> str:
    if not isinstance(hop, dict):
        return str(hop)
    text = f"{hop.get('local-address', '?')}->{hop.get('remote-address', '?')}"
    text += f" label={hop.get('label', '-')}"
    if hop.get("next-hop-node-name") or hop.get("next-hop-node-address"):
        text += (
            f" to {hop.get('next-hop-node-name') or '?'}({hop.get('next-hop-node-address') or '?'})"
        )
    return text


def p2mp_policy_markdown(policy: dict[str, Any]) -> str:
    lines = [f"# P2MP (Tree-SID) policy {policy.get('name', '?')}", "", p2mp_policy_line(policy)]
    paths = _p2mp_paths(policy)
    lines.extend(["", f"Candidate paths ({len(paths)}):"])
    if not paths:
        lines.append("- (no candidate path reported)")
    for path in paths:
        lines.append(
            f"- **{path.get('name') or '(unnamed)'}** {path.get('path-type', '?')} "
            f"oper={path.get('oper-state', '?')} label={path.get('label', '-')} "
            f"metric={path.get('metric-type', '-')} pref={path.get('preference', '-')} "
            f"programming={path.get('programming-state', '-')}"
        )
        lines.append(f"  constraints: {kv_text(path.get('path-constraints'))}")
        nodes = path.get("p2mp-node")
        nodes = [n for n in nodes if isinstance(n, dict)] if isinstance(nodes, list) else []
        lines.append(f"  nodes ({len(nodes)}):")
        for node in nodes:
            next_hops = node.get("next-hop")
            hops = (
                "; ".join(_next_hop_text(h) for h in next_hops)
                if isinstance(next_hops, list) and next_hops
                else "-"
            )
            lines.append(
                f"  - {node.get('hostname', '?')} ({node.get('node-ip-address', '-')}) "
                f"role={node.get('role', '?')} next-hops: {hops}"
            )
        other = _leftover(path, _P2MP_PATH_KEYS)
        if other:
            lines.append(f"  other: {kv_text(other)}")
    return "\n".join(lines)


_RSVP_KEYS = (
    "headend",
    "endpoint",
    "tunnel-id",
    "description",
    "admin-state",
    "oper-state",
    "rsvp-te-tunnel-type",
    "tunnel-details",
)
_RSVP_DETAIL_KEYS = (
    "binding-label",
    "signaled-bandwidth-mbps",
    "setup-priority",
    "hold-priority",
    "pce-controlled",
    "delegated-pce",
    "sub-delegated-pce",
    "pcc-address",
    "non-delegated-pces",
    "pcep-info",
    "update-time",
    "path",
)
_RSVP_PATH_KEYS = (
    "path-name",
    "path-type",
    "path-oper-state",
    "optimization-metric",
    "constraints",
    "computed-time",
    "ero-hop",
    "rro-hop",
)


def tunnel_key_text(tunnel: dict[str, Any]) -> str:
    return (
        f"{tunnel.get('headend', '?')} -> {tunnel.get('endpoint', '?')} "
        f"tunnel-id {tunnel.get('tunnel-id', '?')}"
    )


def tunnel_details(tunnel: dict[str, Any]) -> dict[str, Any]:
    details = tunnel.get("tunnel-details")
    return details if isinstance(details, dict) else {}


def tunnel_paths(tunnel: dict[str, Any]) -> list[dict[str, Any]]:
    paths = tunnel_details(tunnel).get("path")
    if not isinstance(paths, list):
        return []
    return [p for p in paths if isinstance(p, dict)]


def active_tunnel_path(paths: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The ACTIVE path, else an UP one, else the first (RSVP paths have no preference)."""
    for wanted in ("ACTIVE", "UP"):
        for path in paths:
            if str(path.get("path-oper-state") or "").upper() == wanted:
                return path
    return paths[0] if paths else None


def _te_hop_text(hop: Any) -> str:
    if not isinstance(hop, dict):
        return str(hop)
    text = f"{hop.get('node-id') or hop.get('ip-address') or '?'}"
    if hop.get("node-id") and hop.get("ip-address"):
        text += f"({hop['ip-address']})"
    if hop.get("interface-name"):
        text += f"/{hop['interface-name']}"
    if hop.get("te-hop-type"):
        text += f"[{hop['te-hop-type']}]"
    return text


def _te_hops_text(hops: Any) -> str:
    if not isinstance(hops, list) or not hops:
        return "-"
    return " > ".join(_te_hop_text(h) for h in hops)


def rsvp_tunnel_line(tunnel: dict[str, Any]) -> str:
    details = tunnel_details(tunnel)
    paths = tunnel_paths(tunnel)
    head = (
        f"- **{tunnel_key_text(tunnel)}** admin={tunnel.get('admin-state', '?')} "
        f"oper={tunnel.get('oper-state', '?')} type={tunnel.get('rsvp-te-tunnel-type', '?')} "
        f"binding-label={details.get('binding-label', '-')} "
        f"bw-mbps={details.get('signaled-bandwidth-mbps', '-')} "
        f"prio={details.get('setup-priority', '-')}/{details.get('hold-priority', '-')} "
        f"pce-controlled={as_bool(details.get('pce-controlled'))} "
        f"pcc={details.get('pcc-address', '-')}"
    )
    path = active_tunnel_path(paths)
    if path is None:
        tail = "no path reported"
    else:
        tail = (
            f"active path: {path.get('path-name', '?')} {path.get('path-type', '?')} "
            f"oper={path.get('path-oper-state', '?')} metric={_metric_text(path)} "
            f"rro={_te_hops_text(path.get('rro-hop'))}"
        )
        if len(paths) > 1:
            tail += f" (+{len(paths) - 1} more path(s))"
    return f"{head} | {tail} updated={epoch_iso(details.get('update-time'))}"


def rsvp_tunnel_markdown(tunnel: dict[str, Any]) -> str:
    details = tunnel_details(tunnel)
    lines = [
        f"# RSVP-TE tunnel {tunnel_key_text(tunnel)}",
        "",
        f"- admin-state={tunnel.get('admin-state', '?')} "
        f"oper-state={tunnel.get('oper-state', '?')} "
        f"type={tunnel.get('rsvp-te-tunnel-type', '?')} "
        f"description={tunnel.get('description') or '-'}",
        f"- binding-label={details.get('binding-label', '-')} "
        f"signaled-bandwidth-mbps={details.get('signaled-bandwidth-mbps', '-')} "
        f"setup/hold-priority={details.get('setup-priority', '-')}/"
        f"{details.get('hold-priority', '-')} "
        f"pce-controlled={as_bool(details.get('pce-controlled'))} "
        f"pcc-address={details.get('pcc-address', '-')} "
        f"delegated-pce={details.get('delegated-pce', '-')} "
        f"updated={epoch_iso(details.get('update-time'))}",
        f"- pcep-info: {kv_text(details.get('pcep-info'))}",
    ]
    if details.get("non-delegated-pces"):
        lines.append(f"- non-delegated-pces: {_compact(details['non-delegated-pces'])}")
    other = {**_leftover(tunnel, _RSVP_KEYS), **_leftover(details, _RSVP_DETAIL_KEYS)}
    if other:
        lines.append(f"- other: {kv_text(other)}")
    paths = tunnel_paths(tunnel)
    lines.extend(["", f"Paths ({len(paths)}):"])
    if not paths:
        lines.append("- (no path reported)")
    for path in paths:
        lines.append(
            f"- **{path.get('path-name', '?')}** {path.get('path-type', '?')} "
            f"oper={path.get('path-oper-state', '?')} metric={_metric_text(path)} "
            f"computed={epoch_iso(path.get('computed-time'))}"
        )
        lines.append(f"  constraints: {kv_text(path.get('constraints'))}")
        lines.append(f"  ERO: {_te_hops_text(path.get('ero-hop'))}")
        lines.append(f"  RRO: {_te_hops_text(path.get('rro-hop'))}")
        other = _leftover(path, _RSVP_PATH_KEYS)
        if other:
            lines.append(f"  other: {kv_text(other)}")
    return "\n".join(lines)


_LINK_PM_KEYS = (
    "link-id",
    "source",
    "destination",
    "max-bandwidth-kbps",
    "bandwidth-utilization-kbps",
    "delay",
    "delay-telemetry",
    "jitter-telemetry",
    "interfaces",
)
_INTERFACE_PM_KEYS = (
    "Throughput",
    "Bandwidth",
    "TX-Errors",
    "TX-packet-drops",
    "RX-Errors",
    "RX-packet-drops",
)


def link_pm_markdown(entry: dict[str, Any]) -> str:
    source = entry.get("source") if isinstance(entry.get("source"), dict) else {}
    dest = entry.get("destination") if isinstance(entry.get("destination"), dict) else {}
    interfaces = entry.get("interfaces") if isinstance(entry.get("interfaces"), dict) else {}
    lines = [
        f"# Performance metrics for link {entry.get('link-id', '?')}",
        "",
        f"- {source.get('source-node', '?')} {source.get('source-tp', '?')} -> "
        f"{dest.get('dest-node', '?')} {dest.get('dest-tp', '?')}",
        f"- max-bandwidth-kbps={entry.get('max-bandwidth-kbps', '-')} "
        f"bandwidth-utilization-kbps={entry.get('bandwidth-utilization-kbps', '-')} "
        f"delay-us={entry.get('delay', '-')} "
        f"delay-telemetry-us={entry.get('delay-telemetry', '-')} "
        f"jitter-telemetry-us={entry.get('jitter-telemetry', '-')}",
        "- interfaces: "
        + " ".join(f"{k}={interfaces.get(k, '-')}" for k in _INTERFACE_PM_KEYS)
        + (
            f" {kv_text(_leftover(interfaces, _INTERFACE_PM_KEYS))}"
            if _leftover(interfaces, _INTERFACE_PM_KEYS)
            else ""
        ),
    ]
    other = _leftover(entry, _LINK_PM_KEYS)
    if other:
        lines.append(f"- other: {kv_text(other)}")
    lines.extend(
        [
            "",
            "Units: bandwidth in kbps, delay/jitter in microseconds, Throughput the transmit "
            "utilisation in percent, Bandwidth the interface speed as the collector reports it "
            "(1000000000 on a 1 GbE link live).",
        ]
    )
    return "\n".join(lines)


_POLICY_PM_KEYS = (
    "headend",
    "endpoint",
    "color",
    "tunnel-id",
    "delay",
    "bandwidth-utilization-kbps",
    "delay-telemetry",
    "jitter-telemetry",
    "liveness-telemetry",
)
_TELEMETRY_KEYS = ("delay-telemetry", "jitter-telemetry", "liveness-telemetry")
# The caveat on a PM ``delay`` that carries no ``*-telemetry`` key, per object kind. Only the
# SR-policy one is a verified fact (2026-09-14, agent scenario 2: equal to the COE's
# sr-policy-metrics delay); no RSVP-TE tunnel was available live, so the RSVP wording is an
# explicit presumption and cross-references only what can answer a tunnel (cnc_get_lsp_delay
# with tunnel_id set, which selects the RSVP LSP — cnc_get_sr_policy_metrics cannot).
MODELLED_DELAY_NOTES = {
    "sr": (
        "modelled — no NAPM/SR-PM telemetry present: without SR-PM probes on the head-end this "
        "is the sum of the modelled link delays along the route (verified live 2026-09-14: "
        "equal to cnc_get_sr_policy_metrics' delay), not a measurement; measured delay needs "
        "SR-PM probes and appears as delay-telemetry here and as samples in cnc_get_lsp_delay"
    ),
    "rsvp": (
        "presumed modelled, as for SR policies — UNVERIFIED (no RSVP-TE tunnel was available "
        "live): without NAPM telemetry this is most likely the modelled path delay, not a "
        "measurement; measured tunnel delay samples are cnc_get_lsp_delay (with tunnel_id, "
        "which selects the RSVP LSP)"
    ),
}
MODELLED_DELAY_NOTE = MODELLED_DELAY_NOTES["sr"]


def has_pm_telemetry(entry: dict[str, Any]) -> bool:
    """True when the PM entry carries any NAPM ``*-telemetry`` key (measured data present)."""
    return any(entry.get(key) not in (None, "") for key in _TELEMETRY_KEYS)


def policy_pm_markdown(title: str, entry: dict[str, Any], kind: str = "sr") -> str:
    """Markdown for one ``sr-policy-pm`` (``kind="sr"``) or ``rsvp-policy-pm`` (``"rsvp"``) entry.

    The two entries share their shape; only the caveat on a ``delay`` without
    telemetry differs (see :data:`MODELLED_DELAY_NOTES` — verified for SR
    policies, presumed for RSVP-TE tunnels).
    """
    telemetry = has_pm_telemetry(entry)
    delay_text = f"delay-us={entry.get('delay', '-')}"
    if not telemetry and entry.get("delay") not in (None, ""):
        delay_text += f" ({MODELLED_DELAY_NOTES[kind]})"
    lines = [
        f"# Performance metrics for {title}",
        "",
        f"- {delay_text}",
        f"- bandwidth-utilization-kbps={entry.get('bandwidth-utilization-kbps', '-')} "
        f"delay-telemetry-us={entry.get('delay-telemetry', '-')} "
        f"jitter-telemetry-us={entry.get('jitter-telemetry', '-')} "
        f"liveness={entry.get('liveness-telemetry', '-')}",
    ]
    other = _leftover(entry, _POLICY_PM_KEYS)
    if other:
        lines.append(f"- other: {kv_text(other)}")
    verdict = "is modelled" if kind == "sr" else "is presumed modelled"
    lines.extend(
        [
            "",
            "Units: delay/jitter in microseconds, bandwidth in kbps; the *-telemetry fields "
            "come from NAPM telemetry and are absent when none is configured — while they are "
            f"absent, delay-us {verdict} (see above), not measured.",
        ]
    )
    return "\n".join(lines)


def _filter_text(filters: dict[str, Any]) -> str:
    active = {k: v for k, v in filters.items() if v is not None}
    if not active:
        return "no filter"
    return ", ".join(f"{k}={v}" for k, v in active.items())


# --- registration ----------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def get_container(url: str, module: str, name: str) -> list[dict[str, Any]]:
        """GET a whole list container; ``{}`` (empty on this lab) is an empty list."""
        data = await client.request_json("GET", url, headers=YANG_ACCEPT)
        return [e for e in unwrap_list(data, module, name) if isinstance(e, dict)]

    async def get_keyed(
        url: str, module: str, name: str, keys: dict[str, Any], missing: PlatformError
    ) -> dict[str, Any]:
        """GET one keyed entry; 409 data-missing (or an answer without the key) -> ``missing``.

        Not-found is gated on the topology NBI's own spelling — **409
        ``data-missing`` only**. :func:`cnc_mcp.restconf.is_not_found` also
        accepts the NSO proxy's "404 with a RESTCONF document", but that
        spelling has never been observed on this NBI, so a 404 — bare or with
        a document — is NOT a not-found here (malformed / unrouted URL) and is
        raised through http_error with that explanation; a 400
        ``invalid-value`` (a host name where a router-id belongs) is raised
        with the key rule.
        """
        response = await client.request("GET", url, headers=YANG_ACCEPT, raise_on_error=False)
        data: Any = None
        if response.content:
            try:
                data = response.json()
            except ValueError:
                data = None
        if response.status_code == 409 and is_not_found(response.status_code, data):
            raise missing
        if not response.is_success:
            error = http_error(response)
            if is_invalid_key(response.status_code, data):
                raise PlatformError(
                    f"{error} The topology NBI rejected a key part as the wrong type: "
                    "headend/endpoint must be TE router-ids (IP addresses such as 10.0.0.1), "
                    "not host names, and color / tunnel-id must be numbers."
                )
            if response.status_code == 404:
                raise PlatformError(
                    f"{error} On the topology NBI a 404 means the URL was not routed "
                    "(a malformed key or an absent path), never that the object is missing — "
                    "a missing entry answers 409 data-missing."
                )
            raise error
        if response.content and data is None:
            raise PlatformError(
                "The topology NBI returned a non-JSON response where JSON was expected."
            )
        entries = entries_matching(unwrap_list(data, module, name), keys)
        if not entries:
            raise missing
        return entries[0]

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_sr_policies",
        title="List SR Policies",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_sr_policies(
        headend: Annotated[
            str | None,
            Field(
                description=(
                    f"Only policies with this head-end: {_NODE_HELP}; e.g. 'PE1' or '10.0.0.1'."
                ),
                max_length=253,
            ),
        ] = None,
        endpoint: Annotated[
            str | None,
            Field(
                description=(
                    f"Only policies to this endpoint: {_NODE_HELP}; e.g. 'PE2' or '10.0.0.3'."
                ),
                max_length=253,
            ),
        ] = None,
        color: Annotated[
            int | None,
            Field(description="Only policies with this color (e.g. 100).", ge=0, le=4294967295),
        ] = None,
        oper_state: Annotated[
            str | None,
            Field(
                description="Only policies in this operational state: 'UP' or 'DOWN'.",
                max_length=8,
            ),
        ] = None,
        pce_controlled: Annotated[
            bool | None,
            Field(
                description=(
                    "true = only policies delegated to the PCE (it may re-optimise them; "
                    "independent of who created them — see the docstring), false = only "
                    "non-delegated ones."
                ),
            ),
        ] = None,
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the SR-TE policies Crosswork knows, with each policy's active path.

        Read-only. ``GET /crosswork/nbi/topology/v3/restconf/data/
        cisco-crosswork-segment-routing-policy:sr-policies`` — the whole
        container (no server-side filter or paging exists), filtered
        client-side by the arguments. The policies come from the SR-PCE
        provider's gRPC feed and a policy is listed only while that feed is
        up and the head-end PCC reports it (PCEP ``report-all``): PCC-
        initiated and PCE-initiated policies alike, each keyed by
        ``(headend, endpoint, color)`` where headend/endpoint are the TE
        router-ids (loopbacks such as ``10.0.0.1``). The headend/endpoint
        filters accept a host name too (resolved through the topology, one
        extra GET; a router-id costs nothing extra). When a host name was
        given, the topology nodes that resolved it also supply a router-id ->
        host name map, and the header and every row then read ``PE2
        (10.0.0.3) -> PE1 (10.0.0.1) color 100`` (the node ids are the exact
        keys for cnc_get_topology_node); with router-id filters only, or no
        filter, nothing extra is read and the rows show router-ids alone. An
        empty answer (``{}``) is a normal result ("No SR policies are
        reported"), not an error — check the SR-PCE provider
        (cnc_list_providers) and the PCC's PCEP session
        (``node-pcep-sessions`` in the topology) when policies are expected.

        Origin vs delegation (two independent flags, verified live):
        ``policy-details.pcep-info.pcep-flag-c`` says who instantiated the
        policy — 1 = PCE-initiated (cnc_create_sr_policy; only these can be
        modified/deleted through the PCE), 0 = PCC-initiated (configured on
        the head-end router) — rendered as ``origin=``;
        ``policy-details.pce-controlled`` says whether it is delegated to the
        PCE for (re)optimisation. PCC-initiated + pce-controlled true = a
        router-configured policy delegated to the PCE (the lab's colour-100
        policies).

        Args:
            headend, endpoint: host name or TE router-id (exact router-id
                match after resolution, case-insensitive).
            color: numeric color.
            oper_state: 'UP' | 'DOWN' (case-insensitive).
            pce_controlled: delegated-to-PCE filter.
            network: topology network id host names are resolved in.
            response_format: markdown (one line per policy: key — with host
                names next to the router-ids when a host-name filter was
                given — admin/oper state, type, binding SID, origin,
                pce-controlled, PCC address, then the active path — the
                operationally-UP path of highest preference, else the first
                — with its name, preference, type, metric, hops as
                ``<label>(<sid-type>/<address>)`` and the last update time)
                or json (the raw ``policy`` entries, router-ids only).

        Returns:
            str: Markdown, or JSON {"count": int, "total": int (before the
            filter), "filter": {...} (headend/endpoint as the resolved
            router-ids), "items": [{"headend", "endpoint",
            "color", "admin-state", "oper-state", "sr-policy-type",
            "policy-details": {"binding-sid", "pce-controlled", "pcc-address",
            "update-time" (epoch ms string), "pcep-info": {"pcep-flag-c"},
            "path": [{"path-name", "path-type", "preference", "oper-state",
            "optimization-metric", "constraints", "segment-list": [{"weight",
            "hop": [{"type", "local-ip-addr", "label"}]}], "hop": [...]}]}}]}.
            "No SR policies are reported by the SR-PCE feed." when the
            container is empty; "No SR policies match ..." when the filter
            excludes everything. "Error: ..." when oper_state is not UP/DOWN,
            a host name is not in the topology ("no node 'X' in the
            topology"), or on an API failure (400 unknown-element -> the
            module is not served on this build).
        """
        try:
            state = normalize_oper_state(oper_state)
            (head_key, end_key), nodes = await resolve_router_ids_and_nodes(
                client, network, headend, endpoint
            )
            # Host names are known only when the topology was read to resolve one (no
            # extra request is made just to decorate router-ids — the fast path stays).
            names = router_id_names(nodes)
            policies = await get_container(SR_POLICIES_URL, SR_POLICY_MODULE, "policy")
            filters = {
                "headend": head_key,
                "endpoint": end_key,
                "color": color,
                "oper_state": state,
                "pce_controlled": pce_controlled,
            }
            shown = {
                **filters,
                "headend": None if head_key is None else node_text(head_key, names),
                "endpoint": None if end_key is None else node_text(end_key, names),
            }
            matched = [
                p
                for p in policies
                if matches_policy_filter(
                    p,
                    headend=head_key,
                    endpoint=end_key,
                    color=color,
                    oper_state=state,
                    pce_controlled=pce_controlled,
                )
            ]
            if response_format is ResponseFormat.JSON:
                payload = {
                    "count": len(matched),
                    "total": len(policies),
                    "filter": filters,
                    "items": matched,
                }
                return finalize(to_json(payload), settings)
            if not policies:
                return finalize(
                    "No SR policies are reported by the SR-PCE feed. Policies appear here only "
                    "while the SR-PCE provider's gRPC feed is up and the head-end PCC reports "
                    "them (PCEP report-all).",
                    settings,
                )
            lines = [f"# SR policies ({len(matched)} of {len(policies)}, {_filter_text(shown)})"]
            lines.append("")
            if not matched:
                lines.append(
                    f"No SR policies match the filter ({_filter_text(shown)}); "
                    f"{len(policies)} are reported in total."
                )
            lines.extend(sr_policy_line(p, names) for p in matched)
            if names:
                key_note = (
                    "Keys are (headend, endpoint, color); host names are shown next to the TE "
                    "router-ids the wire uses ('PE2 (10.0.0.3)') and the get tools accept either"
                )
            else:
                key_note = (
                    "Keys are (headend, endpoint, color) with headend/endpoint the TE router-ids "
                    "(the get tools accept host names too, and a host-name filter here shows "
                    "host names next to the router-ids)"
                )
            lines.extend(
                [
                    "",
                    f"{key_note}; cnc_get_sr_policy shows every candidate path, "
                    "cnc_get_sr_policy_performance_metrics the PM entry. "
                    f"{_ORIGIN_RULE[0].upper()}{_ORIGIN_RULE[1:]}.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_sr_policy",
        title="Get SR Policy",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_sr_policy(
        headend: Annotated[str, Field(description=_SR_HEADEND_DESC, min_length=1, max_length=253)],
        endpoint: Annotated[
            str, Field(description=_SR_ENDPOINT_DESC, min_length=1, max_length=253)
        ],
        color: Annotated[
            int, Field(description="The policy color (e.g. 100).", ge=0, le=4294967295)
        ],
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one SR-TE policy with every candidate path, its segment lists and constraints.

        Read-only. ``GET .../cisco-crosswork-segment-routing-policy:sr-policies/
        policy=<headend>,<endpoint>,<color>`` (each key part percent-encoded).
        Keys are ``(headend, endpoint, color)`` with headend/endpoint the TE
        router-ids (loopbacks, e.g. ``10.0.0.1``) on the wire; the tool
        accepts a **host name or a router-id** for either (the same resolver
        as cnc_create_sr_policy / cnc_delete_sr_policy: a host name is looked
        up in the topology's ``networks`` collection, one extra GET, and an
        unknown one is refused client-side as "no node 'X' in the topology";
        a router-id goes on the wire as given, no lookup). When a host name
        was given, the topology nodes that resolved it also supply the
        router-id -> host name map, so the header reads ``# SR policy PE2
        (10.0.0.3) -> PE1 (10.0.0.1) color 100`` for BOTH ends (the node ids
        are the exact keys for cnc_get_topology_node); with router-ids only
        nothing extra is read and the header shows router-ids alone. A
        policy exists here only while the SR-PCE gRPC feed is up and the
        head-end PCC reports it (PCEP ``report-all``). The answer is
        re-checked on its key fields client-side. A missing policy answers 409 ``data-missing`` and
        is reported as "Error: no SR policy ..."; should a non-IP key still
        reach the NBI it answers 400 ``invalid-value`` (verified live) and is
        reported with the key rule.

        Origin vs delegation (two independent flags, verified live, rendered
        as the ``origin:`` line): ``pcep-info.pcep-flag-c`` = who
        instantiated the policy — 1 PCE-initiated (cnc_create_sr_policy; the
        only kind cnc_update_sr_policy / cnc_delete_sr_policy can act on),
        0 PCC-initiated (configured on the head-end router);
        ``pce-controlled`` = delegated to the PCE for (re)optimisation.
        ``pcep-flag-c 0`` + ``pce-controlled true`` is a router-configured
        policy delegated to the PCE (the lab's CNC-DYN-100 policies).

        Args:
            headend, endpoint: host name or TE router-id.
            color: policy color.
            network: topology network id host names are resolved in.
            response_format: markdown (state, type, binding SID, delegation,
                PCEP flags, the origin line, then each path with preference,
                type, oper-state, metric, constraints and its segment-lists'
                hops as ``<label>(<sid-type>/<address>)``; keys the renderer
                does not know are appended as ``other:``) or json (the raw
                entry).

        Returns:
            str: Markdown, or the JSON ``policy`` entry ({"headend",
            "endpoint", "color", "admin-state", "oper-state", "sr-policy-type",
            "policy-details": {"binding-sid", "pce-controlled", "pcc-address",
            "update-time", "pcep-info": {"pcep-flag-c"}, "path": [...]}}).
            "Error: no SR policy <headend> -> <endpoint> color <color> ..."
            when it does not exist (hint: cnc_list_sr_policies); "Error: no
            node '<name>' in the topology ..." for an unknown host name
            (nothing else is read); "Error: ... 400 ... wrong type" when a
            key part is rejected by the NBI; "Error: ..." on any other API
            failure (a plain 404 = unrouted/malformed URL, not a missing
            policy).
        """
        try:
            head_key, end_key, names = await resolve_policy_ends(client, network, headend, endpoint)
            label = (
                f"{end_label(headend, head_key, names)} -> {end_label(endpoint, end_key, names)}"
            )
            missing = PlatformError(
                f"no SR policy {label} color {color} is reported by the "
                f"SR-PCE feed. {_KEY_RULE}, and {_FEED_RULE}; list the known policies with "
                "cnc_list_sr_policies."
            )
            policy = await get_keyed(
                sr_policy_url(head_key, end_key, color),
                SR_POLICY_MODULE,
                "policy",
                {"headend": head_key, "endpoint": end_key, "color": color},
                missing,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(policy), settings)
            return finalize(sr_policy_markdown(policy, names), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_p2mp_policies",
        title="List P2MP (Tree-SID) Policies",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_p2mp_policies(
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the SR P2MP (Tree-SID) policies Crosswork knows.

        Read-only. ``GET .../cisco-crosswork-segment-routing-p2mp-policy:
        p2mp-policies`` — the whole container (no filter, no paging). Tree-SID
        trees are computed by the SR-PCE and reach Crosswork over the PCE's
        HTTP leg; each policy is keyed by its ``name`` and carries the root
        address, the ``tree-id`` (0 for a static policy), the PCC/PCE
        addresses, admin/oper state, the destination list and the candidate
        paths (each with its label, metric type, programming state and the
        per-node roles INGRESS/TRANSIT/BUD/EGRESS with next-hops). The
        container answers ``{}`` when there are none (the lab state) — a
        normal "none reported" result, not an error. Rendering follows the
        7.2 document (no Tree-SID policy was available live); keys it does not
        know are appended as ``other=``.

        Args:
            response_format: markdown (one line per policy: name, root,
                tree-id, states, initiation type, PCC/PCE, destinations,
                candidate-path count) or json (the raw ``p2mp-policy``
                entries).

        Returns:
            str: Markdown, or JSON {"count": int, "items": [{"name",
            "root-address", "pcc-address", "pce-address", "initiation-type",
            "admin-state", "oper-state", "tree-id", "destination":
            [{"destination-address"}], "candidate-path": [{"name",
            "oper-state", "path-type", "label", "metric-type", "preference",
            "programming-state", "path-constraints", "p2mp-node": [{"hostname",
            "node-ip-address", "role", "next-hop": [...]}]}]}]}. "No P2MP
            (Tree-SID) policies are reported ..." when empty. "Error: ..." on
            an API failure.
        """
        try:
            policies = await get_container(P2MP_POLICIES_URL, P2MP_MODULE, "p2mp-policy")
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(policies), "items": policies}), settings)
            if not policies:
                return finalize(
                    "No P2MP (Tree-SID) policies are reported by the SR-PCE feed (the platform "
                    "reports none).",
                    settings,
                )
            lines = [f"# P2MP (Tree-SID) policies ({len(policies)})", ""]
            lines.extend(p2mp_policy_line(p) for p in policies)
            lines.extend(["", "cnc_get_p2mp_policy shows the candidate paths and per-node roles."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_p2mp_policy",
        title="Get P2MP (Tree-SID) Policy",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_p2mp_policy(
        name: Annotated[
            str,
            Field(
                description="The P2MP policy name, exact and case-sensitive (e.g. 'tree-sid-100').",
                min_length=1,
                max_length=253,
            ),
        ],
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one SR P2MP (Tree-SID) policy with its candidate paths and per-node tree roles.

        Read-only. ``GET .../cisco-crosswork-segment-routing-p2mp-policy:
        p2mp-policies/p2mp-policy=<name>`` (the name percent-encoded as one
        list key). A missing policy answers 409 ``data-missing`` (verified
        live) and is reported as "Error: no P2MP policy ..."; the answer is
        re-checked on ``name`` client-side. List the names with
        cnc_list_p2mp_policies.

        Args:
            name: exact policy name.
            response_format: markdown (summary line, destinations, then each
                candidate path with label/metric/programming state,
                constraints and the tree nodes with role and next-hops) or
                json (the raw entry).

        Returns:
            str: Markdown, or the JSON ``p2mp-policy`` entry. "Error: no P2MP
            (Tree-SID) policy named '<name>' ..." when it does not exist;
            "Error: ..." on any other API failure.
        """
        try:
            key = name.strip()
            missing = PlatformError(
                f"no P2MP (Tree-SID) policy named '{key}' is reported by the SR-PCE feed. Names "
                "are exact and case-sensitive; list them with cnc_list_p2mp_policies."
            )
            policy = await get_keyed(
                p2mp_policy_url(key), P2MP_MODULE, "p2mp-policy", {"name": key}, missing
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(policy), settings)
            return finalize(p2mp_policy_markdown(policy), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_rsvp_te_tunnels",
        title="List RSVP-TE Tunnels",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_rsvp_te_tunnels(
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the RSVP-TE tunnels (LSPs) Crosswork knows, with each tunnel's active path.

        Read-only. ``GET .../cisco-crosswork-rsvp-te-tunnel:rsvp-te-tunnels``
        — the whole container (no filter, no paging). RSVP-TE tunnels reach
        Crosswork over the SR-PCE's HTTP leg (PCEP-reported LSPs); each is
        keyed by ``(headend, endpoint, tunnel-id)`` with headend/endpoint the
        TE router-ids (loopbacks), not host names. The container answers
        ``{}`` when there are none (the lab state, an SR-MPLS-only network) —
        a normal "none reported" result, not an error. Rendering follows the
        7.2 document (no RSVP-TE tunnel was available live).

        Args:
            response_format: markdown (one line per tunnel: key, states,
                type CW-CONFIGURED|OTHER, binding label, signalled bandwidth,
                setup/hold priority, pce-controlled, PCC, then the active
                path — ACTIVE, else UP, else the first — with its RRO) or
                json (the raw ``rsvp-te-tunnel`` entries).

        Returns:
            str: Markdown, or JSON {"count": int, "items": [{"headend",
            "endpoint", "tunnel-id", "admin-state", "oper-state"
            (UP|DOWN|ACTIVE), "rsvp-te-tunnel-type", "tunnel-details":
            {"binding-label", "signaled-bandwidth-mbps", "setup-priority",
            "hold-priority", "pce-controlled", "pcc-address", "pcep-info",
            "update-time", "path": [{"path-name", "path-type",
            "path-oper-state", "optimization-metric", "constraints",
            "ero-hop": [...], "rro-hop": [...]}]}}]}. "No RSVP-TE tunnels are
            reported ..." when empty. "Error: ..." on an API failure.
        """
        try:
            tunnels = await get_container(RSVP_TUNNELS_URL, RSVP_MODULE, "rsvp-te-tunnel")
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(tunnels), "items": tunnels}), settings)
            if not tunnels:
                return finalize(
                    "No RSVP-TE tunnels are reported by the SR-PCE feed (the platform reports "
                    "none).",
                    settings,
                )
            lines = [f"# RSVP-TE tunnels ({len(tunnels)})", ""]
            lines.extend(rsvp_tunnel_line(t) for t in tunnels)
            lines.extend(
                [
                    "",
                    "Keys are (headend, endpoint, tunnel-id) with headend/endpoint the TE "
                    "router-ids; cnc_get_rsvp_te_tunnel shows every path with ERO/RRO.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_rsvp_te_tunnel",
        title="Get RSVP-TE Tunnel",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_rsvp_te_tunnel(
        headend: Annotated[str, Field(description=_HEADEND_DESC, min_length=1, max_length=64)],
        endpoint: Annotated[
            str,
            Field(
                description="Tail-end TE router-id of the tunnel (e.g. '10.0.0.3').",
                min_length=1,
                max_length=64,
            ),
        ],
        tunnel_id: Annotated[
            int,
            Field(description="The tunnel id on the head-end (e.g. 1).", ge=0, le=4294967295),
        ],
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one RSVP-TE tunnel with every path, its ERO/RRO hops and constraints.

        Read-only. ``GET .../cisco-crosswork-rsvp-te-tunnel:rsvp-te-tunnels/
        rsvp-te-tunnel=<headend>,<endpoint>,<tunnel-id>`` (each key part
        percent-encoded). headend/endpoint are TE router-ids (loopbacks such
        as ``10.0.0.1``), never host names — find them with
        cnc_list_rsvp_te_tunnels. A missing tunnel answers 409
        ``data-missing`` (verified live) and is reported as "Error: no
        RSVP-TE tunnel ..."; the answer is re-checked on its key client-side.

        Args:
            headend, endpoint: TE router-ids.
            tunnel_id: the head-end's tunnel id.
            response_format: markdown (states, type, binding label,
                bandwidth, priorities, delegation, PCEP flags, then each path
                with type, oper-state, metric, constraints, ERO and RRO hop
                lists) or json (the raw entry).

        Returns:
            str: Markdown, or the JSON ``rsvp-te-tunnel`` entry. "Error: no
            RSVP-TE tunnel <headend> -> <endpoint> tunnel-id <id> ..." when it
            does not exist (hint: cnc_list_rsvp_te_tunnels); "Error: ..." on
            any other API failure.
        """
        try:
            head_key, end_key = headend.strip(), endpoint.strip()
            missing = PlatformError(
                f"no RSVP-TE tunnel {head_key} -> {end_key} tunnel-id {tunnel_id} is reported "
                "by the SR-PCE feed. Keys are (headend, endpoint, tunnel-id) with "
                "headend/endpoint the TE router-ids (loopbacks), not host names; list the "
                "known tunnels with cnc_list_rsvp_te_tunnels."
            )
            tunnel = await get_keyed(
                rsvp_tunnel_url(head_key, end_key, tunnel_id),
                RSVP_MODULE,
                "rsvp-te-tunnel",
                {"headend": head_key, "endpoint": end_key, "tunnel-id": tunnel_id},
                missing,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(tunnel), settings)
            return finalize(rsvp_tunnel_markdown(tunnel), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_link_performance_metrics",
        title="Get IGP Link Performance Metrics",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_link_performance_metrics(
        link_id: Annotated[
            str,
            Field(
                description=(
                    "The topology link id VERBATIM as cnc_list_topology_links returns it, e.g. "
                    "'P2 : GigabitEthernet0/0/0/0 : PE2 : GigabitEthernet0/0/0/1 : ISIS_IPV4_L2' "
                    "(spaces and colons included; the tool percent-encodes it). Only IGP links "
                    "(… : ISIS_IPV4_L2 / OSPF) have metrics — ETHERNET (L2) links do not."
                ),
                min_length=1,
                max_length=512,
            ),
        ],
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the performance metrics (utilisation, delay, interface counters) of one IGP link.

        Read-only. ``GET .../cisco-crosswork-performance-metrics:
        igp-links-performance-metrics/igp-link-pm=<link-id>`` with the id
        fully percent-encoded (spaces, ``:`` and ``/`` — an unencoded id would
        break the route and answer a plain 404). **The PM container cannot be
        listed** (an unkeyed GET answers 409 ``data-missing``, verified live):
        take the id verbatim from cnc_list_topology_links. Metrics exist only
        for IGP links (ids ending ``: ISIS_IPV4_L2`` on an IS-IS network) —
        an L2 ``… : ETHERNET`` link answers 409 and is reported as "no
        performance metrics for link". Verified shape: ``max-bandwidth-kbps``,
        ``bandwidth-utilization-kbps`` and the ``interfaces`` counters arrive
        as strings, ``delay`` (microseconds) as an int; ``delay-telemetry`` /
        ``jitter-telemetry`` (NAPM) are present only when configured.

        Args:
            link_id: the verbatim link id.
            response_format: markdown (endpoints, bandwidth/utilisation,
                delay, the interface counters Throughput / Bandwidth /
                TX-Errors / TX-packet-drops (+RX when present)) or json
                (the raw ``igp-link-pm`` entry).

        Returns:
            str: Markdown, or the JSON entry {"link-id", "source":
            {"source-node", "source-tp"}, "destination": {"dest-node",
            "dest-tp"}, "max-bandwidth-kbps", "bandwidth-utilization-kbps",
            "interfaces": {"TX-Errors", "Throughput", "TX-packet-drops",
            "Bandwidth"}, "delay"}. "Error: no performance metrics for link
            '<id>' ..." when the link has none (L2 link, unknown id, or PM not
            collected yet); "Error: ..." on any other API failure (a plain
            404 = the id was not routed, i.e. malformed).
        """
        try:
            key = link_id.strip()
            missing = PlatformError(
                f"no performance metrics for link '{key}' — PM exists only for IGP "
                "(… : ISIS_IPV4_L2) links, not ETHERNET links, and ids must be passed verbatim "
                "from cnc_list_topology_links (spaces and colons included). A link that only "
                "just appeared may not have been collected yet."
            )
            entry = await get_keyed(
                igp_link_pm_url(key), PM_MODULE, "igp-link-pm", {"link-id": key}, missing
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(entry), settings)
            return finalize(link_pm_markdown(entry), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_sr_policy_performance_metrics",
        title="Get SR Policy Performance Metrics",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_sr_policy_performance_metrics(
        headend: Annotated[str, Field(description=_SR_HEADEND_DESC, min_length=1, max_length=253)],
        endpoint: Annotated[
            str, Field(description=_SR_ENDPOINT_DESC, min_length=1, max_length=253)
        ],
        color: Annotated[
            int, Field(description="The policy color (e.g. 100).", ge=0, le=4294967295)
        ],
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the PM entry (delay, bandwidth utilisation) of one SR-TE policy.

        Read-only. ``GET .../cisco-crosswork-performance-metrics:
        sr-policies-performance-metrics/sr-policy-pm=<headend>,<endpoint>,
        <color>`` (key parts percent-encoded). **The PM container cannot be
        listed** — only keyed reads exist (verified live); the key is the
        policy's ``(headend, endpoint, color)`` with headend/endpoint the TE
        router-ids on the wire — the tool accepts a host name or a router-id
        for either (resolved as cnc_get_sr_policy does). A policy without a
        PM entry (unknown key, or the policy is newer than the last
        collection) answers 409 ``data-missing`` and is reported as "Error:
        no performance metrics ...". Verified shape: ``delay`` (microseconds,
        int) and ``bandwidth-utilization-kbps`` (string); ``delay-telemetry``
        / ``jitter-telemetry`` / ``liveness-telemetry`` (NAPM) only when
        configured.

        **``delay`` is MODELLED unless NAPM/SR-PM telemetry is present**
        (verified live 2026-09-14, agent scenario 2): on a lab without SR-PM
        probes the entry carried no ``*-telemetry`` key and its ``delay``
        (20) was exactly the sum of the two link delays on the route (10 each,
        cnc_get_link_performance_metrics) and the COE's modelled path delay
        (cnc_get_sr_policy_metrics: igp-metric 20, te-metric 20, delay 20),
        while cnc_get_lsp_delay had no samples ("Maximum Average Delay for
        given LSP not present..returning default delay!"). So do not report
        it as a measurement: the markdown marks it ``(modelled — ...)`` while
        the telemetry keys are absent; measured delay needs SR-PM probes on
        the head-end and then appears as ``delay-telemetry`` here and as
        samples in cnc_get_lsp_delay. ``bandwidth-utilization-kbps`` is the
        collected policy throughput (0 on an idle policy).

        Args:
            headend, endpoint: host name or TE router-id.
            color: policy color.
            network: topology network id host names are resolved in.
            response_format: markdown (delay-us with the modelled caveat when
                no telemetry key is present, then utilisation and the
                telemetry fields) or json (the raw ``sr-policy-pm`` entry —
                no caveat is added; apply the same rule).

        Returns:
            str: Markdown, or the JSON entry {"headend", "endpoint", "color",
            "delay" (modelled unless a *-telemetry key is present),
            "bandwidth-utilization-kbps", "delay-telemetry"?,
            "jitter-telemetry"?, "liveness-telemetry"?}. "Error: no
            performance metrics for SR policy ..." when absent; "Error: no
            node '<name>' in the topology ..." for an unknown host name;
            "Error: ..." on any other API failure.
        """
        try:
            head_key, end_key, names = await resolve_policy_ends(client, network, headend, endpoint)
            title = (
                f"SR policy {end_label(headend, head_key, names)} -> "
                f"{end_label(endpoint, end_key, names)} color {color}"
            )
            missing = PlatformError(
                f"no performance metrics for {title} — the policy must exist under that exact "
                f"key in cnc_list_sr_policies ({_KEY_RULE}), and a PM entry follows a new "
                "policy only after the next collection."
            )
            entry = await get_keyed(
                sr_policy_pm_url(head_key, end_key, color),
                PM_MODULE,
                "sr-policy-pm",
                {"headend": head_key, "endpoint": end_key, "color": color},
                missing,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(entry), settings)
            return finalize(policy_pm_markdown(title, entry), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_rsvp_tunnel_performance_metrics",
        title="Get RSVP-TE Tunnel Performance Metrics",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_rsvp_tunnel_performance_metrics(
        headend: Annotated[str, Field(description=_HEADEND_DESC, min_length=1, max_length=64)],
        endpoint: Annotated[
            str,
            Field(
                description="Tail-end TE router-id of the tunnel (e.g. '10.0.0.3').",
                min_length=1,
                max_length=64,
            ),
        ],
        tunnel_id: Annotated[
            int,
            Field(description="The tunnel id on the head-end (e.g. 1).", ge=0, le=4294967295),
        ],
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the performance metrics (delay, bandwidth utilisation) of one RSVP-TE tunnel.

        Read-only. ``GET .../cisco-crosswork-performance-metrics:
        rsvp-policies-performance-metrics/rsvp-policy-pm=<headend>,<endpoint>,
        <tunnel-id>`` (key parts percent-encoded). **The PM container cannot
        be listed** (an unkeyed GET answers 409 ``data-missing``, verified
        live) — the key is the tunnel's ``(headend, endpoint, tunnel-id)``
        with headend/endpoint the TE router-ids (loopbacks), not host names,
        as cnc_list_rsvp_te_tunnels shows them. A tunnel without a PM entry
        answers 409 and is reported as "Error: no performance metrics ...".
        Shape per the 7.2 document (no RSVP-TE tunnel was available live):
        ``delay`` (microseconds), ``bandwidth-utilization-kbps``, optional
        ``delay-telemetry`` / ``jitter-telemetry``. A ``delay`` without the
        ``*-telemetry`` keys is PRESUMED to be the modelled path delay, as
        verified for SR policies (cnc_get_sr_policy_performance_metrics) —
        UNVERIFIED for tunnels, since none was available live; the markdown
        marks it "presumed modelled ... UNVERIFIED" rather than as a fact.
        Measured tunnel delay samples are cnc_get_lsp_delay (with tunnel_id
        set, which selects the RSVP LSP); cnc_get_sr_policy_metrics cannot
        answer a tunnel.

        Args:
            headend, endpoint: TE router-ids.
            tunnel_id: the head-end's tunnel id.
            response_format: markdown (delay-us with the presumed-modelled
                caveat when no telemetry key is present) or json (the raw
                ``rsvp-policy-pm`` entry — no caveat is added).

        Returns:
            str: Markdown, or the JSON entry {"headend", "endpoint",
            "tunnel-id", "delay", "bandwidth-utilization-kbps",
            "delay-telemetry"?, "jitter-telemetry"?}. "Error: no performance
            metrics for RSVP-TE tunnel ..." when absent; "Error: ..." on any
            other API failure.
        """
        try:
            head_key, end_key = headend.strip(), endpoint.strip()
            title = f"RSVP-TE tunnel {head_key} -> {end_key} tunnel-id {tunnel_id}"
            missing = PlatformError(
                f"no performance metrics for {title} — the tunnel must exist under that exact "
                "key in cnc_list_rsvp_te_tunnels (headend/endpoint are TE router-ids, not host "
                "names), and a PM entry follows a new tunnel only after the next collection."
            )
            entry = await get_keyed(
                rsvp_pm_url(head_key, end_key, tunnel_id),
                PM_MODULE,
                "rsvp-policy-pm",
                {"headend": head_key, "endpoint": end_key, "tunnel-id": tunnel_id},
                missing,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(entry), settings)
            return finalize(policy_pm_markdown(title, entry, kind="rsvp"), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_te_summary",
        title="Get Traffic-Engineering Summary",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_te_summary() -> str:
        """One-call traffic-engineering health check: SR policy, Tree-SID and RSVP-TE counts.

        Read-only. Reads the three list containers (``sr-policies``,
        ``p2mp-policies``, ``rsvp-te-tunnels`` on the topology NBI) and
        counts them: SR policies in total, UP, DOWN, PCE-controlled and by
        ``sr-policy-type`` (REGULAR, CIRCUIT-STYLE, BANDWIDTH-ON-DEMAND,
        LOCAL-CONGESTION-MITIGATION), plus the number of P2MP policies and
        RSVP-TE tunnels. Use it to answer "is TE healthy?" before drilling
        into cnc_list_sr_policies(oper_state='DOWN') or the get tools. Zero
        everywhere is a normal answer on a network without TE — or a sign the
        SR-PCE gRPC feed is down / the PCCs do not report (PCEP
        ``report-all``), so check cnc_list_providers when policies are
        expected. The per-object PM containers cannot be listed and are not
        part of the summary.

        Returns:
            str: JSON {"sr_policies": {"total": int, "up": int, "down": int,
            "pce_controlled": int, "by_type": {"<sr-policy-type>": int},
            "down_policies": ["<headend> -> <endpoint> color <n>", ...]},
            "p2mp_policies": int, "rsvp_te_tunnels": int, "summary": str}.
            "Error: ..." when any of the three reads fails.
        """
        try:
            policies, p2mp, tunnels = await asyncio.gather(
                get_container(SR_POLICIES_URL, SR_POLICY_MODULE, "policy"),
                get_container(P2MP_POLICIES_URL, P2MP_MODULE, "p2mp-policy"),
                get_container(RSVP_TUNNELS_URL, RSVP_MODULE, "rsvp-te-tunnel"),
            )
            sr = sr_policy_summary(policies)
            if sr["total"] == 0:
                sr_text = "no SR policies"
            elif sr["down"] == 0:
                sr_text = f"{sr['total']} SR policies, all UP"
            else:
                sr_text = f"{sr['total']} SR policies, {sr['down']} DOWN"
            summary = (
                f"{sr_text} ({sr['pce_controlled']} PCE-controlled); "
                f"{len(p2mp)} P2MP (Tree-SID) policies; {len(tunnels)} RSVP-TE tunnels."
            )
            payload = {
                "sr_policies": sr,
                "p2mp_policies": len(p2mp),
                "rsvp_te_tunnels": len(tunnels),
                "summary": summary,
            }
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)
