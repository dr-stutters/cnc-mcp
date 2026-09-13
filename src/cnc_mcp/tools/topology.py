"""Topology tools — the IETF network-topology view on the RESTCONF topology NBI.

Base :data:`cnc_mcp.restconf.TOPOLOGY_NBI` (``/crosswork/nbi/topology/v3/
restconf``), container ``ietf-network-state:networks`` (RFC 8345 network /
node / termination-point / link model with the IETF L3-unicast, L2, SR-MPLS
and Cisco Crosswork augmentations). Everything below was verified live on
Crosswork 7.2 on 2026-09-13 (see the platform notes, "Topology NBI"); this
module replaces the earlier one built on the UI-internal
``/crosswork/topology/v1/topology-service`` API, which is not a published API
and only ever showed the L2 links.

**Where the data comes from.** CNC 7.x learns the L3 topology from an SR-PCE
provider over the XR *service-layer gRPC* (LSLib server, port 57400) — the
provider needs both an HTTP (8080) and a GRPC (57400) ``connectivity_info``
entry and the credential profile a ``ROBOT_USERPASS_GRPC`` password. That feed
supplies the IS-IS nodes and adjacencies (link ids ending ``ISIS_IPV4_L2``),
the SR-MPLS data (SRGB/SRLB, MSD, prefix-SIDs, adjacency-SIDs), the IGP
metrics and bandwidths and the PCEP sessions. The L2 links (ids ending
``ETHERNET``) come from LLDP device collection through the Data Gateway and
exist without any SR-PCE. **A topology whose links are all ``ETHERNET`` means
the SR-PCE gRPC feed is not up** (provider missing, no GRPC endpoint, PCE not
running ``lslib-server`` / ``grpc ... service-layer`` / ``pce distribute
link-state``) — the inventory still fills and the devices stay reachable.
Device reachability, admin/oper state and collection status are NOT in this
view: read them with ``cnc_list_devices`` / ``cnc_get_device``; a topology
``node-id`` equals the inventory ``host_name``.

**Keys and encoding.** Every list key on this NBI — node ids, termination-point
ids (interface names such as ``GigabitEthernet0/0/0/0``) and link ids
(``"PE1 : GigabitEthernet0/0/0/0 : P1 : GigabitEthernet0/0/0/0 : ISIS_IPV4_L2"``,
spaces and colons included, listed once per direction) — is placed in the URL
through :func:`cnc_mcp.restconf.encode_key` (``quote(key, safe="")``). An
unencoded ``/`` breaks the route and the gateway answers a **plain 404** (no
RESTCONF error document); that 404 means "malformed URL" — or, for the same
bare answer from the home app, "NBI prefix not routed" — never "no such
object". Every keyed GET goes through ``keyed_get`` below, which turns such a
404 into :func:`plain_404_error` so the agent is never told the object is
missing (the generic 404 hint of :func:`cnc_mcp.errors.http_error` would say
exactly that).

**Not-found semantics.** A properly encoded key that matches nothing answers
``409`` with a bare-``errors`` RESTCONF document tagged ``data-missing``
(:func:`cnc_mcp.restconf.is_not_found`); the keyed tools turn that into
``Error: no <thing> '<key>' ...`` naming the list tool that shows the valid
keys. The network key is the exception: ``network=<unknown>`` answers the
WHOLE ``networks`` list with the key ignored, so the network is selected
client-side (:func:`select_by_field`) and an unknown id is reported as "no
network" from that check — but only when other networks ARE present. An empty
``networks`` container (``{}``, or the 204 the 7.2 OpenAPI documents for this
GET — a fresh instance before anything is discovered) is not an error: the
summary answers zeros and the list tools "No nodes / No links", each carrying
:data:`NO_NETWORKS_NOTE`. The ``node`` and ``link`` sub-lists cannot be listed
on their own (``400 missing-attribute``), so the list tools fetch the network
and filter / page client-side. A network without nodes or links is likewise a
normal "no nodes / no links" answer. Every request is a GET with
``Accept: application/yang-data+json``.

Member naming follows RFC 7951: a member is prefixed with its module only
where that differs from its parent's (``node-id``, ``tp-id``, ``link-id``,
``source``/``destination`` are bare; ``ietf-l3-unicast-topology-state:
l3-node-attributes``, ``ietf-sr-mpls-topology-state:sr-mpls``,
``cisco-crosswork-l3-te-topology:node-pcep-sessions`` are prefixed). The 7.2
OpenAPI documents prefix every member instead; :func:`field` accepts both, and
the client-side key re-selection (:func:`select_by_field`) is built on it, so
the tools survive either spelling.

NOT in scope of this module: SR / P2MP policies, RSVP-TE tunnels and the
per-link / per-policy performance metrics on the same NBI (their own modules).
"""

from __future__ import annotations

import re
from typing import Annotated, Any, NamedTuple

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import page_envelope
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.restconf import (
    TOPOLOGY_NBI,
    YANG_ACCEPT,
    encode_key,
    is_not_found,
    parse_restconf_errors,
    unwrap_list,
)
from cnc_mcp.safety import AppContext, register_tool

DEFAULT_NETWORK = "Default-network"
NETWORK_MODULE = "ietf-network-state"
TOPOLOGY_MODULE = "ietf-network-topology-state"
NETWORKS_URL = f"{TOPOLOGY_NBI}/data/{NETWORK_MODULE}:networks"

# Verbatim member names verified live (RFC 7951 prefixing — see the module docstring).
L3_TOPOLOGY_ATTRIBUTES = "ietf-l3-unicast-topology-state:l3-topology-attributes"
ISIS_TOPOLOGY_ATTRIBUTES = "cisco-crosswork-isis-topology:isis-topology-attributes"
TERMINATION_POINT = f"{TOPOLOGY_MODULE}:termination-point"
TP_ATTRIBUTES = "cisco-crosswork-topology-state:termination-point-attributes"
L3_NODE_ATTRIBUTES = "ietf-l3-unicast-topology-state:l3-node-attributes"
ISIS_NODE_ATTRIBUTES = "cisco-crosswork-isis-topology:isis-node-attributes"
SR_MPLS = "ietf-sr-mpls-topology-state:sr-mpls"
PCEP_SESSIONS = "cisco-crosswork-l3-te-topology:node-pcep-sessions"
LINK = f"{TOPOLOGY_MODULE}:link"
L3_LINK_ATTRIBUTES = "ietf-l3-unicast-topology-state:l3-link-attributes"
TE_LINK_ATTRIBUTES = "cisco-crosswork-l3-te-topology:l3-link-attributes"
ISIS_LINK_ATTRIBUTES = "cisco-crosswork-isis-topology:isis-link-attributes"
L2_LINK_ATTRIBUTES = "ietf-l2-topology-state:l2-link-attributes"

# The link-id suffix names the link's type (verified: exactly these two on the lab).
LINK_ID_SEPARATOR = " : "
LINK_TYPE_ISIS = "ISIS_IPV4_L2"
LINK_TYPE_ETHERNET = "ETHERNET"
LINK_TYPES = ("all", "isis", "ethernet", "other")
_LINK_TYPE_CHOICES = ", ".join(LINK_TYPES)

_NETWORK_FIELD = Field(
    description=(
        f"Topology network id (e.g. '{DEFAULT_NETWORK}', the only network on a standard "
        "deployment)."
    ),
    min_length=1,
    max_length=200,
)
_FORMAT_FIELD = Field(
    description="'markdown' for human-readable output, 'json' for the raw platform objects."
)

_L2_ONLY_NOTE = (
    "Every link is ETHERNET (L2, from LLDP collection) and no IS-IS/SR data is present: the "
    "SR-PCE gRPC feed is not up. Check the SR-PCE provider (cnc_list_providers: it needs an "
    "HTTP 8080 and a GRPC 57400 connectivity entry, both reachable) and that the PCE runs "
    "lslib-server, 'grpc ... service-layer' and 'pce distribute link-state'."
)
# The networks container answered empty ({} or 204): a fresh instance, not a failure.
NO_NETWORKS_NOTE = (
    "the topology NBI reports no networks yet - the networks container is populated once "
    "devices are onboarded and collected (L2 links, via LLDP) and the SR-PCE gRPC feed is up "
    "(L3 nodes and links). Check onboarding with cnc_list_devices and the SR-PCE provider "
    "with cnc_list_providers."
)


class FetchedNetwork(NamedTuple):
    """One ``network`` entry plus the note explaining an empty ``networks`` container.

    ``note`` is :data:`NO_NETWORKS_NOTE` when the NBI reported no networks at
    all — ``network`` is then a placeholder ``{"network-id": <requested id>}``
    so the callers count zeros — and ``None`` when the entry is real.
    """

    network: dict[str, Any]
    note: str | None


def plain_404_error(url: str) -> PlatformError:
    """The explanation for a 404 that carries no RESTCONF error document.

    Verified live on this NBI: an unencoded ``/`` in a list key breaks the
    route and the gateway answers a plain 404 — "malformed URL", never "no
    such object" (that is spelled ``409 data-missing``). The home app answers
    the same bare 404 when the NBI prefix is not routed at all. Either way the
    generic "Resource not found. Check that the ID or name is correct" hint of
    :func:`cnc_mcp.errors.http_error` would mislead the agent, so ``keyed_get``
    raises this instead. The message keeps the ``API request failed with
    status 404.`` prefix every other API failure carries.
    """
    return PlatformError(
        f"API request failed with status 404. The topology NBI answered a plain 404 (no "
        f"RESTCONF error document) for GET {url}: on this gateway that means the URL is "
        "malformed or the NBI prefix is not routed, NOT that the object is missing (a "
        "properly encoded key that matches nothing answers 409 data-missing). The key was "
        f"sent percent-encoded; check that {TOPOLOGY_NBI} is routed on this instance and "
        "that the data path matches this build's YANG model."
    )


# --- URL builders -------------------------------------------------------------


def network_url(network: str) -> str:
    """``.../networks/network=<id>`` (the id percent-encoded as one list key)."""
    return f"{NETWORKS_URL}/network={encode_key(network)}"


def node_url(network: str, node_id: str) -> str:
    """``.../network=<id>/node=<node-id>`` — answers a list of one node."""
    return f"{network_url(network)}/node={encode_key(node_id)}"


def termination_point_url(network: str, node_id: str, tp_id: str) -> str:
    """``.../node=<node-id>/ietf-network-topology-state:termination-point=<tp-id>``.

    Interface names carry ``/`` and MUST be encoded (``GigabitEthernet0%2F0%2F0%2F0``).
    """
    return f"{node_url(network, node_id)}/{TERMINATION_POINT}={encode_key(tp_id)}"


def link_url(network: str, link_id: str) -> str:
    """``.../network=<id>/ietf-network-topology-state:link=<link-id>`` (spaces, colons and
    slashes in the id percent-encoded)."""
    return f"{network_url(network)}/{LINK}={encode_key(link_id)}"


# --- YANG-JSON accessors (pure functions) ------------------------------------


def field(obj: Any, key: str, default: Any = None) -> Any:
    """A YANG-JSON member by its verbatim key, tolerating the module-prefix variants.

    RFC 7951 prefixes a member only where its module differs from the parent's
    (verified live: ``node-id`` and ``tp-id`` are bare while
    ``ietf-sr-mpls-topology-state:sr-mpls`` is prefixed), whereas the 7.2
    OpenAPI documents prefix every member. The lookup tries ``key`` as given,
    then its bare local name, then any ``<module>:<local name>`` member, so a
    build that spells a prefix differently degrades to nothing worse than the
    same value. Non-dict ``obj`` → ``default``.
    """
    if not isinstance(obj, dict):
        return default
    if key in obj:
        return obj[key]
    local = key.rsplit(":", 1)[-1]
    if local in obj:
        return obj[local]
    suffix = f":{local}"
    for name, value in obj.items():
        if isinstance(name, str) and name.endswith(suffix):
            return value
    return default


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    """A list as-is, a lone dict wrapped, anything else → []."""
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def dict_items(value: Any) -> list[dict[str, Any]]:
    return [item for item in as_list(value) if isinstance(item, dict)]


def select_by_field(items: Any, key_field: str, key: str) -> list[dict[str, Any]]:
    """Client-side exact, case-sensitive key filter tolerant of the module-prefix spellings.

    The topology NBI ignores a key on the top-level ``network`` list and may
    answer a keyed GET with a different entry, so every keyed answer is
    re-matched here. Unlike :func:`cnc_mcp.restconf.select_key`, which reads the
    member by its bare name only, the value is looked up through :func:`field`,
    so a build that spells the key ``ietf-network-state:node-id`` (the 7.2
    OpenAPI form) matches like the live bare ``node-id``. A non-string stored
    value matches its string form (URL keys are always strings); non-dict items
    are dropped.
    """
    matches: list[dict[str, Any]] = []
    for item in dict_items(items):
        value = field(item, key_field)
        if value is None or isinstance(value, (dict, list)):
            continue
        if value == key or str(value) == key:
            matches.append(item)
    return matches


def node_id_matches(pattern: str, node_id: Any) -> bool:
    """Case-insensitive exact match where ``*`` in ``pattern`` is a wildcard.

    Same semantics as the inventory filters (exact, case-insensitive, ``*``
    anywhere) so agents get one behaviour across the server; ``?`` and ``%``
    are literal characters.
    """
    if not isinstance(node_id, str):
        return False
    regex = ".*".join(re.escape(part) for part in pattern.strip().split("*"))
    return re.fullmatch(regex, node_id, re.IGNORECASE) is not None


def link_type_of(link_id: Any) -> str:
    """The type suffix of a link id: what follows the last ``" : "`` (``''`` when absent)."""
    if not isinstance(link_id, str):
        return ""
    _head, sep, tail = link_id.rpartition(LINK_ID_SEPARATOR)
    return tail.strip() if sep else ""


def classify_link(link_id: Any) -> str:
    """``'isis'`` for an ``ISIS_IPV4_L2`` id, ``'ethernet'`` for ``ETHERNET``, else ``'other'``."""
    kind = link_type_of(link_id).upper()
    if kind == LINK_TYPE_ISIS:
        return "isis"
    if kind == LINK_TYPE_ETHERNET:
        return "ethernet"
    return "other"


def normalize_link_type(link_type: str) -> str:
    """'ISIS' / ' ethernet ' -> the LINK_TYPES entry; PlatformError when unknown."""
    key = link_type.strip().lower()
    if key not in LINK_TYPES:
        raise PlatformError(
            f"Unknown link_type '{link_type}'. Use one of: {_LINK_TYPE_CHOICES} "
            f"('isis' = link ids ending {LINK_TYPE_ISIS}, 'ethernet' = ids ending "
            f"{LINK_TYPE_ETHERNET}, 'other' = any other suffix)."
        )
    return key


# Nodes ------------------------------------------------------------------------


def node_id_of(node: dict[str, Any]) -> str:
    return str(field(node, "node-id") or "?")


def node_l3(node: dict[str, Any]) -> dict[str, Any]:
    """The node's ``l3-node-attributes`` (``{}`` for an L2-only node)."""
    return as_dict(field(node, L3_NODE_ATTRIBUTES))


def node_termination_points(node: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(node, TERMINATION_POINT))


def router_ids(l3: dict[str, Any]) -> list[str]:
    return [str(r) for r in as_list(field(l3, "router-id"))]


def isis_of(l3: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(l3, ISIS_NODE_ATTRIBUTES))


def sr_mpls_of(l3: dict[str, Any]) -> dict[str, Any] | None:
    """The ``sr-mpls`` presence container, or None when the node advertises no SR."""
    value = field(l3, SR_MPLS)
    return value if isinstance(value, dict) else None


def prefixes_of(l3: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(l3, "prefix"))


def prefix_sids_of(prefix: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(prefix, SR_MPLS))


def srgb_lower_bound(l3: dict[str, Any]) -> int | None:
    """The first SRGB block's ``lower-bound`` (16000 on the lab), or None."""
    sr = sr_mpls_of(l3)
    for block in dict_items(field(sr, "srgb") if sr else None):
        lower = field(block, "lower-bound")
        try:
            return int(lower)
        except (TypeError, ValueError):
            continue
    return None


def prefix_sid_label(entry: dict[str, Any], srgb_lower: int | None) -> int | None:
    """The absolute MPLS label of one prefix-SID entry, or None.

    Verified live: the feed publishes prefix-SIDs as
    ``{"value-type": "index", "start-sid": 4, "range": 1, "algorithm-value": 0,
    ...}`` — an INDEX into the SRGB, so the label is ``srgb.lower-bound +
    start-sid`` (16000 + 4 = 16004, the value the PCE expects in
    ``node-ipv4-sid``). ``value-type: "absolute"`` carries the label itself in
    ``start-sid``. A bare ``sid`` key (the OpenAPI spelling) is accepted as an
    absolute label too. An index without a known SRGB yields None.
    """
    for key in ("start-sid", "sid"):
        raw = field(entry, key)
        if raw is None:
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        kind = str(field(entry, "value-type") or ("absolute" if key == "sid" else "index"))
        if kind.lower() == "absolute":
            return value
        return srgb_lower + value if srgb_lower is not None else None
    return None


def prefix_sid_count(l3: dict[str, Any]) -> int:
    """How many of the node's prefixes carry SR-MPLS SID entries."""
    return sum(1 for p in prefixes_of(l3) if prefix_sids_of(p))


def pcep_sessions_of(l3: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(l3, PCEP_SESSIONS))


def _ranges_text(ranges: Any) -> str:
    """``[{lower-bound, upper-bound}]`` -> ``16000-23999`` (several joined by ','; '-' if none)."""
    parts = []
    for block in dict_items(ranges):
        lower, upper = field(block, "lower-bound"), field(block, "upper-bound")
        if lower is None and upper is None:
            continue
        parts.append(f"{lower if lower is not None else '?'}-{upper if upper is not None else '?'}")
    return ",".join(parts) or "-"


def _isis_text(l3: dict[str, Any]) -> str:
    entries = [
        f"{field(e, 'level', '?')}/{field(e, 'system-id', '?')}"
        for e in isis_of(l3)
        if field(e, "level") is not None or field(e, "system-id") is not None
    ]
    return ",".join(entries) or "-"


def node_line(node: dict[str, Any]) -> str:
    """One markdown line for a node (the list tool's row; '-' where an attribute is absent)."""
    l3 = node_l3(node)
    sr = sr_mpls_of(l3)
    msd = field(sr, "msd") if sr is not None else None
    return (
        f"- **{node_id_of(node)}** router-id={','.join(router_ids(l3)) or '-'} "
        f"isis={_isis_text(l3)} srgb={_ranges_text(field(sr, 'srgb')) if sr else '-'} "
        f"msd={msd if msd is not None else '-'} prefix-sids={prefix_sid_count(l3)} "
        f"pcep={len(pcep_sessions_of(l3))} tps={len(node_termination_points(node))}"
    )


# Termination points -----------------------------------------------------------


def tp_id_of(tp: dict[str, Any]) -> str:
    return str(field(tp, "tp-id") or "?")


def tp_ip_addresses(tp: dict[str, Any]) -> list[str]:
    """Every IP address on a termination point, from any of the containers that carry one.

    Verified live under ``cisco-crosswork-topology-state:termination-point-attributes``:
    ``l3-termination-point-attributes.ip-address[]`` plus the per-family
    ``ipv4-`` / ``ipv6-termination-point-attributes.l3-termination-point-attributes``;
    the documented plain ``ietf-l3-unicast-topology-state:l3-termination-point-attributes``
    on the TP itself is read too. Duplicates are dropped, order kept.
    """
    attrs = as_dict(field(tp, TP_ATTRIBUTES))
    containers = [
        field(attrs, "l3-termination-point-attributes"),
        field(
            as_dict(field(attrs, "ipv4-termination-point-attributes")),
            "l3-termination-point-attributes",
        ),
        field(
            as_dict(field(attrs, "ipv6-termination-point-attributes")),
            "l3-termination-point-attributes",
        ),
        field(tp, "ietf-l3-unicast-topology-state:l3-termination-point-attributes"),
    ]
    addresses: list[str] = []
    for container in containers:
        for address in as_list(field(as_dict(container), "ip-address")):
            text = str(address)
            if text not in addresses:
                addresses.append(text)
    return addresses


def tp_l2(tp: dict[str, Any]) -> dict[str, Any]:
    """The TP's L2 attributes (Crosswork's container first, the documented IETF one after)."""
    attrs = as_dict(field(tp, TP_ATTRIBUTES))
    return as_dict(field(attrs, "l2-termination-point-attributes")) or as_dict(
        field(tp, "ietf-l2-topology-state:l2-termination-point-attributes")
    )


def tp_summary(tp: dict[str, Any]) -> dict[str, Any]:
    """The curated view of one termination point (what the markdown lines show)."""
    l2 = tp_l2(tp)
    return {
        "tp-id": tp_id_of(tp),
        "ip-address": tp_ip_addresses(tp),
        "mac-address": field(l2, "mac-address"),
        "unnumbered-id": [str(u) for u in as_list(field(l2, "unnumbered-id"))],
        "encapsulation": field(l2, "encapsulation-type"),
    }


def tp_line(tp: dict[str, Any]) -> str:
    s = tp_summary(tp)
    return (
        f"- {s['tp-id']} ip={','.join(s['ip-address']) or '-'} mac={s['mac-address'] or '-'} "
        f"unnumbered={','.join(s['unnumbered-id']) or '-'} encap={s['encapsulation'] or '-'}"
    )


# Links ------------------------------------------------------------------------


def link_id_of(link: dict[str, Any]) -> str:
    return str(field(link, "link-id") or "?")


def link_ends(link: dict[str, Any]) -> tuple[str, str, str, str]:
    """``(source-node, source-tp, dest-node, dest-tp)`` ('?' where absent)."""
    source = as_dict(field(link, "source"))
    destination = as_dict(field(link, "destination"))
    return (
        str(field(source, "source-node") or "?"),
        str(field(source, "source-tp") or "?"),
        str(field(destination, "dest-node") or "?"),
        str(field(destination, "dest-tp") or "?"),
    )


def link_touches(link: dict[str, Any], node_id: str) -> bool:
    """True when ``node_id`` (case-insensitive, exact) is either end of the link."""
    src, _src_tp, dst, _dst_tp = link_ends(link)
    wanted = node_id.strip().lower()
    return src.lower() == wanted or dst.lower() == wanted


def link_l3(link: dict[str, Any]) -> dict[str, Any]:
    return as_dict(field(link, L3_LINK_ATTRIBUTES))


def link_l2(link: dict[str, Any]) -> dict[str, Any]:
    return as_dict(field(link, L2_LINK_ATTRIBUTES))


def adjacency_sids(l3: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(as_dict(field(l3, SR_MPLS)), "sids"))


def _scalars_text(attrs: dict[str, Any]) -> str:
    """``k=v`` for every scalar member (nested containers/lists skipped), '-' when none."""
    parts = [
        f"{str(k).rsplit(':', 1)[-1]}={v}"
        for k, v in attrs.items()
        if not isinstance(v, (dict, list))
    ]
    return " ".join(parts) or "-"


def link_line(link: dict[str, Any]) -> str:
    """One markdown line for a link: endpoints, [type], then the L3 or L2 essentials."""
    src, src_tp, dst, dst_tp = link_ends(link)
    kind = link_type_of(link_id_of(link)) or "?"
    head = f"- {src}:{src_tp} -> {dst}:{dst_tp} [{kind}]"
    l3 = link_l3(link)
    if l3:
        te = as_dict(field(l3, TE_LINK_ATTRIBUTES))
        sids = ",".join(str(field(s, "sid")) for s in adjacency_sids(l3) if field(s, "sid"))
        metric = field(l3, "metric1")
        bandwidth = field(te, "max-bandwidth-kbps")
        return (
            f"{head} metric={metric if metric is not None else '-'} adj-sid={sids or '-'} "
            f"bw={f'{bandwidth}kbps' if bandwidth is not None else '-'}"
        )
    l2 = link_l2(link)
    return f"{head} {_scalars_text(l2)}" if l2 else f"{head} (no attributes)"


# Network ----------------------------------------------------------------------


def network_id_of(network: dict[str, Any]) -> str:
    return str(field(network, "network-id") or "?")


def network_nodes(network: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(network, "node"))


def network_links(network: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(network, LINK))


def isis_area_of(network: dict[str, Any]) -> str | None:
    topo = as_dict(field(network, L3_TOPOLOGY_ATTRIBUTES))
    area = field(as_dict(field(topo, ISIS_TOPOLOGY_ATTRIBUTES)), "area")
    if area is None:
        return None
    return ",".join(str(a) for a in area) if isinstance(area, list) else str(area)


def summarize_network(network: dict[str, Any]) -> dict[str, Any]:
    """The cnc_get_topology_summary payload for one network object."""
    nodes = network_nodes(network)
    links = network_links(network)
    kinds = {"isis": 0, "ethernet": 0, "other": 0}
    for link in links:
        kinds[classify_link(link_id_of(link))] += 1
    l3s = [node_l3(n) for n in nodes]
    summary: dict[str, Any] = {
        "network_id": network_id_of(network),
        "isis_area": isis_area_of(network),
        "nodes": len(nodes),
        "links": {
            "total": len(links),
            "isis_ipv4_l2": kinds["isis"],
            "ethernet": kinds["ethernet"],
            "other": kinds["other"],
        },
        "sr_capable_nodes": sum(1 for l3 in l3s if sr_mpls_of(l3) is not None),
        "pcep_session_nodes": sum(1 for l3 in l3s if pcep_sessions_of(l3)),
        "prefix_sids": sum(prefix_sid_count(l3) for l3 in l3s),
        "termination_points": sum(len(node_termination_points(n)) for n in nodes),
    }
    if links and kinds["isis"] == 0 and kinds["other"] == 0 and summary["sr_capable_nodes"] == 0:
        summary["note"] = _L2_ONLY_NOTE
    return summary


# --- Markdown renderers ---------------------------------------------------------


def _paging_note(envelope: dict[str, Any]) -> list[str]:
    if envelope["has_more"]:
        return ["", f"More available: repeat with page={envelope['next_page']}."]
    return []


def _nodes_markdown(
    network_id: str,
    nodes: list[dict[str, Any]],
    envelope: dict[str, Any],
    filtered: bool,
    note: str | None = None,
) -> str:
    lines = [
        f"# Topology nodes in {network_id} ({envelope['count']} shown, matching "
        f"{envelope['total']}, collection {envelope['collection_total']}; page {envelope['page']})",
        "",
    ]
    if note:
        lines.append(f"No nodes: {note}")
    elif not envelope["collection_total"]:
        lines.append(
            f"No nodes: the platform reports none for network '{network_id}'. Nodes appear "
            "once devices are onboarded and collected (L2) or reported by the SR-PCE feed (L3)."
        )
    elif not nodes and filtered:
        lines.append("No nodes matched the filter (name is exact, case-insensitive, '*' wildcard).")
    lines.extend(node_line(n) for n in nodes)
    lines.extend(_paging_note(envelope))
    lines.append("")
    lines.append(
        "node-id = inventory host_name; reachability and collection state are in "
        "cnc_list_devices. Details per node: cnc_get_topology_node."
    )
    return "\n".join(lines)


def _node_markdown(network_id: str, node: dict[str, Any]) -> str:
    l3 = node_l3(node)
    lines = [f"# Topology node {node_id_of(node)} (network {network_id})", "", node_line(node), ""]
    if not l3:
        lines.append(
            "No L3 node attributes: this node is known from L2 (LLDP) discovery only — the "
            "SR-PCE gRPC feed has not reported it (see cnc_get_topology_summary)."
        )
    else:
        lines.append(f"Router IDs: {', '.join(router_ids(l3)) or '-'}")
        isis = isis_of(l3)
        if isis:
            lines.append(
                "IS-IS: "
                + "; ".join(
                    f"level {field(e, 'level', '?')} system-id {field(e, 'system-id', '?')}"
                    for e in isis
                )
            )
        sr = sr_mpls_of(l3)
        if sr is not None:
            msd = field(sr, "msd")
            lines.append(
                f"SR-MPLS: srgb={_ranges_text(field(sr, 'srgb'))} "
                f"srlb={_ranges_text(field(sr, 'srlb'))} msd={msd if msd is not None else '-'}"
            )
        prefixes = prefixes_of(l3)
        lines.append(f"Prefixes ({len(prefixes)}, {prefix_sid_count(l3)} with SR-MPLS SIDs):")
        if not prefixes:
            lines.append("- (none)")
        for prefix in prefixes:
            sids = prefix_sids_of(prefix)
            if sids:
                srgb_lower = srgb_lower_bound(l3)
                sid_text = ", ".join(
                    f"sid {prefix_sid_label(s, srgb_lower) or '?'} "
                    f"({field(s, 'value-type', '?')} "
                    f"{field(s, 'start-sid', field(s, 'sid', '?'))}) "
                    f"algorithm {field(s, 'algorithm-value', '?')}"
                    for s in sids
                )
            else:
                sid_text = "no SID"
            lines.append(f"- {field(prefix, 'prefix', '?')} -> {sid_text}")
        sessions = pcep_sessions_of(l3)
        lines.append(f"PCEP sessions ({len(sessions)}):")
        if not sessions:
            lines.append("- (none)")
        for s in sessions:
            lines.append(
                f"- pcc {field(s, 'pcc-address', '?')} -> pce {field(s, 'pce-address', '?')} "
                f"stateful={field(s, 'stateful', '?')} sr={field(s, 'capability-sr', '?')} "
                f"update={field(s, 'capability-update', '?')} "
                f"instantiate={field(s, 'capability-instantiate', '?')} msd={field(s, 'msd', '?')}"
            )
    tps = node_termination_points(node)
    lines.append(f"Termination points ({len(tps)}):")
    if not tps:
        lines.append("- (none)")
    lines.extend(tp_line(tp) for tp in tps)
    return "\n".join(lines)


def _interfaces_markdown(network_id: str, node_id: str, tps: list[dict[str, Any]]) -> str:
    lines = [f"# Interfaces of {node_id} in {network_id} ({len(tps)} termination points)", ""]
    if not tps:
        lines.append(f"No termination points: the platform reports none for node '{node_id}'.")
    lines.extend(tp_line(tp) for tp in tps)
    lines.append("")
    lines.append(
        "tp-id is the interface name; pass it verbatim to cnc_get_node_interface. IPs come "
        "from the L3 feed, MAC/unnumbered-id/encapsulation from L2 collection."
    )
    return "\n".join(lines)


def _interface_markdown(network_id: str, node_id: str, tp: dict[str, Any]) -> str:
    lines = [f"# Interface {tp_id_of(tp)} on {node_id} (network {network_id})", "", tp_line(tp)]
    attrs = field(tp, TP_ATTRIBUTES)
    if isinstance(attrs, dict) and attrs:
        lines.extend(["", "Attributes as the platform reports them:", to_json(attrs)])
    return "\n".join(lines)


def _links_markdown(
    network_id: str,
    links: list[dict[str, Any]],
    envelope: dict[str, Any],
    link_type: str,
    node: str | None,
    note: str | None = None,
) -> str:
    scope = f"link_type={link_type}" + (f" node={node}" if node else "")
    lines = [
        f"# Topology links in {network_id} ({envelope['count']} shown, matching "
        f"{envelope['total']}, collection {envelope['collection_total']}; page {envelope['page']}; "
        f"{scope})",
        "",
    ]
    if note:
        lines.append(f"No links: {note}")
    elif not envelope["collection_total"]:
        lines.append(
            f"No links: the platform reports none for network '{network_id}'. L3 "
            f"({LINK_TYPE_ISIS}) links need the SR-PCE gRPC feed; L2 ({LINK_TYPE_ETHERNET}) "
            "links need LLDP collection of the devices."
        )
    elif not links:
        lines.append(f"No links matched {scope}.")
    lines.extend(link_line(link) for link in links)
    lines.extend(_paging_note(envelope))
    lines.append("")
    lines.append(
        "Links are listed once per direction (A->B and B->A are two entries). Link ids are "
        "'<src> : <srcIf> : <dst> : <dstIf> : <TYPE>'; cnc_get_topology_link takes them verbatim."
    )
    return "\n".join(lines)


def _link_markdown(network_id: str, link: dict[str, Any]) -> str:
    src, src_tp, dst, dst_tp = link_ends(link)
    lines = [
        f"# Topology link (network {network_id})",
        "",
        link_line(link),
        "",
        f"link-id: {link_id_of(link)}",
        f"source: {src} / {src_tp}",
        f"destination: {dst} / {dst_tp}",
    ]
    l3 = link_l3(link)
    if l3:
        te = as_dict(field(l3, TE_LINK_ATTRIBUTES))
        isis = as_dict(field(l3, ISIS_LINK_ATTRIBUTES))
        sr = as_dict(field(l3, SR_MPLS))
        lines.append(
            f"L3: name={field(l3, 'name', '-')} metric1={field(l3, 'metric1', '-')} "
            f"metric2={field(l3, 'metric2', '-')} domain-id={field(te, 'domain-id', '-')} "
            f"max-bandwidth-kbps={field(te, 'max-bandwidth-kbps', '-')}"
        )
        if isis:
            net = as_dict(field(isis, "net"))
            lines.append(
                f"IS-IS: level={field(isis, 'level', '-')} system-id={field(net, 'system-id', '-')}"
            )
        if sr:
            lines.append(
                f"SR-MPLS: advertise-protection={field(sr, 'advertise-protection', '-')} "
                f"information-source={field(sr, 'information-source', '-')}"
            )
        sids = adjacency_sids(l3)
        lines.append(f"Adjacency SIDs ({len(sids)}):")
        if not sids:
            lines.append("- (none)")
        for s in sids:
            lines.append(
                f"- {field(s, 'sid', '?')} backup={field(s, 'is-backup', '?')} "
                f"persistent={field(s, 'is-persistent', '?')} local={field(s, 'is-local', '?')} "
                f"address-family={field(s, 'address-family', '?')} "
                f"value-type={field(s, 'value-type', '?')}"
            )
    l2 = link_l2(link)
    if l2:
        lines.extend(["L2 attributes as the platform reports them:", to_json(l2)])
    if not l3 and not l2:
        lines.append("The platform reports no L2 or L3 attributes for this link.")
    return "\n".join(lines)


# --- Registration ----------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def keyed_get(url: str, missing: PlatformError) -> Any:
        """GET one keyed RESTCONF entry (network, node, termination point or link).

        ``missing`` is raised for the platform's not-found spelling — 409
        ``data-missing`` (:func:`is_not_found`). A 404 WITHOUT a RESTCONF error
        document raises :func:`plain_404_error`: on this gateway it means the
        URL is malformed or the NBI prefix is not routed, never that the object
        is absent, and the generic 404 hint would say the opposite. Every other
        failure raises :func:`http_error` with its explanation. A 204 / empty
        body answers ``None`` (an empty container).
        """
        response = await client.request("GET", url, headers=YANG_ACCEPT, raise_on_error=False)
        data: Any = None
        if response.content:
            try:
                data = response.json()
            except ValueError:
                data = None
        if is_not_found(response.status_code, data):
            raise missing
        if response.status_code == 404 and not parse_restconf_errors(data):
            raise plain_404_error(url)
        if not response.is_success:
            raise http_error(response)
        if response.content and data is None:
            raise PlatformError(
                "The topology NBI returned a non-JSON response where YANG JSON was expected."
            )
        return data

    def missing_network(network: str) -> PlatformError:
        return PlatformError(
            f"no network '{network}' on the topology NBI (it answered 409 data-missing for the "
            f"key). The default is '{DEFAULT_NETWORK}'."
        )

    async def fetch_network(network: str) -> FetchedNetwork:
        """The one ``network`` entry for ``network``, from the COLLECTION GET.

        Verified live (2026-09-13): the keyed ``network=<id>`` GET answers a
        SHALLOW copy — nodes carry only ``name``/``router-id`` and the
        ``l3-topology-attributes`` are absent — while the unkeyed
        ``networks`` collection GET carries the full node attributes (IS-IS,
        SRGB/MSD, prefix-SIDs, PCEP sessions) and the topology attributes. So
        the collection is fetched and the id selected client-side (the same
        select_by_field the NBI's key-ignoring behaviour needs anyway): "no
        network" is an error only when OTHER networks are present. An empty
        container (``{}`` / 204 — nothing discovered yet) is answered as a
        placeholder entry with :data:`NO_NETWORKS_NOTE`, so the callers report
        zeros / "No nodes" rather than an error.
        """
        key = network.strip()
        data = await keyed_get(NETWORKS_URL, missing_network(key))
        networks = unwrap_list(data, NETWORK_MODULE, "network")
        matches = select_by_field(networks, "network-id", key)
        if matches:
            return FetchedNetwork(matches[0], None)
        present = [network_id_of(n) for n in networks if isinstance(n, dict)]
        if present:
            raise PlatformError(
                f"no network '{key}' on the topology NBI (the platform answers an unknown "
                f"network id with the whole list, so the id was checked client-side). Networks "
                f"present: {', '.join(present)}. The default is '{DEFAULT_NETWORK}'."
            )
        return FetchedNetwork({"network-id": key}, NO_NETWORKS_NOTE)

    def missing_node(node_id: str, network: str) -> PlatformError:
        return PlatformError(
            f"no node '{node_id}' in topology '{network}'. Node ids are the inventory host names, "
            "exact and case-sensitive; list them with cnc_list_topology_nodes."
        )

    async def fetch_node(network: str, node_id: str) -> dict[str, Any]:
        key = node_id.strip()
        data = await keyed_get(node_url(network, key), missing_node(key, network))
        nodes = select_by_field(unwrap_list(data, NETWORK_MODULE, "node"), "node-id", key)
        if not nodes:
            raise missing_node(key, network)
        return nodes[0]

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_topology_summary",
        title="Get Topology Summary",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_topology_summary(
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
    ) -> str:
        """Summarize one topology network: node and link counts by type, SR/PCEP coverage.

        Read-only. One ``GET /crosswork/nbi/topology/v3/restconf/data/
        ietf-network-state:networks/network=<id>`` (``Accept: application/
        yang-data+json``), then counted client-side. Use it first to learn
        whether the topology is populated and WHICH feed populated it:

        - ``links.isis_ipv4_l2`` > 0, ``sr_capable_nodes`` > 0, ``prefix_sids``
          > 0: the SR-PCE gRPC feed is up and the L3 view (IS-IS adjacencies,
          SR-MPLS, IGP metrics, PCEP sessions) is available.
        - links are ALL ``ethernet`` (``isis_ipv4_l2`` = 0, ``sr_capable_nodes``
          = 0): only LLDP (L2) collection is feeding the topology — **the
          SR-PCE gRPC feed is not up** (no SR-PCE provider, no GRPC 57400
          connectivity entry / ROBOT_USERPASS_GRPC credential, or the PCE not
          running lslib-server, 'grpc ... service-layer' and 'pce distribute
          link-state'). The answer carries a ``note`` saying so. Check the
          provider with cnc_list_providers.
        - 0 nodes: nothing has been discovered yet — check onboarding and
          collection with cnc_list_devices. When the NBI has no networks at
          all (an empty container: a fresh instance) every count is 0 and the
          ``note`` says so; that is not an error.

        Device reachability / admin / oper state are not part of the topology
        model: read them with cnc_list_devices (node-id = host_name).

        Args:
            network: topology network id (default 'Default-network').

        Returns:
            str: JSON {"network_id": str, "isis_area": str|null,
            "nodes": int, "links": {"total": int, "isis_ipv4_l2": int,
            "ethernet": int, "other": int} (classified by the link-id suffix
            after the last ' : '), "sr_capable_nodes": int (nodes advertising
            ietf-sr-mpls-topology-state:sr-mpls), "pcep_session_nodes": int
            (nodes with node-pcep-sessions), "prefix_sids": int (prefix
            entries carrying SR-MPLS SIDs), "termination_points": int,
            "note"?: str (present when the topology is L2-only, or when the
            NBI reports no networks yet — then every count is 0)}. A network
            without nodes or links answers zeros, not an error. "Error: no
            network '<id>' ..." when the id is unknown but other networks
            exist (the NBI answers the whole list, checked client-side);
            "Error: ..." on an API failure (400 unknown-element -> the data
            path is wrong for this build; a plain 404 -> the NBI prefix is not
            routed or the URL is malformed, never a missing object).
        """
        try:
            fetched = await fetch_network(network)
            summary = summarize_network(fetched.network)
            if fetched.note:
                summary["note"] = fetched.note
            return finalize(to_json(summary), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_topology_nodes",
        title="List Topology Nodes",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_topology_nodes(
        name: Annotated[
            str | None,
            Field(
                description=(
                    "node-id filter (= inventory host_name), applied client-side: exact match, "
                    "case-insensitive, '*' wildcard (e.g. 'PE1' or 'pe*')."
                ),
                max_length=253,
            ),
        ] = None,
        sr_only: Annotated[
            bool,
            Field(
                description=(
                    "true to keep only nodes advertising SR-MPLS (ietf-sr-mpls-topology-state:"
                    "sr-mpls under their L3 node attributes)."
                )
            ),
        ] = False,
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        page_size: Annotated[
            int, Field(description="Nodes per page, client-side (e.g. 50).", ge=1, le=500)
        ] = 50,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the nodes of a topology network with their IS-IS / SR-MPLS essentials.

        Read-only. The ``node`` sub-list cannot be listed on its own (the NBI
        answers 400 missing-attribute), so the whole network is fetched
        (``GET .../ietf-network-state:networks/network=<id>``) and the nodes
        are filtered and paged client-side; every call re-downloads the
        network. A node is a router the topology knows: ``node-id`` equals the
        inventory ``host_name``. Nodes reported by the SR-PCE feed carry
        ``ietf-l3-unicast-topology-state:l3-node-attributes`` (router-id,
        IS-IS level/system-id, SR-MPLS SRGB/SRLB/MSD, prefix-SIDs, PCEP
        sessions); nodes known from LLDP collection only have termination
        points and no L3 attributes — they are listed all the same, with '-'
        in the L3 columns. For reachability use cnc_list_devices.

        Args:
            name: node-id filter, exact / case-insensitive / '*' wildcard.
            sr_only: keep only SR-MPLS-capable nodes.
            network: topology network id.
            page_size, page: client-side paging (page is 0-based).
            response_format: markdown (one line per node: "**<node-id>**
                router-id=<ids> isis=<level>/<system-id> srgb=<lower>-<upper>
                msd=<msd> prefix-sids=<n> pcep=<sessions> tps=<n>") or json
                (the raw node objects).

        Returns:
            str: Markdown, or JSON {"network_id": str, "total": int (matches),
            "count": int, "page": int, "page_size": int, "has_more": bool,
            "next_page": int|null, "collection_total": int (nodes in the
            network), "items": [<node as the NBI returns it: {"node-id",
            "ietf-network-topology-state:termination-point": [...],
            "ietf-l3-unicast-topology-state:l3-node-attributes"?: {...}}],
            "note"?: str (the NBI reports no networks yet)}. "No nodes ..."
            (not an error) when the network has none, nothing matches, or
            the NBI has no networks at all. "Error: no network '<id>' ..."
            for an unknown network when other networks exist; "Error: ..."
            on an API failure.
        """
        try:
            fetched = await fetch_network(network)
            network_obj = fetched.network
            network_id = network_id_of(network_obj)
            all_nodes = network_nodes(network_obj)
            nodes = all_nodes
            if name is not None and name.strip():
                nodes = [n for n in nodes if node_id_matches(name, field(n, "node-id"))]
            if sr_only:
                nodes = [n for n in nodes if sr_mpls_of(node_l3(n)) is not None]
            start = page * page_size
            envelope = page_envelope(
                nodes[start : start + page_size],
                result_count=len(nodes),
                total_count=len(all_nodes),
                page_size=page_size,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                payload: dict[str, Any] = {"network_id": network_id, **envelope}
                if fetched.note:
                    payload["note"] = fetched.note
                return finalize(to_json(payload), settings)
            filtered = bool(name and name.strip()) or sr_only
            return finalize(
                _nodes_markdown(network_id, envelope["items"], envelope, filtered, fetched.note),
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_topology_node",
        title="Get Topology Node",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_topology_node(
        node_id: Annotated[
            str,
            Field(
                description=(
                    "Topology node id = inventory host_name, exact and case-sensitive "
                    "(e.g. 'PE1'). List them with cnc_list_topology_nodes."
                ),
                min_length=1,
                max_length=253,
            ),
        ],
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one topology node: router-ids, IS-IS, SR-MPLS, prefix-SIDs, PCEP sessions and
        termination points.

        Read-only. ``GET .../ietf-network-state:networks/network=<id>/node=
        <node-id>`` (the id percent-encoded as one list key) answers a list of
        one node, re-matched on ``node-id`` client-side. Use it to read a
        router's SR data (SRGB/SRLB, MSD, its prefix-SID per prefix and
        algorithm), whether it holds a PCEP session with the PCE (PCC nodes
        only: pcc/pce address, stateful, SR/update/instantiate capabilities)
        and its interfaces (termination points with IP, MAC, unnumbered-id).
        A node known from LLDP collection only has termination points and no
        L3 attributes — the markdown says so. Interfaces alone:
        cnc_list_node_interfaces; adjacency: cnc_list_topology_links with
        node=<node-id>.

        Args:
            node_id: exact node-id (no wildcards).
            network: topology network id.
            response_format: markdown (summary line, router-ids, IS-IS,
                SR-MPLS, prefix table, PCEP sessions, one line per
                termination point) or json (the raw node object).

        Returns:
            str: Markdown, or the JSON node {"node-id": str,
            "ietf-network-topology-state:termination-point": [{"tp-id",
            "cisco-crosswork-topology-state:termination-point-attributes":
            {"l2-termination-point-attributes": {"unnumbered-id": [],
            "mac-address", "encapsulation-type"},
            "l3-termination-point-attributes": {"ip-address": []}, ...}}],
            "ietf-l3-unicast-topology-state:l3-node-attributes"?: {"name",
            "router-id": [], "cisco-crosswork-isis-topology:isis-node-attributes":
            [{"level", "system-id"}], "ietf-sr-mpls-topology-state:sr-mpls":
            {"srgb": [{"lower-bound", "upper-bound"}], "srlb": [...], "msd",
            "node-capabilities"}, "prefix": [{"prefix",
            "ietf-sr-mpls-topology-state:sr-mpls": [{"algorithm-value",
            "algorithm", "sid", ...}]}],
            "cisco-crosswork-l3-te-topology:node-pcep-sessions": [{"pcc-address",
            "pce-address", "capability-sr", "capability-update", "stateful",
            "msd", "capability-instantiate"}]}}.
            "Error: no node '<id>' in topology '<network>' ..." when the NBI
            answers 409 data-missing (or another node came back); "Error: ..."
            on any other API failure — a plain 404 is a malformed / unrouted
            URL, not a missing node.
        """
        try:
            key = node_id.strip()
            node = await fetch_node(network.strip(), key)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(node), settings)
            return finalize(_node_markdown(network.strip(), node), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_node_interfaces",
        title="List Topology Node Interfaces",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_node_interfaces(
        node_id: Annotated[
            str,
            Field(
                description="Topology node id (= host_name), exact and case-sensitive (e.g. 'P1').",
                min_length=1,
                max_length=253,
            ),
        ],
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the interfaces (termination points) of one topology node.

        Read-only. Reads the node (``GET .../network=<id>/node=<node-id>``,
        the same call as cnc_get_topology_node) and reports its
        ``ietf-network-topology-state:termination-point`` entries: ``tp-id``
        (the interface name, e.g. GigabitEthernet0/0/0/0), IP address(es)
        (from the L3 feed), MAC address, unnumbered-id and encapsulation type
        (from L2 collection). Only interfaces that take part in a discovered
        link or carry topology attributes appear here — this is not the
        device's full interface table. Pass a ``tp-id`` verbatim to
        cnc_get_node_interface for its raw attributes.

        Args:
            node_id: exact node-id.
            network: topology network id.
            response_format: markdown (one line per termination point:
                "<tp-id> ip=<a,b> mac=<mac> unnumbered=<ids> encap=<type>") or
                json (the raw termination-point objects).

        Returns:
            str: Markdown, or JSON {"network_id": str, "node_id": str,
            "count": int, "items": [{"tp-id": str,
            "cisco-crosswork-topology-state:termination-point-attributes":
            {"l2-termination-point-attributes": {...},
            "l3-termination-point-attributes": {"ip-address": [str]},
            "ipv4-termination-point-attributes": {...}}}]}. "No termination
            points ..." (not an error) when the node has none. "Error: no
            node '<id>' ..." when the node does not exist; "Error: ..." on an
            API failure.
        """
        try:
            key = node_id.strip()
            net = network.strip()
            node = await fetch_node(net, key)
            tps = node_termination_points(node)
            if response_format is ResponseFormat.JSON:
                payload = {"network_id": net, "node_id": key, "count": len(tps), "items": tps}
                return finalize(to_json(payload), settings)
            return finalize(_interfaces_markdown(net, node_id_of(node), tps), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_node_interface",
        title="Get Topology Node Interface",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_node_interface(
        node_id: Annotated[
            str,
            Field(
                description=(
                    "Topology node id (= host_name), exact and case-sensitive (e.g. 'PE1')."
                ),
                min_length=1,
                max_length=253,
            ),
        ],
        tp_id: Annotated[
            str,
            Field(
                description=(
                    "Termination-point id = interface name, verbatim as cnc_list_node_interfaces "
                    "prints it (e.g. 'GigabitEthernet0/0/0/0'); the tool URL-encodes it."
                ),
                min_length=1,
                max_length=253,
            ),
        ],
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one interface (termination point) of a topology node.

        Read-only. ``GET .../network=<id>/node=<node-id>/ietf-network-topology-
        state:termination-point=<tp-id>`` — the interface name is
        percent-encoded as one list key (``GigabitEthernet0%2F0%2F0%2F0``; an
        unencoded slash would be a plain 404 from the gateway). Answers the
        termination point's ``tp-id`` and its
        ``cisco-crosswork-topology-state:termination-point-attributes``: L2
        (mac-address, unnumbered-id, encapsulation-type) and L3 / IPv4 / IPv6
        (ip-address lists). Use cnc_list_node_interfaces to find the exact
        ``tp-id``.

        Args:
            node_id: exact node-id.
            tp_id: exact termination-point id (interface name).
            network: topology network id.
            response_format: markdown (the summary line plus the attributes
                block) or json (the raw termination-point object).

        Returns:
            str: Markdown, or the JSON termination point {"tp-id": str,
            "cisco-crosswork-topology-state:termination-point-attributes":
            {"l2-termination-point-attributes": {"unnumbered-id": [int],
            "mac-address": str, "encapsulation-type": str},
            "l3-termination-point-attributes": {"ip-address": [str]},
            "ipv4-termination-point-attributes": {"l3-termination-point-
            attributes": {"ip-address": [str]}}}}. "Error: no interface
            '<tp>' on node '<node>' ..." when the NBI answers 409
            data-missing (the node itself may be the missing part — verify
            with cnc_get_topology_node); "Error: ..." on any other API
            failure (a plain 404 is a malformed / unrouted URL).
        """
        try:
            node_key, tp_key, net = node_id.strip(), tp_id.strip(), network.strip()
            missing = PlatformError(
                f"no interface '{tp_key}' on node '{node_key}' in topology '{net}'. Termination-"
                "point ids are interface names, exact and case-sensitive — list them with "
                "cnc_list_node_interfaces (and verify the node with cnc_get_topology_node)."
            )
            data = await keyed_get(termination_point_url(net, node_key, tp_key), missing)
            tps = select_by_field(
                unwrap_list(data, TOPOLOGY_MODULE, "termination-point"), "tp-id", tp_key
            )
            if not tps:
                raise missing
            tp = tps[0]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(tp), settings)
            return finalize(_interface_markdown(net, node_key, tp), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_topology_links",
        title="List Topology Links",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_topology_links(
        link_type: Annotated[
            str,
            Field(
                description=(
                    f"One of: {_LINK_TYPE_CHOICES} — 'isis' = L3 adjacencies (link ids ending "
                    f"{LINK_TYPE_ISIS}), 'ethernet' = L2/LLDP links (ids ending "
                    f"{LINK_TYPE_ETHERNET}), 'other' = any other suffix (e.g. 'isis')."
                ),
                min_length=1,
                max_length=20,
            ),
        ] = "all",
        node: Annotated[
            str | None,
            Field(
                description=(
                    "Keep links with this node-id at either end: exact, case-insensitive, no "
                    "wildcard (e.g. 'PE1')."
                ),
                max_length=253,
            ),
        ] = None,
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        page_size: Annotated[
            int, Field(description="Links per page, client-side (e.g. 50).", ge=1, le=500)
        ] = 50,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the links of a topology network (IS-IS adjacencies and/or L2 Ethernet links).

        Read-only. The ``link`` sub-list cannot be listed on its own (400
        missing-attribute), so the network is fetched whole (``GET .../
        ietf-network-state:networks/network=<id>``) and filtered / paged
        client-side. **Links are directed and listed once per direction**:
        A->B and B->A are two entries, so a ring of 5 routers shows 10 IS-IS
        links plus 10 Ethernet links. The link id is
        ``"<src> : <srcIf> : <dst> : <dstIf> : <TYPE>"`` with ``TYPE``
        ``ISIS_IPV4_L2`` (L3 adjacency from the SR-PCE feed — carries the IGP
        ``metric1``, the adjacency-SIDs and ``max-bandwidth-kbps``) or
        ``ETHERNET`` (L2 link from LLDP collection — L2 attributes only). A
        topology with only ETHERNET links means the SR-PCE gRPC feed is down
        (cnc_get_topology_summary). For one link's full attributes pass its
        id verbatim to cnc_get_topology_link.

        Args:
            link_type: all | isis | ethernet | other.
            node: node-id at either end (exact, case-insensitive).
            network: topology network id.
            page_size, page: client-side paging (page is 0-based).
            response_format: markdown (one line per link: "<src>:<srcIf> ->
                <dst>:<dstIf> [<TYPE>] metric=<metric1> adj-sid=<sids>
                bw=<max-bandwidth-kbps>kbps" for L3, "... [ETHERNET] <l2
                attributes>" for L2) or json (the raw link objects).

        Returns:
            str: Markdown, or JSON {"network_id": str, "link_type": str,
            "node": str|null, "total": int (matches), "count": int, "page":
            int, "page_size": int, "has_more": bool, "next_page": int|null,
            "collection_total": int (links in the network), "items":
            [{"link-id": str, "source": {"source-node", "source-tp"},
            "destination": {"dest-node", "dest-tp"},
            "ietf-l3-unicast-topology-state:l3-link-attributes"?: {"name",
            "metric1", "ietf-sr-mpls-topology-state:sr-mpls": {"sids": [{"sid",
            "is-backup", "is-persistent", "is-local", ...}], ...},
            "cisco-crosswork-l3-te-topology:l3-link-attributes": {"domain-id",
            "max-bandwidth-kbps"}, "cisco-crosswork-isis-topology:isis-link-
            attributes": {"level", "net": {"system-id"}}},
            "ietf-l2-topology-state:l2-link-attributes"?: {...}}], "note"?:
            str (the NBI reports no networks yet)}. "No links ..." (not an
            error) when the network has none, nothing matches, or the NBI has
            no networks at all. "Error: Unknown link_type ..." / "Error: no
            network '<id>' ..." (unknown id while other networks exist) /
            "Error: ..." on an API failure.
        """
        try:
            kind = normalize_link_type(link_type)
            fetched = await fetch_network(network)
            network_obj = fetched.network
            network_id = network_id_of(network_obj)
            all_links = network_links(network_obj)
            links = all_links
            if kind != "all":
                links = [ln for ln in links if classify_link(link_id_of(ln)) == kind]
            node_key = node.strip() if node and node.strip() else None
            if node_key:
                links = [ln for ln in links if link_touches(ln, node_key)]
            start = page * page_size
            envelope = page_envelope(
                links[start : start + page_size],
                result_count=len(links),
                total_count=len(all_links),
                page_size=page_size,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                payload: dict[str, Any] = {
                    "network_id": network_id,
                    "link_type": kind,
                    "node": node_key,
                    **envelope,
                }
                if fetched.note:
                    payload["note"] = fetched.note
                return finalize(to_json(payload), settings)
            return finalize(
                _links_markdown(
                    network_id, envelope["items"], envelope, kind, node_key, fetched.note
                ),
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_topology_link",
        title="Get Topology Link",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_topology_link(
        link_id: Annotated[
            str,
            Field(
                description=(
                    "Link id verbatim as cnc_list_topology_links prints it, spaces and colons "
                    "included (e.g. 'P2 : GigabitEthernet0/0/0/0 : PE2 : GigabitEthernet0/0/0/1 "
                    ": ISIS_IPV4_L2'); the tool URL-encodes it."
                ),
                min_length=1,
                max_length=600,
            ),
        ],
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one topology link with all its L3 (IGP metric, adjacency-SIDs, bandwidth,
        IS-IS) or L2 attributes.

        Read-only. ``GET .../network=<id>/ietf-network-topology-state:link=
        <link-id>`` — the id is percent-encoded as one list key (``%20`` for
        spaces, ``%3A`` for colons, ``%2F`` for the slashes in interface
        names); pass it exactly as listed, the tool does the encoding. Answers
        a list of one link, re-matched on ``link-id`` client-side. An
        ``ISIS_IPV4_L2`` link carries ``ietf-l3-unicast-topology-state:
        l3-link-attributes`` (name, metric1 = IGP metric, the SR-MPLS
        adjacency ``sids`` with their backup/persistent/local flags,
        ``cisco-crosswork-l3-te-topology:l3-link-attributes`` domain-id and
        max-bandwidth-kbps, IS-IS level and neighbour system-id); an
        ``ETHERNET`` link carries ``ietf-l2-topology-state:l2-link-attributes``
        only. Per-link performance metrics (utilisation, delay) are a separate
        keyed read on the same NBI and exist for IGP links only.

        Args:
            link_id: exact link id (directed: A->B and B->A are different links).
            network: topology network id.
            response_format: markdown (summary line, endpoints, L3 / IS-IS /
                SR-MPLS lines, adjacency-SID table, or the L2 attributes) or
                json (the raw link object).

        Returns:
            str: Markdown, or the JSON link {"link-id": str, "source":
            {"source-node", "source-tp"}, "destination": {"dest-node",
            "dest-tp"}, "ietf-l3-unicast-topology-state:l3-link-attributes"?:
            {"name", "metric1", "ietf-sr-mpls-topology-state:sr-mpls":
            {"advertise-protection", "sids": [{"sid", "is-backup",
            "is-persistent", "is-on-lan", "value-type", "is-local",
            "address-family", "is-part-of-set"}], "information-source"},
            "cisco-crosswork-l3-te-topology:l3-link-attributes": {"domain-id",
            "max-bandwidth-kbps"}, "cisco-crosswork-isis-topology:isis-link-
            attributes": {"level", "net": {"system-id"}}},
            "ietf-l2-topology-state:l2-link-attributes"?: {...}}.
            "Error: no link '<id>' in topology '<network>' ..." when the NBI
            answers 409 data-missing (cnc_list_topology_links shows the exact
            ids); "Error: ..." on any other API failure — a plain 404 means
            the URL was malformed or the NBI is not routed, not that the link
            is missing.
        """
        try:
            key, net = link_id.strip(), network.strip()
            missing = PlatformError(
                f"no link '{key}' in topology '{net}'. cnc_list_topology_links shows the exact "
                "ids — they contain spaces and colons ('<src> : <srcIf> : <dst> : <dstIf> : "
                "<TYPE>'), are directed (A->B and B->A differ) and must be passed verbatim."
            )
            data = await keyed_get(link_url(net, key), missing)
            links = select_by_field(unwrap_list(data, TOPOLOGY_MODULE, "link"), "link-id", key)
            if not links:
                raise missing
            link = links[0]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(link), settings)
            return finalize(_link_markdown(net, link), settings)
        except Exception as e:
            return format_error(e)
