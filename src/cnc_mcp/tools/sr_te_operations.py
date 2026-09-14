"""SR-TE operations tools — SR policy provisioning, dry runs and path queries through
the Crosswork Optimization Engine (COE) and its SR-PCE.

What the COE does. The Optimization Engine is the Crosswork application that
computes and programs SR-TE paths through the SR-PCE provider. Its RPCs on the
optimization NBI (``/crosswork/nbi/optimization/v3/restconf/operations``) let a
caller **provision, modify and delete SR policies via PCEP** (the PCE
instantiates the policy on the head-end — a *PCE-initiated* policy), dry-run a
path before committing it, preview the IGP/ECMP route a segment list takes,
and ask which policies ride a node or an interface. It is the write side of
the SR policy story; the read side (what the PCE currently reports) is
:mod:`cnc_mcp.tools.te_state` (``cnc_list_sr_policies`` / ``cnc_get_sr_policy``),
which these tools reuse for their safety check and their convergence wait.

PCE-initiated vs PCC-initiated (verified live 2026-09-13). A policy created here
appears on the head-end within seconds as a PCEP candidate path (``show
segment-routing traffic-eng policy color N``: candidate path "(PCEP)", the
given path name, the SIDs, a binding SID allocated by the router) and on the
topology NBI with ``policy-details.pcep-info.pcep-flag-c: 1`` and
``pce-controlled: true``. A policy **configured on the router** (PCC-initiated,
possibly delegated to the PCE) shows ``pcep-flag-c: 0``. The distinction
matters for delete: the COE's Config DB holds only the policies it initiated,
and ``sr-policy-delete`` on any other key — a PCC-initiated policy included —
answers ``state failure "SR policy not found in Config DB"`` (verified live on
the lab's PCC-initiated color-100 policy; the router keeps it). So
``cnc_delete_sr_policy`` reads the policy first and refuses a ``pcep-flag-c: 0``
policy (or one without the flag) with a plain explanation unless ``force=true``.
The same read is the PCC's report, not the COE's model: a PCE-initiated policy is absent from it
while the head-end does not ``report-all`` it, in the seconds after a create,
or while the SR-PCE feed is down, so ``force=true`` also sends the delete for
a policy the NBI does not report — otherwise a policy created on a
non-reporting head-end could never be removed here.

Naming (verified live). The RPC bodies mix two vocabularies: ``nodes[].node``
and ``interfaces[].node`` are **host names** (``PE1``, the topology
``node-id``), while ``head-end`` / ``end-point`` and every hop address are **TE
router-ids** (the loopbacks, ``10.0.0.1``). Sending a host name where a
router-id belongs, or vice versa, is answered with a bare 500 (below). Every
tool here therefore accepts **either** spelling for a node — a node id
(case-insensitive) or one of its router-ids — and resolves it through the
topology NBI (``ietf-network-state:networks``, the COLLECTION GET: the keyed
``network=<id>`` GET is shallow and carries no SR data) into the form the RPC
wants: ``router-id`` = the router-id the caller named when the input was one,
else the first IPv4 entry of the node's ``l3-node-attributes.router-id``
leaf-list (:func:`select_router_id`); ``prefix-sid`` = the ``sid`` of that
``<router-id>/32`` prefix's ``algorithm-value`` 0 entry and nothing else — a
Flex-Algo SID or another prefix's SID would not belong with the address, so a
node without that entry is refused as an explicit hop rather than guessed
(:func:`node_prefix_sid`). The name -> node -> router-id part of the resolver
(:func:`find_node`, :func:`select_router_id`, :func:`fetch_topology_nodes`)
is shared with the read-side tools and lives in :mod:`cnc_mcp.tools.te_state`
(imported here — one implementation, and the read side accepts host names
too since 2026-09-14); the SID part (:class:`ResolvedNode`,
:func:`resolve_node`, :func:`require_sr`) is this module's. The RPC keys are
hyphenated (``head-end``, ``end-point``, ``color``) where the topology NBI
spells them ``headend`` / ``endpoint``.

The explicit-hop rule (verified live). An explicit hop on the wire is
``{"step": i, "hop": {"node-ipv4-address": <router-id>, "node-ipv4-sid":
<prefix-sid>}}`` — **both fields, always**, despite the OpenAPI document's
``x-choice`` suggesting either: the address alone is answered with a bare 500,
the SID alone with "There is not enough info to lookup for node hop_type:
HOP_IPV4_NODE_SID", and an adjacency address/SID pair that do not belong
together with "Missing SID on some hop". The tools take hops as a
comma-separated list of node names or router-ids (``"P2,PE2"``), resolve each
to its router-id + prefix-SID and number the steps from 0. **Adjacency hops
are not supported** by these tools: an adjacency hop needs the exact
``adjacency-ipv4-address`` + ``adjacency-ipv4-sid`` pair of one link direction,
the pair must match exactly (a mismatch is the "Missing SID on some hop"
failure), and the topology NBI does not expose the pairing usefully — node
SIDs cover the steering use cases.

The empty-500 rule (verified live). A **bare HTTP 500 with an empty body** is
how the COE rejects bad INPUT — an unknown node or interface name, a host
name where a router-id belongs, an explicit hop without its SID — and it is
indistinguishable from the "backend absent" empty 500 that ``list-opm-package``
and ``sr-datalist-oper`` always answer on this build. Every tool therefore
validates its inputs client-side first (node ids, termination points,
router-ids and prefix-SIDs from the topology; the path shape in
:func:`build_policy_path`) and does not send the RPC when validation fails.
An empty 500 that still arrives after validation is reported with the COE
hint (:data:`COE_EMPTY_500_HINT`) — a self-contained text that names the
unresolved-input causes first and the backend-absent case second, instead of
the generic :data:`cnc_mcp.restconf.EMPTY_500_EXPLANATION`, whose "retrying
will not help, the feature is absent" verdict would send an agent away from
the common cause (its own input).

Two result idioms, both inside HTTP 200 (verified live): COE reads (module
``cisco-crosswork-optimization-engine-operations``) answer ``output.status``
``accepted`` | ``error`` (+ ``message``) plus a per-item
``path-computation-status`` ``success`` | ``failure``; SR policy writes and
the dry run (module ``cisco-crosswork-optimization-engine-sr-policy-operations``)
answer ``output.results[] {head-end, end-point, color, state success | failure
| degraded, message}`` — one entry per policy — or, for the dry run,
``output.state`` + ``message``. A ``failure`` state is an API-level outcome
and is reported as "Error: <what> failed for <key>: <platform message>";
``degraded`` is a success that carries the platform's message.

Not exposed because they do not work on this build: ``get-plan`` answers
``status: error`` ("Invalid version spec ...") for every version tried;
``sr-datalist-oper`` and the OPM RPCs (``list-opm-package`` ...) answer the
empty 500. Nor are P2MP / RSVP-TE operations (separate documents, unverified).
"""

from __future__ import annotations

from typing import Annotated, Any, NamedTuple

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.polling import wait_until
from cnc_mcp.restconf import (
    OPTIMIZATION_NBI,
    YANG_ACCEPT,
    YANG_HEADERS,
    check_rpc_output,
    explain_empty_500,
    is_not_found,
    rpc_body,
    rpc_output,
    rpc_path,
    unwrap_list,
)
from cnc_mcp.safety import AppContext, register_tool
from cnc_mcp.tools.te_state import (
    SR_POLICY_MODULE,
    as_bool,
    entries_matching,
    fetch_topology_nodes,
    find_node,
    pcep_flag_c,
    policy_details,
    policy_origin,
    policy_paths,
    select_router_id,
    sr_policy_url,
)
from cnc_mcp.tools.topology import (
    DEFAULT_NETWORK,
    field,
    node_id_of,
    node_l3,
    node_termination_points,
    prefix_sid_label,
    prefix_sids_of,
    prefixes_of,
    router_ids,
    srgb_lower_bound,
    tp_id_of,
)

COE_MODULE = "cisco-crosswork-optimization-engine-operations"
SRP_MODULE = "cisco-crosswork-optimization-engine-sr-policy-operations"

# COE reads (all verified live 2026-09-13).
RPC_POLICIES_ON_NODE = "sr-policies-on-node"
RPC_POLICIES_ON_INTERFACE = "sr-policies-on-interface"
RPC_POLICY_ROUTES = "sr-policy-routes"
RPC_POLICY_METRICS = "sr-policy-metrics"
RPC_ROUTE_PREVIEW = "sr-policy-route-preview"
RPC_GET_NOTIFICATION_STATE = "get-interface-sr-policy-paths-notification-state"
RPC_SET_NOTIFICATION_STATE = "set-interface-sr-policy-paths-notification-state"
# SR policy writes and the dry run (verified live, full create/modify/delete cycle).
RPC_DRYRUN = "sr-policy-dryrun"
RPC_CREATE = "sr-policy-create"
RPC_MODIFY = "sr-policy-modify"
RPC_DELETE = "sr-policy-delete"

PATH_TYPES = ("dynamic", "explicit", "bandwidth")
OBJECTIVES = ("igp-metric", "te-metric", "delay", "hop-count")
DISJOINTNESS_TYPES = ("node", "circuit", "srlg", "srlg-node")
DEFAULT_PATH_TYPE = "dynamic"
DEFAULT_OBJECTIVE = "igp-metric"
# Friendly relation -> the RPC's ``filter`` enumeration (verified spellings).
RELATIONS: dict[str, str] = {
    "source": "nodes-as-source",
    "destination": "nodes-as-destination",
    "source-or-destination": "nodes-as-source-or-destination",
    "through": "through-nodes",
}
DEFAULT_RELATION = "source-or-destination"
DEFAULT_WAIT_TARGET = "UP"
# cnc_wait_for_sr_policy_oper_state targets: the two oper-states, plus ABSENT = no longer
# reported by the topology NBI (409 data-missing) — the convergence signal after a delete.
WAIT_TARGETS = ("UP", "DOWN", "ABSENT")
_WAIT_TARGET_CHOICES = ", ".join(WAIT_TARGETS)

# The whole explanation of a bare 500 from the COE (see the module docstring). It is
# deliberately self-contained and NOT restconf.EMPTY_500_EXPLANATION, whose "the
# backend is not available, retrying will not help" verdict is wrong for this NBI:
# on the COE an empty 500 is, first of all, how bad INPUT is rejected (verified).
COE_EMPTY_500_HINT = (
    "The Optimization Engine answered 500 with an empty body. On this platform that is how "
    "the COE rejects INPUT it cannot resolve — an unknown node or interface name, a router-id "
    "where a host name belongs (nodes[].node / interfaces[].node take host names), a host name "
    "where a router-id belongs (head-end / end-point / hop addresses), or an explicit hop "
    "without its SID — and the very same answer as a COE backend that is absent or down "
    "(list-opm-package and sr-datalist-oper always answer it on this build). This tool "
    "resolved its inputs against the topology NBI before sending, so first compare what was "
    "sent with the COE's own view: cnc_get_topology_node for the node id, router-ids and "
    "algorithm-0 prefix-SIDs, cnc_list_node_interfaces for the exact interface names, "
    "cnc_get_topology_summary for a stale or empty SR-PCE feed. If every input resolves, the "
    "Optimization Engine or the SR-PCE provider is unavailable (cnc_list_providers) and "
    "retrying with the same inputs will not help."
)

_RESPONSE_FORMAT_DESC = "'markdown' for human-readable output, 'json' for the raw RPC output."
_NODE_HELP = (
    "a topology node id (the inventory host name, case-insensitive, e.g. 'PE1') or one of "
    "its TE router-ids (e.g. '10.0.0.1')"
)
_HEADEND_DESC = f"Head-end of the policy: {_NODE_HELP}; sent to the PCE as its router-id."
_ENDPOINT_DESC = f"Endpoint (tail-end) of the policy: {_NODE_HELP}; sent as its router-id."
_COLOR_DESC = "The policy color (e.g. 100)."
_NETWORK_DESC = (
    f"Topology network id the names are resolved against (e.g. '{DEFAULT_NETWORK}', the only "
    "network on a standard deployment)."
)
_HOPS_DESC = (
    "Comma-separated explicit hops in path order, each a node id or router-id (e.g. "
    "'P2,PE2'; the last hop is normally the endpoint). Each becomes a node prefix-SID hop "
    "(router-id + SID from the topology); adjacency hops are not supported."
)
_PATH_TYPE_DESC = (
    "'dynamic' (the PCE computes the path, default), 'explicit' (the hops you give) or "
    "'bandwidth' (bandwidth-on-demand; needs bandwidth_mbps and the BWoD feature enabled)."
)
_OBJECTIVE_DESC = (
    "Metric the PCE minimises for a dynamic or bandwidth path: 'igp-metric' (default), "
    "'te-metric', 'delay' or 'hop-count'. Ignored for an explicit path."
)
_PROTECTED_DESC = (
    "Dynamic path only: prefer protected adjacency SIDs in the computation (default true)."
)
_SID_ALGORITHM_DESC = (
    "Dynamic/bandwidth path only: the Flex-Algo (SID algorithm) to compute with, e.g. 128. "
    "Omit for algorithm 0 (SPF)."
)
_DISJOINTNESS_TYPE_DESC = (
    "Dynamic path only: make the path disjoint from the other member(s) of association_group "
    "— 'node', 'circuit' (link), 'srlg' or 'srlg-node'. Requires association_group."
)
_ASSOCIATION_GROUP_DESC = (
    "Dynamic path only: the disjointness association group id shared by the paths that must "
    "be disjoint (e.g. 1). Requires disjointness_type."
)
_ASSOCIATION_SUB_GROUP_DESC = "Dynamic path only: optional disjointness association sub-group."
_BANDWIDTH_DESC = (
    "Bandwidth path only: the bandwidth to reserve in Mbps (e.g. 100). Requires "
    "path_type='bandwidth'."
)
_PATH_NAME_DESC = (
    "The candidate-path name the head-end shows for the policy (REQUIRED by the platform, "
    "e.g. 'mcp-dyn-200')."
)
_TIMEOUT_DESC = "How long to wait in total, seconds (e.g. 60)."
_INTERVAL_DESC = "Seconds between polls (e.g. 3)."

_PATH_TYPE_CHOICES = ", ".join(PATH_TYPES)
_OBJECTIVE_CHOICES = ", ".join(OBJECTIVES)
_DISJOINTNESS_CHOICES = ", ".join(DISJOINTNESS_TYPES)
_RELATION_CHOICES = ", ".join(RELATIONS)


class ResolvedNode(NamedTuple):
    """A topology node in the two spellings the COE RPCs use.

    ``router_id`` / ``prefix_sid`` are ``None`` for a node the SR-PCE feed
    reports without SR data (an LLDP-only node, or the feed being down) —
    :func:`require_sr` turns that into the agent-facing error where a
    router-id or SID is needed.
    """

    node_id: str
    router_id: str | None
    prefix_sid: int | None


# --- URL builders ----------------------------------------------------------------


def coe_url(rpc: str) -> str:
    """``<OPTIMIZATION_NBI>/operations/cisco-crosswork-optimization-engine-operations:<rpc>``."""
    return rpc_path(OPTIMIZATION_NBI, COE_MODULE, rpc)


def srp_url(rpc: str) -> str:
    """``.../operations/cisco-crosswork-optimization-engine-sr-policy-operations:<rpc>``."""
    return rpc_path(OPTIMIZATION_NBI, SRP_MODULE, rpc)


# --- pure helpers: parsing and validation -----------------------------------------


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_names(text: str, what: str, example: str) -> list[str]:
    """``'PE1, P1'`` -> ``['PE1', 'P1']``; PlatformError when nothing is left after stripping."""
    names = [part.strip() for part in text.split(",")]
    names = [name for name in names if name]
    if not names:
        raise PlatformError(
            f"{what} is empty: give one or more node ids or router-ids separated by commas "
            f"(e.g. '{example}')."
        )
    return names


def normalize_relation(relation: str) -> str:
    """``'source'`` / ``' Through '`` / ``'nodes-as-source'`` -> the RPC ``filter`` value.

    Accepts the friendly names (:data:`RELATIONS` keys, underscores tolerated)
    and the wire spellings themselves; PlatformError for anything else.
    """
    key = relation.strip().lower().replace("_", "-")
    if key in RELATIONS:
        return RELATIONS[key]
    if key in RELATIONS.values():
        return key
    raise PlatformError(
        f"Unknown relation '{relation}'. Use one of: {_RELATION_CHOICES} ('source' = the node "
        "is the head-end, 'destination' = the endpoint, 'through' = a transit hop)."
    )


def _choice(value: str, choices: tuple[str, ...], what: str) -> str:
    key = value.strip().lower().replace("_", "-")
    if key not in choices:
        raise PlatformError(f"Unknown {what} '{value}'. Use one of: {', '.join(choices)}.")
    return key


def normalize_wait_target(target: str) -> str:
    """``'up'`` / ``' Absent '`` -> ``'UP'`` / ``'ABSENT'``; PlatformError for anything else.

    Distinct from :func:`cnc_mcp.tools.te_state.normalize_oper_state`
    because ``ABSENT`` is not an oper-state: it is the wait tool's own
    "no longer reported" target (added 2026-09-14, agent scenario 10 — after
    a delete the only convergence signal is the 409 ``data-missing``).
    """
    key = target.strip().upper()
    if not key:
        raise PlatformError(f"target is empty: pass one of {_WAIT_TARGET_CHOICES}.")
    if key not in WAIT_TARGETS:
        raise PlatformError(
            f"target must be one of {_WAIT_TARGET_CHOICES} (case-insensitive), got '{target}'. "
            "UP/DOWN are the policy's oper-state; ABSENT means the topology NBI no longer "
            "reports the policy (the signal that a delete has converged)."
        )
    return key


def node_prefix_sid(l3: dict[str, Any], router_id: str | None) -> int | None:
    """The node's prefix-SID: the algorithm-0 SID of the ``<router-id>/32`` prefix, or ``None``.

    Strict on purpose — an explicit hop's address and SID must belong together
    (an address/SID pair that do not match is the "Missing SID on some hop"
    failure, or worse, a silently mis-steered path), so the only SID accepted
    is one advertised for the router-id's own /32 with ``algorithm-value`` 0
    (SPF). A Flex-Algo SID of that prefix, or the SID of any other prefix the
    node advertises, is NOT a substitute and yields ``None``, which
    :func:`require_sr` turns into an error before anything is sent. The value
    is the absolute label the PCE expects in ``node-ipv4-sid`` (16004
    verified): the feed publishes an SRGB *index* (``value-type: index``,
    ``start-sid: 4``), which :func:`prefix_sid_label` adds to the node's SRGB
    lower bound.
    """
    if not router_id:
        return None
    srgb_lower = srgb_lower_bound(l3)
    for prefix in prefixes_of(l3):
        if str(field(prefix, "prefix") or "") != f"{router_id}/32":
            continue
        for entry in prefix_sids_of(prefix):
            if _int_or_none(field(entry, "algorithm-value")) != 0:
                continue
            sid = prefix_sid_label(entry, srgb_lower)
            if sid is not None:
                return sid
    return None


def resolve_node(nodes: list[dict[str, Any]], name_or_ip: str) -> ResolvedNode:
    """THE resolver every tool uses: a node id or router-id -> :class:`ResolvedNode`.

    ``router_id`` is chosen by :func:`select_router_id` from the node's
    ``l3-node-attributes.router-id`` list (the input when it named one, else
    the first IPv4 one), ``prefix_sid`` is that router-id's algorithm-0 /32
    SID (:func:`node_prefix_sid`); both ``None`` for a node without SR data.
    PlatformError when no node matches (:func:`find_node`).
    """
    node = find_node(nodes, name_or_ip)
    l3 = node_l3(node)
    router_id = select_router_id(router_ids(l3), name_or_ip)
    return ResolvedNode(node_id_of(node), router_id, node_prefix_sid(l3, router_id))


def require_sr(node: ResolvedNode, *, need_sid: bool = False) -> ResolvedNode:
    """``node`` when it has a router-id (and, with ``need_sid``, a prefix-SID); else PlatformError.

    The SR data comes from the SR-PCE gRPC feed: a node without it is either
    an LLDP-only node, a node that advertises no SR, or the feed being down.
    A node with a router-id but no algorithm-0 SID for its /32 cannot be an
    explicit hop (only that SID belongs with the address on the wire).
    """
    missing = None
    if node.router_id is None:
        missing = "no TE router-id"
    elif need_sid and node.prefix_sid is None:
        missing = f"no algorithm-0 prefix-SID for {node.router_id}/32"
    if missing:
        raise PlatformError(
            f"node '{node.node_id}' has no SR data in the topology ({missing}): the SR-PCE gRPC "
            "feed may be down, or the node advertises no segment routing — check "
            "cnc_list_providers (SR-PCE) and cnc_get_topology_node."
        )
    return node


def resolve_interface(node: dict[str, Any], interface: str) -> str:
    """The exact ``tp-id`` of ``interface`` on the topology node; PlatformError listing the
    node's termination points when it is not one of them (a case-insensitive unique match
    is accepted and returned in its exact spelling)."""
    key = interface.strip()
    tp_ids = [tp_id_of(tp) for tp in node_termination_points(node)]
    if key and key in tp_ids:
        return key
    loose = [tp for tp in tp_ids if tp.lower() == key.lower()] if key else []
    if len(loose) == 1:
        return loose[0]
    raise PlatformError(
        f"no interface '{key}' on node '{node_id_of(node)}' in the topology. Its termination "
        f"points are: {', '.join(tp_ids) if tp_ids else '(none reported)'} — pass the exact "
        "interface name (cnc_list_node_interfaces)."
    )


def explicit_hop(step: int, node: ResolvedNode) -> dict[str, Any]:
    """One wire hop: ``{"step": i, "hop": {"node-ipv4-address", "node-ipv4-sid"}}`` — both fields.

    Verified live: the address alone is a bare 500, the SID alone "There is
    not enough info to lookup for node hop_type: HOP_IPV4_NODE_SID".
    """
    require_sr(node, need_sid=True)
    return {
        "step": step,
        "hop": {"node-ipv4-address": node.router_id, "node-ipv4-sid": node.prefix_sid},
    }


def explicit_hops(nodes: list[ResolvedNode]) -> list[dict[str, Any]]:
    """The ``hops`` list for an explicit path, steps numbered from 0."""
    return [explicit_hop(step, node) for step, node in enumerate(nodes)]


def build_policy_path(
    *,
    path_type: str = DEFAULT_PATH_TYPE,
    objective: str = DEFAULT_OBJECTIVE,
    hops: list[ResolvedNode] | None = None,
    protected: bool = True,
    sid_algorithm: int | None = None,
    disjointness_type: str | None = None,
    association_group: int | None = None,
    association_sub_group: int | None = None,
    bandwidth_mbps: int | None = None,
) -> dict[str, Any]:
    """The ``sr-policy-path`` container for dryrun / create / modify — the YANG choice, flat.

    ``sr-policy-path`` is a YANG choice with three cases; the tools expose it
    as flat arguments and this is the ONE place the wire body is built:

    - ``dynamic`` -> ``{"path-optimization-objective": objective, "protected":
      protected}`` plus ``sid-algorithm`` and ``disjointness``
      (``{"disjointness-type", "association-group", "association-sub-group"?}``)
      when given. ``hops`` and ``bandwidth_mbps`` must not be given.
    - ``explicit`` -> ``{"hops": [...]}`` (:func:`explicit_hops`, both address
      and SID per hop). ``hops`` is required; the objective/protected flags are
      not sent and ``sid_algorithm`` / disjointness / ``bandwidth_mbps`` are
      rejected rather than silently dropped.
    - ``bandwidth`` -> ``{"bandwidth": bandwidth_mbps,
      "bw-path-optimization-objective": objective}`` (+ ``bw-path-sid-algorithm``
      when ``sid_algorithm`` is given — per the 7.2 document, unverified live).
      ``bandwidth_mbps`` is required; ``hops`` and disjointness are rejected.
      Verified answer on a lab without the feature: state ``failure``
      "Bandwidth On Demand currently dormant: disabled".

    PlatformError for an unknown path_type / objective / disjointness_type and
    for every argument combination above.
    """
    kind = _choice(path_type, PATH_TYPES, "path_type")
    metric = _choice(objective, OBJECTIVES, "objective")
    hop_nodes = hops or []
    disjointness: dict[str, Any] | None = None
    if disjointness_type is not None and disjointness_type.strip():
        if association_group is None:
            raise PlatformError(
                "disjointness_type needs association_group: the group id shared by the paths "
                "that must be disjoint from each other."
            )
        disjointness = {
            "disjointness-type": _choice(
                disjointness_type, DISJOINTNESS_TYPES, "disjointness_type"
            ),
            "association-group": association_group,
        }
        if association_sub_group is not None:
            disjointness["association-sub-group"] = association_sub_group
    elif association_group is not None or association_sub_group is not None:
        raise PlatformError(
            "association_group / association_sub_group need disjointness_type (one of "
            f"{_DISJOINTNESS_CHOICES})."
        )

    if kind == "explicit":
        if not hop_nodes:
            raise PlatformError(
                "path_type='explicit' needs hops: a comma-separated list of node ids or "
                "router-ids in path order (e.g. 'P2,PE2')."
            )
        rejected = [
            name
            for name, value in (
                ("sid_algorithm", sid_algorithm),
                ("disjointness_type", disjointness),
                ("bandwidth_mbps", bandwidth_mbps),
            )
            if value is not None
        ]
        if rejected:
            raise PlatformError(
                f"{', '.join(rejected)} do(es) not apply to an explicit path — the PCE programs "
                "exactly the hops given. Drop them, or use path_type='dynamic' / 'bandwidth'."
            )
        return {"hops": explicit_hops(hop_nodes)}

    if hop_nodes:
        raise PlatformError(
            f"hops apply only to path_type='explicit' (got path_type='{kind}'); for a computed "
            "path drop the hops."
        )
    if kind == "dynamic":
        if bandwidth_mbps is not None:
            raise PlatformError(
                "bandwidth_mbps needs path_type='bandwidth' (bandwidth-on-demand); a dynamic "
                "path has no bandwidth constraint."
            )
        path: dict[str, Any] = {"path-optimization-objective": metric, "protected": protected}
        if sid_algorithm is not None:
            path["sid-algorithm"] = sid_algorithm
        if disjointness is not None:
            path["disjointness"] = disjointness
        return path

    # bandwidth
    if bandwidth_mbps is None:
        raise PlatformError("path_type='bandwidth' needs bandwidth_mbps (the Mbps to reserve).")
    if disjointness is not None:
        raise PlatformError(
            "disjointness applies only to a dynamic path; a bandwidth path cannot carry it."
        )
    bw_path: dict[str, Any] = {
        "bandwidth": bandwidth_mbps,
        "bw-path-optimization-objective": metric,
    }
    if sid_algorithm is not None:
        bw_path["bw-path-sid-algorithm"] = sid_algorithm
    return bw_path


def policy_key(head: ResolvedNode, end: ResolvedNode, color: int) -> dict[str, Any]:
    """The RPC key ``{"head-end", "end-point", "color"}`` — router-ids on the wire."""
    require_sr(head)
    require_sr(end)
    return {"head-end": head.router_id, "end-point": end.router_id, "color": color}


def node_label(node: ResolvedNode) -> str:
    """``PE1 (10.0.0.1)`` — both spellings, so the agent can carry on with either."""
    if node.router_id and node.router_id != node.node_id:
        return f"{node.node_id} ({node.router_id})"
    return node.node_id


def policy_label(head: ResolvedNode, end: ResolvedNode, color: int) -> str:
    return f"{node_label(head)} -> {node_label(end)} color {color}"


# --- pure helpers: RPC outcomes ----------------------------------------------------


def check_coe_status(output: dict[str, Any], what: str) -> dict[str, Any]:
    """Raise PlatformError for a COE read that reports ``status`` error / rejected in HTTP 200."""
    check_rpc_output(output, what)
    status = str(output.get("status") or "").strip().lower()
    if status == "rejected":
        message = output.get("message")
        reason = message.strip() if isinstance(message, str) and message.strip() else ""
        raise PlatformError(
            f"{what} was rejected by the Optimization Engine: {reason or 'no message given'}"
        )
    return output


def first_result(output: dict[str, Any], what: str) -> dict[str, Any]:
    """``output.results[0]`` (the one policy the tool sent); PlatformError when there is none.

    The verified idiom always carries ``results[]``; an answer without it
    (the 7.2 document also lists a bodiless 204, never seen live) leaves the
    outcome unknown, so the error says to verify rather than claiming success
    or failure.
    """
    results = output.get("results")
    entries = [r for r in results if isinstance(r, dict)] if isinstance(results, list) else []
    if not entries:
        raise PlatformError(
            f"the Optimization Engine returned no result for {what} (status="
            f"{output.get('status')!r}, message={output.get('message')!r}, state="
            f"{output.get('state')!r}); the request may or may not have been applied — verify "
            "with cnc_get_sr_policy / cnc_list_sr_policies_on_nodes before re-sending."
        )
    return entries[0]


def computed(result: dict[str, Any]) -> bool:
    """True when a COE read item reports ``path-computation-status: success``."""
    return str(result.get("path-computation-status") or "").strip().lower() == "success"


def write_outcome(result: dict[str, Any], what: str, label: str) -> tuple[str, str]:
    """``(state, message)`` of an SR policy write / dry-run result; PlatformError on failure.

    ``failure`` -> "Error: <what> failed for <label>: <platform message>";
    ``success`` and ``degraded`` are returned (degraded carries a message the
    caller must surface); any other state is reported as unexpected.
    """
    state = str(result.get("state") or "").strip().lower()
    message = result.get("message")
    text = message.strip() if isinstance(message, str) else ""
    if state == "failure":
        raise PlatformError(f"{what} failed for {label}: {text or 'no message given'}")
    if state not in ("success", "degraded"):
        raise PlatformError(
            f"{what} for {label} answered an unexpected state {state or '(none)'!r}: "
            f"{text or 'no message given'}"
        )
    return state, text


def dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


# --- markdown renderers ------------------------------------------------------------


def policy_key_line(entry: dict[str, Any]) -> str:
    """``10.0.0.1 -> 10.0.0.3 color 100`` for an RPC key entry (hyphenated keys)."""
    return (
        f"{entry.get('head-end', '?')} -> {entry.get('end-point', '?')} "
        f"color {entry.get('color', '?')}"
    )


def _policy_lines(policies: list[dict[str, Any]], message: Any) -> list[str]:
    lines = [f"- {policy_key_line(p)}" for p in policies] or ["- (none)"]
    if isinstance(message, str) and message.strip():
        lines.append(f"  message: {message.strip()}")
    return lines


def route_line(hop: dict[str, Any]) -> str:
    """``PE1:GigabitEthernet0/0/0/0 (share 0.5)`` for one ``igp-route`` entry."""
    text = f"- {hop.get('node', '?')}:{hop.get('interface', '?')}"
    share = hop.get("interface-use")
    if share not in (None, ""):
        text += f" (share {share})"
    return text


def route_lines(route: Any) -> list[str]:
    hops = dict_list(route)
    return [route_line(h) for h in hops] or ["- (no interfaces reported)"]


def group_route_by_node(route: Any, first_node: str | None = None) -> list[tuple[str, list[str]]]:
    """``[(node, [interface, ...]), ...]`` for an ``igp-route`` list, ``first_node`` leading.

    The dry run's ``igp-route`` is UNORDERED and carries no ``interface-use``
    (verified live 2026-09-14: ``P2:Gi0/0/0/1, PE2:Gi0/0/0/1, P1:Gi0/0/0/0,
    PE2:Gi0/0/0/0`` for a PE2 -> PE1 dynamic path), so a flat list reads like
    a four-hop serial path when it is a two-way ECMP split. Grouping by node
    makes the structure visible: several interfaces on one node are ECMP
    alternatives, not consecutive hops. Nodes keep their first-appearance
    order except ``first_node`` (the head-end), which leads when present.
    """
    grouped: dict[str, list[str]] = {}
    for hop in dict_list(route):
        node = str(hop.get("node") or "?")
        interface = str(hop.get("interface") or "?")
        grouped.setdefault(node, []).append(interface)
    ordered = list(grouped.items())
    if first_node in grouped:
        ordered.sort(key=lambda item: item[0] != first_node)
    return ordered


def grouped_route_lines(route: Any, first_node: str | None = None) -> list[str]:
    """``- PE2: GigabitEthernet0/0/0/0, GigabitEthernet0/0/0/1 (2 ECMP alternatives)`` per node."""
    groups = group_route_by_node(route, first_node)
    if not groups:
        return ["- (no interfaces reported)"]
    lines = []
    for node, interfaces in groups:
        text = f"- {node}: {', '.join(interfaces)}"
        if len(interfaces) > 1:
            text += f" ({len(interfaces)} ECMP alternatives)"
        lines.append(text)
    return lines


def segment_line(hop: dict[str, Any]) -> str:
    """``- step 0: node-ipv4 10.0.0.4 sid 16004`` for one dry-run ``segment-list-hops`` entry."""
    return (
        f"- step {hop.get('step', '?')}: {hop.get('type', '?')} {hop.get('ip-address', '?')} "
        f"sid {hop.get('sid', '?')}"
    )


def path_description(path: dict[str, Any], hops: list[ResolvedNode]) -> str:
    """One line describing the path body sent (for the dry-run / write renderings)."""
    if "hops" in path:
        return "explicit hops " + " > ".join(
            f"{node.node_id} ({node.router_id}/{node.prefix_sid})" for node in hops
        )
    if "bandwidth" in path:
        text = (
            f"bandwidth {path['bandwidth']} Mbps, objective "
            f"{path.get('bw-path-optimization-objective')}"
        )
        if "bw-path-sid-algorithm" in path:
            text += f", sid-algorithm {path['bw-path-sid-algorithm']}"
        return text
    text = (
        f"dynamic, objective {path.get('path-optimization-objective')}, "
        f"protected={path.get('protected')}"
    )
    if "sid-algorithm" in path:
        text += f", sid-algorithm {path['sid-algorithm']}"
    disjointness = path.get("disjointness")
    if isinstance(disjointness, dict):
        text += (
            f", {disjointness.get('disjointness-type')}-disjoint in association group "
            f"{disjointness.get('association-group')}"
        )
        if "association-sub-group" in disjointness:
            text += f" sub-group {disjointness['association-sub-group']}"
    return text


def policy_summary(policy: dict[str, Any] | None) -> dict[str, Any]:
    """The compact view of a topology-NBI policy the wait tool reports (or ``reported: false``)."""
    if policy is None:
        return {"reported": False}
    details = policy_details(policy)
    return {
        "reported": True,
        "headend": policy.get("headend"),
        "endpoint": policy.get("endpoint"),
        "color": policy.get("color"),
        "admin_state": policy.get("admin-state"),
        "oper_state": policy.get("oper-state"),
        "sr_policy_type": policy.get("sr-policy-type"),
        "pce_controlled": as_bool(details.get("pce-controlled")),
        "pcep_flag_c": pcep_flag_c(policy),
        "origin": policy_origin(policy),
        "binding_sid": details.get("binding-sid"),
        "paths": [
            {
                "path_name": p.get("path-name"),
                "path_type": p.get("path-type"),
                "preference": p.get("preference"),
                "oper_state": p.get("oper-state"),
            }
            for p in policy_paths(policy)
        ],
    }


def timeout_hint(target: str, policy: dict[str, Any] | None, seen: bool) -> str:
    """The wait tool's timeout advice, specific to the target, to the LAST poll's answer and
    to whether ANY poll reported the policy.

    ``policy`` is only the last poll's state; ``seen`` is true when at least
    one poll reported the policy. Both matter: a generic "the head-end did
    not accept the PCEP initiate" after a delete (agent scenario 10, target
    DOWN) sent the agent the wrong way TWICE — first because the hint ignored
    the target, then because it ignored that the policy had been reported on
    the first poll and was gone afterwards, which is the converged state after
    cnc_delete_sr_policy (a withdrawn policy is never reported as DOWN — the
    topology NBI answers 409 ``data-missing``). For ``ABSENT`` the policy is
    never ``None`` on a timeout: a poll that does not report it ends the wait.
    """
    if target == "ABSENT":
        if policy is not None and pcep_flag_c(policy) == 0:
            return (
                "The head-end still reports it and it is PCC-initiated (pcep-flag-c 0): the PCE "
                "cannot remove router configuration, so it will not disappear through "
                "cnc_delete_sr_policy — remove it from the router (or NSO) instead."
            )
        return (
            "The head-end still reports it: a PCE-initiated policy is withdrawn within seconds "
            "of cnc_delete_sr_policy, so either the delete did not go through (check its result "
            "and cnc_list_sr_policies_on_nodes, the COE's own view) or the SR-PCE feed lags — "
            "call again to keep waiting."
        )
    if policy is None:
        if seen:
            return (
                "It was reported, then disappeared — after cnc_delete_sr_policy that IS the "
                "converged state (a withdrawn policy does not show up as DOWN, the topology NBI "
                "answers 409 data-missing): wait with target='ABSENT' instead, or confirm with "
                "cnc_list_sr_policies. If nothing deleted it, the head-end withdrew it — check "
                "its PCEP session (cnc_get_topology_node)."
            )
        return (
            "Call again to keep waiting. A policy that is never reported: the head-end did not "
            "accept the PCEP initiate, or does not report it (PCEP report-all) — check its "
            "PCEP session (cnc_get_topology_node) and the SR-PCE provider (cnc_list_providers)."
        )
    return (
        "Call again to keep waiting, or read cnc_get_sr_policy for the candidate paths and "
        "their oper-state."
    )


# --- registration ------------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def topology_nodes(network: str) -> list[dict[str, Any]]:
        """The network's ``node`` entries — the shared resolver's fetch (te_state), bound to
        this client. Every RPC input is validated against it first, because the COE answers
        an unresolved name with the ambiguous empty 500."""
        return await fetch_topology_nodes(client, network)

    async def call_rpc(module: str, rpc: str, body: dict[str, Any] | None) -> dict[str, Any]:
        """POST one RPC and return its ``output`` container.

        ``body`` is the ``{"input": {...}}`` envelope, sent with
        :data:`YANG_HEADERS`; ``None`` sends no body at all (only ``Accept``
        — the verified form of ``get-interface-sr-policy-paths-notification-
        state``). Never auto-retried: these POSTs create, modify and delete
        policies. A bare 500 with an empty body (detected with
        :func:`cnc_mcp.restconf.explain_empty_500`, whose generic text is NOT
        used) is reported as :data:`COE_EMPTY_500_HINT`; any other failure
        through :func:`cnc_mcp.errors.http_error`.
        """
        url = rpc_path(OPTIMIZATION_NBI, module, rpc)
        headers = YANG_HEADERS if body is not None else YANG_ACCEPT
        response = await client.request(
            "POST", url, json_body=body, headers=headers, raise_on_error=False
        )
        if not response.is_success:
            if explain_empty_500(response.status_code, response.text):
                raise PlatformError(COE_EMPTY_500_HINT)
            raise http_error(response)
        data: Any = None
        if response.content:
            try:
                data = response.json()
            except ValueError as e:
                raise PlatformError(
                    "The Optimization Engine returned a non-JSON response where YANG JSON was "
                    "expected."
                ) from e
        return rpc_output(data, module)

    async def read_policy(head: ResolvedNode, end: ResolvedNode, color: int) -> dict | None:
        """The topology NBI's view of one policy, or ``None`` when it is not reported.

        Reads it exactly as cnc_get_sr_policy does (keyed GET with router-ids,
        409 ``data-missing`` = absent, client-side key re-check); any other
        failure is raised through http_error.
        """
        url = sr_policy_url(str(head.router_id), str(end.router_id), color)
        response = await client.request("GET", url, headers=YANG_ACCEPT, raise_on_error=False)
        data: Any = None
        if response.content:
            try:
                data = response.json()
            except ValueError:
                data = None
        if response.status_code == 409 and is_not_found(response.status_code, data):
            return None
        if not response.is_success:
            raise http_error(response)
        entries = entries_matching(
            unwrap_list(data, SR_POLICY_MODULE, "policy"),
            {"headend": head.router_id, "endpoint": end.router_id, "color": color},
        )
        return entries[0] if entries else None

    async def resolve_ends(
        network: str, headend: str, endpoint: str
    ) -> tuple[list[dict[str, Any]], ResolvedNode, ResolvedNode]:
        """Nodes of the network plus the resolved head-end / endpoint (router-ids required)."""
        nodes = await topology_nodes(network)
        head = require_sr(resolve_node(nodes, headend))
        end = require_sr(resolve_node(nodes, endpoint))
        return nodes, head, end

    def resolve_hops(nodes: list[dict[str, Any]], hops: str) -> list[ResolvedNode]:
        """The hop string resolved in order (``[]`` when blank); SR data is checked later."""
        if not hops or not hops.strip():
            return []
        return [resolve_node(nodes, name) for name in parse_names(hops, "hops", "P2,PE2")]

    async def write_policy(
        *,
        rpc: str,
        what: str,
        network: str,
        headend: str,
        endpoint: str,
        color: int,
        path_name: str,
        description: str | None,
        binding_sid: int | None,
        path_type: str,
        objective: str,
        hops: str,
        protected: bool,
        sid_algorithm: int | None,
        disjointness_type: str | None,
        association_group: int | None,
        association_sub_group: int | None,
        bandwidth_mbps: int | None,
        next_hint: str,
    ) -> str:
        """Shared body of cnc_create_sr_policy / cnc_update_sr_policy (create vs modify RPC)."""
        name = path_name.strip()
        if not name:
            raise PlatformError(
                "path_name is empty: the platform requires a candidate-path name for every "
                'policy it creates or modifies ("SR Policy name is empty." otherwise).'
            )
        nodes, head, end = await resolve_ends(network, headend, endpoint)
        hop_nodes = resolve_hops(nodes, hops)
        path = build_policy_path(
            path_type=path_type,
            objective=objective,
            hops=hop_nodes,
            protected=protected,
            sid_algorithm=sid_algorithm,
            disjointness_type=disjointness_type,
            association_group=association_group,
            association_sub_group=association_sub_group,
            bandwidth_mbps=bandwidth_mbps,
        )
        entry: dict[str, Any] = {
            **policy_key(head, end, color),
            "path-name": name,
            "description": description.strip() if description and description.strip() else None,
            "binding-sid": binding_sid,
            "sr-policy-path": path,
        }
        entry = {k: v for k, v in entry.items() if v is not None}
        label = policy_label(head, end, color)
        output = await call_rpc(SRP_MODULE, rpc, rpc_body(**{"sr-policies": [entry]}))
        result = first_result(output, f"{what} of {label}")
        state, message = write_outcome(result, what, label)
        payload: dict[str, Any] = {
            "headend": head.router_id,
            "headend_node": head.node_id,
            "endpoint": end.router_id,
            "endpoint_node": end.node_id,
            "color": color,
            "path_name": name,
            "path": path_description(path, hop_nodes),
            "sr_policy_path": path,
            "state": state,
            "message": message,
            "next": next_hint,
        }
        if state == "degraded":
            payload["note"] = (
                "The platform reports the policy as DEGRADED: it exists but the PCE could not "
                "fully honour the request — read the message, then cnc_get_sr_policy."
            )
        return finalize(to_json(payload), settings)

    # --- READ tools ---------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_sr_policies_on_nodes",
        title="List SR Policies on Nodes",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_sr_policies_on_nodes(
        nodes: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated nodes to ask about, each a node id (host name, "
                    "case-insensitive) or a TE router-id, e.g. 'PE1,P1'."
                ),
                min_length=1,
                max_length=2000,
            ),
        ],
        relation: Annotated[
            str,
            Field(
                description=(
                    "How the policies relate to the nodes: 'source' (head-end), 'destination' "
                    "(endpoint), 'source-or-destination' (default) or 'through' (transit hop)."
                ),
                max_length=40,
            ),
        ] = DEFAULT_RELATION,
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the SR policies that start at, end at, or pass through the given nodes.

        Read-only. Asks the Optimization Engine (``POST .../operations/
        cisco-crosswork-optimization-engine-operations:sr-policies-on-node``
        with ``{"input": {"nodes": [{"node": "<node-id>"}, ...], "filter":
        "<relation>"}}``) which policies the COE's path model has each node
        as head-end / endpoint / transit for. It answers per node with the
        policy KEYS only (``head-end``, ``end-point``, ``color`` — router-ids);
        read a policy's state and paths with cnc_get_sr_policy. Unlike
        cnc_list_sr_policies (the PCE's reported policies), this is the COE's
        computed view, so a policy whose path the COE could not compute may be
        missing here. Node names are validated against the topology first
        (an unknown host name would otherwise be answered with an ambiguous
        empty 500) and sent as node ids — a router-id is accepted and
        translated.

        Args:
            nodes: comma-separated node ids or router-ids.
            relation: source | destination | source-or-destination | through
                (wire filter nodes-as-source | nodes-as-destination |
                nodes-as-source-or-destination | through-nodes).
            network: topology network id the names are resolved in.
            response_format: markdown (one section per node listing "head-end
                -> end-point color N" and the node's message when the COE gave
                one) or json (the raw RPC output).

        Returns:
            str: Markdown, or the JSON ``output`` {"status": "accepted",
            "node-sr-policies": [{"node", "message", "sr-policies": [{"head-end",
            "end-point", "color"}]}]}. "Error: no node '<x>' in the topology
            ..." when a name does not resolve (nothing is sent); "Error: ...
            rejected the request (empty 500) ..." for the COE's bare 500;
            "Error: <what> failed: <message>" when output.status is error;
            "Error: ..." on any other API failure.
        """
        try:
            wire_filter = normalize_relation(relation)
            names = parse_names(nodes, "nodes", "PE1,P1")
            topology = await topology_nodes(network)
            resolved = [resolve_node(topology, name) for name in names]
            body = rpc_body(nodes=[{"node": node.node_id} for node in resolved], filter=wire_filter)
            output = check_coe_status(
                await call_rpc(COE_MODULE, RPC_POLICIES_ON_NODE, body), "sr-policies-on-node"
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            entries = dict_list(output.get("node-sr-policies"))
            by_node = {str(e.get("node")): e for e in entries}
            lines = [
                f"# SR policies on {', '.join(n.node_id for n in resolved)} (filter {wire_filter})"
            ]
            for node in resolved:
                entry = by_node.get(node.node_id, {})
                policies = dict_list(entry.get("sr-policies"))
                lines.extend(["", f"## {node_label(node)} ({len(policies)} policies)"])
                lines.extend(_policy_lines(policies, entry.get("message")))
            lines.extend(
                [
                    "",
                    "Keys are (head-end, end-point, color) with the router-ids; cnc_get_sr_policy "
                    "shows state and paths, cnc_get_sr_policy_routes the interfaces a policy uses.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_sr_policies_on_interface",
        title="List SR Policies on Interface",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_sr_policies_on_interface(
        node: Annotated[
            str,
            Field(
                description=f"The interface's node: {_NODE_HELP}.",
                min_length=1,
                max_length=253,
            ),
        ],
        interface: Annotated[
            str,
            Field(
                description=(
                    "The interface name as the topology lists it (a termination point of the "
                    "node, e.g. 'GigabitEthernet0/0/0/0'); cnc_list_node_interfaces shows them."
                ),
                min_length=1,
                max_length=253,
            ),
        ],
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the SR policies whose computed path uses one interface.

        Read-only. ``POST .../cisco-crosswork-optimization-engine-operations:
        sr-policies-on-interface`` with ``{"input": {"interfaces": [{"node":
        "<node-id>", "interface": "<tp-id>"}]}}`` — the COE's view of which
        policies are forwarded out of that interface (the same routes
        cnc_get_sr_policy_routes shows per policy, inverted). Use it before
        maintenance on a link to see what would be affected. Both the node
        (host name or router-id) and the interface are validated against the
        topology first: the interface must be one of the node's termination
        points, exact spelling (a case-insensitive unique match is accepted),
        because the COE answers an unknown interface with an ambiguous empty
        500.

        Args:
            node: node id or router-id.
            interface: the termination-point id on that node.
            network: topology network id.
            response_format: markdown (the policy keys and the COE's message
                when given) or json (the raw RPC output).

        Returns:
            str: Markdown, or the JSON ``output`` {"status", "interface-sr-policies":
            [{"node", "interface", "message", "sr-policies": [{"head-end",
            "end-point", "color"}]}]}. "Error: no interface '<x>' on node
            '<n>' ... Its termination points are: ..." when it is not one of
            the node's interfaces (nothing is sent); "Error: no node ..." for
            an unknown node; "Error: ..." on an API failure (empty 500 -> the
            COE hint).
        """
        try:
            topology = await topology_nodes(network)
            node_entry = find_node(topology, node)
            node_id = node_id_of(node_entry)
            tp_id = resolve_interface(node_entry, interface)
            body = rpc_body(interfaces=[{"node": node_id, "interface": tp_id}])
            output = check_coe_status(
                await call_rpc(COE_MODULE, RPC_POLICIES_ON_INTERFACE, body),
                "sr-policies-on-interface",
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            entries = dict_list(output.get("interface-sr-policies"))
            lines = [f"# SR policies on {node_id}:{tp_id}"]
            if not entries:
                lines.extend(["", "- (the Optimization Engine returned no entry)"])
            for entry in entries:
                policies = dict_list(entry.get("sr-policies"))
                lines.extend(
                    [
                        "",
                        f"## {entry.get('node', node_id)}:{entry.get('interface', tp_id)} "
                        f"({len(policies)} policies)",
                    ]
                )
                lines.extend(_policy_lines(policies, entry.get("message")))
            lines.extend(
                [
                    "",
                    "Keys are (head-end, end-point, color) with the router-ids; "
                    "cnc_get_sr_policy_routes shows every interface a policy uses.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_sr_policy_routes",
        title="Get SR Policy IGP Route",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_sr_policy_routes(
        headend: Annotated[str, Field(description=_HEADEND_DESC, min_length=1, max_length=253)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, min_length=1, max_length=253)],
        color: Annotated[int, Field(description=_COLOR_DESC, ge=1, le=4294967295)],
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the interfaces (with ECMP shares) an SR policy's traffic is forwarded over.

        Read-only. ``POST .../cisco-crosswork-optimization-engine-operations:
        sr-policy-routes`` with ``{"input": {"sr-policies": [{"head-end",
        "end-point", "color"}]}}`` — the COE resolves the policy's segment
        list over the IGP topology and lists every ``node:interface`` on the
        way with ``interface-use``, the fraction of the policy's traffic that
        interface carries (``"0.5"`` on an ECMP split; a string on the wire).
        headend/endpoint accept host names or router-ids and are sent as
        router-ids. The policy must exist in the COE's model: an unknown key
        answers ``path-computation-status: failure`` (still HTTP 200) and is
        reported as "no route could be computed".

        Args:
            headend, endpoint: node ids or router-ids.
            color: the policy color.
            network: topology network id.
            response_format: markdown ("node:interface (share x)" per hop
                interface) or json (the raw RPC output).

        Returns:
            str: Markdown, or the JSON ``output`` {"status", "results":
            [{"head-end", "end-point", "color", "path-computation-status",
            "igp-route": [{"node", "interface", "interface-use"}]}]}. "Error:
            no route could be computed for SR policy <h> -> <e> color <c> (the
            policy may not exist — check cnc_list_sr_policies)" on failure;
            "Error: no node ..." for an unresolvable name; "Error: ..." on an
            API failure (empty 500 -> the COE hint).
        """
        try:
            _nodes, head, end = await resolve_ends(network, headend, endpoint)
            label = policy_label(head, end, color)
            body = rpc_body(**{"sr-policies": [policy_key(head, end, color)]})
            output = check_coe_status(
                await call_rpc(COE_MODULE, RPC_POLICY_ROUTES, body), "sr-policy-routes"
            )
            result = first_result(output, f"the route of SR policy {label}")
            if not computed(result):
                raise PlatformError(
                    f"no route could be computed for SR policy {label} (the policy may not "
                    "exist — check cnc_list_sr_policies)"
                )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            hops = dict_list(result.get("igp-route"))
            lines = [f"# IGP route of SR policy {label} ({len(hops)} interfaces)", ""]
            lines.extend(route_lines(hops))
            lines.extend(
                [
                    "",
                    "share = interface-use, the fraction of the policy's traffic forwarded out of "
                    "that interface (0.5 on a two-way ECMP split).",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_sr_policy_metrics",
        title="Get SR Policy Path Metrics",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_sr_policy_metrics(
        headend: Annotated[str, Field(description=_HEADEND_DESC, min_length=1, max_length=253)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, min_length=1, max_length=253)],
        color: Annotated[int, Field(description=_COLOR_DESC, ge=1, le=4294967295)],
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the cumulative IGP metric, TE metric and modelled delay of an SR policy's path.

        Read-only. ``POST .../cisco-crosswork-optimization-engine-operations:
        sr-policy-metrics`` with the policy key — the COE sums the metrics of
        the links its computed route uses (``igp-metric``, ``te-metric``,
        ``delay`` in microseconds as the topology models them). This is the
        COE's simulation, not measured performance. The PM entry
        (cnc_get_sr_policy_performance_metrics) is **also modelled unless
        NAPM/SR-PM telemetry is configured** — verified live 2026-09-14: its
        ``delay`` (20) equalled this RPC's ``delay`` (20) with no
        ``*-telemetry`` key present — so neither answers "what is the
        measured delay?" on a network without SR-PM probes; measured LSP
        delay samples come from cnc_get_lsp_delay (empty until probes run),
        and the PM entry's ``bandwidth-utilization-kbps`` is the collected
        throughput. headend / endpoint accept host names or router-ids. An
        unknown policy answers ``path-computation-status: failure`` and is
        reported as an error.

        Args:
            headend, endpoint: node ids or router-ids.
            color: the policy color.
            network: topology network id.
            response_format: markdown or json (the raw RPC output).

        Returns:
            str: Markdown ("- igp-metric=N te-metric=N delay=N"), or the JSON
            ``output`` {"status", "results": [{"head-end", "end-point", "color",
            "path-computation-status", "igp-metric", "te-metric", "delay"}]}.
            "Error: no metrics could be computed for SR policy ... (the policy
            may not exist — check cnc_list_sr_policies)" on failure; "Error:
            ..." on an unresolvable name or an API failure.
        """
        try:
            _nodes, head, end = await resolve_ends(network, headend, endpoint)
            label = policy_label(head, end, color)
            body = rpc_body(**{"sr-policies": [policy_key(head, end, color)]})
            output = check_coe_status(
                await call_rpc(COE_MODULE, RPC_POLICY_METRICS, body), "sr-policy-metrics"
            )
            result = first_result(output, f"the metrics of SR policy {label}")
            if not computed(result):
                raise PlatformError(
                    f"no metrics could be computed for SR policy {label} (the policy may not "
                    "exist — check cnc_list_sr_policies)"
                )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            lines = [
                f"# Path metrics of SR policy {label}",
                "",
                f"- igp-metric={result.get('igp-metric', '-')} "
                f"te-metric={result.get('te-metric', '-')} delay={result.get('delay', '-')}",
                "",
                "Cumulative metrics of the COE's computed route (delay in microseconds as "
                "modelled, not measured). The PM entry (cnc_get_sr_policy_performance_metrics) "
                "is modelled too unless NAPM/SR-PM telemetry is configured; measured LSP delay "
                "samples are cnc_get_lsp_delay.",
            ]
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_preview_sr_policy_route",
        title="Preview SR Policy Route",
        read_only=True,
        idempotent=True,
    )
    async def cnc_preview_sr_policy_route(
        headend: Annotated[str, Field(description=_HEADEND_DESC, min_length=1, max_length=253)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, min_length=1, max_length=253)],
        hops: Annotated[
            str,
            Field(
                description=(
                    f"{_HOPS_DESC} Leave empty to preview the plain IGP/ECMP route from head-end "
                    "to endpoint."
                ),
                max_length=2000,
            ),
        ] = "",
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Preview the interfaces a segment list (or the plain IGP path) would be forwarded over.

        Read-only, creates nothing. ``POST .../cisco-crosswork-optimization-
        engine-operations:sr-policy-route-preview`` with ``{"input":
        {"head-end", "end-point", "sr-policy-path": {"hops": [...]}}}`` — the
        COE resolves the explicit hops over the IGP topology and lists every
        ``node:interface`` with its ECMP share. With ``hops`` empty the tool
        sends ``"sr-policy-path": {}``, which previews the plain IGP/ECMP
        route between the two nodes (verified live). Each hop is sent as a
        node prefix-SID hop with BOTH ``node-ipv4-address`` and
        ``node-ipv4-sid`` (the explicit-hop rule), resolved from the topology.
        Compare with cnc_dryrun_sr_policy, which also returns the segment
        list the PCE would program and accepts dynamic constraints.

        Args:
            headend, endpoint: node ids or router-ids.
            hops: comma-separated node ids / router-ids, or empty.
            network: topology network id.
            response_format: markdown or json (the raw RPC output).

        Returns:
            str: Markdown ("node:interface (share x)" per interface), or the
            JSON ``output`` {"status", "path-computation-status", "igp-route":
            [{"node", "interface", "interface-use"}]}. "Error: no path could
            be computed from <h> to <e> ..." when the COE reports failure;
            "Error: no node ..." / "Error: node '<x>' has no SR data ..." when
            a name or hop does not resolve (nothing is sent); "Error: ..." on
            an API failure (empty 500 -> the COE hint).
        """
        try:
            nodes, head, end = await resolve_ends(network, headend, endpoint)
            hop_nodes = resolve_hops(nodes, hops)
            path: dict[str, Any] = {"hops": explicit_hops(hop_nodes)} if hop_nodes else {}
            body = rpc_body(
                **{"head-end": head.router_id, "end-point": end.router_id, "sr-policy-path": path}
            )
            output = check_coe_status(
                await call_rpc(COE_MODULE, RPC_ROUTE_PREVIEW, body), "sr-policy-route-preview"
            )
            via = (
                " via " + " > ".join(node_label(n) for n in hop_nodes)
                if hop_nodes
                else " (plain IGP route)"
            )
            if not computed(output):
                reason = output.get("message")
                if not isinstance(reason, str) or not reason.strip():
                    reason = "the Optimization Engine reported path-computation-status failure"
                raise PlatformError(
                    f"no path could be computed from {node_label(head)} to {node_label(end)}"
                    f"{via}: {reason.strip()}"
                )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            route = dict_list(output.get("igp-route"))
            lines = [
                f"# Route preview {node_label(head)} -> {node_label(end)}{via} "
                f"({len(route)} interfaces)",
                "",
            ]
            lines.extend(route_lines(route))
            lines.extend(
                [
                    "",
                    "Nothing was created. share = interface-use (ECMP fraction). "
                    "cnc_dryrun_sr_policy adds the segment list the PCE would program.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_dryrun_sr_policy",
        title="Dry-run SR Policy Path",
        read_only=True,
        idempotent=True,
    )
    async def cnc_dryrun_sr_policy(
        headend: Annotated[str, Field(description=_HEADEND_DESC, min_length=1, max_length=253)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, min_length=1, max_length=253)],
        path_type: Annotated[str, Field(description=_PATH_TYPE_DESC, max_length=20)] = (
            DEFAULT_PATH_TYPE
        ),
        objective: Annotated[str, Field(description=_OBJECTIVE_DESC, max_length=20)] = (
            DEFAULT_OBJECTIVE
        ),
        hops: Annotated[str, Field(description=_HOPS_DESC, max_length=2000)] = "",
        protected: Annotated[bool, Field(description=_PROTECTED_DESC)] = True,
        sid_algorithm: Annotated[
            int | None, Field(description=_SID_ALGORITHM_DESC, ge=0, le=255)
        ] = None,
        disjointness_type: Annotated[
            str | None, Field(description=_DISJOINTNESS_TYPE_DESC, max_length=20)
        ] = None,
        association_group: Annotated[
            int | None, Field(description=_ASSOCIATION_GROUP_DESC, ge=0, le=4294967295)
        ] = None,
        association_sub_group: Annotated[
            int | None, Field(description=_ASSOCIATION_SUB_GROUP_DESC, ge=0, le=4294967295)
        ] = None,
        bandwidth_mbps: Annotated[
            int | None, Field(description=_BANDWIDTH_DESC, ge=1, le=2147483647)
        ] = None,
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Compute the segment list and route the PCE WOULD program for a policy, without
        creating it.

        Read-only, creates nothing. ``POST .../cisco-crosswork-optimization-
        engine-sr-policy-operations:sr-policy-dryrun`` with ``{"input":
        {"head-end", "end-point", "sr-policy-path": {...}}}`` where the path
        is built exactly as cnc_create_sr_policy builds it (same arguments,
        same :func:`build_policy_path`): ``dynamic`` (objective, protected,
        optional sid_algorithm and disjointness), ``explicit`` (hops, each a
        node prefix-SID hop with both address and SID) or ``bandwidth``
        (bandwidth_mbps + objective). Run it before creating a policy to see
        the segment list and the IGP route, and to catch constraint failures
        early. Verified outcomes: ``state: success`` with ``segment-list-hops``
        and ``igp-route``; ``failure`` "No path found for the given
        constraints. " for an unreachable endpoint / impossible constraint;
        ``failure`` "Bandwidth On Demand currently dormant: disabled" for a
        bandwidth path on a deployment without the BWoD feature. A failure is
        reported as "Error: dry run failed ...", a ``degraded`` state as a
        success carrying the platform's message. Names are resolved from the
        topology first — nothing is sent when a name or hop is unknown.

        Reading the IGP route (verified live 2026-09-14, agent scenario 10):
        the dry run's ``igp-route`` is **unordered and carries no
        ``interface-use``** (``P2:Gi0/0/0/1, PE2:Gi0/0/0/1, P1:Gi0/0/0/0,
        PE2:Gi0/0/0/0`` for a PE2 -> PE1 dynamic path that is really a
        two-way ECMP split via P1 and P2). It is the set of interfaces the
        path would be forwarded over, not a hop sequence: several interfaces
        on the same node are ECMP alternatives. The markdown therefore groups
        the interfaces by node (head-end first) and says so; the per-interface
        shares (``interface-use`` 0.5/0.5) are available from
        cnc_get_sr_policy_routes once the policy exists. The ordered path is
        the segment list.

        Args:
            headend, endpoint: node ids or router-ids.
            path_type: dynamic | explicit | bandwidth.
            objective: igp-metric | te-metric | delay | hop-count (dynamic /
                bandwidth paths).
            hops: comma-separated node ids / router-ids (explicit paths).
            protected, sid_algorithm, disjointness_type, association_group,
                association_sub_group: dynamic-path constraints.
            bandwidth_mbps: the bandwidth path's reservation.
            network: topology network id.
            response_format: markdown (the path sent, the segment list as
                "step, type, ip-address, sid" lines and the IGP route grouped
                by node) or json (the raw RPC output, ``igp-route`` as the
                platform lists it — unordered).

        Returns:
            str: Markdown, or the JSON ``output`` {"state": "success" |
            "degraded", "message"?, "segment-list-hops": [{"step", "sid",
            "ip-address", "type": "node-ipv4" | "adjacency-ipv4"}], "igp-route":
            [{"node", "interface"}] (unordered, no interface-use)}. "Error:
            dry run failed for <h> -> <e>: <message>" on ``state: failure``;
            "Error: ..." for an unknown name/hop, an invalid argument
            combination (e.g. hops with a dynamic path) or an API failure
            (empty 500 -> the COE hint).
        """
        try:
            nodes, head, end = await resolve_ends(network, headend, endpoint)
            hop_nodes = resolve_hops(nodes, hops)
            path = build_policy_path(
                path_type=path_type,
                objective=objective,
                hops=hop_nodes,
                protected=protected,
                sid_algorithm=sid_algorithm,
                disjointness_type=disjointness_type,
                association_group=association_group,
                association_sub_group=association_sub_group,
                bandwidth_mbps=bandwidth_mbps,
            )
            label = f"{node_label(head)} -> {node_label(end)}"
            body = rpc_body(
                **{"head-end": head.router_id, "end-point": end.router_id, "sr-policy-path": path}
            )
            output = await call_rpc(SRP_MODULE, RPC_DRYRUN, body)
            state, message = write_outcome(output, "dry run", label)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            segments = dict_list(output.get("segment-list-hops"))
            route = dict_list(output.get("igp-route"))
            lines = [
                f"# SR policy dry run {label}: {state}",
                "",
                f"- path: {path_description(path, hop_nodes)}",
            ]
            if message:
                lines.append(f"- message: {message}")
            lines.extend(["", f"Segment list ({len(segments)} hops, in path order):"])
            lines.extend([segment_line(s) for s in segments] or ["- (none reported)"])
            groups = group_route_by_node(route, head.node_id)
            lines.extend(
                [
                    "",
                    f"IGP route ({len(route)} interfaces on {len(groups)} nodes, grouped by "
                    "node — unordered; interfaces on one node are ECMP alternatives):",
                ]
            )
            lines.extend(grouped_route_lines(route, head.node_id))
            lines.extend(
                [
                    "",
                    "The route is the set of interfaces the path would be forwarded over, not a "
                    "hop sequence (the segment list is the ordered path); the platform lists it "
                    "unordered and without shares — per-interface ECMP shares come from "
                    "cnc_get_sr_policy_routes once the policy exists. Nothing was created: this "
                    "is what the PCE would program. cnc_create_sr_policy with the same arguments "
                    "(plus color and path_name) provisions it.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_sr_policy_path_notification_state",
        title="Get SR Policy Path Notification State",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_sr_policy_path_notification_state() -> str:
        """Report whether the Optimization Engine emits interface SR-policy-path notifications.

        Read-only. ``POST .../cisco-crosswork-optimization-engine-operations:
        get-interface-sr-policy-paths-notification-state`` with NO body
        (verified live — only ``Accept`` is sent) answers ``{"status":
        "accepted", "enabled": true|false}``. When enabled, the COE publishes
        a notification whenever the set of SR policy paths crossing an
        interface changes (consumed by Crosswork's notification streams, out
        of MCP scope). Change it with cnc_set_sr_policy_path_notifications.

        Returns:
            str: "SR policy path notifications are enabled." or "... disabled."
            followed by the JSON ``output``. "Error: ..." on an API failure
            (``status: error`` inside 200, or an empty 500 -> the COE hint).
        """
        try:
            output = check_coe_status(
                await call_rpc(COE_MODULE, RPC_GET_NOTIFICATION_STATE, None),
                "get-interface-sr-policy-paths-notification-state",
            )
            enabled = as_bool(output.get("enabled"))
            if enabled is None:
                head = (
                    "The Optimization Engine did not report a boolean 'enabled'; the raw answer "
                    "follows."
                )
            else:
                head = f"SR policy path notifications are {'enabled' if enabled else 'disabled'}."
            return finalize(f"{head}\n{to_json(output)}", settings)
        except Exception as e:
            return format_error(e)

    # --- WRITE tools --------------------------------------------------------------

    _CREATE_NEXT = (
        "The policy is PCE-initiated and appears on the headend within seconds; verify with "
        "cnc_get_sr_policy(headend, endpoint, color) or "
        "cnc_wait_for_sr_policy_oper_state(headend, endpoint, color). A head-end that does not "
        "report it (no PCEP report-all) leaves it unreported there although it exists; "
        "cnc_delete_sr_policy(..., force=true) still removes it."
    )
    _UPDATE_NEXT = (
        "The PCE re-signals the policy with the new path within seconds; verify with "
        "cnc_get_sr_policy(headend, endpoint, color) or "
        "cnc_wait_for_sr_policy_oper_state(headend, endpoint, color)."
    )

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_sr_policy",
        title="Create SR Policy (PCE-initiated)",
        read_only=False,
        destructive=False,
        idempotent=False,
        dry_run_hint="preview the computed path with cnc_dryrun_sr_policy",
    )
    async def cnc_create_sr_policy(
        headend: Annotated[str, Field(description=_HEADEND_DESC, min_length=1, max_length=253)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, min_length=1, max_length=253)],
        color: Annotated[
            int,
            Field(
                description="The policy color, unique per (headend, endpoint) (e.g. 200).",
                ge=1,
                le=4294967295,
            ),
        ],
        path_name: Annotated[str, Field(description=_PATH_NAME_DESC, min_length=1, max_length=64)],
        description: Annotated[
            str | None,
            Field(description="Free-text description stored with the policy.", max_length=255),
        ] = None,
        path_type: Annotated[str, Field(description=_PATH_TYPE_DESC, max_length=20)] = (
            DEFAULT_PATH_TYPE
        ),
        objective: Annotated[str, Field(description=_OBJECTIVE_DESC, max_length=20)] = (
            DEFAULT_OBJECTIVE
        ),
        hops: Annotated[str, Field(description=_HOPS_DESC, max_length=2000)] = "",
        protected: Annotated[bool, Field(description=_PROTECTED_DESC)] = True,
        sid_algorithm: Annotated[
            int | None, Field(description=_SID_ALGORITHM_DESC, ge=0, le=255)
        ] = None,
        disjointness_type: Annotated[
            str | None, Field(description=_DISJOINTNESS_TYPE_DESC, max_length=20)
        ] = None,
        association_group: Annotated[
            int | None, Field(description=_ASSOCIATION_GROUP_DESC, ge=0, le=4294967295)
        ] = None,
        association_sub_group: Annotated[
            int | None, Field(description=_ASSOCIATION_SUB_GROUP_DESC, ge=0, le=4294967295)
        ] = None,
        bandwidth_mbps: Annotated[
            int | None, Field(description=_BANDWIDTH_DESC, ge=1, le=2147483647)
        ] = None,
        binding_sid: Annotated[
            int | None,
            Field(
                description=(
                    "Binding SID to request (a label from the head-end's SRLB, e.g. 15001). "
                    "Omit to let the head-end allocate one."
                ),
                ge=16,
                le=1048575,
            ),
        ] = None,
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
    ) -> str:
        """Create a PCE-initiated SR policy on a head-end through the SR-PCE.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        ``POST .../cisco-crosswork-optimization-engine-sr-policy-operations:
        sr-policy-create`` with ``{"input": {"sr-policies": [{"head-end",
        "end-point", "color", "path-name", "description"?, "binding-sid"?,
        "sr-policy-path": {...}}]}}``. The PCE instantiates the policy on the
        head-end over PCEP: verified live, it is on the router within seconds
        (candidate path "(PCEP)" with the given path-name, the SIDs, a BSID)
        and appears on the topology NBI with ``pcep-flag-c: 1`` and
        ``pce-controlled: true``. Names are resolved from the topology first
        (host names or router-ids; router-ids go on the wire) and the path is
        built by :func:`build_policy_path` — run cnc_dryrun_sr_policy with the
        same arguments first to see the segment list. ``path_name`` is
        REQUIRED by the platform ("SR Policy name is empty." otherwise). The
        POST is never auto-retried (a lost answer could duplicate the policy —
        re-run and read the "already exists" outcome). Delete with
        cnc_delete_sr_policy; change the path with cnc_update_sr_policy.

        Verified failure messages (``state: failure`` inside HTTP 200,
        reported as "Error: create failed for <key>: ..."): "An SR Policy with
        same color, headend and endpoint already exists." (duplicate key —
        use cnc_update_sr_policy or another color); "No permission for device
        <ip>. Contact your administrator for permissions." (the head-end is
        not an inventory device the account may write to); "Bandwidth On
        Demand currently dormant: disabled" (bandwidth path without BWoD).

        Args:
            headend, endpoint: node ids or router-ids.
            color: the policy color (unique per head-end/endpoint pair).
            path_name: the candidate-path name (required).
            description: optional text.
            path_type, objective, hops, protected, sid_algorithm,
                disjointness_type, association_group, association_sub_group,
                bandwidth_mbps: the path, as in cnc_dryrun_sr_policy.
            binding_sid: optional BSID label.
            network: topology network id.

        Returns:
            str: JSON {"headend", "headend_node", "endpoint", "endpoint_node",
            "color", "path_name", "path" (one-line description),
            "sr_policy_path" (the body sent), "state": "success" | "degraded",
            "message", "next": how to verify} (+ "note" when degraded).
            "Error: create failed for <key>: <platform message>" on ``state:
            failure``; "Error: no node ..." / "Error: node ... has no SR data"
            when a name does not resolve (nothing is sent); "Error: ..." for an
            invalid argument combination or an API failure (empty 500 -> the
            COE hint).
        """
        try:
            return await write_policy(
                rpc=RPC_CREATE,
                what="create",
                network=network,
                headend=headend,
                endpoint=endpoint,
                color=color,
                path_name=path_name,
                description=description,
                binding_sid=binding_sid,
                path_type=path_type,
                objective=objective,
                hops=hops,
                protected=protected,
                sid_algorithm=sid_algorithm,
                disjointness_type=disjointness_type,
                association_group=association_group,
                association_sub_group=association_sub_group,
                bandwidth_mbps=bandwidth_mbps,
                next_hint=_CREATE_NEXT,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_sr_policy",
        title="Update SR Policy Path (full replacement)",
        read_only=False,
        destructive=True,
        idempotent=True,
        dry_run_hint="preview the computed path with cnc_dryrun_sr_policy",
    )
    async def cnc_update_sr_policy(
        headend: Annotated[str, Field(description=_HEADEND_DESC, min_length=1, max_length=253)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, min_length=1, max_length=253)],
        color: Annotated[int, Field(description=_COLOR_DESC, ge=1, le=4294967295)],
        path_name: Annotated[str, Field(description=_PATH_NAME_DESC, min_length=1, max_length=64)],
        description: Annotated[
            str | None,
            Field(description="Free-text description stored with the policy.", max_length=255),
        ] = None,
        path_type: Annotated[str, Field(description=_PATH_TYPE_DESC, max_length=20)] = (
            DEFAULT_PATH_TYPE
        ),
        objective: Annotated[str, Field(description=_OBJECTIVE_DESC, max_length=20)] = (
            DEFAULT_OBJECTIVE
        ),
        hops: Annotated[str, Field(description=_HOPS_DESC, max_length=2000)] = "",
        protected: Annotated[bool, Field(description=_PROTECTED_DESC)] = True,
        sid_algorithm: Annotated[
            int | None, Field(description=_SID_ALGORITHM_DESC, ge=0, le=255)
        ] = None,
        disjointness_type: Annotated[
            str | None, Field(description=_DISJOINTNESS_TYPE_DESC, max_length=20)
        ] = None,
        association_group: Annotated[
            int | None, Field(description=_ASSOCIATION_GROUP_DESC, ge=0, le=4294967295)
        ] = None,
        association_sub_group: Annotated[
            int | None, Field(description=_ASSOCIATION_SUB_GROUP_DESC, ge=0, le=4294967295)
        ] = None,
        bandwidth_mbps: Annotated[
            int | None, Field(description=_BANDWIDTH_DESC, ge=1, le=2147483647)
        ] = None,
        binding_sid: Annotated[
            int | None,
            Field(
                description=(
                    "Binding SID to request (a label from the head-end's SRLB, e.g. 15001). "
                    "Omit to keep letting the head-end allocate one."
                ),
                ge=16,
                le=1048575,
            ),
        ] = None,
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
    ) -> str:
        """Replace the path (and name/description) of an existing PCE-initiated SR policy.

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true.
        ``POST .../cisco-crosswork-optimization-engine-sr-policy-operations:
        sr-policy-modify`` with the same body as create. **This is a FULL
        replacement, not a patch**: the ``sr-policy-path`` you give becomes the
        policy's path (an explicit path replaces a dynamic one and vice
        versa), and path-name / description are set to what you pass — read
        the current policy with cnc_get_sr_policy first and pass everything
        you want to keep. The key ``(headend, endpoint, color)`` must be an
        existing policy the PCE initiated: an unknown key answers ``state:
        failure`` "Policy does not exist in the system to update." (verified
        live) — a PCC-initiated policy (``pcep-flag-c: 0``) is not the PCE's
        to modify. Names are resolved from the topology first; the POST is not
        auto-retried. Re-running the same modify is idempotent.

        Args:
            headend, endpoint, color: the policy key (names or router-ids).
            path_name: the candidate-path name (required by the platform).
            description, path_type, objective, hops, protected, sid_algorithm,
                disjointness_type, association_group, association_sub_group,
                bandwidth_mbps, binding_sid: the new definition, as in
                cnc_create_sr_policy.
            network: topology network id.

        Returns:
            str: JSON as cnc_create_sr_policy returns it ({"headend",
            "endpoint", "color", "path_name", "path", "sr_policy_path",
            "state", "message", "next"}). "Error: modify failed for <key>:
            Policy does not exist in the system to update." for an unknown
            key; "Error: ..." for an unresolvable name, an invalid argument
            combination or an API failure (empty 500 -> the COE hint).
        """
        try:
            return await write_policy(
                rpc=RPC_MODIFY,
                what="modify",
                network=network,
                headend=headend,
                endpoint=endpoint,
                color=color,
                path_name=path_name,
                description=description,
                binding_sid=binding_sid,
                path_type=path_type,
                objective=objective,
                hops=hops,
                protected=protected,
                sid_algorithm=sid_algorithm,
                disjointness_type=disjointness_type,
                association_group=association_group,
                association_sub_group=association_sub_group,
                bandwidth_mbps=bandwidth_mbps,
                next_hint=_UPDATE_NEXT,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_sr_policy",
        title="Delete SR Policy (PCE-initiated)",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_sr_policy(
        headend: Annotated[str, Field(description=_HEADEND_DESC, min_length=1, max_length=253)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, min_length=1, max_length=253)],
        color: Annotated[int, Field(description=_COLOR_DESC, ge=1, le=4294967295)],
        force: Annotated[
            bool,
            Field(
                description=(
                    "Send the delete even when the safety read cannot vouch for it: the policy "
                    "is not reported on the topology NBI (a head-end without PCEP report-all, "
                    "the seconds after a create, or the SR-PCE feed being down), it is "
                    "PCC-initiated (pcep-flag-c 0 — the PCE cannot remove the router's "
                    "configuration), or it carries no pcep-flag-c at all."
                ),
            ),
        ] = False,
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
    ) -> str:
        """Delete a PCE-initiated SR policy through the SR-PCE.

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true.
        SAFETY: the tool first reads the policy on the topology NBI (``GET
        .../cisco-crosswork-segment-routing-policy:sr-policies/policy=
        <headend>,<endpoint>,<color>`` — exactly what cnc_get_sr_policy reads,
        i.e. the SR-PCE's PCC report, not the COE's own model) and, without
        ``force``, sends the delete only when that read vouches for it:

        1. not reported (409 ``data-missing``) -> "Error: no SR policy ... is
           reported ...; nothing was deleted" (nothing is sent). The NBI does
           not report a policy while the head-end does not ``report-all`` it,
           in the seconds after a create, or while the SR-PCE gRPC feed is
           down — yet ``sr-policy-delete`` is exactly what removes a
           PCE-initiated policy in those cases, so ``force=true`` sends it
           anyway (``pcep_flag_c: null``, ``reported: false`` and a note in
           the answer; a key the COE does not know answers ``state:
           failure`` with the platform's message);
        2. ``policy-details.pcep-info.pcep-flag-c`` is 0 -> the policy is
           PCC-initiated (configured on the head-end router, possibly
           delegated to the PCE): a PCEP delete cannot remove the router's
           configuration, so the tool refuses unless ``force=true``. Remove
           such a policy on the router (or through NSO) instead;
        3. no ``pcep-flag-c`` at all (or a value other than 0/1) -> the tool
           cannot tell who initiated the policy and refuses unless
           ``force=true`` (every policy on the verified build carries the
           flag);
        4. otherwise (``pcep-flag-c: 1``, PCE-initiated) -> ``POST .../
           cisco-crosswork-optimization-engine-sr-policy-operations:
           sr-policy-delete`` with ``{"input": {"sr-policies": [{"head-end",
           "end-point", "color"}]}}`` and the ``results[0]`` outcome is
           reported.

        Names are resolved from the topology (host names or router-ids); the
        POST is not auto-retried but re-running it is safe (a policy already
        gone answers the "not reported" error without force). The head-end
        withdraws the policy within seconds; the convergence signal is the
        policy becoming ABSENT from the topology NBI (409 ``data-missing``
        — the only signal there is, no "withdrawn" state exists): verify with
        cnc_wait_for_sr_policy_oper_state(..., target="ABSENT") or
        cnc_get_sr_policy (expect "Error: no SR policy ... is reported").
        Do NOT wait for target="DOWN" after a delete — a removed policy is
        never reported as DOWN, so that wait only times out.

        Args:
            headend, endpoint, color: the policy key.
            force: send the delete anyway when the policy is not reported,
                PCC-initiated, or of unknown origin (cases 1-3).
            network: topology network id.

        Returns:
            str: JSON {"headend", "headend_node", "endpoint", "endpoint_node",
            "color", "reported" (bool), "pcep_flag_c" (1, 0 or null),
            "forced" (true when force was needed to proceed), "state":
            "success" | "degraded", "message", "next"} (+ "note" when forced).
            "Error: no SR policy <key> is reported ...; nothing was deleted"
            when absent without force; "Error: SR policy <key> is
            PCC-initiated (configured on <headend>) ..." / "... carries no
            pcep-flag-c ..." without force; "Error: delete failed for <key>:
            <message>" on ``state: failure``; "Error: ..." on an unresolvable
            name or an API failure.
        """
        try:
            _nodes, head, end = await resolve_ends(network, headend, endpoint)
            label = policy_label(head, end, color)
            policy = await read_policy(head, end, color)
            flag = pcep_flag_c(policy) if policy is not None else None
            if policy is None:
                refusal = (
                    f"no SR policy {label} is reported by the SR-PCE feed; nothing was deleted. "
                    "List the known policies with cnc_list_sr_policies (keys are the router-ids). "
                    "A PCE-initiated policy is absent there while the head-end does not report "
                    "it (no PCEP report-all), in the seconds after a create, or while the SR-PCE "
                    "feed is down — pass force=true to send the delete anyway."
                )
                note = (
                    "The policy was not reported by the SR-PCE feed, so the tool could not check "
                    "who initiated it; the delete was sent on your say-so. Confirm the outcome "
                    "with cnc_list_sr_policies_on_nodes (the COE's own view) or on the head-end."
                )
            elif flag == 0:
                refusal = (
                    f"SR policy {label} is PCC-initiated (configured on {head.node_id}); "
                    "it is not in the Optimization Engine's Config DB, so a PCE delete cannot "
                    "remove it (the platform answers 'SR policy not found in Config DB'). "
                    "Remove it from the router's configuration instead, or pass force=true "
                    "to send the delete anyway."
                )
                note = (
                    "The policy was PCC-initiated: the Optimization Engine only holds "
                    "PCE-initiated policies, so expect 'SR policy not found in Config DB'; the "
                    "router's configuration is untouched."
                )
            elif flag != 1:
                seen = "no pcep-info.pcep-flag-c" if flag is None else f"pcep-flag-c {flag}"
                refusal = (
                    f"SR policy {label} carries {seen} on the topology NBI, so the tool cannot "
                    "tell whether the PCE initiated it (only a PCE-initiated policy can be "
                    "removed this way); nothing was deleted. Pass force=true to send the delete "
                    "anyway."
                )
                note = (
                    "The policy carried no pcep-flag-c: if it was PCC-initiated the router's "
                    "configuration remains and the policy may reappear."
                )
            else:
                refusal = note = None
            if refusal and not force:
                raise PlatformError(refusal)
            body = rpc_body(**{"sr-policies": [policy_key(head, end, color)]})
            output = await call_rpc(SRP_MODULE, RPC_DELETE, body)
            result = first_result(output, f"the delete of SR policy {label}")
            state, message = write_outcome(result, "delete", label)
            payload: dict[str, Any] = {
                "headend": head.router_id,
                "headend_node": head.node_id,
                "endpoint": end.router_id,
                "endpoint_node": end.node_id,
                "color": color,
                "reported": policy is not None,
                "pcep_flag_c": flag,
                "forced": bool(refusal),
                "state": state,
                "message": message,
                "next": (
                    "The head-end withdraws the policy within seconds; verify removal with "
                    f"cnc_wait_for_sr_policy_oper_state(headend='{head.node_id}', "
                    f"endpoint='{end.node_id}', color={color}, target='ABSENT') (succeeds once "
                    "the topology NBI no longer reports it) or cnc_get_sr_policy (expect "
                    "'Error: no SR policy ... is reported'). Not target='DOWN' — a removed "
                    "policy is never reported as DOWN."
                ),
            }
            if note:
                payload["note"] = note
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_set_sr_policy_path_notifications",
        title="Set SR Policy Path Notifications",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_set_sr_policy_path_notifications(
        enabled: Annotated[
            bool,
            Field(
                description=(
                    "true to enable interface SR-policy-path notifications, false to disable."
                ),
            ),
        ],
    ) -> str:
        """Enable or disable the Optimization Engine's interface SR-policy-path notifications.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        ``POST .../cisco-crosswork-optimization-engine-operations:
        set-interface-sr-policy-paths-notification-state`` with ``{"input":
        {"enabled": true|false}}`` answers ``status: accepted``; the tool then
        re-reads the state (cnc_get_sr_policy_path_notification_state) and
        reports what the platform now says, so the answer reflects the real
        outcome rather than the acknowledgement. Idempotent: setting the
        current value again is accepted. A global switch — it affects every
        interface and every notification consumer.

        Args:
            enabled: the new state.

        Returns:
            str: "SR policy path notifications are now enabled|disabled." plus
            the JSON re-read ``output`` {"status", "enabled"}. "Error: ... the
            platform accepted the change but still reports ..." when the
            re-read disagrees; "Error: ..." on an API failure (``status: error``
            inside 200, or an empty 500 -> the COE hint).
        """
        try:
            check_coe_status(
                await call_rpc(COE_MODULE, RPC_SET_NOTIFICATION_STATE, rpc_body(enabled=enabled)),
                "set-interface-sr-policy-paths-notification-state",
            )
            output = check_coe_status(
                await call_rpc(COE_MODULE, RPC_GET_NOTIFICATION_STATE, None),
                "get-interface-sr-policy-paths-notification-state",
            )
            now = as_bool(output.get("enabled"))
            wanted = "enabled" if enabled else "disabled"
            if now is not None and now is not enabled:
                raise PlatformError(
                    f"the Optimization Engine accepted the change but still reports the "
                    f"notifications {'enabled' if now else 'disabled'} (wanted {wanted}).\n"
                    f"{to_json(output)}"
                )
            head = (
                f"SR policy path notifications are now {wanted}."
                if now is not None
                else f"The change to {wanted} was accepted; the re-read did not report a boolean "
                "'enabled' — the raw answer follows."
            )
            return finalize(f"{head}\n{to_json(output)}", settings)
        except Exception as e:
            return format_error(e)

    # --- WAIT tool ----------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_wait_for_sr_policy_oper_state",
        title="Wait for SR Policy Oper State",
        read_only=True,
        idempotent=True,
    )
    async def cnc_wait_for_sr_policy_oper_state(
        headend: Annotated[str, Field(description=_HEADEND_DESC, min_length=1, max_length=253)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, min_length=1, max_length=253)],
        color: Annotated[int, Field(description=_COLOR_DESC, ge=1, le=4294967295)],
        target: Annotated[
            str,
            Field(
                description=(
                    "What ends the wait: 'UP' (default) or 'DOWN' — the policy's oper-state — "
                    "or 'ABSENT' — the topology NBI no longer reports the policy, the "
                    "convergence signal after cnc_delete_sr_policy."
                ),
                max_length=8,
            ),
        ] = DEFAULT_WAIT_TARGET,
        timeout_seconds: Annotated[int, Field(description=_TIMEOUT_DESC, ge=5, le=600)] = 60,
        interval_seconds: Annotated[int, Field(description=_INTERVAL_DESC, ge=1, le=30)] = 3,
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
    ) -> str:
        """Poll the topology NBI until an SR policy reports the target oper-state — or is gone.

        Read-only convergence wait. Call it right after cnc_create_sr_policy /
        cnc_update_sr_policy (target UP) or cnc_delete_sr_policy (target
        ABSENT) instead of polling cnc_get_sr_policy in a loop. It resolves
        the names once (host names or router-ids), then polls ``GET .../
        cisco-crosswork-segment-routing-policy:sr-policies/policy=<headend>,
        <endpoint>,<color>`` every ``interval_seconds``:

        - target ``UP`` / ``DOWN``: 409 ``data-missing`` (the PCC has not
          reported the new policy yet, or the SR-PCE gRPC feed lags) keeps
          polling — "not reported yet"; ``oper-state`` equal to the target
          ends the wait; any other state keeps polling until
          ``timeout_seconds``;
        - target ``ABSENT``: the wait ends as soon as the NBI answers 409
          ``data-missing`` (the policy is no longer reported); a policy still
          reported, in any state, keeps polling. This is the only convergence
          signal after a delete (verified live, agent scenario 10): a removed
          policy is never reported as DOWN, so ``target="DOWN"`` after a
          delete only times out — and the timeout hint then says so.

        The tool remembers whether ANY poll reported the policy
        (``seen_during_wait`` in the summary), because the last poll alone
        is ambiguous: an ABSENT wait that ends on the very first poll either
        confirmed a delete or is waiting on a key that never existed (a
        typo'd color, swapped ends — the NBI answers the same 409 for both,
        verified live on a color that never existed), so the two are worded
        apart: "was reported, then withdrawn" when a poll saw it, else "is
        ABSENT: not reported at any poll" — which is the NORMAL success right
        after a fast withdrawal (verified live, agent findings round 2: the
        head-end withdrew within one poll interval), so it is not a warning:
        if it follows a cnc_delete_sr_policy that answered ``reported: true``
        (the policy existed when the delete was sent) the policy is confirmed
        withdrawn (converged); only when the policy was expected to exist
        should the key be verified with cnc_list_sr_policies.

        A timeout is NOT an error: the tool reports the last observed state
        and a hint that depends on the target, on the last state and on
        whether the policy was seen at all, so the agent can decide (call
        again, read cnc_get_sr_policy for the paths, switch to
        target='ABSENT', or check the head-end's PCEP session). A policy
        that is never reported after a create usually means the head-end did
        not accept the PCEP initiate (check the PCEP session in
        cnc_get_topology_node and the SR-PCE provider) or does not report it
        (PCEP ``report-all``). A policy that was reported and then vanished
        during a UP/DOWN wait has been withdrawn — after a delete that is the
        converged state (wait with target='ABSENT'). A policy still reported
        after a delete is usually PCC-initiated (``pcep-flag-c 0``, router
        configuration the PCE cannot remove) or the SR-PCE feed lagging.

        Args:
            headend, endpoint, color: the policy key (names or router-ids).
            target: 'UP', 'DOWN' or 'ABSENT' (case-insensitive).
            timeout_seconds, interval_seconds: the polling budget.
            network: topology network id the names are resolved in.

        Returns:
            str: On success: "SR policy <key> is UP after Ns." — or, for
            ABSENT, "SR policy <key> was reported, then withdrawn (ABSENT)
            after Ns." when a poll had reported it, else "SR policy <key> is
            ABSENT: not reported at any poll after Ns. If this follows a
            cnc_delete_sr_policy that answered reported: true, the policy is
            confirmed withdrawn (converged); if you expected it to exist,
            verify the key with cnc_list_sr_policies." — plus a JSON summary
            ({"reported": true, "seen_during_wait": true, "headend",
            "endpoint", "color", "admin_state", "oper_state",
            "sr_policy_type", "pce_controlled", "pcep_flag_c",
            "origin": "PCE-initiated" | "PCC-initiated" | "unknown",
            "binding_sid", "paths": [{"path_name", "path_type", "preference",
            "oper_state"}]}, or {"reported": false, "seen_during_wait": bool}
            for ABSENT). On timeout (not an error): "SR policy <key> not
            <target> after Ns; current: <oper-state or 'not reported'>.
            <target-specific hint>" plus the summary ("reported" is the LAST
            poll's answer, "seen_during_wait" whether any poll reported it).
            "Error: ..." when target is not UP/DOWN/ABSENT, a name does not
            resolve, or a poll fails with anything but 409 (a 400
            invalid-value cannot happen: router-ids are always sent).
        """
        try:
            wanted = normalize_wait_target(target)
            _nodes, head, end = await resolve_ends(network, headend, endpoint)
            label = policy_label(head, end, color)
            seen = False  # did ANY poll report the policy? (the last poll alone is ambiguous)

            async def fetch() -> dict[str, Any] | None:
                nonlocal seen
                policy = await read_policy(head, end, color)
                if policy is not None:
                    seen = True
                return policy

            def reached(policy: dict[str, Any] | None) -> bool:
                if wanted == "ABSENT":
                    return policy is None
                return policy is not None and str(policy.get("oper-state") or "").upper() == wanted

            finished, policy, elapsed = await wait_until(
                fetch,
                reached,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
            )
            summary = policy_summary(policy)
            summary = {
                "reported": summary.pop("reported"),
                "seen_during_wait": seen,
                **summary,
            }
            if finished:
                if wanted != "ABSENT":
                    head_line = f"SR policy {label} is {wanted} after {elapsed:.0f}s."
                elif seen:
                    head_line = (
                        f"SR policy {label} was reported, then withdrawn (ABSENT) after "
                        f"{elapsed:.0f}s."
                    )
                else:
                    head_line = (
                        f"SR policy {label} is ABSENT: not reported at any poll after "
                        f"{elapsed:.0f}s. If this follows a cnc_delete_sr_policy that answered "
                        "reported: true, the policy is confirmed withdrawn (converged); if you "
                        "expected it to exist, verify the key with cnc_list_sr_policies."
                    )
            else:
                current = (
                    str(policy.get("oper-state") or "unknown")
                    if policy is not None
                    else "not reported"
                )
                head_line = (
                    f"SR policy {label} not {wanted} after {elapsed:.0f}s; current: {current}. "
                    f"{timeout_hint(wanted, policy, seen)}"
                )
            return finalize(f"{head_line}\n{to_json(summary)}", settings)
        except Exception as e:
            return format_error(e)
