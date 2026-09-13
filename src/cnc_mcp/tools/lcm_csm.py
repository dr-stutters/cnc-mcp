"""LCM and CSM tools — Local Congestion Mitigation and Circuit-Style SR-TE, read (plus
one reversible write) through the Crosswork Optimization Engine's function-pack RPCs.

What LCM is. Local Congestion Mitigation is the Optimization Engine (COE)
function pack that watches interface utilisation and, when a link crosses its
utilization threshold, computes **tactical SR policies** — short-lived,
PCE-initiated policies that steer part of the traffic around the congested
link — and either recommends them (``operation-mode: manual``: an operator
commits) or deploys them itself (``automated``). Everything is scoped by an
**LCM domain** (``domain-id``, a string; ``"0"`` is the startup domain every
deployment has): a domain has its own configuration (thresholds, the tactical
policy color, the optimisation objective, ...), its own managed interfaces
(the links LCM may mitigate — or every interface when
``include-all-interfaces`` is true) and its own current recommendation
(``urgency`` none|low|medium|high plus one ``solution`` per congested
interface). Tactical policies LCM deploys are ordinary PCE-initiated SR
policies and appear in cnc_list_sr_policies with the domain's ``color``.

What CSM is. Circuit-Style Manager is the function pack behind **Circuit-Style
SR-TE policies** (CS-SR): bidirectional, co-routed, bandwidth-guaranteed
policies with working and protect paths, provisioned as a pair (one per
direction) and reserved against a per-interface **bandwidth pool** — the share
of each link the CSM may hand to CS policies. CS policies are provisioned
through NSO / the Crosswork UI; this module only reads what the CSM reports
(which CS policy paths exist, per node or per interface, and the bandwidth
pools) — it cannot create one.

Wire facts (verified live on Crosswork 7.2, 2026-09-13 — see the platform
notes, "LCM / CSM RPCs"). All are RPCs on :data:`cnc_mcp.restconf.OPTIMIZATION_NBI`
(``POST .../operations/<module>:<rpc>``, ``application/yang-data+json``) in
five YANG modules:

- ``cisco-crosswork-optimization-engine-lcm-domain-operations`` —
  ``get-lcm-domains`` (NO body) -> ``{"<module>:output": {"response-result":
  "valid", "domain": [{"domain-id": "0", "description": "LCM startup config",
  "recommendation-timestamp": "", "status": "disabled"}]}}``.
- ``cisco-crosswork-optimization-engine-function-pack-operations`` (this is
  the module name on the wire — NOT ``...-lcm-configuration``, which the
  OpenAPI document's title suggests) — ``get-lcm-config`` and
  ``get-lcm-managed-interfaces`` with ``{"input": {"domain-id": "0"}}``; both
  answer ``status: accepted`` plus the configuration leaves /
  ``managed-interfaces[]`` (the list is absent, not empty, when there is
  none). The live configuration carries leaves the document omits
  (``geo-ha-traffic-collection-hold-time``).
- ``cisco-crosswork-optimization-engine-lcm-recommendation-operations`` —
  ``get-lcm-recommendation`` ``{"input": {"domain-id"}}`` -> ``{"urgency":
  "none", "last-recommendation-timestamp": "", "recommendation-id": "",
  "response-result": "valid"}`` when nothing is pending. An **unknown
  domain-id answers a bare 500 with an empty body** (the COE's bad-input
  answer, below).
- ``cisco-crosswork-optimization-engine-csm-config-operations`` —
  ``get-csm-interfaces-bandwidth-pool`` (NO body) -> ``{"response-result":
  "valid"}`` with no ``interface-bandwidth-pools`` when none is configured.
- ``cisco-crosswork-optimization-engine-csm-policy-operations`` —
  ``all-cs-policy-paths`` ``{"input": {"paths-with-no-hops": false}}`` ->
  ``{"status": "accepted", "message": ""}`` (no ``cs-policy-paths`` when
  there is none); ``cs-policy-paths-on-nodes`` ``{"input": {"nodes":
  [{"node": "PE1"}]}}`` -> ``node-cs-policies[] {node, operational-state
  "active"}``; ``cs-policy-paths-on-interface`` ``{"input": {"interfaces":
  [{"node", "interface"}]}}`` -> ``link-cs-policies[] {node, interface,
  operational-state "up"}``. ``node`` is the topology node id (host name).

Two result idioms, both inside HTTP 200: the function-pack and csm-policy
modules answer ``output.status`` ``accepted`` | ``rejected`` | ``error`` (+
``message``); the lcm-domain, lcm-recommendation and csm-config modules
answer ``output.response-result`` ``valid`` | ``invalid`` | ``error``. The
recommendation RPCs that take a ``recommendation-id`` add ``rec-id-check``
``accepted`` | ``refresh`` (the id is stale — LCM has recomputed) | ``error``
and ``request-check-result-enum`` ``accepted`` | ``invalid`` | ``error`` with
a ``reason``. :func:`check_lcm_output` and :func:`check_recommendation_checks`
turn every non-success value into an ``Error:`` carrying the platform's
message; a missing field is success (most answers carry only one idiom).

The empty-500 rule (verified on ``get-lcm-recommendation`` with a domain-id
that does not exist): a **bare HTTP 500 with an empty body** is how the
Optimization Engine rejects INPUT it cannot resolve, and it is the very same
answer as a COE backend that is absent. So, as every Optimization Engine tool
does (:mod:`cnc_mcp.tools.sr_te_operations`), the two CSM tools that send
node / interface names (``cs-policy-paths-on-nodes``,
``cs-policy-paths-on-interface``) resolve them against the topology NBI
FIRST — one ``GET .../ietf-network-state:networks`` — with the same helpers
(:func:`cnc_mcp.tools.sr_te_operations.find_node`, case-insensitive node id
or router-id -> the exact ``node-id``; :func:`~cnc_mcp.tools.sr_te_operations.resolve_interface`,
the exact ``tp-id``) and do not send the RPC when a name does not resolve.
Domain ids are not pre-validated (the domain list is itself an RPC, and the
unknown-domain answer is the verified one), so an empty 500 is reported with
:func:`empty_500_hint`, which names the likely unresolved input first and the
backend-absent case second — never the generic
:data:`cnc_mcp.restconf.EMPTY_500_EXPLANATION`.

The lab (2026-09-13) has LCM **disabled** in its only domain (``"0"``), no
managed interfaces, no recommendation, no CSM bandwidth pools and no
Circuit-Style policies, so the populated shapes (a recommendation with
solutions, a preview, CS policy paths, bandwidth pools) come from the 7.2
OpenAPI documents and are marked unverified where they matter.

Not exposed — writes whose bodies are unverified or that change the network:
``set-lcm-config`` (the whole LCM configuration, ``enable`` included),
``set-lcm-managed-interfaces``, ``commit-lcm-recommendation`` (deploys the
tactical policies), ``remove-lcm-domain``, ``set-csm-interfaces-bandwidth-pool``
and ``reoptimize-csm-policy`` / ``reoptimize-csm-multiple-policies`` (re-path
live CS policies); also the read ``get-lcm-recommendation-policies`` until a
recommendation exists to verify it against. The preview tool calls
``get-lcm-msl-recommendation-preview`` (multi-segment-list) by default: the
7.2 document marks ``get-lcm-recommendation-preview`` "will be deprecated ...
use get-lcm-msl-recommendation-preview", and both take the identical ``Input``
schema and answer the identical documented ``Output`` shape, so the same
parser serves both; ``msl=false`` sends the legacy RPC for a build that lacks
the MSL one (neither is verified live — no recommendation on the lab). The
one write here, ``set-lcm-recommendation-pause``, only stops LCM from acting
on a domain (or one interface) and is reversible.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.restconf import (
    OPTIMIZATION_NBI,
    YANG_ACCEPT,
    YANG_HEADERS,
    check_rpc_output,
    explain_empty_500,
    rpc_body,
    rpc_output,
    rpc_path,
    unwrap_list,
)
from cnc_mcp.safety import AppContext, register_tool
from cnc_mcp.tools.sr_te_operations import find_node, resolve_interface
from cnc_mcp.tools.topology import (
    DEFAULT_NETWORK,
    NETWORK_MODULE,
    NETWORKS_URL,
    network_id_of,
    network_nodes,
    node_id_of,
    select_by_field,
)

# YANG modules (all verified live 2026-09-13 — the function-pack one is the surprise).
LCM_DOMAIN_MODULE = "cisco-crosswork-optimization-engine-lcm-domain-operations"
FUNCTION_PACK_MODULE = "cisco-crosswork-optimization-engine-function-pack-operations"
LCM_RECOMMENDATION_MODULE = "cisco-crosswork-optimization-engine-lcm-recommendation-operations"
CSM_CONFIG_MODULE = "cisco-crosswork-optimization-engine-csm-config-operations"
CSM_POLICY_MODULE = "cisco-crosswork-optimization-engine-csm-policy-operations"

# RPCs. Verified live: every read below. Unverified (no recommendation on the lab):
# the two previews and the pause.
RPC_GET_LCM_DOMAINS = "get-lcm-domains"
RPC_GET_LCM_CONFIG = "get-lcm-config"
RPC_GET_LCM_MANAGED_INTERFACES = "get-lcm-managed-interfaces"
RPC_GET_LCM_RECOMMENDATION = "get-lcm-recommendation"
# The 7.2 document: the non-MSL preview "will be deprecated in future releases. For new
# implementations, please use the get-lcm-msl-recommendation-preview operation"; both share
# the Input schema and the documented Output shape.
RPC_GET_LCM_MSL_RECOMMENDATION_PREVIEW = "get-lcm-msl-recommendation-preview"
RPC_GET_LCM_RECOMMENDATION_PREVIEW = "get-lcm-recommendation-preview"
RPC_SET_LCM_RECOMMENDATION_PAUSE = "set-lcm-recommendation-pause"
RPC_GET_CSM_BANDWIDTH_POOL = "get-csm-interfaces-bandwidth-pool"
RPC_ALL_CS_POLICY_PATHS = "all-cs-policy-paths"
RPC_CS_POLICY_PATHS_ON_NODES = "cs-policy-paths-on-nodes"
RPC_CS_POLICY_PATHS_ON_INTERFACE = "cs-policy-paths-on-interface"

# The startup domain every deployment has (verified: the lab's only domain).
DEFAULT_DOMAIN = "0"

# (leaf, note) in display order — the knobs an operator asks about first. Absent leaves are
# skipped, and the raw output follows the list so nothing the platform said is hidden.
LCM_CONFIG_KNOBS: tuple[tuple[str, str], ...] = (
    ("enable", "LCM function pack on/off for the domain"),
    ("operation-mode", "manual = recommend and wait for a commit, automated = deploy"),
    ("description", ""),
    ("optimization-objective", "metric the tactical policies minimise"),
    ("color", "first color of the tactical SR policies (assigned incrementally from it)"),
    ("maximum-parallel-tactical-sr-policies", "per mitigated interface"),
    ("utilization-threshold", "% utilisation at which an interface counts as congested"),
    ("utilization-hold-margin", "% below the threshold before tactical policies are removed"),
    ("over-provision-factor", "sizes the tactical policies larger when searching a solution"),
    ("adjacency-hop-type", "adjacency-SID protection preference of the detours"),
    ("auto-repair-solution", ""),
    ("delete-tactical-sr-policies", "remove deployed tactical policies when LCM is disabled"),
    ("include-all-interfaces", "false = only the managed interfaces can be mitigated"),
    ("history-retention-time", "days of operational history kept"),
    ("congestion-check-interval", "seconds between congestion evaluations"),
    ("congestion-check-suspension-interval", "seconds of suspension after a policy change"),
    ("deployment-timeout", "seconds allowed to confirm a tactical-policy deployment"),
    ("throttle-mode-threshold", "solution oscillations per hour that pause automated mode"),
    ("uneven-ecmp-traffic-threshold", "% traffic difference that flags uneven ECMP"),
    ("profile-id", "profile of the tactical policies (0 = unset)"),
    ("stay-in-area", ""),
)

_RESPONSE_FORMAT_DESC = "'markdown' for human-readable output, 'json' for the raw RPC output."
_DOMAIN_DESC = (
    "The LCM domain id, a string (e.g. '0' — the startup domain every deployment has; "
    "cnc_list_lcm_domains lists them)."
)
_RECOMMENDATION_ID_DESC = (
    "The recommendation-id reported by cnc_get_lcm_recommendation (e.g. "
    "'1789293787548'); a stale id is answered rec-id-check refresh."
)
_NODE_DESC = (
    "The topology node id / inventory host name (e.g. 'PE1'), as the topology NBI lists "
    "it (cnc_list_topology_nodes) — not a router-id."
)
_INTERFACE_DESC = (
    "The interface name as the topology lists it (e.g. 'GigabitEthernet0/0/0/0'); "
    "cnc_list_node_interfaces shows the exact names."
)
_LCM_INT_NOTE = (
    " Give node AND interface together to address one interface's solution (the RPC's "
    "lcm-int); leave both empty to address the whole domain."
)
_CS_NODE_DESC = (
    "The interface's node: a topology node id (the inventory host name, case-insensitive, "
    "e.g. 'PE1') or one of its TE router-ids (e.g. '10.0.0.1'); resolved against the "
    "topology before the RPC."
)
_CS_INTERFACE_DESC = (
    "The interface name as the topology lists it (a termination point of the node, e.g. "
    "'GigabitEthernet0/0/0/0'; a case-insensitive unique match is accepted); "
    "cnc_list_node_interfaces shows them."
)
_NETWORK_DESC = (
    f"Topology network id the names are resolved against (e.g. '{DEFAULT_NETWORK}', the only "
    "network on a standard deployment)."
)
_MSL_DESC = (
    "true (default) calls get-lcm-msl-recommendation-preview (multi-segment-list; the RPC "
    "the 7.2 document says to use), false the legacy get-lcm-recommendation-preview "
    "(marked 'will be deprecated') for a build that lacks the MSL one."
)


# --- pure helpers -----------------------------------------------------------------


def dict_list(value: Any) -> list[dict[str, Any]]:
    """The dict entries of a list value; ``[]`` for anything else (absent lists included)."""
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def text_of(value: Any) -> str:
    """A stripped string, or ``""`` for None / non-string / blank."""
    return value.strip() if isinstance(value, str) else ""


def first_reason(output: dict[str, Any], *keys: str) -> str:
    """The first non-blank string among ``output[key]`` for the given keys, else ``""``."""
    for key in keys:
        text = text_of(output.get(key))
        if text:
            return text
    return ""


def render_value(value: Any) -> str:
    """A leaf for markdown: JSON booleans as ``true``/``false``, containers as compact JSON."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict | list):
        return json.dumps(value, default=str)
    if value is None:
        return "-"
    return str(value)


def pct(value: Any) -> str:
    """``80%`` for a utilisation figure, ``-`` when absent."""
    return "-" if value in (None, "") else f"{value}%"


def empty_500_hint(suspect: str) -> str:
    """The whole explanation of a bare 500 from an LCM/CSM RPC (see the module docstring).

    ``suspect`` names the input the caller thinks the COE could not resolve
    (an LCM domain id, a node or interface name) and leads the text, because
    on this platform an empty 500 is first of all the COE's bad-input answer
    (verified on ``get-lcm-recommendation`` with an unknown domain-id) and
    only secondly an absent backend. Deliberately NOT
    :data:`cnc_mcp.restconf.EMPTY_500_EXPLANATION`, whose "retrying will not
    help, the feature is absent" verdict would send an agent away from the
    common cause: its own input.
    """
    return (
        f"the Optimization Engine rejected the request ({suspect}): it answered 500 with an "
        "empty body, which on this platform is how the COE rejects INPUT it cannot resolve "
        "(verified live for an LCM domain-id that does not exist; the same answer is expected "
        "for a host name or interface it does not know — nodes[].node / interfaces[].node are "
        "topology node ids such as 'PE1', not router-ids) — and the very same answer as a COE "
        "backend that is absent or down. Check the inputs first: cnc_list_lcm_domains for the "
        "domain ids ('0' is the startup domain), cnc_list_topology_nodes for node ids and "
        "cnc_list_node_interfaces for the exact interface names. If every input resolves, the "
        "Optimization Engine (or its LCM/CSM function pack) is unavailable — cnc_list_providers, "
        "cnc_get_topology_summary — and retrying with the same inputs will not help."
    )


def domain_suspect(domain_id: str) -> str:
    """The ``suspect`` for a domain-keyed RPC: "unknown LCM domain? ...", the verified cause."""
    return f"unknown LCM domain? domain-id '{domain_id}' was sent"


def names_suspect(names: list[str]) -> str:
    """The ``suspect`` for a node/interface-keyed CSM RPC whose names resolved in the topology.

    The names were validated against the topology NBI before the RPC (an
    unknown one is refused without sending), so a residual empty 500 means the
    Circuit-Style Manager does not know a name the topology does (its view
    lags, or the node is not CS-capable) — or the CSM backend is absent.
    """
    return (
        f"the CSM did not resolve a name the topology knows? sent, as the topology spells "
        f"them: {', '.join(names)}"
    )


BACKEND_SUSPECT = "this RPC takes no input, so the LCM/CSM backend itself is absent or down"


def check_lcm_output(output: dict[str, Any], what: str) -> dict[str, Any]:
    """Raise PlatformError for an LCM/CSM RPC that reports failure inside HTTP 200.

    Both idioms: ``status`` ``error`` (through
    :func:`cnc_mcp.restconf.check_rpc_output`) or ``rejected`` with
    ``message``; ``response-result`` anything but ``valid`` (``invalid`` /
    ``error``) with ``reason`` / ``error-description`` / ``message``. A
    missing field is success. Returns ``output`` unchanged on success.
    """
    check_rpc_output(output, what)
    reason = first_reason(output, "message", "reason", "error-description")
    status = text_of(output.get("status")).lower()
    if status == "rejected":
        raise PlatformError(
            f"{what} was rejected by the Optimization Engine: {reason or 'no message given'}"
        )
    result = text_of(output.get("response-result")).lower()
    if result and result != "valid":
        raise PlatformError(
            f"{what} failed: response-result {result}: {reason or 'no message given'}"
        )
    return output


def check_recommendation_checks(
    output: dict[str, Any], what: str, recommendation_id: str
) -> dict[str, Any]:
    """Raise PlatformError for the recommendation RPCs' extra checks (spec, unverified live).

    ``rec-id-check`` ``refresh`` = the id is stale (LCM has recomputed since;
    re-read with cnc_get_lcm_recommendation), ``error`` = not accepted;
    ``request-check-result-enum`` ``invalid`` / ``error`` = the request was
    not accepted, with ``reason``. ``accepted`` and absent fields pass.
    """
    reason = first_reason(output, "reason", "message")
    said = f" Platform said: {reason}" if reason else ""
    check = text_of(output.get("rec-id-check")).lower()
    if check == "refresh":
        raise PlatformError(
            f"{what}: recommendation id '{recommendation_id}' is stale (rec-id-check refresh) "
            "— LCM has computed a newer recommendation since; re-read it with "
            f"cnc_get_lcm_recommendation and retry with the current recommendation-id.{said}"
        )
    if check == "error":
        raise PlatformError(
            f"{what}: recommendation id '{recommendation_id}' was not accepted (rec-id-check "
            f"error): {reason or 'no message given'}"
        )
    request = text_of(output.get("request-check-result-enum")).lower()
    if request in ("invalid", "error"):
        raise PlatformError(
            f"{what} was not accepted (request-check-result {request}): "
            f"{reason or 'no message given'}"
        )
    return output


def parse_hostnames(text: str, what: str, example: str) -> list[str]:
    """``'PE1, P1'`` -> ``['PE1', 'P1']``; PlatformError when nothing is left after stripping.

    The entries are resolved against the topology afterwards (node id,
    case-insensitive, or router-id), so no spelling is enforced here.
    """
    names = [part.strip() for part in text.split(",")]
    names = [name for name in names if name]
    if not names:
        raise PlatformError(
            f"{what} is empty: give one or more topology node ids (host names) or TE "
            f"router-ids separated by commas (e.g. '{example}')."
        )
    return names


def lcm_interface(node: str, interface: str) -> dict[str, str] | None:
    """The RPC's ``lcm-int`` ``{"node", "interface"}``, ``None`` when both are blank.

    One without the other is a PlatformError: the platform addresses a
    solution by both, and sending half of it would at best be answered with an
    unexplained rejection.
    """
    node_name, interface_name = node.strip(), interface.strip()
    if not node_name and not interface_name:
        return None
    if not node_name or not interface_name:
        raise PlatformError(
            "node and interface go together: give both to address one interface's LCM solution "
            "(e.g. node='PE1', interface='GigabitEthernet0/0/0/0'), or neither for the whole "
            "domain."
        )
    return {"node": node_name, "interface": interface_name}


def recommendation_pending(output: dict[str, Any]) -> bool:
    """True when ``get-lcm-recommendation`` reports something to act on.

    The verified "nothing pending" answer is an empty ``recommendation-id``
    with ``urgency: none`` and no ``solutions``; any non-blank id or any
    solution counts as pending.
    """
    return bool(text_of(output.get("recommendation-id"))) or bool(
        dict_list(output.get("solutions"))
    )


def cs_policy_paths_of(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """The CS policy paths of a per-node / per-link entry (``cs-policy-paths`` per the document;
    ``cs-policies`` tolerated)."""
    return dict_list(entry.get("cs-policy-paths", entry.get("cs-policies")))


# --- markdown renderers ------------------------------------------------------------


def interface_label(entry: dict[str, Any]) -> str:
    """``PE1:GigabitEthernet0/0/0/0`` for any entry carrying ``node`` + ``interface``."""
    return f"{entry.get('node', '?')}:{entry.get('interface', '?')}"


def domain_line(entry: dict[str, Any]) -> str:
    """``- domain 0 — LCM startup config: status disabled; last recommendation -``."""
    text = (
        f"- domain {entry.get('domain-id', '?')} — "
        f"{text_of(entry.get('description')) or '(no description)'}: "
        f"status {entry.get('status', '?')}"
    )
    for key in ("operation-mode", "urgency"):
        value = text_of(entry.get(key))
        if value:
            text += f"; {key} {value}"
    return text + f"; last recommendation {text_of(entry.get('recommendation-timestamp')) or '-'}"


def config_lines(output: dict[str, Any]) -> list[str]:
    """One ``- leaf: value  (note)`` line per :data:`LCM_CONFIG_KNOBS` leaf present."""
    lines = []
    for key, note in LCM_CONFIG_KNOBS:
        if key not in output:
            continue
        line = f"- {key}: {render_value(output[key])}"
        if note:
            line += f"  ({note})"
        lines.append(line)
    return lines


def managed_interface_line(entry: dict[str, Any]) -> str:
    threshold = entry.get("utilization-threshold")
    detail = (
        f"utilization-threshold {pct(threshold)}"
        if threshold not in (None, "")
        else "utilization-threshold: the domain's default"
    )
    return f"- {interface_label(entry)} — {detail}"


def solution_line(entry: dict[str, Any]) -> str:
    """One ``solutions[]`` entry: interface, action, LCM state, utilisation figures, statuses."""
    parts = [
        f"- {interface_label(entry)} — recommended-action {entry.get('recommended-action', '?')}",
        f"lcm-state {entry.get('lcm-state', '?')}",
        f"utilization evaluation {pct(entry.get('evaluation-util'))} / threshold "
        f"{pct(entry.get('threshold-util'))} / expected {pct(entry.get('expected-util'))}",
        f"policies-deployed {render_value(entry.get('policies-deployed'))}",
        f"policy-set-status {entry.get('policy-set-status', '?')}",
        f"commit-status {entry.get('commit-status', '?')}",
    ]
    timestamp = text_of(entry.get("solution-timestamp"))
    if timestamp:
        parts.append(f"solution-timestamp {timestamp}")
    return "; ".join(parts)


def segment_hop_text(hop: dict[str, Any]) -> str:
    """``hop-ipv4-node-sid 16004 (node/link <uuid>)`` for one ``segment-list-hop`` entry."""
    return (
        f"{hop.get('hop-type', '?')} sid {hop.get('sid', '?')} "
        f"(topo-element {hop.get('topo-element-id', '?')})"
    )


def preview_policy_lines(index: int, entry: dict[str, Any]) -> list[str]:
    """The lines of one ``tte-policy-preview[]`` entry: change, segment list, IGP path."""
    hops = dict_list(entry.get("segment-list-hop"))
    igp = entry.get("igp-path")
    igp_text = ", ".join(str(x) for x in igp) if isinstance(igp, list) and igp else ""
    return [
        f"- tactical policy {index}: policy-change {entry.get('policy-change', '?')}",
        "  segment list: " + (" > ".join(segment_hop_text(h) for h in hops) or "(no hops)"),
        "  igp-path: " + (igp_text or "(none reported)"),
    ]


def pool_line(entry: dict[str, Any]) -> str:
    pool = render_value(entry.get("bandwidth-pool"))
    return f"- {interface_label(entry)} — bandwidth-pool {pool}"


def cs_policy_line(entry: dict[str, Any]) -> str:
    """``- 10.0.0.1 -> 10.0.0.3 color 1000 preference 100 — operational-state up``."""
    text = (
        f"- {entry.get('head-end', '?')} -> {entry.get('end-point', '?')} "
        f"color {entry.get('color', '?')}"
    )
    preference = entry.get("preference")
    if preference not in (None, ""):
        text += f" preference {preference}"
    state = text_of(entry.get("operational-state"))
    if state:
        text += f" — operational-state {state}"
    return text


def element_section(heading: str, entry: dict[str, Any]) -> list[str]:
    """A ``## <element> — operational-state X (N policies)`` section with its policy lines."""
    paths = cs_policy_paths_of(entry)
    state = text_of(entry.get("operational-state")) or "?"
    lines = ["", f"## {heading} — operational-state {state} ({len(paths)} CS policy paths)"]
    lines.extend(cs_policy_line(p) for p in paths)
    if not paths:
        lines.append("- (none)")
    message = text_of(entry.get("message"))
    if message:
        lines.append(f"  message: {message}")
    return lines


# --- registration ------------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def call_rpc(
        module: str, rpc: str, body: dict[str, Any] | None, suspect: str
    ) -> dict[str, Any]:
        """POST one RPC and return its checked ``output`` container.

        ``body`` is the ``{"input": {...}}`` envelope, sent with
        :data:`YANG_HEADERS`; ``None`` sends no body at all (only ``Accept``
        — the verified form of ``get-lcm-domains`` and
        ``get-csm-interfaces-bandwidth-pool``). Never auto-retried (POST). A
        bare 500 with an empty body is reported as :func:`empty_500_hint`
        led by ``suspect``; any other failure through
        :func:`cnc_mcp.errors.http_error`; a failure reported inside HTTP 200
        through :func:`check_lcm_output`.
        """
        url = rpc_path(OPTIMIZATION_NBI, module, rpc)
        headers = YANG_HEADERS if body is not None else YANG_ACCEPT
        response = await client.request(
            "POST", url, json_body=body, headers=headers, raise_on_error=False
        )
        if not response.is_success:
            if explain_empty_500(response.status_code, response.text):
                raise PlatformError(empty_500_hint(suspect))
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
        return check_lcm_output(rpc_output(data, module), rpc)

    async def domain_rpc(module: str, rpc: str, domain_id: str, **extra: Any) -> dict[str, Any]:
        """A domain-keyed RPC: ``{"input": {"domain-id": <id>, ...extra}}``; None extras dropped."""
        body = rpc_body(**{"domain-id": domain_id, **extra})
        return await call_rpc(module, rpc, body, domain_suspect(domain_id))

    async def fetch_topology_nodes(network: str) -> list[dict[str, Any]]:
        """The ``node`` entries of one network, from the ``networks`` COLLECTION GET.

        The same fetch (and the same reasons) as
        ``cnc_mcp.tools.sr_te_operations``'s: the collection is read and the
        network selected client-side because the keyed ``network=<id>`` GET
        answers the whole list for an unknown key (verified). An empty
        container or a network without nodes is an error here — there is
        nothing to validate the CSM RPC's names against, and the COE would
        answer every unresolved name with the ambiguous empty 500. (A closure
        over the client in both modules; lifting it into
        :mod:`cnc_mcp.tools.topology` is the shared follow-up.)
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
                f"the topology network '{key}' has no nodes yet, so no node name can be "
                "resolved for the Circuit-Style Manager. Nodes appear once devices are "
                "onboarded and the SR-PCE gRPC feed is up (cnc_get_topology_summary)."
            )
        present = [network_id_of(n) for n in networks if isinstance(n, dict)]
        if present:
            raise PlatformError(
                f"no network '{key}' on the topology NBI. Networks present: "
                f"{', '.join(present)}. The default is '{DEFAULT_NETWORK}'."
            )
        raise PlatformError(
            "the topology NBI reports no networks yet, so no node name can be resolved for the "
            "Circuit-Style Manager. The networks container is populated once devices are "
            "onboarded and the SR-PCE gRPC feed is up (cnc_get_topology_summary, "
            "cnc_list_providers)."
        )

    # --- LCM reads -----------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_lcm_domains",
        title="List LCM Domains",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_lcm_domains(
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the Local Congestion Mitigation (LCM) domains and whether each is enabled.

        Read-only. ``POST .../operations/cisco-crosswork-optimization-engine-
        lcm-domain-operations:get-lcm-domains`` with NO body (verified live —
        only ``Accept`` is sent) answers ``response-result: valid`` plus
        ``domain[]``. Start here for anything LCM: it gives the domain ids the
        other LCM tools take (``"0"`` is the startup domain every deployment
        has) and whether LCM runs at all — a ``disabled`` domain mitigates
        nothing and cnc_get_lcm_recommendation answers urgency none for it;
        ``pending-removal`` is a domain being deleted. ``urgency``,
        ``operation-mode`` and ``recommendation-timestamp`` are populated only
        for an enabled domain (per the document; the lab's only domain is
        disabled and reports an empty timestamp).

        Args:
            response_format: markdown (one line per domain) or json (the raw
                RPC ``output``).

        Returns:
            str: Markdown "- domain <id> — <description>: status <status>;
            [operation-mode ...; urgency ...;] last recommendation <timestamp
            or ->", or the JSON ``output`` {"response-result", "domain":
            [{"domain-id", "description", "status", "recommendation-timestamp",
            "urgency"?, "operation-mode"?}]}. "No LCM domains are configured."
            when the list is empty (not an error). "Error: get-lcm-domains
            failed: response-result <x>: ..." when the RPC reports a failure
            inside 200; "Error: the Optimization Engine rejected the request
            (...)" for a bare empty 500 (this RPC has no input to get wrong, so
            that is the backend being absent); "Error: ..." on any other API
            failure.
        """
        try:
            output = await call_rpc(LCM_DOMAIN_MODULE, RPC_GET_LCM_DOMAINS, None, BACKEND_SUSPECT)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            domains = dict_list(output.get("domain"))
            if not domains:
                return finalize(
                    "No LCM domains are configured. (The startup domain '0' normally exists "
                    "on every deployment; the LCM function pack may not be installed.)",
                    settings,
                )
            lines = [f"# LCM domains ({len(domains)})", ""]
            lines.extend(domain_line(d) for d in domains)
            enabled = [
                str(d.get("domain-id")) for d in domains if text_of(d.get("status")) == "enabled"
            ]
            lines.append("")
            if enabled:
                lines.append(
                    f"LCM is enabled in domain(s) {', '.join(enabled)}: cnc_get_lcm_recommendation "
                    "shows what it wants to mitigate, cnc_get_lcm_config its thresholds."
                )
            else:
                lines.append(
                    "LCM is disabled in every domain: no congestion mitigation runs and "
                    "cnc_get_lcm_recommendation answers urgency none. cnc_get_lcm_config still "
                    "shows the configuration it would use."
                )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_lcm_config",
        title="Get LCM Configuration",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_lcm_config(
        domain_id: Annotated[str, Field(description=_DOMAIN_DESC, min_length=1, max_length=64)] = (
            DEFAULT_DOMAIN
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the LCM configuration of one domain — thresholds, tactical-policy settings, mode.

        Read-only. ``POST .../operations/cisco-crosswork-optimization-engine-
        function-pack-operations:get-lcm-config`` with ``{"input":
        {"domain-id": "<id>"}}`` (verified live; note the module name —
        ``function-pack-operations``, not the ``lcm-configuration`` the
        document's title suggests) answers ``status: accepted`` plus the
        configuration leaves: ``enable``, ``operation-mode`` manual|automated,
        ``optimization-objective`` igp-metric|te-metric|delay, ``color`` (the
        first color of the tactical SR policies — 2000 on the lab), ``maximum-
        parallel-tactical-sr-policies``, ``utilization-threshold`` (%),
        ``utilization-hold-margin``, ``over-provision-factor``,
        ``adjacency-hop-type``, ``auto-repair-solution``,
        ``delete-tactical-sr-policies``, ``include-all-interfaces``,
        ``history-retention-time`` (days), the ``congestion-check-*``
        intervals (seconds), ``deployment-timeout``, ``profile-id`` and more
        (the live answer also carries leaves the document omits, e.g.
        ``geo-ha-traffic-collection-hold-time``). The markdown lists the main
        knobs with a one-line meaning each and then the raw output in full.
        This is the configuration LCM WOULD use even while the domain is
        disabled (cnc_list_lcm_domains shows the status). Changing it
        (``set-lcm-config``) is not exposed.

        Args:
            domain_id: the LCM domain id (default '0').
            response_format: markdown (main knobs + raw JSON) or json (the raw
                RPC ``output``).

        Returns:
            str: Markdown "# LCM configuration of domain <id>" with "- <leaf>:
            <value>  (<meaning>)" lines and the raw output, or the JSON
            ``output`` {"status": "accepted", <leaf>: <value>, ...}. "Error:
            get-lcm-config failed: <message>" when the RPC reports status
            error / rejected inside 200; "Error: the Optimization Engine
            rejected the request (unknown LCM domain? ...)" for a bare empty
            500 (verified meaning: the domain-id does not exist); "Error: ..."
            on any other API failure.
        """
        try:
            output = await domain_rpc(FUNCTION_PACK_MODULE, RPC_GET_LCM_CONFIG, domain_id)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            knobs = config_lines(output)
            lines = [f"# LCM configuration of domain {domain_id}", ""]
            lines.extend(knobs or ["- (none of the usual configuration leaves was reported)"])
            lines.extend(
                [
                    "",
                    "Raw output (every leaf the platform reported):",
                    "```json",
                    to_json(output),
                    "```",
                    "",
                    "cnc_list_lcm_domains shows whether this domain is enabled; "
                    "cnc_list_lcm_managed_interfaces the links it may mitigate.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_lcm_managed_interfaces",
        title="List LCM Managed Interfaces",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_lcm_managed_interfaces(
        domain_id: Annotated[str, Field(description=_DOMAIN_DESC, min_length=1, max_length=64)] = (
            DEFAULT_DOMAIN
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the interfaces LCM is allowed to mitigate in one domain, with their thresholds.

        Read-only. ``POST .../operations/cisco-crosswork-optimization-engine-
        function-pack-operations:get-lcm-managed-interfaces`` with
        ``{"input": {"domain-id": "<id>"}}`` (verified live) answers ``status:
        accepted`` plus ``managed-interfaces[] {node, interface,
        utilization-threshold}`` — the list is simply ABSENT when no interface
        is managed (the lab's answer), which this tool reports as a plain
        "none" result. A managed interface's own ``utilization-threshold``
        overrides the domain's; an entry without one uses the domain default
        (cnc_get_lcm_config). When the domain's ``include-all-interfaces`` is
        true LCM may mitigate every interface, and this list is only the set
        with per-interface thresholds. Editing the list
        (``set-lcm-managed-interfaces``) is not exposed.

        Args:
            domain_id: the LCM domain id (default '0').
            response_format: markdown or json (the raw RPC ``output``).

        Returns:
            str: Markdown "- <node>:<interface> — utilization-threshold N%"
            per interface, or the JSON ``output`` {"status",
            "managed-interfaces": [...]}. "No interfaces are managed by LCM in
            domain <id>." when the list is absent or empty (not an error).
            "Error: get-lcm-managed-interfaces failed: ..." for a failure
            inside 200; "Error: the Optimization Engine rejected the request
            (unknown LCM domain? ...)" for a bare empty 500; "Error: ..." on
            any other API failure.
        """
        try:
            output = await domain_rpc(
                FUNCTION_PACK_MODULE, RPC_GET_LCM_MANAGED_INTERFACES, domain_id
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            interfaces = dict_list(output.get("managed-interfaces"))
            if not interfaces:
                return finalize(
                    f"No interfaces are managed by LCM in domain {domain_id}. (LCM can still "
                    "mitigate every interface when the domain's include-all-interfaces is true "
                    "— cnc_get_lcm_config.)",
                    settings,
                )
            lines = [f"# LCM managed interfaces of domain {domain_id} ({len(interfaces)})", ""]
            lines.extend(managed_interface_line(i) for i in interfaces)
            lines.extend(
                [
                    "",
                    "A per-interface utilization-threshold overrides the domain's "
                    "(cnc_get_lcm_config).",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_lcm_recommendation",
        title="Get LCM Recommendation",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_lcm_recommendation(
        domain_id: Annotated[str, Field(description=_DOMAIN_DESC, min_length=1, max_length=64)] = (
            DEFAULT_DOMAIN
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get LCM's current recommendation for a domain: which congested interfaces it wants to
        mitigate, with what urgency.

        Read-only. ``POST .../operations/cisco-crosswork-optimization-engine-
        lcm-recommendation-operations:get-lcm-recommendation`` with
        ``{"input": {"domain-id": "<id>"}}`` (verified live) answers
        ``response-result: valid``, ``urgency`` none|low|medium|high,
        ``recommendation-id``, ``last-recommendation-timestamp`` and
        ``solutions[]`` — one per interface LCM evaluated: ``node``,
        ``interface``, ``recommended-action`` no-change|create-set|
        update-set|delete-set (the tactical policy set to deploy, change or
        remove), ``lcm-state`` congested|mitigating|mitigated (spelled
        "mittigated" by the platform)|paused, ``evaluation-util`` /
        ``threshold-util`` / ``expected-util`` (%), ``policies-deployed``,
        ``policy-set-status`` and ``commit-status``. With nothing pending
        (verified: the disabled lab domain) the id and timestamp are empty
        strings, urgency is none and there is no ``solutions`` list — reported
        as a plain non-error "nothing pending". In manual mode a
        recommendation waits for an operator to commit it (not exposed here:
        ``commit-lcm-recommendation``); cnc_get_lcm_recommendation_preview
        shows the tactical policies it would deploy;
        cnc_pause_lcm_recommendations stops LCM acting on it.

        Args:
            domain_id: the LCM domain id (default '0').
            response_format: markdown or json (the raw RPC ``output``).

        Returns:
            str: Markdown "# LCM recommendation <id> for domain <d> (urgency
            <u>)" with one "- <node>:<interface> — recommended-action ...;
            lcm-state ...; utilization evaluation N% / threshold N% / expected
            N%; ..." line per solution, or the JSON ``output``. "No LCM
            recommendation is pending for domain <id> (urgency none)." when
            nothing is pending (not an error). "Error: get-lcm-recommendation
            failed: response-result <x>: ..." for a failure inside 200;
            "Error: the Optimization Engine rejected the request (unknown LCM
            domain? ...)" for a bare empty 500 — VERIFIED to be the answer for
            a domain-id that does not exist; "Error: ..." on any other API
            failure.
        """
        try:
            output = await domain_rpc(
                LCM_RECOMMENDATION_MODULE, RPC_GET_LCM_RECOMMENDATION, domain_id
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            urgency = text_of(output.get("urgency")) or "none"
            if not recommendation_pending(output):
                return finalize(
                    f"No LCM recommendation is pending for domain {domain_id} (urgency "
                    f"{urgency}). Either nothing is congested or LCM is disabled in the domain "
                    "(cnc_list_lcm_domains).",
                    settings,
                )
            rec_id = text_of(output.get("recommendation-id")) or "(no id)"
            solutions = dict_list(output.get("solutions"))
            lines = [
                f"# LCM recommendation {rec_id} for domain {domain_id} (urgency {urgency})",
                "",
                f"- last-recommendation-timestamp: "
                f"{text_of(output.get('last-recommendation-timestamp')) or '-'}",
                "",
                f"## Solutions ({len(solutions)})",
            ]
            lines.extend(solution_line(s) for s in solutions)
            if not solutions:
                lines.append("- (no per-interface solution reported)")
            lines.extend(
                [
                    "",
                    "cnc_get_lcm_recommendation_preview(domain_id, recommendation_id, node, "
                    "interface) shows the tactical policies a solution would deploy; "
                    "cnc_pause_lcm_recommendations pauses LCM for the domain or one interface. "
                    "Committing a recommendation is not exposed by this server.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_lcm_recommendation_preview",
        title="Preview LCM Recommendation",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_lcm_recommendation_preview(
        domain_id: Annotated[str, Field(description=_DOMAIN_DESC, min_length=1, max_length=64)],
        recommendation_id: Annotated[
            str, Field(description=_RECOMMENDATION_ID_DESC, min_length=1, max_length=128)
        ],
        node: Annotated[str, Field(description=_NODE_DESC + _LCM_INT_NOTE, max_length=253)] = "",
        interface: Annotated[
            str, Field(description=_INTERFACE_DESC + _LCM_INT_NOTE, max_length=253)
        ] = "",
        msl: Annotated[bool, Field(description=_MSL_DESC)] = True,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Preview the tactical SR policies an LCM recommendation would deploy — segment lists
        and the IGP path each would take — without committing anything.

        Read-only, changes nothing. ``POST .../operations/cisco-crosswork-
        optimization-engine-lcm-recommendation-operations:
        get-lcm-msl-recommendation-preview`` (default; ``msl=false`` sends
        the legacy ``get-lcm-recommendation-preview`` instead) with
        ``{"input": {"domain-id", "recommendation-id"[, "lcm-int": {"node",
        "interface"}]}}``. The 7.2 document marks the legacy RPC "will be
        deprecated in future releases. For new implementations, please use the
        get-lcm-msl-recommendation-preview operation" (multi-segment-list
        support); both take the identical ``Input`` schema and answer the
        identical documented ``Output`` shape, so the same parser serves both.
        UNVERIFIED LIVE: the lab has no recommendation to preview, so the
        request and the answer follow the 7.2 document only: ``response-result``,
        ``rec-id-check`` accepted|refresh|error, ``request-check-result-enum``
        accepted|invalid|error + ``reason``, ``description``, ``lcm-int`` and
        ``tte-policy-preview[]`` — one tactical policy each with
        ``policy-change`` nochange|create|update|delete, ``segment-list-hop[]
        {hop-type, sid, topo-element-id}`` (the UUID of the node or L3 link)
        and ``igp-path[]`` (interface hops, unordered, ECMP included). If the
        MSL RPC is answered "403 Unauthorized request" (an unknown path on an
        older build), retry with ``msl=false``. Give ``node`` + ``interface``
        to preview one interface's solution (the ids come from
        cnc_get_lcm_recommendation's solutions and are sent as given). A stale
        recommendation-id is answered ``rec-id-check: refresh`` and reported
        as an error telling you to re-read the recommendation.

        Args:
            domain_id: the LCM domain id (e.g. '0').
            recommendation_id: the id from cnc_get_lcm_recommendation.
            node, interface: optional, both or neither — the solution to
                preview (``lcm-int``).
            msl: true (default) for get-lcm-msl-recommendation-preview, false
                for the legacy get-lcm-recommendation-preview.
            response_format: markdown or json (the raw RPC ``output``).

        Returns:
            str: Markdown "# LCM recommendation <id> preview for domain <d>
            [(<node>:<interface>)]" with one "- tactical policy N:
            policy-change ...; segment list ...; igp-path ..." block per
            policy, or the JSON ``output``. "Error: ... is stale (rec-id-check
            refresh) ..." / "Error: ... was not accepted (request-check-result
            invalid): <reason>" for the document's rejection spellings; "Error:
            node and interface go together ..." when only one was given
            (nothing is sent); "Error: get-lcm-msl-recommendation-preview
            failed: ..." (or the legacy name) for a failure inside 200;
            "Error: the Optimization Engine rejected the request (unknown LCM
            domain? ...)" for a bare empty 500; "Error: ..." on any other API
            failure.
        """
        try:
            target = lcm_interface(node, interface)
            rpc = RPC_GET_LCM_RECOMMENDATION_PREVIEW
            if msl:
                rpc = RPC_GET_LCM_MSL_RECOMMENDATION_PREVIEW
            output = await domain_rpc(
                LCM_RECOMMENDATION_MODULE,
                rpc,
                domain_id,
                **{"recommendation-id": recommendation_id, "lcm-int": target},
            )
            check_recommendation_checks(output, rpc, recommendation_id)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            answered = output.get("lcm-int")
            where = answered if isinstance(answered, dict) else target
            scope = f" ({interface_label(where)})" if where else ""
            policies = dict_list(output.get("tte-policy-preview"))
            lines = [
                f"# LCM recommendation {recommendation_id} preview for domain {domain_id}{scope}",
                "",
            ]
            description = text_of(output.get("description"))
            if description:
                lines.extend([f"- description: {description}", ""])
            lines.append(f"## Tactical SR policies ({len(policies)})")
            for index, policy in enumerate(policies, start=1):
                lines.extend(preview_policy_lines(index, policy))
            if not policies:
                lines.append("- (the platform reported no tactical policy for this preview)")
            lines.extend(
                [
                    "",
                    "Nothing was deployed. Hop types name node or adjacency SIDs; topo-element "
                    "ids are the topology UUIDs of the node or L3 link (cnc_get_topology_node / "
                    "cnc_list_topology_links). This preview shape is from the 7.2 document, "
                    "not yet verified against a live recommendation.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    # --- CSM reads -----------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_csm_bandwidth_pools",
        title="List CSM Interface Bandwidth Pools",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_csm_bandwidth_pools(
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the per-interface bandwidth pools reserved for Circuit-Style SR policies.

        Read-only. ``POST .../operations/cisco-crosswork-optimization-engine-
        csm-config-operations:get-csm-interfaces-bandwidth-pool`` with NO body
        (verified live — only ``Accept`` is sent) answers ``response-result:
        valid`` plus ``interface-bandwidth-pools[] {node, interface,
        bandwidth-pool}`` — the list is ABSENT when no pool is configured (the
        lab's answer), reported here as a plain "none". The bandwidth pool is
        the share of a link the Circuit-Style Manager may reserve for CS
        policies (the CS-SR documentation defines it as a percentage of the
        link's bandwidth; the value is shown as the platform reports it). An
        interface without an entry uses the CSM's global default. Editing the
        pools (``set-csm-interfaces-bandwidth-pool``) is not exposed.

        Args:
            response_format: markdown or json (the raw RPC ``output``).

        Returns:
            str: Markdown "- <node>:<interface> — bandwidth-pool <n>" per
            entry, or the JSON ``output`` {"response-result",
            "interface-bandwidth-pools": [...]}. "No CSM interface bandwidth
            pools are configured." when the list is absent or empty (not an
            error). "Error: get-csm-interfaces-bandwidth-pool failed:
            response-result <x>: ..." for a failure inside 200; "Error: the
            Optimization Engine rejected the request (...)" for a bare empty
            500 (no input to get wrong: the backend is absent); "Error: ..."
            on any other API failure.
        """
        try:
            output = await call_rpc(
                CSM_CONFIG_MODULE, RPC_GET_CSM_BANDWIDTH_POOL, None, BACKEND_SUSPECT
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            pools = dict_list(output.get("interface-bandwidth-pools"))
            if not pools:
                return finalize(
                    "No CSM interface bandwidth pools are configured. (Every interface then "
                    "uses the Circuit-Style Manager's default pool.)",
                    settings,
                )
            lines = [f"# CSM interface bandwidth pools ({len(pools)})", ""]
            lines.extend(pool_line(p) for p in pools)
            lines.extend(
                [
                    "",
                    "bandwidth-pool = the share of the link reservable for Circuit-Style SR "
                    "policies (a percentage of link bandwidth per the CS-SR documentation).",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_cs_policy_paths",
        title="List Circuit-Style SR Policy Paths",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_cs_policy_paths(
        include_paths_without_hops: Annotated[
            bool,
            Field(
                description=(
                    "true to include CS policy paths the CSM has not (yet) computed hops for "
                    "(wire: paths-with-no-hops); default false lists only routed paths."
                ),
            ),
        ] = False,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List every Circuit-Style SR policy path the Circuit-Style Manager reports.

        Read-only. ``POST .../operations/cisco-crosswork-optimization-engine-
        csm-policy-operations:all-cs-policy-paths`` with ``{"input":
        {"paths-with-no-hops": false|true}}`` (verified live) answers
        ``status: accepted``, ``message`` and ``cs-policy-paths[] {head-end,
        end-point, color, preference, operational-state active|up|down|
        unknown}`` — the list is ABSENT when there is no CS policy (the lab's
        answer: ``{"message": "", "status": "accepted"}``), reported here as a
        plain "none". ``head-end`` / ``end-point`` are TE router-ids; a CS
        policy is a pair (one entry per direction) with a working path
        (``preference`` higher) and a protect path. The policies themselves,
        as the PCE reports them, are in cnc_list_sr_policies; this is the
        CSM's own view of the paths it manages.

        Args:
            include_paths_without_hops: also list paths without computed hops.
            response_format: markdown or json (the raw RPC ``output``).

        Returns:
            str: Markdown "- <head-end> -> <end-point> color <c> preference <p>
            — operational-state <s>" per path, or the JSON ``output``. "No
            Circuit-Style SR policies are reported." when the list is absent
            or empty (not an error). "Error: all-cs-policy-paths failed:
            <message>" for status error / rejected inside 200; "Error: the
            Optimization Engine rejected the request (...)" for a bare empty
            500; "Error: ..." on any other API failure.
        """
        try:
            body = rpc_body(**{"paths-with-no-hops": include_paths_without_hops})
            output = await call_rpc(
                CSM_POLICY_MODULE,
                RPC_ALL_CS_POLICY_PATHS,
                body,
                "the CSM backend is absent or down — this RPC's only input is a boolean",
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            paths = dict_list(output.get("cs-policy-paths"))
            message = text_of(output.get("message"))
            if not paths:
                text = "No Circuit-Style SR policies are reported."
                if not include_paths_without_hops:
                    text += " (Paths without computed hops are excluded; retry with "
                    text += "include_paths_without_hops=true to see those too.)"
                if message:
                    text += f" Platform message: {message}"
                return finalize(text, settings)
            lines = [f"# Circuit-Style SR policy paths ({len(paths)})", ""]
            lines.extend(cs_policy_line(p) for p in paths)
            if message:
                lines.extend(["", f"message: {message}"])
            lines.extend(
                [
                    "",
                    "head-end / end-point are TE router-ids; a CS policy is a pair (one entry per "
                    "direction) with working and protect paths. cnc_get_sr_policy shows a path's "
                    "segment lists as the PCE reports them.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_cs_policies_on_nodes",
        title="List Circuit-Style SR Policies on Nodes",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_cs_policies_on_nodes(
        nodes: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated nodes to ask about, each a topology node id (host name, "
                    "case-insensitive) or a TE router-id, e.g. 'PE1,P1'; resolved against the "
                    "topology before the RPC."
                ),
                min_length=1,
                max_length=2000,
            ),
        ],
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the Circuit-Style SR policy paths that touch the given nodes.

        Read-only. ``POST .../operations/cisco-crosswork-optimization-engine-
        csm-policy-operations:cs-policy-paths-on-nodes`` with ``{"input":
        {"nodes": [{"node": "<node-id>"}, ...]}}`` (verified live) answers
        ``status: accepted`` plus ``node-cs-policies[] {node,
        operational-state, message?, cs-policy-paths[]?}`` — one entry per
        node with the node's own state (``active`` on the lab) and, when CS
        policies use it, their paths ``{head-end, end-point, color,
        preference, operational-state}``. Node names are validated against
        the topology first (one GET of the networks collection): each may be
        a node id (case-insensitive) or one of the node's router-ids, and is
        sent as the exact topology ``node-id`` — an unknown name is refused
        with the naming rule and nothing is sent, because the COE answers an
        unresolved name with an ambiguous empty 500 (verified for other COE
        RPCs, not for this one). Same rule and helpers as
        cnc_list_sr_policies_on_nodes.

        Args:
            nodes: comma-separated node ids or router-ids.
            network: topology network id the names are resolved in.
            response_format: markdown (one section per node) or json (the raw
                RPC ``output``).

        Returns:
            str: Markdown "## <node-id> — operational-state <s> (N CS policy
            paths)" sections with "- <head-end> -> <end-point> color <c> ..."
            lines ("- (none)" for a node without any), or the JSON ``output``.
            "Error: nodes is empty ..." when no name is left after stripping;
            "Error: no node '<x>' in the topology ..." when a name does not
            resolve (nothing is sent in either case); "Error: the topology NBI
            reports no networks yet ..." / "Error: no network '<n>' ..." when
            there is nothing to resolve against; "Error: cs-policy-paths-on-
            nodes failed: <message>" for status error / rejected inside 200;
            "Error: the Optimization Engine rejected the request (the CSM did
            not resolve a name the topology knows? ...)" for a bare empty 500;
            "Error: ..." on any other API failure.
        """
        try:
            names = parse_hostnames(nodes, "nodes", "PE1,P1")
            topology = await fetch_topology_nodes(network)
            node_ids = [node_id_of(find_node(topology, name)) for name in names]
            body = rpc_body(nodes=[{"node": node_id} for node_id in node_ids])
            output = await call_rpc(
                CSM_POLICY_MODULE, RPC_CS_POLICY_PATHS_ON_NODES, body, names_suspect(node_ids)
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            entries = dict_list(output.get("node-cs-policies"))
            by_node = {str(e.get("node")): e for e in entries}
            lines = [f"# Circuit-Style SR policies on {', '.join(node_ids)}"]
            for node_id in node_ids:
                entry = by_node.get(node_id)
                if entry is None:
                    lines.extend(
                        ["", f"## {node_id} — (the Optimization Engine returned no entry)"]
                    )
                    continue
                lines.extend(element_section(node_id, entry))
            for entry in entries:
                if str(entry.get("node")) not in node_ids:
                    lines.extend(element_section(str(entry.get("node")), entry))
            total = sum(len(cs_policy_paths_of(e)) for e in entries)
            lines.extend(
                [
                    "",
                    f"{total} CS policy path(s) in total. operational-state on the node line is "
                    "the node's; cnc_list_cs_policy_paths lists every CS path the CSM manages.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_cs_policies_on_interface",
        title="List Circuit-Style SR Policies on Interface",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_cs_policies_on_interface(
        node: Annotated[str, Field(description=_CS_NODE_DESC, min_length=1, max_length=253)],
        interface: Annotated[
            str, Field(description=_CS_INTERFACE_DESC, min_length=1, max_length=253)
        ],
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the Circuit-Style SR policy paths that ride one interface.

        Read-only. ``POST .../operations/cisco-crosswork-optimization-engine-
        csm-policy-operations:cs-policy-paths-on-interface`` with ``{"input":
        {"interfaces": [{"node": "<node-id>", "interface": "<tp-id>"}]}}``
        (verified live) answers ``link-cs-policies[] {node, interface,
        operational-state, message?, cs-policy-paths[]?}`` — the link's own
        state (``up`` on the lab) and, when CS policies are routed over it,
        their paths. Use it before maintenance on a link to see which
        bandwidth-guaranteed circuits it carries (the SR-policy equivalent is
        cnc_list_sr_policies_on_interface). Both names are validated against
        the topology first (one GET of the networks collection): the node may
        be a node id (case-insensitive) or a router-id and is sent as the
        exact ``node-id``; the interface must be one of that node's
        termination points, exact spelling (a case-insensitive unique match
        is accepted and sent in its exact spelling). An unknown node or
        interface is refused — listing the node's termination points — and
        nothing is sent, because the COE answers an unresolved name with an
        ambiguous empty 500. Same rule and helpers as
        cnc_list_sr_policies_on_interface.

        Args:
            node: the interface's node id or router-id.
            interface: the termination-point id on that node.
            network: topology network id the names are resolved in.
            response_format: markdown or json (the raw RPC ``output``).

        Returns:
            str: Markdown "## <node-id>:<tp-id> — operational-state <s> (N CS
            policy paths)" with the path lines, or the JSON ``output``.
            "Error: node and interface are required ..." when either is blank;
            "Error: no node '<x>' in the topology ..." / "Error: no interface
            '<x>' on node '<n>' in the topology. Its termination points are:
            ..." when a name does not resolve (nothing is sent in any of these
            cases); "Error: cs-policy-paths-on-interface failed: <message>"
            for status error / rejected inside 200; "Error: the Optimization
            Engine rejected the request (the CSM did not resolve a name the
            topology knows? ...)" for a bare empty 500; "Error: ..." on any
            other API failure.
        """
        try:
            if not node.strip() or not interface.strip():
                raise PlatformError(
                    "node and interface are required (e.g. node='PE1', "
                    "interface='GigabitEthernet0/0/0/0')."
                )
            topology = await fetch_topology_nodes(network)
            node_entry = find_node(topology, node)
            node_id = node_id_of(node_entry)
            tp_id = resolve_interface(node_entry, interface)
            body = rpc_body(interfaces=[{"node": node_id, "interface": tp_id}])
            output = await call_rpc(
                CSM_POLICY_MODULE,
                RPC_CS_POLICY_PATHS_ON_INTERFACE,
                body,
                names_suspect([f"{node_id}:{tp_id}"]),
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            entries = dict_list(output.get("link-cs-policies"))
            lines = [f"# Circuit-Style SR policies on {node_id}:{tp_id}"]
            if not entries:
                lines.extend(["", "- (the Optimization Engine returned no entry)"])
            for entry in entries:
                lines.extend(element_section(interface_label(entry), entry))
            lines.extend(
                [
                    "",
                    "operational-state on the heading is the link's; cnc_list_cs_policy_paths "
                    "lists every CS path the CSM manages.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    # --- WRITE tool ------------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_pause_lcm_recommendations",
        title="Pause or Resume LCM Recommendations",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_pause_lcm_recommendations(
        domain_id: Annotated[str, Field(description=_DOMAIN_DESC, min_length=1, max_length=64)],
        paused: Annotated[
            bool,
            Field(
                description=(
                    "true to pause LCM (it stops recommending / deploying tactical policies), "
                    "false to resume (wire: pause-state)."
                ),
            ),
        ],
        node: Annotated[str, Field(description=_NODE_DESC + _LCM_INT_NOTE, max_length=253)] = "",
        interface: Annotated[
            str, Field(description=_INTERFACE_DESC + _LCM_INT_NOTE, max_length=253)
        ] = "",
    ) -> str:
        """Pause or resume LCM's congestion mitigation for a domain, or for one interface.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        ``POST .../operations/cisco-crosswork-optimization-engine-
        lcm-recommendation-operations:set-lcm-recommendation-pause`` with
        ``{"input": {"domain-id", "pause-state": true|false[, "lcm-int":
        {"node", "interface"}]}}``. UNVERIFIED LIVE — the lab has LCM disabled
        and nothing to pause, so the body and the answer follow the 7.2
        document only: ``response-result``, ``pause-state`` (the state now in
        force), ``lcm-int``, ``request-check-result-enum`` accepted|invalid|
        error and ``reason``. Paused, LCM keeps evaluating but neither
        recommends nor (in automated mode) deploys or removes tactical
        policies for the scope; the affected solutions show ``lcm-state:
        paused`` in cnc_get_lcm_recommendation. Reversible (``paused=false``)
        and idempotent (setting the current state again is expected to be
        accepted). Already-deployed tactical policies are left as they are.
        The tool reports the ``pause-state`` the platform answers and treats
        a value that disagrees with the request as an error.

        Args:
            domain_id: the LCM domain id (e.g. '0').
            paused: the new state.
            node, interface: optional, both or neither — pause only this
                interface's solution.

        Returns:
            str: "LCM recommendations are now paused|resumed in domain <id>
            [for <node>:<interface>]." followed by the JSON ``output``. "Error:
            ... the platform accepted the change but reports pause-state ..."
            when the answer disagrees; "Error: ... was not accepted
            (request-check-result invalid): <reason>" for the document's
            rejection spelling; "Error: node and interface go together ..."
            when only one was given (nothing is sent); "Error:
            set-lcm-recommendation-pause failed: ..." for a failure inside
            200; "Error: the Optimization Engine rejected the request (unknown
            LCM domain? ...)" for a bare empty 500; "Error: ..." on any other
            API failure.
        """
        try:
            target = lcm_interface(node, interface)
            output = await domain_rpc(
                LCM_RECOMMENDATION_MODULE,
                RPC_SET_LCM_RECOMMENDATION_PAUSE,
                domain_id,
                **{"pause-state": paused, "lcm-int": target},
            )
            check_recommendation_checks(output, RPC_SET_LCM_RECOMMENDATION_PAUSE, "")
            wanted = "paused" if paused else "resumed"
            scope = f" for {interface_label(target)}" if target else ""
            now = output.get("pause-state")
            if isinstance(now, bool) and now is not paused:
                raise PlatformError(
                    f"the platform accepted the change but reports pause-state {render_value(now)} "
                    f"(wanted {render_value(paused)}) for domain {domain_id}{scope}.\n"
                    f"{to_json(output)}"
                )
            if isinstance(now, bool):
                head = f"LCM recommendations are now {wanted} in domain {domain_id}{scope}."
            else:
                head = (
                    f"The change to {wanted} in domain {domain_id}{scope} was accepted; the "
                    "platform did not report a boolean pause-state — the raw answer follows."
                )
            return finalize(
                f"{head}\ncnc_get_lcm_recommendation shows the affected solutions' lcm-state.\n"
                f"{to_json(output)}",
                settings,
            )
        except Exception as e:
            return format_error(e)
