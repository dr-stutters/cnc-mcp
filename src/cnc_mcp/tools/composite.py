"""Composite ("one call") tools — the playbooks agents were running by hand.

What a composite is. Two rounds of blind agent scenarios against this server
showed the same investigations costing 20–45 tool calls each: a network
health overview (25 calls), a "PE2 looks degraded" investigation (44),
"explain policy PE1 -> PE2 colour 100" (22), an alarm triage (22), a
controller audit (26) and an L3VPN create + verify + trace + delete (33).
Each composite here runs that playbook server-side — the same sibling tools,
in the order an experienced operator would call them — and answers with a
VERDICT first, then one section per sub-tool, then an audit list of every
call it made. The individual tools stay registered for follow-up: every
section names the tool behind it so an agent can drill in with exactly that
call.

Composition mechanism. A composite never re-implements a sibling: it calls
the registered tool through the server itself (``await mcp.call_tool(name,
arguments)``, the text blocks flattened) so every verified behaviour, wire
quirk, rendering and error text of the sibling is reused verbatim.
Sub-calls whose JSON feeds the verdict are made with
``response_format="json"`` and parsed (:func:`parse_payload` also finds the
JSON that follows a headline or a markdown rendering); sub-calls made for
display keep the sibling's markdown. Sub-calls run sequentially, in the
order the sections are listed.

Partial-failure rule. A sub-call that answers ``Error: ...`` — or raises the
SDK's ToolError (an unknown tool because writes are disabled, an argument
the sibling no longer accepts) — never fails the whole composite: its
section reads "<section>: unavailable — <error text>", the verdict lists it
under "sections unavailable (not covered by the verdict)", and the rest of
the playbook runs. Only the write composites stop early, and only at the
step whose failure makes the next steps meaningless (a failed dry run, a
failed commit): they report every step taken so far and never delete or
roll back anything the caller did not ask for.

Output. Markdown (default): a ``## VERDICT`` block (status, headline,
reasons, notes, unavailable sections), the sections, then ``## Calls made``
with one ``tool(args) -> ok|error`` line per sub-call. JSON
(``response_format="json"``): ``{"verdict": {"status", "headline",
"reasons", "notes", "missing"}, "sections": {<key>: {"title", "tool",
"status", "summary", "data" | "text", "error"}}, "calls": [{"tool",
"arguments", "ok", "error"?}]}``. Verbatim sub-tool text is kept to
:data:`SECTION_CHARS` per section in markdown (the sibling gives the full
output); every answer passes through ``finalize()``.

Write composites (``cnc_provision_l3vpn_e2e``, ``cnc_create_sr_policy_e2e``)
are registered only with ``CNC_MCP_ENABLE_WRITES=true``, like the writes they
wrap, and only when the write sibling that commits (:data:`WRITE_SIBLINGS`) is
itself registered — with ``CNC_MCP_WRITE_AREAS`` naming ``composite`` but not
``service_provisioning`` / ``sr_te_operations`` they are skipped, the reason
logged and recorded. An optional write sibling (the L3VPN playbook's OAM trace,
``trace=true``) is not required: when it is not registered — ``oam`` kept out of
``CNC_MCP_WRITE_AREAS`` — the step is skipped and the verdict says why. They
also cope with a sibling that is absent at call time (the audit line says so).
Both take ``dry_run``: true stops after the preview stage (NSO's dry run / the
Optimization Engine's dry run) with a ``dry-run`` verdict and nothing committed;
global dry-run mode (``CNC_MCP_DRY_RUN=true``) forces it.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.config import Settings
from cnc_mcp.errors import format_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json, uncapped_internal_call
from cnc_mcp.safety import AppContext, register_tool
from cnc_mcp.tools.fault import (
    age_text,
    event_count,
    fault_event,
    is_cleared,
    is_stale,
    rtm_alarm_line,
)
from cnc_mcp.tools.fault import alarm_line as shared_alarm_line
from cnc_mcp.tools.performance import series_stats, stats_text
from cnc_mcp.tools.services import VPN_LAYERS, vpn_layer
from cnc_mcp.tools.sr_te_operations import group_route_by_node
from cnc_mcp.tools.te_state import node_text, router_id_names

logger = logging.getLogger(__name__)

# Verbatim sub-tool text kept per section in the markdown answer; the sibling tool
# named in the section heading gives the full output.
SECTION_CHARS = 4000
# The audit list shows arguments; a long one (an endpoints JSON) is shortened to this.
ARGUMENT_CHARS = 80

DEFAULT_NETWORK = "Default-network"
REACHABLE = "CONN_STATE_REACHABLE"
UNREACHABLE = "CONN_STATE_UNREACHABLE"
OPER_OK = "ROBOT_OPER_STATE_OK"
OPER_CHECKING = "ROBOT_OPER_STATE_CHECKING"
ADMIN_UP = "ROBOT_ADMIN_STATE_UP"
NSO_SYNCED = "SYNCED"
EMF_SYNCHRONIZED = "MANAGED_AND_SYNCHRONIZED"
BACKUP_MAX_AGE_DAYS = 7
# The CEPMINTERFACE error / discard rates (per second, averaged over the window).
ERROR_METRICS = "ifInErrorsRate,ifOutErrorsRate,ifInDiscardsRate,ifOutDiscardsRate"
# cnc_search_alarms' maximum limit: the sibling matches `text` as a substring and caps the
# sorted matches BEFORE the composite's whole-word re-filter, so the device investigation
# asks for every match it can get and notes when the cap still cut the list.
ALARM_SCAN_LIMIT = 500
# CAT policy services read while looking for the NSO-configured twin of an SR policy.
MAX_POLICY_SERVICE_READS = 10
# Services a bare-name lookup reads from the CAT inventory (cnc_list_services' maximum).
SERVICE_LOOKUP_LIMIT = 500
# Microservices read cluster-wide, in one unscoped cnc_list_microservices, to cross-check
# the pod-health alarms a triage finds stale (the sibling's maximum page; 109 pods on a
# single-VM 7.2 lab).
MICROSERVICE_LIST_PAGE = 500
# The subject of a pod-health alarm: "<pod> is down." / "<pod> health is down." (the
# fault text; verified live 2026-09-14). The alarm's origin_service_id / origin_app_id
# name the pod that RAISED it (robot-orch in capp-infra for the optima-* and cwm-worker
# alarms), not the pod it is about.
POD_HEALTH_TEXT = re.compile(
    r"^\s*(\S+?)(?:\s+health)?\s+is\s+(?:down|degraded|unhealthy)\b", re.IGNORECASE
)
CRITICAL_MAJOR = ("critical", "major")
SR_PCE_FAMILIES = ("ROBOT_PROVIDER_XTC", "ROBOT_PROVIDER_SR_PCE")
NSO_FAMILY = "ROBOT_PROVIDER_NSO"
# The open-alarm states cnc_alarm_triage reads one by one when the open set exceeds one
# cnc_search_alarms fetch (the same split cnc_network_health_report uses).
OPEN_ALARM_STATES = ("Critical", "Major", "Minor", "Warning", "Info")
# Both composites ask cnc_search_alarms for as many alarms as it can return per fetch.
TRIAGE_LIMIT = ALARM_SCAN_LIMIT
# The DLM's reachability cadence seen live (2026-09-14, PE2 polled over 25 min: the
# state_map REACHABILITY stamp advanced every 1200 s). ``next_check_time`` mirrors
# ``last_updated_time`` on 7.2 and is not a schedule, so the cadence is the only bound
# on when a (re)attached device's first check can run.
REACHABILITY_CADENCE_SECONDS = 1200
# ROBOT_OPER_STATE_CHECKING younger than this is the DLM's check cycle in progress (a
# note); older is a stall (a reason). Two cadences: a device whose first check lands on
# the next cadence tick is legitimately CHECKING for up to one cadence, and the second
# is the margin. A HEURISTIC — the CHECKING duration of a healthy re-attach has not been
# measured live; the stalls seen live (P2, 6+ h) are far beyond it either way.
CHECKING_TRANSIENT_SECONDS = 2 * REACHABILITY_CADENCE_SECONDS
# The interface-PM freshness probe: CEPMINTERFACE rows in the last hour prove that
# collection is producing samples. One hour is cnc_get_performance_statistics' smallest
# window (integer hours) and 12x the 300 s default polling interval, so a device with no
# row in it has been silent for far longer than the ~3 intervals that mark a stall.
PM_FRESH_HOURS = 1
PM_POLL_INTERVAL_SECONDS = 300
# Cleared alarms this recent count towards a live alarm's "chronic" history.
CHRONIC_WINDOW_HOURS = 48
# Devices scanned to name the ones in operational_state CHECKING (cnc_list_devices' max).
HEALTH_DEVICE_PAGE = 100
# Nodes read to build the router-id -> host name map (cnc_list_topology_nodes' max).
TOPOLOGY_NODE_PAGE = 500
# One-shot housekeeping alarms Crosswork raises at Critical / Major and never clears
# itself: they ask the operator to do something once, then acknowledge and clear the
# alarm. They are rendered under their own heading and cap a verdict at AMBER (verified
# live 2026-09-14: the data-backup reminder and the pod-reservation warning turned a
# healthy lab RED). Matched case-insensitively against the alarm Description, open
# alarms with at most one event only. The certificate pattern is anchored to the
# future-tense reminder ("certificates will expire in N days"): a past-tense
# "certificate has expired" / "certificates expired" is an outage, never an advisory.
ADVISORY_PATTERNS = (
    re.compile(r"acknowledge/clear\b.*\bmanually", re.IGNORECASE),
    re.compile(r"not recommended for production", re.IGNORECASE),
    re.compile(r"take a data backup", re.IGNORECASE),
    re.compile(r"certificates?\b.*\bwill expire\b", re.IGNORECASE),
)
ADVISORY_HINT = (
    "one-shot housekeeping alarms: do what they ask once, then cnc_acknowledge_alarm / "
    "cnc_clear_alarm — Crosswork never clears them itself"
)
NO_RESPONSE_TEXT = "did not receive any response"

L3VPN_SERVICE_LIST = f"{VPN_LAYERS['l3'].module}:{VPN_LAYERS['l3'].root}/vpn-services/vpn-service"

COMPOSITE_TOOLS = (
    "cnc_investigate_device",
    "cnc_network_health_report",
    "cnc_explain_sr_policy",
    "cnc_alarm_triage",
    "cnc_explain_service",
    "cnc_provision_l3vpn_e2e",
    "cnc_create_sr_policy_e2e",
)
WRITE_COMPOSITES = ("cnc_provision_l3vpn_e2e", "cnc_create_sr_policy_e2e")
# The WRITE sibling each write composite cannot run without — the one that commits:
# the playbook is registered only when it is (register_tool's ``requires``), since a
# playbook whose commit step cannot run has no business being offered. An optional
# write sibling is deliberately NOT listed: cnc_start_oam_trace_route (trace=true,
# area oam) is skipped with a note when it is not registered, so an operator keeping
# OAM writes off still gets the L3VPN playbook. tests/test_tools_composite.py checks
# these against the siblings' read_only annotations.
WRITE_SIBLINGS: dict[str, tuple[str, ...]] = {
    "cnc_provision_l3vpn_e2e": ("cnc_create_l3vpn_service",),
    "cnc_create_sr_policy_e2e": ("cnc_create_sr_policy",),
}
OPTIONAL_WRITE_SIBLINGS: dict[str, tuple[str, ...]] = {
    "cnc_provision_l3vpn_e2e": ("cnc_start_oam_trace_route",),
    "cnc_create_sr_policy_e2e": (),
}
DRY_RUN_STATUS = "dry-run"


def next_step(global_dry_run: bool, action: str) -> str:
    """The sentence that closes a DRY-RUN headline: what turns the preview into the real
    thing. Under the server-wide dry-run mode ``dry_run=false`` would be forced back to
    true by the safety wrapper, so the honest instruction is to unset the variable."""
    if global_dry_run:
        return (
            "This server runs in DRY-RUN mode (CNC_MCP_DRY_RUN=true): nothing can be "
            f"committed until the operator unsets it; then call again to {action}."
        )
    return f"Call again with dry_run=false to {action}."


# Every sibling each composite calls, with the argument names it forwards. This is the
# drift guard: tests/test_tools_composite.py checks every name here against the sibling's
# published input schema, and that every sub-call a composite actually makes is listed
# here with no argument beyond these. Change a sibling's parameters and the test names
# the composite that still sends the old name.
_KEY = frozenset({"headend", "endpoint", "color", "network", "response_format"})
_PATH = frozenset(
    {"path_type", "objective", "hops", "protected", "sid_algorithm", "bandwidth_mbps", "network"}
)
SIBLING_CALLS: dict[str, dict[str, frozenset[str]]] = {
    "cnc_investigate_device": {
        "cnc_get_device": frozenset({"host_name", "uuid"}),
        "cnc_get_device_collection_summary": frozenset(),
        "cnc_search_alarms": frozenset({"text", "open_only", "limit", "response_format"}),
        "cnc_list_device_alarms": frozenset({"node_fdn", "limit", "response_format"}),
        "cnc_list_events": frozenset({"limit", "text", "response_format"}),
        "cnc_get_ems_node": frozenset({"name", "response_format"}),
        "cnc_check_nso_device_sync": frozenset({"host_name", "uuid", "wait_seconds"}),
        "cnc_get_topology_node": frozenset({"node_id", "response_format"}),
        "cnc_list_device_backups": frozenset({"host_name", "uuid", "response_format"}),
        "cnc_get_performance_statistics": frozenset(
            {
                "schema",
                "metrics",
                "device_uuid",
                "hours",
                "only_nonzero",
                "page_size",
                "response_format",
            }
        ),
    },
    "cnc_network_health_report": {
        "cnc_get_device_summary": frozenset(),
        "cnc_list_devices": frozenset({"page_size", "response_format"}),
        "cnc_get_device_collection_summary": frozenset(),
        "cnc_get_cluster_health": frozenset(),
        "cnc_list_data_gateways": frozenset({"response_format"}),
        "cnc_get_collection_health": frozenset(),
        "cnc_list_providers": frozenset({"page_size", "response_format"}),
        "cnc_get_topology_summary": frozenset(),
        "cnc_get_te_summary": frozenset(),
        "cnc_search_alarms": frozenset({"state", "open_only", "limit", "response_format"}),
        "cnc_list_device_alarms": frozenset({"limit", "response_format"}),
        "cnc_check_device_nso_state": frozenset({"host_name", "response_format"}),
    },
    "cnc_explain_sr_policy": {
        "cnc_list_topology_nodes": frozenset({"network", "page_size", "response_format"}),
        "cnc_get_sr_policy": _KEY,
        "cnc_get_sr_policy_routes": _KEY,
        "cnc_get_sr_policy_metrics": _KEY,
        "cnc_get_sr_policy_performance_metrics": _KEY,
        "cnc_get_lsp_utilization": _KEY | {"hours"},
        "cnc_get_lsp_delay": _KEY | {"hours"},
        "cnc_find_services_on_transport": frozenset(
            {"headend", "color", "endpoint", "response_format"}
        ),
        "cnc_list_services": frozenset({"service_type", "limit", "response_format"}),
        "cnc_get_service": frozenset({"yang_path", "include_plan", "response_format"}),
        "cnc_get_nso_device_config": frozenset({"host_name", "subtree"}),
    },
    "cnc_alarm_triage": {
        "cnc_search_alarms": frozenset({"state", "open_only", "limit", "response_format"}),
        "cnc_get_cluster_health": frozenset(),
        "cnc_list_microservices": frozenset({"page_size", "response_format"}),
        "cnc_list_device_alarms": frozenset({"limit", "response_format"}),
    },
    "cnc_explain_service": {
        "cnc_list_services": frozenset({"name_prefix", "limit", "response_format"}),
        "cnc_get_service": frozenset({"yang_path", "include_plan", "response_format"}),
        "cnc_get_service_plan": frozenset({"plan_yang_path", "detail", "response_format"}),
        "cnc_get_vpn_service_health": frozenset({"vpn_id", "layer"}),
        "cnc_get_vpn_underlay_transport": frozenset({"vpn_id", "layer", "response_format"}),
        "cnc_list_sub_services": frozenset({"service_yang_path", "response_format"}),
        "cnc_get_probe_status": frozenset({"service_id"}),
    },
    "cnc_provision_l3vpn_e2e": {
        "cnc_create_l3vpn_service": frozenset(
            {
                "vpn_id",
                "route_distinguisher",
                "route_target",
                "endpoints",
                "topology",
                "profile_id",
                "dry_run",
            }
        ),
        "cnc_wait_for_service_plan": frozenset({"plan_yang_path", "target", "timeout_seconds"}),
        "cnc_get_vpn_service_health": frozenset({"vpn_id", "layer"}),
        "cnc_get_device": frozenset({"host_name"}),
        "cnc_start_oam_trace_route": frozenset(
            {"service_yang_path", "headend_uuid", "endpoint_uuid"}
        ),
        "cnc_wait_for_oam_trace_route": frozenset({"query_id", "timeout_seconds"}),
    },
    "cnc_create_sr_policy_e2e": {
        "cnc_dryrun_sr_policy": _PATH | {"headend", "endpoint", "response_format"},
        "cnc_create_sr_policy": _PATH
        | {"headend", "endpoint", "color", "path_name", "description", "binding_sid"},
        "cnc_wait_for_sr_policy_oper_state": frozenset(
            {"headend", "endpoint", "color", "target", "timeout_seconds", "network"}
        ),
        "cnc_get_sr_policy_routes": _KEY,
    },
}

_FORMAT_DESC = (
    "'markdown' (default): the VERDICT block, one section per sub-tool, then the audit list "
    "of calls made; 'json': {verdict, sections, calls}."
)
_NETWORK_DESC = (
    f"Topology network id host names are resolved against (e.g. '{DEFAULT_NETWORK}', the only "
    "network on a standard deployment)."
)


# --- sub-call plumbing --------------------------------------------------------------


def flatten_result(result: Any) -> str:
    """The text of a ``call_tool`` result: every text block, concatenated."""
    content = getattr(result, "content", None) or []
    return "".join(str(block.text) for block in content if hasattr(block, "text"))


def parse_payload(text: str) -> Any:
    """The JSON a sub-tool answered, or None.

    Accepts the whole text (a JSON answer) and the object / array that follows
    a headline or a markdown rendering (``cnc_get_device_summary``,
    ``cnc_check_nso_device_sync``, ``cnc_get_cluster_health``, the JSON handle
    of ``cnc_start_oam_trace_route``): the first ``{`` / ``[`` at the start of
    a line that decodes to the end of the text wins.
    """
    stripped = text.strip()
    if not stripped:
        return None
    decoder = json.JSONDecoder()
    position = 0
    while True:
        start = _next_json_start(stripped, position)
        if start < 0:
            return None
        try:
            value, end = decoder.raw_decode(stripped, start)
        except ValueError:
            position = start + 1
            continue
        if isinstance(value, dict | list) and not stripped[end:].strip():
            return value
        position = start + 1


def _next_json_start(text: str, position: int) -> int:
    """Index of the next ``{`` or ``[`` that starts a line at or after ``position``; -1."""
    while position < len(text):
        char = text[position]
        if char in "{[" and (position == 0 or text[position - 1] == "\n"):
            return position
        position += 1
    return -1


def _short_argument(value: Any) -> str:
    text = repr(value)
    if len(text) > ARGUMENT_CHARS:
        text = text[: ARGUMENT_CHARS - 3] + "...'"
    return text


@dataclass
class Call:
    """One sub-call: what was asked, whether it answered, what it said."""

    tool: str
    arguments: dict[str, Any]
    ok: bool
    text: str
    data: Any = None
    error: str | None = None

    def audit(self) -> str:
        args = ", ".join(f"{k}={_short_argument(v)}" for k, v in self.arguments.items())
        return f"{self.tool}({args}) -> {'ok' if self.ok else 'error'}"

    def as_json(self) -> dict[str, Any]:
        entry: dict[str, Any] = {"tool": self.tool, "arguments": self.arguments, "ok": self.ok}
        if self.error:
            entry["error"] = self.error
        return entry


@dataclass
class Section:
    """One section of a composite answer, normally backed by one sub-call."""

    key: str
    title: str
    tool: str
    status: str = "ok"  # ok | unavailable | skipped
    lines: list[str] = field(default_factory=list)  # curated markdown lines
    text: str = ""  # the sub-tool's own text, shown when there are no curated lines
    data: Any = None
    error: str | None = None

    @classmethod
    def from_call(cls, key: str, title: str, call: Call) -> Section:
        section = cls(key, title, call.tool, text=call.text, data=call.data)
        if not call.ok:
            section.status = "unavailable"
            section.error = call.error or call.text
        return section

    @classmethod
    def skipped(cls, key: str, title: str, tool: str, why: str) -> Section:
        return cls(key, title, tool, status="skipped", error=why)

    @property
    def usable(self) -> bool:
        return self.status == "ok"

    def markdown(self) -> list[str]:
        head = f"## {self.title} — {self.tool}"
        if self.status == "unavailable":
            return [head, f"{self.title}: unavailable — {self.error}"]
        if self.status == "skipped":
            return [head, f"{self.title}: skipped — {self.error}"]
        if self.lines:
            return [head, *self.lines]
        return [head, clip_text(self.text, self.tool)]

    def as_json(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "title": self.title,
            "tool": self.tool,
            "status": self.status,
            "summary": self.lines,
        }
        if self.status != "ok":
            entry["error"] = self.error
        elif self.data is not None:
            entry["data"] = self.data
        else:
            entry["text"] = self.text
        return entry


def clip_text(text: str, tool: str, limit: int = SECTION_CHARS) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[... {len(text) - limit} more characters; call {tool} for the rest]"


class Composer:
    """Runs sibling tools through the server and keeps the audit list."""

    def __init__(self, mcp: MCPServer) -> None:
        self.mcp = mcp
        self.calls: list[Call] = []

    async def has(self, tool: str) -> bool:
        """Whether ``tool`` is registered on the server right now (an optional write
        sibling may be gated by CNC_MCP_WRITE_AREAS / DISABLED_TOOLS)."""
        return any(t.name == tool for t in await self.mcp.list_tools())

    async def call(self, tool: str, **arguments: Any) -> Call:
        """Call one registered tool; an error answer or a ToolError becomes ``ok=False``.

        The sub-call runs with :data:`formatting.uncapped_internal_call` set,
        so its answer is never size-capped: it feeds this composite, not the
        agent's context, and the composite's own finalize() caps what leaves.
        """
        token = uncapped_internal_call.set(True)
        try:
            text = flatten_result(await self.mcp.call_tool(tool, arguments))
        except Exception as e:  # ToolError: unknown tool / argument validation; anything else
            logger.warning("composite sub-call %s failed: %s", tool, e)
            text = f"Error: {tool}: {e}"
        finally:
            uncapped_internal_call.reset(token)
        ok = not text.startswith("Error:")
        call = Call(tool, arguments, ok, text, parse_payload(text) if ok else None)
        if not ok:
            call.error = text
        self.calls.append(call)
        return call


@dataclass
class Verdict:
    status: str
    headline: str = ""
    reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    def as_json(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "headline": self.headline,
            "reasons": self.reasons,
            "notes": self.notes,
            "missing": self.missing,
        }


def missing_sections(sections: list[Section]) -> list[str]:
    return [f"{s.title} ({s.error})" for s in sections if s.status == "unavailable"]


def render(
    title: str,
    verdict: Verdict,
    sections: list[Section],
    composer: Composer,
    response_format: ResponseFormat,
    settings: Settings,
) -> str:
    """The composite answer: markdown (verdict, sections, audit) or the JSON document."""
    verdict.missing = missing_sections(sections)
    if response_format is ResponseFormat.JSON:
        payload = {
            "verdict": verdict.as_json(),
            "sections": {s.key: s.as_json() for s in sections},
            "calls": [c.as_json() for c in composer.calls],
        }
        return finalize(to_json(payload), settings)
    lines = [f"# {title}", "", f"## VERDICT: {verdict.status.upper()}"]
    if verdict.headline:
        lines.append(verdict.headline)
    if verdict.reasons:
        lines.append("Reasons:")
        lines.extend(f"- {r}" for r in verdict.reasons)
    if verdict.notes:
        lines.append("Notes:")
        lines.extend(f"- {n}" for n in verdict.notes)
    if verdict.missing:
        lines.append("Sections unavailable (not covered by the verdict):")
        lines.extend(f"- {m}" for m in verdict.missing)
    for section in sections:
        lines.append("")
        lines.extend(section.markdown())
    lines.extend(["", "## Calls made"])
    lines.extend(f"- {c.audit()}" for c in composer.calls)
    return finalize("\n".join(lines), settings)


# --- small data helpers --------------------------------------------------------------


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, dict):  # {unit, value}
        return _number(value.get("value"))
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def field_of(item: dict[str, Any], name: str) -> Any:
    """A field by its bare name or any ``<prefix>.<name>`` / ``<prefix>:<name>`` spelling."""
    if name in item:
        return item[name]
    for key, value in item.items():
        text = str(key)
        if text.endswith(f".{name}") or text.endswith(f":{name}"):
            return value
    return None


def mentions(host: str, *texts: Any) -> bool:
    """True when ``host`` appears as a whole word in any of the texts (case-insensitive)."""
    if not host:
        return False
    pattern = re.compile(rf"\b{re.escape(host)}\b", re.IGNORECASE)
    return any(pattern.search(str(t)) for t in texts if t)


def parse_iso(value: Any) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def epoch_datetime(value: Any) -> datetime | None:
    """An epoch stamp (seconds on the inventory, milliseconds on the alarm API — the
    unit is inferred from the magnitude, as :func:`cnc_mcp.formatting.epoch_iso` does)
    as an aware UTC datetime; None when empty, non-numeric or not positive."""
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    seconds: float = n
    for threshold, divisor in ((10**17, 10**9), (10**14, 10**6), (10**11, 10**3)):
        if n >= threshold:
            seconds = n / divisor
            break
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def duration_text(seconds: float) -> str:
    """``5h40m`` / ``2d3h`` / ``12m`` / ``<1m`` for an elapsed time."""
    total = max(0, int(seconds))
    if total >= 86400:
        return f"{total // 86400}d{(total % 86400) // 3600}h"
    if total >= 3600:
        return f"{total // 3600}h{(total % 3600) // 60}m"
    if total >= 60:
        return f"{total // 60}m"
    return "<1m"


def stamp_text(when: datetime | None, now: datetime) -> str:
    """``2026-09-14T03:20:27Z (5h40m ago)`` or ``unknown``."""
    if when is None:
        return "unknown"
    return f"{when:%Y-%m-%dT%H:%M:%SZ} ({duration_text((now - when).total_seconds())} ago)"


def is_advisory(alarm: dict[str, Any]) -> bool:
    """An open one-shot housekeeping alarm (:data:`ADVISORY_PATTERNS`, at most one
    event): it asks for an operator action once and is never cleared by Crosswork, so it
    must not read as a live fault."""
    if is_cleared(alarm) or event_count(alarm) > 1:
        return False
    text = _text(alarm.get("Description"))
    return any(p.search(text) for p in ADVISORY_PATTERNS)


def alarm_line(alarm: dict[str, Any], now: datetime) -> str:
    """The sibling's shared alarm rendering (:func:`cnc_mcp.tools.fault.alarm_line`, so a
    Cleared alarm shows its fault text and "| cleared: ..." rather than the clearing text
    alone) without its leading "- ": composites add their own bullet or a tag."""
    return shared_alarm_line(alarm, now).removeprefix("- ")


def fault_text(alarm: dict[str, Any]) -> str:
    """The fault an alarm is about: ``Description`` for an open alarm, the newest
    fault-severity event's text for a cleared one (whose ``Description`` is the clearing
    text — :func:`cnc_mcp.tools.fault.fault_event`)."""
    if is_cleared(alarm):
        event = fault_event(alarm)
        return _text(event.get("Description")) if event else ""
    return _text(alarm.get("Description"))


def chronic_history(
    live: list[dict[str, Any]], cleared: list[dict[str, Any]], now: datetime
) -> tuple[list[str], list[str]]:
    """``(section lines, notes)`` relating each live alarm to the cleared alarms that
    carried the same fault text within :data:`CHRONIC_WINDOW_HOURS`.

    A fault that Crosswork keeps re-raising after each "Device was detached." clear
    is chronic, not new; the lines say how many times it was raised, since when, and
    what cleared it, so an agent does not read the newest instance as a fresh event.
    """
    cutoff = now.timestamp() - CHRONIC_WINDOW_HOURS * 3600
    recent: list[dict[str, Any]] = []
    for alarm in cleared:
        closed = epoch_datetime(alarm.get("Closed") or alarm.get("Updated"))
        if closed is not None and closed.timestamp() >= cutoff:
            recent.append(alarm)
    by_fault: dict[str, list[dict[str, Any]]] = {}
    for alarm in recent:
        text = fault_text(alarm)
        if text:
            by_fault.setdefault(text, []).append(alarm)
    lines = [
        f"- {len(recent)} cleared alarm(s) naming the device in the last {CHRONIC_WINDOW_HOURS} h"
    ]
    notes: list[str] = []
    for text, group in sorted(by_fault.items(), key=lambda kv: -len(kv[1])):
        created = [d for d in (epoch_datetime(a.get("Created")) for a in group) if d]
        first = min(created) if created else None
        clears: dict[str, int] = {}
        for alarm in group:
            key = _text(alarm.get("Description")) or "?"
            if key == text:
                key = "(same text)"  # the clearing event repeated the fault text
            clears[key] = clears.get(key, 0) + 1
        cleared_by = ", ".join(
            f"'{k}' x{v}" for k, v in sorted(clears.items(), key=lambda kv: -kv[1])
        )
        lines.append(
            f"- '{text}': cleared {len(group)} time(s) since "
            f"{first:%Y-%m-%dT%H:%M:%SZ} (cleared by: {cleared_by})"
            if first
            else f"- '{text}': cleared {len(group)} time(s) (cleared by: {cleared_by})"
        )
        for alarm in live:
            if _text(alarm.get("Description")) == text:
                raised = len(group) + 1
                stamps = [d for d in (first, epoch_datetime(alarm.get("Created"))) if d]
                since_text = f"{min(stamps):%Y-%m-%dT%H:%M:%SZ}" if stamps else "unknown"
                notes.append(
                    f"chronic: '{text}' has been raised {raised} times since {since_text} — "
                    f"{len(group)} instance(s) were cleared in the last {CHRONIC_WINDOW_HOURS} h "
                    f"(by {cleared_by}), so the open one is a recurring fault masked by the "
                    "clears, not a new event"
                )
                break
    if len(lines) == 1 and not recent:
        lines = [f"- none in the last {CHRONIC_WINDOW_HOURS} h"]
    return lines, notes


def device_alarm_line(alarm: dict[str, Any]) -> str:
    """:func:`cnc_mcp.tools.fault.rtm_alarm_line` (prefixes stripped, uuid and cause
    included) without its leading "- "."""
    return rtm_alarm_line(alarm).removeprefix("- ")


def device_alarm_severity(alarm: dict[str, Any]) -> str:
    return _text(field_of(alarm, "perceived-severity")).lower()


def collection_status_code(value: Any) -> str:
    """The ``code`` of the EMF's ``<status><general code="SUCCESS"/></status>`` snippet."""
    match = re.search(r'code="([^"]*)"', _text(value))
    return match.group(1) if match else _text(value)


# --- 1. investigate device -----------------------------------------------------------


def state_map_entries(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(k): v for k, v in _dict(record.get("state_map")).items() if isinstance(v, dict)}


def is_placeholder_entry(key: str, entry: dict[str, Any]) -> bool:
    """The key-0 / UNSUPPORTED placeholder a freshly (re)attached device carries until
    the DLM's first check cycle completes (cnc_get_device labels it, cnc_list_devices
    sends the bare key)."""
    return key == "0" or _text(entry.get("element")) == "UNSUPPORTED"


def placeholder_only(record: dict[str, Any]) -> bool:
    """True when the state_map holds nothing but the placeholder: no REACHABILITY /
    DISCOVERY / CLOCK_DRIFT check has completed since the (re)attach."""
    entries = state_map_entries(record)
    return bool(entries) and all(is_placeholder_entry(k, e) for k, e in entries.items())


def checking_since(record: dict[str, Any]) -> datetime | None:
    """When the current CHECKING episode is known to have started, at the latest.

    The newest of the state_map stamps (the key-0 placeholder's
    ``last_updated_time`` is the re-attach instant; a completed check's stamp is
    the last time the DLM touched the device) and the record's ``last_upd_time``
    — the most recent sign of DLM activity, so the stall age it yields is the
    conservative (smallest) one. None when the record carries no usable stamp.
    """
    stamps = [
        epoch_datetime(e.get("last_updated_time")) for e in state_map_entries(record).values()
    ]
    stamps.append(epoch_datetime(record.get("last_upd_time")))
    known = [s for s in stamps if s is not None]
    return max(known) if known else None


def checking_finding(record: dict[str, Any], now: datetime) -> tuple[str, bool]:
    """``(text, stalled)`` for a device in ROBOT_OPER_STATE_CHECKING.

    Younger than :data:`CHECKING_TRANSIENT_SECONDS` (or with no stamp to age it
    by) it is the DLM's check cycle in progress — a note; older it is a stall —
    a reason. The text names the stamps the age was computed from and, for a
    REACHABLE record, when the transports' REACHABLE stamps date from, so the
    contradiction "REACHABLE but never checked" is explicit.
    """
    reach = _text(record.get("reachability_state"))
    since = checking_since(record)
    age = (now - since).total_seconds() if since else None
    reach_part = f"reachability_state {reach}"
    if reach == REACHABLE:
        stamp = epoch_datetime(record.get("reachability_state_upd_time"))
        if stamp is None:
            stamps = [
                epoch_datetime(t.get("reachability_state_upd_time"))
                for t in _dicts(record.get("connectivity_info"))
            ]
            known = [s for s in stamps if s]
            stamp = max(known) if known else None
        reach_part += f" (the REACHABLE stamps date from {stamp_text(stamp, now)})"
    if age is None or age < CHECKING_TRANSIENT_SECONDS:
        when = f"since {stamp_text(since, now)}" if since else "(no check stamp to age it by)"
        return (
            f"operational_state CHECKING {when}: the DLM's check cycle is in progress — "
            f"transient after onboarding, a PATCH or a re-attach ({reach_part}; "
            "cnc_wait_for_device_reachable)"
        ), False
    if placeholder_only(record):
        detail = (
            "no REACHABILITY / DISCOVERY / CLOCK_DRIFT check has completed since "
            f"{stamp_text(since, now)} — the state_map still holds only the key-0 placeholder "
            "written at the (re)attach"
        )
    else:
        detail = (
            f"the DLM has not returned the device to ROBOT_OPER_STATE_OK since its last check "
            f"stamp {stamp_text(since, now)}"
        )
    return (f"operational_state CHECKING for {duration_text(age)}: {detail}; {reach_part}"), True


def device_findings(
    record: dict[str, Any], now: datetime | None = None
) -> tuple[list[str], list[str], bool]:
    """``(reasons, notes, unreachable)`` from one inventory record.

    Rules: reachability_state not REACHABLE (UNREACHABLE -> unreachable; UNKNOWN
    while the operational state is CHECKING -> part of the CHECKING finding);
    operational state CHECKING -> :func:`checking_finding` (a note while the
    episode is younger than :data:`CHECKING_TRANSIENT_SECONDS`, a reason once it
    has stalled — computed from the state_map / last_upd_time stamps); any other
    operational state not
    OK; admin state not UP; any transport whose reachability_state is not
    REACHABLE (UNREACHABLE -> unreachable); the record's ``errors``; any
    state_map check not UP; nso_state not SYNCED (a *_SCHEDULED / *_STARTED
    state is an action in flight -> note).
    """
    now = now or datetime.now(UTC)
    reasons: list[str] = []
    notes: list[str] = []
    unreachable = False
    reach = _text(record.get("reachability_state"))
    oper = _text(record.get("operational_state"))
    admin = _text(record.get("admin_state"))
    if reach == UNREACHABLE:
        reasons.append(f"reachability_state {reach}")
        unreachable = True
    elif reach and reach != REACHABLE and oper != OPER_CHECKING:
        reasons.append(f"reachability_state {reach}")
    if oper == OPER_CHECKING:
        text, stalled = checking_finding(record, now)
        (reasons if stalled else notes).append(text)
    elif oper and oper != OPER_OK:
        reasons.append(f"operational_state {oper}")
    if admin and admin != ADMIN_UP:
        reasons.append(f"admin_state {admin}")
    for transport in _dicts(record.get("connectivity_info")):
        state = _text(transport.get("reachability_state"))
        kind = _text(transport.get("type")).replace("ROBOT_MSVC_TRANS_", "")
        if state and state != REACHABLE:
            detail = _text(transport.get("error"))
            reasons.append(f"transport {kind} {state}" + (f" ({detail})" if detail else ""))
            if state == UNREACHABLE:
                unreachable = True
    for error in record.get("errors") or []:
        if _text(error):
            reasons.append(f"device error: {_text(error)}")
    for key, entry in state_map_entries(record).items():
        element = _text(entry.get("element")) or key
        value = _text(entry.get("value"))
        if not is_placeholder_entry(key, entry) and value and value.upper() != "UP":
            info = _text(entry.get("info"))
            reasons.append(f"{element} check {value}" + (f" ({info})" if info else ""))
    nso_state = _text(record.get("nso_state"))
    if nso_state and nso_state != NSO_SYNCED:
        msg = _text(record.get("NsoMsg"))
        if nso_state.endswith("_SCHEDULED") or nso_state.endswith("_STARTED"):
            notes.append(f"nso_state {nso_state}: an NSO action is in flight")
        else:
            reasons.append(f"nso_state {nso_state}" + (f" ({msg})" if msg else ""))
    return reasons, notes, unreachable


def transport_stamp(transport: dict[str, Any], now: datetime) -> str:
    """`` (stamped 36h ago)`` for a transport carrying ``reachability_state_upd_time``."""
    when = epoch_datetime(transport.get("reachability_state_upd_time"))
    if when is None:
        return ""
    return f" (stamped {duration_text((now - when).total_seconds())} ago)"


def newest_transport_stamp(record: dict[str, Any]) -> datetime | None:
    stamps = [
        epoch_datetime(t.get("reachability_state_upd_time"))
        for t in _dicts(record.get("connectivity_info"))
    ]
    stamps.append(epoch_datetime(record.get("reachability_state_upd_time")))
    known = [s for s in stamps if s is not None]
    return max(known) if known else None


def device_lines(record: dict[str, Any], now: datetime | None = None) -> list[str]:
    now = now or datetime.now(UTC)
    ip = _dict(record.get("node_ip")).get("inet_addr")
    lines = [
        f"- {record.get('host_name')} ({record.get('uuid')}) ip {ip or '-'}, profile "
        f"{record.get('profile') or '-'}, data gateway {record.get('dg_name') or '-'}",
        f"- admin {record.get('admin_state')}, operational {record.get('operational_state')}, "
        f"reachability {record.get('reachability_state')}",
    ]
    transports = [
        f"{_text(t.get('type')).replace('ROBOT_MSVC_TRANS_', '')}:{t.get('port')}="
        f"{t.get('reachability_state') or 'not checked'}{transport_stamp(t, now)}"
        for t in _dicts(record.get("connectivity_info"))
    ]
    if transports:
        lines.append(
            f"- transports: {', '.join(transports)} — a stamp is the last time the DLM "
            "wrote that state, not a live probe"
        )
    if record.get("nso_state") is not None:
        lines.append(
            f"- nso_state {record.get('nso_state')} (timestamp {record.get('nso_timestamp')}"
            + (f", NsoMsg {record.get('NsoMsg')}" if _text(record.get("NsoMsg")) else "")
            + ")"
        )
    entries = state_map_entries(record)
    if entries and placeholder_only(record):
        since = checking_since({"state_map": record.get("state_map")})
        lines.append(
            "- state_map: no completed check recorded (key-0 placeholder only since "
            f"{stamp_text(since, now)}) — the REACHABILITY / DISCOVERY / CLOCK_DRIFT entries "
            "appear once the DLM's first check cycle after the (re)attach completes"
        )
    elif entries:
        checks = [
            f"{_text(e.get('element')) or key}={e.get('value')}"
            + (
                f" (checked {stamp_text(epoch_datetime(e.get('last_updated_time')), now)})"
                if epoch_datetime(e.get("last_updated_time"))
                else ""
            )
            for key, e in entries.items()
        ]
        lines.append(f"- state_map: {', '.join(checks)}")
    if record.get("uptime"):
        reach_check = entries.get("1", {})
        stamp = epoch_datetime(reach_check.get("last_updated_time"))
        as_of = (
            f"stamped at the last completed reachability check {stamp_text(stamp, now)}"
            if stamp
            else "stamped at the last completed reachability check, none recorded"
        )
        lines.append(
            f"- uptime {record.get('uptime')} (DLM snapshot {as_of}; not live — the EMF "
            "node section carries the collection-time figure and the boot instant)"
        )
    if record.get("errors"):
        lines.append(f"- errors: {record.get('errors')}")
    return lines


def pm_rows(call: Call) -> int | None:
    """Rows on the page of a cnc_get_performance_statistics JSON answer (``records``, the
    platform's count, else the entries listed); None when the call failed."""
    if not call.ok or not isinstance(call.data, dict):
        return None
    records = call.data.get("records")
    if isinstance(records, int) and not isinstance(records, bool):
        return records
    return len(_dicts(call.data.get("entries")))


def pm_freshness_lines(
    bad: list[str],
    fresh_rows: int | None,
    window_rows: int | None,
    hours: int,
    reasons: list[str],
    notes: list[str],
    probe: Call,
) -> list[str]:
    """The interface-PM section's verdict on collection freshness, appending the
    stall reason / no-samples note as it goes.

    ``window_rows`` is the platform's row count for the whole window — the error
    scan's ``records``, which cnc_get_performance_statistics reports before its
    client-side only_nonzero filter — and ``fresh_rows`` the freshness probe's.
    Three cases: rows in the last :data:`PM_FRESH_HOURS` h -> collection is
    producing samples (a clean window then really is clean); rows in the window
    but none in the last hour -> collection stopped (a reason); no rows in the
    window at all -> no samples (a note: a device outside every interface
    performance policy looks the same as one whose collection stalled before
    the window started). A failed probe (``fresh_rows`` None) or an unreadable
    window count (``window_rows`` None) leaves the question open and says so —
    neither is ever reported as a finding.
    """
    intervals = PM_FRESH_HOURS * 3600 // PM_POLL_INTERVAL_SECONDS
    if fresh_rows is None:
        line = (
            "freshness probe unavailable — "
            + (probe.error or "?")
            + ": "
            + (
                ""
                if bad
                else "an empty only_nonzero scan cannot tell 'no errors' from 'no samples'; "
            )
            + "check cnc_get_performance_statistics(schema='CEPMINTERFACE', device_uuid=...)"
        )
        notes.append("interface PM: " + line)
        return [f"- {line}"]
    if fresh_rows > 0:
        state = (
            f"collection is producing samples: {fresh_rows}+ CEPMINTERFACE row(s) in the last "
            f"{PM_FRESH_HOURS} h"
        )
        if bad:
            return [f"- {state}"]
        return [f"- no interface reported errors or discards in the last {hours} h ({state})"]
    if window_rows:
        line = (
            f"interface PM stale: no CEPMINTERFACE samples in the last {PM_FRESH_HOURS} h "
            f"(more than {intervals}x the {PM_POLL_INTERVAL_SECONDS} s default polling "
            f"interval) although the last {hours} h have rows — interface collection for this "
            "device stopped producing data (cnc_list_performance_policy_devices / "
            "cnc_get_collection_health; narrow the window with from_time/to_time on "
            "cnc_get_performance_statistics to date the last sample)"
        )
        reasons.append(line)
        return [f"- {line}"] + (
            [] if bad else [f"- the {hours} h window shows no errors or discards, but see above"]
        )
    if window_rows is None:
        line = (
            f"no CEPMINTERFACE samples in the last {PM_FRESH_HOURS} h, and the scan did not "
            f"report how many rows the last {hours} h hold, so 'stale' cannot be told from 'no "
            "samples'; check cnc_get_performance_statistics(schema='CEPMINTERFACE', "
            "device_uuid=...)"
        )
        notes.append("interface PM: " + line)
        return [f"- {line}"]
    line = (
        f"NO interface PM samples in the last {hours} h: interface collection for this "
        "device is not producing data — it is outside every interface performance policy "
        "(cnc_list_performance_policy_devices) or its collection stalled before the window "
        "(cnc_get_collection_health); 'no errors' cannot be claimed"
    )
    notes.append(line)
    return [f"- {line}"]


async def investigate_device(
    composer: Composer, host_name: str, uuid: str, hours: int
) -> tuple[Verdict, list[Section]]:
    selector = {"host_name": host_name} if host_name else {"uuid": uuid}
    reasons: list[str] = []
    notes: list[str] = []
    unreachable = False
    sections: list[Section] = []
    now = datetime.now(UTC)

    device = await composer.call("cnc_get_device", **selector)
    record = device.data if isinstance(device.data, dict) else None
    host = _text(record.get("host_name")) if record else host_name
    device_uuid = _text(record.get("uuid")) if record else uuid
    section = Section.from_call("device", "Inventory record", device)
    if record:
        section.lines = device_lines(record, now)
        found, found_notes, unreachable = device_findings(record, now)
        reasons.extend(found)
        notes.extend(found_notes)
    sections.append(section)

    summary = await composer.call("cnc_get_device_collection_summary")
    section = Section.from_call(
        "collection_summary", "Inventory collection status (inventory-wide counts)", summary
    )
    if section.usable and isinstance(summary.data, dict):
        counts = ", ".join(f"{k} {v}" for k, v in summary.data.items())
        section.lines = [
            f"- inventory-wide collection status counts: {counts or 'none'} — counts across "
            "the whole inventory, not this device's status: the device's own inventory "
            "collection is nd.collection-status in the EMF node section, its interface PM "
            "collection the freshness probe in the interface errors section"
        ]
    sections.append(section)

    live_alarms: list[dict[str, Any]] = []
    if host:
        alarms = await composer.call(
            "cnc_search_alarms",
            text=host,
            open_only=True,
            limit=ALARM_SCAN_LIMIT,
            response_format="json",
        )
        section = Section.from_call("alarms", "Open Crosswork alarms naming the device", alarms)
        if section.usable:
            payload = _dict(alarms.data)
            items = [
                a
                for a in _dicts(payload.get("items"))
                if mentions(host, a.get("Description"), a.get("object_description"))
                or (device_uuid and _text(a.get("object_id")) == device_uuid)
            ]
            live = [a for a in items if not is_stale(a, now)]
            live_alarms = live
            stale = [a for a in items if is_stale(a, now)]
            section.data = {"count": len(items), "items": items}
            section.lines = [f"- {alarm_line(a, now)}" for a in live]
            section.lines.extend(f"- (stale?) {alarm_line(a, now)}" for a in stale)
            section.lines = section.lines or ["- none"]
            serious = [a for a in live if _text(a.get("State")).lower() in CRITICAL_MAJOR]
            if serious:
                reasons.append(
                    f"{len(serious)} open Critical/Major Crosswork alarm(s) name {host}: "
                    + "; ".join(_text(a.get("Description")) for a in serious[:3])
                )
            if stale:
                notes.append(
                    f"{len(stale)} open alarm(s) naming {host} have 0 events and no update for "
                    "7+ days: listed as possibly stale, not counted against the device (verify "
                    "with cnc_alarm_triage before acting)"
                )
            if payload.get("truncated"):
                total = payload.get("total")
                section.lines.append(
                    f"- alarm scan incomplete: {total} open alarms contain '{host}', only the "
                    f"{ALARM_SCAN_LIMIT} most recently updated were checked"
                )
                notes.append(
                    f"alarm scan incomplete: {total} open alarms contain '{host}' and only the "
                    f"{ALARM_SCAN_LIMIT} most recently updated were checked — older alarms "
                    f"naming {host} may be missing (cnc_search_alarms text='{host}')"
                )
            # REACHABLE transports next to a live "no response" alarm: say which is older.
            no_response = [a for a in live if NO_RESPONSE_TEXT in _text(a.get("Description"))]
            if record and no_response:
                transports = _dicts(record.get("connectivity_info"))
                all_reachable = transports and all(
                    _text(t.get("reachability_state")) == REACHABLE for t in transports
                )
                stamp = newest_transport_stamp(record)
                raised = [d for d in (epoch_datetime(a.get("Created")) for a in no_response) if d]
                if all_reachable and stamp and raised and stamp < min(raised):
                    stamped = stamp_text(stamp, now)
                    line = (
                        f"the transports read REACHABLE but their stamps ({stamped}) "
                        f"predate the live '{NO_RESPONSE_TEXT}' alarm(s) (raised "
                        f"{stamp_text(min(raised), now)}): the REACHABLE state was written "
                        "before the alarm and has not been re-checked since — read the alarm "
                        "as the current state"
                    )
                    section.lines.append(f"- {line}")
                    notes.append(line)
        sections.append(section)

        history = await composer.call(
            "cnc_search_alarms",
            text=host,
            open_only=False,
            limit=ALARM_SCAN_LIMIT,
            response_format="json",
        )
        section = Section.from_call(
            "alarm_history",
            f"Cleared alarm history naming the device (last {CHRONIC_WINDOW_HOURS} h)",
            history,
        )
        if section.usable:
            payload = _dict(history.data)
            cleared = [
                a
                for a in _dicts(payload.get("items"))
                if is_cleared(a)
                and (
                    mentions(host, fault_text(a), a.get("Description"), a.get("object_description"))
                    or (device_uuid and _text(a.get("object_id")) == device_uuid)
                )
            ]
            section.lines, chronic_notes = chronic_history(live_alarms, cleared, now)
            notes.extend(chronic_notes)
            section.data = {"cleared_count": len(cleared), "chronic": chronic_notes}
            if payload.get("truncated"):
                section.lines.append(
                    f"- history scan incomplete: {payload.get('total')} open and cleared alarms "
                    f"contain '{host}', only the {ALARM_SCAN_LIMIT} most recently updated were "
                    "checked"
                )
        sections.append(section)

        rtm = await composer.call(
            "cnc_list_device_alarms",
            node_fdn=f"MD=CISCO_EMS!ND={host}",
            limit=50,
            response_format="json",
        )
        section = Section.from_call("device_alarms", "Device alarms (EMF fault manager)", rtm)
        if section.usable:
            items = _dicts(_dict(rtm.data).get("items"))
            section.lines = [f"- {device_alarm_line(a)}" for a in items] or ["- none"]
            serious = [
                a
                for a in items
                if device_alarm_severity(a) in CRITICAL_MAJOR
                and device_alarm_severity(a) != "cleared"
            ]
            if serious:
                reasons.append(
                    f"{len(serious)} critical/major device alarm(s): "
                    + "; ".join(_text(field_of(a, "description")) for a in serious[:3])
                )
        sections.append(section)

        events = await composer.call(
            "cnc_list_events", limit=100, text=host, response_format="json"
        )
        section = Section.from_call("events", "Recent Crosswork events naming the device", events)
        if section.usable:
            items = [
                e
                for e in _dicts(_dict(events.data).get("items"))
                if mentions(host, e.get("Description"), e.get("object_description"))
            ]
            section.data = {"count": len(items), "items": items[:20]}
            section.lines = [
                f"- [{e.get('EventSeverity', '?')}] {e.get('object_description', '?')} — "
                f"{e.get('Description', '?')} (age {age_text(e.get('Timestamp'), now)})"
                for e in items[:10]
            ] or ["- none on the newest page of events"]
        sections.append(section)

        ems = await composer.call("cnc_get_ems_node", name=host, response_format="json")
        section = Section.from_call("ems_node", "EMF node (config management view)", ems)
        if section.usable and isinstance(ems.data, dict):
            node = ems.data
            lifecycle = _text(node.get("nd.lifecycle-state"))
            comm = _text(node.get("nd.communication-state"))
            section.lines = [
                f"- lifecycle {lifecycle or '?'}, communication {comm or '?'}, collection "
                f"{collection_status_code(node.get('nd.collection-status')) or '?'} at "
                f"{node.get('nd.collection-time') or '-'}",
                f"- software {node.get('nd.software-type') or '-'} "
                f"{node.get('nd.software-version') or ''}, sys-up-time "
                f"{node.get('nd.sys-up-time') or '-'} (as of the collection time), last boot "
                f"{node.get('nd.last-boot-time') or '-'}",
                "- uptime sources: the inventory record's DLM uptime is stamped at the last "
                "completed reachability check and is not live; EMF sys-up-time is as of the "
                "EMF collection time — the two need not agree, and neither is a live reading; "
                "nd.last-boot-time is the boot instant",
            ]
            if lifecycle and lifecycle != EMF_SYNCHRONIZED:
                reasons.append(
                    f"EMF lifecycle-state {lifecycle} (config management and device alarms need "
                    f"{EMF_SYNCHRONIZED})"
                )
            if comm and comm.lower() != "reachable":
                reasons.append(f"EMF communication-state {comm}")
        sections.append(section)

    if record is None or _text(record.get("nso_state")):
        sync = await composer.call("cnc_check_nso_device_sync", **selector, wait_seconds=30)
        section = Section.from_call("nso_sync", "NSO check-sync (fresh)", sync)
        if section.usable:
            devices = _dicts(_dict(sync.data).get("devices"))
            mine = [d for d in devices if _text(d.get("host_name")).lower() == host.lower()]
            entry = (mine or devices or [{}])[0]
            verdict = _text(entry.get("verdict"))
            section.lines = [
                sync.text.split("\n", 1)[0],
                f"- {entry.get('host_name') or host}: {verdict or '?'} (nso_state "
                f"{entry.get('nso_state')}, {entry.get('nso_timestamp_iso') or '-'})",
            ]
            if verdict == "out-of-sync":
                reasons.append(
                    "NSO check-sync: out of sync (the device configuration differs from NSO's "
                    "copy — cnc_nso_device_action compare-config / sync-from)"
                )
            elif verdict == "failed":
                reasons.append(
                    f"NSO check-sync could not run: {entry.get('NsoMsg') or entry.get('nso_state')}"
                )
            elif verdict == "pending":
                notes.append("NSO check-sync still pending after 30 s (cnc_check_device_nso_state)")
        sections.append(section)
    else:
        sections.append(
            Section.skipped(
                "nso_sync",
                "NSO check-sync (fresh)",
                "cnc_check_nso_device_sync",
                "the device has no nso_state (not associated with an NSO provider)",
            )
        )

    if host:
        topo = await composer.call("cnc_get_topology_node", node_id=host, response_format="json")
        section = Section.from_call("topology", "Topology node (SR-PCE feed)", topo)
        if section.usable and isinstance(topo.data, dict):
            node = topo.data
            l3 = _dict(node.get("ietf-l3-unicast-topology-state:l3-node-attributes"))
            sessions = _dicts(l3.get("cisco-crosswork-l3-te-topology:node-pcep-sessions"))
            tps = node.get("ietf-network-topology-state:termination-point")
            router_ids = ", ".join(str(r) for r in (l3.get("router-id") or [])) or "-"
            if l3:
                section.lines = [
                    f"- router-id {router_ids}; SR-MPLS "
                    f"{'yes' if l3.get('ietf-sr-mpls-topology-state:sr-mpls') else 'no'}; "
                    f"{len(sessions)} PCEP session(s); "
                    f"{len(tps) if isinstance(tps, list) else 0} termination point(s)"
                ]
                section.lines.extend(
                    f"- PCEP: pcc {s.get('pcc-address')} <-> pce {s.get('pce-address')}, "
                    f"stateful {s.get('stateful')}, sr {s.get('capability-sr')}, "
                    f"instantiate {s.get('capability-instantiate')}"
                    for s in sessions
                )
            else:
                section.lines = [
                    "- known from LLDP collection only (no IS-IS/SR attributes): the SR-PCE feed "
                    "does not report this node"
                ]
                notes.append("topology: LLDP-only node (no IS-IS/SR data from the SR-PCE feed)")
        elif section.status == "unavailable":
            notes.append("topology: the node is not reported by the topology NBI")
        sections.append(section)

    backups = await composer.call("cnc_list_device_backups", **selector, response_format="json")
    section = Section.from_call("backups", "Configuration backups", backups)
    if section.usable:
        items = _dicts(_dict(backups.data).get("backups"))
        if not items:
            section.lines = ["- no configuration backup stored"]
            notes.append("no configuration backup stored (cnc_backup_device_config)")
        else:
            newest = items[0]
            when = parse_iso(newest.get("backedup_at"))
            age = f"{(now - when).days} day(s) old" if when else "age unknown"
            section.lines = [
                f"- {len(items)} backup(s); newest {newest.get('name')} at "
                f"{newest.get('backedup_at')} ({age}), {newest.get('trigger')}, "
                f"{newest.get('status')}, {newest.get('complianceStatus') or '-'}"
            ]
            if when is None or (now - when).days > BACKUP_MAX_AGE_DAYS:
                notes.append(
                    f"newest configuration backup is {age} (older than {BACKUP_MAX_AGE_DAYS} days)"
                )
    sections.append(section)

    if device_uuid:
        perf = await composer.call(
            "cnc_get_performance_statistics",
            schema="CEPMINTERFACE",
            metrics=ERROR_METRICS,
            device_uuid=device_uuid,
            hours=hours,
            only_nonzero=True,
            page_size=200,
            response_format="json",
        )
        section = Section.from_call(
            "interface_errors", f"Interface errors / discards (last {hours} h)", perf
        )
        if section.usable:
            entries = _dicts(_dict(perf.data).get("entries"))
            bad = []
            for entry in entries:
                keys = _dict(entry.get("keys"))
                metrics = {
                    k: v for k, v in _dict(entry.get("metrics")).items() if (_number(v) or 0) > 0
                }
                if metrics:
                    bad.append(
                        f"{keys.get('interfaceName') or keys.get('name') or '?'}: "
                        + ", ".join(f"{k}={v}" for k, v in metrics.items())
                    )
            section.lines = [f"- {b}" for b in bad]
            if bad:
                reasons.append(
                    f"interface errors/discards in the last {hours} h: " + "; ".join(bad[:3])
                )

            # Freshness: the scan's ``records`` is the platform's row count for the window
            # (the sibling applies only_nonzero client-side and reports the count before
            # it — verified live: records 6, count 0 for a clean device), so it tells "no
            # samples" from "clean"; one cheap probe over the last hour says whether
            # collection is producing rows right now.
            window_rows = pm_rows(perf)
            fresh = await composer.call(
                "cnc_get_performance_statistics",
                schema="CEPMINTERFACE",
                metrics=ERROR_METRICS,
                device_uuid=device_uuid,
                hours=PM_FRESH_HOURS,
                only_nonzero=False,
                page_size=1,
                response_format="json",
            )
            fresh_rows = pm_rows(fresh)
            section.data = {
                "errors": bad,
                "fresh_rows": fresh_rows,
                "window_rows": window_rows,
                "fresh_hours": PM_FRESH_HOURS,
            }
            section.lines.extend(
                pm_freshness_lines(bad, fresh_rows, window_rows, hours, reasons, notes, fresh)
            )
        sections.append(section)
    else:
        sections.append(
            Section.skipped(
                "interface_errors",
                "Interface errors / discards",
                "cnc_get_performance_statistics",
                "needs the device uuid, which the inventory lookup did not return",
            )
        )

    if record is None:
        status = "unknown"
    elif unreachable:
        status = "unreachable"
    elif reasons:
        status = "degraded"
    else:
        status = "healthy"
    label = host or device_uuid or host_name or uuid
    missing = sum(1 for s in sections if s.status == "unavailable")
    headline = f"{label} is {status}: {len(reasons)} reason(s), {len(notes)} note(s)"
    if missing:
        headline += f", {missing} section(s) unavailable"
    if record is None:
        headline += " — the inventory record could not be read, so the verdict is unknown"
    return Verdict(status, headline + ".", reasons, notes), sections


# --- 2. network health report ---------------------------------------------------------


def _health_count(mapping: dict[str, Any], *keys: str) -> int:
    return sum(_int(mapping.get(k)) for k in keys)


async def network_health_report(composer: Composer) -> tuple[Verdict, list[Section]]:
    red: list[str] = []
    amber: list[str] = []
    notes: list[str] = []
    sections: list[Section] = []
    now = datetime.now(UTC)

    devices = await composer.call("cnc_get_device_summary")
    section = Section.from_call("devices", "Device inventory summary", devices)
    if section.usable and isinstance(devices.data, dict):
        oper = _dict(devices.data.get("operational_state"))
        reach = _dict(devices.data.get("reachability"))
        section.lines = [devices.text.split("\n", 1)[0]]
        bad_reach = _health_count(reach, "unreachable", "degraded")
        bad_oper = _health_count(oper, "down", "error")
        if bad_reach:
            amber.append(
                f"{bad_reach} device(s) unreachable/degraded (cnc_list_devices "
                "reachability='unreachable')"
            )
        if bad_oper:
            amber.append(f"{bad_oper} device(s) in operational state down/error")
    sections.append(section)

    checking_count = (
        _int(_dict(devices.data.get("operational_state")).get("checking"))
        if section.usable and isinstance(devices.data, dict)
        else 0
    )
    if checking_count:
        listing = await composer.call(
            "cnc_list_devices", page_size=HEALTH_DEVICE_PAGE, response_format="json"
        )
        section = Section.from_call(
            "checking_devices", "Devices in operational_state CHECKING", listing
        )
        if section.usable:
            payload = _dict(listing.data)
            checking = [
                d
                for d in _dicts(payload.get("items"))
                if _text(d.get("operational_state")) == OPER_CHECKING
            ]
            stalled: list[str] = []
            young: list[str] = []
            section.lines = []
            for d in checking:
                name = _text(d.get("host_name")) or _text(d.get("uuid")) or "?"
                text, is_stalled = checking_finding(d, now)
                section.lines.append(
                    f"- {name}: {text} — cnc_investigate_device(host_name='{name}')"
                )
                since = checking_since(d)
                age = duration_text((now - since).total_seconds()) if since else "age unknown"
                (stalled if is_stalled else young).append(f"{name} ({age})")
            if stalled:
                amber.append(
                    f"{len(stalled)} device(s) stuck in operational_state CHECKING for more than "
                    f"{CHECKING_TRANSIENT_SECONDS // 60} min: {', '.join(stalled)} — no DLM "
                    "check cycle has completed since the stamp shown "
                    "(cnc_investigate_device host_name=<name>)"
                )
            if young:
                notes.append(
                    f"{len(young)} device(s) still CHECKING (transient, check cycle started "
                    f"less than {CHECKING_TRANSIENT_SECONDS // 60} min ago): {', '.join(young)}"
                )
            if len(checking) < checking_count:
                unnamed = checking_count - len(checking)
                section.lines.append(
                    f"- {unnamed} more CHECKING device(s) not named: only the first "
                    f"{HEALTH_DEVICE_PAGE} devices were scanned (cnc_list_devices page=1, ...)"
                )
                notes.append(
                    f"{unnamed} CHECKING device(s) not named (inventory larger than the "
                    f"{HEALTH_DEVICE_PAGE}-device scan)"
                )
            section.lines = section.lines or ["- none on the scanned page"]
        else:
            notes.append(
                f"{checking_count} device(s) in operational_state CHECKING — names unavailable "
                f"({section.error})"
            )
        sections.append(section)

    collection = await composer.call("cnc_get_device_collection_summary")
    section = Section.from_call("collection", "Device collection status", collection)
    if section.usable and isinstance(collection.data, dict):
        counts = collection.data
        section.lines = [
            "- " + ", ".join(f"{k} {v}" for k, v in counts.items()) if counts else "- no counts"
        ]
        failing = _health_count(counts, "failed", "warning")
        if failing:
            amber.append(f"{failing} device(s) with failed/warning inventory collection")
    sections.append(section)

    cluster = await composer.call("cnc_get_cluster_health")
    section = Section.from_call("cluster", "Crosswork cluster health", cluster)
    if section.usable and isinstance(cluster.data, dict):
        state = _text(cluster.data.get("state"))
        apps = _dicts(cluster.data.get("applications"))
        unhealthy = [
            a
            for a in apps
            if _int(a.get("degraded")) or _int(a.get("down")) or _text(a.get("state")) != "Healthy"
        ]
        section.lines = [
            f"- cluster {state or '?'}; {len(apps)} application(s), {len(unhealthy)} needing "
            "attention"
        ]
        section.lines.extend(
            f"- {a.get('app')}: {a.get('state')} healthy {a.get('healthy')}/{a.get('total')}, "
            f"degraded {a.get('degraded')}, down {a.get('down')}"
            for a in unhealthy
        )
        if state and state.lower() != "healthy":
            red.append(f"cluster state {state}")
        if unhealthy:
            amber.append(
                "applications with degraded/down pods: "
                + ", ".join(_text(a.get("app")) for a in unhealthy)
                + " (cnc_list_microservices app_id=...)"
            )
    sections.append(section)

    gateways = await composer.call("cnc_list_data_gateways", response_format="json")
    section = Section.from_call("data_gateways", "Data Gateways", gateways)
    if section.usable:
        items = _dicts(_dict(gateways.data).get("items"))
        section.lines = []
        for g in items:
            config = _dict(g.get("configData"))
            oper_data = _dict(g.get("operationalData"))
            oper_state = _text(oper_data.get("operState"))
            section.lines.append(
                f"- {g.get('name')}: admin {config.get('adminState')}, oper {oper_state or '?'}, "
                f"role {config.get('role')}"
            )
            if oper_state and oper_state != "OS_UP":
                amber.append(f"data gateway {g.get('name')} operState {oper_state}")
        if not items:
            section.lines = ["- no data gateway reported"]
            amber.append("no data gateway reported (collection cannot run)")
    sections.append(section)

    health = await composer.call("cnc_get_collection_health")
    section = Section.from_call("collection_health", "Collection service (DLM job)", health)
    if section.usable and isinstance(health.data, dict):
        section.lines = [f"- {health.data.get('verdict') or '?'}"]
        if health.data.get("healthy") is False:
            amber.append(f"collection job unhealthy: {health.data.get('verdict')}")
    sections.append(section)

    providers = await composer.call("cnc_list_providers", page_size=50, response_format="json")
    section = Section.from_call("providers", "Providers", providers)
    if section.usable:
        items = _dicts(_dict(providers.data).get("items"))
        section.lines = [
            f"- {p.get('name')} ({_text(p.get('family')).replace('ROBOT_PROVIDER_', '')}): "
            f"{p.get('reachability_state')}"
            for p in items
        ] or ["- no providers"]
        for p in items:
            state = _text(p.get("reachability_state"))
            if state and state != REACHABLE:
                family = _text(p.get("family"))
                line = f"provider {p.get('name')} ({family}) {state}"
                (red if family in SR_PCE_FAMILIES or family == NSO_FAMILY else amber).append(line)
    sections.append(section)

    topology = await composer.call("cnc_get_topology_summary")
    section = Section.from_call("topology", "Topology feed", topology)
    if section.usable and isinstance(topology.data, dict):
        links = _dict(topology.data.get("links"))
        section.lines = [
            f"- {topology.data.get('nodes')} node(s), {links.get('total')} link(s) "
            f"({links.get('isis_ipv4_l2')} IS-IS, {links.get('ethernet')} Ethernet), "
            f"{topology.data.get('sr_capable_nodes')} SR-capable, "
            f"{topology.data.get('pcep_session_nodes')} with PCEP sessions"
        ]
        note = _text(topology.data.get("note"))
        if note:
            section.lines.append(f"- {note}")
            amber.append(f"topology: {note}")
    sections.append(section)

    te = await composer.call("cnc_get_te_summary")
    section = Section.from_call("te", "Traffic engineering", te)
    if section.usable and isinstance(te.data, dict):
        sr = _dict(te.data.get("sr_policies"))
        section.lines = [f"- {te.data.get('summary') or '?'}"]
        down = _int(sr.get("down"))
        if down:
            down_list = ", ".join(str(p) for p in (sr.get("down_policies") or [])[:5])
            amber.append(f"{down} SR policy(ies) DOWN: {down_list}")
    sections.append(section)

    stale_lines: list[str] = []
    advisory_lines: list[str] = []
    for state, bucket in (("Critical", red), ("Major", amber)):
        alarms = await composer.call(
            "cnc_search_alarms",
            state=state,
            open_only=True,
            limit=ALARM_SCAN_LIMIT,
            response_format="json",
        )
        section = Section.from_call(
            f"alarms_{state.lower()}", f"Open {state} alarms (Crosswork)", alarms
        )
        if section.usable:
            payload = _dict(alarms.data)
            items = _dicts(payload.get("items"))
            stale = [a for a in items if is_stale(a, now)]
            advisory = [a for a in items if not is_stale(a, now) and is_advisory(a)]
            live = [a for a in items if not is_stale(a, now) and not is_advisory(a)]
            section.lines = [
                f"- {len(live)} live, {len(advisory)} advisory (housekeeping), {len(stale)} "
                "possibly stale"
            ]
            section.lines.extend(f"- {alarm_line(a, now)}" for a in live)
            section.lines.extend(f"- (advisory) {alarm_line(a, now)}" for a in advisory)
            section.lines.extend(f"- (stale?) {alarm_line(a, now)}" for a in stale)
            if live:
                bucket.append(
                    f"{len(live)} live open {state} alarm(s): "
                    + "; ".join(_text(a.get("Description")) for a in live[:3])
                )
            if advisory:
                amber.append(
                    f"{len(advisory)} advisory {state} alarm(s) (housekeeping, never RED): "
                    + "; ".join(_text(a.get("Description")) for a in advisory[:3])
                )
            advisory_lines.extend(alarm_line(a, now) for a in advisory)
            stale_lines.extend(f"[{state}] {alarm_line(a, now)}" for a in stale)
            if payload.get("truncated"):
                total = payload.get("total")
                line = (
                    f"{total} open {state} alarms, only the {ALARM_SCAN_LIMIT} most recently "
                    "updated were classified (cnc_alarm_triage reads them all)"
                )
                section.lines.append(f"- {line}")
                notes.append(line)
        sections.append(section)
    if advisory_lines:
        section = Section(
            "advisories",
            "Advisory / housekeeping alarms — acknowledge and clear",
            "cnc_search_alarms",
        )
        section.lines = [f"- {line}" for line in advisory_lines]
        section.lines.append(f"- {ADVISORY_HINT}")
        section.data = {"count": len(advisory_lines), "items": advisory_lines}
        sections.append(section)
        notes.append(
            f"{len(advisory_lines)} open Critical/Major alarm(s) are advisories — {ADVISORY_HINT}; "
            "they colour the verdict AMBER at most"
        )
    if stale_lines:
        notes.append(
            f"{len(stale_lines)} open alarm(s) with 0 events and no update for 7+ days are "
            "listed as possibly stale, separately from the live ones — confirm with "
            "cnc_alarm_triage / cnc_get_cluster_health before acting"
        )

    rtm = await composer.call("cnc_list_device_alarms", limit=50, response_format="json")
    section = Section.from_call("device_alarms", "Device alarms (EMF fault manager)", rtm)
    if section.usable:
        items = _dicts(_dict(rtm.data).get("items"))
        serious = [a for a in items if device_alarm_severity(a) in CRITICAL_MAJOR]
        section.lines = [f"- {len(items)} on the first page, {len(serious)} critical/major"]
        section.lines.extend(f"- {device_alarm_line(a)}" for a in serious[:10])
        if serious:
            amber.append(f"{len(serious)} critical/major device alarm(s)")
    sections.append(section)

    nso = await composer.call("cnc_check_device_nso_state", host_name="*", response_format="json")
    section = Section.from_call("nso", "NSO sync state (cached per device)", nso)
    if section.usable:
        items = _dicts(_dict(nso.data).get("items"))
        off = [
            i
            for i in items
            if _text(i.get("nso_state")) and _text(i.get("nso_state")) != NSO_SYNCED
        ]
        section.lines = [f"- {len(items)} device(s) with NSO state, {len(off)} not SYNCED"]
        section.lines.extend(
            f"- {i.get('host_name')}: {i.get('nso_state')} ({i.get('nso_timestamp_iso') or '-'})"
            for i in off
        )
        if off:
            amber.append(
                "devices not SYNCED with NSO: "
                + ", ".join(f"{i.get('host_name')} {i.get('nso_state')}" for i in off[:5])
                + " (cnc_check_nso_device_sync for a fresh verdict)"
            )
    sections.append(section)

    status = "red" if red else "amber" if amber else "green"
    reasons = [f"RED: {r}" for r in red] + [f"AMBER: {a}" for a in amber]
    missing = sum(1 for s in sections if s.status == "unavailable")
    headline = f"Network health {status.upper()}: {len(red)} red, {len(amber)} amber finding(s)"
    if missing:
        headline += f"; {missing} section(s) unavailable"
    return Verdict(status, headline + ".", reasons, notes), sections


# --- 3. explain SR policy --------------------------------------------------------------


# Constraint keys an SR policy path can carry besides the SID algorithm (the NBI model's
# names); their absence is worth stating, since the prompt asks agents to report it.
OPTIONAL_CONSTRAINTS = ("affinity", "disjointness", "bandwidth", "protection")


def constraints_text(path: dict[str, Any]) -> str:
    """``sid-algorithm 0; no affinity / disjointness / bandwidth / protection
    constraint`` for a path's ``constraints`` block."""
    constraints = _dict(path.get("constraints"))
    if not constraints:
        return "none reported"
    parts = [
        f"{k} {to_json(v) if isinstance(v, dict | list) else v}" for k, v in constraints.items()
    ]
    lower = {str(k).lower() for k in constraints}
    absent = [c for c in OPTIONAL_CONSTRAINTS if not any(c in key for key in lower)]
    text = ", ".join(parts)
    if absent:
        text += f"; no {' / '.join(absent)} constraint"
    return text


def policy_lines(
    policy: dict[str, Any], names: dict[str, str] | None = None, now: datetime | None = None
) -> tuple[list[str], dict[str, Any]]:
    """Curated lines plus the facts (origin, delegated, ...) the verdict uses.

    ``names`` (router-id -> host name, from the topology nodes) renders every
    router-id as ``PE2 (10.0.0.3)`` — the ends, the hops — so the NBI section
    reads like the title.
    """
    now = now or datetime.now(UTC)
    details = _dict(policy.get("policy-details"))
    flag_c = _dict(details.get("pcep-info")).get("pcep-flag-c")
    origin = (
        "PCE-initiated (pcep-flag-c 1: created through the Optimization Engine / "
        "cnc_create_sr_policy)"
        if _int(flag_c) == 1
        else "PCC-initiated (pcep-flag-c 0: configured on the router — by NSO/CAT if a policy "
        "service matches below, else on the box outside NSO's service layer)"
    )
    delegated = bool(details.get("pce-controlled"))
    updated = epoch_datetime(details.get("update-time"))
    head = node_text(policy.get("headend"), names)
    end = node_text(policy.get("endpoint"), names)
    lines = [
        f"- {head} -> {end} "
        f"color {policy.get('color')}: admin {policy.get('admin-state')}, oper "
        f"{policy.get('oper-state')}, type {policy.get('sr-policy-type')}, binding-sid "
        f"{details.get('binding-sid')}",
        f"- origin: {origin}",
        f"- delegated to the PCE (pce-controlled): {'yes' if delegated else 'no'}",
        f"- updated {stamp_text(updated, now)} (update-time: the PCC's last report of the policy)",
    ]
    for path in _dicts(details.get("path")):
        metric = _dict(path.get("optimization-metric"))
        hops = ", ".join(
            f"{h.get('label')}@"
            f"{node_text(h.get('local-ip-addr') or h.get('remote-ip-addr') or '?', names)}"
            for h in _dicts(path.get("hop"))
        )
        lines.append(
            f"- candidate path {path.get('path-name')} ({path.get('path-type')}, preference "
            f"{path.get('preference')}, oper {path.get('oper-state')}, metric "
            f"{metric.get('metric-type')}={metric.get('metric-value')}): hops {hops or '-'}"
        )
        lines.append(f"  constraints: {constraints_text(path)}")
    return lines, {"origin": origin, "delegated": delegated, "flag_c": _int(flag_c)}


def route_lines(output: dict[str, Any]) -> list[str]:
    """The computed IGP route as one line.

    ``igp-route`` is the SET of interfaces the policy's traffic is forwarded over,
    not an ordered path (:func:`cnc_mcp.tools.sr_te_operations.group_route_by_node`):
    when every ``interface-use`` is 1 it is a single path and is written as a
    ``->`` chain; when any share is below 1 the traffic is ECMP-split and the
    interfaces are listed per node, so two interfaces on the head-end never read
    as consecutive hops.
    """
    results = _dicts(output.get("results"))
    result = results[0] if results else {}
    route = _dicts(result.get("igp-route"))
    status = result.get("path-computation-status") or "?"
    if not route:
        return [f"- computation {status}: no route"]
    shares = [_number(h.get("interface-use")) for h in route]
    if all(s is None or s >= 1.0 for s in shares):
        chain = " -> ".join(f"{h.get('node')} {h.get('interface')}" for h in route)
        return [f"- computation {status}: single path (every interface share 1.0): {chain}"]
    groups = group_route_by_node(route, str(route[0].get("node") or ""))
    per_node = "; ".join(f"{node} {', '.join(interfaces)}" for node, interfaces in groups)
    share_set = sorted({s for s in shares if s is not None})
    share_text = "/".join(f"{s:g}" for s in share_set)
    return [
        f"- computation {status}: ECMP split — {len(route)} interfaces at share {share_text} "
        f"across {len(groups)} node(s): {per_node}",
        "  share = interface-use, the fraction of the policy's traffic forwarded out of that "
        "interface (0.5 on a two-way split); several interfaces on one node are ECMP "
        "alternatives, not consecutive hops — cnc_list_topology_links(link_type='isis') "
        "gives the branches",
    ]


def npm_lines(
    data: dict[str, Any],
    samples_key: str,
    field: str,
    max_key: str,
    key_known: bool | None = None,
) -> list[str]:
    """The measured series of an NPM answer as one stats line plus the platform's maximum.

    cnc_get_lsp_utilization answers ``{"stats", "samples", "max": {maxUtilization,
    message}}``; cnc_get_lsp_delay ``{"delay": [samples], "max_delay": {maxDelay,
    message}}`` — the stats are computed here for the latter. ``key_known`` (an
    earlier NPM call on the same key answered samples) settles the "unknown key
    or no data" ambiguity of an empty series.
    """
    samples = _dicts(data.get(samples_key))
    stats = _dict(data.get("stats")) or (series_stats(samples, field) if samples else {})
    maximum = _dict(data.get(max_key))
    if stats.get("count"):
        lines = [f"- measured {field}: {stats_text(stats, field)}"]
    elif key_known:
        lines = [
            f"- no measured {field} samples in the window — the key is valid (the utilization "
            "series on the same key has samples), so SR-PM delay probes are not configured on "
            "the head-end for this policy: nothing to measure, not an NPM fault"
        ]
    else:
        lines = [
            f"- no measured {field} samples in the window (an unknown key answers the same "
            "empty list)"
        ]
    if maximum:
        value = maximum.get("maxUtilization", maximum.get("maxDelay"))
        lines.append(f"- platform maximum: {value} ({maximum.get('message') or '-'})")
    return lines


def onbox_policy(
    config: Any, color: int, endpoint_ids: set[str]
) -> tuple[dict[str, Any] | None, list[str]]:
    """``(the matching on-box SR-TE policy, PCE peer addresses)`` from NSO's CDB copy of a
    head-end's ``segment-routing`` subtree (``tailf-ned-cisco-ios-xr:segment-routing``
    -> ``traffic-eng`` -> ``policy[]`` with ``color.value`` / ``color.end-point.ipv4``,
    and ``pcc.pce.address.ipv4[].address``)."""
    root = _dict(config)
    sr = _dict(root.get("tailf-ned-cisco-ios-xr:segment-routing") or root.get("segment-routing"))
    te = _dict(sr.get("traffic-eng"))
    match = None
    for policy in _dicts(te.get("policy")):
        colour = _dict(policy.get("color"))
        if _int(colour.get("value")) == color and (
            not endpoint_ids or _text(_dict(colour.get("end-point")).get("ipv4")) in endpoint_ids
        ):
            match = policy
            break
    peers = [
        _text(p.get("address"))
        for p in _dicts(_dict(_dict(_dict(te.get("pcc")).get("pce")).get("address")).get("ipv4"))
        if _text(p.get("address"))
    ]
    return match, peers


def origin_text(
    facts: dict[str, Any],
    twin: dict[str, Any] | None,
    onbox: dict[str, Any] | None,
    onbox_read: bool,
    head: str,
) -> str:
    """The verdict's "created by" line, sharpened by what the CAT twin search and the
    on-box configuration read showed."""
    if facts.get("flag_c") == 1:
        return str(facts.get("origin"))
    base = "PCC-initiated (pcep-flag-c 0): configured on the head-end router " + head
    if twin:
        return f"{base} by NSO/CAT — policy service {twin['yang_path']}"
    if onbox:
        return (
            f"{base} outside NSO's service layer — on-box policy '{onbox.get('name')}' "
            f"({onbox_path_text(onbox)}) in NSO's copy of its configuration"
        )
    if onbox_read:
        return (
            f"{base} by neither NSO/CAT nor (per NSO's CDB copy) the box's own configuration: "
            "another controller, or the copy is stale (cnc_check_nso_device_sync)"
        )
    return f"{base} — by NSO/CAT if a policy service matches, else on the box (unverified)"


def onbox_path_text(policy: dict[str, Any]) -> str:
    """``preference 100 dynamic pcep metric igp`` for each candidate path of an on-box policy."""
    parts = []
    for pref in _dicts(_dict(policy.get("candidate-paths")).get("preference")):
        text = f"preference {pref.get('id')}"
        dynamic = _dict(pref.get("dynamic"))
        if dynamic:
            text += " dynamic" + (" pcep" if "pcep" in dynamic else "")
            metric = _text(_dict(dynamic.get("metric")).get("type"))
            if metric:
                text += f" metric {metric}"
        elif pref.get("explicit") is not None:
            text += " explicit"
        parts.append(text)
    return ", ".join(parts) or "no candidate path"


def policy_service_matches(
    service: dict[str, Any], headend: str, color: int, endpoints: set[str]
) -> bool:
    """A CAT policy service is the NSO twin when its color matches and its head-end name
    or tail-end router-id does."""
    if _int(service.get("color")) != color:
        return False
    heads = {_text(h.get("name")).lower() for h in _dicts(service.get("head-end"))}
    if headend.lower() in heads:
        return True
    return _text(service.get("tail-end")) in endpoints


def policy_service_candidates(
    infos: list[dict[str, Any]], color: int, head_names: set[str]
) -> list[dict[str, Any]]:
    """The CAT policy service infos in the order worth reading: those whose service-name
    mentions the colour or a head-end name first (the naming convention of every
    NSO-provisioned policy seen live), then the rest in listing order. Only
    :data:`MAX_POLICY_SERVICE_READS` of them are read, so the likely twin goes first."""
    needles = [str(color)] + [h.lower() for h in head_names if h]
    likely = [i for i in infos if any(n in _text(i.get("service-name")).lower() for n in needles)]
    return likely + [i for i in infos if i not in likely]


async def explain_sr_policy(
    composer: Composer, headend: str, endpoint: str, color: int, network: str, hours: int
) -> tuple[Verdict, list[Section]]:
    key = {"headend": headend, "endpoint": endpoint, "color": color, "network": network}
    reasons: list[str] = []
    notes: list[str] = []
    sections: list[Section] = []
    facts: dict[str, Any] = {}
    now = datetime.now(UTC)

    nodes = await composer.call(
        "cnc_list_topology_nodes",
        network=network,
        page_size=TOPOLOGY_NODE_PAGE,
        response_format="json",
    )
    section = Section.from_call("nodes", "Topology node names (router-id -> host name)", nodes)
    names: dict[str, str] = {}
    if section.usable:
        names = router_id_names(_dicts(_dict(nodes.data).get("items")))
        shown = ", ".join(
            f"{host} {rid}" for rid, host in sorted(names.items(), key=lambda kv: kv[1])
        )
        section.lines = [
            f"- {len(names)} router-id(s) named: {shown or 'none (no SR-PCE feed data)'}"
        ]
        section.data = names
    else:
        notes.append("router-ids are shown unresolved: the topology node list was unavailable")
    sections.append(section)

    policy = await composer.call("cnc_get_sr_policy", **key, response_format="json")
    section = Section.from_call("policy", "SR policy (topology NBI)", policy)
    record = policy.data if isinstance(policy.data, dict) else None
    if record:
        section.lines, facts = policy_lines(record, names, now)
    sections.append(section)
    head_id = _text(_dict(record).get("headend"))
    end_id = _text(_dict(record).get("endpoint"))
    # The head-end's host name: the topology's spelling for its router-id, else the
    # caller's argument when that is not itself a router-id.
    head_host = names.get(head_id) or names.get(headend) or ""
    if not head_host and not re.fullmatch(r"[\d.:a-fA-F]+", headend):
        head_host = headend

    routes = await composer.call("cnc_get_sr_policy_routes", **key, response_format="json")
    section = Section.from_call("routes", "Computed route (Optimization Engine)", routes)
    if section.usable and isinstance(routes.data, dict):
        section.lines = route_lines(routes.data)
    sections.append(section)

    metrics = await composer.call("cnc_get_sr_policy_metrics", **key, response_format="json")
    section = Section.from_call("metrics", "Path metrics (Optimization Engine)", metrics)
    if section.usable and isinstance(metrics.data, dict):
        results = _dicts(metrics.data.get("results"))
        result = results[0] if results else {}
        section.lines = [
            f"- igp-metric {result.get('igp-metric')}, te-metric {result.get('te-metric')}, "
            f"delay {result.get('delay')} (computed by the PCE for the current path)"
        ]
    sections.append(section)

    pm = await composer.call("cnc_get_sr_policy_performance_metrics", **key, response_format="json")
    section = Section.from_call("performance_metrics", "Performance metrics (topology NBI)", pm)
    if section.usable and isinstance(pm.data, dict):
        measured = [k for k in pm.data if str(k).endswith("-telemetry")]
        section.lines = [
            f"- delay {pm.data.get('delay')} "
            + (
                "(measured: SR-PM telemetry present)"
                if measured
                else "(MODELLED by the PCE — no SR-PM telemetry keys; not a measurement)"
            )
            + f", bandwidth-utilization {pm.data.get('bandwidth-utilization-kbps')} kbps"
        ]
        if not measured:
            notes.append("the NBI delay is the PCE's modelled figure, not a measurement")
    sections.append(section)

    npm_key = {"headend": headend, "endpoint": endpoint, "color": color, "network": network}
    util = await composer.call(
        "cnc_get_lsp_utilization", **npm_key, hours=hours, response_format="json"
    )
    section = Section.from_call("utilization", f"Measured utilization (NPM, last {hours} h)", util)
    key_known = False
    if section.usable and isinstance(util.data, dict):
        section.lines = npm_lines(util.data, "samples", "util", "max")
        key_known = bool(_int(_dict(util.data.get("stats")).get("count"))) or bool(
            _dicts(util.data.get("samples"))
        )
    elif section.usable:
        section.lines = [f"- {util.text.split(chr(10), 1)[0]}"]
    sections.append(section)

    delay = await composer.call("cnc_get_lsp_delay", **npm_key, hours=hours, response_format="json")
    section = Section.from_call("delay", f"Measured delay (NPM, last {hours} h)", delay)
    if section.usable and isinstance(delay.data, dict):
        section.lines = npm_lines(delay.data, "delay", "averageDelay", "max_delay", key_known)
        if key_known and not _dicts(delay.data.get("delay")):
            notes.append(
                "no NPM delay samples although the utilization series has data on the same key: "
                "SR-PM delay probes are not configured on the head-end for this policy (the NBI "
                "delay stays the PCE's modelled figure)"
            )
    elif section.usable:
        section.lines = [f"- {delay.text.split(chr(10), 1)[0]}"]
    sections.append(section)

    riding = await composer.call(
        "cnc_find_services_on_transport",
        headend=headend,
        color=color,
        endpoint=endpoint,
        response_format="json",
    )
    section = Section.from_call("services", "Services riding the policy (CAT)", riding)
    service_paths: list[str] = []
    if section.usable:
        service_paths = [str(p) for p in _dict(riding.data).get("service_paths") or []]
        section.lines = [f"- {p}" for p in service_paths] or ["- no service uses this policy"]
    sections.append(section)

    twin: dict[str, Any] | None = None
    if facts.get("flag_c") == 1:
        sections.append(
            Section.skipped(
                "policy_service",
                "NSO-configured policy service (CAT)",
                "cnc_list_services",
                "the policy is PCE-initiated, so NSO did not configure it",
            )
        )
    else:
        listing = await composer.call(
            "cnc_list_services", service_type="policy", limit=100, response_format="json"
        )
        section = Section.from_call(
            "policy_service", "NSO-configured policy service (CAT)", listing
        )
        if section.usable:
            endpoints = {endpoint, _text(_dict(record).get("endpoint"))} - {""}
            head_names = {headend, _text(_dict(record).get("headend"))} - {""}
            infos = _dicts(_dict(listing.data).get("items"))
            candidates = policy_service_candidates(infos, color, head_names)
            section.lines = [f"- {len(infos)} policy service(s) in CAT"]
            read_count = 0
            for info in candidates[:MAX_POLICY_SERVICE_READS]:
                path = _text(info.get("yang-path"))
                if not path:
                    continue
                read = await composer.call(
                    "cnc_get_service", yang_path=path, include_plan=False, response_format="json"
                )
                read_count += 1
                service = _dict(_dict(read.data).get("service")) if read.ok else {}
                if service and any(
                    policy_service_matches(service, h, color, endpoints) for h in head_names
                ):
                    twin = {"yang_path": path, "service": service}
                    section.lines.append(
                        f"- matches {path}: head-end "
                        f"{[h.get('name') for h in _dicts(service.get('head-end'))]}, tail-end "
                        f"{service.get('tail-end')}, color {service.get('color')} — NSO "
                        "configured this policy (cnc_get_service / cnc_get_service_plan)"
                    )
                    break
            if twin is None and read_count < len(infos):
                section.lines.append(
                    f"- no match among the {read_count} of {len(infos)} policy services read "
                    "(those named after the colour / head-end first): the twin may be among "
                    "the rest — cnc_list_services(service_type='policy') and cnc_get_service "
                    "per yang-path to check them"
                )
                notes.append(
                    f"only {read_count} of {len(infos)} CAT policy services were read looking "
                    "for the NSO twin: an NSO origin is not ruled out"
                )
            elif twin is None:
                section.lines.append(
                    f"- none of the {len(infos)} CAT policy service(s) matches this "
                    "head-end/colour: the policy was configured on the router outside NSO's "
                    "service layer (the on-box configuration below is the evidence)"
                )
            section.data = {
                "policy_services": len(infos),
                "read": read_count,
                "match": twin,
            }
        sections.append(section)

    # The definitive on-box evidence for a PCC-initiated policy: NSO's CDB copy of the
    # head-end's segment-routing subtree names the policy and its PCEP peer.
    onbox: dict[str, Any] | None = None
    pce_peers: list[str] = []
    onbox_read = False
    if facts.get("flag_c") == 1:
        sections.append(
            Section.skipped(
                "onbox_config",
                "On-box SR-TE configuration (NSO CDB copy of the head-end)",
                "cnc_get_nso_device_config",
                "the policy is PCE-initiated, so it is not in the head-end's configuration",
            )
        )
    elif not head_host:
        sections.append(
            Section.skipped(
                "onbox_config",
                "On-box SR-TE configuration (NSO CDB copy of the head-end)",
                "cnc_get_nso_device_config",
                f"the head-end's host name is unknown (router-id {headend} not in the topology "
                "node list) — NSO devices are keyed by host name",
            )
        )
    else:
        config = await composer.call(
            "cnc_get_nso_device_config", host_name=head_host, subtree="segment-routing"
        )
        section = Section.from_call(
            "onbox_config", "On-box SR-TE configuration (NSO CDB copy of the head-end)", config
        )
        if section.usable:
            onbox_read = True
            endpoint_ids = {end_id, endpoint} - {""}
            onbox, pce_peers = onbox_policy(config.data, color, endpoint_ids)
            peers_text = ", ".join(node_text(p, names) for p in pce_peers) or "none configured"
            if onbox:
                colour = _dict(onbox.get("color"))
                tail = _text(_dict(colour.get("end-point")).get("ipv4")) or end_id
                section.lines = [
                    f"- on-box policy '{onbox.get('name')}' color {color} end-point "
                    f"{node_text(tail, names)}: candidate path(s) {onbox_path_text(onbox)}"
                ]
            else:
                tail = node_text(end_id or endpoint, names)
                section.lines = [
                    f"- no on-box SR-TE policy with color {color} to {tail} in NSO's copy of "
                    f"{head_host}'s configuration (the copy may be stale — "
                    "cnc_check_nso_device_sync; or the policy came from another controller)"
                ]
            section.lines.append(
                f"- PCEP peer(s) configured on {head_host} (pcc pce address): {peers_text}"
            )
            section.lines.append(
                "- this is NSO's CDB copy as of its last sync-from, not a live read of the router"
            )
            section.data = {"policy": onbox, "pce_peers": pce_peers}
        sections.append(section)

    if record is None:
        status = "not-reported"
        reasons.append(
            f"the SR-PCE feed does not report SR policy {headend} -> {endpoint} color {color} "
            "(cnc_list_sr_policies lists the known ones)"
        )
    else:
        oper = _text(record.get("oper-state")).upper()
        status = "up" if oper == "UP" else "down" if oper == "DOWN" else oper.lower() or "unknown"
        reasons.append(f"oper-state {oper or '?'}, admin-state {record.get('admin-state')}")
        reasons.append(
            f"created by: {origin_text(facts, twin, onbox, onbox_read, head_host or head_id)}"
        )
        pce_text = ", ".join(node_text(p, names) for p in pce_peers)
        reasons.append(
            "delegated to the PCE"
            + (f" at {pce_text} (the head-end's configured PCEP peer)" if pce_text else "")
            if facts["delegated"]
            else "not delegated (router-computed)"
        )
        if twin:
            reasons.append(f"provisioned by NSO as {twin['yang_path']}")
        reasons.append(
            f"{len(service_paths)} service(s) ride it"
            + (": " + ", ".join(service_paths[:3]) if service_paths else "")
        )
    headline = f"SR policy {headend} -> {endpoint} color {color} is {status}."
    return Verdict(status, headline, reasons, notes), sections


# --- 4. alarm triage --------------------------------------------------------------------


def pod_of(alarm: dict[str, Any]) -> str:
    """The pod / service name a pod-health alarm is ABOUT.

    The fault text names it ("optima-lcm-0 health is down.", "cwm-api-service is
    down." — :data:`POD_HEALTH_TEXT`); failing that, ``object_id`` then the first
    token of ``object_description``. Never ``origin_service_id`` / ``origin_app_id``:
    live (2026-09-14) the "optima-lcm-0 health is down." alarm carries
    origin_service_id robot-orch-6ff95ffb65-cxjdg and origin_app_id capp-infra — the
    pod that raised it — while optima-lcm lives in capp-coe.
    """
    match = POD_HEALTH_TEXT.match(_text(alarm.get("Description")))
    if match:
        return match.group(1)
    for key in ("object_id", "object_description"):
        text = _text(alarm.get(key))
        if text:
            return text.split(" ", 1)[0]
    return ""


def microservice_for(pod: str, services: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The microservice whose Name equals the pod name or is its longest prefix."""
    best: dict[str, Any] | None = None
    for service in services:
        name = _text(service.get("Name"))
        if name and (pod == name or pod.startswith(name + "-")):
            if best is None or len(name) > len(_text(best.get("Name"))):
                best = service
    return best


async def read_open_alarms(
    composer: Composer, alarms: Call
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """``(open alarms, section lines, notes)`` — the whole open set, honestly.

    One ``cnc_search_alarms(open_only=true, limit=500)`` — the sibling's maximum
    — answers every open alarm up to that cap. Two flags say when it did not:
    the sibling's ``truncated`` (more matches than ``limit``) and finalize()'s
    ``truncation_note`` / ``shown`` (the answer was size-capped — no longer
    possible inside a composite, but checked so a regression cannot pass
    silently). In either case the set is re-read per State (Critical, Major,
    Minor, Warning, Info; ``limit`` 500 each — exactly as
    cnc_network_health_report reads them) and merged by AlarmId; only a State
    that still exceeds 500 open alarms is reported as partially read, with its
    total.
    """
    payload = _dict(alarms.data)
    items = _dicts(payload.get("items"))
    size_capped = "truncation_note" in payload or "shown" in payload
    limit_capped = bool(payload.get("truncated"))
    if not size_capped and not limit_capped:
        return items, [], []
    total = payload.get("total")
    why = (
        f"the single fetch was size-capped ({len(items)} of {total} open alarms came back)"
        if size_capped
        else f"{total} open alarms exceed the {TRIAGE_LIMIT}-alarm cap of one cnc_search_alarms "
        "fetch"
    )
    merged: dict[str, dict[str, Any]] = {}
    per_state: list[str] = []
    partial: list[str] = []
    for state in OPEN_ALARM_STATES:
        read = await composer.call(
            "cnc_search_alarms",
            state=state,
            open_only=True,
            limit=TRIAGE_LIMIT,
            response_format="json",
        )
        state_payload = _dict(read.data)
        rows = _dicts(state_payload.get("items")) if read.ok else []
        for a in rows:
            merged[_text(a.get("AlarmId")) or f"{state}-{len(merged)}"] = a
        if not read.ok:
            partial.append(f"{state}: unavailable ({read.error})")
            per_state.append(f"{state} unavailable")
            continue
        state_total = state_payload.get("total")
        if state_payload.get("truncated") or "truncation_note" in state_payload:
            partial.append(
                f"{state}: {len(rows)} of {state_total} open alarms read (the {TRIAGE_LIMIT} most "
                f"recently updated — cnc_search_alarms state='{state}' for the rest)"
            )
            per_state.append(f"{state} {len(rows)}/{state_total}")
        else:
            per_state.append(f"{state} {len(rows)}")
    for a in items:  # anything the first fetch had that a per-State read lacks
        merged.setdefault(_text(a.get("AlarmId")) or f"first-{len(merged)}", a)
    lines = [
        f"- {why}: re-read per State ({', '.join(per_state)}) — {len(merged)} open alarms read"
    ]
    notes = (
        [f"open alarms NOT fully read — {'; '.join(partial)}"]
        if partial
        else [f"{why}: re-read per State, all {len(merged)} open alarms read"]
    )
    return list(merged.values()), lines, notes


async def alarm_triage(composer: Composer, include_cleared: bool) -> tuple[Verdict, list[Section]]:
    notes: list[str] = []
    sections: list[Section] = []
    now = datetime.now(UTC)
    act_now: list[str] = []
    possibly_stale: list[str] = []
    advisory: list[str] = []
    informational: list[str] = []

    alarms = await composer.call(
        "cnc_search_alarms", open_only=True, limit=TRIAGE_LIMIT, response_format="json"
    )
    section = Section.from_call("alarms", "Open Crosswork alarms", alarms)
    items: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    if section.usable:
        items, read_lines, read_notes = await read_open_alarms(composer, alarms)
        notes.extend(read_notes)
        by_state: dict[str, int] = {}
        for a in items:
            by_state[_text(a.get("State")) or "?"] = (
                by_state.get(_text(a.get("State")) or "?", 0) + 1
            )
        section.lines = [
            f"- {len(items)} open alarm(s): "
            + ", ".join(f"{k} {v}" for k, v in sorted(by_state.items())),
            *read_lines,
        ]
        section.data = {"count": len(items), "by_state": by_state, "items": items}
        stale = [a for a in items if is_stale(a, now)]
        for a in items:
            if is_stale(a, now):
                continue  # triaged below, against the cluster's current state
            line = alarm_line(a, now)
            state = _text(a.get("State")).lower()
            if is_advisory(a):
                advisory.append(line)
            elif state in CRITICAL_MAJOR:
                act_now.append(line)
            else:
                informational.append(line)
    sections.append(section)

    cluster: dict[str, Any] | None = None
    if stale:
        health = await composer.call("cnc_get_cluster_health")
        section = Section.from_call("cluster", "Cluster health (stale-alarm cross-check)", health)
        if section.usable and isinstance(health.data, dict):
            cluster = health.data
            apps = _dicts(cluster.get("applications"))
            section.lines = [
                f"- cluster {cluster.get('state')}; "
                + ", ".join(
                    f"{a.get('app')} {a.get('state')} {a.get('healthy')}/{a.get('total')}"
                    for a in apps
                )
            ]
        sections.append(section)

        # The subject pod is looked up cluster-wide: the alarm's origin_app_id names the
        # application that RAISED it, not the one the pod lives in (pod_of).
        listing = await composer.call(
            "cnc_list_microservices", page_size=MICROSERVICE_LIST_PAGE, response_format="json"
        )
        services: list[dict[str, Any]] | None = (
            _dicts(_dict(listing.data).get("items")) if listing.ok else None
        )
        section = Section.from_call("microservices", "Microservices (cluster-wide)", listing)
        if section.usable:
            rows = services or []
            unhealthy = [r for r in rows if _text(r.get("health_state")).lower() != "healthy"]
            section.lines = [f"- {len(rows)} microservice(s), {len(unhealthy)} not Healthy"]
            section.lines.extend(
                f"- {r.get('Name')} ({r.get('app')}): {r.get('health_state')} up {r.get('up_time')}"
                for r in unhealthy[:10]
            )
            if _dict(listing.data).get("has_more"):
                section.lines.append(
                    f"- more than {MICROSERVICE_LIST_PAGE} microservices: only the first "
                    f"{MICROSERVICE_LIST_PAGE} were checked (cnc_list_microservices page=1)"
                )
        sections.append(section)

        cluster_apps = {_text(a.get("app")): a for a in _dicts(_dict(cluster).get("applications"))}
        for a in stale:
            line = alarm_line(a, now)
            pod = pod_of(a)
            evidence: list[str] = []
            healthy_now: bool | None = None
            service = microservice_for(pod, services) if services and pod else None
            app = _text(service.get("app")) if service else ""
            app_health = cluster_apps.get(app) if app else None
            if app_health:
                evidence.append(
                    f"cluster health: {app} {app_health.get('state')} "
                    f"{app_health.get('healthy')}/{app_health.get('total')} pods healthy"
                )
                healthy_now = _text(app_health.get("state")).lower() == "healthy"
            if service:
                state = _text(service.get("health_state"))
                evidence.append(
                    f"microservice {service.get('Name')} ({app or '?'}) is {state} "
                    f"(up {service.get('up_time')})"
                )
                healthy_now = state.lower() == "healthy" and healthy_now is not False
            elif services is not None and pod:
                evidence.append(
                    f"no microservice named like '{pod}' on the cluster"
                    + (f" (cluster {cluster.get('state')})" if cluster else "")
                )
            if healthy_now is False:
                act_now.append(f"{line} — STILL UNHEALTHY: {'; '.join(evidence)}")
            else:
                why = "; ".join(evidence) if evidence else "0 events, unchanged for 7+ days"
                possibly_stale.append(f"{line} — evidence: {why}")

    rtm = await composer.call("cnc_list_device_alarms", limit=50, response_format="json")
    section = Section.from_call("device_alarms", "Device alarms (EMF fault manager)", rtm)
    if section.usable:
        device_items = _dicts(_dict(rtm.data).get("items"))
        section.lines = [f"- {len(device_items)} device alarm(s) on the first page"]
        for a in device_items:
            line = f"device alarm {device_alarm_line(a)}"
            severity = device_alarm_severity(a)
            if severity in CRITICAL_MAJOR:
                act_now.append(line)
            elif severity != "cleared":
                informational.append(line)
    sections.append(section)

    if include_cleared:
        cleared = await composer.call(
            "cnc_search_alarms", state="Clear", open_only=False, limit=30, response_format="json"
        )
        section = Section.from_call("cleared", "Recently cleared alarms", cleared)
        if section.usable:
            rows = _dicts(_dict(cleared.data).get("items"))
            section.lines = [f"- {alarm_line(a, now)}" for a in rows if is_cleared(a)] or ["- none"]
        sections.append(section)

    triage = Section("triage", "Triage", "cnc_alarm_triage")
    triage.lines = [f"### Act now ({len(act_now)})", *(f"- {x}" for x in act_now)]
    triage.lines += [
        f"### Possibly stale ({len(possibly_stale)})",
        *(f"- {x}" for x in possibly_stale),
    ]
    triage.lines += [
        f"### Advisory / housekeeping — acknowledge and clear ({len(advisory)})",
        *(f"- {x}" for x in advisory),
    ]
    if advisory:
        triage.lines.append(f"({ADVISORY_HINT})")
    triage.lines += [
        f"### Informational ({len(informational)})",
        *(f"- {x}" for x in informational),
    ]
    triage.lines.append(
        "Ack state is the ack= flag on each line. Acknowledge with cnc_acknowledge_alarm("
        "alarm_id=...), record a finding with cnc_annotate_alarm(alarm_id=..., note=...) — "
        "notes are permanent — and clear a confirmed-stale alarm with cnc_clear_alarm("
        "alarm_id=...); all three are write tools (CNC_MCP_ENABLE_WRITES=true)."
    )
    triage.data = {
        "act_now": act_now,
        "possibly_stale": possibly_stale,
        "advisory": advisory,
        "informational": informational,
    }
    sections.insert(0, triage)

    status = (
        "act-now"
        if act_now
        else "stale-only"
        if possibly_stale
        else "advisory-only"
        if advisory
        else "clear"
    )
    headline = (
        f"{len(act_now)} alarm(s) to act on, {len(possibly_stale)} possibly stale, "
        f"{len(advisory)} advisory, {len(informational)} informational."
    )
    reasons = act_now[:10]
    return Verdict(status, headline, reasons, notes), sections


# --- 5. explain service -----------------------------------------------------------------


def vpn_parts(yang_path: str) -> tuple[str, str] | None:
    """``(layer, vpn_id)`` of a VPN service path, or None for any other service."""
    match = re.search(
        r"(ietf-l[23]vpn-ntw):l[23]vpn-ntw/vpn-services/vpn-service=([^/]+)", yang_path
    )
    if not match:
        return None
    layer = "l3" if match.group(1) == "ietf-l3vpn-ntw" else "l2"
    return layer, match.group(2)


def plan_status_of(data: Any) -> str:
    """The CAT plan status of a cnc_get_service_plan JSON answer (``plan_data.status``)."""
    return _text(_dict(_dict(data).get("plan_data")).get("status")).lower()


def deployment_verdict(plan_status: str) -> str:
    if plan_status == "completed":
        return "deployed"
    if plan_status in ("in-progress", "delete-in-progress"):
        return "in-progress"
    if plan_status == "failed":
        return "failed"
    return "unknown"


async def resolve_service_name(
    composer: Composer, name: str
) -> tuple[str, Section, Verdict | None]:
    """``(yang_path, section, verdict)`` for a bare service name looked up in the CAT
    inventory: the path of the service whose service-name equals ``name``
    (case-insensitive); an empty path plus a ``not-found`` / ``ambiguous`` /
    ``unknown`` verdict when nothing, several services of different types, or no
    listing at all answers to it."""
    listing = await composer.call(
        "cnc_list_services",
        name_prefix=name,
        limit=SERVICE_LOOKUP_LIMIT,
        response_format="json",
    )
    section = Section.from_call("lookup", "Service lookup (CAT inventory)", listing)
    if not section.usable:
        return "", section, Verdict("unknown", f"'{name}' could not be looked up: {listing.error}")
    infos = _dicts(_dict(listing.data).get("items"))
    exact = [i for i in infos if _text(i.get("service-name")).lower() == name.lower()]
    paths = sorted({_text(i.get("yang-path")) for i in exact} - {""})
    describe = [
        f"- {i.get('service-name')} ({i.get('label') or i.get('service-type')}): "
        f"{i.get('yang-path')}"
        for i in (exact or infos)
    ]
    if len(paths) == 1:
        section.lines = [f"- '{name}' is {describe[0].lstrip('- ')}"]
        return paths[0], section, None
    if not paths:
        section.lines = [
            f"- no service named '{name}' in the CAT inventory; {len(infos)} name(s) start "
            "with it" + (":" if infos else "")
        ] + describe[:10]
        headline = (
            f"No service named '{name}' in the CAT inventory"
            + (f"; {len(infos)} service name(s) start with it (listed below)" if infos else "")
            + ". Check the name with cnc_list_services / cnc_get_service_counts."
        )
        return "", section, Verdict("not-found", headline)
    section.lines = [f"- '{name}' names {len(paths)} services of different types:"] + describe
    return (
        "",
        section,
        Verdict(
            "ambiguous",
            f"'{name}' names {len(paths)} services of different types: call again with the "
            "yang_path of the one you mean.",
        ),
    )


async def explain_service(
    composer: Composer, yang_path: str, vpn_id: str, layer: str, name: str = ""
) -> tuple[Verdict, list[Section]]:
    reasons: list[str] = []
    notes: list[str] = []
    sections: list[Section] = []
    path = yang_path.strip()
    if not path and name.strip():
        path, section, verdict = await resolve_service_name(composer, name.strip())
        sections.append(section)
        if verdict is not None:
            return verdict, sections
    elif not path:
        model = vpn_layer(layer)
        path = f"{model.module}:{model.root}/vpn-services/vpn-service={vpn_id.strip()}"
    vpn = vpn_parts(path)

    service = await composer.call(
        "cnc_get_service", yang_path=path, include_plan=True, response_format="json"
    )
    section = Section.from_call("service", "Service intent and NSO bookkeeping", service)
    plan_status = ""
    if section.usable and isinstance(service.data, dict):
        body = _dict(service.data.get("service"))
        cat_plan = _dict(service.data.get("plan"))
        plan_status = _text(cat_plan.get("status")).lower()
        section.lines = [
            f"- {path}",
            f"- created {body.get('created') or '-'}, last-modified "
            f"{body.get('last-modified') or '-'}, last-run {body.get('last-run') or '-'}; "
            f"modified devices {_dict(body.get('modified')).get('devices') or []}",
            f"- CAT plan: {plan_status or 'no plan data'}"
            + (
                f" — {_dict(cat_plan.get('error-info')).get('message')}"
                if cat_plan.get("error-info")
                else ""
            ),
        ]
        intent = {
            k: v
            for k, v in body.items()
            if k
            not in (
                "created",
                "last-modified",
                "last-run",
                "modified",
                "directly-modified",
                "plan-location",
            )
        }
        section.lines.append(f"- intent: {clip_text(to_json(intent), 'cnc_get_service', 1500)}")
    sections.append(section)

    plan = await composer.call(
        "cnc_get_service_plan", plan_yang_path=path, detail=True, response_format="json"
    )
    section = Section.from_call("plan", "Service plan (CAT status + NSO nano-plan)", plan)
    if section.usable and isinstance(plan.data, dict):
        plan_status = plan_status_of(plan.data) or plan_status
        components = _dicts(_dict(_dict(plan.data.get("plan")).get("plan")).get("component"))
        section.lines = [f"- CAT status {plan_status or 'unknown'}"]
        for c in components:
            states = ", ".join(
                f"{_text(s.get('name')).split(':')[-1]}={s.get('status')}"
                for s in _dicts(c.get("state"))
            )
            section.lines.append(
                f"- {_text(c.get('type')).split(':')[-1]} {c.get('name')}: {states}"
            )
            if any(_text(s.get("status")) == "failed" for s in _dicts(c.get("state"))):
                reasons.append(f"nano-plan component {c.get('name')} has a failed state")
    elif section.usable:
        section.lines = [f"- {plan.text.split(chr(10), 1)[0]}"]
    sections.append(section)

    oper_status = ""
    underlay = ""
    monitoring = ""
    if vpn:
        vpn_layer_name, vpn_key = vpn
        health = await composer.call(
            "cnc_get_vpn_service_health", vpn_id=vpn_key, layer=vpn_layer_name
        )
        section = Section.from_call("health", "VPN oper-status (CAT)", health)
        if section.usable:
            section.lines = [f"- {health.text.split(chr(10), 1)[0]}"]
            oper_status = _text(_dict(health.data).get("status")).split(":")[-1]
        sections.append(section)

        transport = await composer.call(
            "cnc_get_vpn_underlay_transport",
            vpn_id=vpn_key,
            layer=vpn_layer_name,
            response_format="json",
        )
        section = Section.from_call("underlay", "Discovered underlay transport (CAT)", transport)
        if section.usable and isinstance(transport.data, dict):
            policies = _dicts(transport.data.get("sr_policy_refs"))
            tunnels = _dicts(transport.data.get("te_tunnel_refs"))
            underlay = f"{len(policies)} SR policy(ies), {len(tunnels)} RSVP-TE tunnel(s)"
            section.lines = [f"- {underlay}"]
            section.lines.extend(
                f"- SR policy {field_of(p, 'headend')} color {field_of(p, 'color')} -> "
                f"{field_of(p, 'endpoint')} (cnc_explain_sr_policy)"
                for p in policies
            )
        elif section.usable:
            underlay = "none discovered"
            section.lines = [f"- {transport.text.split(chr(10), 1)[0]}"]
        sections.append(section)

        subs = await composer.call(
            "cnc_list_sub_services", service_yang_path=path, response_format="json"
        )
        section = Section.from_call("sub_services", "Sub-services (per vpn-node)", subs)
        if section.usable:
            paths = _dict(subs.data).get("items") or []
            section.lines = [f"- {p}" for p in paths] or ["- none"]
        sections.append(section)

        probe = await composer.call("cnc_get_probe_status", service_id=path)
        section = Section.from_call("monitoring", "Service Health probes", probe)
        if section.usable:
            first = probe.text.split("\n", 1)[0]
            monitoring = (
                "no active probe session"
                if first.startswith("No active probe")
                else "probe report available"
            )
            section.lines = [f"- {first}"]
        sections.append(section)
    else:
        notes.append(
            "not a VPN service: the oper-status, underlay, sub-service and probe sections apply "
            "to ietf-l3vpn / ietf-l2vpn services only"
        )

    status = deployment_verdict(plan_status) if service.ok or plan.ok else "unknown"
    if not service.ok and not plan.ok:
        reasons.append(f"neither the service nor its plan could be read ({service.error})")
    else:
        reasons.append(f"CAT plan status: {plan_status or 'no plan data'}")
    if vpn:
        reasons.append(f"oper-status: {oper_status or 'unknown'}")
        reasons.append(f"underlay: {underlay or 'unknown'}")
        reasons.append(f"monitoring: {monitoring or 'unknown'}")
    headline = f"{path}: {status}."
    return Verdict(status, headline, reasons, notes), sections


# --- 6. provision L3VPN end to end ------------------------------------------------------


def first_two_nodes(endpoints: str) -> list[str]:
    try:
        parsed = json.loads(endpoints)
    except ValueError:
        return []
    nodes: list[str] = []
    for entry in _dicts(parsed):
        node = _text(entry.get("node"))
        if node and node not in nodes:
            nodes.append(node)
    return nodes[:2]


async def provision_l3vpn_e2e(
    composer: Composer,
    *,
    vpn_id: str,
    route_distinguisher: str,
    route_target: str,
    endpoints: str,
    topology: str,
    profile_id: str,
    trace: bool,
    wait_seconds: int,
    dry_run: bool = False,
    global_dry_run: bool = False,
) -> tuple[Verdict, list[Section]]:
    steps: list[str] = []
    notes: list[str] = []
    sections: list[Section] = []
    args = {
        "vpn_id": vpn_id,
        "route_distinguisher": route_distinguisher,
        "route_target": route_target,
        "endpoints": endpoints,
        "topology": topology,
        "profile_id": profile_id,
    }
    service_path = f"{L3VPN_SERVICE_LIST}={vpn_id}"

    def stop(status: str, headline: str) -> tuple[Verdict, list[Section]]:
        return Verdict(status, headline, steps, notes), sections

    dry = await composer.call("cnc_create_l3vpn_service", **args, dry_run=True)
    sections.append(Section.from_call("dry_run", "Dry run (device CLI NSO would push)", dry))
    if not dry.ok:
        steps.append(f"dry run: FAILED — {dry.error}")
        return stop("failed", f"Stopped at the dry run; nothing was committed for '{vpn_id}'.")
    steps.append("dry run: ok (CLI rendered below, nothing committed)")
    if dry_run:
        steps.append("commit: not attempted (dry_run=true)")
        why = "dry_run=true"
        sections.append(Section.skipped("commit", "Commit (NSO)", "cnc_create_l3vpn_service", why))
        sections.append(
            Section.skipped("plan", "Service plan convergence", "cnc_wait_for_service_plan", why)
        )
        sections.append(
            Section.skipped(
                "health", "VPN oper-status (CAT inventory)", "cnc_get_vpn_service_health", why
            )
        )
        sections.append(
            Section.skipped(
                "trace",
                "OAM trace route",
                "cnc_start_oam_trace_route",
                why if trace else "trace=false",
            )
        )
        return stop(
            DRY_RUN_STATUS,
            f"Dry run only for '{vpn_id}': the device CLI NSO would push is rendered below; "
            f"nothing was committed. {next_step(global_dry_run, 'provision it')}",
        )

    commit = await composer.call("cnc_create_l3vpn_service", **args, dry_run=False)
    sections.append(Section.from_call("commit", "Commit (NSO)", commit))
    if not commit.ok:
        steps.append(f"commit: FAILED — {commit.error}")
        return stop(
            "failed",
            f"Stopped at the commit of '{vpn_id}': NSO rejected it, so nothing was deployed. "
            "Nothing was deleted or rolled back.",
        )
    steps.append(f"commit: ok — {commit.text.split(chr(10), 1)[0]}")

    plan = await composer.call(
        "cnc_wait_for_service_plan",
        plan_yang_path=service_path,
        target="completed",
        timeout_seconds=wait_seconds,
    )
    sections.append(Section.from_call("plan", "Service plan convergence", plan))
    plan_ok = plan.ok and " is completed after " in plan.text
    if plan.ok and plan_ok:
        steps.append(f"plan: completed — {plan.text.split(chr(10), 1)[0]}")
    elif plan.ok:
        steps.append(
            f"plan: not completed within {wait_seconds} s — {plan.text.split(chr(10), 1)[0]}"
        )
        notes.append("the plan is still converging: re-check with cnc_wait_for_service_plan")
    else:
        steps.append(f"plan: FAILED — {plan.error}")

    health = await composer.call("cnc_get_vpn_service_health", vpn_id=vpn_id, layer="l3")
    sections.append(Section.from_call("health", "VPN oper-status (CAT inventory)", health))
    oper = ""
    if health.ok:
        oper = _text(_dict(health.data).get("status")).split(":")[-1]
        steps.append(f"verify: in the CAT inventory, oper-status {oper or '?'}")
    else:
        steps.append(f"verify: CAT inventory read failed — {health.error}")

    trace_ok: bool | None = None
    trace_tool_absent = trace and not await composer.has("cnc_start_oam_trace_route")
    if not trace:
        sections.append(
            Section.skipped("trace", "OAM trace route", "cnc_start_oam_trace_route", "trace=false")
        )
    elif trace_tool_absent:
        why = (
            "cnc_start_oam_trace_route is not registered on this server (OAM writes are off: "
            "CNC_MCP_WRITE_AREAS or CNC_MCP_DISABLED_TOOLS), so no trace was run"
        )
        sections.append(
            Section.skipped("trace", "OAM trace route", "cnc_start_oam_trace_route", why)
        )
        steps.append(f"trace: skipped — {why}")
        notes.append(
            "verify the data path another way, or enable OAM writes and run "
            "cnc_start_oam_trace_route yourself"
        )
    elif not plan.ok:
        sections.append(
            Section.skipped(
                "trace", "OAM trace route", "cnc_start_oam_trace_route", "the service plan failed"
            )
        )
    else:
        nodes = first_two_nodes(endpoints)
        if len(nodes) < 2:
            sections.append(
                Section.skipped(
                    "trace",
                    "OAM trace route",
                    "cnc_start_oam_trace_route",
                    "a trace needs two distinct PE nodes in endpoints",
                )
            )
        else:
            uuids: list[str] = []
            for node in nodes:
                device = await composer.call("cnc_get_device", host_name=node)
                device_uuid = _text(_dict(device.data).get("uuid")) if device.ok else ""
                if device_uuid:
                    uuids.append(device_uuid)
                else:
                    sections.append(Section.from_call(f"device_{node}", f"Device {node}", device))
            if len(uuids) < 2:
                steps.append(
                    "trace: skipped — could not resolve both endpoint nodes to inventory uuids"
                )
                trace_ok = False
            else:
                start = await composer.call(
                    "cnc_start_oam_trace_route",
                    service_yang_path=service_path,
                    headend_uuid=uuids[0],
                    endpoint_uuid=uuids[1],
                )
                sections.append(Section.from_call("trace_start", "OAM trace route start", start))
                query_id = _text(_dict(start.data).get("query_id")) if start.ok else ""
                if not query_id:
                    steps.append(
                        f"trace: FAILED to start — {start.error or start.text.split(chr(10), 1)[0]}"
                    )
                    trace_ok = False
                else:
                    wait = await composer.call(
                        "cnc_wait_for_oam_trace_route", query_id=query_id, timeout_seconds=90
                    )
                    sections.append(Section.from_call("trace", "OAM trace route result", wait))
                    first = wait.text.split("\n", 1)[0]
                    if not wait.ok:
                        steps.append(f"trace: FAILED — {wait.error}")
                        trace_ok = False
                    elif "FAILED" in first:
                        steps.append(f"trace: the platform's verdict is FAILED — {first}")
                        trace_ok = False
                    elif "not finished" in first:
                        steps.append(f"trace: not finished — {first}")
                        notes.append(
                            "re-check the trace with cnc_wait_for_oam_trace_route("
                            f"query_id='{query_id}')"
                        )
                    else:
                        steps.append(f"trace: {first}")
                        trace_ok = True

    if plan_ok and health.ok and trace_ok is not False:
        status = "deployed"
    elif not plan.ok:
        status = "failed"
    else:
        status = "deployed-unverified"
    headline = (
        f"L3VPN '{vpn_id}' {status}: committed by NSO, plan "
        f"{'completed' if plan_ok else 'not completed' if plan.ok else 'FAILED'}, oper-status "
        f"{oper or 'unknown'}"
        + (
            ""
            if not trace
            else ", trace skipped (tool not registered)"
            if trace_tool_absent
            else f", trace {'ok' if trace_ok else 'not ok' if trace_ok is False else 'pending'}"
        )
        + f". Remove it with cnc_delete_vpn_service(vpn_id='{vpn_id}', layer='l3') when done."
    )
    return Verdict(status, headline, steps, notes), sections


# --- 7. create SR policy end to end ---------------------------------------------------


async def create_sr_policy_e2e(
    composer: Composer,
    *,
    headend: str,
    endpoint: str,
    color: int,
    path_name: str,
    description: str | None,
    path_type: str,
    objective: str,
    hops: str,
    protected: bool,
    sid_algorithm: int | None,
    bandwidth_mbps: int | None,
    binding_sid: int | None,
    network: str,
    wait_seconds: int,
    dry_run: bool = False,
    global_dry_run: bool = False,
) -> tuple[Verdict, list[Section]]:
    steps: list[str] = []
    notes: list[str] = []
    sections: list[Section] = []
    path_args: dict[str, Any] = {
        "path_type": path_type,
        "objective": objective,
        "hops": hops,
        "protected": protected,
        "sid_algorithm": sid_algorithm,
        "bandwidth_mbps": bandwidth_mbps,
        "network": network,
    }
    key = {"headend": headend, "endpoint": endpoint, "color": color}
    label = f"{headend} -> {endpoint} color {color}"

    dry = await composer.call(
        "cnc_dryrun_sr_policy",
        headend=headend,
        endpoint=endpoint,
        **path_args,
        response_format="json",
    )
    section = Section.from_call("dry_run", "Dry run (Optimization Engine)", dry)
    if dry.ok and isinstance(dry.data, dict):
        route = " -> ".join(
            f"{h.get('node')} {h.get('interface')}" for h in _dicts(dry.data.get("igp-route"))
        )
        sids = ", ".join(
            f"{h.get('sid')}@{h.get('ip-address')}"
            for h in _dicts(dry.data.get("segment-list-hops"))
        )
        section.lines = [
            f"- state {dry.data.get('state')}"
            + (f" — {dry.data.get('message')}" if dry.data.get("message") else ""),
            f"- route: {route or '-'}",
            f"- segment list: {sids or '-'}",
        ]
    sections.append(section)
    if not dry.ok:
        steps.append(f"dry run: FAILED — {dry.error}")
        return Verdict(
            "failed", f"Stopped at the dry run; no policy was created for {label}.", steps, notes
        ), sections
    steps.append(f"dry run: {_dict(dry.data).get('state') or 'ok'}")
    if dry_run:
        steps.append("create: not attempted (dry_run=true)")
        if _text(_dict(dry.data).get("state")) == "degraded":
            notes.append("the dry run was degraded (constraints relaxed)")
        why = "dry_run=true"
        sections.append(
            Section.skipped("create", "Create (PCE-initiated)", "cnc_create_sr_policy", why)
        )
        sections.append(
            Section.skipped(
                "oper_state", "Oper-state convergence", "cnc_wait_for_sr_policy_oper_state", why
            )
        )
        sections.append(
            Section.skipped("routes", "Computed route", "cnc_get_sr_policy_routes", why)
        )
        return Verdict(
            DRY_RUN_STATUS,
            f"Dry run only for {label}: the route the PCE would compute is shown below; no "
            f"policy was created. {next_step(global_dry_run, 'create it')}",
            steps,
            notes,
        ), sections
    if _text(_dict(dry.data).get("state")) == "degraded":
        notes.append("the dry run was degraded (constraints relaxed); the create proceeds anyway")

    create = await composer.call(
        "cnc_create_sr_policy",
        **key,
        path_name=path_name,
        description=description,
        binding_sid=binding_sid,
        **path_args,
    )
    sections.append(Section.from_call("create", "Create (PCE-initiated)", create))
    if not create.ok:
        steps.append(f"create: FAILED — {create.error}")
        return Verdict(
            "failed", f"Stopped at the create of {label}: the PCE rejected it.", steps, notes
        ), sections
    steps.append(f"create: {_dict(create.data).get('state') or 'ok'}")

    wait = await composer.call(
        "cnc_wait_for_sr_policy_oper_state",
        **key,
        target="UP",
        timeout_seconds=wait_seconds,
        network=network,
    )
    sections.append(Section.from_call("oper_state", "Oper-state convergence", wait))
    first = wait.text.split("\n", 1)[0]
    up = wait.ok and " is UP after " in first
    if up:
        steps.append(f"oper-state: {first}")
    elif wait.ok:
        steps.append(f"oper-state: not UP within {wait_seconds} s — {first}")
        notes.append("re-check with cnc_wait_for_sr_policy_oper_state or cnc_get_sr_policy")
    else:
        steps.append(f"oper-state: wait FAILED — {wait.error}")

    routes = await composer.call(
        "cnc_get_sr_policy_routes", **key, network=network, response_format="json"
    )
    section = Section.from_call("routes", "Computed route", routes)
    if routes.ok and isinstance(routes.data, dict):
        section.lines = route_lines(routes.data)
        steps.append(f"route: {section.lines[0].lstrip('- ')}")
    else:
        steps.append(f"route: unavailable — {routes.error}")
    sections.append(section)

    status = "created-up" if up else "created-not-up"
    headline = (
        f"SR policy {label} ({path_name}) was created and is {'UP' if up else 'not UP yet'}. "
        f"Remove it with cnc_delete_sr_policy(headend='{headend}', endpoint='{endpoint}', "
        f"color={color}) when done."
    )
    return Verdict(status, headline, steps, notes), sections


# --- registration -----------------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings = ctx.settings

    @register_tool(
        mcp,
        ctx,
        name="cnc_investigate_device",
        title="Investigate a Device (one call)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_investigate_device(
        host_name: Annotated[
            str,
            Field(
                description="Device host name, exact match, case-insensitive (e.g. 'PE1'). Give "
                "host_name or uuid.",
                max_length=253,
            ),
        ] = "",
        uuid: Annotated[
            str,
            Field(
                description="Device inventory uuid (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d'); "
                "alternative to host_name.",
                max_length=100,
            ),
        ] = "",
        hours: Annotated[
            int,
            Field(
                description="Window for the interface error/discard statistics, in hours "
                "(e.g. 24).",
                ge=1,
                le=720,
            ),
        ] = 24,
        response_format: Annotated[ResponseFormat, Field(description=_FORMAT_DESC)] = (
            ResponseFormat.MARKDOWN
        ),
    ) -> str:
        """The "device X looks degraded" playbook in one call: inventory record, collection
        status, alarms and events naming the device, the EMF node, a fresh NSO check-sync,
        the topology node, the newest configuration backup and the interface error /
        discard counters — with a verdict.

        Use it FIRST for "is PE2 healthy?", "why does P1 look degraded?", "check device
        X". Use the individual tools afterwards to drill into a section that is
        degraded or unavailable (each section names its tool), or when you need only
        one fact (cnc_get_device for the record alone, cnc_search_alarms for the alarms).

        VERDICT rules: ``unreachable`` when reachability_state is CONN_STATE_UNREACHABLE
        or any transport (connectivity_info[].reachability_state) is; ``degraded`` when
        any of: operational_state ROBOT_OPER_STATE_CHECKING for 40+ minutes (a STALL:
        the age is the newest of the state_map stamps and last_upd_time — a state_map
        holding only the key-0 placeholder means no REACHABILITY / DISCOVERY /
        CLOCK_DRIFT check has completed since the (re)attach, and the reason says so
        and dates the REACHABLE transport stamps; younger than 40 minutes it is the
        DLM's check cycle in progress -> note. The 40 min is two reachability
        cadences — 1200 s seen live — a HEURISTIC not measured against a healthy
        re-attach: a first check can land on the next cadence tick, and
        ``next_check_time`` is not a schedule on 7.2), any other operational_state not OK,
        admin_state not UP, a transport not REACHABLE, a device error, a state_map
        check not UP, nso_state not SYNCED (a *_STARTED / *_SCHEDULED state is an
        action in flight -> note), the fresh check-sync out-of-sync or failed, a LIVE
        open Critical / Major Crosswork alarm naming the device (whole-word match on
        the host name, or object_id = uuid), a critical / major device alarm, EMF
        lifecycle-state not MANAGED_AND_SYNCHRONIZED or communication-state not
        Reachable, any interface with non-zero error / discard rates in the window, or
        STALE interface PM (CEPMINTERFACE rows exist in the window but none in the
        last hour — 12x the 300 s default polling interval — so collection for the
        device stopped); ``healthy`` otherwise; ``unknown`` when the inventory record
        itself could not be read. Notes, never degraded: a missing or 7+-day-old
        backup, a stale-looking alarm (0 events, no update for 7+ days — listed
        "(stale?)" and not counted, as in cnc_network_health_report), a pending
        check-sync, an LLDP-only / absent topology node, an incomplete alarm scan (more
        than 500 open alarms contain the host name as a substring — the note says so),
        NO interface PM samples anywhere in the window (a device outside every
        interface performance policy looks the same as one whose collection stalled
        before the window — the section never claims "no errors" then), a CHRONIC
        alarm (the live alarm's fault text was cleared N times in the last 48 h,
        typically by "Device was detached." — the open one is a recurring fault masked
        by the clears, not a new event), and REACHABLE transport stamps that PREDATE a
        live "did not receive any response" alarm (the stamps are the DLM's last write,
        not a live probe; read the alarm as the current state). Sections that answered
        "Error: ..." are listed as unavailable and are not covered by the verdict. The
        inventory record's ``uptime`` is a DLM snapshot stamped at the last completed
        reachability check and the EMF node's sys-up-time is as of the EMF collection
        time: neither is live and they need not agree (both sections say so).

        Sub-tools called, in order: cnc_get_device, cnc_get_device_collection_summary
        (inventory-wide counts, not this device's status), cnc_search_alarms(text=<host>,
        open_only=true, limit=500 — the sibling's cap, applied to the substring matches
        before the whole-word filter here), cnc_search_alarms(text=<host>,
        open_only=false, limit=500 — the cleared history behind the chronic note),
        cnc_list_device_alarms(node_fdn='MD=CISCO_EMS!ND=<host>'), cnc_list_events(
        text=<host>, newest page), cnc_get_ems_node(name=<host>),
        cnc_check_nso_device_sync(wait_seconds=30; skipped when the device has no
        nso_state), cnc_get_topology_node(node_id=<host>), cnc_list_device_backups,
        cnc_get_performance_statistics(schema=CEPMINTERFACE, error/discard metrics,
        only_nonzero=true, device_uuid=<uuid>; its ``records`` is the platform's row
        count for the window, reported before the client-side only_nonzero filter, and
        tells "no samples" from "clean") then the freshness probe — the same call with
        only_nonzero=false, page_size=1, hours=1. The name-keyed sections need the host
        name: with uuid only and a failed record read they are skipped.

        Args:
            host_name / uuid: exactly one selector.
            hours: statistics window (default 24).
            response_format: markdown (default) or json.

        Returns:
            str: Markdown "# Device investigation: <host>" with the VERDICT block
            (status, headline, reasons, notes, unavailable sections), one "## <section>
            — <tool>" block per sub-tool (curated lines, or "<section>: unavailable —
            <error>"), and "## Calls made" (one "tool(args) -> ok|error" line each); or
            JSON {"verdict": {"status", "headline", "reasons", "notes", "missing"},
            "sections": {<key>: {"title", "tool", "status", "summary", "data"|"text",
            "error"?}}, "calls": [{"tool", "arguments", "ok", "error"?}]}.
            "Error: Pass exactly one of host_name or uuid." before any call.
        """
        try:
            if bool(host_name.strip()) == bool(uuid.strip()):
                return "Error: Pass exactly one of host_name or uuid."
            composer = Composer(mcp)
            verdict, sections = await investigate_device(
                composer, host_name.strip(), uuid.strip(), hours
            )
            title = f"Device investigation: {host_name.strip() or uuid.strip()}"
            return render(title, verdict, sections, composer, response_format, settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_network_health_report",
        title="Network Health Report (one call)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_network_health_report(
        response_format: Annotated[ResponseFormat, Field(description=_FORMAT_DESC)] = (
            ResponseFormat.MARKDOWN
        ),
    ) -> str:
        """The network health overview in one call: device counts, collection status,
        cluster health, Data Gateways, the collection service, providers, the topology
        feed, TE policy counts, open Critical / Major alarms (stale ones separated),
        device alarms and the cached NSO sync state of every device — with a
        green / amber / red verdict.

        Use it FIRST for "how is the network?", "give me a health overview", "anything
        wrong?". Drill into a finding with the tool its section names (cnc_list_devices
        reachability='unreachable', cnc_list_microservices app_id=..., cnc_list_sr_policies
        oper_state='DOWN', cnc_alarm_triage for the alarms, cnc_investigate_device for one
        device).

        VERDICT rules: RED when the cluster state is not Healthy, an SR-PCE or NSO
        provider is not CONN_STATE_REACHABLE, or a LIVE (not stale, not advisory) open
        Critical alarm exists; AMBER when devices are unreachable / degraded / down /
        error, a device has been in operational_state CHECKING for 40+ minutes (named,
        with its stall age from the state_map / last_upd_time stamps — younger ones are
        a transient note, also named; 40 min is two 1200 s reachability cadences, a
        heuristic not measured against a healthy re-attach), inventory collection has
        failed / warning
        devices, an application has degraded or down pods, a Data Gateway is not OS_UP
        (or none exists), the collection job is unhealthy, another provider is
        unreachable, the topology summary carries a note (L2-only: the SR-PCE feed is
        not up; or no networks yet), SR policies are DOWN, a live open Major alarm
        exists, an ADVISORY alarm exists, critical / major device alarms exist, or
        devices are not SYNCED with NSO; GREEN otherwise. Two alarm classes never make
        the report RED: an open alarm with 0 events and no update for 7+ days is
        possibly stale (Crosswork does not auto-clear pod-health alarms) — listed
        separately, prefixed "(stale?)", and it never colours the verdict; an open alarm
        with at most one event whose Description is a one-shot housekeeping request
        ("acknowledge/clear this alarm manually", "not recommended for production",
        "take a data backup", "certificates will expire") is an ADVISORY — listed
        "(advisory)" and again under its own "Advisory / housekeeping" section, AMBER
        at most, whatever its State (verified live 2026-09-14: the data-backup reminder
        and the pod-reservation warning are raised Critical and turned a healthy lab
        RED). A past-tense "certificate has expired" is NOT an advisory. Each alarm
        State is read with limit=500 (the sibling's maximum); when more open alarms of
        a State exist the section and a note say "<total> open <State> alarms, only the
        500 most recently updated were classified (cnc_alarm_triage reads them all)".
        Unavailable sections are listed and not covered.

        Sub-tools called, in order: cnc_get_device_summary, cnc_list_devices(
        page_size=100, json — only when the summary counts CHECKING devices, to name
        them; a larger inventory is noted as partially scanned),
        cnc_get_device_collection_summary, cnc_get_cluster_health,
        cnc_list_data_gateways, cnc_get_collection_health (the built-in DLM job),
        cnc_list_providers, cnc_get_topology_summary, cnc_get_te_summary,
        cnc_search_alarms(state='Critical', limit=500) and (state='Major', limit=500)
        (open only), cnc_list_device_alarms, cnc_check_device_nso_state(host_name='*').

        Args:
            response_format: markdown (default) or json.

        Returns:
            str: Markdown "# Network health report" with the VERDICT block (reasons
            prefixed RED: / AMBER:), the sections and the "## Calls made" audit list;
            or JSON {"verdict", "sections", "calls"} as described in the module
            docstring. Never "Error: ..." for a sub-tool failure — the section says so.
        """
        try:
            composer = Composer(mcp)
            verdict, sections = await network_health_report(composer)
            return render(
                "Network health report", verdict, sections, composer, response_format, settings
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_explain_sr_policy",
        title="Explain an SR Policy (one call)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_explain_sr_policy(
        headend: Annotated[
            str,
            Field(
                description="Head-end of the policy: a host name (e.g. 'PE1') or its TE "
                "router-id (e.g. '10.0.0.1').",
                min_length=1,
                max_length=253,
            ),
        ],
        endpoint: Annotated[
            str,
            Field(
                description="Endpoint (tail-end) of the policy: a host name (e.g. 'PE2') or its "
                "TE router-id (e.g. '10.0.0.3').",
                min_length=1,
                max_length=253,
            ),
        ],
        color: Annotated[
            int, Field(description="The policy color (e.g. 100).", ge=1, le=4294967295)
        ],
        network: Annotated[str, Field(description=_NETWORK_DESC, min_length=1, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        hours: Annotated[
            int,
            Field(
                description="Window for the NPM utilization / delay samples, in hours (e.g. 6).",
                ge=1,
                le=720,
            ),
        ] = 6,
        response_format: Annotated[ResponseFormat, Field(description=_FORMAT_DESC)] = (
            ResponseFormat.MARKDOWN
        ),
    ) -> str:
        """Explain one SR policy in one call: who created it (PCE-initiated, pcep-flag-c
        1, vs PCC-initiated / router-configured, 0), whether it is delegated to the PCE
        (pce-controlled), its candidate paths and hops, the route the Optimization
        Engine computes, its path metrics, the NBI performance metrics (modelled unless
        SR-PM telemetry is present), the NPM measured utilization and delay, which
        services ride it, and — for a PCC-initiated policy — the NSO/CAT policy service
        that configured it, if any.

        Use it for "explain policy PE1 -> PE2 colour 100", "who created this policy?",
        "is that policy delegated?", "what rides it?". Drill in with cnc_get_sr_policy
        (raw entry), cnc_get_sr_policy_routes, cnc_get_lsp_utilization / cnc_get_lsp_delay
        (samples — pass hours=<the same hours>, their default is 24),
        cnc_find_services_on_transport, cnc_get_service (the CAT twin),
        cnc_get_nso_device_config(host_name=<head-end>, subtree='segment-routing') (the
        on-box policy and PCEP peer as NSO holds them), cnc_list_topology_links(
        link_type='isis') (the branches of an ECMP route).

        VERDICT: the policy's oper-state (``up`` / ``down`` / ``not-reported`` when the
        SR-PCE feed does not list it); the reasons spell out origin (sharpened by the
        CAT twin search and the on-box configuration: "by NSO/CAT — policy service
        <path>", "outside NSO's service layer — on-box policy '<name>'", or unverified
        when neither could be read), delegation (naming the PCE the head-end is
        configured to peer with, resolved to its host name when the topology knows it),
        the NSO twin and the riding services. A modelled (non-telemetry) NBI delay is a
        note; an empty NPM delay series while the utilization series on the same key
        has samples is explained as "SR-PM delay probes not configured on the head-end"
        (the key is proven valid), not left as "unknown key or no data". The NBI
        section renders every router-id as "<host> (<router-id>)" through the topology
        node map, lists each candidate path's constraints block ("sid-algorithm 0; no
        affinity / disjointness / bandwidth / protection constraint") and the policy's
        update-time. The computed route is the SET of interfaces the traffic uses: a
        route whose interface shares are all 1.0 is a single path written as a "->"
        chain; any share below 1.0 is an ECMP split, written per node ("PE1 Gi0/0/0/0,
        Gi0/0/0/1; P1 ...; P2 ...") — never as a hop chain. Unavailable sections (the
        NPM answering no samples is NOT unavailable — it is an empty section) are listed
        and not covered.

        Sub-tools called, in order: cnc_list_topology_nodes(page_size=500, json — the
        router-id -> host name map), cnc_get_sr_policy, cnc_get_sr_policy_routes,
        cnc_get_sr_policy_metrics, cnc_get_sr_policy_performance_metrics,
        cnc_get_lsp_utilization, cnc_get_lsp_delay, cnc_find_services_on_transport, and
        for a PCC-initiated policy cnc_list_services(service_type='policy') plus up to 10
        cnc_get_service reads matched by colour and head-end name / tail-end router-id —
        the services whose name mentions the colour or head-end are read first, and when
        more policy services exist than were read and none matched, the section says "no
        match among the N of M read" (an NSO origin is not ruled out) rather than
        claiming the policy was configured outside NSO; that claim is made only when
        every policy service was read — then cnc_get_nso_device_config(host_name=<head-end
        host name>, subtree='segment-routing'), NSO's CDB copy (as of its last sync-from,
        not a live read) of the head-end's SR-TE configuration: the on-box policy with
        this colour and end-point, its candidate paths, and the configured PCEP peers.
        Both are skipped for a PCE-initiated policy; the NSO read is also skipped when
        the head-end's host name is unknown (a router-id the topology does not list).

        Args:
            headend / endpoint: host names or TE router-ids (the tools resolve both).
            color: the policy colour.
            network: topology network id for name resolution.
            hours: NPM window (default 6).
            response_format: markdown (default) or json.

        Returns:
            str: Markdown "# SR policy <headend> -> <endpoint> color <c>" with the
            VERDICT block, the sections and the audit list; or JSON {"verdict",
            "sections", "calls"}. Never "Error: ..." for a sub-tool failure.
        """
        try:
            composer = Composer(mcp)
            verdict, sections = await explain_sr_policy(
                composer, headend.strip(), endpoint.strip(), color, network.strip(), hours
            )
            title = f"SR policy {headend.strip()} -> {endpoint.strip()} color {color}"
            return render(title, verdict, sections, composer, response_format, settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_alarm_triage",
        title="Alarm Triage (one call)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_alarm_triage(
        include_cleared: Annotated[
            bool,
            Field(description="true to add a section of recently cleared alarms (default false)."),
        ] = False,
        response_format: Annotated[ResponseFormat, Field(description=_FORMAT_DESC)] = (
            ResponseFormat.MARKDOWN
        ),
    ) -> str:
        """Triage every open alarm in one call: ACT NOW / POSSIBLY STALE (with the
        evidence) / INFORMATIONAL, with the ack state on every line and the hint for
        acknowledging, annotating and clearing.

        Use it for "what alarms need attention?", "triage the alarms", "are these alarms
        real?". Drill in with cnc_get_alarm(alarm_id=...) (events, notes, ack history),
        cnc_get_cluster_health / cnc_list_microservices(app_id=...) for a pod-health alarm,
        cnc_investigate_device for an alarm naming a device.

        Rules: one cnc_search_alarms fetch of every open alarm (limit 500 — the
        sibling's maximum — newest updated first; the platform ignores server-side
        filters, so one fetch split client-side by State costs a fifth of five).
        COMPLETENESS: when that fetch reports ``truncated`` (more than 500 open alarms)
        — or carries finalize()'s ``truncation_note`` / ``shown`` (a size-capped
        answer, impossible inside a composite since sub-calls run uncapped, but checked
        so a regression cannot pass silently) — the open set is re-read per State
        (Critical, Major, Minor, Warning, Info; limit 500 each, exactly as
        cnc_network_health_report reads them) and merged by AlarmId; the note then
        says "re-read per State, all N open alarms read", or names the State that
        still exceeds 500 with "M of T read". Never "exceed the 500-alarm cap" for a
        set that was read in full. Then: an ADVISORY (open, at most one event,
        Description a one-shot housekeeping request: "acknowledge/clear this alarm
        manually", "not recommended for production", "take a data backup",
        "certificates will expire" — a past-tense "certificate has expired" is a live
        fault, not an advisory) -> its own bucket, whatever its State (the data-backup
        reminder is raised Critical); other Critical / Major -> act now; Minor /
        Warning / Info -> informational; an open alarm with 0 events and no update for
        7+ days -> possibly stale, cross-checked against the pod it is ABOUT: the
        subject named by the fault text ("<pod> [health] is down."; else object_id /
        object_description — never origin_service_id / origin_app_id, which name the
        pod that RAISED the alarm: live, "optima-lcm-0 health is down." originates
        from robot-orch in capp-infra while optima-lcm lives in capp-coe) is looked up
        in one cluster-wide cnc_list_microservices (the microservice whose Name is the
        pod name or its longest prefix), and that microservice's own application is
        read from cnc_get_cluster_health: when either is NOT Healthy the alarm moves
        to act now as "STILL UNHEALTHY", otherwise the evidence is quoted (a pod no
        microservice matches is said so); device alarms from cnc_list_device_alarms:
        critical / major -> act now, the rest informational.

        Sub-tools called: cnc_search_alarms(open_only=true, limit=500) (plus one per
        State when the open set exceeds the cap), cnc_get_cluster_health and
        cnc_list_microservices(page_size=500, unscoped — every application) (only when
        stale alarms exist), cnc_list_device_alarms, and with include_cleared
        cnc_search_alarms(state='Clear', open_only=false, limit=30).

        Args:
            include_cleared: also list recently cleared alarms.
            response_format: markdown (default) or json.

        Returns:
            str: Markdown "# Alarm triage" with the VERDICT block (status ``act-now`` /
            ``stale-only`` / ``advisory-only`` / ``clear``; the reasons are the act-now
            lines; a note says how completely the open set was read only when a
            re-read was needed), a "## Triage" section with the four lists (act now,
            possibly stale, advisory / housekeeping, informational) and the ack / note /
            clear hint, the sub-tool sections and the audit list; or JSON {"verdict",
            "sections" (the "triage" section's data holds {"act_now", "possibly_stale",
            "advisory", "informational"}; the "alarms" section's data {"count",
            "by_state", "items"}), "calls"}. Never "Error: ..." for a sub-tool failure.
        """
        try:
            composer = Composer(mcp)
            verdict, sections = await alarm_triage(composer, include_cleared)
            return render("Alarm triage", verdict, sections, composer, response_format, settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_explain_service",
        title="Explain a Service (one call)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_explain_service(
        yang_path: Annotated[
            str,
            Field(
                description="The service yang-path as cnc_list_services returns it (e.g. "
                "'ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-91' or "
                "'cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template=mcp-odn-90'). "
                "Give yang_path or vpn_id.",
                max_length=1000,
            ),
        ] = "",
        vpn_id: Annotated[
            str,
            Field(
                description="A VPN service id (the vpn-id list key, exact and case-sensitive, e.g. "
                "'mcp-l3vpn-91'); alternative to yang_path, with layer. VPNs only — for an "
                "ODN template, policy, slice or tunnel give name or yang_path.",
                max_length=253,
            ),
        ] = "",
        layer: Annotated[
            str,
            Field(
                description="With vpn_id: 'l3' (ietf-l3vpn-ntw, default) or 'l2' (ietf-l2vpn-ntw).",
                max_length=8,
            ),
        ] = "l3",
        name: Annotated[
            str,
            Field(
                description="A bare service name as cnc_list_services shows it, any type "
                "(e.g. 'mcp-odn-90'); resolved to its yang-path through the CAT inventory. "
                "Alternative to yang_path / vpn_id.",
                max_length=253,
            ),
        ] = "",
        response_format: Annotated[ResponseFormat, Field(description=_FORMAT_DESC)] = (
            ResponseFormat.MARKDOWN
        ),
    ) -> str:
        """Explain one provisioned service in one call: its NSO intent and bookkeeping,
        the CAT plan status with the nano-plan components, and for a VPN its
        oper-status, discovered underlay transport, sub-services and Service Health
        probes — with a deployed / in-progress / failed verdict. Give the service as
        its yang-path, as a VPN id, or as a bare name (looked up in the CAT inventory).

        Use it for "is service X deployed?", "explain VPN Y", "what carries this VPN?".
        Drill in with cnc_get_service (the full intent), cnc_get_service_plan(detail=true),
        cnc_get_vpn_underlay_transport, cnc_explain_sr_policy for an underlay policy,
        cnc_get_probe_status.

        VERDICT rules: CAT plan status completed -> ``deployed``; in-progress /
        delete-in-progress -> ``in-progress``; failed -> ``failed`` (error-info and the
        failed nano-plan component are quoted); no plan data -> ``unknown``. The reasons
        add the oper-status (op-up / op-down / op-unknown), the underlay (N SR policies,
        N RSVP-TE tunnels) and the monitoring state (a probe report, or "no active probe
        session" — on single-VM builds Service Health is not installed). Non-VPN services
        get the plan verdict only (a note says so). With ``name``: ``not-found`` when no
        service has exactly that name (the names starting with it are listed as the
        closest ones), ``ambiguous`` when services of different types share it (their
        yang-paths are listed — call again with one), ``unknown`` when the inventory
        could not be listed; nothing else is read in those cases.

        Sub-tools called: with name, cnc_list_services(name_prefix=<name>) first (exact
        service-name match, case-insensitive); then cnc_get_service(include_plan=true),
        cnc_get_service_plan(detail=true), and for ietf-l3vpn / ietf-l2vpn services
        cnc_get_vpn_service_health, cnc_get_vpn_underlay_transport, cnc_list_sub_services,
        cnc_get_probe_status.

        Args:
            yang_path / vpn_id / name: exactly one; vpn_id builds the L3/L2 VPN service
                path from layer; name is resolved through the CAT inventory.
            layer: with vpn_id only.
            response_format: markdown (default) or json.

        Returns:
            str: Markdown "# Service <path>" with the VERDICT block, the sections and
            the audit list; or JSON {"verdict", "sections", "calls"}. "Error: Pass exactly
            one of yang_path, vpn_id or name." / "Error: Unknown VPN layer ..." before
            any call.
        """
        try:
            selectors = [s for s in (yang_path.strip(), vpn_id.strip(), name.strip()) if s]
            if len(selectors) != 1:
                return "Error: Pass exactly one of yang_path, vpn_id or name."
            composer = Composer(mcp)
            verdict, sections = await explain_service(
                composer, yang_path.strip(), vpn_id.strip(), layer, name.strip()
            )
            label = yang_path.strip() or name.strip() or f"{layer} VPN {vpn_id.strip()}"
            return render(
                f"Service {label}", verdict, sections, composer, response_format, settings
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_provision_l3vpn_e2e",
        title="Provision an L3VPN End to End (dry run, commit, verify, trace)",
        read_only=False,
        destructive=True,  # the PUT it wraps replaces an existing service of that name
        idempotent=True,
        requires=WRITE_SIBLINGS["cnc_provision_l3vpn_e2e"],
    )
    async def cnc_provision_l3vpn_e2e(
        vpn_id: Annotated[
            str,
            Field(
                description="The L3NM vpn-id — service name and NSO list key (e.g. 'mcp-l3vpn-1').",
                min_length=1,
                max_length=128,
            ),
        ],
        route_distinguisher: Annotated[
            str,
            Field(
                description="The VRF's route distinguisher (e.g. '0:65091:91').",
                min_length=1,
                max_length=64,
            ),
        ],
        route_target: Annotated[
            str,
            Field(
                description="The route target, imported AND exported (e.g. '0:65091:91').",
                min_length=1,
                max_length=64,
            ),
        ],
        endpoints: Annotated[
            str,
            Field(
                description="JSON list of PE attachments exactly as cnc_create_l3vpn_service takes "
                'it: [{"node": "PE1", "interface": "Loopback91", "address": "10.91.1.1", '
                '"prefix_length": 30, "local_as": 65000}, ...] (local_as and id optional).',
                min_length=2,
                max_length=20000,
            ),
        ],
        topology: Annotated[
            str,
            Field(description="VPN service topology: any-to-any (default) | hub-spoke | custom."),
        ] = "any-to-any",
        profile_id: Annotated[
            str,
            Field(
                description="Name of the single vpn-instance-profile (default 'p1').",
                min_length=1,
                max_length=64,
            ),
        ] = "p1",
        trace: Annotated[
            bool,
            Field(
                description="true (default): after the plan completes, run an OAM trace route "
                "between the first two endpoint nodes."
            ),
        ] = True,
        wait_seconds: Annotated[
            int,
            Field(
                description="How long to wait for the service plan to complete, seconds "
                "(5-600, e.g. 120 — the bounds of cnc_wait_for_service_plan's "
                "timeout_seconds).",
                ge=5,
                le=600,
            ),
        ] = 120,
        dry_run: Annotated[
            bool,
            Field(
                description="true: stop after the NSO dry-run stage — report the device CLI "
                "NSO would push and a VERDICT of DRY-RUN; nothing is committed. false "
                "(default): commit and verify."
            ),
        ] = False,
        response_format: Annotated[ResponseFormat, Field(description=_FORMAT_DESC)] = (
            ResponseFormat.MARKDOWN
        ),
    ) -> str:
        """Provision an L3VPN end to end in one call: dry run (the device CLI NSO would
        push is included in the answer), commit, wait for the service plan, read the
        VPN's oper-status from the CAT inventory, and (trace=true) run an OAM trace route
        between the first two endpoint nodes — with a verdict listing every step's
        outcome. dry_run=true stops after the dry run: the CLI is reported, the verdict
        is ``dry-run`` and nothing is committed (the same preview as
        cnc_create_l3vpn_service(dry_run=true), in the playbook's shape).

        WRITE tool (registered only with CNC_MCP_ENABLE_WRITES=true and when
        cnc_create_l3vpn_service is registered; without cnc_start_oam_trace_route — OAM
        writes off — the trace step is skipped and the verdict says so); the
        commit changes the head-ends' configuration through NSO. Use it when the operator
        has confirmed the intent; use dry_run=true (or cnc_create_l3vpn_service with
        dry_run=true) to only preview. Stop rules: a failed dry run stops before anything
        is committed; a failed commit stops and reports (NSO rejected the service —
        nothing was deployed); a failed plan skips the trace. Nothing is ever deleted or
        rolled back — remove the service yourself with cnc_delete_vpn_service(vpn_id=...,
        layer='l3') when the answer says so. Head-ends need a BGP process (give local_as
        on the endpoints) and must be in sync with NSO (a 502 means run
        cnc_nso_device_action sync-from first).

        VERDICT: ``deployed`` (commit ok, plan completed, CAT inventory read, trace ok or
        not requested), ``deployed-unverified`` (committed but the plan did not complete
        in wait_seconds, the CAT read failed or the trace did not succeed — the reasons
        say which), ``failed`` (stopped at the dry run / commit / plan) or ``dry-run``
        (dry_run=true: the dry run succeeded and nothing was committed; the commit, plan,
        health and trace sections read "skipped — dry_run=true"). A trace the platform
        reports FAILED is the platform's verdict on the network (gNMI / 'mpls oam' on the
        devices), not an API error.

        Sub-tools called, in order: cnc_create_l3vpn_service(dry_run=true), then — unless
        dry_run=true — the same with dry_run=false, cnc_wait_for_service_plan(
        target='completed'), cnc_get_vpn_service_health(layer='l3'), then for the trace
        cnc_get_device(host_name=<node>) for the first two endpoint nodes,
        cnc_start_oam_trace_route and cnc_wait_for_oam_trace_route(timeout_seconds=90).

        Args:
            vpn_id, route_distinguisher, route_target, endpoints, topology, profile_id:
                exactly what cnc_create_l3vpn_service takes.
            trace: run the OAM trace route after the plan completes.
            wait_seconds: plan wait budget.
            dry_run: stop after the dry run with a DRY-RUN verdict; nothing is committed.
            response_format: markdown (default) or json.

        Returns:
            str: Markdown "# L3VPN provisioning: <vpn_id>" with the VERDICT block (the
            reasons are the step outcomes), the dry-run CLI, the commit, plan, health and
            trace sections and the audit list; or JSON {"verdict", "sections", "calls"}.
            "Error: ..." only for a failure of the composite itself, never for a step.
        """
        try:
            composer = Composer(mcp)
            verdict, sections = await provision_l3vpn_e2e(
                composer,
                vpn_id=vpn_id.strip(),
                route_distinguisher=route_distinguisher.strip(),
                route_target=route_target.strip(),
                endpoints=endpoints,
                topology=topology,
                profile_id=profile_id,
                trace=trace,
                wait_seconds=wait_seconds,
                dry_run=dry_run,
                global_dry_run=settings.dry_run,
            )
            return render(
                f"L3VPN provisioning: {vpn_id.strip()}",
                verdict,
                sections,
                composer,
                response_format,
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_sr_policy_e2e",
        title="Create an SR Policy End to End (dry run, create, wait, route)",
        read_only=False,
        destructive=False,
        idempotent=False,
        requires=WRITE_SIBLINGS["cnc_create_sr_policy_e2e"],
    )
    async def cnc_create_sr_policy_e2e(
        headend: Annotated[
            str,
            Field(
                description="Head-end: a topology node id (host name, e.g. 'PE1') or its TE "
                "router-id (e.g. '10.0.0.1').",
                min_length=1,
                max_length=253,
            ),
        ],
        endpoint: Annotated[
            str,
            Field(
                description="Endpoint (tail-end): a topology node id (e.g. 'PE2') or its TE "
                "router-id (e.g. '10.0.0.3').",
                min_length=1,
                max_length=253,
            ),
        ],
        color: Annotated[
            int,
            Field(
                description="The policy color, unique per (headend, endpoint) (e.g. 200).",
                ge=1,
                le=4294967295,
            ),
        ],
        path_name: Annotated[
            str,
            Field(
                description="The candidate-path name the head-end shows for the policy "
                "(e.g. 'mcp-dyn-200'; at most 64 characters, as cnc_create_sr_policy takes it).",
                min_length=1,
                max_length=64,
            ),
        ],
        description: Annotated[
            str | None,
            Field(description="Free-text description stored with the policy.", max_length=255),
        ] = None,
        path_type: Annotated[
            str,
            Field(
                description="'dynamic' (the PCE computes the path, default), 'explicit' (the "
                "hops you give) or 'bandwidth' (needs bandwidth_mbps).",
                max_length=20,
            ),
        ] = "dynamic",
        objective: Annotated[
            str,
            Field(
                description="Metric the PCE minimises for a dynamic / bandwidth path: "
                "'igp-metric' (default), 'te-metric', 'delay' or 'hop-count'.",
                max_length=20,
            ),
        ] = "igp-metric",
        hops: Annotated[
            str,
            Field(
                description="Comma-separated explicit hops in path order for "
                "path_type='explicit' (e.g. 'P2,PE2'); blank otherwise.",
                max_length=2000,
            ),
        ] = "",
        protected: Annotated[
            bool,
            Field(description="Dynamic path only: prefer protected adjacency SIDs (default true)."),
        ] = True,
        sid_algorithm: Annotated[
            int | None,
            Field(
                description="Dynamic/bandwidth path only: the Flex-Algo to compute with "
                "(e.g. 128); omit for SPF.",
                ge=0,
                le=255,
            ),
        ] = None,
        bandwidth_mbps: Annotated[
            int | None,
            Field(
                description="Bandwidth path only: Mbps to reserve (e.g. 100).", ge=1, le=2147483647
            ),
        ] = None,
        binding_sid: Annotated[
            int | None,
            Field(
                description="Binding SID to request from the head-end's SRLB (e.g. 15001); "
                "omit to let the head-end allocate one.",
                ge=16,
                le=1048575,
            ),
        ] = None,
        network: Annotated[str, Field(description=_NETWORK_DESC, min_length=1, max_length=200)] = (
            DEFAULT_NETWORK
        ),
        wait_seconds: Annotated[
            int,
            Field(
                description="How long to wait for the policy to come UP, seconds (5-600, "
                "e.g. 60 — the bounds of cnc_wait_for_sr_policy_oper_state's timeout_seconds).",
                ge=5,
                le=600,
            ),
        ] = 60,
        dry_run: Annotated[
            bool,
            Field(
                description="true: stop after the Optimization Engine dry run — report the "
                "route the PCE would compute and a VERDICT of DRY-RUN; nothing is created. "
                "false (default): create and wait for UP."
            ),
        ] = False,
        response_format: Annotated[ResponseFormat, Field(description=_FORMAT_DESC)] = (
            ResponseFormat.MARKDOWN
        ),
    ) -> str:
        """Create a PCE-initiated SR policy end to end in one call: dry run (the route the
        PCE would compute is included), create, wait for oper-state UP, then read the
        computed route — with a verdict listing every step's outcome. dry_run=true stops
        after the dry run: the computed route is reported, the verdict is ``dry-run`` and
        nothing is created.

        WRITE tool (registered only with CNC_MCP_ENABLE_WRITES=true and when
        cnc_create_sr_policy is registered); the create programs the head-end over PCEP
        within seconds. Use it when the operator has confirmed the intent; dry_run=true
        (or cnc_dryrun_sr_policy alone) only previews. Stop rules: a failed dry run stops
        before anything is created; a failed create stops and reports. Nothing is deleted
        afterwards — remove the policy with cnc_delete_sr_policy(headend=..., endpoint=...,
        color=...) when the answer says so (a PCE-initiated policy can be removed through
        the PCE; a PCC-initiated one cannot).

        VERDICT: ``created-up`` (created and UP within wait_seconds), ``created-not-up``
        (created; the wait timed out — the current state is quoted), ``failed`` (stopped
        at the dry run or the create) or ``dry-run`` (dry_run=true: the dry run succeeded
        and nothing was created; the create, oper-state and route sections read "skipped
        — dry_run=true"). A degraded dry run (constraints relaxed) is a note and the
        create proceeds.

        Sub-tools called, in order: cnc_dryrun_sr_policy, then — unless dry_run=true —
        cnc_create_sr_policy, cnc_wait_for_sr_policy_oper_state(target='UP'),
        cnc_get_sr_policy_routes. The parameters are the common ones of
        cnc_create_sr_policy (disjointness / association groups are not exposed here —
        use cnc_create_sr_policy directly).

        Args:
            headend, endpoint, color, path_name, description, path_type, objective, hops,
                protected, sid_algorithm, bandwidth_mbps, binding_sid, network: as
                cnc_create_sr_policy takes them.
            wait_seconds: oper-state wait budget.
            dry_run: stop after the dry run with a DRY-RUN verdict; nothing is created.
            response_format: markdown (default) or json.

        Returns:
            str: Markdown "# SR policy creation: <headend> -> <endpoint> color <c>" with
            the VERDICT block (the reasons are the step outcomes), the dry-run, create,
            oper-state and route sections and the audit list; or JSON {"verdict",
            "sections", "calls"}. "Error: ..." only for a failure of the composite itself.
        """
        try:
            composer = Composer(mcp)
            verdict, sections = await create_sr_policy_e2e(
                composer,
                headend=headend.strip(),
                endpoint=endpoint.strip(),
                color=color,
                path_name=path_name.strip(),
                description=description,
                path_type=path_type,
                objective=objective,
                hops=hops,
                protected=protected,
                sid_algorithm=sid_algorithm,
                bandwidth_mbps=bandwidth_mbps,
                binding_sid=binding_sid,
                network=network.strip(),
                wait_seconds=wait_seconds,
                dry_run=dry_run,
                global_dry_run=settings.dry_run,
            )
            return render(
                f"SR policy creation: {headend.strip()} -> {endpoint.strip()} color {color}",
                verdict,
                sections,
                composer,
                response_format,
                settings,
            )
        except Exception as e:
            return format_error(e)
