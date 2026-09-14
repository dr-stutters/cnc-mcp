"""NSO integration tools — Cisco Network Services Orchestrator inside Crosswork.

NSO is *embedded* in a Crosswork Network Controller deployment: it runs
in-cluster (``enso.default.svc.cluster.local``) and is registered as the
provider ``nso`` (family ``ROBOT_PROVIDER_NSO``, see cnc_list_providers). The
Device Lifecycle Manager (DLM — the inventory service) auto-associates every
inventory device with that provider according to the DLM->NSO sync policy
(``cnc_get_nso_policy``): with the default ``match/onboardTo/syncFrom/
checkSync`` rules of ``*`` a device added to Crosswork is created in NSO,
connected, its SSH keys fetched and its running configuration read into NSO's
CDB. Where the device stands in that pipeline is its ``nso_state`` on the
Crosswork device record (``cnc_get_device`` / ``cnc_check_device_nso_state``),
with the last NSO message in ``NsoMsg`` and the time of the last change in
``nso_timestamp``.

Two routes reach NSO from this server (both verified live 2026-09-13):

1. **DLM NSO actions** — ``POST /crosswork/inventory/v1/nso/<action>`` with a
   node-query body ``{"filter": {"host_name": ...}}`` (or ``uuid``). These are
   what Crosswork's own UI runs ("Connect", "Sync From", ...). They answer a
   job envelope with ``state: JOB_ACCEPTED`` immediately and are
   **asynchronous**: the device's ``nso_state`` walks ``*_STARTED`` and settles
   (``SYNCED``, ``CONNECT_FAILED``, ...) a few seconds later, and
   ``nso_timestamp`` moves with it. **These are the calls that update
   Crosswork's ``nso_state``** — what ``cnc_check_device_nso_state`` shows is
   therefore the DLM's CACHED verdict from the last action, dated by
   ``nso_timestamp``, never a live check. ``check-sync`` changes no
   configuration (it only compares CDB and device), so it is exposed as the
   read-only ``cnc_check_nso_device_sync`` besides the write-gated
   ``cnc_nso_device_action``; it still creates a job record and refreshes
   ``nso_state`` / ``nso_timestamp``. Use ``cnc_wait_for_device_nso_state``
   after an action, passing the ``nso_timestamp_before`` the action tool
   returned as ``after_timestamp``: the DLM only moves ``nso_state`` off its pre-action
   value a few seconds after ``JOB_ACCEPTED``, so the first poll otherwise
   reads the stale pre-action state (a device already ``SYNCED`` would be
   reported "reached SYNCED after 0s" although nothing ran yet, and a retried
   connect on a ``CONNECT_FAILED`` device would fail at once with the OLD
   message). ``POST .../nso/sync`` ("Sync With NSO", the DLM<->NSO inventory
   association, ``cnc_sync_inventory_with_nso``) is different in two ways:
   it is synchronous (``JOB_COMPLETED``), and per the 7.2 API document
   (operation ``Nso_DLMNSOSync``: "Input should be empty body, e.g. {} ...
   RobotNodeGetReq is just to satisfy API") its request body is ignored —
   it is a **global** re-association of the whole inventory, not a
   per-device action.
2. **The NSO RESTCONF proxy** — ``/crosswork/proxy/nso/restconf`` shows NSO's
   *own* view: the ``tailf-ncs:device`` entries with their NED, authgroup and
   NSO oper-state (``cnc_list_nso_devices`` / ``cnc_get_nso_device``), and
   each device's ``config`` container — NSO's CDB copy of the device's
   running configuration in NED YANG (``cnc_get_nso_device_config``, verified
   live 2026-09-14). That copy is current as of the last sync-from, not a
   live read; ``cnc_check_nso_device_sync`` says whether it still matches the
   device. The XR CLI NED models the config under the module
   ``tailf-ned-cisco-ios-xr`` (``tailf-ned-cisco-ios-xr:router``,
   ``:interface``, ``:segment-routing``, ...); the prefix is required on the
   first path segment — ``cisco-ios-xr:router`` answers 404 "uri keypath not
   found" — so the tool adds it to a bare segment. A proxy read never
   changes ``nso_state``.

SAFETY RULE for the per-device action tools (verified live): the DLM actions
do NOT validate their filter. A filter that matches no device (or an unknown
uuid) still answers ``JOB_ACCEPTED``, and devices other than the target had
their ``nso_timestamp`` refreshed inside that window — an empty or no-match
filter must be treated as potentially acting on every device. Every
per-device action tool here therefore resolves its selector with ``POST
nodes/query`` first, refuses when nothing matches, sends exactly the filter it
resolved, and reports the matched devices back so the agent sees what was
acted on. An empty filter is never sent to a per-device action. (The global
``nso/sync`` sends the documented empty body ``{}`` — there the whole
inventory is the scope by design, and the tool says so.)

``nso_state`` values (``NsoDeviceOperState``), grouped by phase:

- association (DLM<->NSO inventory): ``ASSOCIATED``, ``NOT_ASSOCIATED``,
  ``MATCH``, ``NO_MATCH``, ``ONBOARD_FAIL``;
- SSH host keys: ``FETCH_SSH_KEYS_SCHEDULED`` -> ``FETCH_SSH_KEYS_STARTED`` ->
  (``FETCH_SSH_KEYS_FAILED``);
- connect: ``CONNECT_SCHEDULED`` -> ``CONNECT_STARTED`` -> (``CONNECT_FAILED``);
- sync-from / sync-to: ``SYNC_FROM_SCHEDULED`` -> ``SYNC_FROM_STARTED`` /
  ``SYNC_TO_SCHEDULED`` -> ``SYNC_TO_STARTED`` -> ``SYNCED`` | ``SYNC_FAILED``;
- check-sync: ``CHECK_SYNC_SCHEDULED`` -> ``CHECK_SYNC_STARTED`` -> ``SYNCED``
  (in sync) | ``NOT_SYNCED`` (out of sync — not an error of the check);
- compare-config: ``COMPARE_CONFIG_SCHEDULED`` -> ``COMPARE_CONFIG_STARTED``;
- ``INVALID_NSO_OPER_STATE`` — the proto default, never set deliberately.

The enum has no CONNECTED / KEYS_FETCHED / COMPARED value: only the failure
outcome of connect, fetch-ssh-keys and compare-config is a state of its own,
and a successful one settles into a non-failure state (``SYNCED`` was
observed after the automatic sync-from; what a lone successful connect
settles to was not captured live). Observed on the lab: a CNC-driven
``connect`` can end ``CONNECT_FAILED`` (XRd SSH answers "connection refused"
to NSO's NEDCOM now and then) while the following ``sync-from`` succeeds and
settles ``SYNCED`` — retry, or go straight to the next step, rather than
diagnose.

NOT in scope of this module: ``PUT .../nso/policy`` (policy writes),
``POST /crosswork/inventory/v1/onboarding`` (answers 500 NATS for every body
on this build), ``POST /crosswork/aaa/v1/syncDAGsToNSO`` (not served on this
build), and raw NSO RESTCONF writes / service provisioning through the proxy
(a later ``services`` module) — config READS through the proxy are
``cnc_get_nso_device_config``.
"""

from __future__ import annotations

from typing import Annotated, Any
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import AAA, INVENTORY, check_job, query_body, unwrap
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, epoch_iso, finalize, to_json
from cnc_mcp.polling import wait_until
from cnc_mcp.restconf import (
    NSO_MODULE,
    NSO_PROXY,
    YANG_ACCEPT,
    is_not_found,
    parse_restconf_errors,
    select_key,
    unwrap_list,
)
from cnc_mcp.safety import AppContext, register_tool

NODES_QUERY_URL = f"{INVENTORY}/nodes/query"
NSO_BASE = f"{INVENTORY}/nso"
NSO_POLICY_QUERY_URL = f"{NSO_BASE}/policy/query"
NSO_SYNC_URL = f"{NSO_BASE}/sync"
NSO_SYNC_TO_URL = f"{NSO_BASE}/sync-to"
NSO_CHECK_SYNC_URL = f"{NSO_BASE}/check-sync"
IS_NSO_CONFIGURED_URL = f"{AAA}/isNSOConfigured"
# The proxy's device list (verified). The ``fields`` selector is sent verbatim in the
# path — ``;`` unencoded, as the verified live request had it — rather than through
# httpx ``params`` (which would percent-encode it to ``%3B``). The keyed GET carries
# the same selector: without it NSO returns the device's entire ``config`` subtree
# (its whole running configuration in NED YANG — megabytes on a production router),
# which the tool would only discard or truncate.
NSO_DEVICES_URL = f"{NSO_PROXY}/data/{NSO_MODULE}:devices/device"
NSO_DEVICE_FIELDS = "name;address;port;authgroup;device-type;state"
NSO_DEVICES_LIST_URL = f"{NSO_DEVICES_URL}?fields={NSO_DEVICE_FIELDS}"


def nso_device_url(name: str) -> str:
    """The keyed proxy GET for one ``tailf-ncs:device`` entry, limited to NSO_DEVICE_FIELDS."""
    return f"{NSO_DEVICES_URL}={quote(name, safe='')}?fields={NSO_DEVICE_FIELDS}"


# NSO's copy of a device's configuration (verified live 2026-09-14) is the ``config``
# container of its ``tailf-ncs:device`` entry, modelled in the NED's YANG. The XR CLI NED
# (ned-id cisco-iosxr-cli-7.70) uses the module ``tailf-ned-cisco-ios-xr``; RESTCONF wants
# that module prefix on the FIRST path segment of a subtree (children inherit it), and the
# proxy answers 404 "uri keypath not found" to a wrong one (``cisco-ios-xr:router``) — the
# same 404 a missing device gets. ``?depth=2`` on the bare ``config`` lists the top
# containers.
NSO_XR_NED_MODULE = "tailf-ned-cisco-ios-xr"
NSO_CONFIG_MAX_DEPTH = 64
_NSO_CONFIG_HINT = (
    "Narrow with 'subtree' (e.g. 'router' or 'segment-routing') or set 'depth' (2 lists the "
    "top-level containers)."
)


def normalize_config_subtree(subtree: str | None) -> str:
    """The config subtree path as the proxy wants it ('' for the whole ``config``).

    ``'router'`` -> ``'tailf-ned-cisco-ios-xr:router'`` (the XR NED module
    prefix is added when the first segment carries none); an explicit prefix
    (``'tailf-ned-cisco-ios-xr:router'``, or another NED's module for a
    non-XR device) is kept verbatim. Surrounding whitespace and slashes are
    dropped, as is a leading ``config/`` segment. Segments after the first
    are sent as given, so list keys must already be percent-encoded
    (``'interface/GigabitEthernet=0%2F0%2F0%2F0'``).

    Because the result is spliced verbatim into the request URL, a ``?`` would
    start a query string (bypassing the tool's own ``depth`` parameter), a
    ``#`` would silently cut the path at that point, and interior whitespace
    can only be a typo or an unencoded key — all three raise
    :class:`PlatformError` (the tool returns it as ``Error: ...``) instead of
    being sent.
    """
    text = (subtree or "").strip().strip("/")
    if text.startswith("config/"):
        text = text[len("config/") :].lstrip("/")
    if not text:
        return ""
    bad = next((ch for ch in text if ch in "?#" or ch.isspace()), None)
    if bad is not None:
        shown = "whitespace" if bad.isspace() else f"'{bad}'"
        raise PlatformError(
            f"subtree {text!r} contains {shown}, which is not a RESTCONF path character: "
            "'?' would start a query string, '#' cuts the path short and spaces are never "
            "valid unencoded. Give the subtree as a plain path ('router/isis') with list "
            "keys percent-encoded ('interface/GigabitEthernet=0%2F0%2F0%2F0', a space as "
            "'%20'); set the depth with the 'depth' parameter, not in the path."
        )
    first, sep, rest = text.partition("/")
    if ":" not in first:
        first = f"{NSO_XR_NED_MODULE}:{first}"
    return f"{first}{sep}{rest}"


def nso_config_url(name: str, subtree: str) -> str:
    """``.../device=<name>/config[/<subtree>]`` — the device name percent-encoded as one
    list key, the (already normalised) subtree verbatim so its module prefix and keys
    reach the proxy as written."""
    url = f"{NSO_DEVICES_URL}={quote(name, safe='')}/config"
    return f"{url}/{subtree}" if subtree else url


def _restconf_said(data: Any) -> str:
    """`` 'uri keypath not found' (error-tag invalid-value)`` — what a RESTCONF error
    document said, for splicing after a status code; '' when the body carries none.

    Only the first error entry is quoted (the proxy sends one). The message and
    the tag are each optional, so any combination renders without dangling
    punctuation.
    """
    errors = parse_restconf_errors(data)
    if not errors:
        return ""
    message, tag = errors[0]["message"], errors[0]["tag"]
    text = f" '{message}'" if message else ""
    if tag:
        text += f" (error-tag {tag})"
    return text


def config_top_keys(body: Any) -> list[str]:
    """The top-level keys of a config GET body, for the headline.

    The bare ``config`` GET wraps its children in ``{"tailf-ncs:config": {...}}``
    — those children (the device's top-level containers) are listed; a
    subtree GET answers the subtree's own key (``{"tailf-ned-cisco-ios-xr:
    router": {...}}``), which is listed as is. A non-dict body lists nothing.
    """
    content = body
    if isinstance(content, dict) and len(content) == 1:
        (key, value), *_ = content.items()
        if key == f"{NSO_MODULE}:config" and isinstance(value, dict):
            content = value
    return sorted(str(k) for k in content) if isinstance(content, dict) else []


# Per-device DLM actions (URL segment == friendly name; underscores accepted on input).
# sync-to is deliberately NOT in this table: it pushes CDB config to the device and has
# its own destructive tool (cnc_nso_sync_to_device).
DEVICE_ACTIONS = ("connect", "fetch-ssh-keys", "sync-from", "check-sync", "compare-config")
_ACTION_CHOICES = ", ".join(DEVICE_ACTIONS)

# How many matched devices a selector may resolve to in one call (the DLM acts on every
# match regardless; this caps what is fetched and reported back).
SELECTOR_PAGE_SIZE = 100

# NsoDeviceOperState (documented enum, verified live for the transitions in the module
# docstring), grouped by phase.
NSO_ASSOCIATION_STATES = ("ASSOCIATED", "NOT_ASSOCIATED", "MATCH", "NO_MATCH", "ONBOARD_FAIL")
NSO_IN_PROGRESS_STATES = (
    "FETCH_SSH_KEYS_SCHEDULED",
    "FETCH_SSH_KEYS_STARTED",
    "CONNECT_SCHEDULED",
    "CONNECT_STARTED",
    "SYNC_FROM_SCHEDULED",
    "SYNC_FROM_STARTED",
    "SYNC_TO_SCHEDULED",
    "SYNC_TO_STARTED",
    "CHECK_SYNC_SCHEDULED",
    "CHECK_SYNC_STARTED",
    "COMPARE_CONFIG_SCHEDULED",
    "COMPARE_CONFIG_STARTED",
)
NSO_SETTLED_STATES = (
    "FETCH_SSH_KEYS_FAILED",
    "CONNECT_FAILED",
    "SYNCED",
    "SYNC_FAILED",
    "NOT_SYNCED",
)
NSO_STATES = (
    ("INVALID_NSO_OPER_STATE",)
    + NSO_ASSOCIATION_STATES
    + NSO_IN_PROGRESS_STATES
    + NSO_SETTLED_STATES
)
# Terminal outcomes that end a wait as an API-level failure (not a timeout).
NSO_FAILURE_STATES = frozenset(
    {
        "CONNECT_FAILED",
        "FETCH_SSH_KEYS_FAILED",
        "SYNC_FAILED",
        "ONBOARD_FAIL",
        "NO_MATCH",
        "NOT_SYNCED",
    }
)
DEFAULT_WAIT_TARGET = "SYNCED"
# What a check-sync settles to: SYNCED (in sync) or NOT_SYNCED (out of sync), or one of the
# failure states when NSO could not run the check at all.
CHECK_SYNC_VERDICTS = {"SYNCED": "in-sync", "NOT_SYNCED": "out-of-sync"}
CHECK_SYNC_SETTLED = frozenset(CHECK_SYNC_VERDICTS) | NSO_FAILURE_STATES
DEFAULT_CHECK_SYNC_WAIT = 60
# What run_action() adds to (or check_job() derives from) the platform's job envelope;
# cnc_check_nso_device_sync keeps only the platform's own job record under its "job" key.
_NOT_JOB_KEYS = frozenset(
    {"pending", "impacted_objects", "filter", "matched_devices", "matched_total", "note", "next"}
)

NSO_PROVIDER_FAMILY = "ROBOT_PROVIDER_NSO"
# NSO's device-type choice: exactly one of these containers holds the ned-id.
_NED_KINDS = ("cli", "netconf", "generic", "snmp")

_SELECTOR_HELP = (
    "Filters are exact-match, case-insensitive, '*' wildcard; list devices with cnc_list_devices."
)


def normalize_action(action: str) -> str:
    """'sync_from' / ' Sync-From ' -> 'sync-from'; PlatformError when not in DEVICE_ACTIONS."""
    key = action.strip().lower().replace("_", "-")
    if key not in DEVICE_ACTIONS:
        raise PlatformError(
            f"Unknown NSO device action '{action}'. Use one of: {_ACTION_CHOICES} "
            "(sync-to has its own tool, cnc_nso_sync_to_device)."
        )
    return key


def parse_targets(target: str) -> set[str]:
    """'synced, match' -> {'SYNCED', 'MATCH'}; PlatformError when empty or not an nso_state."""
    states = {part.strip().upper() for part in target.split(",") if part.strip()}
    if not states:
        raise PlatformError(
            f"target is empty: give one or more nso_state values separated by commas "
            f"(e.g. '{DEFAULT_WAIT_TARGET}' or 'SYNCED,MATCH')."
        )
    unknown = sorted(states - set(NSO_STATES))
    if unknown:
        raise PlatformError(
            f"Unknown nso_state value(s) {', '.join(unknown)}. Valid values: "
            f"{', '.join(NSO_STATES)}."
        )
    return states


def parse_after_timestamp(value: str | int | None) -> int | None:
    """``after_timestamp`` -> epoch int (None when not given); PlatformError when not numeric.

    The value is the ``nso_timestamp`` / ``nso_timestamp_before`` Crosswork
    returned (epoch, sent as a numeric string on this platform), never an
    ISO date — it is compared numerically with the polled ``nso_timestamp``.
    """
    if value is None:
        return None
    text = str(value).strip()
    if text == "":
        return None
    if not text.isdigit() or len(text) > 20:
        raise PlatformError(
            f"after_timestamp must be the epoch value Crosswork returned as nso_timestamp / "
            f"nso_timestamp_before (e.g. '1757772000'), got '{text}'."
        )
    return int(text)


def is_stale(node: dict[str, Any], after: int | None) -> bool:
    """True when the node's ``nso_timestamp`` is at or before ``after`` (a pre-action reading).

    Used by the wait tool to skip observations the DLM has not touched since the
    action was accepted. A node without a numeric ``nso_timestamp`` cannot be
    judged and is never considered stale.
    """
    if after is None:
        return False
    text = str(node.get("nso_timestamp") or "").strip()
    if not text.isdigit():
        return False
    return int(text) <= after


def sync_verdict(node: dict[str, Any], after: int | None) -> str:
    """One device's check-sync verdict from its (DLM-cached) nso_state.

    ``pending`` while the reading is still the pre-action one (``nso_timestamp``
    at or before ``after``) or the state is a ``*_SCHEDULED`` / ``*_STARTED``
    one; ``in-sync`` / ``out-of-sync`` for SYNCED / NOT_SYNCED; ``failed``
    for a failure state (NSO could not run the check — NsoMsg says why).
    """
    if is_stale(node, after):
        return "pending"
    state = node.get("nso_state")
    if state in CHECK_SYNC_VERDICTS:
        return CHECK_SYNC_VERDICTS[state]
    if state in NSO_FAILURE_STATES:
        return "failed"
    return "pending"


def _selector(uuid: str | None, host_name: str | None) -> dict[str, str]:
    """Exactly one of uuid / host_name (non-blank) -> the nodes/query filter for it.

    The result is never empty: that is what keeps the SAFETY RULE in the module
    docstring — never send the DLM an empty filter — enforceable at one place.
    """
    uuid_value = (uuid or "").strip()
    host_value = (host_name or "").strip()
    if bool(uuid_value) == bool(host_value):
        raise PlatformError("Pass exactly one of 'uuid' or 'host_name' to select the device(s).")
    return {"uuid": uuid_value} if uuid_value else {"host_name": host_value}


def describe_selector(selector: dict[str, str]) -> str:
    key, value = next(iter(selector.items()))
    return f"{key} '{value}'"


def ned_id_of(device: dict[str, Any]) -> str | None:
    """The NED id of a ``tailf-ncs:device`` entry, whichever device-type container holds it."""
    device_type = device.get("device-type")
    if not isinstance(device_type, dict):
        return None
    for kind in _NED_KINDS:
        entry = device_type.get(kind)
        if isinstance(entry, dict) and entry.get("ned-id"):
            return str(entry["ned-id"])
    return None


def nso_device_line(device: dict[str, Any]) -> str:
    """One markdown line for a ``tailf-ncs:device`` entry (NSO's own view)."""
    state = device.get("state") if isinstance(device.get("state"), dict) else {}
    oper = state.get("oper-state") or "?"
    error_tag = state.get("oper-state-error-tag")
    oper_text = f"{oper} ({error_tag})" if error_tag else str(oper)
    port = device.get("port")
    address = (
        f"{device.get('address') or '?'}:{port}"
        if port not in (None, "")
        else str(device.get("address") or "?")
    )
    return (
        f"- **{device.get('name', '?')}** {address} authgroup={device.get('authgroup') or '-'} "
        f"ned={ned_id_of(device) or '-'} oper={oper_text} admin={state.get('admin-state') or '?'}"
    )


_NSO_VIEW_NOTE = (
    "This is NSO's own view of the devices (the NED that manages each one and NSO's "
    "oper-state: 'enabled' = NSO can talk to it, 'disabled' = it cannot, with the reason "
    "in parentheses). It is distinct from Crosswork's nso_state on the device record — "
    "see cnc_check_device_nso_state for that."
)


def _nso_devices_markdown(devices: list[dict[str, Any]]) -> str:
    lines = [f"# NSO devices ({len(devices)})", ""]
    if not devices:
        lines.append("NSO holds no devices.")
    lines.extend(nso_device_line(d) for d in devices)
    lines.extend(["", _NSO_VIEW_NOTE])
    return "\n".join(lines)


def _nso_device_markdown(device: dict[str, Any]) -> str:
    state = device.get("state") if isinstance(device.get("state"), dict) else {}
    lines = [
        f"# NSO device {device.get('name', '?')}",
        "",
        nso_device_line(device),
        "",
        "State block as NSO reports it:",
        to_json(state),
        "",
        _NSO_VIEW_NOTE,
    ]
    return "\n".join(lines)


def nso_summary(node: dict[str, Any]) -> dict[str, Any]:
    """Crosswork's NSO view of one inventory node (the fields the wait/check tools report)."""
    families = node.get("providers_family")
    family_keys = sorted(families) if isinstance(families, dict) else []
    nso_providers: dict[str, Any] = {}
    if isinstance(families, dict) and isinstance(families.get(NSO_PROVIDER_FAMILY), dict):
        providers = families[NSO_PROVIDER_FAMILY].get("providers")
        if isinstance(providers, dict):
            for name, entry in providers.items():
                node_id = entry.get("provider_node_id") if isinstance(entry, dict) else None
                nso_providers[str(name)] = node_id
    errors = node.get("errors")
    summary: dict[str, Any] = {
        "host_name": node.get("host_name"),
        "uuid": node.get("uuid"),
        "nso_state": node.get("nso_state"),
        "nso_timestamp": node.get("nso_timestamp"),
        "nso_timestamp_iso": epoch_iso(node.get("nso_timestamp")),
        "NsoMsg": node.get("NsoMsg"),
        "errors": [str(e) for e in errors] if isinstance(errors, list) else [],
        "providers_family": family_keys,
        "nso_providers": nso_providers,
    }
    if node.get("ned_id"):
        summary["ned_id"] = node["ned_id"]
    return summary


def _nso_summary_lines(summary: dict[str, Any]) -> list[str]:
    providers = ",".join(summary["providers_family"]) or "-"
    node_ids = ",".join(str(v) for v in summary["nso_providers"].values() if v) or "-"
    line = (
        f"- **{summary['host_name'] or '?'}** ({summary['uuid'] or '?'}) "
        f"nso_state={summary['nso_state'] or '?'} since {summary['nso_timestamp_iso']} "
        f"providers={providers} nso_node_id={node_ids}"
    )
    if summary.get("ned_id"):
        line += f" ned={summary['ned_id']}"
    lines = [line]
    if summary["NsoMsg"]:
        lines.append(f"  message: {summary['NsoMsg']}")
    if summary["errors"]:
        lines.append(f"  errors: {'; '.join(summary['errors'])}")
    return lines


def _policy_markdown(policy: dict[str, Any]) -> str:
    lines = [
        f"# DLM -> NSO sync policy '{policy.get('name', '?')}'",
        "",
        f"- providers_criteria: {policy.get('providers_criteria', '?')}",
        f"- lsa: {policy.get('lsa', '?')}",
    ]
    lsa_policy = policy.get("policy") if isinstance(policy.get("policy"), dict) else {}
    if lsa_policy:
        lines.append(
            f"- policy: auto_onboard_rfs={lsa_policy.get('auto_onboard_rfs', '?')} "
            f"rfs_spread_method={lsa_policy.get('rfs_spread_method', '?')} "
            f"rfs_spread_value={lsa_policy.get('rfs_spread_value', '?')}"
        )
    lines.extend(["", "Per-provider rules:"])
    provider_policy = policy.get("provider_policy")
    if not isinstance(provider_policy, dict) or not provider_policy:
        lines.append("- (none)")
    else:
        for provider, rules in provider_policy.items():
            lines.append(f"- {provider}: {_rules_text(rules)}")
    return "\n".join(lines)


def _rules_text(rules: Any) -> str:
    if not isinstance(rules, dict):
        return str(rules)
    parts: list[str] = []
    for flag in ("match", "onboardTo", "onboardFrom", "syncFrom", "checkSync"):
        rule_key = f"{flag}Rule"
        if flag not in rules and rule_key not in rules:
            continue
        text = f"{flag}={rules.get(flag, '?')}"
        if rule_key in rules:
            text += f" (rule '{rules[rule_key]}')"
        parts.append(text)
    neds = rules.get("neds")
    if isinstance(neds, list) and neds:
        parts.append(
            "neds="
            + ", ".join(
                f"{n.get('ned', '?')}:'{n.get('rule', '')}'" if isinstance(n, dict) else str(n)
                for n in neds
            )
        )
    return " ".join(parts) or "(no rules)"


def _matched_devices(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What the action was sent for, with the pre-action state AND its timestamp.

    ``nso_timestamp_before`` is what the agent passes to
    cnc_wait_for_device_nso_state as ``after_timestamp`` so the wait ignores
    the stale pre-action reading (the DLM moves ``nso_state`` only a few
    seconds after ``JOB_ACCEPTED``).
    """
    return [
        {
            "host_name": n.get("host_name"),
            "uuid": n.get("uuid"),
            "nso_state_before": n.get("nso_state"),
            "nso_timestamp_before": n.get("nso_timestamp"),
        }
        for n in nodes
    ]


def _wait_hint(nodes: list[dict[str, Any]]) -> str:
    names = [str(n.get("host_name")) for n in nodes if n.get("host_name")]
    if len(nodes) == 1:
        node = nodes[0]
        args = f"host_name='{node.get('host_name')}'"
        stamp = node.get("nso_timestamp")
        if stamp not in (None, ""):
            args += f", after_timestamp='{stamp}'"
        return (
            f"Asynchronous: poll with cnc_wait_for_device_nso_state ({args}) — after_timestamp "
            "makes it ignore the stale pre-action nso_state."
        )
    listing = ", ".join(names[:10]) + (", ..." if len(names) > 10 else "")
    return (
        "Asynchronous: poll with cnc_wait_for_device_nso_state, one call per device, passing "
        f"that device's nso_timestamp_before as after_timestamp (host_name={listing})."
    )


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def resolve_devices(selector: dict[str, str]) -> tuple[list[dict[str, Any]], int]:
        """Every device the selector matches (up to SELECTOR_PAGE_SIZE) plus the match total.

        Raises PlatformError when nothing matches — the SAFETY RULE: a DLM NSO
        action must never be sent a filter that resolves to zero devices.
        """
        if not selector:
            raise PlatformError("Refusing to send an empty device filter to the NSO action.")
        data = await client.request_json(
            "POST",
            NODES_QUERY_URL,
            json_body=query_body(selector, page_size=SELECTOR_PAGE_SIZE, page=0),
            retryable=True,  # a read: safe to re-send on 5xx / transport errors
        )
        items, result_count, _ = unwrap(data, "data")
        nodes = [n for n in items if isinstance(n, dict)]
        if not nodes:
            raise PlatformError(
                f"no device matches {describe_selector(selector)}; nothing was sent to NSO. "
                f"{_SELECTOR_HELP}"
            )
        return nodes, result_count if result_count is not None else len(nodes)

    async def find_one_device(selector: dict[str, str]) -> dict[str, Any]:
        """Exactly one device for the selector; PlatformError when none or several match."""
        nodes, total = await resolve_devices(selector)
        if len(nodes) > 1 or total > 1:
            names = ", ".join(str(n.get("host_name")) for n in nodes[:5])
            raise PlatformError(
                f"{describe_selector(selector)} matched {total} devices ({names}, ...); "
                "this tool takes exactly one. Narrow the host_name or use the uuid."
            )
        return nodes[0]

    async def run_action(
        url: str, what: str, selector: dict[str, str], nodes: list[dict[str, Any]], total: int
    ) -> dict[str, Any]:
        """POST the resolved filter to a DLM NSO action URL and shape the answer."""
        result = await client.request_json("POST", url, json_body={"filter": selector})
        envelope = check_job(result, what)
        payload: dict[str, Any] = {
            **envelope,
            "filter": selector,
            "matched_devices": _matched_devices(nodes),
            "matched_total": total,
        }
        if total > len(nodes):
            payload["note"] = (
                f"The filter matches {total} devices; the DLM acts on all of them but only "
                f"the first {len(nodes)} are listed here."
            )
        if envelope.get("pending"):
            payload["next"] = _wait_hint(nodes)
        else:
            payload["next"] = (
                "Completed synchronously; confirm the devices' nso_state with "
                "cnc_check_device_nso_state."
            )
        return payload

    @register_tool(
        mcp,
        ctx,
        name="cnc_is_nso_configured",
        title="Is NSO Configured",
        read_only=True,
        idempotent=True,
    )
    async def cnc_is_nso_configured() -> str:
        """Report whether an NSO provider is configured on this Crosswork instance.

        Read-only. ``GET /crosswork/aaa/v1/isNSOConfigured`` answers
        ``{"nsoConfigured": true|false}``. NSO is embedded in Crosswork
        Network Controller, so on a CNC deployment this is normally true; it
        is the prerequisite for every other tool in this module, for the
        device-configuration ``nso_sync`` option and for service provisioning.
        When it is false, the DLM NSO actions have nothing to talk to — add an
        NSO provider (cnc_list_providers shows the ``nso`` one when present).

        Returns:
            str: "NSO is configured on this Crosswork instance." or "NSO is NOT
            configured on this Crosswork instance. ..." followed by the JSON
            body. On failure: "Error: ..." (403 -> the account lacks the RBAC
            task for this read).
        """
        try:
            data = await client.request_json("GET", IS_NSO_CONFIGURED_URL)
            configured = data.get("nsoConfigured") if isinstance(data, dict) else None
            body = to_json(data if data is not None else {})
            if configured is True:
                head = "NSO is configured on this Crosswork instance."
            elif configured is False:
                head = (
                    "NSO is NOT configured on this Crosswork instance: the DLM NSO actions "
                    "and the NSO proxy have no NSO to reach until an NSO provider is added."
                )
            else:
                head = "Crosswork did not report a boolean 'nsoConfigured'; the raw answer follows."
            return finalize(f"{head}\n{body}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_nso_policy",
        title="Get DLM to NSO Sync Policy",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_nso_policy(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the DLM -> NSO sync policy that governs automatic device association.

        Read-only. The policy says which providers it applies to
        (``providers_criteria``) and, per provider (``provider_policy.<name>``),
        whether Crosswork automatically matches inventory devices to NSO
        devices (``match``), onboards Crosswork devices into NSO
        (``onboardTo``) or NSO devices into Crosswork (``onboardFrom``), reads
        their config into NSO after onboarding (``syncFrom``) and runs
        check-sync (``checkSync``) — each with a ``*Rule`` host-name pattern
        (``*`` = every device). ``policy`` holds the LSA/RFS spread settings
        (``auto_onboard_rfs``, ``rfs_spread_method``
        ARBITRARY_USER_CONTROL|ROUND_ROBIN|RFS_CAPACITY, ``rfs_spread_value``)
        and ``lsa`` whether NSO runs in Layered Service Architecture. Use it to
        understand why a device did or did not get associated/synced with NSO
        on its own. Writing the policy (``PUT .../nso/policy``) is out of scope.

        Sends the verified empty ``{}`` body to ``POST
        /crosswork/inventory/v1/nso/policy/query`` (a read, auto-retried).

        Args:
            response_format: markdown (name, providers_criteria, lsa, the LSA
                policy line, then one line per provider with its flags and
                rules) or json (the policy object as Crosswork returns it).

        Returns:
            str: Markdown, or JSON:
            {"name": "default", "providers_criteria": "*",
             "provider_policy": {"nso": {"match": bool, "matchRule": "*",
                                         "onboardTo": bool, "onboardToRule": "*",
                                         "onboardFromRule": "*",
                                         "syncFrom": bool, "syncFromRule": "*",
                                         "checkSync": bool, "checkSyncRule": "*"}},
             "policy": {"auto_onboard_rfs": bool, "rfs_spread_method": str,
                        "rfs_spread_value": int},
             "lsa": bool}
            On failure: "Error: ..." (500 'NATS request failed' -> the body
            could not be parsed).
        """
        try:
            data = await client.request_json(
                "POST", NSO_POLICY_QUERY_URL, json_body={}, retryable=True
            )
            policy = data if isinstance(data, dict) else {}
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(policy), settings)
            return finalize(_policy_markdown(policy), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_nso_devices",
        title="List NSO Devices",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_nso_devices(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the devices NSO itself holds (NSO's view, through the RESTCONF proxy).

        Read-only. This is NSO's device table (``tailf-ncs:devices/device``):
        which NED manages each device (``device-type.cli.ned-id`` for CLI
        NEDs, ``netconf``/``generic`` otherwise), the ``authgroup`` (mirrors the
        Crosswork credential profile), the management ``address:port``, and
        NSO's own connection state (``state.oper-state`` ``enabled`` = NSO can
        reach it, ``disabled`` = it cannot, with ``oper-state-error-tag`` such
        as ``connection-refused`` saying why; ``state.admin-state`` is
        ``unlocked``/``locked``/``southbound-locked``). A device appears here
        once Crosswork has onboarded it into NSO (``nso_state`` past
        ``ASSOCIATED``). This view is **distinct from Crosswork's ``nso_state``**
        on the device record, which tracks the DLM's pipeline (connect /
        sync-from / check-sync outcomes) and only changes through the DLM
        actions — use cnc_check_device_nso_state for that.

        Sends ``GET /crosswork/proxy/nso/restconf/data/tailf-ncs:devices/device
        ?fields=name;address;port;authgroup;device-type;state`` with ``Accept:
        application/yang-data+json`` (the verified proxy dialect).

        Args:
            response_format: markdown (one line per device: name,
                address:port, authgroup, NED, oper-state with its error tag,
                admin-state) or json (the ``tailf-ncs:device`` entries).

        Returns:
            str: Markdown, or JSON {"count": int, "items": [{"name", "address",
            "port", "authgroup", "device-type": {"cli": {"ned-id"}} | {...},
            "state": {"oper-state": "enabled"|"disabled",
            "oper-state-error-tag", "admin-state", "transaction-mode",
            "last-transaction-id"}}]}. "NSO holds no devices." when the list is
            empty. On failure: "Error: ..." (415 malformed-message -> a body
            was sent without Content-Type application/yang-data+json; a bare
            404 -> the proxy prefix is not routed, i.e. NSO is not configured).
        """
        try:
            data = await client.request_json("GET", NSO_DEVICES_LIST_URL, headers=YANG_ACCEPT)
            devices = [d for d in unwrap_list(data, NSO_MODULE, "device") if isinstance(d, dict)]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(devices), "items": devices}), settings)
            return finalize(_nso_devices_markdown(devices), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_nso_device",
        title="Get NSO Device",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_nso_device(
        name: Annotated[
            str,
            Field(
                description=(
                    "NSO device name, exact and case-sensitive (e.g. 'PE1'). On a Crosswork-"
                    "onboarded device this is the Crosswork host_name (providers_family."
                    "ROBOT_PROVIDER_NSO.providers.<provider>.provider_node_id)."
                ),
                min_length=1,
                max_length=253,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one device as NSO holds it (the ``tailf-ncs:device`` entry's identity and
        state, via the proxy).

        Read-only. The device's NSO record without its configuration:
        address/port, authgroup, device-type/NED and ``state`` (oper-state and
        its error tag, admin-state, transaction-mode, last-transaction-id).
        Use it after a failed connect/sync to read NSO's own reason
        (``state.oper-state-error-tag``) alongside Crosswork's ``NsoMsg``
        (cnc_check_device_nso_state), or to learn which NED a device uses.
        NSO's view, not Crosswork's ``nso_state`` — see cnc_list_nso_devices.
        The device's ``config`` subtree (its whole running configuration in
        NED YANG, potentially megabytes) is deliberately NOT fetched — the
        same ``fields`` selector as cnc_list_nso_devices limits the GET to
        the fields above; read the configuration (whole, a subtree, or the
        top-level containers) with cnc_get_nso_device_config.

        Sends ``GET /crosswork/proxy/nso/restconf/data/tailf-ncs:devices/
        device=<name>?fields=name;address;port;authgroup;device-type;state``
        (the name percent-encoded as one list key, the selector verbatim as
        the verified list request has it) with ``Accept:
        application/yang-data+json``. A missing device answers ``404`` with an
        ``ietf-restconf:errors`` document (``invalid-value``, "uri keypath not
        found") — the one 404 on this gateway that means "not found" — and is
        reported as such; the returned entry is also matched on ``name``
        client-side in case the proxy ignores the key.

        Args:
            name: exact NSO device name (no wildcards; list with
                cnc_list_nso_devices).
            response_format: markdown (summary line plus the whole ``state``
                block) or json (the selected fields as NSO returns them).

        Returns:
            str: Markdown, or the JSON ``tailf-ncs:device`` entry ({"name",
            "address", "port", "authgroup", "device-type", "state": {...}}).
            "Error: NSO has no device named '<name>' ..." when NSO does not
            hold it (list with cnc_list_nso_devices); "Error: ..." on any
            other API failure (415 -> media type; bare 404 -> proxy not routed).
        """
        try:
            key = name.strip()
            response = await client.request(
                "GET",
                nso_device_url(key),
                headers=YANG_ACCEPT,
                raise_on_error=False,
            )
            data: Any = None
            if response.content:
                try:
                    data = response.json()
                except ValueError:
                    data = None
            missing = PlatformError(
                f"NSO has no device named '{key}'. Names are exact and case-sensitive; "
                "list NSO's devices with cnc_list_nso_devices (a device appears in NSO only "
                "once Crosswork has onboarded it — see nso_state in cnc_check_device_nso_state)."
            )
            if is_not_found(response.status_code, data):
                raise missing
            if not response.is_success:
                raise http_error(response)
            if response.content and data is None:
                raise PlatformError(
                    "The NSO proxy returned a non-JSON response where JSON was expected."
                )
            items = select_key(unwrap_list(data, NSO_MODULE, "device"), "name", key)
            if not items:
                raise missing
            device = items[0]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(device), settings)
            return finalize(_nso_device_markdown(device), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_nso_device_config",
        title="Get NSO Device Config (CDB copy)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_nso_device_config(
        host_name: Annotated[
            str,
            Field(
                description=(
                    "NSO device name, exact and case-sensitive (e.g. 'PE1') — the Crosswork "
                    "host_name for a Crosswork-onboarded device."
                ),
                min_length=1,
                max_length=253,
            ),
        ],
        subtree: Annotated[
            str,
            Field(
                description=(
                    "Config subtree to read, as a RESTCONF path under the device's config "
                    "(e.g. 'router', 'segment-routing', 'router/isis' or "
                    "'tailf-ned-cisco-ios-xr:router'). A bare first segment gets the XR NED "
                    "module prefix 'tailf-ned-cisco-ios-xr:' added; list keys must be "
                    "percent-encoded ('interface/GigabitEthernet=0%2F0%2F0%2F0'); '?', '#' "
                    "and whitespace are refused (set the depth with 'depth', not '?depth='). "
                    "Empty = the whole config (combine with depth=2 to list its top-level "
                    "containers)."
                ),
                max_length=500,
            ),
        ] = "",
        depth: Annotated[
            int,
            Field(
                description=(
                    "RESTCONF depth limit (e.g. 2 lists the top-level containers of the "
                    "selected subtree); 0 = unlimited (the whole subtree)."
                ),
                ge=0,
                le=NSO_CONFIG_MAX_DEPTH,
            ),
        ] = 0,
    ) -> str:
        """Read NSO's copy of a device's running configuration (its CDB ``config``
        container) — the whole thing, one subtree, or just the top-level containers.

        Read-only (a proxy GET; nothing on the device, in NSO or in Crosswork
        changes, and ``nso_state`` is untouched). This is **NSO's CDB copy**,
        current as of NSO's last sync-from of the device (the automatic one on
        onboarding, or a later cnc_nso_device_action(action='sync-from')) —
        not a live read of the router. cnc_check_nso_device_sync (a fresh
        check-sync) says whether the copy still matches the device;
        cnc_check_device_nso_state shows when the copy was last refreshed
        (``nso_timestamp``). Use it to answer "what is configured on PE1"
        questions without a write: e.g. subtree 'segment-routing' for the
        SR-TE policies configured on the box (and hence whether an SR policy
        was created on-device rather than by the PCE or a CNC service),
        'router' for IS-IS/BGP/static routing ('router/isis', 'router/bgp'),
        'interface' for interfaces ('interface/Loopback=0'). Verified live
        2026-09-14 on the lab's XR devices (NED cisco-iosxr-cli-7.70): the
        depth-2 listing, 'segment-routing' (the on-box SR-TE policy with its
        PCEP peer 'pcc.pce.address.ipv4'), 'router/isis', 'router/bgp',
        'interface/Loopback=0', an unconfigured container and the 404 cases.

        Path rules (verified live): the config is modelled in the NED's YANG,
        NOT the device's native ``Cisco-IOS-XR-*`` models. The XR CLI NED's
        module is ``tailf-ned-cisco-ios-xr``, and RESTCONF needs that prefix
        on the FIRST segment of the subtree path (children inherit it): a bare
        'router' is sent as 'tailf-ned-cisco-ios-xr:router' automatically; an
        explicit prefix is kept verbatim (pass the right NED module yourself
        for a non-XR device); 'cisco-ios-xr:router', a native model name or a
        node the NED does not model answers 404 "uri keypath not found" — the
        same 404 a missing device gets, and the same 404 a valid list path
        with a key the device has not configured gets ('interface/Loopback=99'
        when only Loopback0 exists) — and is reported as an error naming all
        three causes. A container the NED models but the device has not
        configured (e.g. 'router/ospf' on the lab) answers 204 and is reported
        as empty, not as an error: so "container, no config" is 204 while
        "list entry, no such key" is 404. Some data paths through the same
        proxy spell not-found as 409 data-missing instead (verified on the CAT
        vpn-service lists); the error then reports the 409 and NSO's own
        message rather than the 404 text. The subtree may contain only path
        characters: '?', '#' or interior whitespace is refused before any
        request (a '?' would start a query string and bypass 'depth', a '#'
        would cut the path short) — percent-encode keys instead. Interface
        references inside the config are
        objects ('"update-source": {"Loopback": 0}'), not strings, and an
        empty leaf ('report-all') is rendered ``[null]`` (RFC 7951). Sends
        ``GET /crosswork/proxy/nso/restconf/data/tailf-ncs:devices/
        device=<name>/config[/<subtree>][?depth=N]`` with ``Accept:
        application/yang-data+json``. With no subtree and depth 0 the answer
        is the device's ENTIRE configuration — tens of kilobytes on a lab
        router, megabytes in production — and is cut at the response cap;
        start with depth=2 to see the top-level containers, then read the
        subtree you need.

        Args:
            host_name: exact NSO device name (list with cnc_list_nso_devices).
            subtree: the config subtree path ('' = whole config).
            depth: RESTCONF depth (0 = unlimited).

        Returns:
            str: A headline "NSO's CDB copy of <name>'s configuration (subtree
            <path> | whole config, depth N | full depth): K top-level key(s):
            ... — as of NSO's last sync-from ..." followed by the JSON body as
            NSO returns it. Whole config: ``{"tailf-ncs:config":
            {"tailf-ned-cisco-ios-xr:hostname": "PE1",
            "tailf-ned-cisco-ios-xr:router": {...}, ...}}`` — with depth=2 the
            lab device listed 15 keys: the NED containers (grpc, hostname,
            interface, lldp, logging, mpls, netconf-yang, router,
            segment-routing, snmp-server, ssh, username, xyzroot) as ``{}`` /
            leaf values, plus ``ietf-yang-library:modules-state`` and
            ``ietf-yang-library:yang-library`` (NSO's YANG library, not device
            config). Subtree: ``{"tailf-ned-cisco-ios-xr:<last segment>":
            {...}}`` (e.g. 'router/isis' -> ``{"tailf-ned-cisco-ios-xr:isis":
            {"tag": [...]}}``); ``{}`` with "the subtree is empty in NSO" when
            the container is modelled but unconfigured (204). "Error: NSO
            answered <status> '<NSO's message>' (error-tag <tag>) for device
            '<name>' ..." — 404 'uri keypath not found' (invalid-value), or
            409 (data-missing) on the paths that spell it so — when NSO has no
            such device, OR the subtree path is wrong, OR the list entry with
            that key is not configured (the message explains the prefix rule
            and the 204-vs-404 distinction); "Error: subtree ... contains
            '?' ..." when the path carries '?', '#' or whitespace (refused
            before any request); "Error: ..." on any other API failure (bare
            404 -> the proxy is not routed, i.e. NSO is not configured; 415 ->
            media type).
        """
        try:
            key = host_name.strip()
            if not key:
                raise PlatformError("host_name must not be empty or whitespace-only.")
            path = normalize_config_subtree(subtree)
            response = await client.request(
                "GET",
                nso_config_url(key, path),
                params={"depth": depth} if depth else None,
                headers=YANG_ACCEPT,
                raise_on_error=False,
            )
            data: Any = None
            if response.content:
                try:
                    data = response.json()
                except ValueError:
                    data = None
            if is_not_found(response.status_code, data):
                # Built from the response, not a literal: the proxy spells not-found as
                # 404 invalid-value "uri keypath not found" on device paths (verified), and
                # 409 data-missing on some other data paths (verified on the CAT vpn-service
                # lists through the same proxy) — report whichever NSO actually said.
                status = response.status_code
                where = f"subtree '{path}'" if path else "its whole config"
                raise PlatformError(
                    f"NSO answered {status}{_restconf_said(data)} for device '{key}', {where}. "
                    f"Either NSO holds no device named '{key}' (names are exact and "
                    "case-sensitive; list them with cnc_list_nso_devices), or the subtree path "
                    "is not in NSO's model: the config is in NED YANG, and the XR CLI NED's "
                    f"module prefix '{NSO_XR_NED_MODULE}:' must lead the first segment (a bare "
                    "'router' gets it added; 'cisco-ios-xr:router' and the device's native "
                    "'Cisco-IOS-XR-*' model names do not exist there), or the path is valid "
                    "but the list entry with that key is not configured on the device (a "
                    "container with no config answers 204, a missing list key such as "
                    f"'interface/Loopback=99' answers this {status}). List the valid "
                    "top-level containers with subtree='' and depth=2, or read the parent "
                    "list (e.g. 'interface/Loopback') to see which keys exist."
                )
            if not response.is_success:
                raise http_error(response)
            if response.content and data is None:
                raise PlatformError(
                    "The NSO proxy returned a non-JSON response where JSON was expected."
                )
            body = data if data is not None else {}
            keys = config_top_keys(body)
            listing = ", ".join(keys[:30]) + (", ..." if len(keys) > 30 else "")
            scope = f"subtree {path}" if path else "whole config"
            depth_text = f"depth {depth}" if depth else "full depth"
            head = (
                f"NSO's CDB copy of {key}'s configuration ({scope}, {depth_text}): "
                f"{len(keys)} top-level key(s)"
                + (f": {listing}." if keys else " — the subtree is empty in NSO.")
                + " This is what NSO holds as of its last sync-from (nso_timestamp in "
                "cnc_check_device_nso_state), not a live read of the device — "
                "cnc_check_nso_device_sync tells whether it still matches."
            )
            return finalize(f"{head}\n{to_json(body)}", settings, hint=_NSO_CONFIG_HINT)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_check_device_nso_state",
        title="Check Device NSO State",
        read_only=True,
        idempotent=True,
    )
    async def cnc_check_device_nso_state(
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Device host name, exact match, case-insensitive, '*' wildcard "
                    "(e.g. 'PE1' or 'PE*')."
                ),
                max_length=253,
            ),
        ] = None,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Read Crosswork's CACHED NSO state of one or more devices (nso_state, NsoMsg, ...).

        Read-only. Pass exactly one selector; ``host_name`` may carry ``*`` to
        cover several devices. For each match it reports the DLM's view of the
        device's NSO pipeline: ``nso_state`` (see the module docstring for the
        phases), ``nso_timestamp`` (epoch seconds, also rendered ISO-8601)
        i.e. when that state was set, ``NsoMsg`` (NSO's last message — the
        failure reason after ``CONNECT_FAILED`` etc.), the device ``errors``
        list, the provider families the device is associated with
        (``providers_family`` keys — ``ROBOT_PROVIDER_NSO`` once associated)
        with the NSO device name per NSO provider (``nso_providers``,
        ``provider_node_id``) and ``ned_id`` when Crosswork recorded one.
        This is the same ``nodes/query`` read cnc_get_device does, reduced to
        the NSO fields.

        THE VERDICT IS A CACHE, NOT A LIVE CHECK: ``nso_state`` is whatever the
        DLM recorded the last time an NSO action ran for the device
        (automatic onboarding, or a connect / sync-from / check-sync /
        sync-to), and ``nso_timestamp`` says WHEN. A device showing SYNCED
        with a timestamp from yesterday was in sync yesterday; an out-of-band
        change made since is not reflected here until the next check. Nothing
        in this read contacts NSO or the device. To get a fresh in-sync /
        out-of-sync verdict run cnc_check_nso_device_sync (read-only: NSO's
        check-sync compares its CDB copy with the device's running config
        without changing either, and the result lands here as SYNCED /
        NOT_SYNCED with a new nso_timestamp). cnc_wait_for_device_nso_state
        polls this same view after an action.

        Args:
            uuid / host_name: exactly one; host_name accepts '*'.
            response_format: markdown (one line per device plus message /
                errors sub-lines) or json.

        Returns:
            str: Markdown, or JSON {"selector": {...}, "total": int,
            "count": int, "items": [{"host_name", "uuid", "nso_state",
            "nso_timestamp", "nso_timestamp_iso", "NsoMsg", "errors": [str],
            "providers_family": [str], "nso_providers": {"<provider>":
            "<nso device name>"}, "ned_id"?}]}. "Error: no device matches ..."
            when the selector finds nothing; "Error: ..." on an API failure.
        """
        try:
            selector = _selector(uuid, host_name)
            nodes, total = await resolve_devices(selector)
            summaries = [nso_summary(n) for n in nodes]
            if response_format is ResponseFormat.JSON:
                payload = {
                    "selector": selector,
                    "total": total,
                    "count": len(summaries),
                    "items": summaries,
                }
                return finalize(to_json(payload), settings)
            lines = [
                f"# NSO state of {len(summaries)} device(s) matching "
                f"{describe_selector(selector)} ({total} match in total)",
                "",
            ]
            for summary in summaries:
                lines.extend(_nso_summary_lines(summary))
            lines.append("")
            lines.append(
                "nso_state is the DLM's CACHED verdict from the last NSO action, recorded at "
                "the 'since' timestamp — not a live check. For a fresh in-sync / out-of-sync "
                "verdict run cnc_check_nso_device_sync (read-only check-sync); NSO's own "
                "oper-state is in cnc_list_nso_devices."
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_check_nso_device_sync",
        title="Check NSO Device Sync (fresh check-sync)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_check_nso_device_sync(
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid to check (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Device host name to check: exact match, case-insensitive, '*' wildcard "
                    "(e.g. 'PE1', or '*' for every device — each match is checked)."
                ),
                max_length=253,
            ),
        ] = None,
        wait_seconds: Annotated[
            int,
            Field(
                description=(
                    "How long to wait for the verdicts (e.g. 60). 0 returns as soon as "
                    "Crosswork accepts the check; read the verdicts later with "
                    "cnc_check_device_nso_state."
                ),
                ge=0,
                le=600,
            ),
        ] = DEFAULT_CHECK_SYNC_WAIT,
        interval_seconds: Annotated[
            int, Field(description="Seconds between polls while waiting (e.g. 5).", ge=2, le=60)
        ] = 5,
    ) -> str:
        """Run a FRESH NSO check-sync on the selected device(s) and report, per device,
        whether NSO's copy of its configuration matches the device: in-sync / out-of-sync.
        Read-only for the device and NSO (a check-sync compares, it never writes), but it
        leaves a job record in Crosswork's job list and refreshes the device's nso_state.

        Registered without CNC_MCP_ENABLE_WRITES (read_only_hint is true) for
        that reason: NSO's check-sync only COMPARES its CDB copy with the
        device's running configuration — it
        changes nothing on the device and nothing in NSO's CDB (that is
        sync-from / sync-to). What it does do on the platform: it creates a job
        record in Crosswork's job list (``POST /crosswork/inventory/v1/nso/
        check-sync``, answered ``JOB_ACCEPTED``), and it refreshes each checked
        device's DLM bookkeeping — ``nso_state`` walks CHECK_SYNC_SCHEDULED ->
        CHECK_SYNC_STARTED -> SYNCED (in sync) | NOT_SYNCED (out of sync) and
        ``nso_timestamp`` moves to now. That refreshed value is exactly what
        cnc_check_device_nso_state then shows, so use this tool whenever the
        cached verdict there is too old to trust ("is NSO in sync with every
        device?" -> host_name='*'). Re-running it is safe. To see WHAT NSO
        holds for the device read cnc_get_nso_device_config.

        Verified live 2026-09-14 (this tool, PE1): ``JOB_ACCEPTED`` with
        ``type`` "NSO device check sync" (the platform's spelling), settled in
        ~5 s with the in-sync verdict — nso_state SYNCED, nso_timestamp
        advanced (03:30:03Z -> 03:40:20Z). NOT_SYNCED is the enum's documented
        out-of-sync verdict; the lab's devices were in sync, so that path is
        UNVERIFIED, as is what a check-sync NSO cannot run settles to. The
        enum has no CHECK_SYNC_FAILED value and only ``connect`` was seen to
        fail (CONNECT_FAILED); if a failed check lands in one of the known
        failure states (CONNECT_FAILED, ...) it is reported per device as
        ``failed`` with NsoMsg — the check could not run, which is not the
        same as out of sync — but it may equally stay CHECK_SYNC_STARTED,
        which this tool reports as ``pending`` until the wait runs out.

        SAFETY RULE (verified live): the DLM does not validate the filter — a
        filter matching nothing still answers JOB_ACCEPTED and may act on other
        devices. The selector is therefore resolved with ``POST nodes/query``
        first, zero matches is an error (nothing is sent) and exactly the
        resolved filter is sent. The POST is not auto-retried (a lost answer
        would only mean a second check; re-run it yourself).

        With ``wait_seconds`` > 0 (default 60) the tool then polls the devices'
        ``nso_state`` every ``interval_seconds``, ignoring readings whose
        ``nso_timestamp`` is not newer than the pre-check one (the DLM leaves
        the old state in place for a few seconds after JOB_ACCEPTED), until
        every matched device has settled or the time is up. A timeout is NOT an
        error: the answer says which devices are still pending — call
        cnc_check_device_nso_state (or this tool again) later.

        Args:
            uuid / host_name: exactly one selector; host_name may use '*'.
            wait_seconds: 0 to return at once (verdicts later via
                cnc_check_device_nso_state), else the polling budget.
            interval_seconds: seconds between polls.

        Returns:
            str: A headline "check-sync of N device(s): A in-sync, B
            out-of-sync, C failed, D pending (after Ns)" followed by JSON
            {"job": {"job_id", "state": "JOB_ACCEPTED", "type": "NSO device
            check sync"} (Crosswork's job record for the check — its
            acceptance says nothing about the verdicts, which are below),
            "action": "check-sync", "filter": {...}, "matched_total": int,
            "settled": bool (every matched device has a verdict), "elapsed_seconds": int,
            "devices": [{"host_name", "uuid", "verdict": "in-sync" |
            "out-of-sync" | "failed" | "pending", "nso_state",
            "nso_timestamp", "nso_timestamp_iso", "NsoMsg", "errors": [str],
            "nso_state_before", "nso_timestamp_before"}], "note"? (more
            devices matched than are listed), "next"? (what to do about
            pending devices)}. With wait_seconds=0 every verdict is
            "pending" and ``next`` names the follow-up read. "Error: ..." when
            the selector is missing/ambiguous, no device matches (nothing
            sent), Crosswork rejects the job (JOB_FAILED / JOB_REJECTED with
            its reason) or on an API failure.
        """
        try:
            selector = _selector(uuid, host_name)
            nodes, total = await resolve_devices(selector)
            accepted = await run_action(
                NSO_CHECK_SYNC_URL, "NSO check-sync", selector, nodes, total
            )
            # The job envelope is nested under "job" and its "pending" / empty
            # "impacted_objects" dropped: a top-level "pending: true" next to
            # "settled: true" read as a contradiction (the job's acceptance is not
            # the verdict). A non-empty impacted list is kept in case a build sends one.
            job = {k: v for k, v in accepted.items() if k not in _NOT_JOB_KEYS}
            if accepted.get("impacted_objects"):
                job["impacted_objects"] = accepted["impacted_objects"]
            payload: dict[str, Any] = {
                "job": job,
                "action": "check-sync",
                "filter": accepted["filter"],
                "matched_total": accepted["matched_total"],
            }
            if "note" in accepted:
                payload["note"] = accepted["note"]
            before = {
                str(n.get("uuid")): parse_after_timestamp(n.get("nso_timestamp"))
                for n in nodes
                if str(n.get("nso_timestamp") or "").strip().isdigit()
            }
            matched = {str(n.get("uuid")) for n in nodes}

            def verdicts(fresh: list[dict[str, Any]]) -> list[dict[str, Any]]:
                """One entry per matched device: the re-read record's verdict, or
                ``pending`` with the pre-check fields when it was not re-read."""
                by_uuid = {str(n.get("uuid")): n for n in fresh}
                out: list[dict[str, Any]] = []
                for original in nodes:
                    key = str(original.get("uuid"))
                    node = by_uuid.get(key)
                    summary = nso_summary(node if node is not None else original)
                    out.append(
                        {
                            "host_name": summary["host_name"],
                            "uuid": summary["uuid"],
                            "verdict": (
                                sync_verdict(node, before.get(key))
                                if node is not None
                                else "pending"
                            ),
                            "nso_state": summary["nso_state"],
                            "nso_timestamp": summary["nso_timestamp"],
                            "nso_timestamp_iso": summary["nso_timestamp_iso"],
                            "NsoMsg": summary["NsoMsg"],
                            "errors": summary["errors"],
                            "nso_state_before": original.get("nso_state"),
                            "nso_timestamp_before": original.get("nso_timestamp"),
                        }
                    )
                return out

            elapsed = 0.0
            settled = False
            if wait_seconds > 0:

                async def fetch() -> list[dict[str, Any]]:
                    fresh, _ = await resolve_devices(selector)
                    return [n for n in fresh if str(n.get("uuid")) in matched]

                def done(fresh: list[dict[str, Any]]) -> bool:
                    seen = {str(n.get("uuid")) for n in fresh}
                    return matched <= seen and all(
                        sync_verdict(n, before.get(str(n.get("uuid")))) != "pending" for n in fresh
                    )

                settled, fresh, elapsed = await wait_until(
                    fetch, done, timeout_seconds=wait_seconds, interval_seconds=interval_seconds
                )
                devices = verdicts(fresh)
            else:
                devices = verdicts([])
            payload["settled"] = settled
            payload["elapsed_seconds"] = int(elapsed)
            payload["devices"] = devices
            counts = {k: 0 for k in ("in-sync", "out-of-sync", "failed", "pending")}
            for d in devices:
                counts[d["verdict"]] += 1
            if counts["pending"]:
                pending = ", ".join(
                    str(d["host_name"]) for d in devices if d["verdict"] == "pending"
                )
                payload["next"] = (
                    f"Still pending: {pending}. The verdicts land in the device record a few "
                    "seconds after JOB_ACCEPTED — read them with cnc_check_device_nso_state "
                    "(nso_state SYNCED = in sync, NOT_SYNCED = out of sync, newer "
                    "nso_timestamp) or run this tool again."
                )
            head = (
                f"check-sync of {len(devices)} device(s): {counts['in-sync']} in-sync, "
                f"{counts['out-of-sync']} out-of-sync, {counts['failed']} failed, "
                f"{counts['pending']} pending (after {int(elapsed)}s)."
            )
            if counts["out-of-sync"]:
                head += (
                    " NOT_SYNCED devices differ from NSO's CDB: cnc_nso_device_action("
                    "action='compare-config') shows the diff in the CNC UI; sync-from updates "
                    "NSO, cnc_nso_sync_to_device overwrites the device."
                )
            return finalize(f"{head}\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_nso_device_action",
        title="Run NSO Device Action",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_nso_device_action(
        action: Annotated[
            str,
            Field(
                description=(
                    f"One of: {_ACTION_CHOICES} (e.g. 'sync-from'; underscores accepted). "
                    "sync-to is a separate destructive tool (cnc_nso_sync_to_device)."
                ),
                min_length=1,
                max_length=20,
            ),
        ],
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid to act on (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Device host name to act on: exact match, case-insensitive, '*' wildcard "
                    "(e.g. 'PE1' or 'PE*' — every match is acted on)."
                ),
                max_length=253,
            ),
        ] = None,
    ) -> str:
        """Run a non-destructive NSO device action (connect / fetch-ssh-keys / sync-from /
        check-sync / compare-config) on the selected device(s) through Crosswork's DLM.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        None of these actions changes device configuration; re-running one is
        safe. In NSO terms:

        - ``connect``: open a management session to the device and verify the
          credentials (authgroup) and NED work. nso_state: CONNECT_SCHEDULED ->
          CONNECT_STARTED -> CONNECT_FAILED on failure (NsoMsg carries NSO's
          reason); on success a non-failure state (the enum has no CONNECTED —
          the settled value after a lone connect was not captured live, so
          wait with target='SYNCED,MATCH,ASSOCIATED' or just check
          cnc_check_device_nso_state for the absence of *_FAILED).
        - ``fetch-ssh-keys``: learn and store the device's SSH host keys (NSO
          refuses to connect over SSH to a device whose host key it does not
          hold). nso_state: FETCH_SSH_KEYS_SCHEDULED -> FETCH_SSH_KEYS_STARTED
          -> FETCH_SSH_KEYS_FAILED on failure, a non-failure state on success
          (same caveat as connect).
        - ``sync-from``: read the device's running configuration into NSO's
          CDB so NSO's copy matches the device (required before NSO can
          provision services on it, and after any out-of-band change).
          nso_state: SYNC_FROM_SCHEDULED -> SYNC_FROM_STARTED -> SYNCED, or
          SYNC_FAILED.
        - ``check-sync``: compare NSO's CDB copy with the device WITHOUT
          changing either. nso_state: CHECK_SYNC_SCHEDULED -> CHECK_SYNC_STARTED
          -> SYNCED (in sync) or NOT_SYNCED (out of sync — the check itself
          succeeded; follow with compare-config to see the diff and sync-from
          or cnc_nso_sync_to_device to reconcile). Because it changes no
          configuration it is also offered as the read-only
          cnc_check_nso_device_sync, which waits for and renders the verdicts
          — prefer that when writes are disabled or when you only want the
          in-sync answer.
        - ``compare-config``: produce the configuration diff between the CDB
          and the device (visible in the CNC UI's device NSO panel; Crosswork
          does not return the diff through this API). nso_state:
          COMPARE_CONFIG_SCHEDULED -> COMPARE_CONFIG_STARTED -> a non-failure
          state (no COMPARED value exists; same caveat as connect).

        The action is asynchronous: Crosswork answers a job envelope with
        ``state: JOB_ACCEPTED`` at once and the device's ``nso_state`` walks
        the transitions above over the next seconds — poll with
        cnc_wait_for_device_nso_state (the returned ``next`` says how),
        passing the returned ``nso_timestamp_before`` as ``after_timestamp``:
        the DLM leaves ``nso_state`` on its pre-action value for a few
        seconds after JOB_ACCEPTED, and without ``after_timestamp`` the wait
        would judge that stale reading (a device already SYNCED "reaches
        SYNCED after 0s" although nothing ran; a retried connect on a
        CONNECT_FAILED device "fails" at once with the old NsoMsg). The
        usual bring-up order is fetch-ssh-keys -> connect -> sync-from, but
        Crosswork's policy normally does all of that automatically on
        onboarding, so in practice these are repair actions. On this lab a
        CNC-driven ``connect`` ending CONNECT_FAILED is often XRd SSH flakiness
        ("connection refused" to NSO's NEDCOM): retry it, or run sync-from
        directly — it frequently succeeds and settles SYNCED anyway.

        SAFETY RULE (verified live): the DLM does not validate the filter — a
        filter matching nothing still answers JOB_ACCEPTED and may act on
        other devices. This tool therefore resolves the selector with
        ``POST nodes/query`` first, refuses when zero devices match, sends
        exactly the filter it resolved (``POST /crosswork/inventory/v1/nso/
        <action>`` ``{"filter": {"host_name"|"uuid": ...}}``) and returns the
        matched devices so you see what was acted on. A wildcard host_name
        acts on every match. The POST is not auto-retried (a lost answer
        would only mean a second job; re-run it yourself if needed).

        Args:
            action: connect | fetch-ssh-keys | sync-from | check-sync |
                compare-config (underscores accepted).
            uuid / host_name: exactly one selector; host_name may use '*'.

        Returns:
            str: JSON {"job_id", "state": "JOB_ACCEPTED", "type": "NSO device
            <action>", "pending": true, "impacted_objects": [], "filter":
            {...}, "matched_devices": [{"host_name", "uuid",
            "nso_state_before", "nso_timestamp_before"}], "matched_total":
            int, "note"? (when more devices match than are listed), "next":
            "Asynchronous: poll with cnc_wait_for_device_nso_state
            (host_name=..., after_timestamp=...) ..."}. "Error: ..." when the
            action name is unknown, the selector is missing/ambiguous, no
            device matches (nothing is sent), Crosswork answers a failed job
            (JOB_FAILED/JOB_REJECTED with its reason) or on an API failure.
        """
        try:
            key = normalize_action(action)
            selector = _selector(uuid, host_name)
            nodes, total = await resolve_devices(selector)
            payload = await run_action(f"{NSO_BASE}/{key}", f"NSO {key}", selector, nodes, total)
            payload["action"] = key
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_nso_sync_to_device",
        title="NSO Sync-To Device (push CDB config)",
        read_only=False,
        destructive=True,
        idempotent=True,
        # Names a READ-ONLY tool: in global dry-run mode the compare-config device
        # action (a write with no dry_run form) is itself recorded, not run.
        dry_run_hint=(
            "cnc_check_nso_device_sync (read-only) says whether the device differs from "
            "NSO's CDB; the diff itself is the compare-config device action — a write "
            "too, so it needs CNC_MCP_DRY_RUN unset, and it shows the diff in the CNC UI"
        ),
    )
    async def cnc_nso_sync_to_device(
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid to push to (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Device host name to push to: exact match, case-insensitive, no wildcards "
                    "(e.g. 'PE1') — this tool pushes to exactly one device per call."
                ),
                max_length=253,
            ),
        ] = None,
    ) -> str:
        """Push NSO's CDB copy of the configuration TO the selected device(s) (NSO sync-to).

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true.
        sync-to makes the device match NSO: every difference between the
        device's running configuration and NSO's CDB copy is applied to the
        device, which **overwrites any out-of-band change** made on the device
        since NSO last synced from it. Before running it:

        1. cnc_check_nso_device_sync (read-only check-sync) — in-sync means
           there is nothing to push; out-of-sync means the device drifted;
        2. cnc_nso_device_action(action="compare-config") and read the diff in
           the CNC UI, so you know exactly what sync-to will change;
        3. if the device's version is the one you want to keep, run sync-from
           instead (it updates NSO, not the device).

        Asynchronous like the other actions: ``POST /crosswork/inventory/v1/
        nso/sync-to`` ``{"filter": {...}}`` answers JOB_ACCEPTED and
        nso_state walks SYNC_TO_SCHEDULED -> SYNC_TO_STARTED -> SYNCED or
        SYNC_FAILED — poll with cnc_wait_for_device_nso_state, passing the
        returned ``nso_timestamp_before`` as ``after_timestamp`` (a device
        that was already SYNCED would otherwise be reported "reached SYNCED
        after 0s" before the push even started). The SAFETY RULE of
        cnc_nso_device_action applies: the selector is resolved first, a
        zero-match filter is refused, exactly the resolved filter is sent and
        the matched devices are returned; a wildcard host_name pushes to every
        match. Not auto-retried.

        Args:
            uuid / host_name: exactly one selector.

        Returns:
            str: JSON job envelope plus "filter", "matched_devices"
            [{"host_name", "uuid", "nso_state_before", "nso_timestamp_before"}],
            "matched_total" and "next" (the wait hint) — same shape as
            cnc_nso_device_action. "Error: ..." when no device matches
            (nothing is sent), the selector is missing/ambiguous, the job is
            reported failed, or on an API failure.
        """
        try:
            if host_name and "*" in host_name:
                return (
                    "Error: cnc_nso_sync_to_device overwrites device configuration, so it "
                    "takes one exact host_name or uuid — wildcards are refused. Run it once per "
                    "device, after cnc_nso_device_action(action='compare-config')."
                )
            selector = _selector(uuid, host_name)
            nodes, total = await resolve_devices(selector)
            if len(nodes) != 1:
                return (
                    f"Error: the selector matched {len(nodes)} devices; cnc_nso_sync_to_device "
                    "pushes configuration to exactly one device per call."
                )
            payload = await run_action(NSO_SYNC_TO_URL, "NSO sync-to", selector, nodes, total)
            payload["action"] = "sync-to"
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_sync_inventory_with_nso",
        title="Sync Inventory With NSO (global re-association)",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_sync_inventory_with_nso() -> str:
        """Re-run the DLM <-> NSO inventory association ("Sync With NSO") for the WHOLE
        inventory.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        This is the Crosswork UI's "Sync With NSO": the DLM re-evaluates its
        devices against the DLM -> NSO policy (cnc_get_nso_policy),
        matches/onboards them to the NSO provider and records the result in
        each device's ``nso_state`` (ASSOCIATED / NOT_ASSOCIATED / MATCH /
        NO_MATCH / ONBOARD_FAIL) and ``providers_family.ROBOT_PROVIDER_NSO``.
        Use it when a device shows NOT_ASSOCIATED although the policy should
        cover it, or after fixing the policy or a credential profile. It does
        not push or pull device configuration — that is sync-from / sync-to
        (cnc_nso_device_action / cnc_nso_sync_to_device).

        BLAST RADIUS — this is NOT a per-device action. The 7.2 API document
        (``crosswork_proxy_api_actions_to_nso_api_7_2_0.json``, operation
        ``Nso_DLMNSOSync``) says: "Input should be empty body, e.g. {} or any
        empty object. robotapi.RobotNodeGetReq is just to satisfy API" — the
        endpoint takes no device filter, so the DLM may re-evaluate every
        device in the inventory. There is therefore no selector on this tool;
        it sends the documented empty body ``{}``. (Whether a filter body
        would scope it is UNVERIFIED live — the verified call, which used a
        filter body the document says is ignored, only established that the
        operation is synchronous.) Read the devices you care about with
        cnc_check_device_nso_state before and after to see what changed.

        Verified live: ``POST /crosswork/inventory/v1/nso/sync`` is
        **synchronous** — the answer is ``JOB_COMPLETED`` with a
        ``completion_time`` and the affected devices in ``impacted``
        (returned as ``impacted_objects``). A pending state (JOB_ACCEPTED /
        JOB_RUNNING) is not treated as failure: it is returned with
        ``pending: true`` and a hint to confirm per device. Re-running it is
        safe (it is what the UI button does); the POST is not auto-retried on
        the wire.

        Returns:
            str: JSON job envelope ({"job_id", "state": "JOB_COMPLETED",
            "type", "completion_time", "creation_time", "created_by",
            "impacted_objects": [{"uuid", "name"?, "ip"?}]}) plus "action":
            "sync", "scope": "the whole inventory ..." and "next" (confirm the
            devices of interest with cnc_check_device_nso_state). "Error: ..."
            when the job is reported failed (JOB_FAILED / JOB_REJECTED with the
            platform's reason) or on an API failure.
        """
        try:
            result = await client.request_json("POST", NSO_SYNC_URL, json_body={})
            envelope = check_job(result, "Sync with NSO")
            payload: dict[str, Any] = {
                **envelope,
                "action": "sync",
                "scope": (
                    "the whole inventory: POST nso/sync takes no device filter (its body is "
                    "ignored per the 7.2 API document), so every device may have been "
                    "re-evaluated against the DLM -> NSO policy; impacted_objects is what "
                    "Crosswork reported."
                ),
            }
            if envelope.get("pending"):
                payload["next"] = (
                    "Crosswork reports the re-association as still running; confirm each "
                    "device of interest with cnc_check_device_nso_state (or "
                    "cnc_wait_for_device_nso_state with target='ASSOCIATED,MATCH,SYNCED' "
                    "and the device's previous nso_timestamp as after_timestamp)."
                )
            else:
                payload["next"] = (
                    "Completed synchronously; confirm the devices of interest with "
                    "cnc_check_device_nso_state (nso_state ASSOCIATED/MATCH and "
                    "providers_family ROBOT_PROVIDER_NSO once associated)."
                )
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_wait_for_device_nso_state",
        title="Wait for Device NSO State",
        read_only=True,
        idempotent=True,
    )
    async def cnc_wait_for_device_nso_state(
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description="Device host name, exact match, case-insensitive (e.g. 'PE1').",
                max_length=253,
            ),
        ] = None,
        target: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated nso_state values that end the wait successfully "
                    "(e.g. 'SYNCED' or 'SYNCED,MATCH'); case-insensitive."
                ),
                min_length=1,
                max_length=400,
            ),
        ] = DEFAULT_WAIT_TARGET,
        after_timestamp: Annotated[
            str | int | None,
            Field(
                description=(
                    "The device's nso_timestamp BEFORE the action — the 'nso_timestamp_before' "
                    "an action tool returned, or nso_timestamp from cnc_check_device_nso_state "
                    "(epoch, e.g. '1757772000'). Readings with nso_timestamp at or before it "
                    "are treated as 'not started yet' and polling continues whatever their "
                    "nso_state says. Strongly recommended right after an action."
                ),
            ),
        ] = None,
        timeout_seconds: Annotated[
            int, Field(description="How long to wait in total (e.g. 120).", ge=10, le=600)
        ] = 120,
        interval_seconds: Annotated[
            int, Field(description="Seconds between polls (e.g. 5).", ge=2, le=60)
        ] = 5,
    ) -> str:
        """Poll one device until its nso_state reaches a target state (or fails).

        Read-only convergence wait. Call it right after cnc_nso_device_action
        or cnc_nso_sync_to_device instead of polling cnc_check_device_nso_state
        in a loop, and pass the ``nso_timestamp_before`` that tool returned
        as ``after_timestamp``. Pass exactly one of uuid / host_name and it
        must match exactly one device (no wildcards that match several).
        Polls ``POST nodes/query`` every ``interval_seconds``:

        - a reading whose nso_timestamp is at or before ``after_timestamp``
          is the PRE-action state and is ignored (polling continues whatever
          its nso_state says);
        - nso_state in ``target`` -> success ("... reached SYNCED after Ns");
        - nso_state in the terminal failure set CONNECT_FAILED,
          FETCH_SSH_KEYS_FAILED, SYNC_FAILED, ONBOARD_FAIL, NO_MATCH,
          NOT_SYNCED (and not in ``target``) -> the wait ends at once with
          "Error: ..." carrying NsoMsg and the device errors — that is the
          action's outcome, not a timeout (CONNECT_FAILED on this lab is often
          XRd SSH flakiness; retry or run sync-from). Put a failure state in
          ``target`` to wait for it instead, e.g. target='SYNCED,NOT_SYNCED'
          after check-sync to accept either verdict;
        - any *_SCHEDULED / *_STARTED (or other) state keeps polling until
          ``timeout_seconds``.

        THE RACE ``after_timestamp`` CLOSES: the DLM answers JOB_ACCEPTED at
        once but only moves ``nso_state`` to ``*_SCHEDULED`` / ``*_STARTED`` a
        few seconds later, so the first poll after an action still reads the
        pre-action state. Without ``after_timestamp`` a device that was
        already SYNCED is reported "reached SYNCED after 0s" although nothing
        ran yet, and a retried connect on a CONNECT_FAILED device "fails" at
        once with the OLD NsoMsg. ``nso_timestamp`` moves with every state
        change (verified live), which is what makes the stale readings
        distinguishable. The parameter is optional only so the tool can also
        be used to wait on a state you did not trigger (automatic onboarding)
        — then a timeout is the only signal that nothing moved.

        Args:
            uuid / host_name: exactly one; must select a single device.
            target: acceptable nso_state values, comma-separated (default
                'SYNCED'; valid values are the nso_state enum).
            after_timestamp: the pre-action nso_timestamp (epoch) to ignore
                readings up to; see above.
            timeout_seconds, interval_seconds: the polling budget.

        Returns:
            str: On success: "Device <host> (<uuid>) reached nso_state
            <state> after Ns." plus a JSON summary (nso_state, nso_timestamp,
            NsoMsg, errors, providers_family, nso_providers). On timeout (NOT
            an error): "Not <target> after Ns; current nso_state=..., last
            message=..." plus the same summary — call again to keep waiting;
            when every reading was still the pre-action one the message says
            so ("... still the pre-action nso_state ...: the DLM has not
            started the action yet"). "Error: ..." when the device ends in a
            failure state (with NsoMsg / errors), when the selector matches
            zero or several devices, when ``target`` holds an unknown state,
            when ``after_timestamp`` is not an epoch value, or on an API
            failure.
        """
        try:
            selector = _selector(uuid, host_name)
            targets = parse_targets(target)
            after = parse_after_timestamp(after_timestamp)
            stop_states = targets | NSO_FAILURE_STATES
            finished, node, elapsed = await wait_until(
                lambda: find_one_device(selector),
                lambda n: not is_stale(n, after) and n.get("nso_state") in stop_states,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
            )
            summary = nso_summary(node)
            state = node.get("nso_state")
            label = f"Device {node.get('host_name')} ({node.get('uuid')})"
            target_text = ",".join(sorted(targets))
            if finished and state in targets:
                head = f"{label} reached nso_state {state} after {elapsed:.0f}s."
            elif not finished and is_stale(node, after):
                head = (
                    f"Not {target_text} after {elapsed:.0f}s; nso_state={state} is still the "
                    f"pre-action reading (nso_timestamp {node.get('nso_timestamp')} is not after "
                    f"after_timestamp {after}): the DLM has not started the action yet. Call "
                    "again to keep waiting, or check the job in the CNC UI."
                )
            elif finished:
                message = summary["NsoMsg"] or "no NsoMsg"
                errors = "; ".join(summary["errors"]) or "none"
                hint = ""
                if state == "CONNECT_FAILED":
                    hint = (
                        " On this lab CONNECT_FAILED is often XRd SSH flakiness: retry "
                        "connect, or run sync-from directly — it may still succeed."
                    )
                elif state == "NOT_SYNCED":
                    hint = (
                        " NOT_SYNCED means the device and NSO's CDB differ: run "
                        "compare-config to see the diff, then sync-from (update NSO) or "
                        "cnc_nso_sync_to_device (overwrite the device)."
                    )
                raise PlatformError(
                    f"{label} ended in nso_state {state} after {elapsed:.0f}s (waiting for "
                    f"{target_text}). NsoMsg: {message}. Device errors: {errors}.{hint}\n"
                    f"{to_json(summary)}"
                )
            else:
                head = (
                    f"Not {target_text} after {elapsed:.0f}s; current nso_state={state}, "
                    f"last message={summary['NsoMsg'] or '-'}. Call again to keep waiting, "
                    "or check NSO's own view with cnc_get_nso_device."
                )
            return finalize(f"{head}\n{to_json(summary)}", settings)
        except Exception as e:
            return format_error(e)
