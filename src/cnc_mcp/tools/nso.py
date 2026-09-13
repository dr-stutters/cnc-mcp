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
   Crosswork's ``nso_state``** — use ``cnc_wait_for_device_nso_state`` after
   one, passing the ``nso_timestamp_before`` the action tool returned as
   ``after_timestamp``: the DLM only moves ``nso_state`` off its pre-action
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
   NSO oper-state (``cnc_list_nso_devices`` / ``cnc_get_nso_device``). A
   proxy read never changes ``nso_state``.

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
(a later ``services`` module).
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
    select_key,
    unwrap_list,
)
from cnc_mcp.safety import AppContext, register_tool

NODES_QUERY_URL = f"{INVENTORY}/nodes/query"
NSO_BASE = f"{INVENTORY}/nso"
NSO_POLICY_QUERY_URL = f"{NSO_BASE}/policy/query"
NSO_SYNC_URL = f"{NSO_BASE}/sync"
NSO_SYNC_TO_URL = f"{NSO_BASE}/sync-to"
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
        the fields above; reading configuration through the proxy is a
        separate concern (a later ``services`` module).

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
        """Read Crosswork's NSO state of one or more devices (nso_state, NsoMsg, ...).

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
        the NSO fields; the DLM actions (cnc_nso_device_action) are what move
        ``nso_state``, and cnc_wait_for_device_nso_state polls this view.

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
                "nso_state is Crosswork's (DLM) view and only changes through the DLM NSO "
                "actions; NSO's own oper-state is in cnc_list_nso_devices."
            )
            return finalize("\n".join(lines), settings)
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
          or cnc_nso_sync_to_device to reconcile).
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

        1. cnc_nso_device_action(action="check-sync") — SYNCED means there is
           nothing to push; NOT_SYNCED means the device drifted;
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
