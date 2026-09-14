"""Platform administration and RBAC reads (plus three small writes).

Two services behind the Crosswork gateway, both plain JSON with the bearer
token the client adds (verified live 2026-09-13 on a 7.2 single-VM build):

- ``/crosswork/platform/v2`` — the platform itself: ``cluster/*`` (version,
  cluster / infra / application health, VM nodes, microservices = pods, login
  banner), ``capp/*`` (the application manager: application states, its jobs
  and events), ``platform/maintenance/*``, ``platform/balancer/status``,
  ``upgrademanager`` and ``cert/*`` (certificate manager).
- ``/crosswork/aaa/v1`` (and ``aaa/v2/api``) — RBAC: local users, roles,
  task permissions, session configuration and the active-session list,
  password policy, the secured-API catalogue.

Facts this module encodes (see the platform notes for the wire captures):

- Envelopes differ per endpoint and are unwrapped exactly as recorded:
  ``result_map`` (version), ``cluster_summary`` / ``health_summary``,
  ``node_summary[]``, ``app_health_summary[]``, ``micro_service[]``,
  ``application_states[]``, ``jobs[{"job": {...}}]``, ``events[]``,
  ``cert_summary[]``, a dict keyed by username (``aaa/v1/user``), a dict keyed
  by role name (``aaa/v1/role``), and bare lists (``activeSessions``,
  ``usertask/<role>``, ``userpermission``).
- POST bodies are tiny: ``{"node_id": ...}`` for the node queries,
  ``{"req_id": ...}`` for the microservice list/restart, ``{}`` for the
  ``capp/applicationstatus`` / ``installedapplicationid`` queries and the
  banner read. ``capp/jobs/query`` and ``capp/events/query`` are sent the
  documented ``{"query_options": {"pagination": {"page_token", "page_size"}}}``
  and their returned ``page_token`` is followed (the lab answered a ``{}`` body
  with one page; whether this build ever pages is unverified, so the code
  handles both). A ``{}`` microservice answer means "no microservices", not an
  error.
- ``cluster/banner/set`` is protobuf-backed: an omitted field is
  indistinguishable from ``false`` / ``""``, so the write tool reads the
  current banner first and always sends the full verified object
  ``{ShowMessage, UserAck, Message, Icon, Title}`` (or ``{ResetSettings:
  true}`` alone).
- A session's ``TgtId`` is a credential (``POST sso/v1/tickets/<TGT>`` mints a
  fresh JWT for that user without a password; ``DELETE`` ends the session), so
  the active-session list shortens it in every output format.
- Not-found spellings: an unknown user is **500 ``{"error": "Invalid
  Username"}``** (rendered as ``Error: no user '<name>'``); an empty id is a
  500 ``cluster id is empty`` / ``nodeId is empty`` (validated client-side
  before any request). What the platform answers for an unknown *role* or
  *node id* is NOT verified — those errors pass through as-is.
- The lab is a single VM: one ``HYBRID`` node whose ``node_id`` is its
  management IP, ``CLUSTER_TYPE`` ``SINGLE``, and ten applications
  (``capp-infra``, ``capp-cdg``, ``capp-common-ems-services``, ``capp-coe``,
  ``capp-cat``, ``capp-aa``, ``capp-enso``, ``capp-pa``, ``capp-cwm``,
  ``capp-cwm-solutions``). Multi-node clusters follow the same documented
  shapes but were not exercised.
- ``systempackage/*`` answers 404 text on this build and is not built on;
  ``aaa/v1/preferences/query`` is 404 too. There is NO API to terminate a
  session (``getSessionMgmtPermissions`` reports the permission; the
  termination itself lives in the UI). ``PUT lockUsers``/``unlockUsers``
  bodies are undocumented and not exposed.
- ``aaa/v1/role`` (the ``access_rights`` map) and ``aaa/v1/api`` are huge:
  markdown summarises them; json hands back the raw object and lets
  ``finalize()`` truncate (with a tool-specific hint). The microservice
  endpoints have no paging at all — a whole platform is ~109 pods / 85k
  characters of JSON (verified live 2026-09-14) — so cnc_list_microservices
  pages client-side over what it fetched.

Timestamps: app-manager ``start_time`` / ``completion_time`` / ``event_time``
are epoch-millisecond strings (rendered via ``formatting.epoch_iso``);
microservice ``up_time`` ("207d 11h 30m 10s") and certificate
``expiration_date`` ("Sun, 16 Feb 2031 23:47:42 UTC") are already text.
``up_time`` is the pod's CONTAINER AGE (time since it was last created or
restarted), not time-since-healthy: observed live 2026-09-14, cwm-api-service /
optima-lcm / optima-ddm read 208d although Major alarms recorded them down 37
days earlier — a health=down episode does not reset it; only a restart /
re-creation does (the replaced cwm-worker read 1d).
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from email.utils import parsedate_to_datetime
from typing import Annotated, Any
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import AAA, PLATFORM, page_envelope
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, epoch_iso, finalize, to_json
from cnc_mcp.safety import AppContext, register_tool
from cnc_mcp.tools.platform import _users_from_response

logger = logging.getLogger(__name__)

AAA_V2 = "/crosswork/aaa/v2"

# platform/v2 — cluster manager
VERSION_URL = f"{PLATFORM}/cluster/version/show"
CLUSTER_SUMMARY_URL = f"{PLATFORM}/cluster/summary/list"
INFRA_SUMMARY_URL = f"{PLATFORM}/cluster/infra/summary"
APP_HEALTH_URL = f"{PLATFORM}/cluster/app/health/list"
NODE_SUMMARY_URL = f"{PLATFORM}/cluster/dc/node/summary/list"
NODE_DETAILS_URL = f"{PLATFORM}/cluster/dc/node/details/query"
MICROSERVICES_URL = f"{PLATFORM}/cluster/microservice/list/query"
MICROSERVICE_RESTART_URL = f"{PLATFORM}/cluster/microservice/restart"
BANNER_GET_URL = f"{PLATFORM}/cluster/banner/get"
BANNER_SET_URL = f"{PLATFORM}/cluster/banner/set"
# platform/v2 — application manager
INSTALLED_APP_IDS_URL = f"{PLATFORM}/capp/installedapplicationid/query"
APP_STATUS_URL = f"{PLATFORM}/capp/applicationstatus/query"
APP_JOBS_URL = f"{PLATFORM}/capp/jobs/query"
APP_EVENTS_URL = f"{PLATFORM}/capp/events/query"
# platform/v2 — backup/restore manager, balancer, certificate manager
MAINTENANCE_STATUS_URL = f"{PLATFORM}/platform/maintenance/status"
MAINTENANCE_SET_URL = f"{PLATFORM}/platform/maintenance/set"
UPGRADE_MANAGER_URL = f"{PLATFORM}/upgrademanager"
BALANCER_STATUS_URL = f"{PLATFORM}/platform/balancer/status"
CERT_SUMMARY_URL = f"{PLATFORM}/cert/summary/list"
CERT_EXPIRY_URL = f"{PLATFORM}/cert/renew/check-expiry"
# aaa/v1 + aaa/v2 — RBAC
SESSION_CONFIG_URL = f"{AAA}/sessionconfig"
SESSION_PERMISSIONS_URL = f"{AAA}/getSessionMgmtPermissions"
ACTIVE_SESSIONS_URL = f"{AAA}/activeSessions"
USER_URL = f"{AAA}/user"
ROLES_URL = f"{AAA}/role"
USERTASK_URL = f"{AAA}/usertask"
ROLE_ACCESS_URL = f"{AAA}/roleAccess"
USER_PERMISSION_URL = f"{AAA}/userpermission"
PASSWORD_POLICY_URL = f"{AAA}/passwordPolicyConfig"
SECURED_APIS_URL = f"{AAA_V2}/api"

# clusterHealthState enum (7.2 cluster manager document); matched case-insensitively.
HEALTH_STATES = ("healthy", "degraded", "down", "na", "unknown")
_HEALTH_CHOICES = ", ".join(HEALTH_STATES)

# Verified enum spellings.
CLUSTER_RESULT_SUCCESS = "R_SUCCESS"
CLUSTER_RESULT_NOOP = "R_NOOP"
CAPP_ACCEPTED = "ACCEPTED"
UNKNOWN_ACTION = "UNKNOWN_ACTION"
MAINTENANCE_REQUEST_FAILED = "Maintenance_Mode_Request_Status_Failed"

# clusterBannerLoginIcon enum (cluster manager document; default BANNER_ICON_INFO).
BANNER_ICONS = ("BANNER_ICON_INFO", "BANNER_ICON_IMPORTANT", "BANNER_ICON_CRITICAL")
_BANNER_ICON_CHOICES = " | ".join(BANNER_ICONS)

# capp/* token paging (``query_options.pagination`` in the App Manager document):
# page_size per request, and a hard cap on pages followed per tool call so an
# echoing server can never loop the tool.
CAPP_PAGE_SIZE = 100
CAPP_MAX_PAGES = 20

# cnc_list_microservices pages client-side over what it fetched. JSON rows are
# ~700-800 characters (a 109-pod platform is 85k characters unpaged, verified live
# 2026-09-14), so 40 per page keeps a full JSON page under the default 40 000-char
# response cap; markdown lines are ~100 characters.
MICROSERVICE_PAGE_SIZE = 40
MICROSERVICE_MAX_PAGE_SIZE = 500
# Offset-style keys crosswork.page_envelope() inherits from the template envelope; the
# microservice list pages by page/page_size only, so its JSON drops them.
_OFFSET_KEYS = ("offset", "next_offset")

# Truncation advice for the tools whose full answer can exceed the response cap
# (finalize() otherwise gives a generic hint that names no parameter).
_MICROSERVICES_HINT = (
    "Lower page_size (JSON rows are ~700 characters; 40 per page fit) or narrow with "
    "app_id / node_id / health, then step through with page."
)
_LIMIT_HINT = "Lower limit."
_ROLES_HINT = (
    "Use markdown for the per-role summary, or cnc_get_role_permissions / "
    "cnc_get_role_tasks for one role."
)
_SECURED_APIS_HINT = "Narrow with feature, or use markdown."

# Password policy: the ``*Enable`` flag -> the value it gates (the flag names do not
# all derive from the value names: ``FailedLoginsBefLoEnable`` gates
# ``FailedLoginsBeforeLockout``), plus how to phrase each rule.
_POLICY_GATED_RULES: list[tuple[str, str, str]] = [
    ("NumChangedCharsEnable", "NumChangedChars", "must change at least {} character(s)"),
    ("NumReuseLimitEnable", "NumReuseLimit", "cannot reuse the last {} passwords"),
    (
        "PasswordReuseDaysEnable",
        "PasswordReuseDays",
        "cannot reuse a password used in the last {} days",
    ),
    (
        "FailedLoginsBefLoEnable",
        "FailedLoginsBeforeLockout",
        "lock out after {} failed logins",
    ),
    ("LockOutUserTimeEnable", "LockOutUserTime", "lock out for {} minutes"),
    ("PasswordExpiryDaysEnable", "PasswordExpiryDays", "password expires after {} days"),
    ("DaysForWarningEnable", "DaysForWarning", "warn {} days before expiry"),
]
# Rules always shown regardless of an Enable flag.
_POLICY_ALWAYS_RULES: list[tuple[str, str]] = [
    ("MinPasswordLength", "minimum length {}"),
    ("NoUsername", "no username (or its reverse) in the password"),
    ("NoCiscoVariant", "no 'cisco' variants"),
    ("NoCharRepetition", "no character repeated more than three times in a row"),
    ("ChangePasswdOnFirstLogin", "change password on first login"),
]
_POLICY_ALWAYS_GATED = {"FailedLoginsBefLoEnable", "LockOutUserTimeEnable"}

_TGT_PREFIX = 12


# --- small helpers -----------------------------------------------------------


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _yes_no(value: Any) -> str:
    return "yes" if value is True else "no" if value is False else "?"


def _int_or_zero(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _clean(value: str | None) -> str:
    """Stripped text, or '' for None/blank — so optional args need no None checks."""
    return value.strip() if isinstance(value, str) else ""


def _check_cluster_result(data: Any, what: str) -> dict[str, Any]:
    """cluster/* answers carry ``result`` / ``resp_value`` (R_SUCCESS|R_FAILURE|R_NOOP)."""
    body = _dict(data)
    verdict = body.get("result", body.get("resp_value"))
    if isinstance(verdict, str) and verdict not in (CLUSTER_RESULT_SUCCESS, CLUSTER_RESULT_NOOP):
        reason = body.get("resp_error") or body.get("description") or body.get("error")
        raise PlatformError(f"{what}: Crosswork answered {verdict}: {reason or 'no reason given'}")
    return body


def _check_capp_result(data: Any, what: str) -> dict[str, Any]:
    """capp/* answers carry ``result.request_result`` (ACCEPTED|REJECTED); REJECTED is an error.

    Only a present, non-ACCEPTED verdict raises: the envelope is verified on
    ``installedapplicationid/query`` and documented on the others.
    """
    body = _dict(data)
    result = _dict(body.get("result"))
    verdict = result.get("request_result")
    if verdict is not None and verdict != CAPP_ACCEPTED:
        error = result.get("error")
        reason = error.get("message") if isinstance(error, dict) else error
        raise PlatformError(f"{what} was {verdict}: {reason or 'no reason given'}")
    return body


def _capp_page_body(page_token: str) -> dict[str, Any]:
    """The documented capp/* paging request: ``query_options.pagination``."""
    return {
        "query_options": {"pagination": {"page_token": page_token, "page_size": CAPP_PAGE_SIZE}}
    }


def _capp_next_token(body: dict[str, Any], sent_token: str) -> str | None:
    """The ``page_token`` to send for the next capp/* page, or None at the end.

    The document nests it as ``query_options.pagination.page_token`` ("is
    empty ... then there is no more results"); the flat
    ``query_options.page_token`` spelling of the collection service is read
    as a fallback. An empty token, or one identical to what was sent (no
    progress), means stop.
    """
    options = _dict(body.get("query_options"))
    token = _dict(options.get("pagination")).get("page_token", options.get("page_token"))
    if not isinstance(token, str) or not token or token == sent_token:
        return None
    return token


def _banner_icon(value: str) -> str:
    """Canonical BANNER_ICON_* spelling for a case-insensitive ``value``, or PlatformError."""
    wanted = value.strip().upper()
    if wanted not in BANNER_ICONS:
        raise PlatformError(f"Unknown icon '{value}'. Use one of: {_BANNER_ICON_CHOICES}.")
    return wanted


def _health_text(hs: dict[str, Any]) -> str:
    return (
        f"{hs.get('state', '?')} — {hs.get('healthy', '?')}/{hs.get('total', '?')} healthy, "
        f"{hs.get('degraded', '?')} degraded, {hs.get('down', '?')} down"
    )


def _resource_text(summary: Any) -> str:
    s = _dict(summary)
    if not s:
        return "?"
    return f"{s.get('current_usage', '?')} ({s.get('used', '?')} of {s.get('total', '?')})"


def _is_unhealthy(item: dict[str, Any]) -> bool:
    return str(item.get("health_state", "")).strip().lower() != "healthy"


def _microservice_line(ms: dict[str, Any], app: str | None) -> str:
    line = (
        f"- **{ms.get('Name', '?')}** app={app or '-'} health={ms.get('health_state', '?')} "
        f"up={ms.get('up_time') or '-'} version={ms.get('Version') or '-'}"
    )
    recommendation = str(ms.get("recommendation") or "").strip()
    if recommendation and recommendation.lower() != "none":
        line += f" — recommendation: {recommendation}"
    return line


def _more_hint(envelope: dict[str, Any]) -> list[str]:
    if envelope.get("has_more"):
        return ["", f"More available: repeat with page={envelope['next_page']}."]
    return []


def _user_record(key: str, u: dict[str, Any]) -> dict[str, Any]:
    """Whitelisted, snake_case view of one ``aaa/v1/user`` object.

    Delegates to the list tool's flattener so there is exactly one copy of
    the "never expose ``Password``" whitelist.
    """
    return _users_from_response({key: u})[0]


def _user_markdown(u: dict[str, Any]) -> str:
    full_name = " ".join(p for p in (u["first_name"], u["last_name"]) if p)
    groups = ", ".join(g for g in u["device_access_groups"] if g) or "none"
    line = f"**{u['username']}** — role {u['role'] or '?'}, status {u['status'] or '?'}"
    if full_name:
        line += f", name: {full_name}"
    return line + f", device access groups: {groups}"


def _cert_sort_key(cert: dict[str, Any]) -> tuple[int, float, str]:
    """Soonest expiry first; unparseable dates last, by name."""
    raw = cert.get("expiration_date")
    if isinstance(raw, str) and raw.strip():
        try:
            return (0, parsedate_to_datetime(raw.strip()).timestamp(), "")
        except (TypeError, ValueError):
            pass
    return (1, 0.0, str(cert.get("cert_name", "")))


def _banner_markdown(banner: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"Title: {banner.get('Title') or '-'}",
            f"Message: {banner.get('Message') or '-'}",
            f"Shown at login: {_yes_no(banner.get('ShowMessage'))}; "
            f"acknowledgement required: {_yes_no(banner.get('UserAck'))}; "
            f"icon: {banner.get('Icon') or '-'}",
        ]
    )


def _short_tgt(tgt: Any) -> str:
    text = str(tgt or "")
    return text[:_TGT_PREFIX] + "…" if len(text) > _TGT_PREFIX else text or "-"


def _masked_session(s: dict[str, Any]) -> dict[str, Any]:
    """Copy of an activeSessions row with its TgtId (a reusable credential) shortened.

    Every output format is built from these copies; the raw list is never
    handed back.
    """
    if "TgtId" not in s:
        return dict(s)
    return {**s, "TgtId": _short_tgt(s["TgtId"])}


def _session_line(s: dict[str, Any]) -> str:
    """One markdown line for an already-masked session row."""
    line = (
        f"- **{s.get('UserName', '?')}** since {s.get('LoginTime') or '-'} "
        f"via {s.get('LoginMethod') or '-'} from {s.get('ClientIp') or '-'} "
        f"(tgt {s.get('TgtId') or '-'})"
    )
    extras = [
        f"type {s['SessionType']}" if s.get("SessionType") else "",
        f"last activity {s['LastActivityTime']}" if s.get("LastActivityTime") else "",
    ]
    extras = [e for e in extras if e]
    if extras:
        line += f" [{', '.join(extras)}]"
    return line


def _password_policy_markdown(policy: dict[str, Any]) -> str:
    lines = ["# Password policy", ""]
    for key, template in _POLICY_ALWAYS_RULES:
        value = policy.get(key)
        if isinstance(value, bool):
            lines.append(f"- {template}: {_yes_no(value)}")
        elif value is not None:
            lines.append(f"- {template.format(value)}")
    for flag, key, template in _POLICY_GATED_RULES:
        enabled = policy.get(flag)
        value = policy.get(key)
        if enabled is True or (flag in _POLICY_ALWAYS_GATED and value is not None):
            line = f"- {template.format(value if value is not None else '?')}"
            if enabled is False:
                line += " (disabled)"
            lines.append(line)
    if len(lines) == 2:
        lines.append("No password rules reported.")
    return "\n".join(lines)


def _tasks_markdown(role: str, access: dict[str, Any], groups: list[dict[str, Any]]) -> str:
    lines = [
        f"# Role {role}",
        "",
        f"GUI access: {_yes_no(access.get('GuiAccess'))}, "
        f"API access: {_yes_no(access.get('ApiAccess'))}",
    ]
    if not groups:
        lines.extend(["", "No task groups returned for this role."])
    for group in groups:
        lines.extend(["", f"## {group.get('name') or '?'} ({group.get('id') or '?'})"])
        items = group.get("items")
        if isinstance(items, dict):  # documented ``rbacTaskItems`` wrapper, seen bare live
            items = items.get("items") or items.get("Items")
        for item in _dicts(items):
            box = "[x]" if item.get("enabled") is True else "[ ]"
            line = f"- {box} {item.get('name') or item.get('id') or '?'}"
            if item.get("permission"):
                line += f" ({item['permission']})"
            lines.append(line)
    return "\n".join(lines)


def _secured_apis_markdown(apis: dict[str, list[dict[str, Any]]], feature: str | None) -> str:
    total = sum(len(v) for v in apis.values())
    scope = f" matching '{feature}'" if feature else ""
    lines = [f"# Secured APIs ({total} in {len(apis)} feature(s){scope})", ""]
    if not apis:
        lines.append("No features matched.")
    for name in sorted(apis, key=str.lower):
        lines.append(f"## {name} ({len(apis[name])})")
        for api in apis[name]:
            lines.append(f"- {api.get('name') or '?'} ({api.get('api_id') or '?'})")
        lines.append("")
    return "\n".join(lines).rstrip()


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def fetch_microservices(app_id: str) -> list[dict[str, Any]]:
        """``micro_service`` rows for one application (``{}`` -> none, verified)."""
        data = await client.request_json("POST", MICROSERVICES_URL, json_body={"req_id": app_id})
        return _dicts(_dict(data).get("micro_service"))

    async def fetch_banner() -> dict[str, Any]:
        return _dict(await client.request_json("POST", BANNER_GET_URL, json_body={}))

    async def fetch_maintenance_status() -> dict[str, Any]:
        return _dict(await client.request_json("GET", MAINTENANCE_STATUS_URL))

    async def fetch_capp_pages(url: str, key: str, what: str) -> tuple[list[dict[str, Any]], bool]:
        """Every ``key`` row of a capp/* query across its ``page_token`` pages.

        Sends ``query_options.pagination`` with ``page_token ""`` first and
        follows each returned token until it is empty/unchanged, the page
        is empty, or CAPP_MAX_PAGES have been fetched. The second value is
        True when the platform still had a next page at the cap — the caller
        must say so, because its totals then cover only what was fetched.
        """
        rows: list[dict[str, Any]] = []
        token = ""
        for _ in range(CAPP_MAX_PAGES):
            data = await client.request_json("POST", url, json_body=_capp_page_body(token))
            body = _check_capp_result(data, what)
            page = _dicts(body.get(key))
            rows.extend(page)
            next_token = _capp_next_token(body, token)
            if not page or next_token is None:
                return rows, False
            token = next_token
        logger.warning(
            "%s: stopped after %d pages (%d rows); more remain on the server",
            what,
            CAPP_MAX_PAGES,
            len(rows),
        )
        return rows, True

    def _unfetched_note(what: str) -> list[str]:
        return [
            "",
            f"Warning: the platform still had more {what} after {CAPP_MAX_PAGES} pages "
            f"({CAPP_MAX_PAGES * CAPP_PAGE_SIZE} items); they were not fetched, so the "
            "counts above cover only the fetched pages.",
        ]

    # --- platform ------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_platform_version",
        title="Get Platform Version",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_platform_version() -> str:
        """Get the Crosswork platform product, version, build numbers, cluster type
        and status.

        Read-only. Use it first when a feature or API behaves unexpectedly — the
        answer tells you the product (CNC), the exact version (e.g. 7.2.0), the
        software and OVA builds, whether this is a SINGLE-VM or multi-node
        cluster and its STATUS. For the installed applications and their
        versions use cnc_list_applications instead.

        Returns:
            str: One line "Crosswork <PRODUCT> <VERSION> (build <BUILD>, OVA
            <OVA_BUILD>), cluster type <CLUSTER_TYPE>, status <STATUS>" followed
            by the JSON of result_map:
            {"BUILD": str, "CLUSTER_TYPE": "SINGLE"|..., "OVA_BUILD": str,
             "PRODUCT": "CNC", "STATUS": "ACTIVE"|..., "VERSION": str}
            On failure: "Error: <actionable message>" (a result other than
            R_SUCCESS is reported with the platform's description).
        """
        try:
            data = await client.request_json("GET", VERSION_URL)
            body = _check_cluster_result(data, "Version query")
            info = _dict(body.get("result_map"))
            if not info:
                raise PlatformError(
                    f"Version query returned no result_map. Response: {str(data)[:300]}"
                )
            line = (
                f"Crosswork {info.get('PRODUCT', '?')} {info.get('VERSION', '?')} "
                f"(build {info.get('BUILD', '?')}, OVA {info.get('OVA_BUILD', '?')}), "
                f"cluster type {info.get('CLUSTER_TYPE', '?')}, status {info.get('STATUS', '?')}"
            )
            return finalize(f"{line}\n\n{to_json(info)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_cluster_health",
        title="Get Cluster Health",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_cluster_health() -> str:
        """Get the overall health of the Crosswork cluster: the cluster summary,
        the infrastructure layer and every application's healthy/degraded/down
        pod counts, with unhealthy applications flagged first.

        Read-only. Use it as the first stop for "is Crosswork healthy?" and to
        find which application (capp-coe, capp-cdg, ...) has degraded or down
        pods before drilling into cnc_list_microservices for that app_id.
        Three GETs are made: cluster/summary/list, cluster/infra/summary and
        cluster/app/health/list. Application names are the ``obj_name`` of
        each health summary (the ``app_id`` other tools take).

        Returns:
            str: Markdown — a headline with the cluster state, the infra line,
            a "needs attention" line naming apps with degraded/down > 0 (or a
            note that all are healthy) and a table of every application — then
            the JSON:
            {"cluster_id": str, "state": "Healthy"|"Degraded"|"Down"|...,
             "ip_model": "IPV4"|..., "availability": str,
             "infra": {"state", "total", "healthy", "degraded", "down",
                       "obj_name", "availability"},
             "applications": [{"app": str, "state": str, "healthy": int,
                               "total": int, "degraded": int, "down": int,
                               "recommendation": str}, ...]}
            (unhealthy applications first, then alphabetical).
            On failure: "Error: <actionable message>".
        """
        try:
            summary_data, infra_data, apps_data = await asyncio.gather(
                client.request_json("GET", CLUSTER_SUMMARY_URL),
                client.request_json("GET", INFRA_SUMMARY_URL),
                client.request_json("GET", APP_HEALTH_URL),
            )
            cluster = _dict(_dict(summary_data).get("cluster_summary"))
            cluster_health = _dict(cluster.get("health_summary"))
            infra = _dict(_dict(infra_data).get("health_summary"))
            apps: list[dict[str, Any]] = []
            for entry in _dicts(_dict(apps_data).get("app_health_summary")):
                hs = _dict(entry.get("health_summary"))
                apps.append(
                    {
                        "app": hs.get("obj_name") or "?",
                        "state": hs.get("state") or "?",
                        "healthy": hs.get("healthy"),
                        "total": hs.get("total"),
                        "degraded": hs.get("degraded"),
                        "down": hs.get("down"),
                        "recommendation": entry.get("recommendation") or "",
                    }
                )

            def attention(app: dict[str, Any]) -> bool:
                return (
                    _int_or_zero(app["degraded"]) > 0
                    or _int_or_zero(app["down"]) > 0
                    or str(app["state"]).lower() != "healthy"
                )

            apps.sort(key=lambda a: (not attention(a), str(a["app"]).lower()))
            flagged = [a["app"] for a in apps if attention(a)]
            payload = {
                "cluster_id": cluster.get("cluster_id"),
                "state": cluster_health.get("state"),
                "ip_model": cluster.get("crosswork_ip_model"),
                "availability": cluster_health.get("availability"),
                "infra": infra,
                "applications": apps,
            }
            lines = [
                f"# Cluster health: {cluster_health.get('state', '?')} "
                f"(cluster {cluster.get('cluster_id', '?')}, IP model "
                f"{cluster.get('crosswork_ip_model', '?')}, availability "
                f"{cluster_health.get('availability', '?')})",
                "",
                f"Infrastructure ({infra.get('obj_name') or 'capp-infra'}): {_health_text(infra)}",
                "",
            ]
            if flagged:
                lines.append(
                    f"Needs attention ({len(flagged)}): " + ", ".join(flagged) + " — "
                    "see cnc_list_microservices(app_id=...) for the affected pods."
                )
            elif apps:
                lines.append(f"All {len(apps)} applications are healthy.")
            else:
                lines.append("No application health summaries were returned.")
            if apps:
                lines.extend(
                    [
                        "",
                        "| Application | State | Healthy | Degraded | Down | Recommendation |",
                        "|---|---|---|---|---|---|",
                    ]
                )
                for a in apps:
                    lines.append(
                        f"| {a['app']} | {a['state']} | {a['healthy']}/{a['total']} | "
                        f"{a['degraded']} | {a['down']} | {a['recommendation'] or '-'} |"
                    )
            return finalize("\n".join(lines) + "\n\n" + to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_cluster_nodes",
        title="List Cluster Nodes",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_cluster_nodes(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the Crosswork cluster's VM nodes with health, type, VM state and
        CPU / memory / disk usage.

        Read-only. Use it to find a node's ``node_id`` (its management IP, e.g.
        '192.0.2.21') for cnc_get_cluster_node / cnc_list_microservices, and
        to spot a node running hot. A single-VM deployment shows one HYBRID
        node. Resource figures are the platform's own text ("30 %", "2.40
        cores", "94.29 GB"); ``node_cpu_summary`` / ``node_mem_summary`` are the
        VM-level figures, ``cpu_summary`` / ``memory_summary`` the pod
        allocations.

        Returns:
            str: Markdown, one node per line (name, node_id, health, type, VM
            state, cpu/memory/disk "usage (used of total)", OS version), or
            JSON:
            {"count": int,
             "items": [{"node_name", "node_id", "node_health", "node_type",
                        "vm_name", "vm_state", "vm_id", "availability",
                        "vm_os_version",
                        "node_resource": {"cpu_summary": {"current_usage", "used",
                                                          "total", "thresholds"},
                                          "memory_summary", "disk_summary",
                                          "node_cpu_summary", "node_mem_summary",
                                          "last_updated_time"},
                        "actions": {"cancelJob", "deployVM", "eraseVM", "retry",
                                    "viewDetails"}}, ...]}
            On failure: "Error: <actionable message>".
        """
        try:
            data = await client.request_json("GET", NODE_SUMMARY_URL)
            nodes = _dicts(_dict(data).get("node_summary"))
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(nodes), "items": nodes}), settings)
            lines = [f"# Cluster nodes ({len(nodes)})", ""]
            if not nodes:
                lines.append("No nodes returned.")
            for n in nodes:
                res = _dict(n.get("node_resource"))
                lines.append(
                    f"- **{n.get('node_name', '?')}** (node_id {n.get('node_id', '?')}) "
                    f"health={n.get('node_health', '?')} type={n.get('node_type', '?')} "
                    f"vm={n.get('vm_state', '?')} "
                    f"cpu={_resource_text(res.get('cpu_summary'))} "
                    f"memory={_resource_text(res.get('memory_summary'))} "
                    f"disk={_resource_text(res.get('disk_summary'))} "
                    f"os={n.get('vm_os_version') or '-'}"
                )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_cluster_node",
        title="Get Cluster Node",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_cluster_node(
        node_id: Annotated[
            str,
            Field(
                description="Node id from cnc_list_cluster_nodes — the node's management IP "
                "(e.g. '192.0.2.21').",
                min_length=1,
                max_length=200,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one cluster node's details: network parameters (management / data
        IP), VM size profile, host and datastore, resource usage, the platform's
        recommendation and its microservices (pods), listing any that are not
        Healthy.

        Read-only. Use it after cnc_list_cluster_nodes to see where a node's
        data NIC points, how it is sized, and which of its pods are unhealthy.
        Sends {"node_id": ...} to cluster/dc/node/details/query. A blank
        node_id is refused before any request (the platform answers it with a
        500 "nodeId is empty"); what it answers for an unknown node id is not
        verified — the error is passed through as-is.

        Returns:
            str: Markdown (parameters, resources, recommendation, microservice
            count and the non-Healthy ones), or the raw JSON:
            {"node_name", "node_id", "vm_name", "vm_id", "vm_state",
             "node_parameters": {"status", "availability", "type",
                                 "size_profile": {"cpu", "memory", "disk"},
                                 "host", "data_store", "management_ip", "data_ip",
                                 "management_ip_v4", "data_ip_v4", ...},
             "node_resource": {...as cnc_list_cluster_nodes...},
             "node_recommendation": {"recommendation", "action"},
             "micro_service_list": {"micro_service": [{"Name", "health_state",
                                                       "up_time", "recommendation",
                                                       "Version", ...}]}}
            On failure: "Error: <actionable message>".
        """
        try:
            target = node_id.strip()
            if not target:
                raise PlatformError(
                    "node_id is empty: give the node's management IP from cnc_list_cluster_nodes."
                )
            data = await client.request_json(
                "POST", NODE_DETAILS_URL, json_body={"node_id": target}
            )
            node = _dict(data)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(node), settings)
            params = _dict(node.get("node_parameters"))
            profile = _dict(params.get("size_profile"))
            res = _dict(node.get("node_resource"))
            rec = _dict(node.get("node_recommendation"))
            services = _dicts(_dict(node.get("micro_service_list")).get("micro_service"))
            unhealthy = [ms for ms in services if _is_unhealthy(ms)]
            lines = [
                f"# Node {node.get('node_name', '?')} ({node.get('node_id', target)})",
                "",
                f"- status {params.get('status', '?')}, type {params.get('type', '?')}, "
                f"availability {params.get('availability', '?')}, VM {node.get('vm_state', '?')}",
                f"- management_ip {params.get('management_ip') or '-'}, "
                f"data_ip {params.get('data_ip') or '-'}",
                f"- size profile cpu={profile.get('cpu', '?')} memory={profile.get('memory', '?')} "
                f"disk={profile.get('disk', '?')}; host {params.get('host') or '-'}, "
                f"datastore {params.get('data_store') or '-'}",
                f"- cpu {_resource_text(res.get('cpu_summary'))}, "
                f"memory {_resource_text(res.get('memory_summary'))}, "
                f"disk {_resource_text(res.get('disk_summary'))}",
                f"- recommendation: {rec.get('recommendation') or 'None'}",
                f"- microservices: {len(services)} ({len(unhealthy)} not Healthy)",
            ]
            for ms in unhealthy:
                lines.append("  " + _microservice_line(ms, None))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_microservices",
        title="List Microservices",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_microservices(
        app_id: Annotated[
            str | None,
            Field(
                description="Application id to scope to (e.g. 'capp-coe'); the obj_name in "
                "cnc_get_cluster_health. Give at most one of app_id / node_id.",
                max_length=200,
            ),
        ] = None,
        node_id: Annotated[
            str | None,
            Field(
                description="Node id (management IP, e.g. '192.0.2.21') to scope to. "
                "Give at most one of app_id / node_id.",
                max_length=200,
            ),
        ] = None,
        health: Annotated[
            str | None,
            Field(
                description=f"Keep only microservices whose health_state is this value, "
                f"case-insensitive: one of {_HEALTH_CHOICES} (e.g. 'degraded').",
                max_length=20,
            ),
        ] = None,
        page_size: Annotated[
            int,
            Field(
                description=f"Microservices per page (e.g. {MICROSERVICE_PAGE_SIZE}). Paged "
                "client-side over the fetched list. JSON rows are ~700 characters, so the "
                f"default keeps a full JSON page under the 40 000-character response cap; "
                f"markdown lines are ~100 characters, so page_size={MICROSERVICE_MAX_PAGE_SIZE} "
                "lists a whole platform in one markdown call.",
                ge=1,
                le=MICROSERVICE_MAX_PAGE_SIZE,
            ),
        ] = MICROSERVICE_PAGE_SIZE,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List Crosswork microservices (pods) with health, container age and version —
        for one application, for one node, or for the whole platform — paged.

        Read-only. Use it to find the unhealthy pod behind a degraded
        application (health='degraded' or 'down'), to confirm a pod came back
        after a restart (its ``up_time`` restarts from zero), or to learn the
        exact ``Name`` that cnc_restart_microservice takes. ``up_time`` is the
        pod's CONTAINER AGE — time since the container was last created or
        restarted — NOT time since it was last healthy (observed live
        2026-09-14: cwm-api-service, optima-lcm and optima-ddm read 208d while
        Major alarms recorded them down 37 days earlier; the replaced
        cwm-worker read 1d). A health=down episode therefore leaves
        ``up_time`` untouched; use the alarm history (cnc_list_alarms /
        cnc_search_alarms) for when a pod was unhealthy, and ``up_time`` only
        for when it was last (re)started. Scope:
        - app_id: POST cluster/microservice/list/query {"req_id": app_id};
          an unknown app answers {} which reads as "no microservices".
        - node_id: POST cluster/dc/node/details/query {"node_id"} and its
          micro_service_list (app is unknown in this view and shown as '-').
        - neither: POST capp/installedapplicationid/query {} for the installed
          application ids, then one microservice query per application (ten on
          a single-VM CNC), each row tagged with its app.
        The health filter and the paging are applied client-side: the platform
        has no paging on these endpoints, so the whole scope is fetched every
        call and ``page_size`` / ``page`` (0-based) cut a window out of it.
        The default page_size of 40 exists because JSON rows are ~700
        characters (verified live 2026-09-14: 109 pods across ten applications
        are 85 000 characters unpaged, well past the 40 000-character response
        cap) — markdown lines are ~100 characters, so page_size=500 lists a
        whole platform in one markdown call.

        Args:
            app_id / node_id: scope (at most one). health: client-side filter.
            page_size / page: client-side paging; ``has_more`` / ``next_page``
                (JSON) or "More available: repeat with page=N" (markdown) say
                when to continue.

        Returns:
            str: Markdown, one line per microservice:
            "**Name** app=<app> health=<health_state> up=<up_time> version=<Version>"
            plus "— recommendation: ..." when the platform has one; or JSON
            (page-based — exactly these keys, no offset/next_offset):
            {"total": <matching microservices>, "count": <on this page>,
             "page": int, "page_size": int, "has_more": bool, "next_page": int|null,
             "collection_total": <fetched before the health filter>,
             "items": [{"app": str|null, "Name", "health_state": "Healthy"|...,
                        "up_time": "207d 11h 30m 10s" (container age), "recommendation",
                        "description", "is_dynamic", "Version", "version_history",
                        "micro_service_action": {"actions": [{"action_name",
                                                              "action_id"}]}}]}
            "No microservices ..." / "Page N is past the end ..." (not errors)
            when nothing is on the page. On failure: "Error: <actionable
            message>".
        """
        try:
            app, node = _clean(app_id), _clean(node_id)
            if app and node:
                raise PlatformError("Give at most one of app_id and node_id, not both.")
            wanted = _clean(health).lower()
            if wanted and wanted not in HEALTH_STATES:
                raise PlatformError(f"Unknown health '{health}'. Use one of: {_HEALTH_CHOICES}.")
            rows: list[dict[str, Any]] = []
            if app:
                scope = f"application {app}"
                rows = [{"app": app, **ms} for ms in await fetch_microservices(app)]
            elif node:
                scope = f"node {node}"
                data = await client.request_json(
                    "POST", NODE_DETAILS_URL, json_body={"node_id": node}
                )
                services = _dict(_dict(data).get("micro_service_list")).get("micro_service")
                rows = [{"app": None, **ms} for ms in _dicts(services)]
            else:
                scope = "all applications"
                data = await client.request_json("POST", INSTALLED_APP_IDS_URL, json_body={})
                body = _check_capp_result(data, "Installed application query")
                ids = _dict(body.get("installed_application_ids")).get("application_ids")
                app_ids = (
                    [a for a in ids if isinstance(a, str) and a] if isinstance(ids, list) else []
                )
                logger.debug("Listing microservices for %d applications", len(app_ids))
                per_app = await asyncio.gather(*(fetch_microservices(a) for a in app_ids))
                for app, services in zip(app_ids, per_app, strict=True):
                    rows.extend({"app": app, **ms} for ms in services)
            fetched = len(rows)
            if wanted:
                rows = [r for r in rows if str(r.get("health_state", "")).lower() == wanted]
            start = page * page_size
            shown = rows[start : start + page_size]
            envelope = page_envelope(
                shown,
                result_count=len(rows),
                total_count=fetched,
                page_size=page_size,
                page=page,
            )
            # The paging here is page/page_size (client-side); the offset-style keys the
            # shared envelope also carries are dropped so the JSON matches the documented
            # schema and offers no second, unsupported way to page.
            for key in _OFFSET_KEYS:
                envelope.pop(key, None)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings, hint=_MICROSERVICES_HINT)
            suffix = f", health={wanted}" if wanted else ""
            if len(shown) == len(rows):
                heading = f"# Microservices ({len(rows)}; {scope}{suffix})"
            else:
                heading = (
                    f"# Microservices ({len(shown)} shown of {len(rows)}, page {page}; "
                    f"{scope}{suffix})"
                )
            lines = [heading, ""]
            if not rows:
                lines.append(f"No microservices for {scope}{suffix}.")
            elif not shown:
                last = (len(rows) - 1) // page_size
                lines.append(
                    f"Page {page} is past the end: {len(rows)} microservices for {scope}"
                    f"{suffix} fill pages 0-{last} at page_size={page_size}."
                )
            lines.extend(_microservice_line(r, r.get("app")) for r in shown)
            lines.extend(_more_hint(envelope))
            return finalize("\n".join(lines), settings, hint=_MICROSERVICES_HINT)
        except Exception as e:
            return format_error(e)

    # --- application manager -------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_application_status",
        title="List Application Status",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_application_status(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the application manager's view of every application: lifecycle
        status (ACTIVE, ACTIVATING, INACTIVE, *_FAILED, ...), version, progress,
        the actions currently possible, any pending action and the last
        operation error.

        Read-only. Use it when an application is being installed, activated,
        updated or deactivated (or such an operation failed) — it shows the
        lifecycle state, whereas cnc_get_cluster_health shows pod health and
        cnc_list_applications shows the catalogue entry. Sends {} to
        capp/applicationstatus/query.

        Returns:
            str: Markdown, one line per application ("**capp-coe** 7.2.0 ACTIVE
            (progress 100) — actions: DEACTIVATE, UPDATE" plus "pending: <action>
            (job <id>)" unless UNKNOWN_ACTION, and "last error: ..." when set),
            or JSON:
            {"count": int,
             "items": [{"application_id", "version", "install_id",
                        "status": "ACTIVE"|..., "progress": number,
                        "possible_actions": [str], "available_updates": [...],
                        "pending_action": {"action", "job_id"},
                        "last_operation_error": {"message"}}, ...]}
            On failure: "Error: <actionable message>".
        """
        try:
            data = await client.request_json("POST", APP_STATUS_URL, json_body={})
            body = _check_capp_result(data, "Application status query")
            apps = _dicts(body.get("application_states"))
            apps.sort(key=lambda a: str(a.get("application_id", "")).lower())
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(apps), "items": apps}), settings)
            lines = [f"# Application status ({len(apps)})", ""]
            if not apps:
                lines.append("No application states returned.")
            for a in apps:
                line = (
                    f"- **{a.get('application_id', '?')}** {a.get('version') or '-'} "
                    f"{a.get('status', '?')} (progress {a.get('progress', '?')})"
                )
                actions = [x for x in a.get("possible_actions") or [] if isinstance(x, str)]
                if actions:
                    line += f" — actions: {', '.join(actions)}"
                pending = _dict(a.get("pending_action"))
                if pending.get("action") and pending["action"] != UNKNOWN_ACTION:
                    line += f"; pending: {pending['action']}"
                    if pending.get("job_id"):
                        line += f" (job {pending['job_id']})"
                error = _dict(a.get("last_operation_error")).get("message")
                if isinstance(error, str) and error.strip():
                    line += f"\n  - last error: {error.strip()}"
                lines.append(line)
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_app_manager_jobs",
        title="List Application Manager Jobs",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_app_manager_jobs(
        limit: Annotated[
            int, Field(description="Newest jobs to return (e.g. 20).", ge=1, le=200)
        ] = 20,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List application manager jobs (install / activate / update /
        deactivate operations, ids like 'AJ41'), newest first.

        Read-only. Use it to see when applications were last (re)activated or
        updated, who did it and whether it failed. Sends the documented
        {"query_options": {"pagination": {"page_token": "", "page_size": 100}}}
        to capp/jobs/query and follows the returned page_token (up to 20
        pages / 2000 jobs — the lab answered a {} body with one page, so
        whether this build pages at all is unverified). Everything fetched is
        sorted by start_time descending client-side, then cut to ``limit``;
        ``total`` / ``has_more`` count the fetched jobs. These are NOT the
        inventory jobs of device/credential writes — see
        cnc_list_inventory_jobs for those.

        Returns:
            str: Markdown, one line per job ("**AJ41** JOB_COMPLETED — <job_type>
            (progress 100, started <ISO>, completed <ISO>, by admin)" plus
            "error: ..." when set), or JSON:
            {"total": int, "count": int, "limit": int, "has_more": bool,
             "more_on_server": bool (true only when the platform still had
                                     pages after the 20-page cap; a warning
                                     line says so in markdown),
             "items": [{"job_id", "job_user", "start_time" (epoch ms string),
                        "completion_time", "progress", "job_status":
                        "JOB_COMPLETED"|"JOB_FAILED"|"JOB_IN_PROGRESS"|...,
                        "job_type": {"job_type": str}, "error": {"message"},
                        "owner_type", "description"}, ...]}
            On failure: "Error: <actionable message>".
        """
        try:
            entries, more_on_server = await fetch_capp_pages(
                APP_JOBS_URL, "jobs", "Application job query"
            )
            jobs = [_dict(entry.get("job")) for entry in entries]
            jobs = [j for j in jobs if j]
            jobs.sort(key=lambda j: _int_or_zero(j.get("start_time")), reverse=True)
            items = jobs[:limit]
            envelope = {
                "total": len(jobs),
                "count": len(items),
                "limit": limit,
                "has_more": len(jobs) > limit,
                "more_on_server": more_on_server,
                "items": items,
            }
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings, hint=_LIMIT_HINT)
            lines = [f"# Application manager jobs ({len(items)} of {len(jobs)}, newest first)", ""]
            if not items:
                lines.append("No application manager jobs returned.")
            for j in items:
                job_type = _dict(j.get("job_type")).get("job_type") or "-"
                details = [
                    f"progress {j['progress']}" if j.get("progress") is not None else "",
                    f"started {epoch_iso(j.get('start_time'))}",
                    f"completed {epoch_iso(j.get('completion_time'))}"
                    if _int_or_zero(j.get("completion_time")) > 0
                    else "",
                    f"by {j['job_user']}" if j.get("job_user") else "",
                ]
                line = (
                    f"- **{j.get('job_id', '?')}** {j.get('job_status', '?')} — {job_type} "
                    f"({', '.join(d for d in details if d)})"
                )
                if j.get("description"):
                    line += f": {j['description']}"
                error = _dict(j.get("error")).get("message")
                if isinstance(error, str) and error.strip():
                    line += f"\n  - error: {error.strip()}"
                lines.append(line)
            if envelope["has_more"]:
                lines.extend(["", f"{len(jobs) - limit} older job(s) not shown; raise limit."])
            if more_on_server:
                lines.extend(_unfetched_note("jobs"))
            return finalize("\n".join(lines), settings, hint=_LIMIT_HINT)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_app_manager_events",
        title="List Application Manager Events",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_app_manager_events(
        limit: Annotated[
            int, Field(description="Newest events to return (e.g. 50).", ge=1, le=500)
        ] = 50,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List application manager events — the step-by-step messages emitted
        while applications are installed, activated, updated or removed —
        newest first.

        Read-only. Use it to follow or post-mortem an application operation:
        each event carries tags linking it to the job (JOB_ID_EVENT=AJ41),
        application (APPLICATION_ID_EVENT), package file or pod. Sends the
        documented {"query_options": {"pagination": {"page_token": "",
        "page_size": 100}}} to capp/events/query and follows the returned
        page_token (up to 20 pages / 2000 events; the lab answered a {} body
        with one page, so whether this build pages is unverified). Everything
        fetched is sorted by event_time descending client-side and cut to
        ``limit``; ``total`` / ``has_more`` count the fetched events.

        Returns:
            str: Markdown, one line per event ("- <ISO time> <message>
            [JOB_ID_EVENT=AJ41, APPLICATION_ID_EVENT=capp-coe]"), or JSON:
            {"total": int, "count": int, "limit": int, "has_more": bool,
             "more_on_server": bool (true only when the platform still had
                                     pages after the 20-page cap; a warning
                                     line says so in markdown),
             "items": [{"event_tags": [{"tag_type": "JOB_ID_EVENT"|
                                        "APPLICATION_ID_EVENT"|"FILE_ID_EVENT"|
                                        "DEPLOYMENT_ID_EVENT", "tag_value"}],
                        "message": str, "event_time": "<epoch ms>"}, ...]}
            On failure: "Error: <actionable message>".
        """
        try:
            events, more_on_server = await fetch_capp_pages(
                APP_EVENTS_URL, "events", "Application event query"
            )
            events.sort(key=lambda e: _int_or_zero(e.get("event_time")), reverse=True)
            items = events[:limit]
            envelope = {
                "total": len(events),
                "count": len(items),
                "limit": limit,
                "has_more": len(events) > limit,
                "more_on_server": more_on_server,
                "items": items,
            }
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings, hint=_LIMIT_HINT)
            lines = [
                f"# Application manager events ({len(items)} of {len(events)}, newest first)",
                "",
            ]
            if not items:
                lines.append("No application manager events returned.")
            for e in items:
                tags = ", ".join(
                    f"{t.get('tag_type', '?')}={t.get('tag_value', '?')}"
                    for t in _dicts(e.get("event_tags"))
                )
                line = f"- {epoch_iso(e.get('event_time'))} {e.get('message') or '-'}"
                if tags:
                    line += f" [{tags}]"
                lines.append(line)
            if envelope["has_more"]:
                lines.extend(["", f"{len(events) - limit} older event(s) not shown; raise limit."])
            if more_on_server:
                lines.extend(_unfetched_note("events"))
            return finalize("\n".join(lines), settings, hint=_LIMIT_HINT)
        except Exception as e:
            return format_error(e)

    # --- maintenance / certificates / banner ----------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_maintenance_status",
        title="Get Maintenance Status",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_maintenance_status() -> str:
        """Get the platform's maintenance-mode state, any pending upgrade-manager
        action and the cluster balancer status.

        Read-only. Use it before a backup/restore or upgrade, or when
        collection and services seem paused: maintenance mode
        (Maintenance_Mode_On / *_In_Progress) suspends normal operations, the
        upgrade manager may be waiting on an acknowledgement (action CDG_ACK)
        and the balancer reports a rebalance in progress. Three GETs:
        platform/maintenance/status, upgrademanager, platform/balancer/status.

        Returns:
            str: One markdown line, then JSON:
            {"maintenance_mode": "Maintenance_Mode_Off"|"Maintenance_Mode_On"|
                                 "Maintenance_Mode_On_In_Progress"|
                                 "Maintenance_Mode_Off_In_Progress",
             "last_updated": str, "message": str,
             "upgrade_action": "None"|"CDG_ACK", "upgrade_message": str,
             "balancer": {"Status": "Off"|"Created"|"InProgress"|"Completed"|
                          "Failed"|"NoOpNoRecommendation"|"NoOpRecommendAddNode",
                          "NumberOfTasks": int, "Tasks": [...], "Timeout": str}}
            On failure: "Error: <actionable message>".
        """
        try:
            status, upgrade, balancer = await asyncio.gather(
                fetch_maintenance_status(),
                client.request_json("GET", UPGRADE_MANAGER_URL),
                client.request_json("GET", BALANCER_STATUS_URL),
            )
            upgrade = _dict(upgrade)
            balancer = _dict(balancer)
            payload = {
                "maintenance_mode": status.get("status"),
                "last_updated": status.get("lastUpdated"),
                "message": status.get("message"),
                "upgrade_action": upgrade.get("action"),
                "upgrade_message": upgrade.get("message"),
                "balancer": balancer,
            }
            line = (
                f"Maintenance mode: {status.get('status') or '?'} "
                f"(last updated {status.get('lastUpdated') or '-'}"
                f"{'; ' + status['message'] if status.get('message') else ''}); "
                f"upgrade action: {upgrade.get('action') or '?'}; "
                f"balancer: {balancer.get('Status') or '?'} "
                f"({balancer.get('NumberOfTasks', 0)} task(s))"
            )
            return finalize(f"{line}\n\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_certificates",
        title="List Certificates",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_certificates(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the certificates Crosswork manages (web server, internal TLS,
        device syslog, ...) with their role, auth type, expiry and last update,
        soonest expiry first.

        Read-only. Use it to see when the web certificate or the internal ones
        expire and who last replaced them; cnc_check_certificate_expiry gives
        the platform's own renewal verdict. GET cert/summary/list; sorted
        client-side by expiration_date (RFC 1123 text such as "Sun, 16 Feb 2031
        23:47:42 UTC"; unparseable dates sort last).

        Returns:
            str: Markdown, one line per certificate, or JSON:
            {"count": int,
             "items": [{"cert_name", "role_name", "magnetic_role_name",
                        "auth_type": "MUTUAL_AUTH"|..., "cert_display":
                        "READONLY"|"READWRITE", "expiration_date",
                        "last_update_time", "last_updated_by",
                        "assoc_summary": {"role_name", "magnetic_role_name"}}, ...]}
            On failure: "Error: <actionable message>".
        """
        try:
            data = await client.request_json("GET", CERT_SUMMARY_URL)
            certs = _dicts(_dict(data).get("cert_summary"))
            certs.sort(key=_cert_sort_key)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(certs), "items": certs}), settings)
            lines = [f"# Certificates ({len(certs)}, soonest expiry first)", ""]
            if not certs:
                lines.append("No certificates returned.")
            for c in certs:
                lines.append(
                    f"- **{c.get('cert_name', '?')}** role={c.get('role_name') or '-'} "
                    f"auth={c.get('auth_type') or '-'} display={c.get('cert_display') or '-'} "
                    f"expires {c.get('expiration_date') or '?'} "
                    f"(updated {c.get('last_update_time') or '-'} "
                    f"by {c.get('last_updated_by') or '-'})"
                )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_check_certificate_expiry",
        title="Check Certificate Expiry",
        read_only=True,
        idempotent=True,
    )
    async def cnc_check_certificate_expiry() -> str:
        """Ask the platform whether its internal certificates need renewing.

        Read-only. Use it as the yes/no health check for certificate expiry;
        cnc_list_certificates gives the full dates. GET cert/renew/check-expiry.
        Renewal itself (PUT cert/renew) is not exposed.

        Returns:
            str: "Certificate renewal is not required." or "Renewal REQUIRED:
            <message> (<certificate_name>, <remaining_days> days)", then the
            JSON: {"cert_renewal_required": bool, "message": str,
            "certificate_name": str, "remaining_days": str}.
            On failure: "Error: <actionable message>".
        """
        try:
            data = _dict(await client.request_json("GET", CERT_EXPIRY_URL))
            if data.get("cert_renewal_required") is True:
                line = (
                    f"Renewal REQUIRED: {data.get('message') or 'no message'} "
                    f"({data.get('certificate_name') or '?'}, "
                    f"{data.get('remaining_days', '?')} days)"
                )
            else:
                line = "Certificate renewal is not required."
                if data.get("message"):
                    line += f" ({data['message']})"
            return finalize(f"{line}\n\n{to_json(data)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_login_banner",
        title="Get Login Banner",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_login_banner() -> str:
        """Get the login banner shown on the Crosswork UI sign-in page: title,
        message, whether it is shown and whether users must acknowledge it.

        Read-only. POST cluster/banner/get with {} (the endpoint takes no
        body). Change it with cnc_set_login_banner.

        Returns:
            str: Markdown "Title / Message / Shown at login / acknowledgement
            required / icon", then the JSON:
            {"ShowMessage": bool, "UserAck": bool, "Message": str,
             "Icon": "BANNER_ICON_INFO"|"BANNER_ICON_IMPORTANT"|
                     "BANNER_ICON_CRITICAL", "Title": str}
            On failure: "Error: <actionable message>".
        """
        try:
            banner = await fetch_banner()
            return finalize(f"{_banner_markdown(banner)}\n\n{to_json(banner)}", settings)
        except Exception as e:
            return format_error(e)

    # --- RBAC ------------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_session_config",
        title="Get Session Config",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_session_config() -> str:
        """Get the user-session limits (idle timeout, parallel sessions per
        user and in total, remote-auth fallback) and whether the calling
        account may list/terminate sessions.

        Read-only. Why it matters: every login (including this server's) holds
        one session until it times out or is closed. Once a user has
        NumParallelSessionsPerUser open sessions, further logins fail with 503
        'Per user session limit reached' — a service account can lock itself
        out by leaking sessions. This server releases its session on close;
        sessions leaked by other clients drain only after IdleSessionTimeout
        (IdleSessionTimeoutAPI for API sessions where the build reports one).
        Use cnc_list_active_sessions to see who holds sessions. Two GETs:
        aaa/v1/sessionconfig and aaa/v1/getSessionMgmtPermissions.

        Returns:
            str: One markdown line ("idle timeout <n> min, <n> parallel sessions
            per user (<n> total), fallback <type>; this user may list/terminate
            sessions: yes/no"), then the merged JSON:
            {"IdleSessionTimeout": int (minutes), "IdleSessionTimeoutAPI": int?,
             "NumParallelSessions": int, "NumParallelSessionsPerUser": int,
             "FallbackType": str, "enableDAG": bool,
             "ListAllowedForUser": bool, "TerminateAllowedForUser": bool}
            On failure: "Error: <actionable message>".
        """
        try:
            config, permissions = await asyncio.gather(
                client.request_json("GET", SESSION_CONFIG_URL),
                client.request_json("GET", SESSION_PERMISSIONS_URL),
            )
            merged = {**_dict(config), **_dict(permissions)}
            idle = f"idle timeout {merged.get('IdleSessionTimeout', '?')} min"
            if merged.get("IdleSessionTimeoutAPI") is not None:
                idle += f" (API sessions {merged['IdleSessionTimeoutAPI']} min)"
            line = (
                f"Sessions: {idle}, "
                f"{merged.get('NumParallelSessionsPerUser', '?')} parallel sessions per user "
                f"({merged.get('NumParallelSessions', '?')} total), "
                f"fallback {merged.get('FallbackType') or '-'}; this user may list sessions: "
                f"{_yes_no(merged.get('ListAllowedForUser'))}, terminate sessions: "
                f"{_yes_no(merged.get('TerminateAllowedForUser'))}"
            )
            return finalize(f"{line}\n\n{to_json(merged)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_active_sessions",
        title="List Active Sessions",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_active_sessions(
        username: Annotated[
            str | None,
            Field(
                description="Keep only this user's sessions (exact username, case-insensitive, "
                "e.g. 'admin'). Applied client-side.",
                max_length=200,
            ),
        ] = None,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the active user sessions on Crosswork (UI and API logins) with
        login time, method and client IP, counted per user.

        Read-only. Use it to see who is holding sessions when a login fails
        with 'Per user session limit reached', and to spot leaked API sessions
        (they show the gateway's node IP as ClientIp). There is NO API to
        terminate a session: an administrator does that in the UI
        (Administration > Users and Roles > Active Sessions) — the
        TerminateAllowedForUser flag from cnc_get_session_config only says
        whether the account may. GET aaa/v1/activeSessions; the username
        filter is applied client-side. The TgtId is shortened to its first 12
        characters plus "…" in BOTH formats: a TGT is a credential (POST
        sso/v1/tickets/<TGT> mints a fresh JWT for that user without a
        password, DELETE ends the session), so the whole value is never
        returned.

        Returns:
            str: Markdown with a per-user count in the header and one line per
            session, or JSON:
            {"count": int, "per_user": {"<username>": int, ...},
             "items": [{"UserName", "LoginTime" (ISO), "LoginMethod": "Local"|...,
                        "TgtId" (shortened, e.g. "TGT-5-abcdef…"), "ClientIp",
                        "SessionType"?, "LastActivityTime"?}, ...]}
            On failure: "Error: <actionable message>" (403 -> the account
            lacks the session-management privilege).
        """
        try:
            data = await client.request_json("GET", ACTIVE_SESSIONS_URL)
            sessions = [_masked_session(s) for s in _dicts(data)]
            wanted_user = _clean(username)
            if wanted_user:
                sessions = [
                    s for s in sessions if str(s.get("UserName", "")).lower() == wanted_user.lower()
                ]
            per_user = Counter(str(s.get("UserName") or "?") for s in sessions)
            if response_format is ResponseFormat.JSON:
                payload = {"count": len(sessions), "per_user": dict(per_user), "items": sessions}
                return finalize(to_json(payload), settings)
            counts = ", ".join(f"{u} {n}" for u, n in sorted(per_user.items()))
            lines = [f"# Active sessions ({len(sessions)}{': ' + counts if counts else ''})", ""]
            if not sessions:
                scope = f" for user '{wanted_user}'" if wanted_user else ""
                lines.append(f"No active sessions{scope}.")
            lines.extend(_session_line(s) for s in sessions)
            lines.extend(["", "Sessions cannot be terminated through the API; use the UI."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_user",
        title="Get User",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_user(
        username: Annotated[
            str,
            Field(
                description="Exact Crosswork username (e.g. 'admin'); case as stored.",
                min_length=1,
                max_length=200,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one local user account: role (PolicyId), name, status and device
        access groups.

        Read-only. Use it to confirm an account exists and which role it
        carries before troubleshooting a login or permission problem. GET
        aaa/v1/user/<username> (URL-encoded). An unknown user is answered by
        the platform with 500 {"error": "Invalid Username"} (verified), which
        this tool renders as "Error: no user '<name>'". The Password field the
        API returns (always empty) is never included.

        Returns:
            str: Markdown "**<username>** — role <role>, status <status>, name:
            <first last>, device access groups: <a, b>", or JSON:
            {"username": str, "role": str, "first_name": str, "last_name": str,
             "status": "Active"|..., "device_access_groups": [str, ...]}
            "Error: no user '<name>' (list with cnc_list_users)" when unknown;
            other failures: "Error: <actionable message>".
        """
        try:
            name = username.strip()
            if not name:
                raise PlatformError("username is empty: give a username from cnc_list_users.")
            response = await client.request(
                "GET", f"{USER_URL}/{quote(name, safe='')}", raise_on_error=False
            )
            if response.status_code == 500 and "invalid username" in response.text.lower():
                raise PlatformError(f"no user '{name}' (list with cnc_list_users)")
            if not response.is_success:
                raise http_error(response)
            try:
                data = response.json() if response.content else {}
            except ValueError as e:
                raise PlatformError(
                    "Crosswork returned a non-JSON response where the user object was expected."
                ) from e
            user = _user_record(name, _dict(data))
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(user), settings)
            return finalize(_user_markdown(user), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_roles",
        title="List Roles",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_roles(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the RBAC roles (admin, operator, read-only, ...) with how many
        API grants each carries and its rate limit.

        Read-only. Use it to learn the role names that cnc_get_role_tasks /
        cnc_get_role_permissions take and that users carry as PolicyId. GET
        aaa/v1/role answers a dict keyed by role name whose ``access_rights``
        map (one entry per secured API) is large: markdown summarises it,
        json returns the raw object and may be truncated.

        Returns:
            str: Markdown "**<name>** — <n> API grants, rate <rate>/<per>s"
            per role ("(inactive)" when is_inactive), or the raw JSON:
            {"<role name>": {"id"|"name", "org_id", "rate", "per", "quota_max",
                             "active", "is_inactive", "tags", "access_rights":
                             {"<api_id>": {"api_name", "api_id", "versions",
                                           "allowed_urls": [{"url", "methods"}]}},
                             ...}, ...}
            On failure: "Error: <actionable message>".
        """
        try:
            data = await client.request_json("GET", ROLES_URL)
            roles = _dict(data)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(roles), settings, hint=_ROLES_HINT)
            lines = [f"# Roles ({len(roles)})", ""]
            if not roles:
                lines.append("No roles returned.")
            for key in sorted(roles, key=str.lower):
                r = _dict(roles[key])
                grants = len(_dict(r.get("access_rights")))
                line = (
                    f"- **{r.get('name') or r.get('id') or key}** — {grants} API grants, "
                    f"rate {r.get('rate', '?')}/{r.get('per', '?')}s"
                )
                if r.get("is_inactive") is True or r.get("active") is False:
                    line += " (inactive)"
                lines.append(line)
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_role_tasks",
        title="Get Role Tasks",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_role_tasks(
        role: Annotated[
            str,
            Field(
                description="Role name from cnc_list_roles (e.g. 'admin').",
                min_length=1,
                max_length=200,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get a role's task permissions — the UI's per-feature checkboxes
        (audit logs, device management, topology, ...), grouped — plus whether
        the role has GUI and API access.

        Read-only. Use it to answer "can role X do Y?" in the terms the UI
        uses. Two GETs: aaa/v1/usertask/<role> (task groups with each item's
        enabled flag and permission key) and aaa/v1/roleAccess/<role>
        (GuiAccess / ApiAccess). What the platform answers for an unknown role
        is NOT verified: the error is passed through as the platform gave it.

        Returns:
            str: Markdown — "GUI access: yes/no, API access: yes/no", then per
            group "## <group name> (<id>)" with "- [x]/[ ] <item> (<permission>)"
            lines — or JSON:
            {"role": str,
             "access": {"PolicyId", "GuiAccess": bool, "ApiAccess": bool,
                        "PolicyData"},
             "tasks": [{"id", "name", "items": [{"id", "name", "description",
                                                 "enabled": bool, "permission"}]}]}
            On failure: "Error: <actionable message>".
        """
        try:
            name = role.strip()
            if not name:
                raise PlatformError("role is empty: give a role name from cnc_list_roles.")
            encoded = quote(name, safe="")
            tasks_data, access_data = await asyncio.gather(
                client.request_json("GET", f"{USERTASK_URL}/{encoded}"),
                client.request_json("GET", f"{ROLE_ACCESS_URL}/{encoded}"),
            )
            groups = _dicts(tasks_data)
            access = _dict(access_data)
            if response_format is ResponseFormat.JSON:
                payload = {"role": name, "access": access, "tasks": groups}
                return finalize(to_json(payload), settings)
            return finalize(_tasks_markdown(name, access, groups), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_role_permissions",
        title="Get Role Permissions",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_role_permissions(
        role: Annotated[
            str | None,
            Field(
                description="Role name from cnc_list_roles (e.g. 'admin'). Leave unset for "
                "the calling account's own role.",
                max_length=200,
            ),
        ] = None,
    ) -> str:
        """Get the flat list of permission keys a role holds (dag_management,
        view_audit_logs, ...), or the calling account's own.

        Read-only. Use it for a quick "does this role have permission X" check;
        cnc_get_role_tasks shows the same permissions grouped as the UI does.
        GET aaa/v1/userpermission (own role) or aaa/v1/userpermission/<role>.
        What the platform answers for an unknown role is NOT verified.

        Returns:
            str: "role <role> has <n> permissions: a, b, c" (or "the calling
            account's role has ...") followed by the JSON list of permission
            strings. On failure: "Error: <actionable message>".
        """
        try:
            name = _clean(role)
            if name:
                data = await client.request_json(
                    "GET", f"{USER_PERMISSION_URL}/{quote(name, safe='')}"
                )
                label = f"role {name}"
            else:
                data = await client.request_json("GET", USER_PERMISSION_URL)
                label = "the calling account's role"
            permissions = sorted(
                (p for p in data if isinstance(p, str)) if isinstance(data, list) else []
            )
            line = f"{label} has {len(permissions)} permissions"
            line += f": {', '.join(permissions)}" if permissions else "."
            return finalize(f"{line}\n\n{to_json(permissions)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_password_policy",
        title="Get Password Policy",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_password_policy() -> str:
        """Get the local password policy: length and composition rules, reuse
        and expiry limits, lockout thresholds and first-login change.

        Read-only. Use it to explain why a password was rejected or an account
        got locked (FailedLoginsBeforeLockout / LockOutUserTime). GET
        aaa/v1/passwordPolicyConfig. The markdown lists MinPasswordLength,
        NoUsername, NoCiscoVariant, NoCharRepetition, ChangePasswdOnFirstLogin
        and the lockout pair always, and each other rule only when its
        *Enable flag is true; the JSON is the raw object.

        Returns:
            str: Markdown rule list, then JSON:
            {"MinPasswordLength": n, "NoUsername": bool, "NoCiscoVariant": bool,
             "NoCharRepetition": bool, "NumChangedCharsEnable": bool,
             "NumChangedChars": n, "NumReuseLimitEnable", "NumReuseLimit",
             "PasswordReuseDaysEnable", "PasswordReuseDays",
             "FailedLoginsBefLoEnable", "FailedLoginsBeforeLockout",
             "LockOutUserTimeEnable", "LockOutUserTime" (minutes),
             "PasswordExpiryDaysEnable", "PasswordExpiryDays",
             "DaysForWarningEnable", "DaysForWarning", "ChangePasswdOnFirstLogin"}
            On failure: "Error: <actionable message>".
        """
        try:
            policy = _dict(await client.request_json("GET", PASSWORD_POLICY_URL))
            return finalize(f"{_password_policy_markdown(policy)}\n\n{to_json(policy)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_secured_apis",
        title="List Secured APIs",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_secured_apis(
        feature: Annotated[
            str | None,
            Field(
                description="Case-insensitive substring of the feature name to keep "
                "(e.g. 'topology'). Applied client-side.",
                max_length=200,
            ),
        ] = None,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the gateway's secured APIs grouped by feature — the catalogue
        of api_ids that role access_rights refer to.

        Read-only. Use it to translate an api_id seen in cnc_list_roles into a
        name, or to see which APIs a feature exposes. GET aaa/v2/api answers
        {"<feature>": [{"api_id", "name"}]}; the feature filter is a
        client-side substring match. (aaa/v1/api, the full API definitions,
        is huge and not exposed.)

        Returns:
            str: Markdown "## <feature> (<n>)" sections with "- <name>
            (<api_id>)" lines, or the raw (filtered) JSON:
            {"<feature>": [{"api_id": str, "name": str}, ...], ...}
            On failure: "Error: <actionable message>".
        """
        try:
            data = _dict(await client.request_json("GET", SECURED_APIS_URL))
            apis: dict[str, list[dict[str, Any]]] = {
                str(k): _dicts(v) for k, v in data.items() if isinstance(v, list)
            }
            needle = _clean(feature).lower()
            if needle:
                apis = {k: v for k, v in apis.items() if needle in k.lower()}
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(apis), settings, hint=_SECURED_APIS_HINT)
            return finalize(
                _secured_apis_markdown(apis, needle or None), settings, hint=_SECURED_APIS_HINT
            )
        except Exception as e:
            return format_error(e)

    # --- writes ----------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_set_login_banner",
        title="Set Login Banner",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_set_login_banner(
        message: Annotated[
            str | None,
            Field(
                description="New banner message text (e.g. 'Authorised use only.').",
                max_length=4000,
            ),
        ] = None,
        title: Annotated[
            str | None,
            Field(description="New banner title (e.g. 'Legal notice').", max_length=500),
        ] = None,
        show: Annotated[
            bool | None,
            Field(description="Show the banner on the login page (true) or hide it (false)."),
        ] = None,
        user_ack: Annotated[
            bool | None,
            Field(
                description="Require users to acknowledge the banner before signing in "
                "(true/false). Ignored by the platform while the banner is hidden."
            ),
        ] = None,
        icon: Annotated[
            str | None,
            Field(
                description=f"Banner icon, one of {_BANNER_ICON_CHOICES} (case-insensitive, "
                "e.g. 'BANNER_ICON_IMPORTANT').",
                max_length=40,
            ),
        ] = None,
        reset: Annotated[
            bool,
            Field(
                description="True to restore the factory banner; the other fields are then "
                "ignored (e.g. false)."
            ),
        ] = False,
    ) -> str:
        """Change the UI login banner: message, title, icon, whether it is
        shown and whether users must acknowledge it — or reset it to the
        factory text.

        Write (idempotent, not destructive: the banner is cosmetic and can be
        set again or reset). cluster/banner/set is protobuf-backed, where an
        omitted field is indistinguishable from false / "" — so the tool
        first reads cluster/banner/get, merges the fields you give over the
        current banner and always sends the full verified object
        {"ShowMessage", "UserAck", "Message", "Icon", "Title"}; fields you do
        not give keep their current value. reset=true sends
        {"ResetSettings": true} alone (no prior read) and ignores the other
        fields. At least one field (or reset) is required, and an unknown
        icon is refused — both before anything is sent. The tool then
        re-reads cluster/banner/get and returns the banner as it now stands,
        so verify from the output rather than assuming.

        Returns:
            str: "Login banner updated." followed by the banner markdown
            (Title / Message / shown / acknowledgement / icon) and its JSON
            {"ShowMessage", "UserAck", "Message", "Icon", "Title"}.
            "Error: nothing to set ..." when no field was given, "Error:
            Unknown icon ..." for a bad icon; other failures:
            "Error: <actionable message>".
        """
        try:
            body: dict[str, Any]
            if reset:
                body = {"ResetSettings": True}
            else:
                wanted_icon = _banner_icon(icon) if _clean(icon) else None
                if all(v is None for v in (message, title, show, user_ack, wanted_icon)):
                    raise PlatformError(
                        "nothing to set: give message, title, show, user_ack or icon, "
                        "or reset=true."
                    )
                current = await fetch_banner()
                body = {
                    "ShowMessage": current.get("ShowMessage") is True if show is None else show,
                    "UserAck": current.get("UserAck") is True if user_ack is None else user_ack,
                    "Message": str(current.get("Message") or "") if message is None else message,
                    "Icon": wanted_icon or current.get("Icon") or BANNER_ICONS[0],
                    "Title": str(current.get("Title") or "") if title is None else title,
                }
            result = await client.request_json("POST", BANNER_SET_URL, json_body=body)
            _check_cluster_result(result, "Banner update")
            banner = await fetch_banner()
            return finalize(
                f"Login banner updated.\n\n{_banner_markdown(banner)}\n\n{to_json(banner)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_set_maintenance_mode",
        title="Set Maintenance Mode",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_set_maintenance_mode(
        enabled: Annotated[
            bool,
            Field(description="True to enter maintenance mode, false to leave it (e.g. true)."),
        ],
    ) -> str:
        """Enter or leave Crosswork maintenance mode.

        Write, DESTRUCTIVE in effect: maintenance mode suspends normal
        operations platform-wide — device collection, jobs and application
        services pause, new jobs are refused and running ones are allowed to
        finish — so that a backup, restore or upgrade can run safely. Only use
        it when an operator has asked for exactly that, and leave it again
        (enabled=false) when done. POST platform/maintenance/set
        {"isSetMaintenance": bool}, then GET platform/maintenance/status.
        NOT exercised live: the request body is verified from the document and
        the answer shape below is the documented one, not a captured answer.
        The transition is asynchronous (status *_In_Progress first); call
        cnc_get_maintenance_status to watch it settle.

        Returns:
            str: "Maintenance mode <on|off> requested: <message>" then JSON
            {"request": {"message", "requestStatus":
                         "Maintenance_Mode_Request_Status_Success"|"..._Failed",
                         "modeStatus": "Maintenance_Mode_On"|...},
             "status": {"message", "status", "lastUpdated"}}.
            "Error: ..." when the platform reports the request failed or the
            call fails.
        """
        try:
            result = _dict(
                await client.request_json(
                    "POST", MAINTENANCE_SET_URL, json_body={"isSetMaintenance": enabled}
                )
            )
            if result.get("requestStatus") == MAINTENANCE_REQUEST_FAILED:
                raise PlatformError(
                    f"Maintenance mode request failed: {result.get('message') or 'no reason given'}"
                )
            status = await fetch_maintenance_status()
            line = (
                f"Maintenance mode {'on' if enabled else 'off'} requested: "
                f"{result.get('message') or 'no message'}. Current status: "
                f"{status.get('status') or '?'}."
            )
            return finalize(f"{line}\n\n{to_json({'request': result, 'status': status})}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_restart_microservice",
        title="Restart Microservice",
        read_only=False,
        destructive=True,
        idempotent=False,
    )
    async def cnc_restart_microservice(
        name: Annotated[
            str,
            Field(
                description="Microservice (pod) Name exactly as cnc_list_microservices shows it "
                "(e.g. 'robot-topo-svc').",
                min_length=1,
                max_length=200,
            ),
        ],
    ) -> str:
        """Restart one Crosswork microservice (pod).

        Write, DESTRUCTIVE: the pod is killed and rescheduled, so whatever it
        serves (topology, collection, a UI service, ...) is briefly unavailable
        and in-flight work on it is lost. Verify the exact Name with
        cnc_list_microservices first (it lists the actions each pod offers;
        RESTART is one of them) and prefer restarting only pods that are
        Degraded/Down or that the platform's recommendation names. POST
        cluster/microservice/restart {"req_id": name}. NOT exercised live:
        the body is the documented one and the answer is returned as the
        platform gives it (documented as {"resp_value": "R_SUCCESS"|
        "R_FAILURE", "resp_error", "description"}). Watch the pod come back
        with cnc_list_microservices: ``up_time`` is the container's age, so a
        restarted pod reads seconds/minutes again (a mere health=down episode
        never resets it).

        Returns:
            str: "Restart requested for microservice <name>." followed by the
            platform's JSON answer. "Error: ..." when the platform reports
            R_FAILURE or the call fails.
        """
        try:
            target = name.strip()
            if not target:
                raise PlatformError(
                    "name is empty: give a microservice Name from cnc_list_microservices."
                )
            data = await client.request_json(
                "POST", MICROSERVICE_RESTART_URL, json_body={"req_id": target}
            )
            _check_cluster_result(data, f"Restart of microservice {target}")
            return finalize(
                f"Restart requested for microservice {target}.\n\n{to_json(data)}", settings
            )
        except Exception as e:
            return format_error(e)
