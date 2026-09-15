#!/usr/bin/env python3
"""Generate the RBAC map: which Crosswork gateway APIs each cnc-mcp tool needs.

Maintainer script. Crosswork's API gateway is Tyk v5.1.1: a ROLE is a Tyk policy
whose ``access_rights`` grant, per secured API (``api_id``), a list of
``allowed_urls`` ``{url: <regex>, methods: [...]}``; a request is routed to the
secured API with the LONGEST matching listen path (a gorilla-mux pattern such as
``/crosswork/inventory/`` or ``/crosswork/performance/v{.}/dashboards/``) and
refused (403) when the role has no entry for it or none of the entry's
``allowed_urls`` covers the path and method — each ``url`` is evaluated as an
UNANCHORED regex search against the FULL request path (per the Tyk v5.1.1
gateway source, ``mw_granular_access.go``, and observed live 2026-09-15 with a
user carrying the generated read-only role). This script joins the two sides:

- the tool side: every ``register_tool(...)`` function's ``(METHOD, path
  template)`` endpoints, extracted statically by ``scripts/api_coverage.py``'s
  analyser (``{}`` marks a runtime value); the composite playbooks send nothing
  themselves and are resolved as the UNION of their siblings' endpoints
  (``cnc_mcp.tools.composite.SIBLING_CALLS``);
- the gateway side: the secured-API catalogue — ``GET /crosswork/aaaread/v2/api``
  (``{<feature>: [{api_id, name}]}``, the grouping the UI's role editor shows)
  and ``GET /crosswork/aaaread/v1/api`` (the Tyk API definitions; ONLY
  ``api_id``, ``name`` and ``proxy.listen_path`` are read — the rest of a
  definition is the gateway's administrative configuration, which has no place
  in the repository);
- the platform side (verified live 2026-09-14 by creating a test role through
  an admin session and reading it back): Crosswork's AAA service does NOT store
  a submitted role verbatim. A row submitted as ``{url: "/.*", methods:
  ["GET"]}``, ``{url: "/.*", methods: ["POST", "PUT", "PATCH"]}`` or ``{url:
  "/.*", methods: ["DELETE"]}`` is stored verbatim — the shapes the role
  editor's **Read / Write / Delete** ticks are taken to emit (an inference: no
  UI-built role exists on the lab, so the editor's own wire shape was never
  read back) — and a row with a GET entry (and no POST entry) additionally
  receives the platform's per-API **read templates**: extra POST entries naming
  the read-by-POST paths of that API (``/.+/query$`` on
  ``inventory_cwinventory``, the get-*/…-preview RPC names on
  ``optima_restconf``, ...). Every stored role also gains two **baseline rows**
  (``aaa_cwpassword``, ``aaa_selected_pref``). A custom-URL GET entry is kept
  verbatim (the template is still added). A row whose ONLY entry was a
  custom-URL POST was REINTERPRETED on the nine APIs it was tried on (its
  methods stripped, a wide service pattern added — a broader grant than
  submitted), while a custom POST entry beside a custom GET entry was kept
  verbatim (no template added) on four others; whether the API or the row
  shape decides was not isolated, so the generated bodies never carry a custom
  POST entry. The captured templates and baseline rows are carried in the
  map's ``platform`` block (``--read-templates`` loads a fresh capture; offline
  runs reuse what the committed map carries, like the catalogue);
  ``tests/fixtures/rbac/`` holds the sanitised read-backs the stored-role model
  (``stored_access_rights``) is pinned against — two experiments and the committed
  read-only body as stored.

Each template is routed to the api_id whose listen path claims it (longest
match, ``{...}`` = one segment, trailing slash optional, segment boundary
required — ``cnc_mcp.tools.admin.listen_path_pattern``, the same function the
runtime check uses). A template whose ``{}`` runtime value could extend into a
LONGER listen path is reported and the longer API is added as a second
requirement (none in the 7.2 catalogue).

Each requirement (method, path, api_id) is then classified as the UI tick that
permits it (``classify``): GET → R; POST → R when a read template of the API
permits it under Tyk's rule, else W; PUT/PATCH → W; DELETE → D. Per API the
ticks the read tools need and the ones each write area adds follow from that.

Outputs (all deterministic — sorted keys, no timestamps — so ``--check`` can
compare):

- ``src/cnc_mcp/data/rbac_map.json`` — packaged with the server; read by
  ``cnc_check_permissions`` at runtime;
- ``docs/RBAC.md`` — the operator's guide: how Crosswork RBAC works and how it
  stores a role, the least-privilege read-only recipe, the per-write-area
  additions, the per-tool table, the task-checkbox bundles, verification;
- ``docs/rbac/cnc-mcp-readonly.role.json`` / ``cnc-mcp-operator.role.json`` —
  ready-made role bodies for ``POST /crosswork/aaa/v1/role``, UI-shaped: per
  api_id one ``/.*`` entry per tick (R = GET, W = POST/PUT/PATCH, D = DELETE);
  the read-only body carries R rows only. The one exception: the R entry of the
  two AAA rows keeps an anchored GET regex (``path_regex``) over exactly the
  templates the tools send, which the service keeps verbatim — it excludes the
  broader ``GET .../v1/api`` listing (administrative data).

Two per-tool overrides the static extraction cannot see: ``METHOD_CHOICES``
(a tool whose method argument the analyser reads as ``*`` but which only
accepts a subset — cnc_provision_service: PUT | PATCH) and ``ANY_OF`` (a tool
that tries one API and falls back to another — cnc_check_permissions reads the
role through the aaaread mirror, then aaa/v1 — so ONE of the groups suffices;
``cnc_mcp.tools.admin.evaluate_rbac_map`` honours the ``any_of`` key).

Usage::

    uv run python scripts/rbac_map.py                    # fetch the catalogue live (.env)
    uv run python scripts/rbac_map.py --catalogue-dir D  # from api_v1.json + api_v2.json dumps
    uv run python scripts/rbac_map.py --offline          # from the committed map's catalogue
    uv run python scripts/rbac_map.py --read-templates F # + a fresh capture of the platform's
                                                         #   read templates (any mode)
    uv run python scripts/rbac_map.py --check            # offline; exit 1 when anything is stale

Limits (a static heuristic — read them before trusting one row): the endpoint
extraction is api_coverage.py's (a request built from platform data folds to
``{}``; a probe counts as a use); the routing and ``allowed_urls`` semantics
come from the Tyk v5.1.1 source and were confirmed by a user on the generated
read-only role (2026-09-15: every predicted refusal answered 403, nothing
unpredicted did, and the ``/crosswork/aaaread/`` mirror served that user its
own role). The task-checkbox bundles in section 5 are the five the lab's
``taskAPIPermission/admin`` returned (verified 2026-09-14); the other tasks map
to no API grant there.
"""

from __future__ import annotations

import argparse
import asyncio
import html
import json
import re
import sys
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_DIR = SCRIPTS_DIR.parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import api_coverage  # noqa: E402  (scripts/ on sys.path)

DEFAULT_SRC = REPO_DIR / "src" / "cnc_mcp"
MAP_RELATIVE = Path("src/cnc_mcp/data/rbac_map.json")
DOC_RELATIVE = Path("docs/RBAC.md")
ROLE_DIR_RELATIVE = Path("docs/rbac")
READONLY_ROLE = "cnc-mcp-readonly"
OPERATOR_ROLE = "cnc-mcp-operator"

PLATFORM = "CNC 7.2.0"
PLATFORM_VERSION = "7.2.0"
CATALOGUE_VERIFIED = "2026-09-14"
# When a --read-templates capture file carries no "captured" date of its own.
TEMPLATES_CAPTURED = "2026-09-14"
AAA_READ_V1_API = "/crosswork/aaaread/v1/api"
AAA_READ_V2_API = "/crosswork/aaaread/v2/api"
UNCATEGORISED = "(not in aaa/v2/api)"
ALL_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
WILDCARD = "*"

# The role editor's per-row ticks and the allowed_urls entry each one is taken to emit.
# The stored form of these entries was verified 2026-09-14 (submitted, read back
# unchanged); that the editor's tick emits exactly this entry is inferred — no UI-built
# role exists on the lab to read back.
TICKS = ("R", "W", "D")
TICK_METHODS: dict[str, tuple[str, ...]] = {
    "R": ("GET",),
    "W": ("POST", "PUT", "PATCH"),
    "D": ("DELETE",),
}
TICK_NAMES = {"R": "Read", "W": "Write", "D": "Delete"}
ANY_PATH = "/.*"

# The two rows the AAA service adds to EVERY role it stores (a user's own password
# change and UI preferences). They are captured together with the read templates and
# kept apart from them in the map's platform block.
BASELINE_APIS = ("aaa_cwpassword", "aaa_selected_pref")

# APIs on which a row whose ONLY entry was a custom-URL POST was reinterpreted (verified
# 2026-09-14: its methods stripped to [] and a service pattern permitting POST on every
# path whose last segment is not "delete" added), and the APIs on which — in the same
# submission — a custom-URL POST entry BESIDE a custom GET entry was kept verbatim (no
# template added). Whether the API or the row shape decides was not isolated; both lists
# are named in the guide and the bodies never carry a custom POST entry on any API.
REINTERPRETED_POST_APIS = (
    "collection_dg-manager",
    "cw-fault-alarms-api",
    "cw-fault-events-api",
    "cw-probe-mgr",
    "cw-ztp-service",
    "cwcollection",
    "dg-manager-global-parameters-api",
    "optima_analytics_api",
    "optima_restconf",
)
VERBATIM_POST_BESIDE_GET_APIS = (
    "device-config",
    "inventory_cwinventory",
    "platform_cwplatform",
    "tsdn_cat-restconf-nbi",
)

# A refused read tool (section 2 of the guide) that also has a FORM sending only a
# request the read template names — a different RPC selected by an argument, so that
# form of the call runs under Read: tool -> (that request's path, what selects it). The
# static extraction cannot tell an alternative from a request the tool always sends
# (cnc_check_nso_device_sync POSTs nodes/query AND nso/check-sync every call), so the
# forms are declared here; the generator checks each against the map (the tool must be
# a refused read and the path a Read-permitted POST of it on the refused row) and stops
# on a stale entry.
LCM_OPERATIONS = (
    "/crosswork/nbi/optimization/v3/restconf/operations/"
    "cisco-crosswork-optimization-engine-lcm-recommendation-operations:"
)
READ_FORMS: dict[str, tuple[str, str]] = {
    "cnc_get_lcm_recommendation_preview": (
        f"{LCM_OPERATIONS}get-lcm-recommendation-preview",
        "the legacy RPC, `msl=false`",
    ),
}

# A tool whose method argument the analyser folds to ``*`` (passed through at runtime)
# but which validates it against a subset: the map records the subset, not all five.
# cnc_provision_service: ``_choice(method, WRITE_METHODS)`` with WRITE_METHODS =
# ("put", "patch") (tools/service_provisioning.py).
METHOD_CHOICES: dict[str, tuple[str, ...]] = {"cnc_provision_service": ("PUT", "PATCH")}

# A tool that tries one API and falls back to another: groups of api_ids of which ONE
# group's rows must all be granted (the first group is what the tool tries first).
# cnc_check_permissions reads the role through the aaaread mirror (aaa_cw_role_read),
# then through aaa/v1 (aaa_cwaaa) when the mirror answers 403/404.
ANY_OF: dict[str, list[list[str]]] = {
    "cnc_check_permissions": [["aaa_cw_role_read"], ["aaa_cwaaa"]],
}

# The two AAA rows whose R entry is NOT the UI's ``/.*``: both APIs also serve
# ``GET .../v1/api`` — the gateway's full API-definition listing, administrative data
# that a non-administrator must not be granted — and Tyk's unanchored search reads
# ``/.*`` as "every path". Their GET entry is an anchored regex over exactly the
# templates the tools send (``path_regex``), which the AAA service keeps verbatim
# (verified 2026-09-14).
AAA_APIS = ("aaa_cw_role_read", "aaa_cwaaa")

# The Tyk policy fields of the lab's admin role (GET /crosswork/aaa/v1/role, verified
# 2026-09-14) that a generated role copies verbatim. ``_id``/``id``/``last_updated``/
# ``meta_data`` are server-assigned and left out.
ROLE_SKELETON: dict[str, Any] = {
    "org_id": "1",
    "rate": 5000,
    "per": 60,
    "quota_max": -1,
    "quota_renewal_rate": 60,
    "throttle_interval": 0,
    "throttle_retry_limit": 0,
    "hmac_enabled": False,
    "enable_http_signature_validation": False,
    "active": True,
    "is_inactive": False,
    "tags": [],
    "key_expires_in": -1,
    "partitions": {"quota": False, "rate_limit": False, "acl": False, "per_api": False},
}

# GET /crosswork/aaa/v1/taskAPIPermission/admin (verified 2026-09-14): the UI's task
# checkboxes that bundle per-API R/W/D grants. task id -> (UI name, task group,
# {api_id: "RWD" letters}). The other admin tasks (id_bwod_config, id_csm_config,
# id_lcm_0, id_lcm_all_access) returned no API bundle: they are feature permissions
# (aaa/v1/userpermission), not gateway grants.
TASK_BUNDLES: dict[str, tuple[str, str, dict[str, str]]] = {
    "id_dag_management": (
        "Device Access Group Management",
        "Platform",
        {"cw-grouping-service": "RWD"},
    ),
    "id_export_audit_logs_access": (
        "Export Audit Logs",
        "Audit Logs",
        {"cw-fault-events-api": "RW"},
    ),
    "id_nso_fp_deployment_management": (
        "Function Pack Deployment",
        "NSO Management",
        {"nso-fp-dep-mngr": "RWD"},
    ),
    "id_provisioning": (
        "Provisioning",
        "Crosswork Network Controller",
        {"inventory_cwinventory": "RW"},
    ),
    "id_view_audit_logs_access": ("View Audit Logs", "Audit Logs", {"cw-fault-events-api": "R"}),
}
TASKS_WITHOUT_BUNDLE = (
    ("id_bwod_config", "Bandwidth on Demand Configuration", "Crosswork Optimization Engine"),
    ("id_csm_config", "Circuit Style SR-TE Configuration", "Crosswork Optimization Engine"),
    ("id_lcm_0", "Local Congestion Mitigation Domain 0", "Crosswork Optimization Engine"),
    (
        "id_lcm_all_access",
        "Local Congestion Mitigation All Domains",
        "Crosswork Optimization Engine",
    ),
)


Catalogue = dict[str, dict[str, str]]  # api_id -> {name, feature, listen_path}
Entries = list[dict[str, Any]]  # [{url, methods}] — an access_rights row's allowed_urls
Platform = dict[str, Any]  # {version, captured, read_templates, baseline_rows}
Ticks = dict[str, set[str]]  # api_id -> subset of TICKS


# --- catalogue ------------------------------------------------------------------------


def sanitise_catalogue(v1: Any, v2: Any) -> Catalogue:
    """Keep ONLY api_id, name and proxy.listen_path from the API definitions, plus the
    feature each api_id sits under in the v2 grouping. Nothing else is copied."""
    if not isinstance(v1, list):
        raise SystemExit("aaa/v1/api: expected a list of API definitions")
    if not isinstance(v2, dict):
        raise SystemExit("aaa/v2/api: expected {<feature>: [{api_id, name}]}")
    feature_of: dict[str, str] = {}
    for feature, entries in v2.items():
        for entry in entries if isinstance(entries, list) else []:
            if isinstance(entry, dict) and isinstance(entry.get("api_id"), str):
                feature_of[entry["api_id"]] = str(feature)
    catalogue: Catalogue = {}
    for definition in v1:
        if not isinstance(definition, dict):
            continue
        api_id = definition.get("api_id")
        name = definition.get("name")
        listen_path = (definition.get("proxy") or {}).get("listen_path")
        if not (isinstance(api_id, str) and isinstance(name, str) and isinstance(listen_path, str)):
            raise SystemExit(f"aaa/v1/api: definition without api_id/name/listen_path: {api_id!r}")
        catalogue[api_id] = {
            "name": name,
            "feature": feature_of.get(api_id, UNCATEGORISED),
            "listen_path": listen_path,
        }
    return catalogue


def load_catalogue_dir(directory: Path) -> Catalogue:
    v1 = json.loads((directory / "api_v1.json").read_text(encoding="utf-8"))
    v2 = json.loads((directory / "api_v2.json").read_text(encoding="utf-8"))
    return sanitise_catalogue(v1, v2)


def read_committed_map(map_path: Path) -> dict[str, Any]:
    if not map_path.exists():
        raise SystemExit(
            f"{map_path} does not exist: run once with --catalogue-dir or live before --offline"
        )
    data = json.loads(map_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"{map_path} is not a JSON object")
    return data


def load_catalogue_map(map_path: Path) -> Catalogue:
    apis = read_committed_map(map_path).get("apis")
    if not isinstance(apis, dict) or not apis:
        raise SystemExit(f"{map_path} carries no 'apis' catalogue")
    return {
        api_id: {k: str(v) for k, v in api.items() if k in ("name", "feature", "listen_path")}
        for api_id, api in apis.items()
    }


async def fetch_catalogue_live() -> Catalogue:
    """Read both catalogue endpoints through the read-only mirror with the configured
    credentials (.env); the token never leaves the client."""
    from cnc_mcp.client import ApiClient
    from cnc_mcp.config import Settings
    from cnc_mcp.server import create_auth, quiet_http_logging

    quiet_http_logging()
    settings = Settings()  # type: ignore[call-arg]  # env supplies base_url
    client = ApiClient(settings, create_auth(settings))
    try:
        v2 = await client.request_json("GET", AAA_READ_V2_API)
        v1 = await client.request_json("GET", AAA_READ_V1_API)
    finally:
        await client.aclose()
    return sanitise_catalogue(v1, v2)


# --- platform: read templates and baseline rows -----------------------------------------


def sanitise_entries(raw: Any, context: str) -> Entries:
    """``[{url, methods}]`` with nothing else copied: ``url`` a regex that compiles,
    ``methods`` upper-cased, known, in GET/POST/PUT/PATCH/DELETE order; entries sorted
    by url so the map is deterministic whatever order the capture lists them in."""
    if not isinstance(raw, list):
        raise SystemExit(f"{context}: expected a list of {{url, methods}} entries")
    entries: Entries = []
    for entry in raw:
        url = entry.get("url") if isinstance(entry, dict) else None
        methods = entry.get("methods") if isinstance(entry, dict) else None
        if not isinstance(url, str) or not isinstance(methods, list):
            raise SystemExit(f"{context}: entry without url/methods: {entry!r}")
        upper = {str(m).upper() for m in methods}
        if not upper <= set(ALL_METHODS):
            raise SystemExit(f"{context}: unknown method in {sorted(upper)}")
        try:
            re.compile(url)
        except re.error as exc:
            raise SystemExit(f"{context}: url {url!r} is not a valid regex: {exc}") from None
        entries.append({"url": url, "methods": ordered(upper)})
    return sorted(entries, key=lambda e: (e["url"], e["methods"]))


def sanitise_platform(
    read_templates: Any, baseline_rows: Any, captured: Any, catalogue: Catalogue
) -> Platform:
    """The map's platform block from raw ``{api_id: [{url, methods}]}`` mappings: every
    api_id must be in the catalogue, a baseline API never appears among the templates
    (a capture that lists it there is split), and only url/methods survive."""
    if not isinstance(read_templates, dict) or not isinstance(baseline_rows, dict):
        raise SystemExit("platform: read_templates and baseline_rows must be {api_id: [...]}")
    templates: dict[str, Entries] = {}
    baseline: dict[str, Entries] = {}
    for api_id, raw in {**baseline_rows, **read_templates}.items():
        if api_id not in catalogue:
            raise SystemExit(f"platform: {api_id} is not in the secured-API catalogue")
        target = baseline if api_id in BASELINE_APIS else templates
        target[api_id] = sanitise_entries(raw, f"platform: {api_id}")
    if not isinstance(captured, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", captured):
        raise SystemExit(f"platform: 'captured' must be a YYYY-MM-DD date, not {captured!r}")
    return {
        "version": PLATFORM_VERSION,
        "captured": captured,
        "read_templates": dict(sorted(templates.items())),
        "baseline_rows": dict(sorted(baseline.items())),
    }


def load_platform_file(path: Path, catalogue: Catalogue) -> Platform:
    """A capture of what the AAA service added to a role whose every row was
    ``{url: "/.*", methods: ["GET"]}`` (``GET aaa/v1/role/<r>`` after the PUT): either
    ``{"captured": ..., "read_templates": {api_id: [{url, methods}]}}`` or the bare
    mapping. The two baseline rows are usually captured in the same mapping (the
    service adds them to every role) and are split out by api_id."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    if "read_templates" in raw:
        rows, captured = raw["read_templates"], raw.get("captured", TEMPLATES_CAPTURED)
    else:
        rows, captured = raw, TEMPLATES_CAPTURED
    return sanitise_platform(rows, {}, captured, catalogue)


def load_platform_map(map_path: Path, catalogue: Catalogue) -> Platform:
    platform = read_committed_map(map_path).get("platform")
    if not isinstance(platform, dict) or "read_templates" not in platform:
        raise SystemExit(
            f"{map_path} carries no 'platform' block: run once with --read-templates <capture>"
        )
    return sanitise_platform(
        platform["read_templates"],
        platform.get("baseline_rows", {}),
        platform.get("captured"),
        catalogue,
    )


# --- tools ------------------------------------------------------------------------------


def collect_tools(src: Path) -> tuple[list[api_coverage.Tool], dict[str, list[str]]]:
    """Every registered tool with its endpoints; playbooks get the union of their
    siblings' endpoints. Returns (tools, {playbook: [sibling names]})."""
    from cnc_mcp.tools.composite import SIBLING_CALLS

    tools = api_coverage.Analyzer(src).collect_tools()
    if not tools:
        raise SystemExit(f"no register_tool(...) functions found under {src}")
    by_name = {t.name: t for t in tools}
    for name, methods in METHOD_CHOICES.items():
        tool = by_name.get(name)
        if tool is None:
            raise SystemExit(f"METHOD_CHOICES names {name}, which is not a registered tool")
        wildcards = {path for method, path in tool.endpoints if method == WILDCARD}
        if not wildcards:
            raise SystemExit(f"METHOD_CHOICES: {name} no longer passes a method through")
        tool.endpoints = {e for e in tool.endpoints if e[0] != WILDCARD} | {
            (method, path) for path in wildcards for method in methods
        }
    composed: dict[str, list[str]] = {}
    for playbook, siblings in SIBLING_CALLS.items():
        tool = by_name.get(playbook)
        if tool is None:
            raise SystemExit(f"SIBLING_CALLS names {playbook}, which is not a registered tool")
        for sibling in siblings:
            if sibling not in by_name:
                raise SystemExit(f"{playbook} calls {sibling}, which is not a registered tool")
            tool.endpoints |= by_name[sibling].endpoints
        composed[playbook] = sorted(siblings)
    return tools, composed


# --- routing ----------------------------------------------------------------------------


class Router:
    """Route a path template to the secured API whose listen path claims it."""

    def __init__(self, catalogue: Catalogue) -> None:
        from cnc_mcp.tools.admin import listen_path_pattern

        self.catalogue = catalogue
        self.patterns = {
            api_id: listen_path_pattern(api["listen_path"]) for api_id, api in catalogue.items()
        }

    def route(self, template: str) -> str | None:
        best: tuple[int, str] | None = None
        for api_id, pattern in self.patterns.items():
            match = pattern.match(template)
            if match is None:
                continue
            candidate = (match.end(), api_id)
            # longest claimed prefix wins; the api_id breaks a tie deterministically
            if (
                best is None
                or candidate[0] > best[0]
                or (candidate[0] == best[0] and candidate[1] < best[1])
            ):
                best = candidate
        return best[1] if best else None

    def ambiguous(self, template: str, chosen: str | None) -> list[str]:
        """APIs a runtime value of ``{}`` could extend the template into
        (``could_extend_into``), other than the one it routes to."""
        return sorted(
            api_id
            for api_id, api in self.catalogue.items()
            if api_id != chosen and could_extend_into(template, api["listen_path"])
        )


def could_extend_into(template: str, listen_path: str) -> bool:
    """Whether a runtime value of the template's first ``{}`` could extend it into
    ``listen_path``: the listen path starts with the template's literal prefix but is
    longer than it (``/crosswork/inventory/v1/{}`` into ``/crosswork/inventory/v1/
    networkelement``). ``build_map`` records such a template on the longer API too,
    and ``path_regex`` renders it there as its whole path."""
    if api_coverage.PLACEHOLDER not in template:
        return False
    prefix = template.split(api_coverage.PLACEHOLDER, 1)[0]
    listen = listen_path.rstrip("/")
    return len(listen) > len(prefix) and listen.startswith(prefix)


def build_map(
    catalogue: Catalogue,
    platform: Platform,
    tools: list[api_coverage.Tool],
    composed: dict[str, list[str]],
):
    router = Router(catalogue)
    tools_out: dict[str, Any] = {}
    unresolved: list[dict[str, str]] = []
    ambiguities: list[str] = []
    for tool in tools:
        requirements: list[dict[str, str]] = []
        for method, template in sorted(tool.endpoints, key=lambda e: (e[1], e[0])):
            api_id = router.route(template)
            if api_id is None:
                unresolved.append({"tool": tool.name, "method": method, "path": template})
                continue
            requirements.append({"method": method, "path": template, "api_id": api_id})
            for extra in router.ambiguous(template, api_id):
                ambiguities.append(f"{tool.name}: {method} {template} may also route to {extra}")
                requirements.append({"method": method, "path": template, "api_id": extra})
        entry: dict[str, Any] = {
            "area": tool.module,
            "read_only": tool.read_only,
            "requirements": sorted(
                requirements, key=lambda r: (r["path"], r["method"], r["api_id"])
            ),
        }
        if tool.name in composed:
            entry["composed_from"] = composed[tool.name]
        if tool.name in ANY_OF:
            required = {r["api_id"] for r in requirements}
            for group in ANY_OF[tool.name]:
                for api_id in group:
                    if api_id not in required:
                        raise SystemExit(
                            f"ANY_OF: {tool.name} has no requirement on {api_id} "
                            "(the alternative no longer exists in the source)"
                        )
            entry["any_of"] = [list(group) for group in ANY_OF[tool.name]]
        tools_out[tool.name] = entry
    for name in (*METHOD_CHOICES, *ANY_OF):
        if name not in tools_out:
            raise SystemExit(f"{name} (METHOD_CHOICES / ANY_OF) is not a registered tool")
    features = {api["feature"] for api in catalogue.values()}
    rbac_map = {
        "generated_from": {
            "platform": PLATFORM,
            "catalogue": (
                f"GET {AAA_READ_V2_API} (feature grouping) + GET {AAA_READ_V1_API} "
                "(api_id, name, proxy.listen_path only)"
            ),
            "catalogue_verified": CATALOGUE_VERIFIED,
            "api_count": len(catalogue),
            "feature_count": len(features),
            "tool_count": len(tools_out),
            "generator": "scripts/rbac_map.py",
            "routing": (
                "a path is routed to the secured API with the longest matching listen path "
                "({...} = one segment, trailing slash optional); a role's allowed_urls regex "
                "is an unanchored search on the full request path (Tyk v5.1.1 source); '{}' "
                "in a path is a runtime value; method '*' means the tool passes the method "
                "through (all five needed); 'any_of' lists groups of api_ids of which one "
                "group's rows suffice (the tool falls back from the first to the next)"
            ),
            "ticks": (
                "a row submitted as {url: '/.*', methods: [GET]} / [POST, PUT, PATCH] / "
                "[DELETE] is stored verbatim; a row with a GET entry and no POST entry also "
                "receives the platform's read templates ('platform.read_templates', extra "
                "POST entries for that API's read-by-POST paths) and every stored role the "
                "'platform.baseline_rows'; a requirement is permitted by Read when its "
                "method is GET or a read template of its API matches its path under the "
                "unanchored-search rule (the stored forms were verified 2026-09-14 by "
                "storing a test role through an admin session; that the role editor's "
                "Read / Write / Delete ticks emit exactly these entries is inferred — the "
                "editor's wire shape was not captured, no UI-built role exists on the lab)"
            ),
        },
        "platform": platform,
        "apis": {api_id: dict(sorted(api.items())) for api_id, api in sorted(catalogue.items())},
        "tools": dict(sorted(tools_out.items())),
        "unresolved": sorted(unresolved, key=lambda u: (u["tool"], u["path"], u["method"])),
    }
    return rbac_map, ambiguities


# --- classification ---------------------------------------------------------------------


def needed_methods(method: str) -> set[str]:
    return set(ALL_METHODS) if method == WILDCARD else {method}


def ordered(methods: Iterable[str]) -> list[str]:
    wanted = set(methods)
    return [m for m in ALL_METHODS if m in wanted]


def ordered_ticks(ticks: Iterable[str]) -> str:
    wanted = set(ticks)
    return "".join(t for t in TICKS if t in wanted)


RESTCONF_MARKER = "/restconf/"


def tail_may_carry_slash(template: str) -> bool:
    """Whether a runtime value in the LAST segment of a template can contain ``/``: a
    RESTCONF key can (``.../restconf/data/{}`` takes ``tailf-ncs:devices/device=x``,
    ``.../node={}`` a ``/``-bearing id); elsewhere a last-segment value is one segment
    (a role or user name, a job id, a group uuid)."""
    return RESTCONF_MARKER in template


def concrete_path(template: str) -> str:
    """A plausible request path for a template: ``abc`` for a runtime value — except
    ``a/b=c`` (a RESTCONF key, with ``/``) in the last segment where
    ``tail_may_carry_slash``."""
    segments = template.split("/")
    tail = "a/b=c" if tail_may_carry_slash(template) else "abc"
    return "/".join(
        segment.replace(api_coverage.PLACEHOLDER, tail if index == len(segments) - 1 else "abc")
        for index, segment in enumerate(segments)
    )


def entries_permit(entries: Iterable[dict[str, Any]], method: str, path: str) -> bool:
    """Tyk's granular-access rule (section 1 of the guide) over a list of
    ``allowed_urls`` entries: some entry lists the method and its regex matches the
    full path as an unanchored search."""
    return any(
        method in entry["methods"] and re.search(entry["url"], path) is not None
        for entry in entries
    )


def body_permits(body: dict[str, Any], api_id: str, method: str, path: str) -> bool:
    """``entries_permit`` over a role body's row for ``api_id`` (an absent row permits
    nothing)."""
    (role,) = body.values()
    grant = role["access_rights"].get(api_id)
    return grant is not None and entries_permit(grant["allowed_urls"], method, path)


def classify(method: str, path: str, api_id: str, read_templates: dict[str, Entries]) -> str:
    """The UI tick that permits one (method, path template) on ``api_id``: GET → R;
    POST → R when a read template of the API permits it (Tyk's rule against a
    concrete request path), else W; PUT/PATCH → W; DELETE → D. A ``*`` method is
    expanded by the caller (``needed_methods``)."""
    if method == "GET":
        return "R"
    if method == "POST":
        permitted = entries_permit(read_templates.get(api_id, []), "POST", concrete_path(path))
        return "R" if permitted else "W"
    if method in ("PUT", "PATCH"):
        return "W"
    if method == "DELETE":
        return "D"
    raise ValueError(f"not an HTTP method: {method!r}")


def requirement_ticks(req: dict[str, Any], read_templates: dict[str, Entries]) -> set[str]:
    """The ticks one requirement needs (a ``*`` method needs all three)."""
    return {
        classify(method, req["path"], req["api_id"], read_templates)
        for method in needed_methods(req["method"])
    }


def ticks_for(tool_specs: Iterable[dict[str, Any]], read_templates: dict[str, Entries]) -> Ticks:
    """Per api_id, the union of the ticks the given tools' requirements need."""
    ticks: Ticks = defaultdict(set)
    for spec in tool_specs:
        for req in spec["requirements"]:
            ticks[req["api_id"]] |= requirement_ticks(req, read_templates)
    return dict(ticks)


def non_read_requirements(
    spec: dict[str, Any], read_templates: dict[str, Entries]
) -> list[tuple[str, str, str, str]]:
    """The (method, path, api_id, tick) of one tool's requirements the Read tick does
    NOT permit, honouring ``any_of`` the way the runtime check does: the plain
    requirements, plus — when no alternative group is fully permitted — those of the
    first group. Empty = the tool runs under a role whose rows are all Read."""
    groups = spec.get("any_of") or []
    grouped = {api_id for group in groups for api_id in group}

    def lacking(reqs: Iterable[dict[str, Any]]) -> list[tuple[str, str, str, str]]:
        return [
            (method, req["path"], req["api_id"], tick)
            for req in reqs
            for method in ordered(needed_methods(req["method"]))
            for tick in [classify(method, req["path"], req["api_id"], read_templates)]
            if tick != "R"
        ]

    rows = lacking(r for r in spec["requirements"] if r["api_id"] not in grouped)
    if groups:
        per_group = [
            lacking(r for r in spec["requirements"] if r["api_id"] in group) for group in groups
        ]
        if all(per_group):
            rows.extend(per_group[0])
    return sorted(set(rows))


def get_templates_for(tool_specs: Iterable[dict[str, Any]]) -> dict[str, set[str]]:
    """Per api_id, the path templates the given tools send with GET (what the anchored
    R entry of an AAA row covers)."""
    templates: dict[str, set[str]] = defaultdict(set)
    for spec in tool_specs:
        for req in spec["requirements"]:
            if "GET" in needed_methods(req["method"]):
                templates[req["api_id"]].add(req["path"])
    return dict(templates)


# --- anchored URL patterns (the two AAA rows) -------------------------------------------

# The characters that are regex metacharacters in BOTH Go RE2 (Tyk) and Python's ``re``;
# escaping only these keeps ``-``, ``:`` and ``=`` (common in RESTCONF paths) literal
# and readable (``re.escape`` would write ``\-``, which RE2 accepts but nobody enjoys).
_META_RE = re.compile(r"[\\.^$*+?()\[\]{}|]")


def escape_literal(text: str) -> str:
    return _META_RE.sub(lambda m: "\\" + m.group(), text)


ONE_SEGMENT = "[^/]+"
ANY_TAIL = ".+"


def segment_regex(segment: str, *, value: str = ONE_SEGMENT) -> str:
    """One path segment of a template as a regex: literal text escaped, each ``{}``
    runtime value rendered as ``value`` — ``[^/]+`` (one segment) unless the caller
    passes ``.+`` for a last segment whose value may carry ``/`` (``path_regex``)."""
    return value.join(escape_literal(part) for part in segment.split(api_coverage.PLACEHOLDER))


def path_regex(listen_path: str, templates: Iterable[str]) -> str:
    """One anchored regex matching exactly the path templates under ``listen_path``.

    ``^<base>/(alt|alt|...)$`` — ``base`` is the part of the template the listen
    path claims (literal for the template, so ``v{.}`` in a listen path becomes
    the ``v1`` the tool sends), the alternatives are the sorted, deduplicated
    remainders rendered by ``segment_regex``: a runtime value is ``[^/]+`` (one
    segment), in the last segment ``.+`` only where the value can carry ``/`` —
    a RESTCONF key (``tail_may_carry_slash``) or the extending case below; a
    template that IS the base gives ``^<base>$``; templates under different
    bases are joined with ``|``. A template the listen path does not claim but
    a runtime value of its ``{}`` could extend into it (``could_extend_into`` —
    ``build_map`` records those on the longer API too) is rendered whole,
    ``^<template>$`` with a ``.+`` tail: the gateway consults this row only for
    requests the listen path claims, and the value may run any depth into
    them, so that is exactly the paths the tool can send here. Tyk (Go RE2)
    and Python's ``re`` read the result identically — no lookarounds, no
    back-references — and Tyk searches the FULL request path (section 1 of the
    guide), which is why every alternative starts at ``^`` and names the
    listen path.
    """
    from cnc_mcp.tools.admin import listen_path_pattern

    claimed = listen_path_pattern(listen_path)
    bare: set[str] = set()
    remainders: dict[str, set[str]] = defaultdict(set)  # base regex -> alternatives
    for template in templates:
        segments = template.split("/")
        match = claimed.match(template)
        extends = match is None and could_extend_into(template, listen_path)
        tail = ANY_TAIL if extends or tail_may_carry_slash(template) else ONE_SEGMENT
        rendered = [
            segment_regex(segment, value=tail if index == len(segments) - 1 else ONE_SEGMENT)
            for index, segment in enumerate(segments)
        ]
        if match is None:
            if not extends:
                raise SystemExit(f"path_regex: {template} is not under listen path {listen_path}")
            bare.add("/".join(rendered))
            continue
        n_base = template[: match.end()].count("/") + 1
        base = "/".join(rendered[:n_base])
        if n_base == len(segments):
            bare.add(base)
        else:
            remainders[base].add("/".join(rendered[n_base:]))
    parts: list[str] = []
    for base in sorted(bare | set(remainders)):
        if base in bare:
            parts.append(f"^{base}$")
        alternatives = sorted(remainders.get(base, ()))
        if len(alternatives) == 1:
            parts.append(f"^{base}/{alternatives[0]}$")
        elif alternatives:
            parts.append(f"^{base}/({'|'.join(alternatives)})$")
    return "|".join(parts)


# --- role bodies ------------------------------------------------------------------------


def allowed_urls_for(
    api_id: str, ticks: set[str], get_templates: dict[str, set[str]], catalogue: Catalogue
) -> Entries:
    """One row's ``allowed_urls`` in the UI's shape — one ``/.*`` entry per tick, in
    R, W, D order — except that the R entry of an AAA row (``AAA_APIS``) is the
    anchored regex over the GET templates the tools send there."""
    entries: Entries = []
    for tick in TICKS:
        if tick not in ticks:
            continue
        url = ANY_PATH
        if tick == "R" and api_id in AAA_APIS:
            templates = get_templates.get(api_id)
            if not templates:
                raise SystemExit(f"{api_id}: R tick without a GET template to anchor to")
            url = path_regex(catalogue[api_id]["listen_path"], templates)
        entries.append({"url": url, "methods": list(TICK_METHODS[tick])})
    return entries


def role_body(
    name: str, ticks: Ticks, get_templates: dict[str, set[str]], catalogue: Catalogue
) -> dict[str, Any]:
    access_rights = {
        api_id: {
            "api_name": catalogue[api_id]["name"],
            "api_id": api_id,
            "versions": ["Default"],
            "allowed_urls": allowed_urls_for(api_id, row_ticks, get_templates, catalogue),
            "limit": None,
            "allowance_scope": "",
        }
        for api_id, row_ticks in sorted(ticks.items())
        if row_ticks
    }
    return {name: {"name": name, **ROLE_SKELETON, "access_rights": access_rights}}


def body_ticks(body: dict[str, Any]) -> Ticks:
    """The ticks each row of a generated body carries (from its entries' methods)."""
    (role,) = body.values()
    ticks: Ticks = {}
    for api_id, grant in role["access_rights"].items():
        methods = {m for entry in grant["allowed_urls"] for m in entry["methods"]}
        ticks[api_id] = {tick for tick in TICKS if methods & set(TICK_METHODS[tick])}
    return ticks


def stored_access_rights(
    body: dict[str, Any], platform: Platform, catalogue: Catalogue
) -> dict[str, Any]:
    """The ``access_rights`` the AAA service stores for a submitted body (verified
    2026-09-14 by reading test roles back): every submitted entry verbatim; a row with a
    GET entry and no POST entry gains the API's read templates (a row ticked Read+Write
    did not — its Write entry already covers them); the baseline rows are added when
    absent. This is what ``cnc_check_permissions`` sees, so it is what the guide's
    counts and ``tests/test_rbac_map.py`` evaluate."""
    (role,) = body.values()
    rights: dict[str, Any] = {}
    for api_id, grant in role["access_rights"].items():
        entries = [dict(entry) for entry in grant["allowed_urls"]]
        has_get = any("GET" in entry["methods"] for entry in entries)
        has_post = any("POST" in entry["methods"] for entry in entries)
        if has_get and not has_post:
            entries.extend(dict(entry) for entry in platform["read_templates"].get(api_id, []))
        rights[api_id] = {**grant, "allowed_urls": entries}
    for api_id, entries in platform["baseline_rows"].items():
        rights.setdefault(
            api_id,
            {
                "api_name": catalogue[api_id]["name"],
                "api_id": api_id,
                "versions": ["Default"],
                "allowed_urls": [dict(entry) for entry in entries],
                "limit": None,
                "allowance_scope": "",
            },
        )
    return rights


def evaluate_body(
    body: dict[str, Any], rbac_map: dict[str, Any], catalogue: Catalogue
) -> dict[str, Any]:
    """``cnc_check_permissions``' verdict on every tool of the map under the role the
    service would store for ``body`` (``stored_access_rights``)."""
    from cnc_mcp.tools.admin import evaluate_rbac_map

    stored = stored_access_rights(body, rbac_map["platform"], catalogue)
    return evaluate_rbac_map(sorted(rbac_map["tools"]), rbac_map, stored)


# --- documentation ----------------------------------------------------------------------


def md(text: str) -> str:
    return html.unescape(text).replace("|", "\\|")


def api_row(catalogue: Catalogue, api_id: str, ticks: set[str]) -> str:
    api = catalogue[api_id]
    return f"| {md(api['feature'])} | `{api_id}` | {md(api['name'])} | {ordered_ticks(ticks)} |"


def aaa_entries(body: dict[str, Any], api_id: str) -> list[str]:
    """``- api_id (METHODS): url`` lines for one AAA row of a role body (empty when the
    body does not grant the row)."""
    (role,) = body.values()
    grant = role["access_rights"].get(api_id)
    if grant is None:
        return []
    return [
        f"- `{api_id}` ({', '.join(entry['methods'])}): `{entry['url']}`"
        for entry in grant["allowed_urls"]
    ]


def template_urls(platform: Platform, api_id: str) -> str:
    return ", ".join(f"`{entry['url']}`" for entry in platform["read_templates"].get(api_id, []))


def read_tick_reason(method: str, api_id: str, platform: Platform) -> str:
    """Why the Read tick does not permit one (method, api_id) — in the platform's terms."""
    if method == "POST":
        urls = template_urls(platform, api_id)
        if urls:
            return f"Read permits POST on `{api_id}` only where the path matches {urls}"
        return f"Read grants no POST at all on `{api_id}` (no read template)"
    if method in TICK_METHODS["W"]:
        return f"{method} is a Write tick"
    return f"{method} is a Delete tick"


def read_alternatives(
    spec: dict[str, Any], api_id: str, read_templates: dict[str, Entries]
) -> list[str]:
    """The POST paths one tool sends on ``api_id`` that the Read tick DOES permit (the
    row's template names them): a refused read tool with one runs under Read in the form
    of the call that sends it (cnc_get_lcm_recommendation_preview with ``msl=false``)."""
    return sorted(
        {
            req["path"]
            for req in spec["requirements"]
            if req["api_id"] == api_id
            and "POST" in needed_methods(req["method"])
            and classify("POST", req["path"], api_id, read_templates) == "R"
        }
    )


def post_senders(tool_specs: dict[str, Any], api_id: str) -> list[tuple[str, str]]:
    """``(tool, path)`` for every POST the given tools send on ``api_id``."""
    return sorted(
        {
            (name, req["path"])
            for name, spec in tool_specs.items()
            for req in spec["requirements"]
            if req["api_id"] == api_id and "POST" in needed_methods(req["method"])
        }
    )


def refused_read_rows(
    verdict: dict[str, Any], tools: dict[str, Any], platform: Platform
) -> list[tuple[str, list[tuple[str, str, str]]]]:
    """Per refused READ tool (sorted by name), the (method, path, api_id) rows it lacks
    under a Read-only role — and a cross-check that the Tyk evaluation of the stored
    role and ``classify`` agree on which read tools those are."""
    refused = {
        entry["tool"]: sorted(
            {(str(r["method"]), str(r["path"]), str(r["api_id"])) for r in entry["missing"]}
        )
        for entry in verdict["refused"]
        if tools[entry["tool"]]["read_only"]
    }
    by_classification = {
        name
        for name, spec in tools.items()
        if spec["read_only"] and non_read_requirements(spec, platform["read_templates"])
    }
    if set(refused) != by_classification:
        raise SystemExit(
            "the Tyk evaluation of the stored read-only role and classify() disagree: "
            f"evaluation refuses {sorted(refused)}, classification {sorted(by_classification)}"
        )
    return sorted(refused.items())


def render_doc(
    rbac_map: dict[str, Any],
    catalogue: Catalogue,
    readonly_body: dict[str, Any],
    operator_body: dict[str, Any],
) -> str:
    tools = rbac_map["tools"]
    platform = rbac_map["platform"]
    read_templates = platform["read_templates"]
    read_specs = [s for s in tools.values() if s["read_only"]]
    write_specs = [s for s in tools.values() if not s["read_only"]]
    read_ticks = ticks_for(read_specs, read_templates)
    readonly_ticks = body_ticks(readonly_body)
    operator_ticks = body_ticks(operator_body)
    write_areas: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for name, spec in tools.items():
        if not spec["read_only"]:
            write_areas[spec["area"]].append((name, spec))
    info = rbac_map["generated_from"]
    n_read = len(read_specs)
    n_write = len(write_specs)
    (readonly_role,) = readonly_body.values()
    (operator_role,) = operator_body.values()

    readonly_verdict = evaluate_body(readonly_body, rbac_map, catalogue)
    operator_verdict = evaluate_body(operator_body, rbac_map, catalogue)
    if operator_verdict["refused"] or operator_verdict["not_in_map"]:
        raise SystemExit(
            "the operator body does not permit every tool: "
            + ", ".join(r["tool"] for r in operator_verdict["refused"])
        )
    refused_reads = refused_read_rows(readonly_verdict, tools, platform)
    refused_names = [name for name, _ in refused_reads]
    permitted_reads = [n for n in readonly_verdict["permitted"] if tools[n]["read_only"]]
    permitted_writes = [n for n in readonly_verdict["permitted"] if not tools[n]["read_only"]]
    if len(permitted_reads) + len(refused_reads) != n_read:
        raise SystemExit("read tools neither permitted nor refused by the read-only role")
    # the APIs the refused reads need Write on, and what else Write permits there
    write_needed: dict[str, set[str]] = defaultdict(set)  # api_id -> refused read tools
    for name, rows in refused_reads:
        for _method, _path, api_id in rows:
            write_needed[api_id].add(name)
    write_tools_on: dict[str, set[str]] = defaultdict(set)  # api_id -> write tools using W
    for name, spec in tools.items():
        if spec["read_only"]:
            continue
        for req in spec["requirements"]:
            if "W" in requirement_ticks(req, read_templates):
                write_tools_on[req["api_id"]].add(name)
    stored_readonly = stored_access_rights(readonly_body, platform, catalogue)

    out: list[str] = []
    w = out.append
    w("# RBAC: what a Crosswork account needs to run cnc-mcp")
    w("")
    w(
        "> **Generated** by `scripts/rbac_map.py` from the tool source, the gateway's "
        f"secured-API catalogue ({info['platform']}, {info['api_count']} APIs in "
        f"{info['feature_count']} features, catalogue verified live {info['catalogue_verified']}) "
        f"and the platform's read templates (captured {platform['captured']}) — do not edit "
        "by hand. Regenerate with `make rbac` (offline, from the catalogue and templates "
        "embedded in `src/cnc_mcp/data/rbac_map.json`) or `make rbac-fetch` (re-read the "
        "catalogue from a live instance; `--read-templates <capture>` loads a fresh template "
        "capture); `make rbac-check` fails when the committed files are stale."
    )
    w("")
    w(
        f"The server registers {len(tools)} tools ({n_read} read-only, {n_write} write). "
        "Each sends a known set of HTTP requests; each request is routed by the gateway to "
        "one secured API, and a role must grant that API (with the method) or the gateway "
        "refuses the call (403). This page lists exactly which API rows a role needs and "
        "which of the role editor's **Read / Write / Delete** ticks on each — first for a "
        "read-only account, then per write area, then per tool."
    )
    w("")
    # --- 1
    w("## 1. How Crosswork RBAC works")
    w("")
    w("**Verified live** (CNC 7.2.0 single-VM lab, 2026-09-14):")
    w("")
    w(
        "- The API gateway is **Tyk** (v5.1.1, from its `/hello` health endpoint). Every "
        f"`/crosswork/*` request is routed to one of {info['api_count']} secured API "
        "definitions (`GET /crosswork/aaa/v1/api`), each with an `api_id`, a display `name` "
        "and a gorilla-mux **listen path** (`/crosswork/inventory/`, "
        "`/crosswork/alarms/v1/query`, `/crosswork/performance/v{.}/dashboards/`, ...)."
    )
    w(
        "- A **role** (`GET /crosswork/aaa/v1/role` → a dict keyed by role name) is a Tyk "
        'policy: `access_rights{<api_id>: {api_name, api_id, versions ["Default"], '
        "allowed_urls [{url: <regex>, methods: [GET, POST, PUT, PATCH, DELETE]}], "
        "allowance_scope}}` plus `rate 5000 / per 60 / quota_max -1 / active true`. The "
        'lab\'s built-in role, `admin`, grants every API with `url "/.*"` and all five '
        "methods."
    )
    w(
        "- `GET /crosswork/aaa/v2/api` → `{<feature>: [{api_id, name}]}` "
        f"({info['feature_count']} features) is the grouping the UI's role editor "
        "(Administration > Users and Roles > Roles) shows; the `feature` column below is it."
    )
    w(
        "- `GET /crosswork/aaa/v1/taskAPIPermission/<role>` → `{<task id>: {apiIds: "
        '{<api_id>: ["R", "W", "D"]}}}`: the UI\'s **task** checkboxes are bundles of '
        "per-API R/W/D grants (section 5). `GET aaa/v1/task/<role>` lists the task groups "
        "(audit_logs, coe, crosswork_network_controller, nso_management, platform); "
        "`GET aaa/v1/roleAccess/<role>` → `{PolicyId, GuiAccess, ApiAccess, PolicyData}` — "
        "`ApiAccess false` means no API call at all."
    )
    w(
        "- A **user** (`GET aaa/v1/user/<name>`) carries `PolicyId` (= its role), `Status` and "
        "`DeviceAccessGroups [{Uuid, DomainName}]` (`ALL-ACCESS` on the lab). A device access "
        "group other than ALL-ACCESS restricts which **devices** the account sees, not which "
        "APIs it may call."
    )
    w(
        "- The CAS-issued session token is an HS512 JWT sent as `Authorization: Bearer`; its "
        "claims are readable without the key: `sub`/`username` (the login name), `policy_id` "
        "(the role), `deviceAccessGroups`, `exp`/`iat` (8 h), `iss`. cnc_check_permissions "
        "reads the identity from them."
    )
    w(
        '- The read-only mirror `/crosswork/aaaread/...` (api_id `aaa_cw_role_read`, "Know my '
        'role - Read only", same backend) answers the same GETs as `aaa/v1` (`role/<r>`, '
        "`roleAccess/<r>`, `user/<u>`, `userpermission`, `task/<r>`, `v1/api`, `v2/api` — all "
        "200 as admin). It is the endpoint a non-admin account is expected to read its own "
        "role through."
    )
    w(
        "- The three SSO ticket calls the server logs in with (`POST /crosswork/sso/v1/tickets`, "
        "`POST .../tickets/{TGT}`, `DELETE .../tickets/{TGT}`) are **not** gateway APIs: no "
        "role grant is involved in logging in, only in what the token may then call."
    )
    w("")
    w(
        "**Verified live: how Crosswork stores a role** (2026-09-14, through an admin "
        f"session: a test role `{READONLY_ROLE}` was created, rewritten in several shapes "
        "and read back each time). The AAA service does **not** store a submitted role "
        "verbatim — it normalises `access_rights` per API:"
    )
    w("")
    w(
        "- `POST /crosswork/aaa/v1/role` needs `Content-Type: application/json; charset=UTF-8` "
        '(plain `application/json` → 405); body `{"<name>": {<rbacRole>}}` → **201**. '
        "`PUT /crosswork/aaa/v1/role/<name>` with the inner object → **204**. "
        "`GET /crosswork/aaa/v1/role/<name>` → the stored object (**404** when absent)."
    )
    w(
        '- A row submitted as `{url: "/.*", methods: ["GET"]}`, `{url: "/.*", methods: '
        '["POST", "PUT", "PATCH"]}` or `{url: "/.*", methods: ["DELETE"]}` is stored '
        "verbatim. This is the shape the generated bodies use — the one the role editor's "
        "**Read / Write / Delete** ticks most plausibly emit (an inference, see *Not "
        "verified* below; this page calls it the UI shape and the letters R / W / D)."
    )
    baseline_lines = [
        f"`{api_id}` ("
        + "; ".join(f"{', '.join(e['methods'])} `{e['url']}`" for e in entries)
        + ")"
        for api_id, entries in platform["baseline_rows"].items()
    ]
    w(
        f"- Every stored role gains {len(platform['baseline_rows'])} **baseline rows** the "
        "service adds on its own — " + ", ".join(baseline_lines) + " — the account's own "
        "password change and UI preferences. No cnc-mcp tool uses them; they are not in the "
        "bodies and appear when the role is read back."
    )
    readonly_rows = set(readonly_role["access_rights"])
    templated_outside = sorted(set(read_templates) - readonly_rows)
    w(
        "- A row with a GET entry (and no POST entry) additionally receives the platform's "
        "per-API **read templates**: extra POST entries naming the read-by-POST paths of "
        "that API — so a GET-only row permits those POSTs as well (what a Read tick grants, "
        f"if it emits that entry). The {len(set(read_templates) & readonly_rows)} APIs with "
        f"a template among the {len(readonly_rows)} rows the read tools use (every other "
        f"one of these rows received GET only when stored; the "
        f"{len(catalogue) - len(readonly_rows)} catalogued APIs outside these rows were "
        "never stored as GET-only rows, so their templates are unknown and any POST there "
        "is classed W)"
        + (
            f"; {len(templated_outside)} more with a template outside these rows: "
            + ", ".join(f"`{api_id}`" for api_id in templated_outside)
            if templated_outside
            else ""
        )
        + ":"
    )
    for api_id, entries in read_templates.items():
        w(
            f"  - `{api_id}`: "
            + "; ".join(f"{', '.join(e['methods'])} `{e['url']}`" for e in entries)
        )
    w(
        "- A GET entry with a **custom URL** is kept verbatim (and the read template is still "
        "added) — so anchoring the two AAA rows' GET pattern (section 2) works."
    )
    w(
        "- A **custom-URL POST entry is reinterpreted** where it was submitted as the row's "
        f"only entry — on the {len(REINTERPRETED_POST_APIS)} APIs that was tried on ("
        + ", ".join(f"`{api_id}`" for api_id in REINTERPRETED_POST_APIS)
        + "): its methods are stripped to `[]` and a service pattern permitting POST on "
        "every path whose last segment is not `delete` is added — a **wider** grant than "
        "submitted. In the same submission a custom POST entry next to a custom GET entry "
        "was kept verbatim (and no template added) on "
        + ", ".join(f"`{api_id}`" for api_id in VERBATIM_POST_BESIDE_GET_APIS)
        + ". Whether the API or the row shape decides was not isolated. Never submit "
        "exact-path POST entries; the bodies carry none (an earlier generation of this page "
        "did, and was wrong for this platform)."
    )
    w(
        "- A row ticked Read **and** Write was stored as the two `/.*` entries only (no "
        "template — the Write entry already covers every POST)."
    )
    w("")
    w(
        "**From the Tyk v5.1.1 gateway source** (`gateway/api_loader.go`, "
        "`mw_access_rights.go`, `mw_granular_access.go`), confirmed live 2026-09-15 by a "
        "users carrying the generated roles (read-only, 2026-09-15: 262 read calls answered, "
        "the 7 predicted refusals the smoke exercises answered 403, nothing unpredicted was "
        "refused, two writes and the `/v1/api` listings refused as predicted; operator, "
        "2026-09-15: all 432 read and write steps of the smoke answered, every created object "
        "removed again, no 403 at all):"
    )
    w("")
    w(
        "- Tyk registers the API definitions **longest listen path first** and each as a "
        "gorilla-mux path prefix, so a request goes to the API with the longest listen path "
        "that claims it; `{...}` in a listen path matches one segment. The map's router "
        "additionally requires the match to end at a segment boundary and accepts a missing "
        "trailing slash; no template in the map routes differently under either reading "
        "(`tests/test_rbac_map.py`). The query string is not part of the match."
    )
    w(
        "- Within the routed API, each `allowed_urls[].url` is run as an **unanchored regex "
        "search against the full request path** (`regexp.MatchString` on `r.URL.Path`; the "
        "listen path is not stripped first): `/nodes` permits "
        "`/crosswork/inventory/v1/nodes/query`, `^/v1/nodes/query$` permits nothing, and "
        "`/.+/query$` (an inventory read template) permits every `.../query` under the API. "
        "The method must be listed on a matching entry; an API with an empty `allowed_urls` "
        "has no path restriction."
    )
    w(
        "- A request the role does not permit is refused with a **403** whose body names "
        'which check failed (observed 2026-09-15): `{"error": "Access to this API has been '
        'disallowed"}` when the role has no entry for the API at all (`PUT '
        '/crosswork/alarms/v1/ack` under the read-only role), `{"error": "Access to this '
        'resource has been disallowed"}` when the API is granted but no `allowed_urls` '
        "entry covers the path and method (`POST /crosswork/inventory/v1/tags`, and the "
        "`/v1/api` listings excluded by the anchored AAA rows). Neither is an "
        "authentication failure: the server does not re-login on them. Two fail-open "
        "cases: an `allowed_urls` regex that does not compile is let through, and so is a "
        "role whose `access_rights` map is empty — "
        "cnc_check_permissions reports both as refusals (the role as it should be "
        "configured)."
    )
    w("")
    w("**Not verified (assumed — say so when it bites):**")
    w("")
    w(
        "- The role editor's own wire shape. No UI-built role exists on the lab, so what "
        "ticking **Read / Write / Delete** submits was never read back; the generated bodies "
        "use the shape whose stored form was verified (`/.*` with `[GET]`, `[POST, PUT, "
        "PATCH]`, `[DELETE]`), which is the one a tick most plausibly emits. Should the "
        "editor emit something else (a Write template rather than `/.*`, say), the tick "
        "columns on this page describe the bodies, not the editor."
    )
    w(
        "- Whether `/crosswork/aaaread/` is readable by **every** role: verified for the "
        "admin role and for the generated read-only role (its user read its own role and "
        "roleAccess through the mirror, 2026-09-15); a role built without the "
        "`aaa_cw_role_read` row is untested. cnc_check_permissions falls back to "
        "`/crosswork/aaa/v1` and says which one answered — either grant suffices for it."
    )
    write_only_rows = sorted(api_id for api_id, t in operator_ticks.items() if "R" not in t)
    w(
        "- A row ticked Write **without** Read"
        + (
            f" (the operator body has {len(write_only_rows)}: "
            + ", ".join(f"`{api_id}`" for api_id in write_only_rows)
            + ")"
            if write_only_rows
            else ""
        )
        + " was not among the shapes read back through the admin session; it was exercised "
        "by a user on the operator body (2026-09-15: the alarm acknowledge / note / clear "
        "tools and the NSO connector calls answered), so the stored form works even though "
        "it was never inspected."
    )
    w("")
    # --- 2
    w("## 2. Least-privilege recipe: a read-only account")
    w("")
    w(
        f"The {n_read} read-only tools touch the {len(read_ticks)} API rows below; the last "
        "column is the tick(s) their requests need on each row (R = every GET plus the POSTs "
        "the row's read template names, W = the other POSTs and every PUT/PATCH, D = DELETE). "
        f"**`docs/rbac/{READONLY_ROLE}.role.json` (section 6) grants the Read tick on every "
        f"row and nothing else** — {len(readonly_role['access_rights'])} rows, R only, never "
        "W — the shape ticking Read on these rows in the role editor "
        "(Administration > Users and Roles > Roles: create a role, tick the rows under their "
        "feature, leave `ApiAccess` on) is taken to produce (inferred, section 1), except for "
        "the URL pattern of the two AAA rows (below). Assign it to a dedicated service "
        "account with device access group `ALL-ACCESS` (or the device scope you intend)."
    )
    w("")
    w("| feature | api_id | API name | ticks the read tools need |")
    w("|---|---|---|---|")
    for api_id, ticks in sorted(
        read_ticks.items(), key=lambda kv: (catalogue[kv[0]]["feature"], kv[0])
    ):
        w(api_row(catalogue, api_id, ticks))
    w("")
    w(
        "`aaa_cw_role_read` (`/crosswork/aaaread/`) is what cnc_check_permissions reads the "
        "account's own role through; `aaa_cwaaa` (`/crosswork/aaa/`) is needed by the RBAC "
        "read tools (cnc_list_roles, cnc_get_user, ...) and is cnc_check_permissions' "
        "fallback (either of the two rows satisfies that tool)."
    )
    w("")
    w(
        f"### The {len(refused_reads)} read tools a Read-only role cannot call"
        if refused_reads
        else "### Every read tool runs under a Read-only role"
    )
    w("")
    if refused_reads:
        w(
            f"Under the stored `{READONLY_ROLE}` role (its {len(readonly_role['access_rights'])} "
            f"R rows plus the read templates and baseline rows the service adds — "
            f"{len(stored_readonly)} rows as read back) cnc_check_permissions permits "
            f"{len(permitted_reads)} of the {n_read} read tools. The other "
            f"{len(refused_reads)} read through a POST Crosswork classes as a **write** — the "
            "path is outside the API's read template (or the API has none) — so the gateway "
            "would refuse it (403) under Read:"
        )
        w("")
        by_api: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        for name, rows in refused_reads:
            for method, path, api_id in rows:
                by_api[api_id].append((name, method, path))
        with_form: set[str] = set()
        for api_id in sorted(by_api):
            methods = sorted({method for _, method, _ in by_api[api_id]})
            reason = "; ".join(read_tick_reason(method, api_id, platform) for method in methods)
            w(f"- `{api_id}` — {reason}:")
            for name, method, path in sorted(by_api[api_id]):
                line = f"  - `{name}`: `{method} {path}`"
                form = READ_FORMS.get(name)
                if form and form[0] in read_alternatives(tools[name], api_id, read_templates):
                    with_form.add(name)
                    line += (
                        f" — its `POST {form[0]}` ({form[1]}) is within the template, so "
                        "that form of the call runs under Read"
                    )
                w(line)
        stale_forms = sorted(set(READ_FORMS) - with_form)
        if stale_forms:
            raise SystemExit(
                "READ_FORMS names tools that are not refused reads with that Read-permitted "
                f"POST on the refused row: {stale_forms}"
            )
        w("")
        w("Two ways to handle them:")
        w("")
        option_lines = []
        for api_id in sorted(write_needed):
            others = sorted(write_tools_on.get(api_id, set()))
            also = (
                f"what its {len(others)} write tool{'s' if len(others) != 1 else ''} ("
                + ", ".join(f"`{n}`" for n in others)
                + ") do there, and any other POST/PUT/PATCH the API serves"
                if others
                else "every POST/PUT/PATCH the API serves (no cnc-mcp write tool uses it)"
            )
            option_lines.append(f"  - `{api_id}`: Write also permits {also}.")
        verbatim_here = sorted(set(write_needed) & set(VERBATIM_POST_BESIDE_GET_APIS))
        w(
            "1. **Tick Write as well as Read** on the rows above — the account is then no "
            "longer read-only at the gateway, because Write is `/.*` for POST/PUT/PATCH on "
            "the whole API. A narrowed POST entry beside the GET entry "
            + (
                "was stored verbatim on "
                + " and ".join(f"`{api_id}`" for api_id in verbatim_here)
                + " in the one shape tried (it then needs the read-template paths listed by "
                "hand, since a row with a POST entry receives none) and "
                if verbatim_here
                else "was not tried on these rows; a custom POST entry "
            )
            + "was reinterpreted into a wider grant where it was the row's only entry "
            "(section 1) — untested as a user, so not offered here:"
        )
        out.extend(option_lines)
        w(
            "2. **Leave them refused** (they answer the gateway's 403 with a hint pointing at "
            "cnc_check_permissions) or, better, keep the agent from seeing them: "
            "`CNC_MCP_DISABLED_TOOLS="
            + ",".join(refused_names)
            + "`."
            + (
                " ("
                + ", ".join(f"`{name}`" for name in sorted(with_form))
                + (" is" if len(with_form) == 1 else " are")
                + " in the list although one form of the call runs under Read, above — leave "
                + ("it" if len(with_form) == 1 else "them")
                + " out to keep that form.)"
                if with_form
                else ""
            )
        )
        w("")
    w(
        "**The two AAA rows.** Both APIs also serve the broader `GET .../v1/api` listing, which "
        "returns the gateway's full API definitions — administrative data; do not grant it to "
        "a non-administrator. A Read tick grants URL pattern `/.*`, and because the gateway "
        "evaluates a row's pattern as an unanchored search on the full path (section 1), "
        "`/.*` includes that listing. The generated bodies therefore give these two rows a "
        "GET entry anchored to exactly the paths the tools send (the service keeps a "
        "custom GET URL verbatim, section 1); where the editor lets you set a row's URL "
        "pattern, use the same:"
    )
    w("")
    for api_id in AAA_APIS:
        out.extend(aaa_entries(readonly_body, api_id))
    w("")
    read_tools = {name: spec for name, spec in tools.items() if spec["read_only"]}
    for api_id in AAA_APIS:
        urls = template_urls(platform, api_id)
        if not urls:
            continue
        posts = post_senders(read_tools, api_id)
        w(
            f"(The `{api_id}` row still receives its read template, POST {urls}, when "
            "stored; "
            + (
                "no read tool sends a POST there.)"
                if not posts
                else "the read tools' POSTs there — "
                + ", ".join(f"`{name}` `POST {path}`" for name, path in posts)
                + " — are classified against it above.)"
            )
        )
    w("")
    # --- 3
    w("## 3. Write areas: what each adds")
    w("")
    w(
        "Write tools are registered only with `CNC_MCP_ENABLE_WRITES=true`. Per area (the "
        "`tools/` module), the API rows and ticks a role needs **in addition to** the "
        f"read-only body of section 2 — a row already ticked Read is listed only when the "
        f"writes add Write or Delete on it. `docs/rbac/{OPERATOR_ROLE}.role.json` is section "
        "2 plus every area below"
        + (
            ", plus the Write ticks the "
            f"{len(refused_reads)} read tools of section 2 need ("
            + ", ".join(f"`{api_id}`" for api_id in sorted(write_needed))
            + ")"
            if write_needed
            else ""
        )
        + "."
    )
    for area in sorted(write_areas):
        specs = write_areas[area]
        area_ticks = ticks_for([s for _, s in specs], read_templates)
        w("")
        names = ", ".join(f"`{n}`" for n, _ in sorted(specs))
        w(f"### {area} ({len(specs)} write tool{'s' if len(specs) != 1 else ''}: {names})")
        w("")
        rows = []
        for api_id, ticks in sorted(
            area_ticks.items(), key=lambda kv: (catalogue[kv[0]]["feature"], kv[0])
        ):
            extra = ticks - readonly_ticks.get(api_id, set())
            if extra:
                rows.append(api_row(catalogue, api_id, extra))
        if rows:
            w("| feature | api_id | API name | ticks to add |")
            w("|---|---|---|---|")
            out.extend(rows)
        else:
            w("Nothing beyond section 2 (the writes use rows and ticks the reads already need).")
    widened = [
        api_id
        for api_id in AAA_APIS
        if aaa_entries(operator_body, api_id) != aaa_entries(readonly_body, api_id)
    ]
    w("")
    w(
        f"`{OPERATOR_ROLE}.role.json` carries {len(operator_role['access_rights'])} rows: "
        f"{sum('W' in t for t in operator_ticks.values())} with Write, "
        f"{sum('D' in t for t in operator_ticks.values())} with Delete, "
        f"{sum(t == {'W'} for t in operator_ticks.values())} Write-only (no read tool uses "
        "the API). "
        + (
            "The AAA rows of section 2 change to:"
            if widened
            else "The AAA rows of section 2 are unchanged (no write tool sends anything on them)."
        )
    )
    if widened:
        w("")
        for api_id in widened:
            out.extend(aaa_entries(operator_body, api_id))
    w("")
    # --- 4
    w("## 4. Per-tool requirements")
    w("")
    w(
        "Every registered tool with the api_id(s) it needs and the ticks per api_id (R = "
        "GET, or a POST the row's read template names; W = any other POST, PUT, PATCH; D = "
        "DELETE; a tool that passes the method through needs all three). Playbooks (area "
        "`composite`) send nothing themselves: their rows are the union of the siblings "
        "they call. A tool that tries one API and falls back to another lists its "
        "alternatives with *or*: one of them suffices. The HTTP methods and path templates "
        "behind each cell are in `src/cnc_mcp/data/rbac_map.json`."
    )
    w("")
    w("| tool | area | kind | api_id: ticks |")
    w("|---|---|---|---|")
    for name, spec in tools.items():
        ticks = ticks_for([spec], read_templates)
        groups = spec.get("any_of") or []
        grouped = {api_id for group in groups for api_id in group}
        cells = ", ".join(
            f"`{api_id}`: {ordered_ticks(t)}"
            for api_id, t in sorted(ticks.items())
            if api_id not in grouped
        )
        if groups:
            alternatives = " *or* ".join(
                ", ".join(f"`{api_id}`: {ordered_ticks(ticks[api_id])}" for api_id in group)
                for group in groups
            )
            cells = f"{cells}, {alternatives}" if cells else alternatives
        kind = "read" if spec["read_only"] else "write"
        if "composed_from" in spec:
            kind += f" playbook ({len(spec['composed_from'])} siblings)"
        if name in refused_names:
            kind += " (needs W, section 2)"
        w(f"| `{name}` | {spec['area']} | {kind} | {cells or '—'} |")
    w("")
    if rbac_map["unresolved"]:
        w("Templates that matched no listen path (the tool would answer a 404/403 on this build):")
        w("")
        for u in rbac_map["unresolved"]:
            w(f"- `{u['tool']}`: {u['method']} `{u['path']}`")
        w("")
    else:
        w("Every request template the tools send resolved to a secured API.")
        w("")
    # --- 5
    w("## 5. Task checkboxes that bundle the same grants")
    w("")
    w(
        "`GET /crosswork/aaa/v1/taskAPIPermission/admin` answered five task bundles (verified "
        "2026-09-14). Ticking a task in the UI grants the listed api_id(s) with the listed "
        "R/W/D ticks — the same letters as the tables above (section 1 says what each "
        "letter's `/.*` entry is stored as; that a tick emits that entry is inferred, not "
        'observed), so treat a bundle as "which rows and ticks the UI sets for you".'
    )
    w("")
    w("| task (UI name) | group | grants | rows it covers here |")
    w("|---|---|---|---|")
    for task_id, (ui_name, group, apis) in sorted(TASK_BUNDLES.items()):
        grants_txt = ", ".join(f"`{api_id}` {letters}" for api_id, letters in sorted(apis.items()))
        covers = []
        for api_id in sorted(apis):
            if api_id not in operator_ticks:
                continue
            reads = read_ticks.get(api_id, set())
            extra = operator_ticks[api_id] - reads
            parts = []
            if reads:
                parts.append(f"reads need {ordered_ticks(reads)}")
            if extra:
                parts.append(f"writes add {ordered_ticks(extra)}")
            covers.append(f"`{api_id}` ({'; '.join(parts)})")
        w(
            f"| {ui_name} (`{task_id}`) | {group} | {grants_txt} | "
            f"{'; '.join(covers) if covers else 'no cnc-mcp tool uses these rows'} |"
        )
    w("")
    w(
        "The remaining tasks the admin role carries — "
        + ", ".join(
            f"{name} (`{task_id}`, {group})" for task_id, name, group in TASKS_WITHOUT_BUNDLE
        )
        + " — returned no API bundle: they are feature permissions "
        "(`GET aaa/v1/userpermission`), not gateway grants, and are not needed for the API "
        "calls above. Whether other task bundles exist for other roles is not known."
    )
    w("")
    # --- 6
    w("## 6. Verifying an account")
    w("")
    w(
        "Log the server in as the account (username/password in `.env`) and call "
        "`cnc_check_permissions` (`make cli ARGS=\"call cnc_check_permissions '{}'\"`). It "
        "reports the identity from the JWT (username, role, device access groups, token "
        "expiry), where it read the role from (`aaaread` or the `aaa/v1` fallback), "
        "GuiAccess / ApiAccess, and then one of:"
    )
    w("")
    w("- `All N registered tools are permitted by role '<role>'`, or")
    w(
        "- `K of N registered tools would be refused by the gateway (403) under role "
        "'<role>'`, followed by the **API rows to grant** (feature | api_id | API name | "
        "methods to add | tools affected) and, per refused tool, the missing METHOD path "
        "rows — the same rows as this page, filtered to what the role lacks. A missing "
        "GET is the Read tick; a missing POST is Read when the row's template names the "
        "path (section 1) and Write otherwise; PUT/PATCH is Write; DELETE is Delete."
    )
    w(
        '- Tools the packaged map does not know are listed under "not in the RBAC map" — '
        "regenerate with `make rbac`."
    )
    w(
        "- `Error: role '<role>' may not read its own role ...` when neither the mirror nor "
        "`aaa/v1` lets the account read its role: grant Read on `aaa_cw_role_read` first."
    )
    w("")
    permitted_write_notes = []
    for name in permitted_writes:
        sent = sorted(
            {
                (method, req["path"], req["api_id"])
                for req in tools[name]["requirements"]
                for method in needed_methods(req["method"])
            }
        )
        sent_txt = ", ".join(f"`{m} {p}` on `{a}`" for m, p, a in sent)
        permitted_write_notes.append(
            f"`{name}` ({sent_txt}: the platform's read template for the API names that "
            "path, so **Read permits this write**)"
        )
    w(
        f"Evaluated against the stored `{READONLY_ROLE}` role, it reports "
        f"{len(refused_reads)} of the {n_read} read tools refused (the list in section 2)"
        + (
            f" and {len(permitted_writes)} write tool"
            f"{'s' if len(permitted_writes) != 1 else ''} **permitted** — "
            + ", ".join(permitted_write_notes)
            if permitted_writes
            else " and no write tool permitted"
        )
        + f". Against the stored `{OPERATOR_ROLE}` role every tool is permitted."
    )
    w("")
    w("What this verification is and is not:")
    w("")
    w(
        "- **Verified (2026-09-14, admin session, test role):** the shape the AAA service "
        "stores a submitted role in — `/.*` rows verbatim, the read templates added to a "
        "GET-only row, a lone custom POST entry reinterpreted, the two baseline rows, the "
        "POST/PUT/GET status codes and the `charset=UTF-8` content type (section 1). The "
        "counts above are computed from that stored shape with Tyk's matching rule; "
        "`tests/fixtures/rbac/` pins the model against the read-backs."
    )
    w(
        "- **Still assumed:** the gateway's refusal itself. No user carrying a restricted "
        "role has logged in yet, so no 403 by a role grant has been observed; the matching "
        "rule (unanchored search on the full path, method listed) is the Tyk v5.1.1 source. "
        "And that the role editor's Read / Write / Delete ticks emit the `/.*` entries the "
        "bodies carry (section 1)."
    )
    w(
        "- The check is **static**: the map is derived from the tool source by "
        "api_coverage.py's extraction heuristic; no tool endpoint is called. A request built "
        "from platform data folds to `{}`; a probe counts as a use."
    )
    w(
        "- A device access group other than ALL-ACCESS restricts devices, not APIs; it is "
        "reported, not evaluated. `/crosswork/aaaread/` is verified readable by the admin "
        "and the generated read-only roles. The two gateway fail-open cases (a regex that "
        "does not compile, an empty `access_rights` map) are reported as refusals."
    )
    w("")
    w("### Ready-made role bodies")
    w("")
    w(
        f"`docs/rbac/{READONLY_ROLE}.role.json` (section 2) and "
        f"`docs/rbac/{OPERATOR_ROLE}.role.json` "
        "(sections 2 + 3) are generated with this page, in the shape `POST "
        '/crosswork/aaa/v1/role` takes — `{"<role name>": {<rbacRole>}}`, the shape '
        "`GET /crosswork/aaa/v1/role` answers — with `rate`/`per`/`quota_max`/`active`/"
        "`partitions`/`key_expires_in` copied from the lab's admin role, one `access_rights` "
        'entry per api_id, `versions ["Default"]` and `allowance_scope ""` like admin. Each '
        "row carries the entries a tick is taken to emit — `/.*` with `[GET]` for Read, "
        "`[POST, PUT, PATCH]` for Write, `[DELETE]` for Delete — which the service stores "
        "verbatim (section 1); the only custom URL is the anchored GET pattern on the two "
        "AAA rows. "
        f"`{READONLY_ROLE}` is R only; `{OPERATOR_ROLE}` adds Write and Delete where a "
        "tool needs them."
    )
    w("")
    w(
        "Load one with an admin's SSO JWT (one curl per file; the content type must carry the "
        "charset), read it back to see the templates and baseline rows the service added, "
        "then verify with cnc_check_permissions as a user carrying the role:"
    )
    w("")
    w("```bash")
    w("CNC=https://<host>:30603")
    w('TGT=$(curl -sk -X POST "$CNC/crosswork/sso/v1/tickets" \\')
    w('      -d "username=$CNC_USER" -d "password=$CNC_PASS")  # an admin')
    w('JWT=$(curl -sk -X POST "$CNC/crosswork/sso/v1/tickets/$TGT" \\')
    w('      -d "service=$CNC/app-dashboard")')
    w("# create (201); to update an existing role instead: PUT .../role/<name> with the")
    w("# inner object (204)")
    w('curl -sk -X POST "$CNC/crosswork/aaa/v1/role" -H "Authorization: Bearer $JWT" \\')
    w('     -H "Content-Type: application/json; charset=UTF-8" \\')
    w(f"     --data @docs/rbac/{READONLY_ROLE}.role.json")
    w(f'curl -sk "$CNC/crosswork/aaa/v1/role/{READONLY_ROLE}" -H "Authorization: Bearer $JWT"')
    w("# release the SSO session (Crosswork caps concurrent sessions per user)")
    w('curl -sk -X DELETE "$CNC/crosswork/sso/v1/tickets/$TGT" -H "Authorization: Bearer $JWT"')
    w("```")
    w("")
    w(
        "No UI import for a role body is documented; the equivalent is ticking the rows of "
        "sections 2 and 3 in the role editor by hand (the bodies are the shape the editor "
        "is taken to emit, section 1), with the two AAA rows' URL patterns set as in "
        "section 2 where the editor allows it."
    )
    return "\n".join(out) + "\n"


# --- driver -----------------------------------------------------------------------------


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def generate(
    catalogue: Catalogue, platform: Platform, src: Path
) -> tuple[dict[str, str], dict[str, Any], list[str]]:
    """Every output file (repo-relative path -> content) plus the map and the ambiguity notes."""
    tools, composed = collect_tools(src)
    rbac_map, ambiguities = build_map(catalogue, platform, tools, composed)
    read_templates = platform["read_templates"]
    read_specs = [s for s in rbac_map["tools"].values() if s["read_only"]]
    all_specs = list(rbac_map["tools"].values())
    # the read-only body: the Read tick on every row the read tools touch, nothing else
    readonly_ticks = {api_id: {"R"} for api_id in ticks_for(read_specs, read_templates)}
    readonly_body = role_body(
        READONLY_ROLE, readonly_ticks, get_templates_for(read_specs), catalogue
    )
    operator_body = role_body(
        OPERATOR_ROLE, ticks_for(all_specs, read_templates), get_templates_for(all_specs), catalogue
    )
    files = {
        str(MAP_RELATIVE): dump_json(rbac_map),
        str(DOC_RELATIVE): render_doc(rbac_map, catalogue, readonly_body, operator_body),
        str(ROLE_DIR_RELATIVE / f"{READONLY_ROLE}.role.json"): dump_json(readonly_body),
        str(ROLE_DIR_RELATIVE / f"{OPERATOR_ROLE}.role.json"): dump_json(operator_body),
    }
    return files, rbac_map, ambiguities


def stale_files(files: dict[str, str], repo: Path) -> list[str]:
    """The generated files (repo-relative path -> content) that differ from what is on disk."""
    return [
        relative
        for relative, content in files.items()
        if not (repo / relative).exists() or (repo / relative).read_text("utf-8") != content
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--catalogue-dir",
        type=Path,
        help="directory with api_v1.json (GET aaa/v1/api) and api_v2.json (GET aaa/v2/api) dumps",
    )
    source.add_argument(
        "--offline",
        action="store_true",
        help="use the catalogue embedded in the committed rbac_map.json (no network)",
    )
    parser.add_argument(
        "--read-templates",
        type=Path,
        metavar="FILE",
        help=(
            "a capture of the platform's read templates (GET aaa/v1/role/<r> after storing "
            "a role whose every row was {url: '/.*', methods: ['GET']}); default: the "
            "'platform' block of the committed rbac_map.json"
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="offline: exit 1 if regenerating would change any generated file; writes nothing",
    )
    parser.add_argument(
        "--src", type=Path, default=DEFAULT_SRC, help="the cnc_mcp package (default: src/cnc_mcp)"
    )
    parser.add_argument(
        "--repo", type=Path, default=REPO_DIR, help="repository root the outputs are written under"
    )
    parser.add_argument("--quiet", action="store_true", help="print only problems")
    args = parser.parse_args(argv)

    map_path = args.repo / MAP_RELATIVE
    if args.check or args.offline:
        if args.catalogue_dir:
            catalogue = load_catalogue_dir(args.catalogue_dir)
        else:
            catalogue = load_catalogue_map(map_path)
    elif args.catalogue_dir:
        catalogue = load_catalogue_dir(args.catalogue_dir)
    else:
        catalogue = asyncio.run(fetch_catalogue_live())
    if args.read_templates:
        platform = load_platform_file(args.read_templates, catalogue)
    else:
        platform = load_platform_map(map_path, catalogue)

    files, rbac_map, ambiguities = generate(catalogue, platform, args.src)
    err = sys.stderr
    for note in ambiguities:
        print(f"warning: {note} (both APIs recorded as requirements)", file=err)

    if args.check:
        stale = stale_files(files, args.repo)
        if stale:
            print("stale (regenerate with 'make rbac'): " + ", ".join(stale), file=err)
            return 1
        if not args.quiet:
            print(f"up to date: {', '.join(files)}", file=err)
        return 0

    for relative, content in files.items():
        path = args.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    if not args.quiet:
        tools = rbac_map["tools"]
        used = {r["api_id"] for spec in tools.values() for r in spec["requirements"]}
        print(
            f"tools={len(tools)} (read {sum(s['read_only'] for s in tools.values())}, "
            f"write {sum(not s['read_only'] for s in tools.values())}) "
            f"api_ids used={len(used)} of {len(catalogue)} "
            f"read templates={len(platform['read_templates'])} "
            f"unresolved={len(rbac_map['unresolved'])}",
            file=err,
        )
        for u in rbac_map["unresolved"]:
            print(f"  unresolved: {u['tool']}: {u['method']} {u['path']}", file=err)
        print("wrote " + ", ".join(files), file=err)
    return 0


if __name__ == "__main__":
    sys.exit(main())
