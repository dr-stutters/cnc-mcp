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
gateway source, ``mw_granular_access.go``; not observed live — the lab had no
restricted role). This script joins the two sides:

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
  in the repository).

Each template is routed to the api_id whose listen path claims it (longest
match, ``{...}`` = one segment, trailing slash optional, segment boundary
required — ``cnc_mcp.tools.admin.listen_path_pattern``, the same function the
runtime check uses). A template whose ``{}`` runtime value could extend into a
LONGER listen path is reported and the longer API is added as a second
requirement (none in the 7.2 catalogue).

Outputs (all deterministic — sorted keys, no timestamps — so ``--check`` can
compare):

- ``src/cnc_mcp/data/rbac_map.json`` — packaged with the server; read by
  ``cnc_check_permissions`` at runtime;
- ``docs/RBAC.md`` — the operator's guide: how Crosswork RBAC works, the
  least-privilege read-only recipe, the per-write-area additions, the per-tool
  table, the task-checkbox bundles, verification;
- ``docs/rbac/cnc-mcp-readonly.role.json`` / ``cnc-mcp-operator.role.json`` —
  ready-made role bodies for ``POST /crosswork/aaa/v1/role`` (untested
  against a real role — the maintainer will test). Per api_id, ``allowed_urls``
  carries one entry PER HTTP METHOD whose ``url`` is an anchored regex covering
  exactly the path templates the granted tools send with that method
  (``path_regex``; methods that send the same templates share an entry), so
  the gateway refuses every other path on the row — in particular the
  read-only body refuses the write paths that share a row and a method with
  the query-over-POST reads (``POST /crosswork/inventory/v1/nodes`` next to
  ``POST .../nodes/query``).

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
    uv run python scripts/rbac_map.py --check            # offline; exit 1 when anything is stale

Limits (a static heuristic — read them before trusting one row): the endpoint
extraction is api_coverage.py's (a request built from platform data folds to
``{}``; a probe counts as a use); the UI's Read/Write/Delete checkboxes' mapping
to HTTP methods is NOT verified (plausibly R=GET, W=POST/PUT/PATCH, D=DELETE —
but many Crosswork READS are ``POST .../query`` calls); the routing and
``allowed_urls`` semantics come from the Tyk v5.1.1 source, not from a
restricted role observed live; the ``/crosswork/aaaread/`` mirror is assumed
readable by every role (verified as admin only). The task-checkbox bundles in
section 5 are the five the lab's ``taskAPIPermission/admin`` returned (verified
2026-09-14); the other tasks map to no API grant there.
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
CATALOGUE_VERIFIED = "2026-09-14"
AAA_READ_V1_API = "/crosswork/aaaread/v1/api"
AAA_READ_V2_API = "/crosswork/aaaread/v2/api"
UNCATEGORISED = "(not in aaa/v2/api)"
ALL_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
WILDCARD = "*"

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

# The two AAA rows the guide calls out for UI-built roles: both APIs also serve
# ``GET .../v1/api`` — the gateway's full API-definition listing, administrative data
# that a non-administrator must not be granted — and a row ticked in the UI grants
# ``/.*``, which Tyk's unanchored search reads as "every path". The generated bodies
# anchor EVERY row (``path_regex``); these two are singled out in the doc only.
AAA_APIS = ("aaa_cw_role_read", "aaa_cwaaa")

# Write-only request paths the guide names as examples of what the read-only body
# refuses at the gateway, next to "and every DELETE" (each must be sent by a write tool
# only — checked at render).
REFUSED_EXAMPLES = (
    ("POST", "/crosswork/inventory/v1/nodes"),
    ("POST", "/crosswork/inventory/v1/tags"),
    ("PUT", "/crosswork/alarms/v1/ack"),
    (
        "POST",
        "/crosswork/nbi/optimization/v3/restconf/operations/"
        "cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-create",
    ),
)

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


def load_catalogue_map(map_path: Path) -> Catalogue:
    if not map_path.exists():
        raise SystemExit(
            f"{map_path} does not exist: run once with --catalogue-dir or live before --offline"
        )
    data = json.loads(map_path.read_text(encoding="utf-8"))
    apis = data.get("apis")
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


def build_map(catalogue: Catalogue, tools: list[api_coverage.Tool], composed: dict[str, list[str]]):
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
        },
        "apis": {api_id: dict(sorted(api.items())) for api_id, api in sorted(catalogue.items())},
        "tools": dict(sorted(tools_out.items())),
        "unresolved": sorted(unresolved, key=lambda u: (u["tool"], u["path"], u["method"])),
    }
    return rbac_map, ambiguities


# --- derived views ----------------------------------------------------------------------

Grants = dict[str, set[str]]  # api_id -> methods


def needed_methods(method: str) -> set[str]:
    return set(ALL_METHODS) if method == WILDCARD else {method}


def grants_for(tool_specs: list[dict[str, Any]]) -> Grants:
    grants: Grants = defaultdict(set)
    for spec in tool_specs:
        for req in spec["requirements"]:
            grants[req["api_id"]] |= needed_methods(req["method"])
    return grants


def ordered(methods: set[str]) -> list[str]:
    return [m for m in ALL_METHODS if m in methods]


Paths = dict[str, dict[str, set[str]]]  # api_id -> method -> path templates sent with it


def paths_for(tool_specs: list[dict[str, Any]]) -> Paths:
    """Per api_id and HTTP method, the path templates the given tools send (a ``*``
    requirement counts for all five methods)."""
    paths: Paths = defaultdict(lambda: defaultdict(set))
    for spec in tool_specs:
        for req in spec["requirements"]:
            for method in needed_methods(req["method"]):
                paths[req["api_id"]][method].add(req["path"])
    return paths


def sent_by(tool_specs: list[dict[str, Any]]) -> set[tuple[str, str]]:
    """Every (method, path template) pair the given tools send."""
    return {
        (method, req["path"])
        for spec in tool_specs
        for req in spec["requirements"]
        for method in needed_methods(req["method"])
    }


# The characters that are regex metacharacters in BOTH Go RE2 (Tyk) and Python's ``re``;
# escaping only these keeps ``-``, ``:`` and ``=`` (common in RESTCONF paths) literal
# and readable (``re.escape`` would write ``\-``, which RE2 accepts but nobody enjoys).
_META_RE = re.compile(r"[\\.^$*+?()\[\]{}|]")


def escape_literal(text: str) -> str:
    return _META_RE.sub(lambda m: "\\" + m.group(), text)


def segment_regex(segment: str, *, tail: bool) -> str:
    """One path segment of a template as a regex: literal text escaped, each ``{}``
    runtime value ``[^/]+`` (one segment) — or ``.+`` in the LAST segment, where a
    RESTCONF-style value (``.../restconf/data/{}``, ``.../node={}``) carries ``/``."""
    value = ".+" if tail else "[^/]+"
    return value.join(escape_literal(part) for part in segment.split(api_coverage.PLACEHOLDER))


def path_regex(listen_path: str, templates: Iterable[str]) -> str:
    """One anchored regex matching exactly the path templates under ``listen_path``.

    ``^<base>/(alt|alt|...)$`` — ``base`` is the part of the template the listen
    path claims (literal for the template, so ``v{.}`` in a listen path becomes
    the ``v1`` the tool sends), the alternatives are the sorted, deduplicated
    remainders rendered by ``segment_regex``; a template that IS the base gives
    ``^<base>$``; templates under different bases are joined with ``|``. A
    template the listen path does not claim but a runtime value of its ``{}``
    could extend into it (``could_extend_into`` — ``build_map`` records those
    on the longer API too) is rendered whole, ``^<template>$``: the gateway
    consults this row only for requests the listen path claims, so that is
    exactly the paths the tool can send here. Tyk (Go RE2) and Python's ``re``
    read the result identically — no lookarounds, no back-references — and
    Tyk searches the FULL request path (section 1 of the guide), which is why
    every alternative starts at ``^`` and names the listen path.
    """
    from cnc_mcp.tools.admin import listen_path_pattern

    claimed = listen_path_pattern(listen_path)
    bare: set[str] = set()
    remainders: dict[str, set[str]] = defaultdict(set)  # base regex -> alternatives
    for template in templates:
        segments = template.split("/")
        rendered = [
            segment_regex(segment, tail=index == len(segments) - 1)
            for index, segment in enumerate(segments)
        ]
        match = claimed.match(template)
        if match is None:
            if not could_extend_into(template, listen_path):
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


def allowed_urls_for(listen_path: str, by_method: dict[str, set[str]]) -> list[dict[str, Any]]:
    """The ``allowed_urls`` of one access_rights entry: one ``{url, methods}`` per HTTP
    method, ``url`` anchored to exactly the templates sent with that method
    (``path_regex``); methods that send the same templates share one entry. Ordered
    by first method (GET, POST, PUT, PATCH, DELETE)."""
    by_templates: dict[frozenset[str], set[str]] = defaultdict(set)
    for method, templates in by_method.items():
        by_templates[frozenset(templates)].add(method)
    entries = [
        {"url": path_regex(listen_path, templates), "methods": ordered(methods)}
        for templates, methods in by_templates.items()
    ]
    return sorted(entries, key=lambda entry: ALL_METHODS.index(entry["methods"][0]))


def role_body(name: str, paths: Paths, catalogue: Catalogue) -> dict[str, Any]:
    access_rights = {
        api_id: {
            "api_name": catalogue[api_id]["name"],
            "api_id": api_id,
            "versions": ["Default"],
            "allowed_urls": allowed_urls_for(catalogue[api_id]["listen_path"], by_method),
            "limit": None,
            "allowance_scope": "",
        }
        for api_id, by_method in sorted(paths.items())
    }
    return {name: {"name": name, **ROLE_SKELETON, "access_rights": access_rights}}


def entry_count(body: dict[str, Any]) -> int:
    """The number of ``allowed_urls`` entries across a role body's access_rights."""
    (role,) = body.values()
    return sum(len(grant["allowed_urls"]) for grant in role["access_rights"].values())


def concrete_path(template: str) -> str:
    """A plausible request path for a template: ``abc`` for a mid-path runtime value,
    ``a/b=c`` (a RESTCONF key, with ``/``) for one in the last segment."""
    segments = template.split("/")
    return "/".join(
        segment.replace(api_coverage.PLACEHOLDER, "a/b=c" if index == len(segments) - 1 else "abc")
        for index, segment in enumerate(segments)
    )


def body_permits(body: dict[str, Any], api_id: str, method: str, path: str) -> bool:
    """Tyk's granular-access rule (section 1 of the guide): the role grants the API and
    some ``allowed_urls`` entry lists the method and matches the full path (unanchored
    search)."""
    (role,) = body.values()
    grant = role["access_rights"].get(api_id)
    return grant is not None and any(
        method in entry["methods"] and re.search(entry["url"], path) is not None
        for entry in grant["allowed_urls"]
    )


def readonly_exceptions(
    readonly_body: dict[str, Any], tools: dict[str, Any]
) -> list[tuple[str, str]]:
    """The (method, path) pairs only the WRITE tools send that the read-only body
    nevertheless permits: GET reads a write tool sends under a read tool's own runtime-
    valued template (``GET /crosswork/proxy/nso/restconf/data/{}`` covers every RESTCONF
    data path — a read tool can send them too). A mutating method here would mean the
    read-only body permits a write a read tool could equally send: the generator stops
    so the read tool's template is narrowed rather than the property silently lost."""
    read_specs = [s for s in tools.values() if s["read_only"]]
    read_pairs = sent_by(read_specs)
    exceptions: set[tuple[str, str]] = set()
    for spec in tools.values():
        if spec["read_only"]:
            continue
        for req in spec["requirements"]:
            for method in needed_methods(req["method"]):
                if (method, req["path"]) in read_pairs:
                    continue
                if body_permits(readonly_body, req["api_id"], method, concrete_path(req["path"])):
                    exceptions.add((method, req["path"]))
    mutating = sorted(pair for pair in exceptions if pair[0] != "GET")
    if mutating:
        raise SystemExit(
            "the read-only body permits write paths only write tools send (narrow the read "
            "tool whose template covers them): "
            + ", ".join(f"{method} {path}" for method, path in mutating)
        )
    return sorted(exceptions)


def covering_reads(
    exceptions: Iterable[tuple[str, str]], tools: dict[str, Any], catalogue: Catalogue
) -> dict[tuple[str, str], list[str]]:
    """For each read-only exception (``readonly_exceptions``), the read tools' path
    templates on an API the write tools send it to, with the same method, whose own
    rendered pattern (``path_regex``) matches it — the runtime-valued reads that cover
    it. A body entry is the union of its templates' patterns, so a permitted exception
    always has one; the generator stops rather than attribute it to the wrong read."""
    read_reqs = {
        (method, req["path"], req["api_id"])
        for spec in tools.values()
        if spec["read_only"]
        for req in spec["requirements"]
        for method in needed_methods(req["method"])
    }
    write_apis: dict[tuple[str, str], set[str]] = defaultdict(set)
    for spec in tools.values():
        if spec["read_only"]:
            continue
        for req in spec["requirements"]:
            for method in needed_methods(req["method"]):
                write_apis[(method, req["path"])].add(req["api_id"])
    covering: dict[tuple[str, str], list[str]] = {}
    for method, path in exceptions:
        found = {
            template
            for read_method, template, api_id in read_reqs
            if read_method == method
            and api_id in write_apis[(method, path)]
            and re.search(
                path_regex(catalogue[api_id]["listen_path"], {template}), concrete_path(path)
            )
        }
        if not found:
            raise SystemExit(f"no read tool's template covers the permitted {method} {path}")
        covering[(method, path)] = sorted(found)
    return covering


# --- documentation ----------------------------------------------------------------------


def md(text: str) -> str:
    return html.unescape(text).replace("|", "\\|")


def api_row(catalogue: Catalogue, api_id: str, methods: set[str]) -> str:
    api = catalogue[api_id]
    return (
        f"| {md(api['feature'])} | `{api_id}` | {md(api['name'])} | {', '.join(ordered(methods))} |"
    )


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


def render_doc(
    rbac_map: dict[str, Any],
    catalogue: Catalogue,
    readonly_body: dict[str, Any],
    operator_body: dict[str, Any],
) -> str:
    tools = rbac_map["tools"]
    read_specs = [s for s in tools.values() if s["read_only"]]
    all_specs = list(tools.values())
    read_grants = grants_for(read_specs)
    write_areas: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for name, spec in tools.items():
        if not spec["read_only"]:
            write_areas[spec["area"]].append((name, spec))
    operator_grants = grants_for(all_specs)
    write_only = sent_by(all_specs) - sent_by(read_specs)
    for example in REFUSED_EXAMPLES:
        if example not in write_only:
            raise SystemExit(
                f"REFUSED_EXAMPLES: {example[0]} {example[1]} is no longer a write-only path"
            )
    refused_examples = ", ".join(f"`{method} {path}`" for method, path in REFUSED_EXAMPLES)
    info = rbac_map["generated_from"]
    n_read = len(read_specs)
    n_write = len(tools) - n_read

    out: list[str] = []
    w = out.append
    w("# RBAC: what a Crosswork account needs to run cnc-mcp")
    w("")
    w(
        "> **Generated** by `scripts/rbac_map.py` from the tool source and the gateway's "
        f"secured-API catalogue ({info['platform']}, {info['api_count']} APIs in "
        f"{info['feature_count']} features, catalogue verified live {info['catalogue_verified']}) "
        "— do not edit by hand. Regenerate with `make rbac` (offline, from the catalogue "
        "embedded in `src/cnc_mcp/data/rbac_map.json`) or `make rbac-fetch` (re-read the "
        "catalogue from a live instance); `make rbac-check` fails when the committed files "
        "are stale."
    )
    w("")
    w(
        f"The server registers {len(tools)} tools ({n_read} read-only, {n_write} write). "
        "Each sends a known set of HTTP requests; each request is routed by the gateway to "
        "one secured API, and a role must grant that API (with the method) or the gateway "
        "refuses the call (403). This page lists exactly which API rows a role needs, first "
        "for a read-only account, then per write area, then per tool."
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
        'lab\'s only role, `admin`, grants every API with `url "/.*"` and all five methods.'
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
        "**From the Tyk v5.1.1 gateway source** (`gateway/api_loader.go`, "
        "`mw_access_rights.go`, `mw_granular_access.go` — read, not observed live: the lab "
        "had no restricted role, so no refusal by a role grant was ever captured):"
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
        "`/crosswork/inventory/v1/nodes/query`, `^/v1/nodes/query$` permits nothing. The "
        "method must be listed on a matching entry; an API with an empty `allowed_urls` "
        "has no path restriction."
    )
    w(
        "- A request the role does not permit (no entry for the API, or no matching "
        "`allowed_urls` entry) is refused with a **403**; the body Crosswork puts on that "
        "403 was not observed. Two fail-open cases: an `allowed_urls` regex that does not "
        "compile is let through, and so is a role whose `access_rights` map is empty — "
        "cnc_check_permissions reports both as refusals (the role as it should be "
        "configured)."
    )
    w("")
    w("**Not verified (assumed — say so when it bites):**")
    w("")
    w(
        "- Which HTTP methods the UI's **R / W / D** checkboxes translate to on the wire. "
        "Plausibly R = GET, W = POST/PUT/PATCH, D = DELETE — but many Crosswork READS are "
        "`POST .../query` calls (`POST /crosswork/inventory/v1/nodes/query` lists devices), so "
        'a UI-built "Read" role may refuse them. The tables below give the exact methods.'
    )
    w(
        "- Whether `/crosswork/aaaread/` is readable by every role (verified as admin only; "
        "no restricted role existed on the lab). cnc_check_permissions falls back to "
        "`/crosswork/aaa/v1` and says which one answered — either grant suffices for it."
    )
    w("- The generated role bodies (section 6) have not been loaded into a real Crosswork yet.")
    w("")
    # --- 2
    w("## 2. Least-privilege recipe: a read-only account")
    w("")
    w(
        f"The {n_read} read-only tools need the {len(read_grants)} API rows below with the "
        "listed methods. **The recommended way is to load "
        f"`docs/rbac/{READONLY_ROLE}.role.json` (section 6)**: it grants each row exactly the "
        "request paths the read tools send with each method (anchored URL patterns, one per "
        "method), so every path that only the write tools send is refused at the gateway "
        "(403) even where it shares a row and a method with a read — "
        "`POST /crosswork/inventory/v1/nodes/query` (list devices) is permitted while "
        f"{refused_examples} and every DELETE are not. Assign the role to a dedicated service "
        "account with device access group `ALL-ACCESS` (or the device scope you intend)."
    )
    w("")
    w(
        "Building the role in the UI instead (Administration > Users and Roles > Roles: create "
        "a role, tick these rows under their feature, leave `ApiAccess` on) cannot reach the "
        "same result: the editor's per-row **Read / Write / Delete** checkboxes cannot separate "
        "a POST query from a POST create on the same row, so a UI-built role is read-only only "
        "if the UI's *Read* maps to what the tools send — which is not verified (section 1). If "
        "the editor offers only Read / Write / Delete, tick **Write as well as Read** for every "
        "row whose methods include POST, PUT or PATCH (the query-over-POST reads), and accept "
        "that the row then permits its writes too (`POST /crosswork/inventory/v1/nodes` next "
        "to `POST .../nodes/query`)."
    )
    w("")
    w("| feature | api_id | API name | HTTP methods the read tools use |")
    w("|---|---|---|---|")
    for api_id, methods in sorted(
        read_grants.items(), key=lambda kv: (catalogue[kv[0]]["feature"], kv[0])
    ):
        w(api_row(catalogue, api_id, methods))
    w("")
    w(
        "`aaa_cw_role_read` (`/crosswork/aaaread/`) is what cnc_check_permissions reads the "
        "account's own role through; `aaa_cwaaa` (`/crosswork/aaa/`) is needed by the RBAC "
        "read tools (cnc_list_roles, cnc_get_user, ...) and is cnc_check_permissions' "
        "fallback (either of the two rows satisfies that tool)."
    )
    w("")
    w(
        "**The two AAA rows in a UI-built role.** Both APIs also serve the broader "
        "`GET .../v1/api` listing, which returns the gateway's full API definitions — "
        "administrative data; do not grant it to a non-administrator. A row ticked in the UI "
        "grants URL pattern `/.*`, and because the gateway evaluates a row's pattern as an "
        "unanchored search on the full path (section 1), `/.*` (or any unanchored pattern) "
        "includes that listing. Where the editor lets you set a row's URL pattern, use the "
        "anchored patterns below — exactly the paths the read tools send, derived from the "
        "map; the generated bodies carry them (and a pattern of the same kind on every other "
        "row):"
    )
    w("")
    for api_id in AAA_APIS:
        out.extend(aaa_entries(readonly_body, api_id))
    w("")
    # --- 3
    w("## 3. Write areas: what each adds")
    w("")
    w(
        "Write tools are registered only with `CNC_MCP_ENABLE_WRITES=true`. Per area (the "
        "`tools/` module), the API rows and methods a role needs **in addition to** section 2 "
        "— a row already granted for reads is listed only when the writes need more methods "
        "on it. `docs/rbac/cnc-mcp-operator.role.json` is section 2 plus every area below."
    )
    for area in sorted(write_areas):
        specs = write_areas[area]
        area_grants = grants_for([s for _, s in specs])
        w("")
        names = ", ".join(f"`{n}`" for n, _ in sorted(specs))
        w(f"### {area} ({len(specs)} write tool{'s' if len(specs) != 1 else ''}: {names})")
        w("")
        rows = []
        for api_id, methods in sorted(
            area_grants.items(), key=lambda kv: (catalogue[kv[0]]["feature"], kv[0])
        ):
            extra = methods - read_grants.get(api_id, set())
            if extra:
                rows.append(api_row(catalogue, api_id, extra))
        if rows:
            w("| feature | api_id | API name | additional methods |")
            w("|---|---|---|---|")
            out.extend(rows)
        else:
            w("Nothing beyond section 2 (the writes use rows and methods the reads already need).")
    widened = [
        api_id
        for api_id in AAA_APIS
        if aaa_entries(operator_body, api_id) != aaa_entries(readonly_body, api_id)
    ]
    w("")
    w(
        f"`{OPERATOR_ROLE}.role.json` widens the URL patterns accordingly: per row, the "
        "methods the writes add get their own anchored entries covering exactly the write "
        "paths, and a method the reads already use gains the write paths it sends (section "
        "6). "
        + (
            "The AAA rows of section 2 widen to:"
            if widened
            else "The AAA rows of section 2 are unchanged (the write tools add no path on them)."
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
        "Every registered tool with the api_id(s) it needs and the methods per api_id "
        "(`*` in the map = the tool passes the method through, all five needed; `{}` in a "
        "path = a runtime value). Playbooks (area `composite`) send nothing themselves: their "
        "rows are the union of the siblings they call. A tool that tries one API and falls "
        "back to another lists its alternatives with *or*: one of them suffices."
    )
    w("")
    w("| tool | area | kind | api_id: methods |")
    w("|---|---|---|---|")
    for name, spec in tools.items():
        grants = grants_for([spec])
        groups = spec.get("any_of") or []
        grouped = {api_id for group in groups for api_id in group}
        cells = ", ".join(
            f"`{api_id}`: {'/'.join(ordered(m))}"
            for api_id, m in sorted(grants.items())
            if api_id not in grouped
        )
        if groups:
            alternatives = " *or* ".join(
                ", ".join(f"`{api_id}`: {'/'.join(ordered(grants[api_id]))}" for api_id in group)
                for group in groups
            )
            cells = f"{cells}, {alternatives}" if cells else alternatives
        kind = "read" if spec["read_only"] else "write"
        if "composed_from" in spec:
            kind += f" playbook ({len(spec['composed_from'])} siblings)"
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
        "R/W/D letters — how those letters map to HTTP methods is not verified (section 1), "
        'so treat a bundle as "which rows the UI ticks for you", not as a substitute for the '
        "methods above."
    )
    w("")
    w("| task (UI name) | group | grants | rows it covers here |")
    w("|---|---|---|---|")
    for task_id, (ui_name, group, apis) in sorted(TASK_BUNDLES.items()):
        grants_txt = ", ".join(f"`{api_id}` {letters}" for api_id, letters in sorted(apis.items()))
        covers = []
        for api_id in sorted(apis):
            if api_id not in operator_grants:
                continue
            reads = read_grants.get(api_id, set())
            extra = operator_grants[api_id] - reads
            parts = []
            if reads:
                parts.append(f"reads need {'/'.join(ordered(reads))}")
            if extra:
                parts.append(f"writes add {'/'.join(ordered(extra))}")
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
        "rows — the same rows as this page, filtered to what the role lacks."
    )
    w(
        '- Tools the packaged map does not know are listed under "not in the RBAC map" — '
        "regenerate with `make rbac`."
    )
    w(
        "- `Error: role '<role>' may not read its own role ...` when neither the mirror nor "
        "`aaa/v1` lets the account read its role: grant GET on `aaa_cw_role_read` first."
    )
    w("")
    w("Caveats the tool repeats in its own output:")
    w("")
    w(
        "- The check is **static**: the map is derived from the tool source by "
        "api_coverage.py's extraction heuristic and matched against the role's "
        "`access_rights` with the Tyk semantics of section 1 (unanchored search on the full "
        "path); no tool endpoint is called. A request built from platform data folds to "
        "`{}`; a probe counts as a use."
    )
    w("- The R/W/D → HTTP-method mapping of the UI is unverified; the map names methods.")
    w(
        "- A device access group other than ALL-ACCESS restricts devices, not APIs; it is "
        "reported, not evaluated."
    )
    w("- `/crosswork/aaaread/` is assumed readable by every role (verified as admin only).")
    w(
        "- The two gateway fail-open cases (a regex that does not compile, an empty "
        "`access_rights` map) are reported as refusals."
    )
    w("")
    w("### Ready-made role bodies")
    w("")
    (readonly_role,) = readonly_body.values()
    (operator_role,) = operator_body.values()
    w(
        f"`docs/rbac/{READONLY_ROLE}.role.json` (section 2) and "
        f"`docs/rbac/{OPERATOR_ROLE}.role.json` "
        "(sections 2 + 3) are generated with this page, in the shape the AAA API document "
        'gives for `POST /crosswork/aaa/v1/role` — `{"<role name>": {<rbacRole>}}`, the '
        "shape `GET /crosswork/aaa/v1/role` answers — with `rate`/`per`/`quota_max`/`active`/"
        "`partitions`/`key_expires_in` copied from the lab's admin role, one `access_rights` "
        'entry per api_id, `versions ["Default"]` and `allowance_scope ""` like admin. Where '
        'admin grants `allowed_urls [{"url": "/.*", "methods": [all five]}]`, a generated '
        "row carries **one entry per HTTP method**, "
        '`{"url": "^<listen path>/(<path>|<path>|...)$", "methods": ["POST"]}`, whose URL '
        "pattern is an anchored regex naming exactly the path templates the granted tools "
        "send with that method (methods that send the same paths share an entry; a runtime "
        "value is one segment, `[^/]+`, except in the last segment, `.+`, where a RESTCONF "
        "key such as `.../device={}` or `.../restconf/data/{}` carries `/`). The gateway runs "
        "each pattern as an unanchored search on the full request path (section 1), which is "
        "why every alternative starts with `^` and the listen path and ends with `$` — "
        "nothing else on the row is permitted. Two limits of that claim: a last-segment "
        "`.+` also admits deeper sub-paths under its template, and a mid-path `[^/]+` "
        "assumes the runtime key never contains `/` (the gateway matches the decoded path, "
        "so a percent-encoded `/` is refused too) — no key the tools send does today."
    )
    w("")
    exceptions = readonly_exceptions(readonly_body, tools)
    if exceptions:
        by_cover: dict[tuple[str, ...], list[tuple[str, str]]] = defaultdict(list)
        for pair, covers in covering_reads(exceptions, tools, catalogue).items():
            by_cover[tuple(covers)].append(pair)
        listed = "; ".join(
            ", ".join(f"`{method} {path}`" for method, path in pairs)
            + " under "
            + " and ".join(f"`{pairs[0][0]} {template}`" for template in covers)
            for covers, pairs in sorted(by_cover.items())
        )
        exception_text = (
            f" The {len(exceptions)} write-tool pairs it does match are GETs: reads a write "
            "tool sends that fall under a read tool's own runtime-valued path, so a read tool "
            f"can send them just as well ({listed}). No mutating method leaks — the generator "
            "refuses to write a body where one would."
        )
    else:
        exception_text = ""
    w(
        f"So `{READONLY_ROLE}` ({len(readonly_role['access_rights'])} rows, "
        f"{entry_count(readonly_body)} URL entries) **refuses every write path at the "
        f"gateway**: of the {len(write_only)} (method, path) pairs only the write tools "
        "send, none with a mutating method matches any of its entries — "
        f"{refused_examples} and every DELETE, PUT and PATCH are refused — while every "
        f"path the read tools send matches one.{exception_text} "
        "`tests/test_rbac_map.py` proves all of this under Tyk's "
        f"matching rule. `{OPERATOR_ROLE}` ({len(operator_role['access_rights'])} rows, "
        f"{entry_count(operator_body)} URL entries) permits every path every tool sends, and "
        "nothing beyond their templates. Neither body permits `GET /crosswork/aaa/v1/api` or "
        "`GET /crosswork/aaaread/v1/api`."
    )
    w("")
    w(
        "**They are generated and have not been tested against a real role** (the "
        "maintainer will); load one with the SSO JWT (one curl per file) and then verify "
        "with cnc_check_permissions as a user carrying the role:"
    )
    w("")
    w("```bash")
    w("CNC=https://<host>:30603")
    w('TGT=$(curl -sk -X POST "$CNC/crosswork/sso/v1/tickets" \\')
    w('      -d "username=$CNC_USER" -d "password=$CNC_PASS")  # an admin')
    w('JWT=$(curl -sk -X POST "$CNC/crosswork/sso/v1/tickets/$TGT" \\')
    w('      -d "service=$CNC/app-dashboard")')
    w('curl -sk -X POST "$CNC/crosswork/aaa/v1/role" -H "Authorization: Bearer $JWT" \\')
    w(f'     -H "Content-Type: application/json" --data @docs/rbac/{READONLY_ROLE}.role.json')
    w("# release the SSO session (Crosswork caps concurrent sessions per user)")
    w('curl -sk -X DELETE "$CNC/crosswork/sso/v1/tickets/$TGT" -H "Authorization: Bearer $JWT"')
    w("```")
    w("")
    w(
        "No UI import for a role body is documented; the alternative is ticking the rows of "
        "sections 2 and 3 in the role editor by hand — with the caveat of section 2 that the "
        "editor's Read / Write / Delete checkboxes cannot express the per-path grants above."
    )
    return "\n".join(out) + "\n"


# --- driver -----------------------------------------------------------------------------


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def generate(catalogue: Catalogue, src: Path) -> tuple[dict[str, str], dict[str, Any], list[str]]:
    """Every output file (repo-relative path -> content) plus the map and the ambiguity notes."""
    tools, composed = collect_tools(src)
    rbac_map, ambiguities = build_map(catalogue, tools, composed)
    read_specs = [s for s in rbac_map["tools"].values() if s["read_only"]]
    all_specs = list(rbac_map["tools"].values())
    readonly_body = role_body(READONLY_ROLE, paths_for(read_specs), catalogue)
    operator_body = role_body(OPERATOR_ROLE, paths_for(all_specs), catalogue)
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

    files, rbac_map, ambiguities = generate(catalogue, args.src)
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
            f"unresolved={len(rbac_map['unresolved'])}",
            file=err,
        )
        for u in rbac_map["unresolved"]:
            print(f"  unresolved: {u['tool']}: {u['method']} {u['path']}", file=err)
        print("wrote " + ", ".join(files), file=err)
    return 0


if __name__ == "__main__":
    sys.exit(main())
