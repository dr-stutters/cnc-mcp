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
  (``{<feature>: [{api_id, name}]}``, the grouping the UI's role editor shows;
  each api_id's ``position`` in that response is recorded because the editor
  shows a display-name group as its FIRST api_id in this order) and
  ``GET /crosswork/aaaread/v1/api`` (the Tyk API definitions; ONLY
  ``api_id``, ``name`` and ``proxy.listen_path`` are read — the rest of a
  definition is the gateway's administrative configuration, which has no place
  in the repository);
- the platform side, verified live in two rounds — 2026-09-14 by storing test
  roles through an admin session and reading them back, 2026-09-15 by building
  a role in the UI's role editor (Administration > Users and Roles > Roles) and
  reading THAT back, and by reading the editor's own role model in the UI
  bundle (``class bP``: ``setAllApis`` / ``setAccess`` / ``getPayload``, the
  ``Afe`` defaults). The editor submits, per ticked row, ONE ``allowed_urls``
  entry ``{url: "/.*", methods: <union>}`` — Read adds GET, Write adds POST,
  PUT, PATCH, Delete adds DELETE — with ``versions []`` and the ``Afe`` role
  fields (``ROLE_SKELETON``); a row in the editor is a DISPLAY-NAME GROUP (one
  tick grants every api_id sharing the row's name), and the editor hides the
  four api_ids of ``HIDDEN_APIS``. Crosswork's AAA service does NOT store a
  submitted role verbatim: a row with a GET entry and no POST entry receives
  the platform's per-API **read templates** — extra POST entries naming the
  read-by-POST paths of that API (``/.+/query$`` on ``inventory_cwinventory``,
  the get-*/…-preview RPC names on ``optima_restconf``, ...) — and every
  stored role gains three **baseline rows** (``BASELINE_APIS``:
  ``aaa_cw_role_read`` with its query template, ``aaa_cwpassword``,
  ``aaa_selected_pref``), which the generated bodies therefore never carry.
  On the APIs on which the service reserves a last segment ``delete`` for the
  Delete tick (``POST_DELETE_APIS`` — presumably the ones that delete through
  ``POST .../delete``; the name records the presumption) a row whose single
  entry carries POST without DELETE — Write without Delete, the shape the
  editor submits — is SPLIT: POST moves to a second entry under
  ``NOT_DELETE_PATTERN`` (any path whose last segment is not the word
  ``delete``) and the other methods stay on the entry in alphabetical order
  (2026-09-15: the operator body's ``[GET, POST, PUT, PATCH]`` rows on
  ``cwcollection``, ``optima_restconf``, ``platform_cwplatform`` read back as
  ``[GET, PATCH, PUT] /.*`` + ``[POST] <pattern>``; 2026-09-14: a custom-url
  POST-only entry read back with its methods stripped to ``[]`` and the
  pattern entry appended — the same split). A role whose first entry
  on some api_id has a url other than ``/.*`` crashes the Roles page for
  everyone (the editor looks the url up among its ``/.*`` rows), so a body
  never carries a custom url. The captured templates, baseline rows,
  POST-delete APIs and the pattern are carried in the map's ``platform``
  block (``--read-templates`` loads a fresh capture; offline runs reuse what
  the committed map carries, like the catalogue); ``tests/fixtures/rbac/``
  holds the sanitised read-backs the stored-role model
  (``stored_access_rights``) is pinned against — the two generated bodies as
  committed, the UI-built role and two API-stored experiments.

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
  ready-made role bodies for ``POST /crosswork/aaa/v1/role`` in the shape the
  role editor submits: per api_id one ``/.*`` entry whose methods are the
  union of the row's ticks (R = GET, W = POST/PUT/PATCH, D = DELETE) in the
  editor's order, ``versions []``, the editor's role fields; the read-only
  body carries R rows only. Unlike a UI-built role they grant single api_ids,
  not whole display-name groups — so an API-loaded role is managed through
  the API: the editor displays a group as its first api_id and a Save rebuilds
  the group from the editor's own model (read from the bundle).

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
# The sanitised read-back of the role built in the UI's role editor (2026-09-15): the
# guide cites it, and reads from it which Read-ticked APIs stored GET-only (no template).
UI_FIXTURE_RELATIVE = Path("tests/fixtures/rbac/stored_ui_built_role.json")

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

# The role editor's per-row ticks and the methods each one adds to the row's single
# ``{url: "/.*", methods: [...]}`` entry (the bundle's getPayload: read -> GET; write ->
# POST, PUT, PATCH; delete -> DELETE; url always "/.*"). Verified 2026-09-15: a role
# built in the editor with one Read, one Write and one Delete tick was read back as
# exactly these entries (tests/fixtures/rbac/stored_ui_built_role.json).
TICKS = ("R", "W", "D")
TICK_METHODS: dict[str, tuple[str, ...]] = {
    "R": ("GET",),
    "W": ("POST", "PUT", "PATCH"),
    "D": ("DELETE",),
}
TICK_NAMES = {"R": "Read", "W": "Write", "D": "Delete"}
ANY_PATH = "/.*"
UI_VERIFIED = "2026-09-15"

# The rows the AAA service adds to EVERY role it stores (verified 2026-09-15: a role
# built in the UI without any of them, and the two generated roles PUT without any AAA
# row, all came back with the three): the account's own role through the read-only
# mirror (aaa_cw_role_read, GET plus its query template), its password change and its
# UI preferences. Captured in the map's platform block, kept apart from the read
# templates, and never emitted in a generated body.
BASELINE_APIS = ("aaa_cw_role_read", "aaa_cwpassword", "aaa_selected_pref")

# The api_ids the role editor does not show as rows (the bundle's setAllApis): the
# three baseline APIs and cwcrossclusterstate (not in the 7.2 catalogue).
HIDDEN_APIS = (*BASELINE_APIS, "cwcrossclusterstate")

# The sanitised read-backs of the generated bodies as committed (2026-09-15: each PUT
# through an admin API session, then GET): the guide's section 6 cites them and states
# the verdict the runtime evaluator gives on the stored form; the generator stops when a
# read-back does not give the model's verdict for the committed body.
GENERATED_FIXTURES = {
    READONLY_ROLE: Path("tests/fixtures/rbac/stored_generated_readonly.json"),
    OPERATOR_ROLE: Path("tests/fixtures/rbac/stored_generated_operator.json"),
}

# The APIs on which the service reserves a last segment ``delete`` for the Delete tick
# (presumably the ones that delete through ``POST .../delete`` — nothing in the map or
# the fixtures shows such an endpoint; the names below record the presumption) and so
# does not store a Write-without-Delete row verbatim: a row whose SINGLE entry carries
# POST and not DELETE is split — the entry keeps its url and its other methods, in
# alphabetical order (``[]`` when POST was the only one), and a second entry ``{url:
# NOT_DELETE_PATTERN, methods: ["POST"]}`` is appended — POST is permitted on every path
# whose last segment is not the word ``delete``. Read and Write submitted as two entries
# beside each other (the 2026-09-14 experiment) were stored verbatim; a row carrying
# DELETE has been stored verbatim wherever it was tried (five APIs, none of them in
# these lists). The platform block's ``post_delete_apis`` must be exactly the union of
# the two tuples: the guide documents each API as one or the other and the generator
# stops on any other (verify live before documenting it).
POST_DELETE_VERIFIED = (
    # VERIFIED for the union entry (2026-09-15: the operator body's [GET, POST, PUT,
    # PATCH] rows came back split — tests/fixtures/rbac/stored_generated_operator.json)
    "cwcollection",
    "optima_restconf",
    "platform_cwplatform",
)
POST_DELETE_INFERRED = (
    # INFERRED from the 2026-09-14 POST-only experiment (not a fixture): a row whose
    # only entry was a custom-url POST came back with its methods stripped to [] and the
    # not-delete pattern entry appended on these seven (and on cwcollection and
    # optima_restconf — POST_ONLY_EXPERIMENT_APIS); no union entry has been stored on
    # them, so the split of a union entry there is the model's extrapolation
    "collection_dg-manager",
    "cw-fault-alarms-api",
    "cw-fault-events-api",
    "cw-probe-mgr",
    "cw-ztp-service",
    "dg-manager-global-parameters-api",
    "optima_analytics_api",
)
POST_DELETE_APIS = (*POST_DELETE_VERIFIED, *POST_DELETE_INFERRED)
# The 2026-09-14 experiment the inferred list rests on (an admin session storing a body
# whose rows carried custom-url entries, then reading it back; its read-back was
# deleted with that shape and is not a fixture — the maintainer's notes and the guide's
# earlier generation are the record): the nine APIs on which a row whose ONLY entry was
# a custom-url POST came back with its methods stripped to [] and the pattern entry
# appended, and the four on which — in the same submission — a custom GET entry beside
# a custom POST entry was stored verbatim (no template added). The second observation is
# what the split keys on: the row having a SINGLE entry (``is_split_row``).
POST_ONLY_EXPERIMENT_APIS = (*POST_DELETE_INFERRED, "cwcollection", "optima_restconf")
POST_BESIDE_GET_EXPERIMENT_APIS = (
    "device-config",
    "inventory_cwinventory",
    "platform_cwplatform",
    "tsdn_cat-restconf-nbi",
)
# The url the service stores POST under when it splits such a row (read back verbatim
# on the three verified APIs): an unanchored search that matches when the LAST path
# segment is 1-5 characters, 7 or more, or six characters that differ from d-e-l-e-t-e
# in at least one position — every path except one ending in the segment ``delete``
# (a trailing slash allowed); ``Delete`` and ``deletes`` pass.
NOT_DELETE_PATTERN = (
    ".+(?:/[^/]{1,5}|/[^/]{7,}|/[^d][^/]{5}|/[^/][^e][^/]{4}|/[^/]{2}[^l][^/]{3}"
    "|/[^/]{3}[^e][^/]{2}|/[^/]{4}[^t][^/]|/[^/]{5}[^e])[/]?$"
)
DELETE_SEGMENT = "delete"

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

# The role fields the editor submits with every role (the UI bundle's ``Afe`` defaults,
# minus the empty ``_id``/``id`` the service assigns); read back unchanged from the
# UI-built role (2026-09-15). The service adds ``STORED_ROLE_FIELDS`` when storing.
# ``rate``/``per`` is the gateway's per-key rate limit: 1000 requests per 60 s is the
# editor's default (every UI-built role carries it; the built-in admin role carries
# 5000) — raise it through the API if an agent-driven server hits 429s (ApiClient
# retries them, slower). The service's own baseline rows carry ``versions
# ["Default"]``; a submitted row keeps its ``versions []``.
BASELINE_VERSIONS = ["Default"]
ROLE_SKELETON: dict[str, Any] = {
    "org_id": "1",
    "rate": 1000,
    "per": 60,
    "quota_max": -1,
    "quota_renewal_rate": 60,
    "hmac_enabled": False,
    "active": True,
    "is_inactive": False,
    "tags": [],
    "key_expires_in": -1,
    "partitions": {"quota": False, "rate_limit": False, "acl": False},
}
STORED_ROLE_FIELDS: dict[str, Any] = {
    "throttle_interval": 0,
    "throttle_retry_limit": 0,
    "enable_http_signature_validation": False,
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


Catalogue = dict[str, dict[str, Any]]  # api_id -> {name, feature, listen_path, position}
CATALOGUE_FIELDS = ("name", "feature", "listen_path", "position")
Entries = list[dict[str, Any]]  # [{url, methods}] — an access_rights row's allowed_urls
# {version, captured, read_templates, baseline_rows, post_delete_apis, not_delete_pattern}
Platform = dict[str, Any]
Ticks = dict[str, set[str]]  # api_id -> subset of TICKS


# --- catalogue ------------------------------------------------------------------------


def sanitise_catalogue(v1: Any, v2: Any) -> Catalogue:
    """Keep ONLY api_id, name and proxy.listen_path from the API definitions, plus the
    feature each api_id sits under in the v2 grouping and its ``position`` in that
    response (features in response order, then list order: the order the role editor
    builds its rows in — ``setAllApis`` iterates the v2 response, and a display-name
    group is shown as its first api_id). Nothing else is copied."""
    if not isinstance(v1, list):
        raise SystemExit("aaa/v1/api: expected a list of API definitions")
    if not isinstance(v2, dict):
        raise SystemExit("aaa/v2/api: expected {<feature>: [{api_id, name}]}")
    feature_of: dict[str, str] = {}
    position_of: dict[str, int] = {}
    for feature, entries in v2.items():
        for entry in entries if isinstance(entries, list) else []:
            if isinstance(entry, dict) and isinstance(entry.get("api_id"), str):
                feature_of.setdefault(entry["api_id"], str(feature))
                position_of.setdefault(entry["api_id"], len(position_of))
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
            "position": position_of.get(api_id),
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
    catalogue: Catalogue = {}
    for api_id, api in apis.items():
        if not isinstance(api, dict) or "position" not in api:
            raise SystemExit(
                f"{map_path}: {api_id} carries no 'position' (the api_id's place in the "
                "aaa/v2/api response): regenerate once with --catalogue-dir or live"
            )
        catalogue[api_id] = {
            "name": str(api["name"]),
            "feature": str(api["feature"]),
            "listen_path": str(api["listen_path"]),
            "position": None if api["position"] is None else int(api["position"]),
        }
    return catalogue


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


def entry_order(entry: dict[str, Any]) -> tuple[bool, str, list[str]]:
    """Sort key for a row's entries: the ``/.*`` entry first (where the service stores it
    — every row of every read-back in ``tests/fixtures/rbac/`` starts with it, and the
    editor reads only that first entry), then by url and methods."""
    return (entry["url"] != ANY_PATH, entry["url"], entry["methods"])


def sanitise_entries(raw: Any, context: str) -> Entries:
    """``[{url, methods}]`` with nothing else copied: ``url`` a regex that compiles,
    ``methods`` upper-cased, known, in GET/POST/PUT/PATCH/DELETE order; entries in
    ``entry_order`` (``/.*`` first, then by url) so the map is deterministic whatever
    order the capture lists them in."""
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
    return sorted(entries, key=entry_order)


def sanitise_platform(
    read_templates: Any,
    baseline_rows: Any,
    captured: Any,
    catalogue: Catalogue,
    post_delete_apis: Any = POST_DELETE_APIS,
    not_delete_pattern: Any = NOT_DELETE_PATTERN,
) -> Platform:
    """The map's platform block from two raw ``{api_id: [{url, methods}]}`` mappings —
    the read templates the service appends to a GET-only row and the baseline rows it
    adds to every role: every api_id must be in the catalogue, a baseline row must be
    one of ``BASELINE_APIS`` (``aaa_cw_role_read`` legitimately appears in both: its
    baseline row carries the same query template it receives when submitted), and only
    url/methods survive. A read template is BY DEFINITION the POST entries the service
    appended to a GET-only row, so an entry with any other methods under
    ``read_templates`` — or a baseline API other than ``aaa_cw_role_read`` there — is a
    capture in the previous format (the baseline rows listed among the templates, with
    their GET/PUT entries) and is refused rather than re-split. ``post_delete_apis``
    (catalogued api_ids, stored sorted) and ``not_delete_pattern`` (a regex that must
    refuse a path ending in the segment ``delete`` and permit any other, since that is
    what the guide says of it) are the split rule's data — a capture may carry them,
    the committed map does, the constants are the 2026-09-15 read-back."""
    if not isinstance(read_templates, dict) or not isinstance(baseline_rows, dict):
        raise SystemExit("platform: read_templates and baseline_rows must be {api_id: [...]}")
    if not isinstance(post_delete_apis, (list, tuple)) or not all(
        isinstance(api_id, str) for api_id in post_delete_apis
    ):
        raise SystemExit("platform: post_delete_apis must be a list of api_ids")
    for api_id in post_delete_apis:
        if api_id not in catalogue:
            raise SystemExit(f"platform: post_delete_apis: {api_id} is not in the catalogue")
    if not isinstance(not_delete_pattern, str):
        raise SystemExit("platform: not_delete_pattern must be a regex string")
    try:
        not_delete = re.compile(not_delete_pattern)
    except re.error as exc:
        raise SystemExit(f"platform: not_delete_pattern is not a valid regex: {exc}") from None
    refused = (f"/crosswork/x/v1/{DELETE_SEGMENT}", f"/crosswork/x/v1/{DELETE_SEGMENT}/")
    permitted = ("/crosswork/x/v1/query", f"/crosswork/x/v1/{DELETE_SEGMENT}s", "/crosswork/x")
    if any(not_delete.search(p) for p in refused) or not all(
        not_delete.search(p) for p in permitted
    ):
        raise SystemExit(
            "platform: not_delete_pattern does not mean 'every path except one ending in "
            f"the segment {DELETE_SEGMENT!r}' — the guide's wording of the split rule "
            "needs revisiting before this capture is loaded"
        )
    templates: dict[str, Entries] = {}
    baseline: dict[str, Entries] = {}
    for api_id, raw in read_templates.items():
        if api_id not in catalogue:
            raise SystemExit(f"platform: {api_id} is not in the secured-API catalogue")
        if api_id in BASELINE_APIS and api_id != "aaa_cw_role_read":
            raise SystemExit(
                f"platform: {api_id} is a baseline row, not a read template — move it to "
                "'baseline_rows' (a capture in the previous format lists it under "
                "'read_templates')"
            )
        entries = sanitise_entries(raw, f"platform: {api_id}")
        for entry in entries:
            if entry["methods"] != ["POST"]:
                raise SystemExit(
                    f"platform: {api_id}: read template {entry['url']!r} has methods "
                    f"{entry['methods']} — a read template is the POST entries the service "
                    "appends to a GET-only row; other entries belong in 'baseline_rows'"
                )
        templates[api_id] = entries
    for api_id, raw in baseline_rows.items():
        if api_id not in BASELINE_APIS:
            raise SystemExit(f"platform: {api_id} is not a baseline API ({BASELINE_APIS})")
        if api_id not in catalogue:
            raise SystemExit(f"platform: {api_id} is not in the secured-API catalogue")
        baseline[api_id] = sanitise_entries(raw, f"platform: {api_id}")
    if not isinstance(captured, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", captured):
        raise SystemExit(f"platform: 'captured' must be a YYYY-MM-DD date, not {captured!r}")
    return {
        "version": PLATFORM_VERSION,
        "captured": captured,
        "read_templates": dict(sorted(templates.items())),
        "baseline_rows": dict(sorted(baseline.items())),
        "post_delete_apis": sorted(set(post_delete_apis)),
        "not_delete_pattern": not_delete_pattern,
    }


SPLIT_RULE_KEYS = ("post_delete_apis", "not_delete_pattern")


def load_platform_file(path: Path, catalogue: Catalogue, fallback: Platform | None) -> Platform:
    """A capture ``{"captured": ..., "read_templates": {api_id: [{url, methods}]},
    "baseline_rows": {api_id: [...]}, "post_delete_apis": [...], "not_delete_pattern":
    "..."}``: ``read_templates`` is what the AAA service appended to each row of a role
    whose every row was ``{url: "/.*", methods: ["GET"]}`` (``GET aaa/v1/role/<r>``
    after the PUT), ``baseline_rows`` the rows it added to a role stored without them,
    the last two the split rule's data (the APIs on which a single POST-without-DELETE
    entry is split, and the url the POST comes back under). A capture without
    ``baseline_rows`` keeps the committed map's (``fallback``); one without the split
    rule's keys keeps the committed map's, or the constants when there is no map."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("read_templates"), dict):
        raise SystemExit(f"{path}: expected a JSON object with a 'read_templates' mapping")
    baseline = raw.get("baseline_rows")
    if baseline is None:
        if fallback is None:
            raise SystemExit(f"{path}: no 'baseline_rows' and no committed map to take them from")
        baseline = fallback["baseline_rows"]
    defaults = {"post_delete_apis": POST_DELETE_APIS, "not_delete_pattern": NOT_DELETE_PATTERN}
    split_rule = {
        key: raw.get(key, fallback[key] if fallback is not None else defaults[key])
        for key in SPLIT_RULE_KEYS
    }
    return sanitise_platform(
        raw["read_templates"],
        baseline,
        raw.get("captured", TEMPLATES_CAPTURED),
        catalogue,
        **split_rule,
    )


def load_platform_map(map_path: Path, catalogue: Catalogue) -> Platform:
    """The committed map's platform block; a map from before the split rule was
    modelled (no ``post_delete_apis`` / ``not_delete_pattern``) takes the constants."""
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
        platform.get("post_delete_apis", POST_DELETE_APIS),
        platform.get("not_delete_pattern", NOT_DELETE_PATTERN),
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
    networkelement``). ``build_map`` records such a template on the longer API too."""
    if api_coverage.PLACEHOLDER not in template:
        return False
    prefix = template.split(api_coverage.PLACEHOLDER, 1)[0]
    listen = listen_path.rstrip("/")
    return len(listen) > len(prefix) and listen.startswith(prefix)


COUNT_WORDS = ("zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine")


def count_word(n: int) -> str:
    """``three`` for 3 — the prose counts the split-rule lists derive from the constants
    (a capture that changed a list would otherwise be documented with a stale count)."""
    return COUNT_WORDS[n] if 0 <= n < len(COUNT_WORDS) else str(n)


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
                "the role editor submits per ticked row one entry {url: '/.*', methods: "
                "<union>} — Read adds GET, Write adds POST, PUT, PATCH, Delete adds DELETE "
                "(verified 2026-09-15 by reading a UI-built role back); a row with a GET "
                "entry and no POST entry also receives the platform's read templates "
                "('platform.read_templates', extra POST entries for that API's read-by-POST "
                "paths) and every stored role the 'platform.baseline_rows'; on the "
                "'platform.post_delete_apis' a row whose single entry carries POST without "
                "DELETE is split — the other methods stay on '/.*' in alphabetical order and "
                "POST moves to 'platform.not_delete_pattern', every path except one ending "
                "in the segment 'delete' (verified 2026-09-15 by reading the generated "
                f"operator role back on {count_word(len(POST_DELETE_VERIFIED))} of them, "
                f"extrapolated to the {count_word(len(POST_DELETE_INFERRED))} others from "
                "a POST-only experiment); a requirement is permitted by Read when its method "
                "is GET or a read template of its API matches its path under the "
                "unanchored-search rule"
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


# --- role bodies ------------------------------------------------------------------------


def allowed_urls_for(ticks: set[str]) -> Entries:
    """One row's ``allowed_urls`` as the role editor submits it: a single ``/.*`` entry
    whose methods are the union of the ticks in the editor's order (GET, POST, PUT,
    PATCH, DELETE); no ticks, no entry."""
    methods = ordered(m for tick in ticks for m in TICK_METHODS[tick])
    return [{"url": ANY_PATH, "methods": methods}] if methods else []


def role_row(
    api_id: str, entries: Entries, catalogue: Catalogue, versions: list[str] | None = None
) -> dict[str, Any]:
    """One ``access_rights`` row in the editor's shape: ``versions []`` unless given (the
    service's own baseline rows carry ``BASELINE_VERSIONS``); ``limit`` and
    ``allowance_scope`` are the read-back's fields — the editor's ``getPayload`` sends
    only api_name, api_id, versions and allowed_urls, and the service adds the two."""
    return {
        "api_name": catalogue[api_id]["name"],
        "api_id": api_id,
        "versions": list(versions or []),
        "allowed_urls": entries,
        "limit": None,
        "allowance_scope": "",
    }


def role_body(name: str, ticks: Ticks, catalogue: Catalogue) -> dict[str, Any]:
    """A role body in the shape ``POST /crosswork/aaa/v1/role`` takes and the editor
    submits: the editor's role fields (``ROLE_SKELETON``), one row per api_id with
    ticks. The baseline APIs are never emitted: the service adds them to every role."""
    access_rights = {
        api_id: role_row(api_id, allowed_urls_for(row_ticks), catalogue)
        for api_id, row_ticks in sorted(ticks.items())
        if row_ticks and api_id not in BASELINE_APIS
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


def split_post_entry(entry: dict[str, Any], not_delete_pattern: str) -> Entries:
    """The two entries the service stores for a single POST-without-DELETE entry on a
    POST-delete API: the entry under its own url with its other methods in ALPHABETICAL
    order — ``[GET, POST, PUT, PATCH]`` came back ``[GET, PATCH, PUT]`` (read back
    2026-09-15 on the three verified APIs) — then ``{url: <not-delete pattern>, methods:
    [POST]}``. One rule for every shape: an entry with no other method (a POST-only
    entry, the 2026-09-14 experiment's custom-url shape) is kept with its methods
    stripped to ``[]`` — which permits nothing — and the pattern entry appended, as that
    experiment read back."""
    remaining = sorted(m for m in entry["methods"] if m != "POST")
    return [
        {"url": entry["url"], "methods": remaining},
        {"url": not_delete_pattern, "methods": ["POST"]},
    ]


def is_split_row(api_id: str, entries: Entries, platform: Platform) -> bool:
    """Whether the service splits this row: a POST-delete API and a SINGLE entry that
    carries POST and not DELETE (the editor's union entry; two entries beside each
    other — Read and Write submitted separately — were stored verbatim)."""
    if api_id not in platform["post_delete_apis"] or len(entries) != 1:
        return False
    methods = set(entries[0]["methods"])
    return "POST" in methods and "DELETE" not in methods


def stored_access_rights(
    body: dict[str, Any], platform: Platform, catalogue: Catalogue
) -> dict[str, Any]:
    """The ``access_rights`` the AAA service stores for a submitted body (verified
    2026-09-14/15 by reading test roles, a UI-built role and the two generated bodies
    back — the five read-backs in ``tests/fixtures/rbac/``, reproduced entry for entry,
    in order): every submitted entry verbatim, except that on a POST-delete API a row
    whose single entry carries POST without DELETE is split (``split_post_entry``); a
    row with a GET entry and no POST entry gains the API's read templates (a row ticked
    Read+Write did not — its Write entry already covers them); the baseline rows are
    added when absent, with the service's ``versions ["Default"]``. This is what
    ``cnc_check_permissions`` sees, so it is what the guide's counts and
    ``tests/test_rbac_map.py`` evaluate."""
    (role,) = body.values()
    rights: dict[str, Any] = {}
    for api_id, grant in role["access_rights"].items():
        entries = [dict(entry) for entry in grant["allowed_urls"]]
        has_get = any("GET" in entry["methods"] for entry in entries)
        has_post = any("POST" in entry["methods"] for entry in entries)
        if is_split_row(api_id, entries, platform):
            entries = split_post_entry(entries[0], platform["not_delete_pattern"])
        elif has_get and not has_post:
            entries.extend(dict(entry) for entry in platform["read_templates"].get(api_id, []))
        rights[api_id] = {**grant, "allowed_urls": entries}
    for api_id, entries in platform["baseline_rows"].items():
        rights.setdefault(
            api_id,
            role_row(api_id, [dict(entry) for entry in entries], catalogue, BASELINE_VERSIONS),
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


def post_delete_requests(tools: dict[str, Any], platform: Platform) -> list[tuple[str, str, str]]:
    """The (tool, path, api_id) of every POST a tool sends on a POST-delete API that the
    not-delete pattern REFUSES (a path ending in the segment ``delete``): the one
    request Write without Delete does not permit there. None in the map — the
    Optimization Engine's delete RPC ends in ``...:sr-policy-delete``, one segment,
    which the pattern permits — and the generator stops if one appears, because what
    the service stores for a row carrying DELETE on these APIs has not been read back
    (no verified rule to classify it by)."""
    not_delete = re.compile(platform["not_delete_pattern"])
    return sorted(
        (name, req["path"], req["api_id"])
        for name, spec in tools.items()
        for req in spec["requirements"]
        if req["api_id"] in platform["post_delete_apis"]
        and "POST" in needed_methods(req["method"])
        and not not_delete.search(concrete_path(req["path"]))
    )


def read_back_verdict(
    kind: str, rbac_map: dict[str, Any], repo: Path = REPO_DIR
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The sanitised read-back of a generated body (``GENERATED_FIXTURES``) and the
    runtime evaluator's verdict on its stored rows — the check that the model's verdict
    for the committed body is also the verdict on what the service actually stored."""
    from cnc_mcp.tools.admin import evaluate_rbac_map

    path = repo / GENERATED_FIXTURES[kind]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(
            f"{path} is missing: PUT the {kind} body through an admin session, GET it back "
            "and sanitise it into this fixture (see the committed fixture's 'how')"
        ) from None
    stored = data.get("stored") if isinstance(data, dict) else None
    if not isinstance(stored, dict) or not isinstance(data.get("captured"), str):
        raise SystemExit(f"{path}: expected a read-back with 'captured' and 'stored'")
    rows = {
        api_id: {"api_id": api_id, "allowed_urls": entries} for api_id, entries in stored.items()
    }
    return data, evaluate_rbac_map(sorted(rbac_map["tools"]), rbac_map, rows)


def verdict_drift(model: dict[str, Any], read_back: dict[str, Any]) -> list[str]:
    """The tools on which the model's verdict for a body and the verdict on its
    read-back disagree (permitted by one, refused by the other)."""
    return sorted(set(model["permitted"]) ^ set(read_back["permitted"]))


def normalised_rows(rows: dict[str, Entries]) -> dict[str, list[tuple[str, tuple[str, ...]]]]:
    """Per api_id the ``(url, methods)`` of every entry IN STORED ORDER — what the
    fixture tests compare (``tests/test_rbac_map.py``: ``normalised``)."""
    return {
        api_id: [(str(e["url"]), tuple(e["methods"])) for e in entries]
        for api_id, entries in rows.items()
    }


def row_drift(
    body: dict[str, Any], read_back: dict[str, Any], platform: Platform, catalogue: Catalogue
) -> list[str]:
    """The api_ids on which the model's stored form of a body (``stored_access_rights``)
    and the read-back's ``stored`` rows differ — a row in one only, or entries differing
    in url, methods or order. A read-back can give the committed body's verdict for
    every tool while storing different rows (the previous generation did: the same
    refusals from different AAA entries), so this, not the verdict, is what says the
    fixture is of the body as committed."""
    modelled = stored_access_rights(body, platform, catalogue)
    model_rows = normalised_rows({a: g["allowed_urls"] for a, g in modelled.items()})
    fixture_rows = normalised_rows(read_back["stored"])
    return sorted(
        api_id
        for api_id in set(model_rows) | set(fixture_rows)
        if model_rows.get(api_id) != fixture_rows.get(api_id)
    )


def read_back_drift(
    kind: str, body: dict[str, Any], rbac_map: dict[str, Any], catalogue: Catalogue, repo: Path
) -> tuple[dict[str, Any], dict[str, Any], list[str], list[str]]:
    """A generated body's read-back, the evaluator's verdict on it, and how it differs
    from the body as given: the tools whose verdict differs (``verdict_drift``) and the
    api_ids whose stored rows differ (``row_drift``). Either non-empty means the fixture
    is of a PREVIOUS body — the guide says so and ``generate`` warns."""
    data, verdict = read_back_verdict(kind, rbac_map, repo)
    model = evaluate_body(body, rbac_map, catalogue)
    rows = row_drift(body, data, rbac_map["platform"], catalogue)
    return data, verdict, verdict_drift(model, verdict), rows


def drift_note(tools: list[str], rows: list[str], quote: str = "") -> str:
    """``its verdict differs on N tool(s) (...); its stored rows differ on N row(s)
    (...)`` — the first five of each named, ``quote`` wrapping each name (backticks in
    the guide, nothing on stderr)."""

    def names(items: list[str]) -> str:
        more = ", ..." if len(items) > 5 else ""
        return ", ".join(f"{quote}{n}{quote}" for n in items[:5]) + more

    parts = []
    if tools:
        parts.append(f"its verdict differs on {len(tools)} tool(s) ({names(tools)})")
    if rows:
        parts.append(f"its stored rows differ on {len(rows)} row(s) ({names(rows)})")
    return "; ".join(parts)


# --- documentation ----------------------------------------------------------------------


def md(text: str) -> str:
    return html.unescape(text).replace("|", "\\|")


def api_row(catalogue: Catalogue, api_id: str, ticks: set[str]) -> str:
    api = catalogue[api_id]
    return f"| {md(api['feature'])} | `{api_id}` | {md(api['name'])} | {ordered_ticks(ticks)} |"


def display_groups(catalogue: Catalogue) -> dict[str, list[str]]:
    """The role editor's rows: display name (HTML-unescaped, as ``aaa/v2/api`` lists it)
    -> the sorted api_ids sharing it, the editor's hidden api_ids left out. One tick on
    the row grants every api_id of the group (verified 2026-09-15)."""
    groups: dict[str, list[str]] = defaultdict(list)
    for api_id, api in sorted(catalogue.items()):
        if api_id not in HIDDEN_APIS:
            groups[html.unescape(api["name"])].append(api_id)
    return dict(groups)


def first_in_editor_order(api_ids: Iterable[str], catalogue: Catalogue) -> str:
    """The api_id the editor DISPLAYS a display-name group as: the first in ``aaa/v2/api``
    order (the bundle's ``setAllApis`` iterates the v2 response; ``setDuplicateApi``
    marks every later same-name row ``dupOf`` and the template hides those), which is
    not the alphabetical order the guide's tables use. The displayed row shows that
    api_id's own ticks, so a group whose first api_id a role does not grant is shown
    unticked although the role grants a sibling."""
    positions = {api_id: catalogue[api_id].get("position") for api_id in api_ids}
    missing = sorted(api_id for api_id, position in positions.items() if position is None)
    if missing:
        raise SystemExit(
            f"the catalogue carries no aaa/v2/api position for {missing}: regenerate once "
            "with --catalogue-dir or live"
        )
    return min(positions, key=lambda api_id: positions[api_id])


def rows_shown_unticked(
    granted: set[str], catalogue: Catalogue, groups: dict[str, list[str]]
) -> list[tuple[str, str, str]]:
    """The editor rows (feature, name, displayed api_id) a role granting exactly
    ``granted`` shows UNTICKED although it grants a member: rows of more than one api_id
    whose first api_id in ``aaa/v2/api`` order is not granted while a sibling is. Sorted
    by feature then name, like the tables."""
    rows = []
    for name, api_ids in groups.items():
        if len(api_ids) < 2 or not granted & set(api_ids):
            continue
        shown = first_in_editor_order(api_ids, catalogue)
        if shown not in granted:
            rows.append((catalogue[shown]["feature"], name, shown))
    return sorted(rows)


def ui_fixture_get_only_rows(repo: Path = REPO_DIR) -> list[str]:
    """The api_ids the UI-built role's read-back stores as the single entry
    ``{url: "/.*", methods: ["GET"]}`` — Read-ticked APIs the service added no template
    to, so their (absence of a) template is known although they were not in the
    template capture."""
    path = repo / UI_FIXTURE_RELATIVE
    if not path.exists():
        raise SystemExit(f"{path} is missing: the guide cites the UI-built role's read-back")
    data = json.loads(path.read_text(encoding="utf-8"))
    return sorted(
        api_id
        for api_id, entries in data["stored"].items()
        if entries == [{"url": ANY_PATH, "methods": ["GET"]}]
    )


def editor_rows(
    ticks: Ticks, catalogue: Catalogue, groups: dict[str, list[str]]
) -> list[tuple[str, str, list[str], list[str], set[str]]]:
    """The editor rows a set of per-api_id ticks maps to, sorted by feature then row
    name: (feature, row name, api_ids used, sibling api_ids the tick also grants, the
    union of the ticks). Hidden api_ids (the baseline rows) have no editor row."""
    by_name: dict[str, set[str]] = defaultdict(set)
    for api_id in ticks:
        if api_id not in HIDDEN_APIS:
            by_name[html.unescape(catalogue[api_id]["name"])].add(api_id)
    rows = []
    for name, used in by_name.items():
        feature = catalogue[next(iter(used))]["feature"]
        siblings = [api_id for api_id in groups[name] if api_id not in used]
        union = set().union(*(ticks[api_id] for api_id in used))
        rows.append((feature, name, sorted(used), siblings, union))
    return sorted(rows, key=lambda r: (r[0], r[1]))


def editor_row_cells(feature: str, name: str, used: list[str], siblings: list[str]) -> str:
    return (
        f"| {md(feature)} | {md(name)} | "
        + ", ".join(f"`{api_id}`" for api_id in used)
        + " | "
        + (", ".join(f"`{api_id}`" for api_id in siblings) if siblings else "—")
    )


def entries_text(entries: Entries) -> str:
    return "; ".join(f"{', '.join(e['methods'])} `{e['url']}`" for e in entries)


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


def without_row(body: dict[str, Any], api_id: str) -> dict[str, Any]:
    """The body minus one ``access_rights`` row (the body itself is not modified)."""
    (name,) = body
    role = body[name]
    rights = {k: v for k, v in role["access_rights"].items() if k != api_id}
    return {name: {**role, "access_rights": rights}}


def render_doc(
    rbac_map: dict[str, Any],
    catalogue: Catalogue,
    readonly_body: dict[str, Any],
    operator_body: dict[str, Any],
    repo: Path = REPO_DIR,
) -> str:
    """The guide. ``repo`` is where the read-back fixtures of the generated bodies are
    read from (``GENERATED_FIXTURES``); section 6 states the verdict on them."""
    tools = rbac_map["tools"]
    platform = rbac_map["platform"]
    read_templates = platform["read_templates"]
    baseline_rows = platform["baseline_rows"]
    post_delete_apis = platform["post_delete_apis"]
    not_delete_pattern = platform["not_delete_pattern"]
    groups = display_groups(catalogue)
    multi_groups = {name: ids for name, ids in groups.items() if len(ids) > 1}
    read_specs = [s for s in tools.values() if s["read_only"]]
    write_specs = [s for s in tools.values() if not s["read_only"]]
    read_ticks = ticks_for(read_specs, read_templates)
    readonly_ticks = body_ticks(readonly_body)
    operator_ticks = body_ticks(operator_body)
    union_rw_rows = sum(t == {"R", "W"} for t in operator_ticks.values())
    union_rwd_rows = sum(t == {"R", "W", "D"} for t in operator_ticks.values())
    write_areas: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for name, spec in tools.items():
        if not spec["read_only"]:
            write_areas[spec["area"]].append((name, spec))
    info = rbac_map["generated_from"]
    n_read = len(read_specs)
    n_write = len(write_specs)
    (readonly_role,) = readonly_body.values()
    (operator_role,) = operator_body.values()
    for role in (readonly_role, operator_role):
        if set(role["access_rights"]) & set(BASELINE_APIS):
            raise SystemExit("a generated body carries a baseline row")

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
    # the read tools that need the aaa_cwaaa row (refused once it is dropped)
    AAA_ROW = "aaa_cwaaa"
    aaa_row_name = html.unescape(catalogue[AAA_ROW]["name"])
    without_aaa = evaluate_body(without_row(readonly_body, AAA_ROW), rbac_map, catalogue)
    already_refused = {r["tool"] for r in readonly_verdict["refused"]}
    needs_aaa_row = sorted({r["tool"] for r in without_aaa["refused"]} - already_refused)
    if not needs_aaa_row or "cnc_check_permissions" in needs_aaa_row:
        raise SystemExit("the aaa_cwaaa row note is stale: recompute which tools need it")
    ui_fixture = str(UI_FIXTURE_RELATIVE)
    granted_by_a_body = set(readonly_role["access_rights"]) | set(operator_role["access_rights"])
    unticked_rows = rows_shown_unticked(granted_by_a_body, catalogue, groups)
    if not unticked_rows:
        raise SystemExit("the unticked-rows note is stale: every displayed api_id is granted")
    # the split rule: the POSTs the tools send on the POST-delete APIs, and the delete
    # RPC the map records for the Optimization Engine
    if post_delete_requests(tools, platform):
        raise SystemExit(
            "a tool POSTs a path ending in the segment 'delete' on a POST-delete API "
            f"({post_delete_requests(tools, platform)}): Write without Delete does not permit "
            "it there, and what the service stores for a row carrying DELETE on these APIs "
            "has not been read back — verify live before classifying it"
        )
    # the guide documents every POST-delete API as verified (a fixture) or inferred (the
    # 2026-09-14 experiment) and counts them: a capture that adds or drops one is not
    # documented until the constants — and the sentence — say what was observed on it
    known_split = set(POST_DELETE_VERIFIED) | set(POST_DELETE_INFERRED)
    if set(post_delete_apis) != known_split:
        unknown = sorted(set(post_delete_apis) - known_split)
        lacking = sorted(known_split - set(post_delete_apis))
        raise SystemExit(
            "the platform block's post_delete_apis "
            + (
                f"carries an API neither verified nor in the 2026-09-14 experiment: {unknown} "
                "— verify live before documenting it"
                if unknown
                else f"lacks a verified or inferred API: {lacking}"
            )
        )
    verified_split = [a for a in post_delete_apis if a in POST_DELETE_VERIFIED]
    inferred_split = [a for a in post_delete_apis if a in POST_DELETE_INFERRED]
    if not set(POST_DELETE_INFERRED) <= set(POST_ONLY_EXPERIMENT_APIS):
        raise SystemExit("an inferred POST-delete API is not in the POST-only experiment")
    # the verified APIs the POST-only experiment was also run on, and where the two-entry
    # (custom GET beside custom POST) shape of the same submission was stored verbatim
    post_only_verified = [a for a in verified_split if a in POST_ONLY_EXPERIMENT_APIS]
    beside_get_on_list = [a for a in POST_BESIDE_GET_EXPERIMENT_APIS if a in post_delete_apis]
    beside_get_off_list = [a for a in POST_BESIDE_GET_EXPERIMENT_APIS if a not in post_delete_apis]
    if not post_only_verified or not beside_get_on_list or not beside_get_off_list:
        raise SystemExit("the 2026-09-14 experiment notes are stale: recompute from the constants")
    oe_delete = sorted(
        {
            (name, req["path"])
            for name, spec in tools.items()
            for req in spec["requirements"]
            if req["api_id"] == "optima_restconf"
            and req["method"] == "POST"
            and req["path"].endswith("-delete")
        }
    )
    if not oe_delete:
        raise SystemExit("the OE delete-RPC note is stale: no tool POSTs a ...-delete RPC")
    stored_operator = stored_access_rights(operator_body, platform, catalogue)
    split_rows = sorted(
        api_id
        for api_id, grant in operator_role["access_rights"].items()
        if is_split_row(api_id, grant["allowed_urls"], platform)
    )
    if not split_rows:
        raise SystemExit("the split-rule note is stale: no operator row is split")
    first_entry, second_entry = stored_operator[split_rows[0]]["allowed_urls"]
    if second_entry != {"url": not_delete_pattern, "methods": ["POST"]}:
        raise SystemExit("the split-rule note is stale: the split row's POST is not the pattern")
    split_text = (
        f"`[{', '.join(first_entry['methods'])}] {first_entry['url']}` + `[POST] <the pattern>`"
    )
    delete_rows = sorted(a for a, t in operator_ticks.items() if "D" in t)
    write_only_rows = sorted(a for a, t in operator_ticks.items() if "R" not in t)
    if set(delete_rows + write_only_rows) & set(post_delete_apis):
        raise SystemExit(
            "the split-rule note is stale: an operator row carrying DELETE, or a Write-only "
            "row, is on a POST-delete API — what the service stores for it has not been read "
            "back"
        )
    # the read-backs of the bodies as committed: what the service stored must be the
    # model's stored form of the body, row for row (the tests pin the rows entry for
    # entry), and the verdict on it the model's verdict — a fixture of a previous body
    # can keep the verdict while its rows differ, so both are compared
    read_backs: dict[str, tuple[dict[str, Any], dict[str, Any], list[str], list[str]]] = {}
    for kind, body_obj in ((READONLY_ROLE, readonly_body), (OPERATOR_ROLE, operator_body)):
        read_backs[kind] = read_back_drift(kind, body_obj, rbac_map, catalogue, repo)
    fixture_paths = ", ".join(f"`{GENERATED_FIXTURES[k]}`" for k in (READONLY_ROLE, OPERATOR_ROLE))
    captured_dates = sorted({data["captured"] for data, _, _, _ in read_backs.values()})
    ro_read_back = read_backs[READONLY_ROLE][1]
    op_read_back = read_backs[OPERATOR_ROLE][1]
    ro_permitted_reads = [n for n in ro_read_back["permitted"] if tools[n]["read_only"]]
    ro_refused_reads = [r["tool"] for r in ro_read_back["refused"] if tools[r["tool"]]["read_only"]]
    ro_permitted_writes = [n for n in ro_read_back["permitted"] if not tools[n]["read_only"]]
    drifted = {
        k: (tool_drift, rows)
        for k, (_, _, tool_drift, rows) in read_backs.items()
        if tool_drift or rows
    }
    if not drifted:
        read_back_clause = (
            f"the bodies as committed were stored through the API and read back "
            f"({', '.join(captured_dates)}: {fixture_paths}); evaluated on the stored form "
            "they give the same verdict for every tool as the model — "
            f"`{READONLY_ROLE}`: {len(ro_permitted_reads)} of the {n_read} read tools "
            f"permitted, {len(ro_refused_reads)} refused, "
            f"{len(ro_permitted_writes)} write tool"
            f"{'s' if len(ro_permitted_writes) != 1 else ''} permitted"
            + (
                f" ({', '.join(f'`{n}`' for n in ro_permitted_writes)})"
                if ro_permitted_writes
                else ""
            )
            + f"; `{OPERATOR_ROLE}`: {len(op_read_back['permitted'])} of {len(tools)} permitted"
        )
    else:
        read_back_clause = (
            f"the read-backs of the bodies ({', '.join(captured_dates)}: {fixture_paths}) are "
            "of a PREVIOUS body — against the current bodies' stored form, "
            + "; ".join(
                f"under `{kind}` {drift_note(tool_drift, rows, quote='`')}"
                for kind, (tool_drift, rows) in drifted.items()
            )
            + " — re-PUT the bodies, read them back and refresh the fixtures"
        )
    smoke_generation = (
        "the smoke runs were on the previous generation of the bodies, which differed only "
        "in the two AAA rows — `aaa_cwaaa` a GET pattern limited to the paths the tools "
        "send then, `/.*` now; `aaa_cw_role_read` in the body then, left to the baseline "
        "row now — `versions` and the `rate` field, and their refusal predictions are "
        f"identical; {read_back_clause}"
    )

    out: list[str] = []
    w = out.append
    w("# RBAC: what a Crosswork account needs to run cnc-mcp")
    w("")
    w(
        "> **Generated** by `scripts/rbac_map.py` from the tool source, the gateway's "
        f"secured-API catalogue ({info['platform']}, {info['api_count']} APIs in "
        f"{info['feature_count']} features, catalogue verified live {info['catalogue_verified']}) "
        f"and the platform's read templates and baseline rows (captured {platform['captured']} "
        f"and {UI_VERIFIED}) — do not edit by hand. Regenerate with `make rbac` (offline, from "
        "the catalogue and templates embedded in `src/cnc_mcp/data/rbac_map.json`) or `make "
        "rbac-fetch` (re-read the catalogue from a live instance; `--read-templates <capture>` "
        "loads a fresh template capture); `make rbac-check` fails when the committed files "
        "are stale."
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
    w(f"**Verified live** (CNC 7.2.0 single-VM lab, 2026-09-14 and {UI_VERIFIED}):")
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
        "policy: `access_rights{<api_id>: {api_name, api_id, versions, allowed_urls [{url: "
        "<regex>, methods: [GET, POST, PUT, PATCH, DELETE]}], allowance_scope}}` plus the "
        "policy fields (`rate`, `per`, `quota_max`, `key_expires_in`, `active`, ...). The "
        'lab\'s built-in role, `admin`, grants every API with `url "/.*"` and all five '
        'methods (`rate 5000`, `versions ["Default"]`).'
    )
    w(
        "- `GET /crosswork/aaa/v2/api` → `{<feature>: [{api_id, name}]}` "
        f"({info['feature_count']} features) is what the UI's role editor "
        "(Administration > Users and Roles > Roles) builds its rows from; the `feature` "
        "column below is it. A **row in the editor is a display-name group**: one tick "
        "grants every api_id sharing the row's `name` (below)."
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
        "`roleAccess/<r>`, `user/<u>`, `userpermission`, `task/<r>`, `v1/api`, `v2/api`). "
        "It is a **baseline row of every role** — the AAA service adds it to every role it "
        "stores (below) — so every account can read its own role, and the mirror's "
        "catalogue listing, by platform design. cnc_check_permissions reads the account's "
        "role through it."
    )
    w(
        "- The three SSO ticket calls the server logs in with (`POST /crosswork/sso/v1/tickets`, "
        "`POST .../tickets/{TGT}`, `DELETE .../tickets/{TGT}`) are **not** gateway APIs: no "
        "role grant is involved in logging in, only in what the token may then call."
    )
    w("")
    w(
        "**Verified live: the role editor, and how Crosswork stores a role** (2026-09-14 "
        f"through an admin session: test roles stored in several shapes and read back; "
        f"{UI_VERIFIED}: a role built in the editor with three ticks and read back through the "
        "API, the editor's own role model read from the UI bundle, and the two generated "
        "bodies as committed stored through the API and read back — section 6 says what "
        "the fixtures pin):"
    )
    w("")
    w(
        "- `POST /crosswork/aaa/v1/role` needs `Content-Type: application/json; charset=UTF-8` "
        '(plain `application/json` → 405); body `{"<name>": {<rbacRole>}}` → **201**. '
        "`PUT /crosswork/aaa/v1/role/<name>` with the inner object → **204**. "
        "`GET /crosswork/aaa/v1/role/<name>` → the stored object (**404** when absent)."
    )
    w(
        "- **What a tick submits.** Per ticked row the editor sends ONE `allowed_urls` entry "
        '`{url: "/.*", methods: <union>}` — **Read** adds `GET`, **Write** adds `POST, PUT, '
        "PATCH`, **Delete** adds `DELETE` (in that order) — with `versions []` and the "
        "editor's role fields (`rate 1000 / per 60 / quota_max -1 / quota_renewal_rate 60 / "
        "key_expires_in -1 / active true / hmac_enabled false`; `rate`/`per` is the "
        "gateway's per-key rate limit — 1000 requests per 60 s, the editor's default, where "
        "the built-in `admin` role carries 5000 — raise it through the API if an "
        "agent-driven server hits 429s, which ApiClient retries, slower). A role built in "
        "the editor "
        "with exactly three ticks — Read on *Alarm Settings*, Write on *Alarm Suppression "
        "Policies*, Delete on *Alarms and Events RESTCONF* — was read back as exactly that "
        f"(`{ui_fixture}`): the seven *Alarm Settings* api_ids `[GET] /.*`, "
        "`event-processing-service-suppressionpolicy-api` `[POST, PUT, PATCH] /.*`, the six "
        "*Alarms and Events RESTCONF* api_ids `[DELETE] /.*`, plus the three baseline rows. "
        "This page calls the ticks R / W / D; the generated bodies use exactly this shape."
    )
    w(
        "- **A row is a display-name group.** The editor shows one row per `name` and hides "
        + ", ".join(f"`{api_id}`" for api_id in HIDDEN_APIS)
        + f"; {len(multi_groups)} of the editor's {len(groups)} rows cover more than one "
        f"api_id ({len(groups['Alarm Settings'])} for *Alarm Settings*, "
        f"{len(groups['Alarms and Events RESTCONF'])} for *Alarms and Events RESTCONF*, "
        f"{len(groups['Alarms & Events'])} for *Alarms & Events*, ...), and one tick grants "
        "all of them. So **the UI cannot grant a single api_id of a group; the API can** — "
        "the generated bodies grant only the api_ids the tools use, and sections 2 and 3 "
        "list the sibling api_ids a UI tick grants as well. When the editor displays a "
        "stored role it reads only the FIRST `allowed_urls` entry of each api_id, and only "
        'when that entry\'s url is `"/.*"`; a group row shows the ticks of its first api_id '
        "in `aaa/v2/api` order (the editor's row order, not the alphabetical order of the "
        f"tables here). On {len(unticked_rows)} rows neither generated body grants that "
        "first api_id while granting a sibling — "
        + ", ".join(f"*{md(name)}* (`{shown}`)" for _feature, name, shown in unticked_rows)
        + " — so the editor shows those rows unticked while the grant is live (from the "
        "catalogue's v2 positions and the bundle's row model; not exercised live)."
    )
    w(
        f"- Every stored role gains {len(baseline_rows)} **baseline rows** the service adds "
        "on its own — "
        + ", ".join(
            f"`{api_id}` ({entries_text(entries)})" for api_id, entries in baseline_rows.items()
        )
        + " — the account's own role through the mirror, its password change and its UI "
        f"preferences (verified {UI_VERIFIED}: the UI-built role, submitted with none of them, "
        "came back with all three; the two 2026-09-14 API-stored experiments, submitted with "
        "`aaa_cw_role_read` only, came back with the other two — `tests/fixtures/rbac/`). "
        "They are not in the bodies; they appear when a role is read back."
    )
    readonly_rows = set(readonly_role["access_rights"])
    templated_outside = sorted(set(read_templates) - readonly_rows - set(BASELINE_APIS))
    get_only_outside = [a for a in ui_fixture_get_only_rows() if a not in readonly_rows]
    if not get_only_outside:
        raise SystemExit("the GET-only exception note is stale: recompute from the UI fixture")
    w(
        "- A row with a GET entry (and no POST entry) additionally receives the platform's "
        "per-API **read templates**: extra POST entries naming the read-by-POST paths of "
        "that API — so a Read tick permits those POSTs as well. The "
        f"{len(set(read_templates) & readonly_rows)} APIs with a template among the "
        f"{len(readonly_rows)} rows the read-only body carries (every other one of these "
        f"rows received GET only when stored; the "
        f"{len(catalogue) - len(readonly_rows) - len(BASELINE_APIS)} catalogued APIs outside "
        f"these rows and the baseline rows were not in the template capture "
        f"({platform['captured']}), so their templates are unknown and any POST there is "
        f"classed W — except that the UI-built role stored "
        + ", ".join(f"`{api_id}`" for api_id in get_only_outside)
        + f" as GET-only rows, template-free, `{ui_fixture}`)"
        + (
            f"; {len(templated_outside)} more with a template outside these rows: "
            + ", ".join(f"`{api_id}`" for api_id in templated_outside)
            if templated_outside
            else ""
        )
        + "; the `aaa_cw_role_read` baseline row carries its own template ("
        + template_urls(platform, "aaa_cw_role_read")
        + "):"
    )
    for api_id, entries in read_templates.items():
        if api_id in BASELINE_APIS:
            continue
        w(f"  - `{api_id}`: {entries_text(entries)}")
    w(
        "- A row ticked Read **and** Write is stored as its single `/.*` entry only (no "
        "template — the entry already covers every POST), **except on the APIs on which the "
        "service reserves a last segment `delete` for the Delete tick** (presumably the ones "
        "that delete through `POST .../delete` — no tool POSTs such a path, so the map does "
        "not show one): there a row whose single entry carries POST without "
        "DELETE — Write without Delete, the one entry the editor submits and the generated "
        "bodies carry — is **split**: POST moves to a second entry "
        f'`{{url: "{not_delete_pattern}", methods: [POST]}}`, an unanchored search that '
        "matches every path whose LAST segment is not the six-character word `delete` (a "
        "last segment of 1-5 characters, of 7 or more, or of six characters differing from "
        "d-e-l-e-t-e in some position; a trailing slash allowed — `deletes` and `Delete` "
        "pass), and the remaining methods come back in **alphabetical** order: the operator "
        f"body's `[GET, POST, PUT, PATCH] /.*` row read back as {split_text}. Verified "
        f"{UI_VERIFIED} on " + ", ".join(f"`{a}`" for a in verified_split) + " (the operator "
        f"body's Write rows there, `{GENERATED_FIXTURES[OPERATOR_ROLE]}`); **inferred** for "
        + ", ".join(f"`{a}`" for a in inferred_split)
        + " from the 2026-09-14 experiment in which a row whose only entry was a custom-url "
        "POST came back with its methods stripped to `[]` and this same pattern entry "
        f"appended, on those {count_word(len(inferred_split))} (and on "
        + ", ".join(f"`{a}`" for a in post_only_verified)
        + ") — the same split, POST being the entry's only method; no union entry has been "
        "stored on them, so the split there is the model's extrapolation, not a read-back. "
        "Read and Write submitted as two entries beside each other (the 2026-09-14 "
        "experiment) were stored verbatim, and "
        f"so were the operator body's {len(delete_rows)} rows carrying DELETE and its "
        f"{len(write_only_rows)} Write-only rows (`[POST, PUT, PATCH]`) — none of them on "
        "this list. In the same 2026-09-14 submission a custom GET entry beside a custom "
        "POST entry was stored verbatim on "
        + ", ".join(f"`{a}`" for a in beside_get_on_list)
        + f" (and on {count_word(len(beside_get_off_list))} API"
        f"{'s' if len(beside_get_off_list) != 1 else ''} off this list, "
        + ", ".join(f"`{a}`" for a in beside_get_off_list)
        + ") — the split keys on the row having a single entry. **Consequence: "
        "Write without Delete on these APIs still permits every POST except a path ending "
        "in `/delete`.** For the Optimization Engine (`optima_restconf`) an operator role "
        "without Delete can still create policies, and the delete RPC the map records — "
        + ", ".join(f"`POST {path}` (`{name}`)" for name, path in oe_delete)
        + " — ends in the segment `"
        + oe_delete[0][1].rsplit("/", 1)[1]
        + "`, not `delete`, so it stays permitted too; no POST any tool sends on these "
        f"{len(post_delete_apis)} APIs ends in `/delete`."
    )
    w("")
    w(
        '> **Warning — never load a role body with a url other than `"/.*"`.** A role whose '
        "FIRST `allowed_urls` entry on some api_id has any other url **crashes the Roles "
        f"page for everyone** (verified {UI_VERIFIED}: `TypeError: Cannot read properties of "
        "undefined (reading 'read')` in the editor's `setAccess` — it looks the url up among "
        'its `"/.*"` rows and finds nothing) and the whole page renders blank until the role '
        "is fixed through the API or deleted. The service's own appended templates are "
        "custom urls too, but they sit at index 1 or later, which the editor never reads. "
        "Independently of the crash the service does not store every custom-URL shape "
        "verbatim either (2026-09-14: a row whose only entry was a custom-URL POST came "
        "back with its methods stripped to `[]` and the not-delete pattern above appended "
        "— a wider grant than the url submitted — on the "
        f"{count_word(len(POST_ONLY_EXPERIMENT_APIS))} APIs it was tried on). The generated "
        'bodies carry `"/.*"` only.'
    )
    w("")
    w(
        "**From the Tyk v5.1.1 gateway source** (`gateway/api_loader.go`, "
        "`mw_access_rights.go`, `mw_granular_access.go`), confirmed live 2026-09-15 by "
        "users carrying the generated roles (read-only: 262 read calls answered, the 7 "
        "predicted refusals the smoke exercises answered 403, nothing unpredicted was "
        "refused, two writes refused as predicted; operator: all 432 read and write steps "
        f"of the smoke answered, every created object removed again, no 403 at all; "
        f"{smoke_generation}):"
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
        "entry covers the path and method (`POST /crosswork/inventory/v1/tags`). Neither is "
        "an authentication failure: the server does not re-login on them. Two fail-open "
        "cases: an `allowed_urls` regex that does not compile is let through, and so is a "
        "role whose `access_rights` map is empty — "
        "cnc_check_permissions reports both as refusals (the role as it should be "
        "configured)."
    )
    w("")
    w("**Not verified:**")
    w("")
    w(
        "- The editor's wire shape, the display-name groups, the stored form of single-tick, "
        "per-tick and union entries (the generated bodies read back), the baseline rows, "
        "the split of a Write-without-Delete row on "
        + ", ".join(f"`{a}`" for a in verified_split)
        + " and the gateway's refusals are all observed. Read from the UI bundle but not "
        "exercised live: how the editor displays and re-saves an API-loaded role (the group "
        "rows above, section 6). Extrapolated, not read back: the same split on the "
        f"{len(inferred_split)} other POST-delete APIs (from a POST-only experiment), and "
        "what the service stores for a row carrying DELETE, or a Write-only row, on any of "
        "them (the bodies have none). What is still static is the map itself (section 6: a "
        "source-derived heuristic, no tool endpoint is called), a device access group is "
        "reported, not evaluated, and whether task bundles exist for roles other than admin "
        "(section 5) is unknown."
    )
    w("")
    # --- 2
    w("## 2. Least-privilege recipe: a read-only account")
    w("")
    read_rows = editor_rows(read_ticks, catalogue, groups)
    read_siblings = sorted({api_id for _, _, _, siblings, _ in read_rows for api_id in siblings})
    w(
        f"The {n_read} read-only tools touch {len(read_ticks)} API rows; "
        f"{len(readonly_role['access_rights'])} of them go in the role, the other one — "
        "`aaa_cw_role_read` — is the baseline row every role has (cnc_check_permissions "
        "reads the role through it). "
        f"**`docs/rbac/{READONLY_ROLE}.role.json` (section 6) grants the Read tick on every "
        f"one of those {len(readonly_role['access_rights'])} rows and nothing else** — R only, "
        "never W — in the shape the editor submits (section 1). Building the same account in "
        "the editor (Administration > Users and Roles > Roles: create a role, tick **Read** on "
        f"the {len(read_rows)} editor rows of the first table under their feature, leave "
        f"`ApiAccess` on) also grants the {len(read_siblings)} sibling api_ids in its last "
        "column, because a row is a display-name group; the body grants only the api_ids "
        "the tools use (second table). Assign the role to a dedicated service account with "
        "device access group `ALL-ACCESS` (or the device scope you intend)."
    )
    w("")
    w("**By editor row** (tick Read on each):")
    w("")
    w(
        "| feature | editor row | api_ids the read tools use | sibling api_ids the tick "
        "also grants |"
    )
    w("|---|---|---|---|")
    for feature, name, used, siblings, _ticks in read_rows:
        w(editor_row_cells(feature, name, used, siblings) + " |")
    w("")
    w(
        "**By api_id** (what an API-loaded body grants; the last column is the tick(s) the "
        "read tools' requests need on the row — R = every GET plus the POSTs the row's read "
        "template names, W = the other POSTs and every PUT/PATCH, D = DELETE):"
    )
    w("")
    w("| feature | api_id | API name (editor row) | ticks the read tools need |")
    w("|---|---|---|---|")
    for api_id, ticks in sorted(
        read_ticks.items(), key=lambda kv: (catalogue[kv[0]]["feature"], kv[0])
    ):
        row = api_row(catalogue, api_id, ticks)
        if api_id in BASELINE_APIS:
            row = row[:-1] + "(baseline row: every role has it) |"
        w(row)
    w("")
    w(
        f"`{AAA_ROW}` (`/crosswork/aaa/`, editor row *{md(aaa_row_name)}*) is what the RBAC "
        "read tools read users, roles and sessions through. Drop that row and the account "
        f"can no longer read them: the gateway refuses these {len(needs_aaa_row)} tools — "
        + ", ".join(f"`{name}`" for name in needs_aaa_row)
        + ". cnc_check_permissions keeps working without it: it reads the role through the "
        "`aaa_cw_role_read` baseline row and falls back to `aaa/v1` only when the mirror "
        "answers 403/404 (either row suffices for it)."
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
            if api_id in post_delete_apis:
                also += (
                    " — POST under the not-delete pattern, every path except one ending in "
                    "`/delete` (section 1)"
                )
            option_lines.append(f"  - `{api_id}`: Write also permits {also}.")
        w(
            "1. **Tick Write as well as Read** on the rows above — the account is then no "
            "longer read-only at the gateway, because Write is `/.*` on the whole API for "
            "PUT/PATCH and — except on the POST-delete APIs of section 1 — for POST, and a "
            "narrower custom-URL entry is not an option (section 1's warning):"
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
    # --- 3
    w("## 3. Write areas: what each adds")
    w("")
    w(
        "Write tools are registered only with `CNC_MCP_ENABLE_WRITES=true`. Per area (the "
        "`tools/` module), the editor rows and ticks a role needs **in addition to** the "
        "read-only recipe of section 2 — a row already ticked Read is listed only when the "
        "writes add Write or Delete on it; the api_id column says which member(s) of the "
        "row the writes use, the last column which sibling api_ids the tick grants as well "
        f"(the body grants the members only). `docs/rbac/{OPERATOR_ROLE}.role.json` is "
        "section 2 plus every area below"
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
        extra_ticks: Ticks = {}
        for api_id, ticks in area_ticks.items():
            extra = ticks - readonly_ticks.get(api_id, set())
            if extra:
                extra_ticks[api_id] = extra
        rows = editor_rows(extra_ticks, catalogue, groups)
        if rows:
            w(
                "| feature | editor row | api_ids the writes use | sibling api_ids the tick "
                "also grants | ticks to add |"
            )
            w("|---|---|---|---|---|")
            for feature, name, used, siblings, ticks in rows:
                per_api = ", ".join(
                    f"`{api_id}` {ordered_ticks(extra_ticks[api_id])}" for api_id in used
                )
                w(
                    f"| {md(feature)} | {md(name)} | {per_api} | "
                    + (", ".join(f"`{api_id}`" for api_id in siblings) if siblings else "—")
                    + f" | {ordered_ticks(ticks)} |"
                )
        else:
            w("Nothing beyond section 2 (the writes use rows and ticks the reads already need).")
    w("")
    w(
        f"`{OPERATOR_ROLE}.role.json` carries {len(operator_role['access_rights'])} rows: "
        f"{sum('W' in t for t in operator_ticks.values())} with Write, "
        f"{sum('D' in t for t in operator_ticks.values())} with Delete, "
        f"{sum(t == {'W'} for t in operator_ticks.values())} Write-only (no read tool uses "
        "the API)."
    )
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
        groups_of = spec.get("any_of") or []
        grouped = {api_id for group in groups_of for api_id in group}
        cells = ", ".join(
            f"`{api_id}`: {ordered_ticks(t)}"
            for api_id, t in sorted(ticks.items())
            if api_id not in grouped
        )
        if groups_of:
            alternatives = " *or* ".join(
                ", ".join(f"`{api_id}`: {ordered_ticks(ticks[api_id])}" for api_id in group)
                for group in groups_of
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
        "letter adds to the row's `/.*` entry and how it is stored), so treat a bundle as "
        '"which rows and ticks the UI sets for you".'
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
        "`aaa/v1` lets the account read its role — the service adds the `aaa_cw_role_read` "
        "row to every role it stores, so on this platform version check the role's "
        "`roleAccess` (`ApiAccess`) and the stored role through an admin session."
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
        "- **Verified (2026-09-14, admin session, test roles):** the shape the AAA service "
        "stores a submitted role in — `/.*` entries verbatim, the read templates added to a "
        "GET-only row, the baseline rows, the POST/PUT/GET status codes and the "
        "`charset=UTF-8` content type (section 1). The counts above are computed from that "
        "stored shape with Tyk's matching rule; `tests/fixtures/rbac/` pins the model "
        "against the read-backs."
    )
    w(
        f"- **Verified ({UI_VERIFIED}, users carrying the generated roles; a UI-built role; "
        "the bodies as committed read back):** the gateway's refusals — every predicted 403 "
        f"observed, nothing unpredicted refused (section 1; {smoke_generation}) — and the "
        "editor's tick → entry mapping the bodies use."
    )
    w(
        "- The check is **static**: the map is derived from the tool source by "
        "api_coverage.py's extraction heuristic; no tool endpoint is called. A request built "
        "from platform data folds to `{}`; a probe counts as a use."
    )
    w(
        "- A device access group other than ALL-ACCESS restricts devices, not APIs; it is "
        "reported, not evaluated. The two gateway fail-open cases (a regex that does not "
        "compile, an empty `access_rights` map) are reported as refusals."
    )
    w("")
    w("### Ready-made role bodies")
    w("")
    w(
        f"`docs/rbac/{READONLY_ROLE}.role.json` (section 2) and "
        f"`docs/rbac/{OPERATOR_ROLE}.role.json` "
        "(sections 2 + 3) are generated with this page, in the shape `POST "
        '/crosswork/aaa/v1/role` takes — `{"<role name>": {<rbacRole>}}`, the shape '
        "`GET /crosswork/aaa/v1/role` answers. **The generated bodies are the shape the "
        f"editor submits** (verified {UI_VERIFIED} against the UI-built role's read-back, "
        f"`{ui_fixture}`) — the editor's role fields, `versions []`, one `access_rights` "
        'entry per api_id with a single `{url: "/.*", methods: [...]}` whose methods are '
        "the union of the row's ticks (`[GET]` for Read, `[POST, PUT, PATCH]` for Write, "
        "`[DELETE]` for Delete, in that order) — minus the empty `_id`/`id` the editor also "
        "sends; `limit`/`allowance_scope` are the read-back's fields (the service adds them "
        "itself), and `api_name` is the v1 catalogue's HTML-escaped form (`Alarms &amp; "
        "Events`, as the built-in `admin` role stores it) where the editor sends "
        "`aaa/v2/api`'s unescaped one. "
        + (
            "What the fixtures pin: both bodies as committed, stored and read back"
            if not drifted
            else "What the fixtures pinned for a PREVIOUS generation of the bodies (section "
            "1 names the rows and verdicts that differ; re-PUT, read back and refresh them): "
            "both bodies as then committed, stored and read back"
        )
        + f" ({', '.join(captured_dates)}: {fixture_paths} — the model "
        "reproduces every stored row entry for entry: the read-only body's "
        f"{len(readonly_role['access_rights'])} Read rows with their templates; the "
        f"operator body's union entries, `[GET, POST, PUT, PATCH]` on {union_rw_rows} rows "
        f"and all five methods on {union_rwd_rows}, verbatim except the "
        f"{len(split_rows)} split rows section 1 describes — "
        + ", ".join(f"`{a}`" for a in split_rows)
        + " — where POST came back under the not-delete pattern; plus the three baseline "
        "rows on each), the UI-built role's single-tick entries (`[GET]`, `[POST, PUT, "
        "PATCH]`, `[DELETE]`) and the 2026-09-14 experiments' per-tick entries on these "
        "rows. The Roles page has not been opened on these bodies (their first entries are "
        "all `/.*`, the one shape the editor reads). Two differences from a UI-built role: "
        "a body grants single "
        "api_ids where a UI tick grants the whole display-name group (section 1), and so "
        "**an API-loaded role is managed through the API only** — the editor shows a group "
        "row from its first api_id in `aaa/v2/api` order (unticked on the "
        f"{len(unticked_rows)} rows section 1 names, although the grant is live) and a Save "
        "rebuilds every group from the editor's model, the hidden members taking the ticks "
        "of the group's most-ticked member (read from the bundle, not exercised live). No "
        f"baseline row is in a body (the service adds them). `{READONLY_ROLE}` is R only; "
        f"`{OPERATOR_ROLE}` adds Write and Delete where a tool needs them."
    )
    w("")
    w(
        "Load one with an admin's SSO JWT (one curl per file; the content type must carry the "
        "charset), read it back to see the templates, baseline rows and split rows the "
        "service added, then verify with cnc_check_permissions as a user carrying the role:"
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
        "No UI import for a role body is documented; the equivalent is ticking the editor "
        "rows of sections 2 and 3 by hand, which also grants the sibling api_ids those "
        "tables list."
    )
    return "\n".join(out) + "\n"


# --- driver -----------------------------------------------------------------------------


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def generate(
    catalogue: Catalogue, platform: Platform, src: Path, repo: Path = REPO_DIR
) -> tuple[dict[str, str], dict[str, Any], list[str]]:
    """Every output file (repo-relative path -> content) plus the map and the warnings:
    a template that may route to a second API (both recorded), and a read-back fixture
    of a generated body that no longer matches the model's stored form of it, row for
    row, or its verdict (the guide then says so; re-PUT, read back, refresh —
    ``tests/test_rbac_map.py`` pins the rows too)."""
    tools, composed = collect_tools(src)
    rbac_map, ambiguities = build_map(catalogue, platform, tools, composed)
    warnings = [f"{note} (both APIs recorded as requirements)" for note in ambiguities]
    read_templates = platform["read_templates"]
    read_specs = [s for s in rbac_map["tools"].values() if s["read_only"]]
    all_specs = list(rbac_map["tools"].values())
    # the read-only body: the Read tick on every row the read tools touch, nothing else
    readonly_ticks = {api_id: {"R"} for api_id in ticks_for(read_specs, read_templates)}
    readonly_body = role_body(READONLY_ROLE, readonly_ticks, catalogue)
    operator_body = role_body(OPERATOR_ROLE, ticks_for(all_specs, read_templates), catalogue)
    for kind, body in ((READONLY_ROLE, readonly_body), (OPERATOR_ROLE, operator_body)):
        _data, _verdict, tool_drift, rows = read_back_drift(kind, body, rbac_map, catalogue, repo)
        if tool_drift or rows:
            warnings.append(
                f"{GENERATED_FIXTURES[kind]} is a read-back of a previous {kind} body: "
                f"{drift_note(tool_drift, rows)} — re-PUT the body, read it back and refresh "
                "the fixture"
            )
    files = {
        str(MAP_RELATIVE): dump_json(rbac_map),
        str(DOC_RELATIVE): render_doc(rbac_map, catalogue, readonly_body, operator_body, repo),
        str(ROLE_DIR_RELATIVE / f"{READONLY_ROLE}.role.json"): dump_json(readonly_body),
        str(ROLE_DIR_RELATIVE / f"{OPERATOR_ROLE}.role.json"): dump_json(operator_body),
    }
    return files, rbac_map, warnings


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
            "a capture {captured, read_templates: {api_id: [{url, methods}]}, baseline_rows: "
            "{...}, post_delete_apis: [...], not_delete_pattern: '...'} of the platform's "
            "read templates (what GET aaa/v1/role/<r> shows added to each row after storing "
            "a role whose every row was {url: '/.*', methods: ['GET']}), baseline rows (the "
            "rows a role stored without them comes back with) and the split rule's data "
            "(the APIs on which a single POST-without-DELETE entry comes back split, and "
            "the url POST comes back under); a key omitted keeps the committed map's; "
            "default: the 'platform' block of the committed rbac_map.json"
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
        committed = None
        if map_path.exists() and "platform" in read_committed_map(map_path):
            committed = load_platform_map(map_path, catalogue)
        platform = load_platform_file(args.read_templates, catalogue, committed)
    else:
        platform = load_platform_map(map_path, catalogue)

    files, rbac_map, warnings = generate(catalogue, platform, args.src, args.repo)
    err = sys.stderr
    for note in warnings:
        print(f"warning: {note}", file=err)

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
