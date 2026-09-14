#!/usr/bin/env python3
"""Map the published CNC 7.2 OpenAPI operations onto the cnc-mcp tools.

Maintainer script. It needs the Cisco-licensed OpenAPI document set locally —
the documents are NOT in this repository (Cisco's licence does not allow
redistribution); download them from developer.cisco.com (Crosswork Network
Controller 7.2 API reference) into one directory, ideally with a
``catalogue.json`` listing ``{file, title, base, deprecated}`` per document
(without it every ``*.json`` / ``*.yaml`` in the directory is read and the
title is taken from ``info.title``). Only method names and path templates are
copied out of the documents into the report; no descriptive text.

Usage::

    uv run --with pyyaml python scripts/api_coverage.py \\
        --specs ~/cnc-openapi-7.2 --src src/cnc_mcp --out docs/COVERAGE.md

PyYAML is needed only because the Optimization Engine documents are YAML; the
server itself does not depend on it.

How coverage is decided (a static heuristic — read its limits before trusting
one row):

1. Every tool module is parsed with ``ast``. For each function registered
   through ``register_tool(name=...)`` the script walks its body (nested
   closures included) and every helper it calls, in this package, binding
   call arguments to parameters, and records each ``client.request(...)`` /
   ``client.request_json(...)`` it reaches as a (method, path template) pair.
   String constants, f-strings, module-level constants, imported constants,
   dict lookups and helper functions that return path strings are folded;
   anything it cannot fold (a runtime value, ``quote()``, ``encode_key()``)
   becomes a ``{}`` placeholder.
2. Every documented operation (method + base + path) is normalised the same
   way: ``{param}`` segments become placeholders, the scheme/host/port is
   dropped, module prefixes on RESTCONF list names (``ietf-l3vpn-ntw:``) are
   ignored, ``//`` is collapsed.
3. An operation is **covered** when a tool sends the same method to a path
   with the same number of segments, each segment equal or matched by the
   other side's placeholder. A tool template ending in ``/data/{}`` (an
   agent-supplied RESTCONF path) counts as **generic** coverage of every
   longer documented path under that prefix — reported separately, never as
   covered.
4. Everything else is **not exposed** and gets a reason class from pattern
   lists at the top of this file (``NOT_ROUTED_PREFIXES``, ``UI_INTERNAL``,
   ``NETWORK_IMPACTING``, ...). Those classes are labels for review, not
   verified facts.

Known limits: a POST the tool uses as a query is matched to the documented
POST whatever the document says it does; a tool that only probes an endpoint
(``raise_on_error=False``) counts as using it; a helper that builds a path
from data the platform returned (``nso_data_url(yang_path)``) folds to a
placeholder and is matched generically; path constants that no registered
tool reaches are ignored. The "unmatched tool endpoints" section lists every
template the tools send that matched no documented operation — those are
either undocumented endpoints (several are, verified live) or heuristic
misses, and are worth a look after each edit.
"""

from __future__ import annotations

import argparse
import ast
import itertools
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
PLACEHOLDER = "{}"
MAX_CALL_DEPTH = 8
MAX_TEMPLATES_PER_EXPR = 64

# --- review classes ---------------------------------------------------------------------

# API prefixes that answer the home application's 404 on a single-VM CNC 7.2
# deployment (README "Platform facts", CHANGELOG "Known limits", verified live). Service
# Health's own ``/crosswork/aa/`` paths are absent there, but its probe manager
# (``/crosswork/probemgr/``) IS routed on that build (tools/oam.py, verified live), so it
# is deliberately not listed.
NOT_ROUTED_PREFIXES: dict[str, str] = {
    "/crosswork/aa/": "Service Health (capp-aa)",
    "/crosswork/hi/": "Health Insights",
    "/crosswork/nca/": "Change Automation",
    "/crosswork/path_analytics/": "Path Analytics",
    "/crosswork/crosscluster/": "cross-cluster service",
    "/crosswork/performance/restconf/": "RESTCONF performance API",
}

# Operations that look like a read even though they are POST/PUT (the platform's
# JSON-over-POST query idiom, RESTCONF RPC reads, ...).
READ_LIKE = re.compile(
    r"(/query[a-z]*$|/count$|/list$|/show$|/summary$|/summary/|/get$|/get[A-Z/]|/search$|/history$"
    r"|/status$|/details$|/report$|/check-expiry$|/isNSOConfigured$|/validate$"
    r"|/operations/[^/]*:(get-|list-|all-|[a-z0-9-]*-(oper|on-node|on-nodes|on-interface|metrics"
    r"|routes|preview|dryrun|paths|count|status|state|report|list|log)$))",
)

# Reason-class patterns for operations no tool covers (first match wins, top to bottom,
# after the not-routed / deprecated / streaming checks). Case-insensitive on the path.
UI_INTERNAL = re.compile(
    r"(/preferences(/|$)|/log/|changeLogLevel|staticFile|upload|download|/export|/import"
    r"|csv|getSessionMgmtPermissions|taskAPIPermission|/ui/|/scripts?(/|$)|/staticFiles)",
    re.IGNORECASE,
)
NETWORK_IMPACTING = re.compile(
    r"(^/crosswork/performance/v1/policies"
    r"|^/crosswork/collection/v1/(collectionjob|jobs|templatecollectionjob|devicecollection"
    r"|template)$"
    r"|^/crosswork/api/\{version\}/op/swim/image/"
    r"|^/crosswork/(ztp|configsvc|imagesvc)/v1/"
    r"|^/crosswork/config/v1/(config-restore|restore|schedule-config-restore|deploy)"
    r"|^/crosswork/proxy/nso/restconf/data/"
    r"|/operations/[^/]*:(?![a-z0-9-]*opm)[a-z0-9-]*(create|modify|delete|commit|reoptimize|set-)"
    r"|^/crosswork/inventory/v1/nso/(sync|sync-to|sync-from|connect)$)",
)
STREAMING_PATH = re.compile(r"(/streams?(/|$)|socket|\.(json|xml)$)")
STREAMING_TITLE = re.compile(r"(Streaming|Connection Oriented)", re.IGNORECASE)

# The CAS SSO flow lives in auth.py (CrossworkCasAuth), not in a tool; the script checks
# that the literal path is still in auth.py before claiming these.
AUTH_LABEL = "CrossworkCasAuth (auth.py)"
AUTH_PATH_LITERAL = "/crosswork/sso/v1/tickets"
AUTH_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("POST", "/crosswork/sso/v1/tickets"),
    ("POST", "/crosswork/sso/v1/tickets/{}"),
    ("DELETE", "/crosswork/sso/v1/tickets/{}"),
)

# Operations that were exercised live and left out on purpose (README "Platform facts").
# (METHOD, path regex) -> why.
DELIBERATELY_UNUSED: tuple[tuple[str, str, str], ...] = (
    (
        "GET",
        r"/nbi/topology/v3/restconf/data/ietf-network-state:networks/network=\{[^}]*\}$",
        "the keyed network GET answers a shallow topology; the tools read the collection",
    ),
    (
        "GET",
        r"/vpn-service=\{[^}]*\}/status/oper-status$",
        "answers 409 as a sub-path; the tools read the service node with content=nonconfig",
    ),
    (
        "POST",
        r"^/crosswork/sso/v2/tickets/jwt$",
        "the v1 two-leg CAS flow is used instead (auth.py)",
    ),
)

CLASS_NOT_ROUTED = "not routed on single-VM deployments"
CLASS_DEPRECATED = "deprecated duplicate"
CLASS_STREAMING = "streaming/websocket"
CLASS_UI_INTERNAL = "UI-internal"
CLASS_NETWORK_WRITE = "network-impacting write"
CLASS_UNVERIFIED_WRITE = "unverified write"
CLASS_UNVERIFIED_READ = "unverified read"
CLASS_DELIBERATE = "verified live, deliberately unused"

STATUS_COVERED = "covered"
STATUS_GENERIC = "generic"
STATUS_NOT_EXPOSED = "not exposed"


# --- spec side --------------------------------------------------------------------------


@dataclass
class Operation:
    doc: Document
    method: str
    path: str  # full path template, base included
    deprecated: bool
    segments: tuple[str, ...] = field(init=False)

    def __post_init__(self) -> None:
        self.segments = normalise(self.path)

    @property
    def is_read(self) -> bool:
        return self.method == "GET" or bool(READ_LIKE.search(self.path))

    @property
    def not_routed(self) -> str | None:
        for prefix, app in NOT_ROUTED_PREFIXES.items():
            if self.path.startswith(prefix):
                return app
        return None


@dataclass
class Document:
    file: str
    title: str
    base: str
    deprecated: bool
    operations: list[Operation] = field(default_factory=list)


def load_yaml_or_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError:  # pragma: no cover - environment dependent
            sys.exit(
                f"{path.name} is YAML and PyYAML is not installed: run with "
                "'uv run --with pyyaml python scripts/api_coverage.py ...'"
            )
        return yaml.safe_load(text)
    return json.loads(text)


def base_path_of(spec: dict[str, Any]) -> str:
    """The path part of servers[0].url (OpenAPI 3) or basePath (Swagger 2)."""
    url = ""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = str(servers[0].get("url") or "")
    elif spec.get("basePath"):
        url = str(spec["basePath"])
    # Drop scheme + host[:port]; the catalogue keeps ':30603/...' for some documents.
    url = re.sub(r"^[a-z]+://[^/]*", "", url)
    url = re.sub(r"^:[^/]*", "", url)
    return "/" + url.strip("/") if url.strip("/") else ""


def load_documents(specs_dir: Path) -> list[Document]:
    catalogue = specs_dir / "catalogue.json"
    entries: list[dict[str, Any]]
    if catalogue.exists():
        entries = json.loads(catalogue.read_text(encoding="utf-8"))
    else:
        entries = [
            {"file": p.name}
            for p in sorted(specs_dir.iterdir())
            if p.suffix.lower() in (".json", ".yaml", ".yml") and p.name != "spec_index.json"
        ]
    documents: list[Document] = []
    for entry in entries:
        path = specs_dir / entry["file"]
        spec = load_yaml_or_json(path)
        if not isinstance(spec, dict) or "paths" not in spec:
            continue
        info = spec.get("info") or {}
        title = str(entry.get("title") or info.get("title") or path.stem)
        doc_deprecated = bool(entry.get("deprecated")) or "deprecated" in title.lower()
        doc = Document(
            file=path.name, title=title, base=base_path_of(spec), deprecated=doc_deprecated
        )
        for raw_path, item in (spec.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            for method, op in item.items():
                if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                    continue
                full = collapse_slashes(f"{doc.base}/{raw_path}")
                doc.operations.append(
                    Operation(
                        doc=doc,
                        method=method.upper(),
                        path=full,
                        deprecated=doc_deprecated or bool(op.get("deprecated")),
                    )
                )
        documents.append(doc)
    return documents


# --- path normalisation and matching ------------------------------------------------


def collapse_slashes(path: str) -> str:
    return re.sub(r"/{2,}", "/", path)


_PARAM_RE = re.compile(r"\{[^{}]*\}")
_MODULE_PREFIX_RE = re.compile(r"^[^/=]*:")


def normalise(path: str) -> tuple[str, ...]:
    """Segments with ``{param}`` -> placeholder, module prefixes dropped, query removed."""
    path = path.split("?", 1)[0].split("#", 1)[0]
    path = _PARAM_RE.sub(PLACEHOLDER, path)
    out: list[str] = []
    for seg in collapse_slashes(path).strip("/").split("/"):
        if not seg:
            continue
        out.append(_MODULE_PREFIX_RE.sub("", seg))
    return tuple(out)


def _segment_regex(seg: str) -> re.Pattern[str]:
    parts = [re.escape(p) for p in seg.split(PLACEHOLDER)]
    return re.compile(".+".join(parts) if len(parts) > 1 else re.escape(seg))


def segment_match(a: str, b: str) -> bool:
    if a == b:
        return True
    if PLACEHOLDER in a and _segment_regex(a).fullmatch(b):
        return True
    return PLACEHOLDER in b and bool(_segment_regex(b).fullmatch(a))


def path_match(spec: tuple[str, ...], tool: tuple[str, ...]) -> bool:
    return len(spec) == len(tool) and all(
        segment_match(s, t) for s, t in zip(spec, tool, strict=True)
    )


def is_generic_template(tool: tuple[str, ...]) -> bool:
    """``.../data/{}``: the whole RESTCONF path is agent-supplied (never an exact match)."""
    return len(tool) >= 2 and tool[-1] == PLACEHOLDER and tool[-2] == "data"


def generic_match(spec: tuple[str, ...], tool: tuple[str, ...]) -> bool:
    """A ``.../data/{}`` template reaches every documented path under its prefix."""
    if not is_generic_template(tool):
        return False
    prefix = tool[:-1]
    return len(spec) > len(prefix) and all(
        segment_match(s, t) for s, t in zip(spec[: len(prefix)], prefix, strict=True)
    )


# --- source side: a small constant folder over the tool modules ----------------------


@dataclass
class SourceModule:
    name: str  # e.g. "tools.devices" or "restconf"
    tree: ast.Module
    constants: dict[str, ast.expr] = field(default_factory=dict)
    functions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = field(default_factory=dict)
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)  # local -> (module, attr)
    module_aliases: dict[str, str] = field(default_factory=dict)  # alias -> module name

    @classmethod
    def parse(cls, name: str, path: Path, package: str) -> SourceModule:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        mod = cls(name=name, tree=tree)
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        mod.constants[target.id] = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.value is not None:
                    mod.constants[node.target.id] = node.value
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith(package + "."):
                    source = node.module[len(package) + 1 :]
                    for alias in node.names:
                        mod.imports[alias.asname or alias.name] = (source, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(package + "."):
                        mod.module_aliases[alias.asname or alias.name] = alias.name[
                            len(package) + 1 :
                        ]
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                mod.functions.setdefault(node.name, []).append(node)
        return mod


@dataclass(frozen=True)
class Env:
    module: SourceModule
    func: ast.FunctionDef | ast.AsyncFunctionDef | None
    bindings: tuple[tuple[str, tuple[str, ...]], ...] = ()
    stack: tuple[str, ...] = ()  # names being resolved (self-reference guard)

    def bound(self, name: str) -> set[str] | None:
        for key, values in self.bindings:
            if key == name:
                return set(values)
        return None


@dataclass
class Tool:
    name: str
    module: str
    read_only: bool
    endpoints: set[tuple[str, str]] = field(default_factory=set)  # (METHOD|*, template)


class Analyzer:
    def __init__(self, src_dir: Path) -> None:
        self.src_dir = src_dir
        self.package = src_dir.name
        self.modules: dict[str, SourceModule] = {}
        for path in sorted(src_dir.glob("*.py")):
            self.modules[path.stem] = SourceModule.parse(path.stem, path, self.package)
        for path in sorted((src_dir / "tools").glob("*.py")):
            name = f"tools.{path.stem}"
            self.modules[name] = SourceModule.parse(name, path, self.package)
        self._const_memo: dict[tuple[str, str], set[str]] = {}

    # -- lookups -----------------------------------------------------------------------

    def resolve_name(self, module: SourceModule, name: str) -> tuple[SourceModule, str] | None:
        """Follow ``from cnc_mcp.x import name`` chains to the defining module."""
        seen: set[tuple[str, str]] = set()
        current, attr = module, name
        while (current.name, attr) not in seen:
            seen.add((current.name, attr))
            if attr in current.constants or attr in current.functions:
                return current, attr
            target = current.imports.get(attr)
            if target is None:
                return None
            source, attr = target
            if source == "tools":
                source = f"tools.{attr}"
            if source not in self.modules:
                return None
            current = self.modules[source]
        return None

    def function_for(
        self, module: SourceModule, node: ast.expr
    ) -> list[tuple[SourceModule, ast.FunctionDef | ast.AsyncFunctionDef]]:
        if isinstance(node, ast.Name):
            resolved = self.resolve_name(module, node.id)
            if resolved and resolved[1] in resolved[0].functions:
                return [(resolved[0], fn) for fn in resolved[0].functions[resolved[1]]]
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            alias = module.module_aliases.get(node.value.id)
            if alias and alias in self.modules and node.attr in self.modules[alias].functions:
                return [
                    (self.modules[alias], fn) for fn in self.modules[alias].functions[node.attr]
                ]
        return []

    # -- evaluation --------------------------------------------------------------------

    def eval_constant(self, module: SourceModule, name: str) -> set[str]:
        key = (module.name, name)
        if key in self._const_memo:
            return self._const_memo[key]
        self._const_memo[key] = {PLACEHOLDER}  # recursion guard
        expr = module.constants[name]
        value = self.evaluate(expr, Env(module, None, stack=(name,)))
        self._const_memo[key] = value
        return value

    def evaluate(self, node: ast.expr | None, env: Env, depth: int = 0) -> set[str]:
        if node is None or depth > 40:
            return {PLACEHOLDER}
        if isinstance(node, ast.Constant):
            return {node.value} if isinstance(node.value, str) else {PLACEHOLDER}
        if isinstance(node, ast.JoinedStr):
            parts: list[set[str]] = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append({str(value.value)})
                elif isinstance(value, ast.FormattedValue):
                    if value.format_spec is not None:
                        parts.append({PLACEHOLDER})
                    else:
                        parts.append(self.evaluate(value.value, env, depth + 1))
                else:
                    parts.append({PLACEHOLDER})
            return _product(parts)
        if isinstance(node, ast.Name):
            return self.eval_name(node.id, env, depth)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                alias = env.module.module_aliases.get(node.value.id)
                if alias and alias in self.modules and node.attr in self.modules[alias].constants:
                    return self.eval_constant(self.modules[alias], node.attr)
            return {PLACEHOLDER}
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return _product(
                [
                    self.evaluate(node.left, env, depth + 1),
                    self.evaluate(node.right, env, depth + 1),
                ]
            )
        if isinstance(node, ast.IfExp):
            return self.evaluate(node.body, env, depth + 1) | self.evaluate(
                node.orelse, env, depth + 1
            )
        if isinstance(node, ast.BoolOp):
            out: set[str] = set()
            for value in node.values:
                out |= self.evaluate(value, env, depth + 1)
            return out
        if isinstance(node, ast.Subscript):
            return self.eval_subscript(node, env, depth)
        if isinstance(node, ast.Call):
            return self.eval_call(node, env, depth)
        return {PLACEHOLDER}

    def eval_name(self, name: str, env: Env, depth: int) -> set[str]:
        bound = env.bound(name)
        if bound is not None:
            return bound
        if name in env.stack:
            return {PLACEHOLDER}
        if env.func is not None:
            values: set[str] = set()
            for assign in _assignments_to(env.func, name):
                values |= self.evaluate(
                    assign, Env(env.module, env.func, env.bindings, env.stack + (name,)), depth + 1
                )
            if values:
                return values
        resolved = self.resolve_name(env.module, name)
        if resolved and resolved[1] in resolved[0].constants:
            return self.eval_constant(resolved[0], resolved[1])
        return {PLACEHOLDER}

    def eval_subscript(self, node: ast.Subscript, env: Env, depth: int) -> set[str]:
        if isinstance(node.value, ast.Name):
            resolved = self.resolve_name(env.module, node.value.id)
            if resolved and resolved[1] in resolved[0].constants:
                target = resolved[0].constants[resolved[1]]
                if isinstance(target, ast.Dict):
                    key_env = Env(resolved[0], None)
                    if isinstance(node.slice, ast.Constant):
                        for key, value in zip(target.keys, target.values, strict=True):
                            if isinstance(key, ast.Constant) and key.value == node.slice.value:
                                return self.evaluate(value, key_env, depth + 1)
                    out: set[str] = set()
                    for value in target.values:
                        out |= self.evaluate(value, key_env, depth + 1)
                    return out or {PLACEHOLDER}
        return {PLACEHOLDER}

    def eval_call(self, node: ast.Call, env: Env, depth: int) -> set[str]:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in ("rstrip", "strip", "lstrip", "removesuffix", "removeprefix"):
                return self.evaluate(func.value, env, depth + 1)
            if func.attr == "format":
                return {
                    _PARAM_RE.sub(PLACEHOLDER, value)
                    for value in self.evaluate(func.value, env, depth + 1)
                }
        targets = self.function_for(env.module, func)
        if not targets or depth > MAX_CALL_DEPTH * 4:
            return {PLACEHOLDER}
        out: set[str] = set()
        for module, fn in targets:
            if fn.name in env.stack:
                continue
            callee_env = self.bind(fn, module, node, env, depth)
            for ret in _returns_of(fn):
                out |= self.evaluate(ret, callee_env, depth + 1)
        return out or {PLACEHOLDER}

    def bind(
        self,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        module: SourceModule,
        call: ast.Call,
        caller: Env,
        depth: int,
    ) -> Env:
        params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
        kwonly = [a.arg for a in fn.args.kwonlyargs]
        defaults: dict[str, ast.expr] = {}
        positional_defaults = fn.args.defaults
        for name, default in zip(
            params[len(params) - len(positional_defaults) :], positional_defaults, strict=True
        ):
            defaults[name] = default
        for name, default in zip(kwonly, fn.args.kw_defaults, strict=True):
            if default is not None:
                defaults[name] = default
        bindings: dict[str, set[str]] = {}
        for index, arg in enumerate(call.args):
            if isinstance(arg, ast.Starred):
                break
            if index < len(params):
                bindings[params[index]] = self.evaluate(arg, caller, depth + 1)
        for kw in call.keywords:
            if kw.arg is not None and (kw.arg in params or kw.arg in kwonly):
                bindings[kw.arg] = self.evaluate(kw.value, caller, depth + 1)
        callee_env = Env(module, fn, stack=caller.stack + (fn.name,))
        for name, default in defaults.items():
            if name not in bindings:
                bindings[name] = self.evaluate(default, callee_env, depth + 1)
        return Env(
            module,
            fn,
            tuple((k, tuple(sorted(v))) for k, v in sorted(bindings.items())),
            caller.stack + (fn.name,),
        )

    # -- endpoint collection ---------------------------------------------------------------

    def collect_tools(self) -> list[Tool]:
        tools: list[Tool] = []
        for module in self.modules.values():
            if not module.name.startswith("tools."):
                continue
            for node in ast.walk(module.tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                meta = _register_tool_meta(node)
                if meta is None:
                    continue
                name, read_only = meta
                tool = Tool(
                    name=name, module=module.name.removeprefix("tools."), read_only=read_only
                )
                visited: set[tuple[int, tuple[Any, ...]]] = set()
                self.collect(node, Env(module, node), tool.endpoints, visited, 0)
                tools.append(tool)
        return tools

    def collect(
        self,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        env: Env,
        out: set[tuple[str, str]],
        visited: set[tuple[int, tuple[Any, ...]]],
        depth: int,
    ) -> None:
        key = (id(fn), env.bindings)
        if key in visited or depth > MAX_CALL_DEPTH:
            return
        visited.add(key)
        nodes = list(ast.walk(fn))
        called = {id(node.func) for node in nodes if isinstance(node, ast.Call)}
        for node in nodes:
            if isinstance(node, ast.Call):
                if _is_client_request(node):
                    self.record_request(node, env, out)
                    continue
                for module, callee in self.function_for(env.module, node.func):
                    if callee is fn:
                        continue
                    self.collect(
                        callee, self.bind(callee, module, node, env, depth), out, visited, depth + 1
                    )
            elif isinstance(node, ast.Name) and id(node) not in called:
                if isinstance(node.ctx, ast.Store):
                    continue
                # A function passed as a value (a wait_until fetch callback, a dispatch table):
                # expanded with no bindings, so its parameters become placeholders.
                for module, callee in self.function_for(env.module, node):
                    if callee is not fn:
                        self.collect(
                            callee,
                            Env(module, callee, stack=env.stack + (callee.name,)),
                            out,
                            visited,
                            depth + 1,
                        )

    def record_request(self, node: ast.Call, env: Env, out: set[tuple[str, str]]) -> None:
        method_expr: ast.expr | None = node.args[0] if node.args else None
        path_expr: ast.expr | None = node.args[1] if len(node.args) > 1 else None
        for kw in node.keywords:
            if kw.arg == "method":
                method_expr = kw.value
            elif kw.arg == "path":
                path_expr = kw.value
        methods = {
            m.upper() if m.upper() in {h.upper() for h in HTTP_METHODS} else "*"
            for m in self.evaluate(method_expr, env)
        }
        for template in self.evaluate(path_expr, env):
            template = template.split("?", 1)[0]
            # Consecutive placeholders fold to one; a trailing slash is the empty branch of
            # a helper (``f"{url}/{subtree}"`` with no subtree) and is never sent as such.
            template = re.sub(r"(\{\})+", PLACEHOLDER, template)
            if not template.startswith("/") or template.endswith("/"):
                continue
            for method in methods:
                out.add((method, template))


def _product(parts: list[set[str]]) -> set[str]:
    out: set[str] = set()
    for combo in itertools.islice(itertools.product(*parts), MAX_TEMPLATES_PER_EXPR):
        out.add("".join(combo))
    return out or {PLACEHOLDER}


def _assignments_to(fn: ast.AST, name: str) -> list[ast.expr]:
    """Every expression ``name`` is bound to anywhere inside ``fn``.

    Plain, annotated, augmented and walrus assignments, tuple/list targets
    unpacked element-wise against a literal tuple/list on the right
    (``url, params = FULL_RESYNC_URL, {...}``), and ``for`` targets bound to
    each element of a literal iterable (``for what, path in ((..., PATH), ...)``).
    A target the folder cannot unpack (starred, or a runtime right-hand side)
    binds a placeholder so the name is not mistaken for a module constant.
    """
    found: list[ast.expr] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                found.extend(_bind_target(target, node.value, name))
        elif isinstance(node, ast.AnnAssign | ast.AugAssign):
            if node.value is not None:
                found.extend(_bind_target(node.target, node.value, name))
        elif isinstance(node, ast.NamedExpr):
            found.extend(_bind_target(node.target, node.value, name))
        elif isinstance(node, ast.For | ast.AsyncFor):
            if isinstance(node.iter, ast.Tuple | ast.List | ast.Set) and node.iter.elts:
                for element in node.iter.elts:
                    found.extend(_bind_target(node.target, element, name))
            elif _target_names(node.target) & {name}:
                found.append(ast.Constant(value=None))  # runtime iterable: placeholder
    return found


def _bind_target(target: ast.expr, value: ast.expr, name: str) -> list[ast.expr]:
    """Expressions bound to ``name`` when ``target = value`` runs (see _assignments_to)."""
    if isinstance(target, ast.Name):
        return [value] if target.id == name else []
    if isinstance(target, ast.Tuple | ast.List):
        if name not in _target_names(target):
            return []
        if (
            isinstance(value, ast.Tuple | ast.List)
            and len(value.elts) == len(target.elts)
            and not any(isinstance(t, ast.Starred) for t in target.elts)
        ):
            found: list[ast.expr] = []
            for element_target, element_value in zip(target.elts, value.elts, strict=True):
                found.extend(_bind_target(element_target, element_value, name))
            return found
        return [ast.Constant(value=None)]  # bound, value unknown: placeholder
    return []


def _target_names(target: ast.expr) -> set[str]:
    """Names an assignment/for target binds (``a``, ``(a, b)``, ``[a, *rest]``)."""
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    if isinstance(target, ast.Tuple | ast.List):
        out: set[str] = set()
        for element in target.elts:
            out |= _target_names(element)
        return out
    return set()


def _returns_of(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.expr]:
    """Return expressions of fn, not descending into nested functions/lambdas."""
    found: list[ast.expr] = []
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
            continue
        if isinstance(node, ast.Return) and node.value is not None:
            found.append(node.value)
        stack.extend(ast.iter_child_nodes(node))
    return found


def _register_tool_meta(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, bool] | None:
    for deco in fn.decorator_list:
        if not (isinstance(deco, ast.Call) and isinstance(deco.func, ast.Name)):
            continue
        if deco.func.id != "register_tool":
            continue
        name: str | None = None
        read_only = True
        for kw in deco.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                name = str(kw.value.value)
            elif kw.arg == "read_only" and isinstance(kw.value, ast.Constant):
                read_only = bool(kw.value.value)
        if name:
            return name, read_only
    return None


def _is_client_request(node: ast.Call) -> bool:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr not in ("request", "request_json"):
        return False
    receiver = func.value
    while isinstance(receiver, ast.Attribute):
        if "client" in receiver.attr:
            return True
        receiver = receiver.value
    return isinstance(receiver, ast.Name) and "client" in receiver.id


# --- matching + classification ----------------------------------------------------------


@dataclass
class OpResult:
    op: Operation
    status: str
    tools: list[str]
    reason: str | None
    generic_tools: list[str]


def deliberate_note(op: Operation) -> str | None:
    for method, pattern, why in DELIBERATELY_UNUSED:
        if op.method == method and re.search(pattern, op.path):
            return why
    return None


def classify(op: Operation) -> str:
    if op.not_routed:
        return CLASS_NOT_ROUTED
    if deliberate_note(op):
        return CLASS_DELIBERATE
    if op.deprecated:
        return CLASS_DEPRECATED
    if STREAMING_TITLE.search(op.doc.title) or STREAMING_PATH.search(op.path):
        return CLASS_STREAMING
    if UI_INTERNAL.search(op.path):
        return CLASS_UI_INTERNAL
    if op.is_read:
        return CLASS_UNVERIFIED_READ
    if NETWORK_IMPACTING.search(op.path):
        return CLASS_NETWORK_WRITE
    return CLASS_UNVERIFIED_WRITE


def match_all(
    documents: list[Document], tools: list[Tool], auth_endpoints: tuple[tuple[str, str], ...]
) -> tuple[list[OpResult], dict[tuple[str, str], list[str]]]:
    endpoint_tools: dict[tuple[str, str], list[str]] = defaultdict(list)
    for tool in tools:
        for endpoint in tool.endpoints:
            endpoint_tools[endpoint].append(tool.name)
    for endpoint in auth_endpoints:
        endpoint_tools[endpoint].append(AUTH_LABEL)
    endpoint_segments = {ep: normalise(ep[1]) for ep in endpoint_tools}
    matched_endpoints: set[tuple[str, str]] = set()
    results: list[OpResult] = []
    for doc in documents:
        for op in doc.operations:
            exact: set[str] = set()
            generic: set[str] = set()
            for (method, template), names in endpoint_tools.items():
                if method not in ("*", op.method):
                    continue
                segs = endpoint_segments[(method, template)]
                if not is_generic_template(segs) and path_match(op.segments, segs):
                    exact.update(names)
                    matched_endpoints.add((method, template))
                elif generic_match(op.segments, segs):
                    generic.update(names)
                    matched_endpoints.add((method, template))
            if exact:
                status, reason = STATUS_COVERED, None
            elif generic:
                status, reason = STATUS_GENERIC, None
            else:
                status, reason = STATUS_NOT_EXPOSED, classify(op)
            results.append(OpResult(op, status, sorted(exact), reason, sorted(generic)))
    unmatched = {
        ep: sorted(names) for ep, names in endpoint_tools.items() if ep not in matched_endpoints
    }
    return results, unmatched


# --- report -----------------------------------------------------------------------------


def doc_status(rows: list[OpResult], doc: Document) -> str:
    covered = sum(r.status == STATUS_COVERED for r in rows)
    generic = sum(r.status == STATUS_GENERIC for r in rows)
    total = len(rows)
    if covered == total:
        return STATUS_COVERED
    if covered or generic:
        return "partial"
    reasons = Counter(r.reason for r in rows if r.reason)
    if not reasons:
        return STATUS_NOT_EXPOSED
    top, _ = reasons.most_common(1)[0]
    if top == CLASS_NOT_ROUTED:
        return CLASS_NOT_ROUTED
    return f"{STATUS_NOT_EXPOSED} ({top})"


def md_escape(text: str) -> str:
    return text.replace("|", "\\|")


SUMMARY_NAMES_SHOWN = 12


def _name_list(names: list[str]) -> str:
    """Up to SUMMARY_NAMES_SHOWN backticked names, then "+N more" (the detail has them all)."""
    shown = ", ".join(f"`{n}`" for n in names[:SUMMARY_NAMES_SHOWN])
    if len(names) > SUMMARY_NAMES_SHOWN:
        shown += f" +{len(names) - SUMMARY_NAMES_SHOWN} more"
    return shown


def render(
    documents: list[Document],
    tools: list[Tool],
    results: list[OpResult],
    unmatched: dict[tuple[str, str], list[str]],
    specs_dir: Path,
) -> str:
    by_doc: dict[str, list[OpResult]] = defaultdict(list)
    for row in results:
        by_doc[row.op.doc.file].append(row)

    total_ops = len(results)
    covered = [r for r in results if r.status == STATUS_COVERED]
    generic = [r for r in results if r.status == STATUS_GENERIC]
    not_exposed = [r for r in results if r.status == STATUS_NOT_EXPOSED]
    reasons = Counter(r.reason for r in not_exposed)
    reason_docs: dict[str, set[str]] = defaultdict(set)
    for r in not_exposed:
        reason_docs[r.reason or "?"].add(r.op.doc.title)
    tools_used = {name for r in covered + generic for name in r.tools + r.generic_tools} - {
        AUTH_LABEL
    }
    tools_without_docs = sorted(t.name for t in tools if t.name not in tools_used)
    tools_without_endpoints = sorted(t.name for t in tools if not t.endpoints)
    read_tools = sum(t.read_only for t in tools)
    write_tools = len(tools) - read_tools
    deprecated_docs = sum(d.deprecated for d in documents)
    deprecated_ops = sum(op.deprecated for d in documents for op in d.operations)
    covered_not_routed = sum(bool(r.op.not_routed) for r in covered)
    live_ops = [r for r in results if not r.op.not_routed and not r.op.deprecated]
    live_covered = sum(r.status == STATUS_COVERED for r in live_ops)
    areas = {t.module for t in tools}

    lines: list[str] = []
    w = lines.append
    w("# API coverage: CNC 7.2 published operations vs cnc-mcp tools")
    w("")
    w(
        "Generated by `scripts/api_coverage.py` from the published Cisco Crosswork Network "
        "Controller 7.2 OpenAPI documents (Cisco-licensed, kept outside this repository; "
        "only method names and path templates are reproduced here) and the tool modules in "
        "`src/cnc_mcp/tools/`. Every number on this page is computed by the script, not "
        "copied from the README; re-run it after adding a tool module."
    )
    w("")
    w("## How to read this page")
    w("")
    w(
        "- **covered**: a registered tool sends that HTTP method to that path template "
        "(same segments, `{param}` on either side matching anything). The matching is a "
        "static heuristic over the source (constants, f-strings and helper functions folded "
        "into path templates; runtime values become `{}`), so a row proves a tool *calls* the "
        "endpoint, not that every documented option of the operation is exposed. The three "
        "SSO ticket operations are credited to `auth.py`, which is where the CAS flow lives."
    )
    w(
        "- **generic**: no tool targets the path itself, but a tool that takes an "
        "agent-supplied RESTCONF path (`cnc_get_service`, `cnc_provision_service`, "
        "`cnc_delete_service`, ...) can reach it. Counted separately from covered."
    )
    w(
        "- **not exposed**: no tool reaches the operation. The reason class is a label "
        "assigned by pattern lists in the script, for review, not a verified fact: "
        "*unverified read* / *unverified write* (never exercised against a live instance, so "
        "not shipped; the write class includes platform-administration writes), "
        "*network-impacting write* (provisioning, collection, software or ZTP writes that "
        "change devices), *streaming/websocket* (not request/response, out of MCP scope), "
        "*deprecated duplicate* (the document or the operation carries `deprecated: true`, "
        "usually a v1 copy of a current document; the SWIM document is flagged whole with no "
        "documented successor and its reads are used anyway), *UI-internal* (uploads, "
        "downloads, exports, log levels, UI preferences), *verified live, deliberately "
        "unused* (exercised on the lab and left out for the reason given in the row)."
    )
    w(
        "- **not routed on single-VM deployments**: the prefix answers the home application's "
        "404 on a single-VM CNC 7.2 deployment (Service Health `aa`, Health Insights `hi`, "
        "Change Automation `nca`, Path Analytics, cross-cluster, the RESTCONF performance "
        "API), verified live; tools that exist for such a prefix report the missing "
        "application instead of failing. Service Health's probe manager (`probemgr`) is "
        "routed on that build and is covered like any other prefix."
    )
    w(
        "- The heuristic's blind spots: a POST the tool uses as a query is matched to the "
        "documented POST whatever the document calls it; a tool that only probes an endpoint "
        "counts as using it; a path built from data the platform returned folds to `{}` and is "
        "matched generically; path constants no registered tool reaches are ignored. The "
        "*unmatched tool endpoints* section lists every template the tools send that matched "
        "no documented operation, so undocumented endpoints (several were verified live) and "
        "heuristic misses are visible rather than hidden."
    )
    w("")
    w("## Headline numbers")
    w("")
    w("| Measure | Value |")
    w("|---|---:|")
    w(
        f"| OpenAPI documents read (`{md_escape(specs_dir.name)}`) | "
        f"{len(documents)} ({deprecated_docs} deprecated) |"
    )
    w(f"| Documented operations (method + path) | {total_ops} ({deprecated_ops} deprecated) |")
    w(
        f"| Registered tools found in the source | {len(tools)} "
        f"({read_tools} read, {write_tools} write) over {len(areas)} modules |"
    )
    w(f"| Operations covered by a tool | {len(covered)} ({100 * len(covered) / total_ops:.0f}%) |")
    w(f"| Operations reachable only through a generic RESTCONF path tool | {len(generic)} |")
    w(f"| Operations not exposed | {len(not_exposed)} |")
    w(
        f"| Operations on prefixes not routed on single-VM deployments | "
        f"{sum(bool(r.op.not_routed) for r in results)} "
        f"({covered_not_routed} of them covered by a tool anyway) |"
    )
    w(
        f"| Coverage of routed, non-deprecated operations | "
        f"{live_covered} of {len(live_ops)} ({100 * live_covered / max(len(live_ops), 1):.0f}%) |"
    )
    w(f"| Tools mapped to at least one documented operation | {len(tools_used)} of {len(tools)} |")
    w(f"| Tool endpoints matching no documented operation | {len(unmatched)} |")
    w("")
    w("Not exposed, by reason class:")
    w("")
    w("| Reason class | Operations | Documents |")
    w("|---|---:|---:|")
    for reason, count in reasons.most_common():
        w(f"| {reason} | {count} | {len(reason_docs[reason or '?'])} |")
    w("")
    if tools_without_docs:
        w(
            "Tools whose endpoints match no documented operation (they use endpoints the "
            "documents do not list, or a path the heuristic could not fold): "
            + ", ".join(f"`{n}`" for n in tools_without_docs)
            + "."
        )
        w("")
    if tools_without_endpoints:
        w(
            "Tools for which the script found no request at all (pure client-side tools or "
            "an analysis miss): " + ", ".join(f"`{n}`" for n in tools_without_endpoints) + "."
        )
        w("")

    w("## Per-document summary")
    w("")
    w("| Document | Base prefix | Ops | Covered | Generic | Status | Tools |")
    w("|---|---|---:|---:|---:|---|---|")
    for doc in sorted(documents, key=lambda d: (d.base, d.title)):
        rows = by_doc[doc.file]
        names = sorted({n for r in rows for n in r.tools})
        generic_names = sorted({n for r in rows for n in r.generic_tools} - set(names))
        shown = _name_list(names)
        if generic_names:
            shown += (" · " if shown else "") + "generic: " + _name_list(generic_names)
        w(
            f"| {md_escape(doc.title)} | `{doc.base or '/'}` | {len(rows)} | "
            f"{sum(r.status == STATUS_COVERED for r in rows)} | "
            f"{sum(r.status == STATUS_GENERIC for r in rows)} | {doc_status(rows, doc)} | {shown} |"
        )
    w("")

    w("## Operations by document")
    w("")
    w(
        "Method and path template as documented (base prefix included); status and the tools "
        "that send it."
    )
    w("")
    for doc in sorted(documents, key=lambda d: (d.base, d.title)):
        rows = by_doc[doc.file]
        covered_n = sum(r.status == STATUS_COVERED for r in rows)
        w("<details>")
        w(
            f"<summary><b>{md_escape(doc.title)}</b> — <code>{doc.file}</code> — "
            f"{covered_n}/{len(rows)} covered, {doc_status(rows, doc)}</summary>"
        )
        w("")
        w("| Method | Path | Status | Tools |")
        w("|---|---|---|---|")
        for r in sorted(rows, key=lambda r: (r.op.path, r.op.method)):
            if r.status == STATUS_COVERED:
                status = "covered"
                if r.op.not_routed:
                    status += " (prefix not routed on single-VM deployments)"
                if r.op.deprecated:
                    status += " (documented as deprecated)"
                names = ", ".join(f"`{n}`" for n in r.tools)
            elif r.status == STATUS_GENERIC:
                status = "generic"
                names = ", ".join(f"`{n}`" for n in r.generic_tools)
            else:
                status = f"not exposed: {r.reason}"
                note = deliberate_note(r.op)
                names = md_escape(note) if note else ""
            w(f"| {r.op.method} | `{md_escape(r.op.path)}` | {status} | {names} |")
        w("")
        w("</details>")
        w("")

    w("## Unmatched tool endpoints")
    w("")
    w(
        "Templates the tools send that matched no documented operation. Verified-live but "
        "undocumented endpoints belong here (see the README's platform facts); anything else is "
        "a heuristic miss to check."
    )
    w("")
    w("| Method | Path template | Tools |")
    w("|---|---|---|")
    for (method, template), names in sorted(unmatched.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        w(f"| {method} | `{md_escape(template)}` | {', '.join(f'`{n}`' for n in names)} |")
    w("")
    return "\n".join(lines)


# --- main -------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--specs", required=True, type=Path, help="directory with the OpenAPI documents"
    )
    parser.add_argument(
        "--src",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "src" / "cnc_mcp",
        help="the cnc_mcp package directory (default: src/cnc_mcp next to this script)",
    )
    parser.add_argument("--out", type=Path, help="write the Markdown report here (default: stdout)")
    parser.add_argument(
        "--dump-tools",
        type=Path,
        help="also write the tool -> (method, template) map as JSON, for debugging the heuristic",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="do not print the unmatched review lists to stderr"
    )
    args = parser.parse_args(argv)

    if not args.specs.is_dir():
        sys.exit(f"--specs {args.specs} is not a directory (the OpenAPI set is not in the repo)")
    documents = load_documents(args.specs)
    if not documents:
        sys.exit(f"no OpenAPI documents with a 'paths' object found in {args.specs}")
    analyzer = Analyzer(args.src)
    tools = analyzer.collect_tools()
    if not tools:
        sys.exit(f"no register_tool(...) decorated functions found under {args.src}")
    auth_source = args.src / "auth.py"
    auth_endpoints = AUTH_ENDPOINTS
    if not (auth_source.exists() and AUTH_PATH_LITERAL in auth_source.read_text(encoding="utf-8")):
        print(
            f"warning: {AUTH_PATH_LITERAL!r} not found in {auth_source}; auth flow not credited",
            file=sys.stderr,
        )
        auth_endpoints = ()
    results, unmatched = match_all(documents, tools, auth_endpoints)
    report = render(documents, tools, results, unmatched, args.specs)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report + "\n", encoding="utf-8")
    else:
        sys.stdout.write(report + "\n")
    if args.dump_tools:
        args.dump_tools.write_text(
            json.dumps(
                {t.name: sorted(f"{m} {p}" for m, p in t.endpoints) for t in tools}, indent=1
            ),
            encoding="utf-8",
        )
    if not args.quiet:
        err = sys.stderr
        not_exposed = [r for r in results if r.status == STATUS_NOT_EXPOSED and not r.op.not_routed]
        print(f"documents={len(documents)} operations={len(results)} tools={len(tools)}", file=err)
        print(
            f"covered={sum(r.status == STATUS_COVERED for r in results)} "
            f"generic={sum(r.status == STATUS_GENERIC for r in results)} "
            f"not_exposed={sum(r.status == STATUS_NOT_EXPOSED for r in results)}",
            file=err,
        )
        print(
            f"\nUnmatched operations for review ({len(not_exposed)}, routed prefixes only):",
            file=err,
        )
        for r in not_exposed:
            print(f"  {r.op.method:6} {r.op.path}  [{r.reason}]", file=err)
        print(f"\nTool endpoints matching no documented operation ({len(unmatched)}):", file=err)
        for (method, template), names in sorted(unmatched.items(), key=lambda kv: kv[0][1]):
            print(f"  {method:6} {template}  <- {', '.join(names)}", file=err)
    return 0


if __name__ == "__main__":
    sys.exit(main())
