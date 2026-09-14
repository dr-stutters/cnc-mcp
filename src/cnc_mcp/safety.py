"""Write-safety gating and tool registration.

Every tool in this server is registered through register_tool(), which:
- forces a decision on read_only/destructive/idempotent annotations
- refuses to register write tools unless settings.enable_writes is true, and —
  when ``write_areas`` names areas — only the write tools of those areas (an
  area is the tools/ module the tool is defined in)
- never registers a tool named in ``disabled_tools``, read or write
- in global dry-run mode (``dry_run``) keeps the write tools registered but
  swaps their function for a preview: a tool with a ``dry_run`` argument runs
  with it forced true, any other write answers with the arguments it would have
  sent and is not executed (see ``_install_dry_run``)
- makes the tool reject argument names it does not declare (see
  ``_forbid_unknown_arguments``), so a misspelt parameter is reported by name
  instead of being silently dropped
- records every tool — registered or skipped, with the reason — in
  ``AppContext.tools`` so startup validation, the prompts and the permission-check
  tools can reason about the whole tool set; a name registered twice is a bug and
  raises at import

With writes disabled (the default), agents never even see the write tools, so a
misbehaving prompt can't touch production systems or their
configuration. Enable writes per-deployment with *_ENABLE_WRITES=true.

Argument-validation errors keep pydantic's per-field ``input_value=...`` echo
(the agent's own argument, and the best clue to what it got wrong). Only the
two places where pydantic would echo the WHOLE argument dict — a credential
password included — are withheld: the value of an unknown key and the input of
a ``missing`` error (see ``strict_argument_model``).
"""

from __future__ import annotations

import difflib
import functools
import inspect
import json
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, get_args

from mcp.server.mcpserver import MCPServer
from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationError,
    ValidatorFunctionWrapHandler,
    model_validator,
)
from pydantic_core import ErrorDetails, ErrorType, InitErrorDetails, PydanticCustomError

from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings

logger = logging.getLogger(__name__)

# Error types pydantic can re-create from type + ctx (everything else is a
# validator's custom type, re-created from its rendered message instead).
_KNOWN_ERROR_TYPES = frozenset(get_args(ErrorType))

# Argument names whose VALUES are never echoed by the dry-run "not executed" answer
# (matched as substrings of the lower-cased name: ssh_password, snmpv2_read_community,
# api_token, ...). A tool whose free-text arguments may carry secrets the name does not
# betray (a configlet with 'username ... password' lines) names them in register_tool's
# ``redact``: those values are withheld too, summarised by size.
SECRET_ARGUMENT_MARKERS = ("password", "secret", "token", "key", "passphrase", "community")
REDACTED = "***"
# The "not executed" answer stays readable: the argument JSON is cut to fit this.
NOT_EXECUTED_MAX_CHARS = 1500

DRY_RUN_PREVIEW_SUFFIX = (
    "DRY-RUN MODE is active on this server: dry_run is forced to true — the tool only "
    "previews; nothing is committed."
)
DRY_RUN_RECORDED_SUFFIX = (
    "DRY-RUN MODE is active on this server: this tool is NOT executed — it answers with "
    "the arguments it would have sent."
)


@dataclass
class ToolRecord:
    """One register_tool() decision: what the tool is and whether it was registered.

    ``requires`` and ``dry_run_hint`` are the register_tool arguments of the same
    name (kept so startup validation and the tests can check them after the fact);
    ``dry_run_form`` is set in global dry-run mode on a registered write:
    ``"preview"`` (its dry_run argument is forced true) or ``"recorded"`` (not
    executed; the answer echoes the arguments).
    """

    name: str
    area: str
    read_only: bool
    destructive: bool
    registered: bool
    skipped_reason: str | None = None
    requires: tuple[str, ...] = ()
    dry_run_hint: str | None = None
    dry_run_form: str | None = None


@dataclass
class AppContext:
    """Dependencies handed to every tool module's register() function.

    ``tools`` is the registry every register_tool() call writes to — registered
    tools and skipped ones alike, so the whole tool set (and why a tool is absent)
    can be reasoned about after registration.
    """

    settings: Settings
    client: ApiClient
    tools: dict[str, ToolRecord] = field(default_factory=dict)


def tool_area(fn: Callable[..., Any]) -> str:
    """The area a tool belongs to: the tools/ module it is defined in
    (``cnc_mcp.tools.devices`` -> ``devices``)."""
    module = getattr(fn, "__module__", None) or ""
    return module.rsplit(".", 1)[-1]


def skip_reason(settings: Settings, *, name: str, area: str, read_only: bool) -> str | None:
    """Why the tool must not be registered, or None. Decision order: disabled by name,
    writes off, write area not allowed. A ``requires`` sibling is checked by the
    caller afterwards (it needs the registry)."""
    prefix = settings.env_prefix
    if name.lower() in settings.disabled_tool_set:
        return f"disabled by {prefix}DISABLED_TOOLS"
    if read_only:
        return None
    if not settings.enable_writes:
        return "enable_writes is false"
    areas = settings.write_area_set
    if areas and area.lower() not in areas:
        return f"area '{area}' is not in {prefix}WRITE_AREAS ({', '.join(sorted(areas))})"
    return None


def register_tool(
    mcp: MCPServer,
    ctx: AppContext,
    *,
    name: str,
    title: str,
    read_only: bool,
    destructive: bool = False,
    idempotent: bool = False,
    open_world: bool = True,
    dry_run_hint: str | None = None,
    requires: tuple[str, ...] = (),
    redact: tuple[str, ...] = (),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory used instead of @mcp.tool for every tool in this server.

    The decision happens inside the returned decorator, where the function — and
    with it the tool's area (its module) — is known. A tool is not registered when
    it is named in ``disabled_tools``, when it is a write and writes are disabled or
    its area is not in ``write_areas``, or when a tool in ``requires`` (a write
    sibling a playbook cannot run without) is itself not registered. Skipped
    functions are returned unregistered so module import still succeeds; every
    decision is recorded in ``ctx.tools``. A name that already has a record is a
    programming error (two modules defining the same tool) and raises ValueError:
    the SDK would keep the first tool and this module would wrap the second.

    ``requires`` is resolved against the registry at decoration time, so the module
    defining a required tool must come before the requiring one in
    ``tools.ALL_MODULES`` — ``tools.validate_gating`` fails startup when it does not.

    Registered tools reject unknown argument names (``_forbid_unknown_arguments``).
    In global dry-run mode a registered write is wrapped (``_install_dry_run``);
    ``dry_run_hint`` names the preview tool an agent should use instead of a write
    that has no ``dry_run`` argument of its own — a read-only tool or one with a
    ``dry_run`` argument, i.e. something that still works in that mode — and
    ``redact`` names the arguments whose values the recorded answer must not echo
    (free-text bodies that may carry credentials the argument name does not betray).
    """
    settings = ctx.settings

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        area = tool_area(fn)
        if name in ctx.tools:
            raise ValueError(
                f"tool {name} registered twice (areas {ctx.tools[name].area} and {area})"
            )
        record = ToolRecord(
            name=name,
            area=area,
            read_only=read_only,
            destructive=destructive,
            registered=False,
            requires=tuple(requires),
            dry_run_hint=dry_run_hint,
        )
        ctx.tools[name] = record
        reason = skip_reason(settings, name=name, area=area, read_only=read_only)
        if reason is None:
            reason = _missing_requirement(mcp, ctx, requires)
        if reason is not None:
            record.skipped_reason = reason
            logger.info("Tool %s not registered (%s)", name, reason)
            return fn

        mcp.tool(
            name=name,
            title=title,
            annotations={
                "read_only_hint": read_only,
                "destructive_hint": destructive,
                "idempotent_hint": idempotent,
                "open_world_hint": open_world,
            },
        )(fn)
        _forbid_unknown_arguments(mcp, name)
        if not read_only and settings.dry_run:
            form = _install_dry_run(mcp, name, fn, dry_run_hint, settings.env_prefix, redact)
            if form not in DRY_RUN_FORMS:
                record.skipped_reason = form
                return fn
            record.dry_run_form = form
        record.registered = True
        return fn

    return decorator


def is_registered(mcp: MCPServer, ctx: AppContext, name: str) -> bool:
    """Whether ``name`` is a registered tool: the registry's word when it has a
    record, else the tool manager's."""
    record = ctx.tools.get(name)
    if record is not None:
        return record.registered
    try:
        return mcp._tool_manager.get_tool(name) is not None
    except Exception:  # pragma: no cover - SDK internals moved
        return False


def _missing_requirement(mcp: MCPServer, ctx: AppContext, requires: Iterable[str]) -> str | None:
    """``needs <tool> (area <area>)`` for the first required tool that is not
    registered, or None when every one is. A required tool with no record yet (its
    module comes later in ALL_MODULES, or the name is a typo) reads ``area unknown``;
    ``tools.validate_gating`` turns that into a startup failure."""
    for required in requires:
        if is_registered(mcp, ctx, required):
            continue
        record = ctx.tools.get(required)
        area = record.area if record is not None else "unknown"
        return f"needs {required} (area {area})"
    return None


def absent_tool_reasons(ctx: AppContext, names: Iterable[str]) -> dict[str, str]:
    """Why each of ``names`` is missing from the tool list: the registry's skip reason
    (``enable_writes is false``, ``area 'oam' is not in CNC_MCP_WRITE_AREAS (...)``,
    ``disabled by CNC_MCP_DISABLED_TOOLS``, ``needs cnc_create_sr_policy (...)``), or
    ``not a tool of this build`` for a name no module defines. Registered tools are
    left out — including the writes global dry-run mode keeps registered (their
    ``dry_run_form`` says how they answer). For the prompts and the permission-check
    tools, which must explain an absence with the remedy that actually applies."""
    reasons: dict[str, str] = {}
    for name in names:
        record = ctx.tools.get(name)
        if record is None:
            reasons[name] = "not a tool of this build"
        elif not record.registered:
            reasons[name] = record.skipped_reason or "not registered"
    return reasons


def safety_mode_lines(settings: Settings) -> list[str]:
    """The exact safety mode this server runs in, as paragraphs for the server
    instructions and the prompts: read-only / writes for all areas / writes for
    listed areas only, plus the dry-run and disabled-tools qualifiers when they
    apply. Lives here (not in server.py) so the prompts can import it without a
    circular import."""
    prefix = settings.env_prefix
    lines: list[str] = []
    areas = sorted(settings.write_area_set)
    if not settings.enable_writes:
        lines.append(
            "This server is READ-ONLY: write tools are not registered. To enable "
            f"them, set the {prefix}ENABLE_WRITES=true environment variable and restart."
        )
    elif areas:
        lines.append(
            f"Write tools are ENABLED only for the areas {', '.join(areas)} "
            f"({prefix}WRITE_AREAS); the write tools of every other area are not registered. "
            "The registered writes modify the live platform: confirm intent before creating, "
            "changing, or deleting anything."
        )
    else:
        lines.append(
            "Write tools are ENABLED for all areas and modify the live platform. Confirm "
            "intent before creating, changing, or deleting anything."
        )
    if settings.enable_writes and settings.dry_run:
        lines.append(
            f"DRY-RUN MODE is active ({prefix}DRY_RUN=true): the write tools are registered "
            "but nothing changes on the platform. A write tool that takes dry_run runs with "
            "it forced to true and answers the preview (the device CLI NSO would push, the "
            "path the PCE would compute); every other write tool is NOT executed and answers "
            "'NOT EXECUTED' with the arguments it would have sent. Each write tool's "
            "description ends with which of the two applies to it. Tell the operator that "
            "writes are previews until the variable is unset."
        )
    disabled = sorted(settings.disabled_tool_set)
    if disabled:
        noun = "tool is" if len(disabled) == 1 else "tools are"
        lines.append(
            f"{len(disabled)} {noun} disabled by configuration ({prefix}DISABLED_TOOLS) and "
            f"not registered: {', '.join(disabled)}. Do not try to call them; if a task needs "
            "one, say that it is disabled by policy on this server."
        )
    return lines


# --- global dry-run mode ---------------------------------------------------------

DRY_RUN_FORMS = ("preview", "recorded")


def _withheld(value: Any) -> str:
    """The stand-in for a value named in ``redact``: its size, never its content."""
    size = len(value) if isinstance(value, str) else len(json.dumps(value, default=_json_value))
    return f"<withheld: {size} chars>"


def redact_arguments(arguments: dict[str, Any], redact: Iterable[str] = ()) -> dict[str, Any]:
    """The arguments with every secret-looking VALUE replaced by ``***`` (names
    containing password, secret, token, key, passphrase or community) and every
    value whose name is in ``redact`` replaced by its size (``<withheld: N chars>``).
    An absent value (None) is reported absent either way."""
    withheld = {name.lower() for name in redact}
    out: dict[str, Any] = {}
    for key, value in arguments.items():
        lowered = key.lower()
        if value is None:
            out[key] = None
        elif any(m in lowered for m in SECRET_ARGUMENT_MARKERS):
            out[key] = REDACTED
        elif lowered in withheld:
            out[key] = _withheld(value)
        else:
            out[key] = value
    return out


def _json_value(value: Any) -> Any:
    """A JSON-friendly stand-in for a non-JSON argument value: an enum's value, else str."""
    inner = getattr(value, "value", None)
    return inner if isinstance(inner, str | int | float | bool) else str(value)


def not_executed_text(
    name: str,
    arguments: dict[str, Any],
    hint: str | None,
    prefix: str,
    redact: Iterable[str] = (),
) -> str:
    """The answer of a write that global dry-run mode did not execute.

    Names the tool, echoes the (redacted) arguments as compact JSON — cut with a
    note saying exactly how many characters were dropped when the answer would
    exceed :data:`NOT_EXECUTED_MAX_CHARS` — and says how to preview (``hint``) and
    how to execute (unset the variable).
    """
    head = (
        f"NOT EXECUTED — DRY-RUN MODE ({prefix}DRY_RUN=true): {name} has no preview form, "
        "so the call was recorded, not sent. It would have run with: "
    )
    tail = (
        "."
        + (f" Preview instead: {hint.rstrip('.')}." if hint else "")
        + (f" Unset {prefix}DRY_RUN to execute writes.")
    )
    echo = json.dumps(
        redact_arguments(arguments, redact), default=_json_value, separators=(", ", ": ")
    )
    room = NOT_EXECUTED_MAX_CHARS - len(head) - len(tail)
    if len(echo) > room:
        # Size the note for the largest figure it could carry (the whole echo) so the
        # kept prefix is fixed before the real figure — hidden = total - kept — is known.
        note_room = len(_truncation_note(len(echo)))
        keep = max(room - note_room, 0)
        echo = echo[:keep] + _truncation_note(len(echo) - keep)
    return f"{head}{echo}{tail}"


def _truncation_note(hidden: int) -> str:
    return f" [... {hidden} more characters of arguments not shown]"


def dry_run_preview_text(text: str, prefix: str) -> str:
    """Prefix a preview's answer with the dry-run banner, unless prefixing would
    break the answer: a JSON answer (starts with ``{`` or ``[``; the tool's
    description carries the mode instead) or an ``Error:`` answer (its prefix is
    what tells callers — the composites' ``Composer.call`` included — that the
    preview failed)."""
    if text.startswith(("{", "[", "Error:")):
        return text
    return (
        f"DRY-RUN MODE ({prefix}DRY_RUN=true): nothing was committed — the answer below is "
        f"the preview.\n\n{text}"
    )


def _accepts_dry_run(fn: Callable[..., Any]) -> bool:
    try:
        return "dry_run" in inspect.signature(fn).parameters
    except (TypeError, ValueError):  # pragma: no cover - builtins, C callables
        return False


def _install_dry_run(
    mcp: MCPServer,
    name: str,
    fn: Callable[..., Any],
    hint: str | None,
    prefix: str,
    redact: tuple[str, ...] = (),
) -> str:
    """Swap the just-registered write tool's function for its dry-run form.

    The registered Tool keeps its input schema (built from the original signature
    at registration; the wrapper is installed after) and its validation; the SDK
    calls ``tool.fn(**validated_arguments)``, so the wrapper receives the same
    keyword arguments the original would. The wrapper is ``functools.wraps``-ed
    (``__wrapped__`` is the original) and async.

    - a function with a ``dry_run`` parameter runs with ``dry_run=True`` whatever
      the caller passed, and its answer is banner-prefixed (``dry_run_preview_text``)
    - any other function is NOT called: the answer records the call
      (``not_executed_text``, the ``redact``-ed arguments withheld)

    The tool's description gains a final paragraph saying which, so agents know
    before calling. Returns the form installed (``"preview"`` or ``"recorded"``,
    :data:`DRY_RUN_FORMS`). If the SDK's tool record cannot be reached
    (``_tool_manager.get_tool``; verified against mcp 2.1.x) the write is REMOVED
    from the server — silently running a write in dry-run mode would be a safety
    failure — and the skip reason is returned instead.
    """
    try:
        tool = mcp._tool_manager.get_tool(name)
        if tool is None:
            raise LookupError("tool not found in the tool manager")
        previews = _accepts_dry_run(fn)
        if previews:

            @functools.wraps(fn)
            async def preview(**kwargs: Any) -> Any:
                kwargs["dry_run"] = True
                result = fn(**kwargs)
                if inspect.isawaitable(result):
                    result = await result
                return dry_run_preview_text(result, prefix) if isinstance(result, str) else result

            wrapper: Callable[..., Any] = preview
        else:

            @functools.wraps(fn)
            async def recorded(**kwargs: Any) -> str:
                return not_executed_text(name, kwargs, hint, prefix, redact)

            wrapper = recorded

        suffix = DRY_RUN_PREVIEW_SUFFIX if previews else DRY_RUN_RECORDED_SUFFIX
        tool.fn = wrapper
        tool.is_async = True
        tool.description = f"{(tool.description or '').rstrip()}\n\n{suffix}"
        return "preview" if previews else "recorded"
    except Exception as e:
        reason = f"dry-run wrapper could not be installed ({e}); removed rather than left live"
        logger.warning("Write tool %s not registered: %s", name, reason)
        _remove_tool(mcp, name)
        return reason


def _remove_tool(mcp: MCPServer, name: str) -> None:
    """Unregister ``name`` through the public API, falling back to the manager's dict."""
    try:
        mcp.remove_tool(name)
        return
    except Exception:
        pass
    try:
        mcp._tool_manager._tools.pop(name, None)
    except Exception:  # pragma: no cover - SDK internals moved
        logger.warning("Could not remove tool %s from the tool manager", name)


def describe_unknown_arguments(unknown: list[str], accepted: list[str]) -> str:
    """Name each unknown argument, with the closest accepted name as a hint.

    ``unknown argument 'host_names' (did you mean 'host_name'?); accepted:
    host_name, response_format, uuid``
    """
    parts = []
    for key in unknown:
        match = difflib.get_close_matches(key, accepted, n=1, cutoff=0.6)
        hint = f" (did you mean '{match[0]}'?)" if match else ""
        parts.append(f"'{key}'{hint}")
    noun = "argument" if len(parts) == 1 else "arguments"
    return f"unknown {noun} {', '.join(parts)}; accepted: {', '.join(accepted)}"


def _is_unknown_argument(err: ErrorDetails) -> bool:
    """An ``extra="forbid"`` rejection of a top-level argument key."""
    return err["type"] == "extra_forbidden" and len(err["loc"]) == 1


def _echoes_whole_input(err: ErrorDetails) -> bool:
    """Pydantic's ``input`` for this error is the entire argument dict.

    ``missing`` reports the dict the field was missing from; a model-level
    error (empty loc) reports the model's input.
    """
    return err["type"] == "missing" or not err["loc"]


def _line_error(err: ErrorDetails) -> InitErrorDetails:
    """Turn an ``errors()`` entry back into a line error ``from_exception_data`` takes.

    A known error type is re-created from type + ctx and renders exactly as
    pydantic rendered it (documentation URL included); a validator's custom type
    keeps its rendered message verbatim. The input is withheld where it would be
    the whole argument dict.
    """
    kind = err["type"]
    line = InitErrorDetails(
        type=kind
        if kind in _KNOWN_ERROR_TYPES
        else PydanticCustomError(kind, err["msg"], err.get("ctx")),
        loc=err["loc"],
        input=None if _echoes_whole_input(err) else err["input"],
    )
    if kind in _KNOWN_ERROR_TYPES and "ctx" in err:
        line["ctx"] = err["ctx"]
    return line


def strict_argument_model(arg_model: type[BaseModel]) -> type[BaseModel]:
    """Subclass a tool's pydantic argument model so it rejects undeclared keys.

    The subclass keeps the parent's name (so the published schema title is
    unchanged) and its fields, and adds:

    - ``extra="forbid"``, so pydantic refuses undeclared keys and the JSON
      schema publishes ``additionalProperties: false``;
    - a wrap-validator that rewrites pydantic's per-key ``extra_forbidden``
      errors into one ``unknown_argument`` error naming every unknown key with
      a did-you-mean hint and the accepted names (``describe_unknown_arguments``).
      The SDK reports the ValidationError as a ToolError the agent can read.

    Field-level errors are left exactly as pydantic renders them, ``input_value``
    echo included (a wrong ``page_size`` shows ``input_value=99``). Only the two
    places pydantic would echo the WHOLE argument dict — credential passwords
    and all — are withheld: the values of unknown keys (dropped with the
    per-key errors) and the input of ``missing``/model-level errors
    (``_echoes_whole_input``), which render as ``input_value=None``.

    Accepted names are the wire names (a field's alias when it has one: the
    SDK aliases parameters such as ``schema`` that shadow BaseModel methods).
    """
    accepted = sorted(
        field.alias or field_name for field_name, field in arg_model.model_fields.items()
    )

    def report_unknown_arguments(
        cls: type[BaseModel], data: Any, handler: ValidatorFunctionWrapHandler
    ) -> Any:
        try:
            return handler(data)
        except ValidationError as e:
            errors = e.errors(include_url=False)
            unknown = [str(err["loc"][0]) for err in errors if _is_unknown_argument(err)]
            if not unknown and not any(_echoes_whole_input(err) for err in errors):
                raise  # per-field errors only: pydantic's own report, untouched
            rebuilt: list[InitErrorDetails] = []
            if unknown:
                rebuilt.append(
                    InitErrorDetails(
                        type=PydanticCustomError(
                            "unknown_argument", describe_unknown_arguments(unknown, accepted)
                        ),
                        loc=(),
                        input=None,
                    )
                )
            rebuilt.extend(_line_error(err) for err in errors if not _is_unknown_argument(err))
            raise ValidationError.from_exception_data(e.title, rebuilt) from None

    return type(
        arg_model.__name__,
        (arg_model,),
        {
            "__module__": arg_model.__module__,
            "__qualname__": arg_model.__qualname__,
            "model_config": ConfigDict(extra="forbid"),
            "report_unknown_arguments": model_validator(mode="wrap")(
                classmethod(report_unknown_arguments)
            ),
        },
    )


def _forbid_unknown_arguments(mcp: MCPServer, name: str) -> None:
    """Make the just-registered tool reject argument names it does not declare.

    The SDK builds each tool's argument model from the function signature with
    pydantic's default ``extra="ignore"``, so a misspelt key was dropped without
    a word and the tool answered as if nothing had been passed
    (``cnc_check_device_nso_state {"host_names": "PE1,PE2"}`` -> "Pass exactly
    one of uuid or host_name"; agent scenario 2026-09-14). This swaps in
    ``strict_argument_model`` and publishes ``additionalProperties: false`` on
    the tool's input schema so clients see the rule.

    It reaches into SDK internals (``_tool_manager``, ``Tool.fn_metadata``,
    ``Tool.parameters``; verified against mcp 2.1.x). If they are not where
    expected the registration stands and the tool keeps the SDK's default
    behaviour — logged, never fatal.
    """
    try:
        tool = mcp._tool_manager.get_tool(name)
        if tool is None:
            raise LookupError("tool not found in the tool manager")
        strict = strict_argument_model(tool.fn_metadata.arg_model)
        tool.fn_metadata.arg_model = strict
        tool.parameters = {**tool.parameters, "additionalProperties": False}
    except Exception as e:
        logger.warning(
            "Tool %s keeps the SDK's default argument handling (unknown keys ignored): %s",
            name,
            e,
        )
