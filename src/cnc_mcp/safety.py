"""Write-safety gating and tool registration.

Every tool in this server is registered through register_tool(), which:
- forces a decision on read_only/destructive/idempotent annotations
- refuses to register write tools unless settings.enable_writes is true
- makes the tool reject argument names it does not declare (see
  ``_forbid_unknown_arguments``), so a misspelt parameter is reported by name
  instead of being silently dropped

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
import logging
from collections.abc import Callable
from dataclasses import dataclass
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


@dataclass
class AppContext:
    """Dependencies handed to every tool module's register() function."""

    settings: Settings
    client: ApiClient


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
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory used instead of @mcp.tool for every tool in this server.

    Write tools (read_only=False) are silently skipped when writes are disabled;
    the function is returned unregistered so module import still succeeds.
    Registered tools reject unknown argument names (see
    ``_forbid_unknown_arguments``).
    """
    if not read_only and not ctx.settings.enable_writes:

        def skip(fn: Callable[..., Any]) -> Callable[..., Any]:
            logger.info("Write tool %s not registered (enable_writes is false)", name)
            return fn

        return skip

    register = mcp.tool(
        name=name,
        title=title,
        annotations={
            "read_only_hint": read_only,
            "destructive_hint": destructive,
            "idempotent_hint": idempotent,
            "open_world_hint": open_world,
        },
    )

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        register(fn)
        _forbid_unknown_arguments(mcp, name)
        return fn

    return decorator


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
