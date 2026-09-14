"""Grouping service reads — device / port groups, their hierarchies, members and
the rule vocabulary that classifies members into groups.

What grouping is. Crosswork's grouping service (``/crosswork/grouping/v1/
grouping``, plain JSON, Bearer) organises devices and ports into **groups**:
a tree per *classifier*. The device classifiers are ``DeviceAccess`` (the
RBAC device-access groups — root ``ALL-ACCESS``), ``LocationDevices`` (root
``Location`` > ``All Locations`` > ``Unassigned Devices`` until locations are
assigned) and ``TopologyTypeDevices`` (root ``Topology Type`` > ``AS`` >
``<asn>`` > ``IGP Domain`` > ``<id>``, derived from the topology); the port
classifiers are ``PortType`` and ``UserDefinedPorts``. All five are verified
live (2026-09-14). A group is ``StaticSystem`` (system-managed), ``Static``
(members added by hand) or ``Dynamic`` (members selected by a **rule** — a set
of ``<attribute> <operator> <value>`` conditions over the device / port
attributes the ``rule/conditions`` endpoints enumerate). Device groups are
what the alarm suppression policies (:mod:`cnc_mcp.tools.fault`), the PM
monitoring policies (``deviceGroups`` uuid) and the UI's group views scope on.

Only reads are exposed. The create / update / delete group and rule bodies
(``POST group``, ``POST rule``, ``PUT group/<uuid>``, ``member/move|copy``,
port add/remove) are unverified on this build, so nothing here writes.

Wire facts (verified live on Crosswork 7.2, 2026-09-13 and 2026-09-14, base
:data:`GROUPING`):

- ``GET device/rule/conditions`` -> ``{"conditions": [{"attributeName":
  "hostname" | "node_ip" | "description" | "product_type" | "software_type"
  | ..., "type": "STRING", "operators": [{"operatorName": "SO_Matches" |
  "SO_NotMatches" | "SO_Contains" | "SO_NotContains" | "SO_StartWith" |
  "SO_EndWith" | "SO_Equals" | "SO_NotEquals" | "SO_InRange"}]}]}``;
  ``GET ports/rule/conditions`` answers the same shape with the port
  attributes.
- ``GET group/root/<classifiers>/uuid`` -> a JSON **list of root-group
  uuids**, NOT in the order the classifiers were given (the lab answered
  Location, ALL-ACCESS, Topology Type for ``DeviceAccess,LocationDevices,
  TopologyTypeDevices``) — expand them with the hierarchy call to learn which
  is which. ``DeviceAccess,LocationDevices,TopologyTypeDevices`` -> 3 uuids,
  ``PortType,UserDefinedPorts`` -> 2 uuids on the lab. An unknown classifier
  (e.g. the guesses ``DeviceGroup,Device,Devices``) answers ``[]``, not an
  error.
- ``GET groups/<uuids>?brief=<bool>&direct=<bool>`` -> a list of ``GroupDTO``
  trees ``[{uuid, name, children[]?, childrenCount?, operations?}]``. The
  **brief** view carries ONLY ``uuid``, ``name``, ``children``,
  ``childrenCount`` and ``operations`` — no ``classifier``; the **full** view
  (``brief=false``) adds ``discoveryType``, ``nodeType`` and ``classifier``.
  Neither view carried ``description``, ``parentUuid`` or ``parentName`` on
  the lab (those come from ``group/<uuid>/details``). ``childrenCount`` in
  this call is the number of DEVICES that are direct members of the group,
  not its sub-groups: the lab's three device groups that hold members
  directly (the leaves Unassigned Devices and IGP Domain 0, and the root
  ALL-ACCESS, which has no sub-groups) each showed 5 = the whole inventory,
  while ``All Locations`` (one sub-group, no direct members) showed 0. It
  is absent on the ``Location`` and ``Topology Type`` roots (and on nothing
  else seen) — present on the ``ALL-ACCESS`` root, so "root" alone does not
  predict it. ``GET group/<uuids>`` is the deprecated spelling.
- ``GET group/<uuid>/details`` -> ``{"status": "Success", "group": {uuid,
  name, discoveryType, nodeType, classifier, parentUuid?, parentName?,
  childrenCount?, operations{...}}}``. Here ``childrenCount`` is NOT the
  member count: it read 0 on ``Unassigned Devices`` (5 members) and was
  absent on the root ``ALL-ACCESS`` (5 members) — count members with the
  device listing instead.
- ``GET device/<uuid>?start=<i>&end=<j>`` -> ``{"status": "Success",
  "devices": [{"uuid", "attributes": {"hostname", "node_ip", "product_type",
  "product_family", "product_series", "software_type", "software_version",
  "description", "contact", "location", "reachability", "discoveryType",
  "last_update" (epoch s), "delete"}}], "total": N}``. ``start``/``end`` is a
  0-based index window with ``end`` EXCLUSIVE (``0-2`` answered indexes 0 and
  1), and ``total`` is the member count of the WHOLE group (5 on every window
  of a 5-member group), so it is trusted for paging. The device uuids are the
  inventory node uuids. A group whose members live in its sub-groups (``All
  Locations``) answers ``devices: [], total: 0``.
- ``GET groups/<uuids>`` defaults on the platform to ``brief=false&direct=
  true``; :func:`cnc_get_group_hierarchy` defaults to the opposite
  (``brief=true&direct=false``, the whole subtree in the small view) and
  always sends both flags explicitly.
- Every answer is checked before it is rendered: a ``status: Error``
  document, an empty body or an unrecognised shape is an ``Error:`` text —
  only a genuine empty list (``[]``, ``{"conditions": []}``, ``{"groups":
  []}``, ``{"devices": []}``) is a non-error "nothing here" result.
"""

from __future__ import annotations

import json
from typing import Annotated, Any
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.errors import PlatformError, format_error
from cnc_mcp.formatting import (
    ResponseFormat,
    epoch_iso,
    finalize,
    pagination_envelope,
    to_json,
)
from cnc_mcp.safety import AppContext, register_tool

GROUPING = "/crosswork/grouping/v1/grouping"
DEVICE_CONDITIONS_PATH = f"{GROUPING}/device/rule/conditions"
PORT_CONDITIONS_PATH = f"{GROUPING}/ports/rule/conditions"
ROOT_GROUPS_PATH = f"{GROUPING}/group/root"  # + /<classifiers>/uuid
HIERARCHIES_PATH = f"{GROUPING}/groups"  # + /<uuids>
GROUP_PATH = f"{GROUPING}/group"  # + /<uuid>/details
GROUP_DEVICES_PATH = f"{GROUPING}/device"  # + /<uuid>

CONDITION_KINDS: dict[str, str] = {"device": DEVICE_CONDITIONS_PATH, "port": PORT_CONDITIONS_PATH}
# All five classifiers of the 7.2 OpenAPI enum are verified live (2026-09-14): the device
# ones answer 3 root uuids on the lab, the port ones 2.
DEVICE_CLASSIFIERS = ("DeviceAccess", "LocationDevices", "TopologyTypeDevices")
PORT_CLASSIFIERS = ("PortType", "UserDefinedPorts")
VERIFIED_CLASSIFIERS = DEVICE_CLASSIFIERS + PORT_CLASSIFIERS
# The device classifiers are the entry point agents want by default (device groups are
# what alarm suppression and PM policies scope on); the port ones are the alternative.
DEFAULT_CLASSIFIERS = ",".join(DEVICE_CLASSIFIERS)
PORT_CLASSIFIERS_CSV = ",".join(PORT_CLASSIFIERS)
RESULT_ERROR = "Error"
RESULT_PARTIAL = "Partial"
# The OpenAPI document's own example window for GET device/<uuid> is ?start=0&end=30;
# the default here is wider so a small group lists in one call. ``end`` is exclusive
# (verified live 2026-09-14).
DEFAULT_DEVICE_START = 0
DEFAULT_DEVICE_END = 100
MAX_DEVICE_END = 10000

_RESPONSE_FORMAT_DESC = "'markdown' for human-readable output, 'json' for the raw platform data."
_GROUP_UUID_DESC = (
    "Group uuid as returned by cnc_list_root_groups / cnc_get_group_hierarchy "
    "(e.g. 'efc42cda-6ce5-4a47-ad96-d1e08a16b228')."
)


# --- pure helpers ----------------------------------------------------------------


def condition_kind(kind: str) -> str:
    """``'device'`` | ``'port'`` (case-insensitive, ``'ports'`` accepted), else PlatformError."""
    text = (kind or "").strip().lower()
    if text == "ports":
        text = "port"
    if text not in CONDITION_KINDS:
        raise PlatformError(
            f"Unknown rule-condition kind '{kind}'. Use one of: {', '.join(CONDITION_KINDS)}."
        )
    return text


def split_csv(value: str, what: str) -> list[str]:
    """Comma-separated tokens, stripped, blanks dropped; PlatformError when none remain."""
    tokens = [t.strip() for t in (value or "").split(",")]
    tokens = [t for t in tokens if t]
    if not tokens:
        raise PlatformError(f"{what} must name at least one value (comma-separated).")
    return tokens


def csv_path_segment(tokens: list[str]) -> str:
    """``a,b,c`` with each token percent-encoded (the comma stays the list separator)."""
    return ",".join(quote(t, safe="") for t in tokens)


def root_groups_url(classifiers: list[str]) -> str:
    """``.../group/root/<classifiers>/uuid``."""
    return f"{ROOT_GROUPS_PATH}/{csv_path_segment(classifiers)}/uuid"


def hierarchies_url(uuids: list[str]) -> str:
    """``.../groups/<uuids>`` (the non-deprecated spelling)."""
    return f"{HIERARCHIES_PATH}/{csv_path_segment(uuids)}"


def group_details_url(uuid: str) -> str:
    return f"{GROUP_PATH}/{quote(uuid, safe='')}/details"


def group_devices_url(uuid: str) -> str:
    return f"{GROUP_DEVICES_PATH}/{quote(uuid, safe='')}"


def _dicts(items: Any) -> list[dict[str, Any]]:
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def shape_error(what: str, expected: str, data: Any) -> PlatformError:
    """A PlatformError for an answer that is neither an error document nor the expected shape.

    An empty body (``None`` from ``request_json``) is named as such — it is a
    distinct failure from a wrong-shaped document and must never be read as
    "the platform answered an empty list".
    """
    if data is None:
        return PlatformError(
            f"{what}: the platform answered an empty body where {expected} was expected."
        )
    return PlatformError(f"{what}: expected {expected}, got: {str(data)[:200]}")


def check_result(data: Any, what: str) -> dict[str, Any]:
    """Validate a ``ResultDTO`` answer (``status`` Success | Partial | Error).

    ``Error`` is raised with the document's ``error`` text; ``Partial`` is
    returned (the caller reports it). A non-dict body is a shape error (an
    empty body is named as such).
    """
    if not isinstance(data, dict):
        raise shape_error(what, "a JSON object", data)
    status = str(data.get("status") or "")
    if status == RESULT_ERROR:
        reason = data.get("error") or data.get("details") or "no reason given"
        raise PlatformError(f"{what} failed: {str(reason)[:300]}")
    return data


def as_count(value: Any) -> int | None:
    """A ``total`` as an int: ints and numeric strings (``"7"``, the idiom the
    sibling collection service uses for every count) are accepted; bools,
    blanks, text, floats and negatives are ``None`` so no count is invented.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def conditions_of(data: Any) -> list[dict[str, Any]]:
    """The ``conditions[]`` of a rule-conditions answer (a bare list is tolerated).

    A dict answer is checked like a ``ResultDTO`` first, so ``{"status":
    "Error", "error": ...}`` raises with the platform's text instead of
    reading as "no conditions". ``{"conditions": null}`` is the Go idiom for
    an empty list and is tolerated; a dict without a ``conditions`` list, an
    empty body or any other shape is a shape error.
    """
    what = "Rule-conditions read"
    if isinstance(data, list):
        return _dicts(data)
    if isinstance(data, dict):
        check_result(data, what)
        if "conditions" in data and data["conditions"] is None:
            return []
        if isinstance(data.get("conditions"), list):
            return _dicts(data["conditions"])
    raise shape_error(what, '{"conditions": [...]}', data)


def operator_names(condition: dict[str, Any]) -> list[str]:
    """``operators[].operatorName`` (a bare string entry is taken as the name)."""
    names: list[str] = []
    for op in condition.get("operators") or []:
        if isinstance(op, dict):
            name = op.get("operatorName") or op.get("name")
            if name:
                names.append(str(name))
        elif isinstance(op, str) and op:
            names.append(op)
    return names


def condition_line(condition: dict[str, Any]) -> str:
    """``- <attributeName> (<type>): op1, op2, ...``."""
    ops = operator_names(condition)
    return (
        f"- {condition.get('attributeName') or '?'} ({condition.get('type') or '?'}): "
        f"{', '.join(ops) if ops else '(no operators listed)'}"
    )


def root_uuids(data: Any) -> list[str]:
    """The uuid list of ``group/root/<classifiers>/uuid``.

    Verified live as a JSON array; the OpenAPI document types the body as a
    *string* holding a JSON array, so that spelling is decoded too. A dict is
    checked like a ``ResultDTO`` first, so ``{"status": "Error", "error":
    ...}`` raises with the platform's text; an empty body is named as such;
    anything else is a shape error. Only ``[]`` is a genuine empty answer.
    """
    what = "Root-group read"
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError as e:
            raise PlatformError(
                f"{what}: expected a JSON list of uuids, got text: {data[:200]}"
            ) from e
    if isinstance(data, dict):
        check_result(data, what)
    if not isinstance(data, list):
        raise shape_error(what, "a JSON list of uuids", data)
    return [str(u) for u in data if u not in (None, "")]


def hierarchy_entries(data: Any) -> list[dict[str, Any]]:
    """The group entries of a hierarchies answer: a list, one group object, or ``{groups: []}``.

    A dict answer is checked like a ``ResultDTO`` first, so the ``{"status":
    "Error", "error": "Group not found"}`` envelope the rest of this service
    uses raises with the platform's text instead of reading as "no groups".
    An empty body or a dict that is neither a ``groups`` envelope nor a group
    object (``uuid`` / ``name``) is a shape error; only ``[]`` and
    ``{"groups": []}`` are genuine empty answers.
    """
    what = "Group hierarchy read"
    if isinstance(data, list):
        return _dicts(data)
    if isinstance(data, dict):
        check_result(data, what)
        if isinstance(data.get("groups"), list):
            return _dicts(data["groups"])
        if data.get("uuid") or data.get("name"):
            return [data]
    raise shape_error(what, "a JSON list of groups", data)


def _compact(value: Any) -> str:
    if isinstance(value, dict | list):
        return json.dumps(value, separators=(",", ":"), default=str)
    if value is None:
        return "-"
    return str(value)


def _leftover(data: dict[str, Any], rendered: tuple[str, ...]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k not in rendered}


_GROUP_KEYS = (
    "uuid",
    "name",
    "classifier",
    "description",
    "discoveryType",
    "nodeType",
    "referenceUuid",
    "parentUuid",
    "parentName",
    "childrenCount",
    "children",
    "operations",
)


def group_line(group: dict[str, Any]) -> str:
    """``**name** (uuid)`` plus the GroupDTO leaves that are present.

    ``classifier`` is rendered only when the answer carries it — the brief
    hierarchy view does not (verified live), so the line never shows a
    meaningless ``classifier=-``. ``childrenCount`` keeps its wire name; the
    hierarchy footer says what it counts (member devices, not sub-groups).
    """
    text = f"**{group.get('name') or '?'}** ({group.get('uuid') or '?'})"
    if group.get("classifier"):
        text += f" classifier={group['classifier']}"
    for key in ("discoveryType", "nodeType"):
        if group.get(key):
            text += f" {key}={group[key]}"
    if group.get("childrenCount") is not None:
        text += f" childrenCount={group['childrenCount']}"
    if group.get("parentName") or group.get("parentUuid"):
        text += f" parent={group.get('parentName') or '?'}"
        if group.get("parentUuid"):
            text += f" ({group['parentUuid']})"
    if group.get("description"):
        text += f" — {group['description']}"
    other = _leftover(group, _GROUP_KEYS)
    if other:
        text += f" other={_compact(other)}"
    return text


def group_tree_lines(groups: list[dict[str, Any]], depth: int = 0) -> list[str]:
    """One indented ``- `` line per group, children nested two spaces deeper."""
    lines: list[str] = []
    for group in groups:
        lines.append(f"{'  ' * depth}- {group_line(group)}")
        children = _dicts(group.get("children"))
        if children:
            lines.extend(group_tree_lines(children, depth + 1))
    return lines


def count_groups(groups: list[dict[str, Any]]) -> int:
    """Groups in the forest, children included."""
    return sum(1 + count_groups(_dicts(g.get("children"))) for g in groups)


def has_children(groups: list[dict[str, Any]]) -> bool:
    return any(_dicts(g.get("children")) for g in groups)


def group_details_markdown(data: dict[str, Any]) -> str:
    group = data.get("group") if isinstance(data.get("group"), dict) else {}
    lines = [f"# Group {group.get('name') or '?'} ({group.get('uuid') or '?'})", ""]
    if not group:
        lines.append("The platform returned no group object in its answer.")
    else:
        lines.append(f"- {group_line(group)}")
        if isinstance(group.get("operations"), dict):
            lines.append(f"- operations: {_compact(group['operations'])}")
        children = _dicts(group.get("children"))
        if children:
            lines.extend(["", f"Children ({len(children)}):"])
            lines.extend(group_tree_lines(children))
    if str(data.get("status") or "") == RESULT_PARTIAL:
        lines.append(f"- status: Partial — {data.get('error') or 'no detail given'}")
    return "\n".join(lines)


_DEVICE_ATTRIBUTE_KEYS = (
    "hostname",
    "node_ip",
    "product_type",
    "product_family",
    "product_series",
    "software_type",
    "software_version",
    "reachability",
    "discoveryType",
    "description",
    "location",
    "contact",
    "last_update",
    "delete",
)


def device_line(device: dict[str, Any]) -> str:
    """``- **hostname** (uuid) ip=... type=... sw=... reachability=... updated=...``."""
    attrs = device.get("attributes") if isinstance(device.get("attributes"), dict) else {}
    text = (
        f"- **{attrs.get('hostname') or '(no hostname)'}** ({device.get('uuid') or '?'}) "
        f"ip={attrs.get('node_ip') or '-'} type={attrs.get('product_type') or '-'} "
        f"sw={attrs.get('software_type') or '-'}"
    )
    if attrs.get("software_version"):
        text += f" {attrs['software_version']}"
    text += f" reachability={attrs.get('reachability') or '-'}"
    for key in ("product_family", "discoveryType"):
        if attrs.get(key):
            text += f" {key}={attrs[key]}"
    for key in ("description", "location"):
        if attrs.get(key):
            text += f" {key}={attrs[key]}"
    if attrs.get("last_update"):
        text += f" updated={epoch_iso(attrs.get('last_update'))}"
    other = _leftover(attrs, _DEVICE_ATTRIBUTE_KEYS)
    if other:
        text += f" other={_compact(other)}"
    return text


def device_page(
    devices: list[dict[str, Any]], total: int | None, start: int, end: int
) -> dict[str, Any]:
    """The pagination envelope of one ``device/<uuid>`` window.

    ``total`` is the member count of the whole group and ``end`` is exclusive
    (both verified live 2026-09-14: a 5-member group answered ``total: 5`` on
    every window and ``0-2`` returned indexes 0 and 1), so ``has_more`` is
    ``start + count < total`` whenever the platform reports a total, and
    falls back to "the window came back full" only when it does not.
    ``window_full`` (``count >= end - start``) is reported alongside;
    ``next_offset`` is ``start + count`` — the continuation that skips
    nothing.
    """
    envelope = pagination_envelope(devices, total=total, offset=start, limit=end - start)
    envelope["window_full"] = len(devices) >= end - start
    return envelope


# --- registration ----------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_group_rule_conditions",
        title="List Group Rule Conditions",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_group_rule_conditions(
        kind: Annotated[
            str,
            Field(
                description=(
                    "Which rule vocabulary: 'device' (the device attributes a dynamic device "
                    "group can match on) or 'port' (the port attributes). E.g. 'device'."
                ),
                max_length=16,
            ),
        ] = "device",
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the attributes and operators a dynamic group rule can use — the
        vocabulary for "hostname SO_StartWith PE" style conditions.

        Read-only. ``GET /crosswork/grouping/v1/grouping/device/rule/conditions``
        (kind='device') or ``.../ports/rule/conditions`` (kind='port'), both
        verified live. Use it to explain an existing dynamic group's rule or to
        check which attribute / operator names exist before someone writes a
        rule in the UI (rule writes are not offered here). Every attribute seen
        live is ``STRING`` typed with the operators SO_Matches, SO_NotMatches,
        SO_Contains, SO_NotContains, SO_StartWith, SO_EndWith, SO_Equals,
        SO_NotEquals, SO_InRange. The kind is checked before anything is sent.

        Args:
            kind: 'device' | 'port' (case-insensitive).
            response_format: markdown (one line per attribute:
                ``<attributeName> (<type>): op1, op2, ...``) or json.

        Returns:
            str: Markdown, or JSON {"kind": str, "count": int, "items":
            [{"attributeName", "type", "operators": [{"operatorName"}]}]}.
            "No <kind> rule conditions are reported." when the list is empty
            (``{"conditions": []}`` or ``null`` — not an error). "Error:
            Unknown rule-condition kind ..." for any other kind (nothing
            sent); "Error: Rule-conditions read failed: ..." when the platform
            answers a ``status: Error`` document; "Error: Rule-conditions
            read: ..." on an empty body or an unrecognised shape; "Error: ..."
            on an HTTP failure.
        """
        try:
            wanted = condition_kind(kind)
            data = await client.request_json("GET", CONDITION_KINDS[wanted])
            conditions = conditions_of(data)
            if response_format is ResponseFormat.JSON:
                payload = {"kind": wanted, "count": len(conditions), "items": conditions}
                return finalize(to_json(payload), settings)
            if not conditions:
                return finalize(f"No {wanted} rule conditions are reported.", settings)
            lines = [f"# {wanted.capitalize()} group rule conditions ({len(conditions)})", ""]
            lines.extend(condition_line(c) for c in conditions)
            lines.extend(
                [
                    "",
                    "A dynamic group rule is a set of <attribute> <operator> <value> conditions "
                    "over these attributes; rule writes are not offered by this server.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_root_groups",
        title="List Root Groups",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_root_groups(
        classifiers: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated classifier names whose root groups to list. Device "
                    "classifiers (the default): 'DeviceAccess,LocationDevices,"
                    "TopologyTypeDevices'; port classifiers (the alternative): "
                    "'PortType,UserDefinedPorts'. All five verified live. E.g. 'LocationDevices'."
                ),
                min_length=1,
                max_length=500,
            ),
        ] = DEFAULT_CLASSIFIERS,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the root group uuids of one or more classifiers — the entry point
        into the group trees (feed them to cnc_get_group_hierarchy).

        Read-only. ``GET /crosswork/grouping/v1/grouping/group/root/<classifiers>/uuid``
        answers a bare JSON list of uuids. Verified live (2026-09-14): the
        default device classifiers ``DeviceAccess,LocationDevices,
        TopologyTypeDevices`` answer 3 roots (ALL-ACCESS, Location, Topology
        Type — system groups every Crosswork has, even with no user-defined
        groups); the port classifiers ``PortType,UserDefinedPorts`` answer 2.
        The uuids come back in the PLATFORM's order, not the order the
        classifiers were given, and carry no name — expand them with
        cnc_get_group_hierarchy to see which root is which. An unknown
        classifier name (e.g. ``DeviceGroup``) — or a classifier with no
        groups — answers an empty list, reported as a normal result, not an
        error. Device groups are what alarm suppression policies and PM
        monitoring policies scope on (their ``deviceGroups`` uuid is one of
        these trees' groups, e.g. ``All Locations``).

        Args:
            classifiers: comma-separated classifier names (default: the three
                device classifiers; pass 'PortType,UserDefinedPorts' for the
                port trees).
            response_format: markdown or json.

        Returns:
            str: Markdown listing the uuids, or JSON {"classifiers": [str],
            "count": int, "uuids": [str]}. "No root groups for classifiers
            ..." only when the platform answers a genuine empty list. "Error:
            classifiers must name at least one value" when blank (nothing
            sent); "Error: Root-group read failed: <platform text>" on a
            ``{"status": "Error", "error": ...}`` document; "Error: Root-group
            read: ..." on an empty body or any non-list answer; "Error: ..."
            on an HTTP failure.
        """
        try:
            names = split_csv(classifiers, "classifiers")
            data = await client.request_json("GET", root_groups_url(names))
            uuids = root_uuids(data)
            if response_format is ResponseFormat.JSON:
                payload = {"classifiers": names, "count": len(uuids), "uuids": uuids}
                return finalize(to_json(payload), settings)
            if not uuids:
                return finalize(
                    f"No root groups for classifiers {', '.join(names)} (the platform answered "
                    "an empty list — an unknown classifier name answers the same; the "
                    f"verified names are {', '.join(VERIFIED_CLASSIFIERS)}).",
                    settings,
                )
            lines = [f"# Root groups for {', '.join(names)} ({len(uuids)})", ""]
            lines.extend(f"- {u}" for u in uuids)
            lines.extend(
                [
                    "",
                    "The platform lists root uuids in its own order (not the classifiers' "
                    "order) and without names: cnc_get_group_hierarchy expands them (names, "
                    "sub-groups; brief=False adds the classifier); cnc_get_group_details "
                    "shows one group.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_group_hierarchy",
        title="Get Group Hierarchy",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_group_hierarchy(
        group_uuids: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated group uuids to expand (from cnc_list_root_groups), e.g. "
                    "'efc42cda-6ce5-4a47-ad96-d1e08a16b228,9ac87805-69a9-403c-9fda-a0d892f362a8'."
                ),
                min_length=1,
                max_length=4000,
            ),
        ],
        brief: Annotated[
            bool,
            Field(
                description="True (this tool's default) for the brief view (uuid, name, "
                "children, childrenCount — NO classifier); False for the full leaves (adds "
                "classifier, discoveryType, nodeType). The platform's own default is the "
                "opposite (brief=false), so the UI / a bare curl shows the full leaves."
            ),
        ] = True,
        direct: Annotated[
            bool,
            Field(
                description="True for the direct sub-groups only; False (this tool's default) "
                "for the entire hierarchy below each group. The platform's own default is the "
                "opposite (direct=true), so the UI / a bare curl shows one level and a smaller "
                "group count."
            ),
        ] = False,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the hierarchy (sub-group tree) of one or more groups by uuid.

        Read-only. ``GET /crosswork/grouping/v1/grouping/groups/<uuids>?brief=
        <bool>&direct=<bool>`` answers a list of ``GroupDTO`` trees (verified
        live 2026-09-14 on the lab's 9 system device groups). The BRIEF view
        carries only ``uuid``, ``name``, ``children``, ``childrenCount`` and
        ``operations`` — no ``classifier`` — so a brief line shows no
        classifier; pass ``brief=False`` for ``classifier``, ``discoveryType``
        (StaticSystem / Static / Dynamic) and ``nodeType``. Neither view
        carries ``description``, ``parentUuid`` or ``parentName`` (those are
        in cnc_get_group_details). ``childrenCount`` here is the number of
        DEVICES that are direct members of the group, NOT its sub-groups: the
        lab's groups with direct members — the leaves Unassigned Devices and
        IGP Domain 0, and the root ALL-ACCESS (no sub-groups) — each showed 5
        (the whole inventory), ``All Locations`` — one sub-group, no direct
        members — showed 0, and it is absent on the Location and Topology
        Type roots (present on the ALL-ACCESS root). Start from
        cnc_list_root_groups for the root uuids. An empty list is a normal
        "no groups" result; a ``{"status": "Error", "error": ...}`` document
        (the envelope the rest of this service uses), an empty body or an
        unrecognised shape is an error, never an empty result.

        Defaults: this tool sends ``brief=true&direct=false`` (the whole
        subtree in the small view) unless told otherwise. The platform's own
        defaults are the OPPOSITE — ``brief=false&direct=true`` (full leaves,
        direct children only) — so the UI or a bare curl of the same uuids
        shows a different shape and a smaller group count; pass brief=False,
        direct=True to match them. Both flags are always sent explicitly.

        Args:
            group_uuids: comma-separated uuids.
            brief: brief view (tool default True; platform default false) or
                full leaves (classifier, discoveryType, nodeType).
            direct: direct children only (platform default true), or the
                whole subtree (tool default False).
            response_format: markdown (an indented tree when ``children`` are
                present, else a flat list; each line ``**name** (uuid)
                [classifier=... discoveryType=... nodeType=...]
                [childrenCount=N]`` — only the leaves the view carries) or
                json (the raw list).

        Returns:
            str: Markdown, or JSON {"count": int (groups incl. children),
            "requested": [str], "brief": bool, "direct": bool, "items":
            [{"uuid", "name", "children"?: [...], "childrenCount"? (member
            devices), "operations"?: {...}, and with brief=False
            "classifier", "discoveryType", "nodeType"}]}. "No groups were
            returned for uuids ..." when the answer is an empty list; "Error:
            group_uuids must name at least one value" when blank (nothing
            sent); "Error: Group hierarchy read failed: <platform text>" on a
            ``status: Error`` document; "Error: Group hierarchy read: ..." on
            an empty body or an unrecognised shape; "Error: ..." on an HTTP
            failure.
        """
        try:
            uuids = split_csv(group_uuids, "group_uuids")
            params = {
                "brief": "true" if brief else "false",
                "direct": "true" if direct else "false",
            }
            data = await client.request_json("GET", hierarchies_url(uuids), params=params)
            groups = hierarchy_entries(data)
            if response_format is ResponseFormat.JSON:
                payload = {
                    "count": count_groups(groups),
                    "requested": uuids,
                    "brief": brief,
                    "direct": direct,
                    "items": groups,
                }
                return finalize(to_json(payload), settings)
            if not groups:
                return finalize(
                    f"No groups were returned for uuids {', '.join(uuids)} (the platform "
                    "answered an empty list; check the uuids with cnc_list_root_groups).",
                    settings,
                )
            scope = "direct sub-groups" if direct else "entire hierarchy"
            view = "brief" if brief else "full"
            total = count_groups(groups)
            shape = "tree" if has_children(groups) else "no sub-groups returned"
            lines = [f"# Group hierarchy ({total} group(s), {scope}, {view} view, {shape})", ""]
            lines.extend(group_tree_lines(groups))
            notes = [
                "",
                "childrenCount = devices that are direct members of the group (not its "
                "sub-groups; absent on some roots, e.g. Location and Topology Type).",
            ]
            if brief:
                notes.append(
                    "The brief view carries no classifier: pass brief=False for classifier, "
                    "discoveryType and nodeType."
                )
            notes.append(
                "cnc_get_group_details shows one group (parent, operations); "
                "cnc_list_group_devices lists the devices of a device group."
            )
            lines.extend(notes)
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_group_details",
        title="Get Group Details",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_group_details(
        group_uuid: Annotated[
            str, Field(description=_GROUP_UUID_DESC, min_length=1, max_length=255)
        ],
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one group's details: name, classifier, discovery type
        (StaticSystem / Static / Dynamic), parent and the operations the UI
        allows on it.

        Read-only. ``GET /crosswork/grouping/v1/grouping/group/<uuid>/details``
        -> ``{"status": "Success", "group": {uuid, name, discoveryType,
        nodeType, classifier, parentUuid?, parentName?, childrenCount?,
        operations: {showMem, addMem, upd, cpf, mv, del, subGrp}}}``
        (verified live 2026-09-14 on the lab's system device groups; a root
        has no parent keys). This is the call that names a group's PARENT and
        its CLASSIFIER regardless of view — use it to resolve a group uuid
        seen elsewhere (e.g. the ``deviceGroups`` uuid of a PM monitoring
        policy). ``childrenCount`` here is NOT a member count: it read 0 on
        ``Unassigned Devices`` (5 members) and was absent on ``ALL-ACCESS``
        (5 members) — count members with cnc_list_group_devices, or read the
        hierarchy's childrenCount. A ``status`` of ``Error`` is reported as
        an error with the platform's text; ``Partial`` is shown in the result.

        Args:
            group_uuid: the group uuid.
            response_format: markdown or json (the answer as-is).

        Returns:
            str: Markdown (the group line, its operations and any nested
            children), or the raw JSON document. "Error: Group details read
            failed: ..." when the platform answers status Error (e.g. "Group
            not found"); "Error: ..." on an HTTP failure (a 404/500 is passed
            through with its hint).
        """
        try:
            uuid = group_uuid.strip()
            if not uuid:
                raise PlatformError("group_uuid must not be blank.")
            data = await client.request_json("GET", group_details_url(uuid))
            result = check_result(data, "Group details read")
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(result), settings)
            return finalize(group_details_markdown(result), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_group_devices",
        title="List Group Devices",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_group_devices(
        group_uuid: Annotated[
            str, Field(description=_GROUP_UUID_DESC, min_length=1, max_length=255)
        ],
        start: Annotated[
            int,
            Field(
                description=(
                    "0-based start index of the ?start=&end= window the document requires "
                    "(e.g. 0). Always sent; continue with the next_offset a previous call "
                    "reported."
                ),
                ge=0,
                le=MAX_DEVICE_END - 1,
            ),
        ] = DEFAULT_DEVICE_START,
        end: Annotated[
            int,
            Field(
                description=(
                    "End index of the window, EXCLUSIVE (e.g. 100 -> indexes start..99); must "
                    "be greater than start. Always sent. The document's own example is "
                    "start=0, end=30."
                ),
                ge=1,
                le=MAX_DEVICE_END,
            ),
        ] = DEFAULT_DEVICE_END,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the devices that are members of a device group (one index window per call).

        Read-only. ``GET /crosswork/grouping/v1/grouping/device/<uuid>?start=
        <i>&end=<j>`` -> ``{"status": "Success", "devices": [{"uuid",
        "attributes": {"hostname", "node_ip", "product_type", "software_type",
        "software_version", "product_family", "product_series",
        "reachability", "discoveryType", "description", "contact",
        "location", "last_update" (epoch seconds), "delete"}}], "total": N}``
        — verified live 2026-09-14 on the lab's system device groups. The
        document calls it "essential" to send both ``start`` and ``end``, so
        a window is always sent (default ``0-100``). ``end`` is EXCLUSIVE
        (``0-2`` answered indexes 0 and 1) and ``total`` is the member count
        of the WHOLE group (5 on every window of a 5-member group), so paging
        is driven by it: ``has_more`` = ``start + count < total``. A group
        whose members sit in its sub-groups (``All Locations``) answers no
        devices and ``total: 0`` — list its sub-groups with
        cnc_get_group_hierarchy and query the leaf (``Unassigned Devices``).
        The device uuids are the inventory node uuids (cnc_get_device).

        Args:
            group_uuid: the device group uuid (a port group answers no devices).
            start / end: the index window (end > start, end exclusive), always
                sent.
            response_format: markdown (one line per device) or json.

        Returns:
            str: Markdown "**hostname** (uuid) ip=... type=... sw=...
            reachability=... updated=..." lines, headed "(<count> of <total>)"
            when the group holds more than this window, plus "More available:
            repeat with start=<n>, end=<m>." when ``total`` says so; or JSON
            {"group_uuid": str, "status": str, "start": int, "end": int,
            "total": int|null, "count": int, "offset": int, "items":
            [<device>], "has_more": bool, "next_offset": int|null (start +
            count — skips nothing), "window_full": bool}. When the platform
            omits ``total``, ``has_more`` falls back to "the window came back
            full". "No devices are members of group <uuid> ..." when the
            window is empty (not an error). "Error: end must be greater than
            start" (nothing sent); "Error: Group devices read failed:
            <platform text>" on a ``status: Error`` document; "Error: Group
            devices read: ..." on an empty body or a non-object answer;
            "Error: ..." on an HTTP failure (a 400 here means the platform
            rejected the uuid or the window — try the document's ``start=0,
            end=30``).
        """
        try:
            uuid = group_uuid.strip()
            if not uuid:
                raise PlatformError("group_uuid must not be blank.")
            if end <= start:
                raise PlatformError("end must be greater than start (e.g. start=0, end=100).")
            params = {"start": start, "end": end}
            data = await client.request_json("GET", group_devices_url(uuid), params=params)
            result = check_result(data, "Group devices read")
            devices = _dicts(result.get("devices"))
            envelope = device_page(devices, as_count(result.get("total")), start, end)
            if response_format is ResponseFormat.JSON:
                payload = {
                    "group_uuid": uuid,
                    "status": result.get("status"),
                    "start": start,
                    "end": end,
                    **envelope,
                }
                return finalize(to_json(payload), settings)
            total = envelope["total"]
            count = envelope["count"]
            if not devices:
                text = f"No devices are members of group {uuid} in the index window {start}-{end}"
                if total and start > 0:
                    text += f" (the group has {total} members; try an earlier window)"
                elif total:
                    text += f" (the platform reports {total} members yet answered none here)"
                else:
                    text += (
                        " (a group whose members sit in its sub-groups answers none here — "
                        "expand it with cnc_get_group_hierarchy and query a leaf group)"
                    )
                return finalize(f"{text}.", settings)
            head = f"# Devices in group {uuid} ({count}"
            if total is not None and total != count:
                head += f" of {total}"
            head += f"; indexes {start}-{end})"
            lines = [head, ""]
            lines.extend(device_line(d) for d in devices)
            if str(result.get("status") or "") == RESULT_PARTIAL:
                lines.extend(["", f"Status Partial: {result.get('error') or 'no detail given'}"])
            if envelope["has_more"]:
                next_start = envelope["next_offset"]
                if next_start >= MAX_DEVICE_END:
                    hint = f"beyond index {MAX_DEVICE_END} (the cap this tool can request)"
                else:
                    next_end = min(next_start + (end - start), MAX_DEVICE_END)
                    hint = f"repeat with start={next_start}, end={next_end}"
                lines.extend(["", f"More available: {hint}."])
            lines.extend(["", "The uuids are inventory node uuids (cnc_get_device shows one)."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)
