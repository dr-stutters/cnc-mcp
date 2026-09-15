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

Writes (all verified live 2026-09-15 with create -> read back -> update ->
delete sequences that left the lab as found): user groups under the
``LocationDevices``, ``DeviceAccess`` and ``UserDefinedPorts`` classifiers
(``POST group``, ``PUT group/<uuid>``, ``DELETE group/<uuid>``), membership
(``PUT group/<uuid>/members`` REMOVES members; ``POST group/member/move`` and
``member/copy`` add them from the LocationDevices leaf that holds the device)
and the one rule a group may carry (``POST rule``, ``PUT rule/<uuid>``,
``DELETE rule/<uuid>``; read with ``GET rule/group/<uuid>`` and
``rule/classifier/<classifier>``). The rule is a separate object (own uuid,
name, ``active`` flag) bound 1:1 to its target group (a second rule on the
same group is refused with a ``unq_target_group_uuid`` constraint error and
deleting the group cascades to its rule), so its lifecycle is folded into the
group tools here: ``rule_conditions`` on cnc_create_device_group /
cnc_update_device_group creates, replaces or removes it. Port add/remove
(``POST/DELETE port/<uuid>``) stays unexposed.

**Dynamic groups on 7.2.0**: a rule on a ``UserDefinedPorts`` group is
evaluated within seconds (5 Loopback ports matched ``name SO_Contains
Loopback`` 3 s after ``POST rule``, each with ``discoveryType: Dynamic``;
``speed NO_Equals 0`` — a NUMBER attribute, wire key ``numericCondition`` —
matched 7). A rule with TWO OR MORE conditions is stored but makes ``GET
port/<uuid>`` answer HTTP 500 for as long as it stays (string+string,
string+numeric, either order), so the tools allow one condition per rule
and the platform's multi-condition semantics (AND / OR) stay unverified. A
rule on a ``LocationDevices`` group is stored and readable but was NEVER
evaluated on the lab — 0 members after 150 s for ``hostname SO_StartWith PE``,
``node_ip SO_Contains 198.18`` and a re-PUT of the rule, the group's
``discoveryType`` stayed ``Static``, no evaluate endpoint exists, and the
group's ``operations`` carry no ``rule`` flag (the port group's do) — so a
device group is populated by MOVING devices into it (the UI's own way), and a
device rule is documentation at best on this build.

Wire facts (verified live on Crosswork 7.2, 2026-09-13 .. 2026-09-15, base
:data:`GROUPING`):

- Write envelopes: every write answers HTTP 200 with a ``ResultDTO`` —
  ``{"status": "Success", "group": {uuid, name, description?, nodeType,
  classifier}}`` (create / update / delete a group; NO discoveryType or
  parentUuid in the echo — read ``group/<uuid>/details`` for those),
  ``{"status": "Success", "rule": {uuid, ordering, name, classifier, active,
  conditions (a JSON STRING), targetGroupUuid}}`` (create / update a rule),
  ``{"status": "Success"}`` (member move / copy / remove, rule delete). A
  refusal is ALSO HTTP 200: ``{"status": "Error", "error": <code>}`` with the
  codes ``NAME_ALREADY_EXIST`` (create: the name exists in the classifier),
  ``RESERVED_GROUP_NAME`` (update: renaming to a system group's name),
  ``INVALID_PARENT_GROUP`` (create: unknown parentUuid), ``GROUP_NOT_EXIST``
  (details / delete of an unknown or already-deleted uuid), ``MEMBER_NOT_EXIST``
  (move / copy / remove: a device that is not in the SOURCE group — a parent
  group such as ``All Locations`` never counts as the source), ``INVALID_
  OPERATION`` (move from a non-leaf source or into a DeviceAccess group; copy
  out of a DeviceAccess group), ``RULE_NOT_EXIST`` (a static group's
  ``rule/group``, or an unknown / already-deleted rule uuid),
  ``TARGET_GROUP_NOT_EXIST`` (rule: unknown target) and a raw SQL ``duplicate
  key ... unq_target_group_uuid`` text (a second rule on one group). Spring
  answers a missing required field with HTTP 400 (``PUT group`` without
  ``name`` + ``parentUuid``, a rule ``conditions`` sent as an object instead
  of a string, a move without ``groupUuid``, an empty group name) and HTTP 500
  for ``PUT group/<unknown uuid>``, an empty ``references`` list, an unknown
  move target and an unknown rule operator — an unknown rule ATTRIBUTE and an
  unknown CLASSIFIER are accepted silently (the classifier falls back to
  LocationDevices), which is why the tools validate both before sending.
- ``PUT group/<uuid>`` is a full replace that REQUIRES ``name`` and
  ``parentUuid``: a body without ``description`` clears it to ``""``.
  cnc_update_device_group reads the details first and re-sends what it keeps.
- ``PUT group/<uuid>/members {"references": [uuids]}`` REMOVES those members
  (the OpenAPI summary says so; it is not a "set members" call). A device
  removed from a LocationDevices group lands back in ``Unassigned Devices``
  (the classifier partitions the inventory: every device is in exactly one
  leaf); removed from a DeviceAccess group it simply stops being visible
  through that access group. Deleting a group with members has the same
  effect on them.
- ``POST group/member/move {"groupUuid": <source>, "newGroupUuid": <target>,
  "references": [uuids]}`` moves devices between LocationDevices groups; the
  SOURCE must be the exact leaf that holds each device today (``Unassigned
  Devices`` for a device never placed). ``member/copy`` (same body) copies
  from a LocationDevices leaf INTO a DeviceAccess group and is idempotent
  (copying an existing member answers Success); a repeated move answers
  ``MEMBER_NOT_EXIST``. ``selectAll=true`` is documented but unexercised.
- A created group is ``discoveryType: Static`` with ``operations {showMem,
  addMem, upd, cpf, mv, del, subGrp}`` (LocationDevices), ``{showMem, upd,
  del, cpt, subGrp}`` (DeviceAccess) or ``{showMem, upd, addMem, rule, del}``
  (UserDefinedPorts); ``childrenCount`` in its details stays 0 whatever the
  membership.
- Platform-managed groups come in TWO shapes (details read live 2026-09-15):
  ``discoveryType: StaticSystem`` (``Location`` {cpf}, ``All Locations``
  {cpf, subGrp}, ``Unassigned Devices`` {showMem, cpf, addMem, mv}, ``ALL-
  ACCESS`` / ``User Defined`` {subGrp}, ``Topology Type`` with no operations)
  and ``discoveryType: Dynamic`` — the ``PortType`` tree (``Port Type`` root
  without operations; ``Software Loopback``, ``MPLS Tunnel``, ``Ethernet
  CSMACD`` {showMem}, each the target of a system rule ``rule/group/<uuid>``
  answers) and the ``TopologyTypeDevices`` auto-groups (``AS`` > ``65000`` >
  ``IGP Domain`` > ``0``, no operations in their details). None of them
  carries ``upd`` or ``del``; every user group does. The write tools refuse a
  group by StaticSystem, by a classifier outside the three creatable ones and
  by the missing operation flag (:func:`refuse_system_group`) — never by
  ``Dynamic`` alone (``discoveryType`` says how members are found, not who
  owns the group: a rule-populated user port group read ``Static`` with
  ``Dynamic`` members). What the platform would answer to a DELETE / PUT on
  these groups is deliberately unverified (never sent).
- ``GET rule/group/<uuid>`` answers ``RULE_NOT_EXIST`` for an UNKNOWN group
  uuid exactly as for a static group (verified with the all-zero uuid), so
  "no rule" alone never proves the group exists.
- ``GET port/<uuid>?start=&end=`` -> ``{"status": "Success", "ports":
  [{portUuid, deviceUuid, node_ip, hostName, portName, description, speed,
  type, delete, discoveryType}], "total": N}`` — the port members of a port
  group (verified live on a rule-populated UserDefinedPorts group).
- ``childrenCount`` in the hierarchy call is populated only for
  ``direct=false`` requests: the same ``Unassigned Devices`` (5 members)
  answered ``childrenCount: 5`` with ``direct=false`` and ``0`` with
  ``direct=true`` (2026-09-15).
- Seen twice (2026-09-15), not reproduced in three targeted attempts: within
  a couple of seconds of deleting user groups, ``GET groups/<All Locations>``
  answered ``All Locations`` with NO children although ``Unassigned Devices``
  still existed (its device listing was fine); a re-read a little later
  showed the child again. Re-read the hierarchy before concluding a system
  group is gone.

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
import logging
from typing import Annotated, Any
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.client import ApiClient
from cnc_mcp.errors import PlatformError, format_error
from cnc_mcp.formatting import (
    ResponseFormat,
    epoch_iso,
    finalize,
    pagination_envelope,
    to_json,
)
from cnc_mcp.safety import AppContext, register_tool

logger = logging.getLogger(__name__)

GROUPING = "/crosswork/grouping/v1/grouping"
DEVICE_CONDITIONS_PATH = f"{GROUPING}/device/rule/conditions"
PORT_CONDITIONS_PATH = f"{GROUPING}/ports/rule/conditions"
ROOT_GROUPS_PATH = f"{GROUPING}/group/root"  # + /<classifiers>/uuid
HIERARCHIES_PATH = f"{GROUPING}/groups"  # + /<uuids>
GROUP_PATH = f"{GROUPING}/group"  # POST; + /<uuid> (PUT, DELETE), /<uuid>/details, /<uuid>/members
GROUP_DEVICES_PATH = f"{GROUPING}/device"  # + /<uuid>
GROUP_PORTS_PATH = f"{GROUPING}/port"  # + /<uuid>?start=&end=
MEMBER_MOVE_PATH = f"{GROUPING}/group/member/move"
MEMBER_COPY_PATH = f"{GROUPING}/group/member/copy"
RULE_PATH = f"{GROUPING}/rule"  # POST; + /<uuid> (GET, PUT, DELETE), /group/<uuid>, /classifier/<c>

CONDITION_KINDS: dict[str, str] = {"device": DEVICE_CONDITIONS_PATH, "port": PORT_CONDITIONS_PATH}
MEMBER_OPERATION_PATHS: dict[str, str] = {"move": MEMBER_MOVE_PATH, "copy": MEMBER_COPY_PATH}
# The classifiers the create DTO enumerates (all three verified live 2026-09-15); the
# rule DTO's are LocationDevices and UserDefinedPorts, and rule/classifier/<c> also
# lists the PortType system rules.
WRITABLE_CLASSIFIERS = ("LocationDevices", "DeviceAccess", "UserDefinedPorts")
# The classifiers whose groups hold DEVICES as members (the member tools' scope; the
# port classifiers' members are ports, the TopologyTypeDevices groups are derived).
MEMBER_CLASSIFIERS = ("LocationDevices", "DeviceAccess")
RULE_CLASSIFIERS = ("LocationDevices", "UserDefinedPorts", "PortType")
# Which rule vocabulary (``CONDITION_KINDS``) a classifier's rule is written in.
RULE_KIND_OF_CLASSIFIER: dict[str, str] = {
    "LocationDevices": "device",
    "UserDefinedPorts": "port",
    "PortType": "port",
}
# The wire key of a condition by the attribute's ``type`` in the rule/conditions
# vocabulary: ``stringCondition`` (SO_* operators) and ``numericCondition`` (NO_*
# operators, e.g. port ``speed``) — both verified live 2026-09-15.
CONDITION_TYPE_STRING = "STRING"
CONDITION_TYPE_NUMBER = "NUMBER"
CONDITION_KEYS: dict[str, str] = {
    CONDITION_TYPE_STRING: "stringCondition",
    CONDITION_TYPE_NUMBER: "numericCondition",
}
MEMBER_MODES = ("replace", "add", "remove")
MEMBER_OPERATIONS = ("move", "copy")
DISCOVERY_SYSTEM = "StaticSystem"
# The ``operations`` flag of ``group/<uuid>/details`` a write needs, by the action word
# :func:`refuse_system_group` is called with. Verified live 2026-09-15: a created user
# group answers {showMem, addMem, upd, cpf, mv, del, subGrp} (LocationDevices), {showMem,
# upd, del, cpt, subGrp} (DeviceAccess) or {showMem, upd, addMem, rule, del}
# (UserDefinedPorts) — every user group carries ``upd`` and ``del`` — while NO
# platform-managed group does: Unassigned Devices {showMem, cpf, addMem, mv}, the roots /
# All Locations {cpf} / {subGrp}, the PortType groups {showMem} or nothing, the
# TopologyTypeDevices auto-groups nothing. A DeviceAccess user group has no ``addMem`` /
# ``mv`` (its copy-in flag is ``cpt``), so membership changes key on ``upd`` as well.
REQUIRED_OPERATION: dict[str, str] = {"deleted": "del", "updated": "upd", "changed": "upd"}
RULE_NOT_EXIST = "RULE_NOT_EXIST"
# A rule with TWO OR MORE conditions is accepted by POST/PUT rule but makes the group's
# member listing (GET port/<uuid>) answer HTTP 500 for as long as it stays — string +
# string, string + numeric, either order, all verified live 2026-09-15 on 7.2.0; a
# single string or numeric condition works. So the tools refuse more than one.
MAX_RULE_CONDITIONS = 1
MAX_MEMBER_REFERENCES = 10000  # the DTOs' maxItems
# Platform refusal codes (HTTP 200 ``{"status": "Error", "error": <code>}``, verified
# live 2026-09-15) and what an agent should do about each.
GROUPING_ERROR_HINTS: dict[str, str] = {
    "NAME_ALREADY_EXIST": (
        "a group with that name already exists in this classifier's tree (names are unique "
        "per classifier; see cnc_get_group_hierarchy)"
    ),
    "RESERVED_GROUP_NAME": (
        "the name belongs to a system group (e.g. 'Unassigned Devices', 'All Locations') "
        "and cannot be given to a user group"
    ),
    "INVALID_PARENT_GROUP": (
        "parent_uuid is not an existing group of this classifier (cnc_list_root_groups + "
        "cnc_get_group_hierarchy list the candidates)"
    ),
    "GROUP_NOT_EXIST": "no group with that uuid (already deleted, or a typo)",
    "MEMBER_NOT_EXIST": (
        "a device named in the request is not a member of the SOURCE group — the source must "
        "be the exact leaf group that holds the device today (a parent such as 'All "
        "Locations' never counts); cnc_set_device_group_members finds the leaf for you"
    ),
    "INVALID_OPERATION": (
        "the platform refuses this member operation between these groups: move works only "
        "between LocationDevices groups and only from the exact leaf holding the device; "
        "copy only from a LocationDevices leaf INTO a DeviceAccess group"
    ),
    RULE_NOT_EXIST: (
        "the group has no rule (a static group), the GROUP uuid is unknown (rule/group answers "
        "the same code for both — cnc_get_group_details tells them apart) or the rule uuid is "
        "unknown"
    ),
    "TARGET_GROUP_NOT_EXIST": "the rule's target group uuid does not exist",
    "unq_target_group_uuid": (
        "the target group already carries a rule — a group has at most one; replace it with "
        "cnc_update_device_group rule_conditions=... instead"
    ),
}
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


def group_url(uuid: str) -> str:
    """``.../group/<uuid>`` (PUT update, DELETE)."""
    return f"{GROUP_PATH}/{quote(uuid, safe='')}"


def group_members_url(uuid: str) -> str:
    """``.../group/<uuid>/members`` (PUT = remove members)."""
    return f"{GROUP_PATH}/{quote(uuid, safe='')}/members"


def group_ports_url(uuid: str) -> str:
    return f"{GROUP_PORTS_PATH}/{quote(uuid, safe='')}"


def rule_url(uuid: str) -> str:
    return f"{RULE_PATH}/{quote(uuid, safe='')}"


def rule_of_group_url(group_uuid: str) -> str:
    return f"{RULE_PATH}/group/{quote(group_uuid, safe='')}"


def rules_of_classifier_url(classifier: str) -> str:
    return f"{RULE_PATH}/classifier/{quote(classifier, safe='')}"


def canonical_choice(value: str, choices: tuple[str, ...], what: str) -> str:
    """The entry of ``choices`` that equals ``value`` case-insensitively, else PlatformError."""
    text = (value or "").strip()
    for choice in choices:
        if text.lower() == choice.lower():
            return choice
    raise PlatformError(f"Unknown {what} '{value}'. Use one of: {', '.join(choices)}.")


def rule_kind_of(classifier: str) -> str:
    """The rule vocabulary kind of a classifier, else PlatformError (DeviceAccess has none)."""
    kind = RULE_KIND_OF_CLASSIFIER.get(classifier)
    if kind is None:
        raise PlatformError(
            f"Groups of classifier {classifier} cannot carry a rule; rules exist for "
            f"{', '.join(RULE_KIND_OF_CLASSIFIER)} groups."
        )
    return kind


def vocabulary_of(conditions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """``{attributeName: {"type": "STRING" | "NUMBER", "operators": [names]}}`` of a
    rule-conditions answer (an attribute without a type is taken as STRING)."""
    return {
        str(c.get("attributeName")): {
            "type": str(c.get("type") or CONDITION_TYPE_STRING).upper(),
            "operators": operator_names(c),
        }
        for c in conditions
        if c.get("attributeName")
    }


def _match_operator(wanted: str, allowed: list[str]) -> str | None:
    """The allowed operator ``wanted`` names — exact, case-insensitive, or without
    its ``SO_`` / ``NO_`` prefix (``StartWith`` -> ``SO_StartWith``, ``Equals`` ->
    ``SO_Equals`` on a string attribute and ``NO_Equals`` on a numeric one)."""
    text = wanted.strip().lower()
    for name in allowed:
        lowered = name.lower()
        if text in (lowered, lowered.removeprefix("so_").removeprefix("no_")):
            return name
    return None


def parse_rule_conditions(text: str, vocabulary: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Decode a ``rule_conditions`` argument into the wire condition list, validated.

    Accepts a JSON list of ``{"attribute", "operator", "value"}`` objects (the
    wire spellings ``attributeName`` and ``stringCondition`` /
    ``numericCondition: {"operator"}`` are taken too) or a ``{"conditions":
    [...]}`` wrapper. Every attribute must be in ``vocabulary`` (the
    ``rule/conditions`` answer for the group's kind) and every operator one of
    that attribute's, named exactly, case-insensitively or without the
    ``SO_`` / ``NO_`` prefix; values are sent as strings. Returns ``[{"order":
    n, "attributeName", "value", "stringCondition": {"operator"}}]`` for a
    STRING attribute and ``{..., "numericCondition": {"operator"}}`` for a
    NUMBER one — the shapes the platform stores (both verified live
    2026-09-15; ``numberCondition`` and a numeric ``value`` are HTTP 500) — or
    raises PlatformError naming the first problem. An empty list is returned
    for ``[]`` (the caller decides what that means).
    """
    try:
        data = json.loads(text)
    except ValueError as e:
        raise PlatformError(
            "rule_conditions must be a JSON list such as "
            '[{"attribute": "hostname", "operator": "SO_StartWith", "value": "PE"}].'
        ) from e
    if isinstance(data, dict) and isinstance(data.get("conditions"), list):
        data = data["conditions"]
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise PlatformError("rule_conditions must be a JSON list of condition objects.")
    if len(data) > MAX_RULE_CONDITIONS:
        raise PlatformError(
            f"rule_conditions: at most {MAX_RULE_CONDITIONS} condition per rule — Crosswork "
            "7.2.0 accepts a multi-condition rule but its group's member listing then "
            "answers HTTP 500 until the rule is back to one condition (verified live)."
        )
    wire: list[dict[str, Any]] = []
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise PlatformError(f"rule_conditions[{index - 1}] is not an object.")
        attribute = str(item.get("attribute") or item.get("attributeName") or "").strip()
        operator = item.get("operator")
        for key in CONDITION_KEYS.values():
            if operator is None and isinstance(item.get(key), dict):
                operator = item[key].get("operator")
        operator = str(operator or "").strip()
        value = item.get("value")
        if not attribute or not operator or value is None:
            raise PlatformError(
                f"rule_conditions[{index - 1}] needs 'attribute', 'operator' and 'value'."
            )
        if attribute not in vocabulary:
            raise PlatformError(
                f"rule_conditions[{index - 1}]: unknown attribute '{attribute}'. Known: "
                f"{', '.join(sorted(vocabulary)) or '(none reported)'} "
                "(cnc_list_group_rule_conditions)."
            )
        entry = vocabulary[attribute]
        wire_operator = _match_operator(operator, entry["operators"])
        if wire_operator is None:
            raise PlatformError(
                f"rule_conditions[{index - 1}]: unknown operator '{operator}' for "
                f"'{attribute}'. Known: {', '.join(entry['operators']) or '(none)'}."
            )
        key = CONDITION_KEYS.get(entry["type"], CONDITION_KEYS[CONDITION_TYPE_STRING])
        wire.append(
            {
                "order": index,
                "attributeName": attribute,
                "value": str(value),
                key: {"operator": wire_operator},
            }
        )
    return wire


def conditions_payload(conditions: list[dict[str, Any]]) -> str:
    """The ``conditions`` field of a RuleDTO: a JSON STRING (an object is refused with 400)."""
    return json.dumps({"conditions": conditions}, separators=(",", ":"))


def decode_conditions(rule: dict[str, Any]) -> list[dict[str, Any]]:
    """The condition objects of a rule's ``conditions`` string (``[]`` when undecodable)."""
    raw = rule.get("conditions")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return []
    if isinstance(raw, dict):
        raw = raw.get("conditions")
    return _dicts(raw)


def condition_text(condition: dict[str, Any]) -> str:
    """``hostname SO_StartWith 'PE'`` (string or numeric condition)."""
    operator = condition.get("operator")
    for key in CONDITION_KEYS.values():
        if operator is None and isinstance(condition.get(key), dict):
            operator = condition[key].get("operator")
    return (
        f"{condition.get('attributeName') or condition.get('attribute') or '?'} "
        f"{operator or '?'} '{condition.get('value', '')}'"
    )


def rule_summary(rule: dict[str, Any]) -> str:
    """``cond1; cond2`` of a rule, or ``(no conditions)``."""
    parts = [condition_text(c) for c in decode_conditions(rule)]
    return "; ".join(parts) if parts else "(no conditions)"


def rule_line(rule: dict[str, Any]) -> str:
    """``- **name** (uuid) active=... classifier=... target=<group uuid>: <conditions>``."""
    return (
        f"- **{rule.get('name') or '?'}** ({rule.get('uuid') or '?'}) "
        f"active={rule.get('active')} classifier={rule.get('classifier') or '-'} "
        f"target={rule.get('targetGroupUuid') or '-'}: {rule_summary(rule)}"
    )


def rule_view(rule: dict[str, Any]) -> dict[str, Any]:
    """The rule with its ``conditions`` string decoded alongside (``conditions_decoded``)."""
    return {**rule, "conditions_decoded": decode_conditions(rule)}


def rules_of(data: Any, what: str) -> list[dict[str, Any]]:
    """The rule list of ``rule/classifier/<c>`` (a bare list live; a ``{rules: []}``
    envelope and a single ``{rule: {...}}`` document are tolerated)."""
    if isinstance(data, list):
        return _dicts(data)
    if isinstance(data, dict):
        check_result(data, what)
        if isinstance(data.get("rules"), list):
            return _dicts(data["rules"])
        if isinstance(data.get("rule"), dict):
            return [data["rule"]]
    raise shape_error(what, "a JSON list of rules", data)


def flatten_groups(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every group of a hierarchy forest, depth-first, children included."""
    flat: list[dict[str, Any]] = []
    for group in groups:
        flat.append(group)
        flat.extend(flatten_groups(_dicts(group.get("children"))))
    return flat


def device_hostname(device: dict[str, Any]) -> str:
    attrs = device.get("attributes") if isinstance(device.get("attributes"), dict) else {}
    return str(attrs.get("hostname") or "")


def match_devices(
    tokens: list[str], devices: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Resolve device tokens (uuid, or host name case-insensitively) against a
    member list: ``({token: device}, [unresolved tokens])``."""
    by_uuid = {str(d.get("uuid")): d for d in devices if d.get("uuid")}
    by_name = {device_hostname(d).lower(): d for d in devices if device_hostname(d)}
    resolved: dict[str, dict[str, Any]] = {}
    unresolved: list[str] = []
    for token in tokens:
        device = by_uuid.get(token) or by_name.get(token.lower())
        if device is None:
            unresolved.append(token)
        else:
            resolved[token] = device
    return resolved, unresolved


def member_brief(device: dict[str, Any]) -> dict[str, Any]:
    return {"uuid": device.get("uuid"), "hostname": device_hostname(device) or None}


def port_line(port: dict[str, Any]) -> str:
    """``- **host:port** (portUuid) device=... ip=... type=... speed=... discoveryType=...``."""
    text = (
        f"- **{port.get('hostName') or '?'}:{port.get('portName') or '?'}** "
        f"({port.get('portUuid') or '?'}) device={port.get('deviceUuid') or '-'} "
        f"ip={port.get('node_ip') or '-'} type={port.get('type') or '-'} "
        f"speed={port.get('speed') or '-'}"
    )
    if port.get("discoveryType"):
        text += f" discoveryType={port['discoveryType']}"
    if port.get("description"):
        text += f" — {port['description']}"
    return text


def _dicts(items: Any) -> list[dict[str, Any]]:
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def response_json(response: Any) -> Any:
    """The parsed JSON body of an httpx response, or None (never raises)."""
    try:
        return response.json()
    except ValueError:
        return None


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


def error_code_of(data: Any) -> str | None:
    """The ``error`` text of a ``{"status": "Error", ...}`` document, else None."""
    if isinstance(data, dict) and str(data.get("status") or "") == RESULT_ERROR:
        return str(data.get("error") or data.get("details") or "no reason given")
    return None


def error_hint(reason: str) -> str | None:
    """The :data:`GROUPING_ERROR_HINTS` entry for a platform refusal text.

    An exact code (``MEMBER_NOT_EXIST``) matches directly; free text (the SQL
    constraint message of a second rule, a code with a trailing detail) is
    matched by the LONGEST marker it contains, so ``TARGET_GROUP_NOT_EXIST:
    ...`` gets its own hint and not ``GROUP_NOT_EXIST``'s.
    """
    text = reason.strip()
    if text in GROUPING_ERROR_HINTS:
        return GROUPING_ERROR_HINTS[text]
    for marker in sorted(GROUPING_ERROR_HINTS, key=len, reverse=True):
        if marker in text:
            return GROUPING_ERROR_HINTS[marker]
    return None


def check_result(data: Any, what: str) -> dict[str, Any]:
    """Validate a ``ResultDTO`` answer (``status`` Success | Partial | Error).

    ``Error`` is raised with the document's ``error`` text plus the
    :data:`GROUPING_ERROR_HINTS` advice when the code is a known one;
    ``Partial`` is returned (the caller reports it). A non-dict body is a
    shape error (an empty body is named as such).
    """
    if not isinstance(data, dict):
        raise shape_error(what, "a JSON object", data)
    reason = error_code_of(data)
    if reason is not None:
        message = f"{what} failed: {reason[:300]}"
        hint = error_hint(reason)
        if hint:
            message += f" Hint: {hint}."
        raise PlatformError(message)
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


# --- platform helpers (one request each, shared by the write tools) ------------------


async def read_group(client: ApiClient, group_uuid: str) -> dict[str, Any]:
    """The ``group`` object of ``group/<uuid>/details`` (GROUP_NOT_EXIST raises)."""
    data = await client.request_json("GET", group_details_url(group_uuid))
    result = check_result(data, f"Group {group_uuid} details read")
    group = result.get("group")
    if not isinstance(group, dict):
        raise shape_error(f"Group {group_uuid} details read", '{"group": {...}}', result)
    return group


def refuse_system_group(group: dict[str, Any], action: str) -> None:
    """PlatformError when the group is platform-managed, so nothing is sent.

    Three checks in the platform's own words (all verified live 2026-09-15 on
    the ``group/<uuid>/details`` answers): ``discoveryType: StaticSystem`` (the
    roots, All Locations, Unassigned Devices, ALL-ACCESS, User Defined); a
    classifier outside :data:`WRITABLE_CLASSIFIERS` — the ``PortType`` port-type
    groups (Software Loopback, Ethernet CSMACD, MPLS Tunnel, each fed by a
    system rule) and the ``TopologyTypeDevices`` AS / IGP-domain auto-groups
    are ``discoveryType: Dynamic``, NOT StaticSystem, so the classifier is what
    marks them as derived; and an ``operations`` map without the flag the
    action needs (:data:`REQUIRED_OPERATION`: ``del`` to be deleted, ``upd`` to
    be updated or have its members changed — every user group carries both, no
    platform-managed group seen carries either). The gate never keys on
    ``Dynamic`` itself: ``discoveryType`` says how members are found, not who
    owns the group (a rule-populated UserDefinedPorts user group read
    ``Static`` with ``Dynamic`` port members on the lab, 2026-09-15, and a
    build that reports it Dynamic must not lose its writability). ``action``
    is the past participle the message uses ('deleted' | 'updated' |
    'changed').
    """
    name, uuid = group.get("name"), group.get("uuid")
    discovery = str(group.get("discoveryType") or "")
    if discovery == DISCOVERY_SYSTEM:
        raise PlatformError(
            f"Group '{name}' ({uuid}) is a system group (discoveryType StaticSystem) and "
            f"cannot be {action}; only user groups can."
        )
    classifier = str(group.get("classifier") or "")
    if classifier not in WRITABLE_CLASSIFIERS:
        raise PlatformError(
            f"Group '{name}' ({uuid}) is a platform-managed {classifier or 'unknown-classifier'} "
            f"group (discoveryType {discovery or '?'}; the platform derives these groups and "
            f"their rules) and cannot be {action}; only user groups of the "
            f"{', '.join(WRITABLE_CLASSIFIERS)} classifiers can."
        )
    flag = REQUIRED_OPERATION.get(action)
    operations = group.get("operations") if isinstance(group.get("operations"), dict) else {}
    if flag and not operations.get(flag):
        raise PlatformError(
            f"Group '{name}' ({uuid}) cannot be {action}: the platform lists no '{flag}' "
            f"operation for it (operations: {_compact(operations) if operations else 'none'}), "
            "which marks it as platform-managed rather than a user group."
        )


async def all_group_devices(client: ApiClient, group_uuid: str) -> list[dict[str, Any]]:
    """Every device member of a group (all ``start``/``end`` windows, up to
    :data:`MAX_DEVICE_END`)."""
    members: list[dict[str, Any]] = []
    start = 0
    while start < MAX_DEVICE_END:
        end = min(start + DEFAULT_DEVICE_END, MAX_DEVICE_END)
        data = await client.request_json(
            "GET", group_devices_url(group_uuid), params={"start": start, "end": end}
        )
        result = check_result(data, f"Group {group_uuid} devices read")
        devices = _dicts(result.get("devices"))
        members.extend(devices)
        total = as_count(result.get("total"))
        window_full = len(devices) >= end - start
        start += len(devices)
        if not devices or not window_full or (total is not None and start >= total):
            break
    return members


async def location_groups(client: ApiClient) -> list[dict[str, Any]]:
    """The whole LocationDevices tree, flattened (brief view, ``direct=false`` so
    ``childrenCount`` — the direct member count — is populated)."""
    roots = root_uuids(await client.request_json("GET", root_groups_url(["LocationDevices"])))
    if not roots:
        raise PlatformError("The platform reports no LocationDevices root group.")
    data = await client.request_json(
        "GET", hierarchies_url(roots), params={"brief": "true", "direct": "false"}
    )
    return flatten_groups(hierarchy_entries(data))


async def locate_devices(
    client: ApiClient, tokens: list[str]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Find the LocationDevices leaf holding each device (by uuid or host name).

    Walks the Location tree and lists the members of each group that may hold
    devices until every token is found: groups whose ``childrenCount`` (the
    direct member count in the ``direct=false`` view) is positive are listed
    first, then the groups that carry no count (the roots — never holding a
    device on the lab, but not proven empty); a group with ``childrenCount``
    0 is skipped. Returns ``({token: {"device": <device>, "group_uuid",
    "group_name"}}, [unresolved])``. This is how a move / copy learns its
    mandatory SOURCE group.
    """
    found: dict[str, dict[str, Any]] = {}
    pending = list(tokens)
    counted: list[dict[str, Any]] = []
    uncounted: list[dict[str, Any]] = []
    for group in await location_groups(client):
        count = as_count(group.get("childrenCount"))
        if group.get("childrenCount") is None:
            uncounted.append(group)
        elif count:
            counted.append(group)
    for group in counted + uncounted:
        if not pending:
            break
        uuid = str(group.get("uuid") or "")
        if not uuid:
            continue
        resolved, pending = match_devices(pending, await all_group_devices(client, uuid))
        for token, device in resolved.items():
            found[token] = {
                "device": device,
                "group_uuid": uuid,
                "group_name": group.get("name"),
            }
    return found, pending


async def rule_of_group(client: ApiClient, group_uuid: str) -> dict[str, Any] | None:
    """The rule targeting a group, or None when ``rule/group/<uuid>`` says RULE_NOT_EXIST.

    ``RULE_NOT_EXIST`` is ALSO what an UNKNOWN group uuid answers (verified
    live 2026-09-15 with 00000000-0000-0000-0000-000000000000), so None means
    "no rule OR no such group": callers that need the distinction read the
    group first (:func:`read_group` raises GROUP_NOT_EXIST for a bad uuid).
    """
    data = await client.request_json("GET", rule_of_group_url(group_uuid))
    if error_code_of(data) == RULE_NOT_EXIST:
        return None
    result = check_result(data, f"Group {group_uuid} rule read")
    rule = result.get("rule")
    if not isinstance(rule, dict):
        raise shape_error(f"Group {group_uuid} rule read", '{"rule": {...}}', result)
    return rule


async def rule_vocabulary(client: ApiClient, classifier: str) -> dict[str, dict[str, Any]]:
    """The attribute -> operators vocabulary a rule of this classifier may use."""
    kind = rule_kind_of(classifier)
    data = await client.request_json("GET", CONDITION_KINDS[kind])
    vocabulary = vocabulary_of(conditions_of(data))
    if not vocabulary:
        raise PlatformError(f"The platform reports no {kind} rule conditions to validate against.")
    return vocabulary


async def default_parent(client: ApiClient, classifier: str) -> dict[str, Any]:
    """The group new user groups go under when no parent_uuid is given.

    LocationDevices: the single child of the ``Location`` root (``All
    Locations`` on every Crosswork seen); DeviceAccess / UserDefinedPorts:
    the root itself (``ALL-ACCESS`` / ``User Defined``). Anything else
    (several roots, several candidates) asks for an explicit parent_uuid.
    """
    roots = root_uuids(await client.request_json("GET", root_groups_url([classifier])))
    if len(roots) != 1:
        raise PlatformError(
            f"Could not pick a default parent for classifier {classifier}: the platform "
            f"answers {len(roots)} root group(s); pass parent_uuid explicitly."
        )
    data = await client.request_json(
        "GET", hierarchies_url(roots), params={"brief": "true", "direct": "true"}
    )
    entries = hierarchy_entries(data)
    root = entries[0] if entries else {"uuid": roots[0]}
    if classifier != "LocationDevices":
        return root
    children = _dicts(root.get("children"))
    if len(children) != 1:
        names = ", ".join(f"{c.get('name')} ({c.get('uuid')})" for c in children) or "none"
        raise PlatformError(
            f"Could not pick a default parent under the LocationDevices root: expected one "
            f"child ('All Locations'), found {names}; pass parent_uuid explicitly."
        )
    return children[0]


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
        verified live. Use it to explain an existing rule (cnc_list_group_rules)
        or to pick the attribute / operator names for the ``rule_conditions``
        of cnc_create_device_group / cnc_update_device_group, which validate
        against this very list before sending. Live 2026-09-15: the device
        attributes (hostname, node_ip, description, location, contact,
        product_type, product_family, product_series, software_type,
        software_version, reachability) are all ``STRING`` with SO_* operators
        (SO_Matches, SO_NotMatches, SO_Contains, SO_NotContains, SO_StartWith,
        SO_EndWith, SO_Equals, SO_NotEquals and, per attribute, SO_InRange /
        SO_Blank / SO_NotBlank; reachability only SO_Equals / SO_NotEquals);
        the port attributes are ``name``, ``admin_status``, ``type``,
        ``oper_status`` (STRING) and ``speed`` (``NUMBER`` with NO_Equals,
        NO_NotEquals, NO_GreaterThan, NO_GreaterThanOrEquals, NO_LessThan,
        NO_LessThanOrEquals). The kind is checked before anything is sent.

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
                    "A group rule is ONE <attribute> <operator> <value> condition over these "
                    "attributes (cnc_create_device_group / cnc_update_device_group "
                    "rule_conditions; a second condition breaks the member listing on "
                    "Crosswork 7.2.0). Only UserDefinedPorts rules are evaluated on this build.",
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

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_group_rules",
        title="List Group Rules",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_group_rules(
        classifier: Annotated[
            str,
            Field(
                description=(
                    "Classifier whose rules to list when no group_uuid is given: "
                    "'LocationDevices' (default), 'UserDefinedPorts' or 'PortType' (the "
                    "system port-type rules). E.g. 'UserDefinedPorts'."
                ),
                max_length=32,
            ),
        ] = "LocationDevices",
        group_uuid: Annotated[
            str,
            Field(
                description=(
                    "A group uuid to show THAT group's rule instead (e.g. "
                    "'210b6a29-e08c-4dc2-8d6d-560217fba6b6'); empty for the classifier list."
                ),
                max_length=255,
            ),
        ] = "",
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the membership rules of a classifier, or show the one rule a group
        carries — the "dynamic group" definition (attribute / operator / value
        conditions).

        Read-only. ``GET /crosswork/grouping/v1/grouping/rule/classifier/
        <classifier>`` answers a bare list of RuleDTOs ``[{uuid, ordering,
        name, classifier, active, conditions (a JSON string), targetGroupUuid}]``;
        ``GET .../rule/group/<uuid>`` answers ``{"status": "Success", "rule":
        {...}}`` or ``{"status": "Error", "error": "RULE_NOT_EXIST"}`` for a
        static group — and the SAME ``RULE_NOT_EXIST`` for an UNKNOWN group
        uuid (all verified live 2026-09-15), so "has no rule" never proves the
        group exists; cnc_get_group_details does. A rule belongs to exactly
        one target group. On the lab the ``PortType`` classifier carries the
        three system rules (Software Loopback, Ethernet CSMACD, MPLS Tunnel —
        one condition each); ``LocationDevices`` and ``UserDefinedPorts`` are
        empty until a rule is created with cnc_create_device_group /
        cnc_update_device_group. Note that on Crosswork 7.2.0 a LocationDevices
        rule is stored but not evaluated (see cnc_create_device_group) — the
        list shows the definition, not proof that members follow it — and a
        rule with two or more conditions (possible through the API or the UI)
        makes its group's member listing answer HTTP 500: such a rule is the
        first thing to suspect when cnc_list_group_ports fails.

        Args:
            classifier: 'LocationDevices' | 'UserDefinedPorts' | 'PortType'
                (case-insensitive); ignored when group_uuid is given.
            group_uuid: show this group's rule instead of a classifier list.
            response_format: markdown (one line per rule: name, uuid, active,
                target group, conditions as ``attr op 'value'``) or json
                (each rule as-is plus ``conditions_decoded``).

        Returns:
            str: Markdown, or JSON {"classifier"?: str, "group_uuid"?: str,
            "count": int, "items": [<rule + conditions_decoded>]}. "Group
            <uuid> has no rule (a static group — or an unknown uuid; ...)." /
            "No rules exist for classifier <c>." when empty (not errors —
            the platform answers RULE_NOT_EXIST for a typo'd group uuid too,
            so check the uuid with cnc_get_group_details when in doubt). "Error: Unknown rule
            classifier ..." (nothing sent); "Error: Group <uuid> rule read
            failed: ..." on another ``status: Error`` document; "Error: ..."
            on an HTTP failure.
        """
        try:
            uuid = group_uuid.strip()
            if uuid:
                rule = await rule_of_group(client, uuid)
                rules = [rule] if rule else []
                scope: dict[str, Any] = {"group_uuid": uuid}
                empty = (
                    f"Group {uuid} has no rule (a static group — or an unknown uuid: the "
                    "platform answers RULE_NOT_EXIST for both; cnc_get_group_details confirms "
                    "the group exists)."
                )
                head = f"# Rule of group {uuid}"
            else:
                wanted = canonical_choice(classifier, RULE_CLASSIFIERS, "rule classifier")
                data = await client.request_json("GET", rules_of_classifier_url(wanted))
                rules = rules_of(data, f"Rules of classifier {wanted} read")
                scope = {"classifier": wanted}
                empty = f"No rules exist for classifier {wanted}."
                head = f"# Rules of classifier {wanted} ({len(rules)})"
            if response_format is ResponseFormat.JSON:
                payload = {**scope, "count": len(rules), "items": [rule_view(r) for r in rules]}
                return finalize(to_json(payload), settings)
            if not rules:
                return finalize(empty, settings)
            lines = [head, ""]
            lines.extend(rule_line(r) for r in rules)
            lines.extend(
                [
                    "",
                    "target = the group the rule populates (cnc_get_group_details); a "
                    "LocationDevices rule is stored but not evaluated on Crosswork 7.2.0, a "
                    "UserDefinedPorts rule is (cnc_list_group_ports). A rule with 2+ "
                    "conditions breaks its group's member listing on this build (HTTP 500).",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_group_ports",
        title="List Group Ports",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_group_ports(
        group_uuid: Annotated[
            str,
            Field(
                description=(
                    "Port group uuid (a PortType or UserDefinedPorts group, e.g. "
                    "'1b1b59ab-abda-4130-9b7d-d7151a898891')."
                ),
                min_length=1,
                max_length=255,
            ),
        ],
        start: Annotated[
            int,
            Field(
                description="0-based start index of the ?start=&end= window (e.g. 0).",
                ge=0,
                le=MAX_DEVICE_END - 1,
            ),
        ] = DEFAULT_DEVICE_START,
        end: Annotated[
            int,
            Field(
                description="End index of the window, EXCLUSIVE (e.g. 100); must exceed start.",
                ge=1,
                le=MAX_DEVICE_END,
            ),
        ] = DEFAULT_DEVICE_END,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the ports that are members of a port group (one index window per call).

        Read-only. ``GET /crosswork/grouping/v1/grouping/port/<uuid>?start=<i>&
        end=<j>`` -> ``{"status": "Success", "ports": [{"portUuid",
        "deviceUuid", "node_ip", "hostName", "portName", "description",
        "speed", "type", "delete", "discoveryType"}], "total": N}`` (verified
        live 2026-09-15 on a UserDefinedPorts group populated by a rule: 5
        Loopback0 ports, each ``discoveryType: Dynamic``). This is how the
        members computed by a port rule are checked. Device groups answer no
        ports here — use cnc_list_group_devices for them. The window works
        like cnc_list_group_devices (``end`` exclusive, ``total`` = the whole
        group).

        Args:
            group_uuid: the port group uuid.
            start / end: the index window (end > start, end exclusive).
            response_format: markdown (one line per port) or json.

        Returns:
            str: Markdown "**host:port** (portUuid) device=... ip=... type=...
            speed=... discoveryType=..." lines, or JSON {"group_uuid", "status",
            "start", "end", "total", "count", "offset", "items": [<port>],
            "has_more", "next_offset", "window_full"}. "No ports are members
            of group <uuid> ..." when the window is empty (not an error).
            "Error: end must be greater than start" (nothing sent); "Error:
            Group ports read failed: ..." on a ``status: Error`` document;
            "Error: ..." on an HTTP failure.
        """
        try:
            uuid = group_uuid.strip()
            if not uuid:
                raise PlatformError("group_uuid must not be blank.")
            if end <= start:
                raise PlatformError("end must be greater than start (e.g. start=0, end=100).")
            params = {"start": start, "end": end}
            data = await client.request_json("GET", group_ports_url(uuid), params=params)
            result = check_result(data, "Group ports read")
            ports = _dicts(result.get("ports"))
            envelope = device_page(ports, as_count(result.get("total")), start, end)
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
            if not ports:
                text = f"No ports are members of group {uuid} in the index window {start}-{end}"
                if total:
                    text += f" (the platform reports {total} members; try an earlier window)"
                else:
                    text += (
                        " (a device group answers none here — cnc_list_group_devices; a "
                        "UserDefinedPorts group is populated by its rule)"
                    )
                return finalize(f"{text}.", settings)
            head = f"# Ports in group {uuid} ({envelope['count']}"
            if total is not None and total != envelope["count"]:
                head += f" of {total}"
            head += f"; indexes {start}-{end})"
            lines = [head, ""]
            lines.extend(port_line(p) for p in ports)
            if envelope["has_more"]:
                next_start = envelope["next_offset"]
                next_end = min(next_start + (end - start), MAX_DEVICE_END)
                lines.extend(
                    ["", f"More available: repeat with start={next_start}, end={next_end}."]
                )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_device_group",
        title="Create Device Group",
        read_only=False,
        idempotent=False,
        dry_run_hint=(
            "cnc_get_group_hierarchy (read-only) shows the tree the group would join and "
            "cnc_list_group_rule_conditions the rule vocabulary; a create has no preview"
        ),
    )
    async def cnc_create_device_group(
        name: Annotated[
            str,
            Field(
                description="Group name, unique within the classifier's tree (e.g. 'Paris PEs').",
                min_length=1,
                max_length=255,
            ),
        ],
        classifier: Annotated[
            str,
            Field(
                description=(
                    "Which tree: 'LocationDevices' (default — the device groups alarm "
                    "suppression and PM policies scope on; members are moved in), "
                    "'DeviceAccess' (an RBAC device-access group under ALL-ACCESS; members "
                    "are copied in) or 'UserDefinedPorts' (a port group; members come from "
                    "its rule). E.g. 'LocationDevices'."
                ),
                max_length=32,
            ),
        ] = "LocationDevices",
        description: Annotated[
            str,
            Field(
                description="Free-text description (e.g. 'Edge routers in Paris').", max_length=255
            ),
        ] = "",
        parent_uuid: Annotated[
            str,
            Field(
                description=(
                    "Parent group uuid; empty (default) picks the classifier's natural parent: "
                    "'All Locations' for LocationDevices, the ALL-ACCESS root for DeviceAccess, "
                    "the 'User Defined' root for UserDefinedPorts. Pass a user group's uuid to "
                    "nest under it (e.g. '7913c888-f691-4c08-ac71-55a35b236e49')."
                ),
                max_length=255,
            ),
        ] = "",
        rule_conditions: Annotated[
            str,
            Field(
                description=(
                    "Empty (default) for a static group. A JSON list with ONE condition (as "
                    'TEXT) makes the group rule-based: \'[{"attribute": "hostname", '
                    '"operator": "SO_StartWith", "value": "PE"}]\' (attributes and operators '
                    "from cnc_list_group_rule_conditions — device vocabulary for "
                    "LocationDevices, port vocabulary for UserDefinedPorts; 'StartWith' is "
                    "accepted for 'SO_StartWith'; numeric attributes such as port 'speed' take "
                    "NO_* operators). A second condition is refused: it breaks the group's "
                    "member listing on Crosswork 7.2.0. NOT for DeviceAccess groups."
                ),
                max_length=20000,
            ),
        ] = "",
    ) -> str:
        """Create a user group — a static device group, an RBAC device-access
        group, or a rule-based (dynamic) group — under a classifier's tree.

        Write. Sends ``POST /crosswork/grouping/v1/grouping/group {"classifier",
        "name", "description", "parentUuid"}`` -> ``{"status": "Success",
        "group": {uuid, name, description, nodeType: "Group", classifier}}``
        (verified live 2026-09-15 for all three classifiers; the echo carries
        no discoveryType / parentUuid — cnc_get_group_details does). The new
        group is ``discoveryType: Static`` and EMPTY: a LocationDevices group is
        filled by moving devices into it (cnc_set_device_group_members, or
        cnc_move_group_members from the leaf that holds them — ``Unassigned
        Devices`` for devices never placed), a DeviceAccess group by copying
        them (cnc_set_device_group_members does that too). ``parentUuid`` is
        mandatory on the wire; when parent_uuid is empty the tool resolves the
        classifier's natural parent with two reads (root uuid + its direct
        children) before creating anything.

        With ``rule_conditions`` the tool ALSO sends ``POST .../rule
        {"classifier", "name": <group name>, "targetGroupUuid": <new uuid>,
        "active": true, "ordering": 0, "conditions": "<JSON string>"}`` ->
        ``{"status": "Success", "rule": {uuid, ...}}``. The conditions are
        validated against the live ``rule/conditions`` vocabulary FIRST (the
        platform accepts an unknown attribute silently and answers 500 for an
        unknown operator), and if the rule call fails the just-created group is
        deleted again so a failed create leaves nothing behind — and when that
        rollback itself fails (a refusal, or the platform unreachable) the
        error still names the orphaned group uuid and cnc_delete_device_group
        as the way to remove it. ONE condition
        per rule: a rule with two or more is accepted by the platform but its
        group's member listing then answers HTTP 500 until the rule is back to
        one (verified live on 7.2.0 for string+string and string+numeric in
        either order), so the tool refuses a second condition. A rule on a
        **UserDefinedPorts** group is evaluated within seconds (verified: ``name
        SO_Contains Loopback`` matched 5 ports, ``speed NO_GreaterThan 5`` the
        20 Ethernet/Mgmt ports; see cnc_list_group_ports). A
        rule on a **LocationDevices** group is stored and readable
        (cnc_list_group_rules) but was NEVER evaluated on Crosswork 7.2.0 (0
        members after 150 s, group still Static, no evaluate endpoint, no
        ``rule`` operation flag) — populate device groups by moving devices in,
        and treat a device rule as documentation of intent. Rules are refused
        for DeviceAccess groups (nothing sent).

        Not idempotent: a repeat with the same name is refused with
        ``NAME_ALREADY_EXIST`` (names are unique per classifier tree).

        Args:
            name: unique group name.
            classifier: 'LocationDevices' | 'DeviceAccess' | 'UserDefinedPorts'
                (case-insensitive).
            description: free text (kept verbatim; the platform allows 255 chars).
            parent_uuid: parent group uuid (empty = the natural parent).
            rule_conditions: '' (static) or a JSON list of {attribute, operator,
                value} objects.

        Returns:
            str: "Group '<name>' (<uuid>) created under <parent name> (<parent
            uuid>) as a static|rule-based <classifier> group." plus JSON
            {"group": {<platform echo>}, "parent": {"uuid", "name"?},
            "classifier": str, "rule": {<rule echo> + "conditions_decoded"} |
            null, "note": str}. "Error: Create group '<name>' failed:
            NAME_ALREADY_EXIST Hint: ..." / "... INVALID_PARENT_GROUP Hint: ..."
            on a platform refusal (HTTP 200 status Error); "Error:
            rule_conditions[0]: unknown attribute ..." (nothing sent); "Error:
            Create rule for group '<name>' failed: <reason> The group <uuid>
            was deleted again." when the rule step fails, or "... could NOT be
            deleted again (<why>) — remove it with cnc_delete_device_group."
            when the rollback fails too (the uuid is always named); "Error:
            ..." on an HTTP failure.
        """
        try:
            wanted = canonical_choice(classifier, WRITABLE_CLASSIFIERS, "group classifier")
            group_name = name.strip()
            if not group_name:
                raise PlatformError("name must not be blank.")
            conditions: list[dict[str, Any]] = []
            if rule_conditions.strip():
                vocabulary = await rule_vocabulary(client, wanted)
                conditions = parse_rule_conditions(rule_conditions, vocabulary)
                if not conditions:
                    raise PlatformError(
                        "rule_conditions is an empty list: leave it empty for a static group "
                        "or give at least one condition."
                    )
            parent: dict[str, Any]
            if parent_uuid.strip():
                parent = {"uuid": parent_uuid.strip()}
            else:
                parent = await default_parent(client, wanted)
            body = {
                "classifier": wanted,
                "name": group_name,
                "description": description.strip(),
                "parentUuid": parent["uuid"],
            }
            data = await client.request_json("POST", GROUP_PATH, json_body=body)
            result = check_result(data, f"Create group '{group_name}'")
            group = result.get("group") if isinstance(result.get("group"), dict) else {}
            uuid = str(group.get("uuid") or "")
            if not uuid:
                raise shape_error(
                    f"Create group '{group_name}'", '{"group": {"uuid": ...}}', result
                )
            rule: dict[str, Any] | None = None
            if conditions:
                rule_body = {
                    "classifier": wanted,
                    "name": group_name,
                    "targetGroupUuid": uuid,
                    "active": True,
                    "ordering": 0,
                    "conditions": conditions_payload(conditions),
                }
                try:
                    rule_data = await client.request_json("POST", RULE_PATH, json_body=rule_body)
                    rule_result = check_result(rule_data, f"Create rule for group '{group_name}'")
                    rule = (
                        rule_result.get("rule") if isinstance(rule_result.get("rule"), dict) else {}
                    )
                except Exception as rule_error:
                    # The rollback must never mask the rule error: a transport failure
                    # here (client.request raises even with raise_on_error=False once the
                    # retries are spent) is reported as "could NOT be deleted", uuid named.
                    cleaned, why = False, ""
                    try:
                        cleanup = await client.request(
                            "DELETE", group_url(uuid), raise_on_error=False
                        )
                        code = error_code_of(response_json(cleanup))
                        cleaned = cleanup.is_success and code is None
                        if not cleaned:
                            why = code or f"HTTP {cleanup.status_code}"
                    except Exception as cleanup_error:
                        why = str(cleanup_error)[:200]
                        logger.warning(
                            "Rollback DELETE of group %s after a failed rule create raised: %s",
                            uuid,
                            cleanup_error,
                        )
                    raise PlatformError(
                        f"{rule_error} The group {uuid} "
                        + (
                            "was deleted again."
                            if cleaned
                            else f"could NOT be deleted again ({why}) — remove it with "
                            "cnc_delete_device_group."
                        )
                    ) from rule_error
            kind = "rule-based" if rule is not None else "static"
            parent_text = f"{parent.get('name') or 'parent'} ({parent['uuid']})"
            text = (
                f"Group '{group_name}' ({uuid}) created under {parent_text} as a {kind} "
                f"{wanted} group."
            )
            if wanted == "UserDefinedPorts":
                note = (
                    "Port group: members come from its rule (cnc_list_group_ports shows them "
                    "within seconds of the rule being set)."
                    if rule is not None
                    else "Port group with no rule: set one with cnc_update_device_group "
                    "rule_conditions=... to populate it."
                )
            elif wanted == "DeviceAccess":
                note = (
                    "Access group is empty: cnc_set_device_group_members copies devices into "
                    "it from their LocationDevices leaf."
                )
            elif rule is not None:
                note = (
                    "The rule is stored but Crosswork 7.2.0 does NOT evaluate LocationDevices "
                    "rules (verified live: no member ever joined); add members with "
                    "cnc_set_device_group_members."
                )
            else:
                note = (
                    "The group is empty: cnc_set_device_group_members moves devices into it "
                    "(from Unassigned Devices or whichever location group holds them)."
                )
            payload = {
                "group": group,
                "parent": parent,
                "classifier": wanted,
                "rule": rule_view(rule) if rule else None,
                "note": note,
            }
            return finalize(f"{text}\n{note}\n\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_device_group",
        title="Update Device Group",
        read_only=False,
        destructive=True,
        idempotent=True,
        dry_run_hint=(
            "cnc_get_group_details and cnc_list_group_rules (read-only) show the group and "
            "rule the update would change"
        ),
    )
    async def cnc_update_device_group(
        group_uuid: Annotated[
            str,
            Field(
                description="Uuid of the USER group to update (from cnc_create_device_group / "
                "cnc_get_group_hierarchy), e.g. '22b69d42-4bd4-4636-bbce-ae2786ac5956'. "
                "Platform-managed groups are refused with nothing sent: the StaticSystem "
                "ones (roots, All Locations, Unassigned Devices, ALL-ACCESS) and the Dynamic "
                "PortType / TopologyTypeDevices groups, which carry no 'upd' operation.",
                min_length=1,
                max_length=255,
            ),
        ],
        name: Annotated[
            str,
            Field(
                description="New name (e.g. 'Paris PEs'); empty keeps the current one.",
                max_length=255,
            ),
        ] = "",
        description: Annotated[
            str,
            Field(
                description="New description (e.g. 'Edge routers in Paris'); empty keeps the "
                "current one — pass clear_description=true to blank it.",
                max_length=255,
            ),
        ] = "",
        clear_description: Annotated[
            bool,
            Field(description="True to clear the description (description must be empty then)."),
        ] = False,
        parent_uuid: Annotated[
            str,
            Field(
                description="New parent group uuid to move the group under; empty keeps it.",
                max_length=255,
            ),
        ] = "",
        rule_conditions: Annotated[
            str,
            Field(
                description=(
                    "Rule change as TEXT: empty (default) leaves the rule alone; a JSON list "
                    'with ONE condition (\'[{"attribute": "hostname", "operator": '
                    '"SO_StartWith", "value": "PE"}]\') replaces the group\'s rule (or '
                    "creates one); '[]' removes it (the group becomes plain static). A second "
                    "condition is refused (it breaks the member listing on 7.2.0). Not for "
                    "DeviceAccess groups."
                ),
                max_length=20000,
            ),
        ] = "",
        rule_active: Annotated[
            bool | None,
            Field(
                description="Set the rule's active flag (true/false); omit to keep it. Needs an "
                "existing rule unless rule_conditions creates one in the same call."
            ),
        ] = None,
    ) -> str:
        """Rename, re-describe or re-parent a user group, and/or set, replace,
        deactivate or remove its membership rule.

        DESTRUCTIVE write (the PUT is a full replace of name / description /
        parent, and ``rule_conditions='[]'`` deletes the group's rule). Reads
        ``group/<uuid>/details`` first — platform-managed groups are refused
        with nothing sent: the ``StaticSystem`` ones (the roots, All Locations,
        Unassigned Devices, ALL-ACCESS, User Defined) AND the ``Dynamic``
        ``PortType`` port-type groups (Software Loopback, Ethernet CSMACD, MPLS
        Tunnel, each fed by a system rule that classifies every such port
        platform-wide) and ``TopologyTypeDevices`` AS / IGP-domain auto-groups,
        which the platform derives and lists without an ``upd`` operation
        (verified live 2026-09-15) — then, when name / description / parent
        change, sends ``PUT /crosswork/grouping/v1/grouping/group/<uuid>
        {"name", "description", "parentUuid"}`` -> ``{"status": "Success",
        "group": {...}}``. The PUT is a FULL REPLACE that requires ``name`` and
        ``parentUuid`` (a body without them is HTTP 400) and clears
        ``description`` when it is absent (verified live 2026-09-15) — which is
        why the tool re-sends the current values it keeps. Renaming to a
        system group's name is refused with ``RESERVED_GROUP_NAME``.

        Rule handling (``rule_conditions`` / ``rule_active``): the group's rule
        is looked up with ``GET .../rule/group/<uuid>``; new conditions are
        validated against the live vocabulary before anything is sent, then
        ``PUT .../rule/<rule uuid>`` (full RuleDTO: uuid, classifier, name,
        targetGroupUuid, active, ordering, conditions — a body with only
        ``conditions`` is HTTP 400) replaces an existing rule or ``POST
        .../rule`` creates one; ``'[]'`` sends ``DELETE .../rule/<rule uuid>``
        (``{"status": "Success"}``; the group stays, its members stay). A
        UserDefinedPorts rule re-evaluates within seconds; a LocationDevices
        rule is stored but NOT evaluated on Crosswork 7.2.0 (see
        cnc_create_device_group). Members are not touched by this tool —
        cnc_set_device_group_members does that.

        Order of the writes: the group PUT first, then the rule call. Both are
        validated before the first write (bad conditions send nothing), but a
        platform refusal on the rule step after a successful group PUT leaves
        the group change applied — the error then says so ("the group change
        was already applied: renamed ...") so a retry re-sends only the rule.

        Idempotent: re-sending the same values changes nothing (the tool skips
        the group PUT when nothing differs).

        Args:
            group_uuid: the user group's uuid.
            name / description / clear_description / parent_uuid: the fields
                to change (see each; empty = keep).
            rule_conditions: '' (keep) | JSON list (set / replace) | '[]'
                (remove), as TEXT.
            rule_active: true / false to (de)activate the rule; omit to keep it.

        Returns:
            str: "Group '<name>' (<uuid>) updated: <change>, <change>." plus
            JSON {"group": {<details after the update>}, "changes": [str],
            "rule": {<rule> + "conditions_decoded"} | null}. "Group ... is
            already as requested (no change)." when nothing differs. "Error:
            Group ... is a system group ... cannot be updated" / "Error: Group
            ... is a platform-managed PortType group ... cannot be updated" /
            "Error: Group ... cannot be updated: the platform lists no 'upd'
            operation for it" (all nothing sent); "Error: Update group <uuid>
            failed: RESERVED_GROUP_NAME Hint: ..." (nothing changed); "Error:
            Update rule <uuid> failed: <reason> (the group change was already
            applied: renamed ...)" when the rule step is refused AFTER the group
            PUT succeeded; "Error: Group <uuid> has no rule to (de)activate
            ..."; "Error: rule_conditions[0]: unknown operator ..." (nothing
            sent); "Error: Group <uuid> details read failed: GROUP_NOT_EXIST
            ..." for an unknown uuid; "Error: ..." on an HTTP failure.
        """
        try:
            uuid = group_uuid.strip()
            if not uuid:
                raise PlatformError("group_uuid must not be blank.")
            group = await read_group(client, uuid)
            refuse_system_group(group, "updated")
            classifier = str(group.get("classifier") or "")
            current_name = str(group.get("name") or "")
            current_description = str(group.get("description") or "")
            current_parent = str(group.get("parentUuid") or "")
            new_name = name.strip() or current_name
            if clear_description and description.strip():
                raise PlatformError("Pass either description or clear_description=true, not both.")
            new_description = (
                "" if clear_description else (description.strip() or current_description)
            )
            new_parent = parent_uuid.strip() or current_parent
            if not new_parent:
                raise PlatformError(
                    f"Group '{current_name}' ({uuid}) has no parent (a root group); only "
                    "groups below a root can be updated here."
                )
            group_changed = (
                new_name != current_name
                or new_description != current_description
                or new_parent != current_parent
            )
            # Everything the rule step needs is resolved BEFORE the first write so a bad
            # condition cannot leave a renamed group with an unchanged rule.
            rule_action: str | None = None
            current_rule: dict[str, Any] | None = None
            new_conditions: list[dict[str, Any]] = []
            rule_text = rule_conditions.strip()
            remove_rule = rule_text in ("[]", "{}", '{"conditions": []}')
            if rule_text or rule_active is not None:
                current_rule = await rule_of_group(client, uuid)
                if rule_text and not remove_rule:
                    vocabulary = await rule_vocabulary(client, classifier)
                    new_conditions = parse_rule_conditions(rule_conditions, vocabulary)
                    if not new_conditions:
                        remove_rule = True
                if remove_rule:
                    rule_action = "remove" if current_rule else "none"
                    if rule_active is not None and not current_rule:
                        raise PlatformError(
                            f"Group {uuid} has no rule to set active={rule_active} on "
                            "(and rule_conditions removes rather than creates one)."
                        )
                elif new_conditions:
                    rule_action = "replace" if current_rule else "create"
                elif rule_active is not None:
                    if not current_rule:
                        raise PlatformError(
                            f"Group {uuid} has no rule to set active={rule_active} on; pass "
                            "rule_conditions to create one."
                        )
                    rule_action = "activate"
            changes: list[str] = []
            if group_changed:
                body = {"name": new_name, "description": new_description, "parentUuid": new_parent}
                data = await client.request_json("PUT", group_url(uuid), json_body=body)
                check_result(data, f"Update group {uuid}")
                if new_name != current_name:
                    changes.append(f"renamed '{current_name}' -> '{new_name}'")
                if new_description != current_description:
                    changes.append(
                        "description cleared" if not new_description else "description set"
                    )
                if new_parent != current_parent:
                    changes.append(f"moved under {new_parent}")
            rule: dict[str, Any] | None = current_rule
            try:
                if rule_action == "remove" and current_rule:
                    rule_uuid = str(current_rule.get("uuid") or "")
                    data = await client.request_json("DELETE", rule_url(rule_uuid))
                    check_result(data, f"Delete rule {rule_uuid}")
                    rule = None
                    changes.append(f"rule {rule_uuid} removed (the group is static now)")
                elif rule_action in ("replace", "create", "activate"):
                    base = current_rule or {}
                    rule_body: dict[str, Any] = {
                        "classifier": classifier,
                        "name": str(base.get("name") or new_name),
                        "targetGroupUuid": uuid,
                        "active": rule_active
                        if rule_active is not None
                        else bool(base.get("active", True)),
                        "ordering": base.get("ordering", 0),
                        "conditions": conditions_payload(new_conditions)
                        if new_conditions
                        else str(base.get("conditions") or conditions_payload([])),
                    }
                    if current_rule:
                        rule_uuid = str(current_rule.get("uuid") or "")
                        rule_body["uuid"] = rule_uuid
                        data = await client.request_json(
                            "PUT", rule_url(rule_uuid), json_body=rule_body
                        )
                        what = f"Update rule {rule_uuid}"
                    else:
                        data = await client.request_json("POST", RULE_PATH, json_body=rule_body)
                        what = f"Create rule for group {uuid}"
                    result = check_result(data, what)
                    rule = result.get("rule") if isinstance(result.get("rule"), dict) else rule_body
                    if rule_action == "create":
                        changes.append(f"rule created: {rule_summary(rule)}")
                    elif rule_action == "replace":
                        changes.append(f"rule replaced: {rule_summary(rule)}")
                    if rule_active is not None:
                        changes.append(f"rule active={rule_active}")
            except Exception as rule_error:
                # The group PUT (if any) has already been applied: say so, so the agent
                # neither retries the rename nor believes nothing changed.
                if changes:
                    raise PlatformError(
                        f"{rule_error} (the group change was already applied: {'; '.join(changes)})"
                    ) from rule_error
                raise
            after = await read_group(client, uuid)
            payload = {
                "group": after,
                "changes": changes,
                "rule": rule_view(rule) if rule else None,
            }
            if not changes:
                text = f"Group '{current_name}' ({uuid}) is already as requested (no change)."
            else:
                text = f"Group '{new_name}' ({uuid}) updated: {'; '.join(changes)}."
                if (
                    rule
                    and classifier == "LocationDevices"
                    and rule_action in ("create", "replace")
                ):
                    text += (
                        " Note: Crosswork 7.2.0 stores but does not evaluate LocationDevices "
                        "rules — members still come from cnc_set_device_group_members."
                    )
            return finalize(f"{text}\n\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_device_group",
        title="Delete Device Group",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_device_group(
        group_uuid: Annotated[
            str,
            Field(
                description="Uuid of the USER group to delete (e.g. "
                "'22b69d42-4bd4-4636-bbce-ae2786ac5956'). Platform-managed groups are "
                "refused with nothing sent: the StaticSystem ones (roots, All Locations, "
                "Unassigned Devices, ALL-ACCESS) and the Dynamic PortType (Software Loopback, "
                "Ethernet CSMACD, MPLS Tunnel) / TopologyTypeDevices (AS, IGP Domain) groups, "
                "which carry no 'del' operation.",
                min_length=1,
                max_length=255,
            ),
        ],
    ) -> str:
        """Delete a user group (device, access or port group) with everything
        it carries: its members are released and its rule is removed.

        DESTRUCTIVE write. Reads the group's details, members and rule first —
        a platform-managed group is refused with nothing sent: the
        ``StaticSystem`` ones (Unassigned Devices, All Locations, ALL-ACCESS,
        User Defined, the roots) AND the ``discoveryType: Dynamic`` groups of
        the ``PortType`` classifier (Software Loopback, Ethernet CSMACD, MPLS
        Tunnel — each fed by a system rule that classifies every such port
        platform-wide) and of ``TopologyTypeDevices`` (AS / <asn> / IGP Domain
        / <id>), which the platform derives and lists without a ``del``
        operation (verified live 2026-09-15; whether Crosswork would refuse the
        DELETE on the wire is deliberately unverified) — then sends
        ``DELETE /crosswork/grouping/v1/grouping/group/<uuid>`` -> ``{"status":
        "Success", "group": {uuid, name, nodeType, classifier}}`` (verified
        live 2026-09-15). Effects seen live: devices of a LocationDevices group
        land back in ``Unassigned Devices``; devices of a DeviceAccess group
        simply lose that access-group membership; the group's rule is deleted
        with it (``GET rule/<uuid>`` answers an empty body afterwards, a DELETE
        of it ``RULE_NOT_EXIST``); sub-groups were not exercised — delete the
        leaves first to be safe. Alarm suppression policies and PM monitoring
        policies that scope on the group's uuid keep a dangling reference —
        check cnc_list_alarm_suppression_policies / cnc_list_monitoring_
        policies before deleting a group they use. An unknown or already-
        deleted uuid answers ``GROUP_NOT_EXIST`` (reported as an error, so a
        repeat is harmless but not silent).

        Args:
            group_uuid: the user group's uuid.

        Returns:
            str: "Group '<name>' (<uuid>, <classifier>) deleted; <n> member(s)
            released [to Unassigned Devices]; rule <uuid> deleted with it."
            plus JSON {"deleted": {<platform echo>}, "classifier": str,
            "members_released": [{"uuid", "hostname"}], "rule_deleted": {<rule>}
            | null}. "Error: Group ... is a system group ... cannot be deleted"
            / "Error: Group ... is a platform-managed PortType group ... cannot
            be deleted" / "Error: Group ... cannot be deleted: the platform
            lists no 'del' operation for it" (all nothing sent); "Error: Group
            <uuid> details read failed: GROUP_NOT_EXIST Hint: ..." for an
            unknown uuid; "Error: Delete group <uuid> failed: <reason>";
            "Error: ..." on an HTTP failure.
        """
        try:
            uuid = group_uuid.strip()
            if not uuid:
                raise PlatformError("group_uuid must not be blank.")
            group = await read_group(client, uuid)
            refuse_system_group(group, "deleted")
            classifier = str(group.get("classifier") or "")
            members: list[dict[str, Any]] = []
            if classifier in ("LocationDevices", "DeviceAccess"):
                members = await all_group_devices(client, uuid)
            rule = (
                await rule_of_group(client, uuid) if classifier in RULE_KIND_OF_CLASSIFIER else None
            )
            data = await client.request_json("DELETE", group_url(uuid))
            result = check_result(data, f"Delete group {uuid}")
            echo = result.get("group") if isinstance(result.get("group"), dict) else {}
            released = [member_brief(d) for d in members]
            text = f"Group '{group.get('name')}' ({uuid}, {classifier}) deleted"
            if released:
                names = ", ".join(str(m["hostname"] or m["uuid"]) for m in released)
                text += f"; {len(released)} member(s) released ({names})"
                if classifier == "LocationDevices":
                    text += " — they are back in Unassigned Devices"
            if rule:
                text += f"; rule {rule.get('uuid')} deleted with it"
            payload = {
                "deleted": echo,
                "classifier": classifier,
                "members_released": released,
                "rule_deleted": rule_view(rule) if rule else None,
            }
            return finalize(f"{text}.\n\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_set_device_group_members",
        title="Set Device Group Members",
        read_only=False,
        destructive=True,
        idempotent=True,
        dry_run_hint=(
            "cnc_list_group_devices (read-only) shows the members the change would replace, "
            "add to or remove"
        ),
    )
    async def cnc_set_device_group_members(
        group_uuid: Annotated[
            str,
            Field(
                description="Uuid of the USER device group (LocationDevices or DeviceAccess) "
                "whose membership to change, e.g. '22b69d42-4bd4-4636-bbce-ae2786ac5956'. "
                "Platform-managed groups (StaticSystem such as Unassigned Devices, and the "
                "Dynamic PortType / TopologyTypeDevices groups, which carry no 'upd' "
                "operation) are refused with nothing sent.",
                min_length=1,
                max_length=255,
            ),
        ],
        devices: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated devices by host name or inventory uuid (e.g. 'PE1,PE2'). "
                    "For mode 'replace' this is the COMPLETE wanted membership ('' empties "
                    "the group); for 'add' / 'remove' the devices to add / remove."
                ),
                max_length=100000,
            ),
        ],
        mode: Annotated[
            str,
            Field(
                description="'replace' (default: the group ends up with exactly these devices), "
                "'add' (these join, others stay) or 'remove' (these leave).",
                max_length=16,
            ),
        ] = "replace",
    ) -> str:
        """Make a device group hold exactly (or additionally, or no longer) the
        given devices — the "set members" operation the platform has no
        single call for.

        DESTRUCTIVE write: mode 'replace' removes every member not listed
        (``devices=''`` empties the group) and 'remove' takes members away; a
        device removed from a LocationDevices group is back in Unassigned
        Devices. The grouping service offers only REMOVE (``PUT /crosswork/
        grouping/v1/grouping/group/<uuid>/members {"references": [uuids]}``)
        and MOVE / COPY from a source group (``POST .../group/member/move`` and
        ``.../member/copy {"groupUuid": <source>, "newGroupUuid": <target>,
        "references": [uuids]}``), and the source MUST be the exact
        LocationDevices leaf that holds each device today (a parent such as
        'All Locations' is refused with INVALID_OPERATION / MEMBER_NOT_EXIST) —
        all verified live 2026-09-15. So this tool: reads the group
        (platform-managed groups refused with nothing sent — StaticSystem such
        as Unassigned Devices, and the Dynamic PortType / TopologyTypeDevices
        groups, which carry no ``upd`` operation; port groups refused — their
        members come from a rule), lists its current members, resolves every
        device name / uuid, finds
        the LocationDevices leaf of each device to add by walking the Location
        tree and listing its groups' members, computes the difference, and
        only then writes: removals with one PUT, additions with one move (a
        LocationDevices target) or copy (a DeviceAccess target) per source
        leaf. Nothing is written when a device cannot be resolved. Effects:
        a device removed from a LocationDevices group is back in ``Unassigned
        Devices`` (every device sits in exactly one Location leaf; moving it
        here takes it out of the leaf it was in); a device removed from a
        DeviceAccess group stays where it is in the Location tree. Idempotent:
        re-running with the same list changes nothing.

        Cost: 3 reads + one member listing per Location group visited (the
        walk stops as soon as every device to add is found) + the writes + one
        read-back.

        Args:
            group_uuid: the user device group's uuid.
            devices: comma-separated host names and/or uuids ('' only with
                mode 'replace' = empty the group).
            mode: 'replace' | 'add' | 'remove' (case-insensitive).

        Returns:
            str: "Group '<name>' (<uuid>): added <hosts> (from <leaf>), removed
            <hosts>; members now: <hosts>." plus JSON {"group_uuid", "group_name",
            "classifier", "mode", "added": [{"uuid", "hostname",
            "from_group_uuid", "from_group_name"}], "removed": [{"uuid",
            "hostname"}], "kept": [{"uuid", "hostname"}], "members_after":
            [{"uuid", "hostname"}]}. "... already as requested (no change)."
            when nothing differs. "Error: Unknown mode ..." / "Error: devices
            must name at least one value" (nothing sent); "Error: Group ... is
            a system group ..." / "Error: Group <uuid> is a UserDefinedPorts
            group ..." (nothing sent); "Error: not members of group <uuid>:
            <names>" (mode remove; nothing sent); "Error: no LocationDevices
            group holds: <names> — unknown host names / uuids?" (nothing sent);
            "Error: Move members into <uuid> failed: MEMBER_NOT_EXIST Hint: ..."
            on a platform refusal; "Error: ..." on an HTTP failure.
        """
        try:
            wanted_mode = canonical_choice(mode, MEMBER_MODES, "mode")
            uuid = group_uuid.strip()
            if not uuid:
                raise PlatformError("group_uuid must not be blank.")
            tokens = [t.strip() for t in (devices or "").split(",") if t.strip()]
            if not tokens and wanted_mode != "replace":
                raise PlatformError("devices must name at least one value (comma-separated).")
            if len(tokens) > MAX_MEMBER_REFERENCES:
                raise PlatformError(f"devices: at most {MAX_MEMBER_REFERENCES} per call.")
            group = await read_group(client, uuid)
            refuse_system_group(group, "changed")
            classifier = str(group.get("classifier") or "")
            if classifier not in MEMBER_CLASSIFIERS:
                raise PlatformError(
                    f"Group {uuid} is a {classifier or 'non-device'} group; its members are "
                    "not devices (a port group is populated by its rule — "
                    "cnc_update_device_group rule_conditions=...)."
                )
            current = await all_group_devices(client, uuid)
            resolved_current, not_members = match_devices(tokens, current)
            located: dict[str, dict[str, Any]] = {}
            if wanted_mode == "remove":
                if not_members:
                    members_text = ", ".join(
                        device_hostname(d) or str(d.get("uuid")) for d in current
                    )
                    raise PlatformError(
                        f"not members of group {uuid}: {', '.join(not_members)} (current "
                        f"members: {members_text or 'none'})."
                    )
            elif not_members:
                located, unresolved = await locate_devices(client, not_members)
                if unresolved:
                    raise PlatformError(
                        f"no LocationDevices group holds: {', '.join(unresolved)} — unknown "
                        "host names / uuids? (cnc_list_devices shows the inventory)."
                    )
            wanted_uuids = {str(d.get("uuid")) for d in resolved_current.values()} | {
                str(entry["device"].get("uuid")) for entry in located.values()
            }
            if wanted_mode == "remove":
                to_remove = list(resolved_current.values())
            elif wanted_mode == "replace":
                to_remove = [d for d in current if str(d.get("uuid")) not in wanted_uuids]
            else:
                to_remove = []
            kept = [
                d
                for d in current
                if str(d.get("uuid")) not in {str(r.get("uuid")) for r in to_remove}
            ]
            # Deduplicate additions (a device named twice) and group them by source leaf.
            additions: dict[str, dict[str, Any]] = {}
            for entry in located.values():
                additions.setdefault(str(entry["device"].get("uuid")), entry)
            by_source: dict[str, list[dict[str, Any]]] = {}
            for entry in additions.values():
                by_source.setdefault(str(entry["group_uuid"]), []).append(entry)
            if not to_remove and not additions:
                payload = {
                    "group_uuid": uuid,
                    "group_name": group.get("name"),
                    "classifier": classifier,
                    "mode": wanted_mode,
                    "added": [],
                    "removed": [],
                    "kept": [member_brief(d) for d in kept],
                    "members_after": [member_brief(d) for d in current],
                }
                return finalize(
                    f"Group '{group.get('name')}' ({uuid}) is already as requested (no change).\n\n"
                    f"{to_json(payload)}",
                    settings,
                )
            if to_remove:
                references = sorted({str(d.get("uuid")) for d in to_remove if d.get("uuid")})
                data = await client.request_json(
                    "PUT", group_members_url(uuid), json_body={"references": references}
                )
                check_result(data, f"Remove members from group {uuid}")
            operation = "copy" if classifier == "DeviceAccess" else "move"
            for source_uuid, entries in by_source.items():
                references = sorted({str(e["device"].get("uuid")) for e in entries})
                body = {"groupUuid": source_uuid, "newGroupUuid": uuid, "references": references}
                data = await client.request_json(
                    "POST", MEMBER_OPERATION_PATHS[operation], json_body=body
                )
                check_result(data, f"{operation.capitalize()} members into group {uuid}")
            after = await all_group_devices(client, uuid)
            added = [
                {
                    **member_brief(entry["device"]),
                    "from_group_uuid": entry["group_uuid"],
                    "from_group_name": entry["group_name"],
                }
                for entry in additions.values()
            ]
            removed = [member_brief(d) for d in to_remove]
            parts: list[str] = []
            if added:
                sources = sorted({str(a["from_group_name"] or a["from_group_uuid"]) for a in added})
                parts.append(
                    f"{'copied in' if operation == 'copy' else 'added'} "
                    f"{', '.join(str(a['hostname'] or a['uuid']) for a in added)} "
                    f"(from {', '.join(sources)})"
                )
            if removed:
                parts.append(
                    f"removed {', '.join(str(r['hostname'] or r['uuid']) for r in removed)}"
                    + (" (back in Unassigned Devices)" if classifier == "LocationDevices" else "")
                )
            members_now = (
                ", ".join(device_hostname(d) or str(d.get("uuid")) for d in after) or "none"
            )
            text = (
                f"Group '{group.get('name')}' ({uuid}): {'; '.join(parts)}; "
                f"members now: {members_now}."
            )
            payload = {
                "group_uuid": uuid,
                "group_name": group.get("name"),
                "classifier": classifier,
                "mode": wanted_mode,
                "added": added,
                "removed": removed,
                "kept": [member_brief(d) for d in kept],
                "members_after": [member_brief(d) for d in after],
            }
            return finalize(f"{text}\n\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_move_group_members",
        title="Move or Copy Group Members",
        read_only=False,
        idempotent=False,
        dry_run_hint=(
            "cnc_list_group_devices (read-only) on the source and target shows what a move "
            "or copy would change"
        ),
    )
    async def cnc_move_group_members(
        source_group_uuid: Annotated[
            str,
            Field(
                description=(
                    "Uuid of the group that holds the devices NOW — the exact LocationDevices "
                    "leaf (e.g. 'Unassigned Devices' c820712b-460b-439f-b184-6fa159ae6a7c "
                    "for devices never placed), not a parent."
                ),
                min_length=1,
                max_length=255,
            ),
        ],
        target_group_uuid: Annotated[
            str,
            Field(
                description="Uuid of the group to move / copy them into (a LocationDevices group "
                "for a move, a DeviceAccess group for a copy).",
                min_length=1,
                max_length=255,
            ),
        ],
        devices: Annotated[
            str,
            Field(
                description="Comma-separated devices by host name or uuid, all members of the "
                "source group (e.g. 'PE1,PE2').",
                min_length=1,
                max_length=100000,
            ),
        ],
        operation: Annotated[
            str,
            Field(
                description="'move' (default: LocationDevices -> LocationDevices; the devices "
                "leave the source) or 'copy' (LocationDevices leaf -> DeviceAccess group; the "
                "devices stay in the source).",
                max_length=16,
            ),
        ] = "move",
    ) -> str:
        """Move devices between two location groups, or copy them from a
        location group into a device-access group — the raw member operation
        (cnc_set_device_group_members finds the source for you).

        Write. Sends ``POST /crosswork/grouping/v1/grouping/group/member/move``
        or ``.../member/copy {"groupUuid": <source>, "newGroupUuid": <target>,
        "references": [device uuids]}`` -> ``{"status": "Success"}`` (verified
        live 2026-09-15). Platform rules seen live: the SOURCE must be the
        exact leaf that holds each device (``MEMBER_NOT_EXIST`` otherwise —
        also for a device already moved; ``INVALID_OPERATION`` when the source
        is a parent such as 'All Locations'); a move into a DeviceAccess group
        is ``INVALID_OPERATION`` (copy instead); a copy out of a DeviceAccess
        group is ``INVALID_OPERATION`` (the document: copy is only from
        LocationDevices into DeviceAccess); a copy of a device that is already
        in the target answers Success (idempotent), a repeated move does not.
        The tool lists the source group's members first and refuses unknown
        names / uuids before sending (the platform answers 500 for an unknown
        target group and an empty reference list — both caught earlier here).
        The target's details are read too, so an unknown target is a clear
        ``GROUP_NOT_EXIST``, and a target outside the device classifiers
        (LocationDevices, DeviceAccess) — a PortType / UserDefinedPorts port
        group or a TopologyTypeDevices auto-group — is refused with nothing
        sent. A StaticSystem target such as Unassigned Devices is allowed: it
        is where a move puts a device back. A move takes the devices OUT of the
        source leaf (the Location tree partitions the inventory).

        Args:
            source_group_uuid: the leaf holding the devices.
            target_group_uuid: the destination group.
            devices: comma-separated host names and/or uuids.
            operation: 'move' | 'copy' (case-insensitive).

        Returns:
            str: "Moved|Copied <hosts> from '<source>' to '<target>' (<uuid>);
            target members now: <hosts>." plus JSON {"operation", "source_group_uuid",
            "target_group_uuid", "target_group_name", "devices": [{"uuid",
            "hostname"}], "target_members_after": [{"uuid", "hostname"}],
            "response": {...}}. "Error: Unknown member operation ..." /
            "Error: not members of the source group <uuid>: <names> ..." /
            "Error: Group <uuid> is a PortType group; devices cannot be moved
            or copied into it" (nothing sent); "Error: Move members failed:
            INVALID_OPERATION Hint: ..." on a platform refusal; "Error: ..."
            on an HTTP failure.
        """
        try:
            wanted = canonical_choice(operation, MEMBER_OPERATIONS, "member operation")
            source = source_group_uuid.strip()
            target = target_group_uuid.strip()
            if not source or not target:
                raise PlatformError("source_group_uuid and target_group_uuid must not be blank.")
            tokens = split_csv(devices, "devices")
            if len(tokens) > MAX_MEMBER_REFERENCES:
                raise PlatformError(f"devices: at most {MAX_MEMBER_REFERENCES} per call.")
            target_group = await read_group(client, target)
            target_classifier = str(target_group.get("classifier") or "")
            if target_classifier not in MEMBER_CLASSIFIERS:
                raise PlatformError(
                    f"Group {target} is a {target_classifier or 'non-device'} group; devices "
                    "cannot be moved or copied into it (targets are "
                    f"{' / '.join(MEMBER_CLASSIFIERS)} groups)."
                )
            source_members = await all_group_devices(client, source)
            resolved, unresolved = match_devices(tokens, source_members)
            if unresolved:
                raise PlatformError(
                    f"not members of the source group {source}: {', '.join(unresolved)} — the "
                    "source must be the exact leaf group holding the device (cnc_set_device_"
                    "group_members finds it; cnc_list_group_devices lists a group)."
                )
            chosen: dict[str, dict[str, Any]] = {}
            for device in resolved.values():
                chosen.setdefault(str(device.get("uuid")), device)
            body = {"groupUuid": source, "newGroupUuid": target, "references": sorted(chosen)}
            data = await client.request_json("POST", MEMBER_OPERATION_PATHS[wanted], json_body=body)
            result = check_result(data, f"{wanted.capitalize()} members")
            after = await all_group_devices(client, target)
            names = ", ".join(device_hostname(d) or str(d.get("uuid")) for d in chosen.values())
            members_now = (
                ", ".join(device_hostname(d) or str(d.get("uuid")) for d in after) or "none"
            )
            verb = "Copied" if wanted == "copy" else "Moved"
            text = (
                f"{verb} {names} from {source} to '{target_group.get('name')}' ({target}); "
                f"target members now: {members_now}."
            )
            payload = {
                "operation": wanted,
                "source_group_uuid": source,
                "target_group_uuid": target,
                "target_group_name": target_group.get("name"),
                "devices": [member_brief(d) for d in chosen.values()],
                "target_members_after": [member_brief(d) for d in after],
                "response": result,
            }
            return finalize(f"{text}\n\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)
