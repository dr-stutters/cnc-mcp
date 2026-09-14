"""Credential profiles (Crosswork inventory: ``/crosswork/inventory/v1/credentials``).

A credential profile is a named bundle of per-protocol login secrets (SSH,
HTTP, HTTPS user/password pairs, SNMPv2 communities, ...). Devices and
providers reference a profile by name (``profile`` field) instead of carrying
their own secrets, so a profile must exist before any device or provider that
uses it can be added.

Wire facts (verified live):

- read:   ``POST .../credentials/query`` with the inventory filter body; the
  envelope key is ``data`` (bare ``{}`` when nothing matches).
- create: ``POST .../credentials`` ``{"data": [{...}]}``.
- update: ``PUT .../credentials`` ``{"data": [{"profile", "v2_info"?, "user_pass":
  [...]}]}`` (verified live 2026-09-14 with the FULL entry list — every
  ``user_pass`` entry and the SNMPv2 community re-sent; the API masks passwords
  on read, so they must be given again rather than copied from a read). It
  answers ``JOB_COMPLETED_WITH_WARNING`` with the advisory "Note, if Credential
  Profile <p> is used in NSO, any updates to it needs be done through NSO
  interface": a success (``check_job`` returns the advisory as ``warning``).
- delete: ``DELETE .../credentials`` with a JSON body ``{"data": [{"profile": ...}]}``.
  Path-parameter forms (``/credentials/{name}``) do not exist (500).
- every write answers with a job envelope; a failed write is HTTP 200 with
  ``state != JOB_COMPLETED`` (checked by ``crosswork.check_job``).
- the API masks secrets on read (``"password": "******"``); the tools never
  add anything beyond what the API returns.

- **PUT is a full replace (verified live 2026-09-14)**: a profile created with
  SSH + gRPC + gNMI pairs and an SNMPv2 community, then PUT with only the SSH
  and gNMI pairs, read back with exactly those two entries and no ``v2_info``
  — the omitted gRPC pair and the community were REMOVED (the 7.2 API
  document's "adds or updates ... by the client set fields" wording is
  misleading). Hence the update tool takes the profile's COMPLETE content.

Expected but NOT verified live (confirm in the write-phase smoke run):

- what a second ``POST`` with an EXISTING profile name does. The 7.2 API
  document calls POST "Add or Overwrite credential profiles", so a duplicate
  create may silently replace the profile's secrets rather than fail. The
  create tool therefore reads the name first and refuses when it exists.
  Smoke step to add: create with an existing name (on a throwaway profile)
  and record the answer.
- what a ``PUT`` with an UNKNOWN profile name does (the API document says
  "adds or updates"). The update tool reads the name first and refuses when
  it does not exist, so this is never sent.
- the job envelope's ``impacted`` entries for credentials. Devices and
  providers put ``"<uuid> <name> [<ip>]"`` strings there; profiles have no
  UUID, so the entry is expected to be the bare profile name. The tools
  therefore expose ``impacted_objects`` as ``[{"profile": "<raw entry>"}]``
  (the raw string, never whitespace-split) instead of ``check_job``'s
  ``{"uuid": ...}`` parsing, which would mangle a name containing spaces.
- the ``type`` wording (``"1 credential(s) added|deleted successfully"`` by
  analogy with ``provider(s)`` / ``device(s)``).
- create-body variants beyond the single UI capture (SSH + HTTP pairs plus an
  SNMPv2 read community): an SNMPv2-only profile (``user_pass`` omitted, as
  ``v2_info`` is when empty), HTTPS pairs, ``write_community`` and a non-empty
  ``enable_password_data``.

User/password types implemented, and how each wire enum is known:

- SSH, HTTP: the UI's own create XHR; HTTPS: live reads of the pre-existing
  ``nso`` profile.
- gRPC (``ROBOT_USERPASS_GRPC``) and gNMI (``ROBOT_USERPASS_GNMI``): verified
  live 2026-09-14 — the lab profile ``cml-xrd`` carries SSH+HTTP+GRPC+GNMI
  entries, written with the update PUT above (the entry shape is the same
  ``{"user_name", "password", "type"}`` triple as HTTP/HTTPS). A gNMI entry
  is what a device needs before its GNMI transport can be added
  (cnc_enable_device_gnmi); the gRPC entry is what an SR-PCE provider's
  ``ROBOT_MSVC_TRANS_GRPC`` transport authenticates with.
- NETCONF (``ROBOT_USERPASS_NETCONF``): the enum value and entry shape the 7.2
  API document's own example body uses — NOT verified live on this build.

Telnet and SNMPv3 exist in the UI (the enum lists ``ROBOT_USERPASS_TELNET`` and
``v3_info``) but have not been exercised, so they are left out rather than
guessed. The API document's enum also lists ``TCP``, ``UDP``, ``SNMP``, ``TL1``,
``TL1_SECURE``, ``ADMIN`` and ``ENABLE`` user/password types. Because the update
tool sends the profile's whole definition, a profile carrying any of those (or
``v3_info``) would lose them on update; the tool reads the profile first and
refuses unless ``force=true`` (:func:`unsupported_credential_types`).

Secrets submitted to the create and update tools are scrubbed from any error
text they return: ``check_job`` and ``http_error`` echo platform response text, and a
validation response that echoed the request body would otherwise hand the
password straight back to the agent. The scrub runs BEFORE any truncation:
``check_job`` slices a non-envelope echo to 300 characters, and a secret
straddling that cut would survive as a prefix that whole-string replacement
cannot match, so ``_write_profile`` builds that message itself.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import INVENTORY, check_job, page_envelope, query_body, unwrap
from cnc_mcp.errors import PlatformError, format_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.safety import AppContext, register_tool

CREDENTIALS_PATH = f"{INVENTORY}/credentials"
CREDENTIALS_QUERY_PATH = f"{CREDENTIALS_PATH}/query"

# user_pass[].type wire values (verified from UI XHR / live reads).
USERPASS_SSH = "ROBOT_USERPASS_SSH"
USERPASS_HTTP = "ROBOT_USERPASS_HTTP"
USERPASS_HTTPS = "ROBOT_USERPASS_HTTPS"
USERPASS_GRPC = "ROBOT_USERPASS_GRPC"  # verified live 2026-09-14 (lab profile cml-xrd)
USERPASS_GNMI = "ROBOT_USERPASS_GNMI"  # verified live 2026-09-14 (lab profile cml-xrd)
USERPASS_NETCONF = "ROBOT_USERPASS_NETCONF"  # API document example only; unverified live
_USERPASS_PREFIX = "ROBOT_USERPASS_"
# The user/password types the create/update tools can express (and so re-send).
SUPPORTED_USERPASS_TYPES = frozenset(
    {
        USERPASS_SSH,
        USERPASS_HTTP,
        USERPASS_HTTPS,
        USERPASS_GRPC,
        USERPASS_GNMI,
        USERPASS_NETCONF,
    }
)
# How many characters of a non-envelope response are echoed in an error (the
# same cut crosswork.check_job makes — applied here only AFTER scrubbing).
_ECHO_LIMIT = 300


def _userpass_label(entry: dict[str, Any]) -> str:
    """Human label for one ``user_pass`` entry, e.g. ``SSH (cisco)`` or ``TELNET``."""
    wire = str(entry.get("type") or "")
    label = wire[len(_USERPASS_PREFIX) :] if wire.startswith(_USERPASS_PREFIX) else wire
    label = label or "?"
    user = entry.get("user_name")
    return f"{label} ({user})" if user else label


def _snmpv2_label(v2_info: Any) -> str:
    """``SNMPv2 (read)`` / ``(write)`` / ``(read+write)`` from the (masked) ``v2_info``.

    Says WHICH communities the profile holds without printing them (the API
    masks them as ``******`` anyway); a ``v2_info`` with neither key renders
    the bare ``SNMPv2``.
    """
    if not isinstance(v2_info, dict):
        return "SNMPv2"
    parts = [
        name
        for name, key in (("read", "read_community"), ("write", "write_community"))
        if v2_info.get(key) not in (None, "")
    ]
    return f"SNMPv2 ({'+'.join(parts)})" if parts else "SNMPv2"


def _snmpv3_label(v3_info: Any) -> str:
    """``SNMPv3 (<user>, <security level>, <auth>/<priv>)`` from the ``v3_info`` block.

    Built from the 7.2 API document's ``robotapiRobotSnmpV3`` fields (the read
    shape is NOT verified live — no SNMPv3 profile exists on the lab):
    ``user_name``, ``security_level`` (``SL_AUTH_PRIV`` -> ``AUTH_PRIV``),
    ``auth_type`` (``AT_HMAC_SHA`` -> ``HMAC_SHA``) and ``priv_type``
    (``PT_CFB_AES_128`` -> ``CFB_AES_128``); ``*_UNKNOWN`` values are
    skipped. The ``auth_password`` / ``priv_password`` secrets are never
    rendered. A ``v3_info`` with none of the fields renders the bare ``SNMPv3``.
    """
    if not isinstance(v3_info, dict):
        return "SNMPv3"

    def enum_text(key: str, prefix: str) -> str | None:
        raw = str(v3_info.get(key) or "").strip()
        if not raw or raw.endswith("_UNKNOWN"):
            return None
        return raw[len(prefix) :] if raw.startswith(prefix) else raw

    parts: list[str] = []
    user = str(v3_info.get("user_name") or "").strip()
    if user:
        parts.append(user)
    level = enum_text("security_level", "SL_")
    if level:
        parts.append(level)
    auth, priv = enum_text("auth_type", "AT_"), enum_text("priv_type", "PT_")
    if auth or priv:
        parts.append(f"{auth or '-'}/{priv or '-'}")
    return f"SNMPv3 ({', '.join(parts)})" if parts else "SNMPv3"


def _credential_types(item: dict[str, Any]) -> list[str]:
    """Human labels for the credential types a profile carries, e.g. ``SSH (cisco)``,
    ``SNMPv2 (read)``, ``SNMPv3 (v3u, AUTH_PRIV, HMAC_SHA/CFB_AES_128)``."""
    labels = [
        _userpass_label(entry) for entry in item.get("user_pass") or [] if isinstance(entry, dict)
    ]
    if item.get("v2_info"):
        labels.append(_snmpv2_label(item["v2_info"]))
    if item.get("v3_info"):
        labels.append(_snmpv3_label(item["v3_info"]))
    return labels


def unsupported_credential_types(item: dict[str, Any]) -> list[str]:
    """Labels of the credentials in a read profile record that the update tool cannot re-send.

    ``cnc_update_credential_profile`` sends the profile's whole definition, so
    anything it cannot express — a ``user_pass`` type outside
    :data:`SUPPORTED_USERPASS_TYPES` (Telnet, TCP, UDP, SNMP, TL1, ADMIN, ...)
    or an SNMPv3 ``v3_info`` block — would be dropped by the PUT. Returns e.g.
    ``["TELNET (cisco)", "SNMPv3"]``; empty when the whole profile can be re-sent.
    """
    dropped = [
        _userpass_label(entry)
        for entry in item.get("user_pass") or []
        if isinstance(entry, dict) and str(entry.get("type") or "") not in SUPPORTED_USERPASS_TYPES
    ]
    if item.get("v3_info"):
        dropped.append("SNMPv3")
    return dropped


def _profiles_markdown(items: list[dict[str, Any]], envelope: dict[str, Any]) -> str:
    total = envelope["total"]
    total_text = f"total {total}" if total is not None else "total unknown"
    lines = [f"# Credential profiles ({envelope['count']} shown, {total_text})", ""]
    if not items:
        lines.append("No credential profiles matched.")
    for item in items:
        name = item.get("profile", "?")
        types = ", ".join(_credential_types(item)) or "none"
        lines.append(f"- **{name}** — types: {types}")
    if envelope["has_more"]:
        lines.append("")
        lines.append(f"More available: repeat with page={envelope['next_page']}.")
    return "\n".join(lines)


def _clean(value: str | None) -> str | None:
    """Strip a string argument; whitespace-only (or None) counts as unset."""
    return (value or "").strip() or None


def _profile_name(profile: str) -> str:
    """Normalise a profile-name argument (stripped; whitespace-only is an error).

    The platform matches names exactly (case-insensitively), so a padded name
    would silently miss on read and create a padded profile on write.
    """
    name = profile.strip()
    if not name:
        raise PlatformError("profile must not be empty or whitespace-only.")
    return name


def _require_pair(username: str | None, password: str | None, what: str) -> bool:
    """True when both halves of a user/password pair are set; error when only one is."""
    has_user, has_pass = username is not None, password is not None
    if has_user != has_pass:
        raise PlatformError(
            f"{what}_username and {what}_password must be given together "
            f"(only one of them was set)."
        )
    return has_user


def build_create_body(
    *,
    profile: str,
    ssh_username: str | None,
    ssh_password: str | None,
    http_username: str | None,
    http_password: str | None,
    https_username: str | None,
    https_password: str | None,
    snmpv2_read_community: str | None,
    snmpv2_write_community: str | None,
    enable_password: str | None,
    grpc_username: str | None = None,
    grpc_password: str | None = None,
    gnmi_username: str | None = None,
    gnmi_password: str | None = None,
    netconf_username: str | None = None,
    netconf_password: str | None = None,
) -> dict[str, Any]:
    """Validate the flat credential arguments and build the ``{"data": [{...}]}`` body.

    The same body serves ``POST credentials`` (create) and ``PUT credentials``
    (update — the full definition, see the module docstring). Every string
    argument is stripped and a whitespace-only value is treated as unset, so
    ``' '`` can never be sent as a real username, password or community.
    ``user_pass`` is omitted (not sent as ``[]``) when no user/password pair
    was given, mirroring how ``v2_info`` is omitted when no community was given
    — the SNMPv2-only shape is unverified live either way. Entry order is SSH,
    HTTP, HTTPS, gRPC, gNMI (the order the live lab profile carries them), then
    NETCONF (unverified live).
    """
    profile = _profile_name(profile)
    ssh_username, ssh_password = _clean(ssh_username), _clean(ssh_password)
    http_username, http_password = _clean(http_username), _clean(http_password)
    https_username, https_password = _clean(https_username), _clean(https_password)
    grpc_username, grpc_password = _clean(grpc_username), _clean(grpc_password)
    gnmi_username, gnmi_password = _clean(gnmi_username), _clean(gnmi_password)
    netconf_username, netconf_password = _clean(netconf_username), _clean(netconf_password)
    snmpv2_read_community = _clean(snmpv2_read_community)
    snmpv2_write_community = _clean(snmpv2_write_community)
    enable_password = _clean(enable_password)

    user_pass: list[dict[str, Any]] = []
    if _require_pair(ssh_username, ssh_password, "ssh"):
        user_pass.append(
            {
                "user_name": ssh_username,
                "password": ssh_password,
                "enable_password_data": enable_password or "",
                "type": USERPASS_SSH,
            }
        )
    elif enable_password:
        raise PlatformError(
            "enable_password only applies to the SSH credential: set ssh_username and "
            "ssh_password as well."
        )
    if _require_pair(http_username, http_password, "http"):
        user_pass.append(
            {"user_name": http_username, "password": http_password, "type": USERPASS_HTTP}
        )
    if _require_pair(https_username, https_password, "https"):
        user_pass.append(
            {"user_name": https_username, "password": https_password, "type": USERPASS_HTTPS}
        )
    if _require_pair(grpc_username, grpc_password, "grpc"):
        user_pass.append(
            {"user_name": grpc_username, "password": grpc_password, "type": USERPASS_GRPC}
        )
    if _require_pair(gnmi_username, gnmi_password, "gnmi"):
        user_pass.append(
            {"user_name": gnmi_username, "password": gnmi_password, "type": USERPASS_GNMI}
        )
    if _require_pair(netconf_username, netconf_password, "netconf"):
        user_pass.append(
            {"user_name": netconf_username, "password": netconf_password, "type": USERPASS_NETCONF}
        )
    v2_info = {
        k: v
        for k, v in (
            ("read_community", snmpv2_read_community),
            ("write_community", snmpv2_write_community),
        )
        if v
    }
    if not user_pass and not v2_info:
        raise PlatformError(
            "A credential profile needs at least one credential: give an SSH, HTTP, HTTPS, "
            "gRPC, gNMI or NETCONF username/password pair, or an SNMPv2 read/write community."
        )
    item: dict[str, Any] = {"profile": profile}
    if user_pass:
        item["user_pass"] = user_pass
    if v2_info:
        item["v2_info"] = v2_info
    return {"data": [item]}


def credential_job(result: Any, what: str) -> dict[str, Any]:
    """``check_job`` for credential writes: ``impacted`` entries are profile names.

    Profiles have no UUID, so the generic ``parse_impacted`` (``"<uuid> <name>
    [<ip>]"`` split on whitespace) does not apply. Each raw ``impacted`` string
    is exposed verbatim as ``{"profile": <entry>}``. The real entry shape is
    unverified live; this keeps whatever the platform sends intact.
    """
    envelope = check_job(result, what)
    envelope["impacted_objects"] = [
        {"profile": entry} for entry in envelope.get("impacted") or [] if isinstance(entry, str)
    ]
    return envelope


def scrub_secrets(text: str, secrets: Iterable[str | None]) -> str:
    """Replace every non-empty secret in ``text`` with ``******`` (longest first).

    Used on the create/update tools' error output: ``check_job`` echoes a non-envelope
    response body and ``http_error`` echoes the platform's error detail, either
    of which could contain the request body — and with it the plaintext
    passwords/communities — verbatim. Whole-string replacement only: the text
    must be scrubbed BEFORE it is truncated (see :func:`non_envelope_message`),
    or a secret cut in half survives as a prefix.
    """
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(secret, "******")
    return text


def non_envelope_message(result: Any, what: str, secrets: Iterable[str | None]) -> str:
    """The ``check_job`` "did not return a job envelope" text, scrubbed before the cut.

    ``check_job`` slices ``str(result)`` to 300 characters and only then would
    the tool scrub it — a password straddling character 300 came back as its
    first 38 characters in a live-shaped echo. Scrub the whole echo first, then
    apply the same 300-character limit.
    """
    echo = scrub_secrets(str(result), secrets)[:_ECHO_LIMIT]
    return f"{what}: Crosswork did not return a job envelope. Response: {echo}"


def is_job_envelope(result: Any) -> bool:
    """True when ``result`` is what ``check_job`` accepts (a dict carrying ``state``)."""
    return isinstance(result, dict) and "state" in result


# Flat credential arguments shared by cnc_create_credential_profile and
# cnc_update_credential_profile (same wire body, see build_create_body). Each is a
# plain optional string parameter; the aliases only avoid repeating the Field text.
ProfileArg = Annotated[
    str,
    Field(
        description=(
            "Profile name (e.g. 'cml-xrd'): must not exist yet on create, must exist on "
            "update (both checked with a read first; names match case-insensitively)."
        ),
        min_length=1,
        max_length=200,
    ),
]
ForceArg = Annotated[
    bool,
    Field(
        description=(
            "Send the PUT even though the profile currently holds credential types this "
            "tool cannot re-send (Telnet, SNMPv3, TCP/UDP/SNMP/TL1/ADMIN entries) — they "
            "are DROPPED from the profile. Default false: refuse and list them."
        ),
    ),
]
SshUsernameArg = Annotated[
    str | None,
    Field(description="SSH login user (e.g. 'cisco'). Requires ssh_password.", max_length=200),
]
SshPasswordArg = Annotated[
    str | None, Field(description="SSH login password. Requires ssh_username.", max_length=500)
]
HttpUsernameArg = Annotated[
    str | None,
    Field(description="HTTP login user (e.g. 'cisco'). Requires http_password.", max_length=200),
]
HttpPasswordArg = Annotated[
    str | None, Field(description="HTTP login password. Requires http_username.", max_length=500)
]
HttpsUsernameArg = Annotated[
    str | None,
    Field(description="HTTPS login user (e.g. 'admin'). Requires https_password.", max_length=200),
]
HttpsPasswordArg = Annotated[
    str | None,
    Field(description="HTTPS login password. Requires https_username.", max_length=500),
]
GrpcUsernameArg = Annotated[
    str | None,
    Field(
        description=(
            "gRPC login user (e.g. 'cisco') — what an SR-PCE provider's gRPC transport "
            "authenticates with. Requires grpc_password."
        ),
        max_length=200,
    ),
]
GrpcPasswordArg = Annotated[
    str | None, Field(description="gRPC login password. Requires grpc_username.", max_length=500)
]
GnmiUsernameArg = Annotated[
    str | None,
    Field(
        description=(
            "gNMI login user (e.g. 'cisco') — needed before a device's gNMI transport can "
            "be added (cnc_enable_device_gnmi). Requires gnmi_password."
        ),
        max_length=200,
    ),
]
GnmiPasswordArg = Annotated[
    str | None, Field(description="gNMI login password. Requires gnmi_username.", max_length=500)
]
NetconfUsernameArg = Annotated[
    str | None,
    Field(
        description=(
            "NETCONF login user (e.g. 'cisco'). Requires netconf_password. Sent as "
            "ROBOT_USERPASS_NETCONF (the API document's example shape; not verified live)."
        ),
        max_length=200,
    ),
]
NetconfPasswordArg = Annotated[
    str | None,
    Field(description="NETCONF login password. Requires netconf_username.", max_length=500),
]
Snmpv2ReadCommunityArg = Annotated[
    str | None, Field(description="SNMPv2c read community (e.g. 'public').", max_length=200)
]
Snmpv2WriteCommunityArg = Annotated[
    str | None, Field(description="SNMPv2c write community (e.g. 'private').", max_length=200)
]
EnablePasswordArg = Annotated[
    str | None,
    Field(
        description=(
            "Enable/privileged-mode password for the SSH credential (IOS-style devices). "
            "Only valid together with ssh_username/ssh_password."
        ),
        max_length=500,
    ),
]


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def _lookup_profile(name: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
        """Query by exact name: (the case-insensitive exact match or None, every item returned).

        Shared by the get tool and the create/update safety reads. The platform
        filter is exact-match, case-insensitive; the second element only matters
        when the name carried a ``*`` wildcard and several profiles came back.
        """
        body = query_body({"profile": name}, page_size=50, page=0)
        data = await client.request_json("POST", CREDENTIALS_QUERY_PATH, json_body=body)
        items, _, _ = unwrap(data, "data")
        items = [item for item in items if isinstance(item, dict)]
        wanted = name.lower()
        for item in items:
            if str(item.get("profile", "")).lower() == wanted:
                return item, items
        return None, items

    async def _refuse_if_exists(name: str, force: bool) -> None:
        """Create guard: the API document calls POST "add or overwrite", so never re-add."""
        existing, _ = await _lookup_profile(name)
        if existing is not None:
            held = ", ".join(_credential_types(existing)) or "none"
            raise PlatformError(
                f"Credential profile '{existing.get('profile', name)}' already exists "
                f"(types: {held}); nothing was sent. The platform's POST is documented as "
                "'add or overwrite', so a second create could silently replace its secrets: "
                "use cnc_update_credential_profile to change it, or pick another name."
            )

    async def _refuse_unless_updatable(name: str, force: bool) -> None:
        """Update guard: the profile must exist and be re-sendable in full (or force)."""
        existing, _ = await _lookup_profile(name)
        if existing is None:
            raise PlatformError(
                f"Credential profile '{name}' not found; nothing was sent (what the "
                "platform does with a PUT for an unknown name is unverified). Create it "
                "with cnc_create_credential_profile, or list names with "
                "cnc_list_credential_profiles (exact match, case-insensitive)."
            )
        dropped = unsupported_credential_types(existing)
        if dropped and not force:
            raise PlatformError(
                f"Credential profile '{existing.get('profile', name)}' holds credential "
                f"types this tool cannot re-send: {', '.join(dropped)}. The PUT replaces "
                "the whole definition, so they would be DROPPED; nothing was sent. Edit "
                "this profile in the Crosswork UI, or repeat with force=true to drop them."
            )

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_credential_profiles",
        title="List Credential Profiles",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_credential_profiles(
        profile: Annotated[
            str | None,
            Field(
                description=(
                    "Filter by profile name: exact match, case-insensitive, '*' is a "
                    "wildcard (e.g. 'nso', 'cml-*', '*xrd'). No filter lists every profile."
                ),
                max_length=200,
            ),
        ] = None,
        page_size: Annotated[
            int, Field(description="Profiles per page (e.g. 20).", ge=1, le=500)
        ] = 20,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List credential profiles known to Crosswork, with optional name filter and paging.

        Read-only. Use it to find the profile name to reference when adding devices
        or providers, or to check which protocols (SSH/HTTP/HTTPS/SNMPv2/...) a
        profile covers. For one profile's full record use cnc_get_credential_profile.

        Secrets are masked by the API ("******"); usernames are returned in clear.
        The markdown line names each user/password type with its username and
        says which SNMP credentials exist without a follow-up read: "SNMPv2
        (read)" / "SNMPv2 (write)" / "SNMPv2 (read+write)" from the masked
        ``v2_info`` communities, and "SNMPv3 (<user>, <security level>,
        <auth>/<priv>)" from ``v3_info`` (built from the API document's
        fields — no SNMPv3 profile exists on the lab, so that read shape is
        unverified; its passwords are never rendered).

        Args:
            profile: name filter (exact, case-insensitive, '*' wildcard; surrounding
                whitespace is stripped and a blank filter means no filter).
            page_size / page: filterData paging (0-based page).
            response_format: 'markdown' (default) or 'json'.

        Returns:
            str: Markdown "- **profile** — types: SSH (user), HTTP (user), SNMPv2 (read)"
            lines, or JSON:
            {"total": int|null, "count": int, "page": int, "page_size": int,
             "items": [{"profile": str,
                        "user_pass": [{"user_name": str, "password": "******",
                                       "type": "ROBOT_USERPASS_SSH|HTTP|HTTPS|..."}],
                        "v2_info": {"read_community": "******", ...}?}, ...],
             "has_more": bool, "next_page": int|null, "collection_total": int|null}
            "total" is the number of profiles matching the filter (null when the
            platform omits it, i.e. zero matches); "collection_total" is the size of the
            whole collection regardless of filter.
            On failure: "Error: <actionable message>" (500 "NATS request failed" -> the
            query body was rejected; 403 -> token rejected or missing privilege).
        """
        try:
            body = query_body({"profile": _clean(profile)}, page_size=page_size, page=page)
            data = await client.request_json("POST", CREDENTIALS_QUERY_PATH, json_body=body)
            items, result_count, total_count = unwrap(data, "data")
            envelope = page_envelope(
                items,
                result_count=result_count,
                total_count=total_count,
                page_size=page_size,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            return finalize(_profiles_markdown(items, envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_credential_profile",
        title="Get Credential Profile",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_credential_profile(
        profile: Annotated[
            str,
            Field(
                description="Exact profile name, case-insensitive (e.g. 'nso', 'cml-xrd').",
                min_length=1,
                max_length=200,
            ),
        ],
    ) -> str:
        """Get the full record of one credential profile by name.

        Read-only. Profiles have no UUID: the name is the identifier everywhere
        (devices and providers reference it in their "profile" field). Find names
        with cnc_list_credential_profiles.

        Args:
            profile: exact profile name (case-insensitive; surrounding whitespace is
                stripped). A '*' wildcard is accepted by the platform but this tool
                needs a single exact match.

        Returns:
            str: JSON object {"profile": str, "user_pass": [{"user_name", "password":
            "******", "type": "ROBOT_USERPASS_SSH|HTTP|HTTPS|...", ...}],
            "v2_info": {...}?, "v3_info": {...}?}. Secrets are masked by the API.
            On failure: "Error: Credential profile '<name>' not found ..." when nothing
            matches, "Error: ... matches several profiles ..." when a wildcard was used,
            "Error: profile must not be empty ..." for a blank name, or
            "Error: <API failure>".
        """
        try:
            name = _profile_name(profile)
            item, items = await _lookup_profile(name)
            if item is not None:
                return finalize(to_json(item), settings)
            if not items:
                raise PlatformError(
                    f"Credential profile '{name}' not found. List existing profiles with "
                    "cnc_list_credential_profiles (names are exact-match, case-insensitive)."
                )
            names = ", ".join(str(i.get("profile", "?")) for i in items)
            raise PlatformError(
                f"'{name}' matches several profiles ({names}) but none exactly. "
                "Pass one exact profile name."
            )
        except Exception as e:
            return format_error(e)

    async def _write_profile(
        method: str,
        verb: str,
        guard: Callable[[str, bool], Awaitable[None]],
        *,
        profile: str,
        force: bool = False,
        **fields: str | None,
    ) -> str:
        """Shared body of the create (POST) and update (PUT) tools.

        Validates and builds the ``{"data": [{...}]}`` body with
        :func:`build_create_body` (so an argument error costs no request), runs
        the tool's safety read (``guard``: create refuses an existing name,
        update refuses a missing one or credential types it would drop), sends
        the body, and renders the job envelope through :func:`credential_job`.
        The POST is left non-retryable (client default for POST); the PUT is
        idempotent and takes the client's default retry. Every submitted secret
        is scrubbed from error text: both the non-envelope echo (scrubbed before
        it is truncated, see :func:`non_envelope_message`) and ``http_error``
        (platform detail) can reflect the request body.
        """
        secrets = tuple(
            _clean(fields.get(k))
            for k in (
                "ssh_password",
                "http_password",
                "https_password",
                "grpc_password",
                "gnmi_password",
                "netconf_password",
                "enable_password",
                "snmpv2_read_community",
                "snmpv2_write_community",
            )
        )
        try:
            name = _profile_name(profile)
            body = build_create_body(profile=name, **fields)
            await guard(name, force)
            result = await client.request_json(method, CREDENTIALS_PATH, json_body=body)
            what = f"{verb} credential profile '{name}'"
            if not is_job_envelope(result):
                raise PlatformError(non_envelope_message(result, what, secrets))
            envelope = credential_job(result, what)
            return finalize(to_json(envelope), settings)
        except Exception as e:
            return scrub_secrets(format_error(e), secrets)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_credential_profile",
        title="Create Credential Profile",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_create_credential_profile(
        profile: ProfileArg,
        ssh_username: SshUsernameArg = None,
        ssh_password: SshPasswordArg = None,
        http_username: HttpUsernameArg = None,
        http_password: HttpPasswordArg = None,
        https_username: HttpsUsernameArg = None,
        https_password: HttpsPasswordArg = None,
        grpc_username: GrpcUsernameArg = None,
        grpc_password: GrpcPasswordArg = None,
        gnmi_username: GnmiUsernameArg = None,
        gnmi_password: GnmiPasswordArg = None,
        netconf_username: NetconfUsernameArg = None,
        netconf_password: NetconfPasswordArg = None,
        snmpv2_read_community: Snmpv2ReadCommunityArg = None,
        snmpv2_write_community: Snmpv2WriteCommunityArg = None,
        enable_password: EnablePasswordArg = None,
    ) -> str:
        """Create a credential profile: SSH/HTTP/HTTPS/gRPC/gNMI/NETCONF logins + SNMPv2.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true. Create the
        profile BEFORE adding devices or providers that reference it by name.

        At least one credential must be given; usernames and passwords come in pairs
        (ssh_username + ssh_password, ...). enable_password is attached to the SSH
        credential only. Typical lab profile: ssh_username/ssh_password plus
        snmpv2_read_community='public'. Every string argument is stripped and a
        whitespace-only value counts as not given.

        Verified live: the SSH + HTTP pair + SNMPv2 read-community shape (captured
        from the UI), and the gRPC / gNMI entries (ROBOT_USERPASS_GRPC / _GNMI —
        the lab profile cml-xrd carries SSH+HTTP+GRPC+GNMI, written 2026-09-14
        through cnc_update_credential_profile with the same entry shape). A gNMI
        pair is required before cnc_enable_device_gnmi can add a device's gNMI
        transport; a gRPC pair is what an SR-PCE provider's gRPC transport uses.
        Expected but unverified live (confirm in the write-phase smoke run):
        SNMPv2-only profiles (no user/password pair — "user_pass" is omitted from
        the body), HTTPS pairs, snmpv2_write_community, enable_password, and
        NETCONF pairs (sent as ROBOT_USERPASS_NETCONF, the API document's own
        example shape).

        Not supported by this tool: Telnet and SNMPv3 credentials — add those in
        the Crosswork UI. To add a credential type to an EXISTING profile use
        cnc_update_credential_profile.

        SAFETY: the tool reads the name first (POST .../credentials/query, the
        same read as cnc_get_credential_profile) and refuses when a profile with
        that name already exists (case-insensitive) — nothing is sent. The API
        document describes this POST as "Add or Overwrite credential profiles",
        so a second create with an existing name may silently replace its
        secrets rather than fail; what the platform actually does is unverified
        live, and the guard makes it irrelevant. A failed safety read is an
        error and nothing is sent either.

        The POST is not auto-retried (a lost response would leave the tool unable
        to tell whether the profile was created; re-run the tool — the safety read
        then reports it as existing). Submitted secrets are scrubbed ("******")
        from any error text returned, so an error message shows "******"
        wherever a secret's text happens to occur (e.g. in a profile name that
        contains the password).

        Args:
            profile: new profile name (must not exist yet).
            ssh_username/ssh_password, http_username/http_password,
            https_username/https_password, grpc_username/grpc_password,
            gnmi_username/gnmi_password, netconf_username/netconf_password: login
            pairs, each optional as a pair.
            snmpv2_read_community/snmpv2_write_community: SNMPv2c communities.
            enable_password: SSH enable password (optional, SSH only).

        Returns:
            str: JSON job envelope {"job_id": str, "state": "JOB_COMPLETED",
            "type": str, "impacted": [str, ...],
            "impacted_objects": [{"profile": "<raw impacted entry>"}, ...], ...}.
            "type" is expected to read "1 credential(s) added successfully" and each
            "impacted" entry is expected to be the new profile's name (profiles have
            no UUID) — neither is verified live yet, so "impacted_objects" carries
            each raw entry verbatim under "profile" rather than parsing it.
            On failure: "Error: Credential profile '<name>' already exists (types: ...);
            nothing was sent ..." from the safety read, "Error: Create credential
            profile ... failed (job ..., state JOB_FAILED): <platform reason>", or
            "Error: <validation message>" before any request is sent.
        """
        return await _write_profile(
            "POST",
            "Create",
            _refuse_if_exists,
            profile=profile,
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            http_username=http_username,
            http_password=http_password,
            https_username=https_username,
            https_password=https_password,
            grpc_username=grpc_username,
            grpc_password=grpc_password,
            gnmi_username=gnmi_username,
            gnmi_password=gnmi_password,
            netconf_username=netconf_username,
            netconf_password=netconf_password,
            snmpv2_read_community=snmpv2_read_community,
            snmpv2_write_community=snmpv2_write_community,
            enable_password=enable_password,
        )

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_credential_profile",
        title="Update Credential Profile",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_update_credential_profile(
        profile: ProfileArg,
        ssh_username: SshUsernameArg = None,
        ssh_password: SshPasswordArg = None,
        http_username: HttpUsernameArg = None,
        http_password: HttpPasswordArg = None,
        https_username: HttpsUsernameArg = None,
        https_password: HttpsPasswordArg = None,
        grpc_username: GrpcUsernameArg = None,
        grpc_password: GrpcPasswordArg = None,
        gnmi_username: GnmiUsernameArg = None,
        gnmi_password: GnmiPasswordArg = None,
        netconf_username: NetconfUsernameArg = None,
        netconf_password: NetconfPasswordArg = None,
        snmpv2_read_community: Snmpv2ReadCommunityArg = None,
        snmpv2_write_community: Snmpv2WriteCommunityArg = None,
        enable_password: EnablePasswordArg = None,
        force: ForceArg = False,
    ) -> str:
        """Re-send the whole definition of an existing credential profile (PUT).

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true. Treat
        the arguments as the profile's COMPLETE new content, not a delta: give
        every user/password pair and SNMPv2 community the profile should hold,
        not just the change. Verified live 2026-09-14: the PUT is a FULL REPLACE
        — an entry (or the SNMPv2 community) left out of the body is REMOVED
        from the profile, so omitting a pair deletes that credential; devices
        using the profile then lose that access. Because the
        API masks passwords on read ("******"), a read record cannot be replayed
        — re-supply every password (and community) yourself. Workflow:
        cnc_get_credential_profile to see which usernames/types the profile
        carries, then call this tool with ALL of them plus the change.

        SAFETY (a read before the write, POST .../credentials/query):
        1. the profile must exist (case-insensitive name match), otherwise
           "Error: Credential profile '<name>' not found; nothing was sent" —
           what the platform does with a PUT for an unknown name is unverified;
           create profiles with cnc_create_credential_profile;
        2. the profile must hold only credential types this tool can re-send
           (SSH, HTTP, HTTPS, gRPC, gNMI, NETCONF user/password pairs and SNMPv2
           communities). A Telnet (ROBOT_USERPASS_TELNET) or SNMPv3 (v3_info)
           credential — or any other enum value (TCP, UDP, SNMP, TL1, TL1_SECURE,
           ADMIN) — cannot be expressed here and WOULD BE DROPPED by the
           full-definition PUT, so the tool refuses and names them: "Error: ...
           holds credential types this tool cannot re-send: TELNET (cisco),
           SNMPv3 ...; nothing was sent". Edit such a profile in the Crosswork UI,
           or pass force=true to proceed and drop them knowingly.
        A failed safety read is an error and nothing is sent.

        Typical use: adding a gNMI credential to an existing profile before
        cnc_enable_device_gnmi (e.g. profile 'cml-xrd' with its SSH and HTTP
        pairs and snmpv2_read_community re-sent, plus gnmi_username/gnmi_password
        — that exact call is what onboarded the lab's gNMI transports on
        2026-09-14), or adding a gRPC pair for an SR-PCE provider's gRPC transport.

        Verified live (2026-09-14): PUT /crosswork/inventory/v1/credentials
        {"data": [{"profile", "v2_info"?, "user_pass": [...]}]} with the full
        entry list answers JOB_COMPLETED_WITH_WARNING carrying the advisory
        "Note, if Credential Profile <p> is used in NSO, any updates to it needs
        be done through NSO interface". That is a SUCCESS: the update applied and
        the advisory is returned under "warning" — it only matters when NSO
        manages the same profile, in which case make the change there as well.
        The gRPC and gNMI entries (ROBOT_USERPASS_GRPC / _GNMI) are verified in
        this very form; NETCONF (ROBOT_USERPASS_NETCONF) is the API document's
        example shape and unverified live.

        Validation is the same as for create (pairs must be complete, at least one
        credential, whitespace-only values count as unset, enable_password needs
        the SSH pair) and happens before the safety read. The PUT is idempotent,
        so a 5xx/transport failure is auto-retried. Submitted secrets are
        scrubbed ("******") from any error text returned.

        Args:
            profile: exact name of the existing profile (surrounding whitespace
                stripped).
            ssh_username/ssh_password, http_username/http_password,
            https_username/https_password, grpc_username/grpc_password,
            gnmi_username/gnmi_password, netconf_username/netconf_password: the
            login pairs the profile should hold from now on (each optional as a
            pair). Re-send every pair the profile already has: whether an
            omitted pair is removed is unverified.
            snmpv2_read_community/snmpv2_write_community: the SNMPv2c communities
            the profile should hold from now on (re-send existing ones).
            enable_password: SSH enable password (optional, SSH only).
            force: send the PUT although the profile holds Telnet/SNMPv3/other
                credential types this tool cannot re-send (they are dropped).

        Returns:
            str: JSON job envelope {"job_id": str, "state":
            "JOB_COMPLETED_WITH_WARNING" | "JOB_COMPLETED", "warning"?: "Note, if
            Credential Profile <p> is used in NSO, ...", "type": str, "impacted":
            [str, ...], "impacted_objects": [{"profile": "<raw impacted entry>"},
            ...], ...} — a "warning" is advisory, not a failure.
            On failure: the two safety-read refusals above (nothing sent), "Error:
            Update credential profile ... failed (job ..., state JOB_FAILED):
            <platform reason>", or "Error: <validation message>" before any
            request is sent.
        """
        return await _write_profile(
            "PUT",
            "Update",
            _refuse_unless_updatable,
            profile=profile,
            force=force,
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            http_username=http_username,
            http_password=http_password,
            https_username=https_username,
            https_password=https_password,
            grpc_username=grpc_username,
            grpc_password=grpc_password,
            gnmi_username=gnmi_username,
            gnmi_password=gnmi_password,
            netconf_username=netconf_username,
            netconf_password=netconf_password,
            snmpv2_read_community=snmpv2_read_community,
            snmpv2_write_community=snmpv2_write_community,
            enable_password=enable_password,
        )

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_credential_profile",
        title="Delete Credential Profile",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_credential_profile(
        profile: Annotated[
            str,
            Field(
                description="Exact name of the profile to delete (e.g. 'cml-xrd').",
                min_length=1,
                max_length=200,
            ),
        ],
    ) -> str:
        """Permanently delete a credential profile by name.

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true. Verify
        the name with cnc_get_credential_profile first.

        Ordering rule: a profile that is still referenced by devices or providers
        (their "profile" field; the device list tool accepts a profile filter) cannot
        be deleted — delete those objects or re-point them at another profile first,
        then delete the profile. (Expect the platform to report this as a failed job;
        the exact error text is not verified.) Do not delete the pre-existing 'nso'
        profile on an instance with an NSO provider.

        Sends DELETE /crosswork/inventory/v1/credentials with a JSON body
        {"data": [{"profile": name}]} — the only form the platform accepts.

        Args:
            profile: exact profile name (surrounding whitespace is stripped).

        Returns:
            str: JSON job envelope {"job_id": str, "state": "JOB_COMPLETED",
            "type": str, "impacted": [str, ...],
            "impacted_objects": [{"profile": "<raw impacted entry>"}, ...], ...}.
            "type" is expected to read "1 credential(s) deleted successfully" and
            "impacted" to carry the profile name — both unverified live, so each raw
            entry is passed through verbatim under "profile".
            On failure: "Error: Delete credential profile ... failed (job ..., state
            JOB_FAILED): <platform reason>" (profile missing or still in use),
            "Error: profile must not be empty ..." for a blank name, or
            "Error: <API failure>".
        """
        try:
            name = _profile_name(profile)
            body = {"data": [{"profile": name}]}
            result = await client.request_json("DELETE", CREDENTIALS_PATH, json_body=body)
            envelope = credential_job(result, f"Delete credential profile '{name}'")
            return finalize(to_json(envelope), settings)
        except Exception as e:
            return format_error(e)
