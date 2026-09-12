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
- delete: ``DELETE .../credentials`` with a JSON body ``{"data": [{"profile": ...}]}``.
  Path-parameter forms (``/credentials/{name}``) do not exist (500).
- every write answers with a job envelope; a failed write is HTTP 200 with
  ``state != JOB_COMPLETED`` (checked by ``crosswork.check_job``).
- the API masks secrets on read (``"password": "******"``); the tools never
  add anything beyond what the API returns.

Expected but NOT verified live (confirm in the write-phase smoke run):

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

Only the SSH/HTTP/HTTPS user-password types and SNMPv2 communities are
implemented: those are the wire shapes captured from the UI (the HTTPS enum is
verified from live reads of the pre-existing ``nso`` profile). NETCONF, gNMI,
gRPC, Telnet and SNMPv3 exist in the UI but their wire enums are unverified,
so they are deliberately left out rather than guessed.

Secrets submitted to the create tool are scrubbed from any error text it
returns: ``check_job`` and ``http_error`` echo platform response text, and a
validation response that echoed the request body would otherwise hand the
password straight back to the agent.
"""

from __future__ import annotations

from collections.abc import Iterable
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
_USERPASS_PREFIX = "ROBOT_USERPASS_"


def _credential_types(item: dict[str, Any]) -> list[str]:
    """Human labels for the credential types a profile carries, e.g. ``SSH (cisco)``."""
    labels: list[str] = []
    for entry in item.get("user_pass") or []:
        if not isinstance(entry, dict):
            continue
        wire = str(entry.get("type") or "")
        label = wire[len(_USERPASS_PREFIX) :] if wire.startswith(_USERPASS_PREFIX) else wire
        label = label or "?"
        user = entry.get("user_name")
        labels.append(f"{label} ({user})" if user else label)
    if item.get("v2_info"):
        labels.append("SNMPv2")
    if item.get("v3_info"):
        labels.append("SNMPv3")
    return labels


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
) -> dict[str, Any]:
    """Validate the flat create arguments and build the ``POST credentials`` body.

    Every string argument is stripped and a whitespace-only value is treated as
    unset, so ``' '`` can never be sent as a real username, password or
    community. ``user_pass`` is omitted (not sent as ``[]``) when no
    user/password pair was given, mirroring how ``v2_info`` is omitted when no
    community was given — the SNMPv2-only shape is unverified live either way.
    """
    profile = _profile_name(profile)
    ssh_username, ssh_password = _clean(ssh_username), _clean(ssh_password)
    http_username, http_password = _clean(http_username), _clean(http_password)
    https_username, https_password = _clean(https_username), _clean(https_password)
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
            "A credential profile needs at least one credential: give an SSH, HTTP or HTTPS "
            "username/password pair, or an SNMPv2 read/write community."
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

    Used on the create tool's error output: ``check_job`` echoes a non-envelope
    response body and ``http_error`` echoes the platform's error detail, either
    of which could contain the request body — and with it the plaintext
    passwords/communities — verbatim.
    """
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(secret, "******")
    return text


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

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

        Args:
            profile: name filter (exact, case-insensitive, '*' wildcard; surrounding
                whitespace is stripped and a blank filter means no filter).
            page_size / page: filterData paging (0-based page).
            response_format: 'markdown' (default) or 'json'.

        Returns:
            str: Markdown "- **profile** — types: SSH (user), HTTP (user), SNMPv2" lines,
            or JSON:
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
            body = query_body({"profile": name}, page_size=50, page=0)
            data = await client.request_json("POST", CREDENTIALS_QUERY_PATH, json_body=body)
            items, _, _ = unwrap(data, "data")
            wanted = name.lower()
            for item in items:
                if isinstance(item, dict) and str(item.get("profile", "")).lower() == wanted:
                    return finalize(to_json(item), settings)
            if not items:
                raise PlatformError(
                    f"Credential profile '{name}' not found. List existing profiles with "
                    "cnc_list_credential_profiles (names are exact-match, case-insensitive)."
                )
            names = ", ".join(str(i.get("profile", "?")) for i in items if isinstance(i, dict))
            raise PlatformError(
                f"'{name}' matches several profiles ({names}) but none exactly. "
                "Pass one exact profile name."
            )
        except Exception as e:
            return format_error(e)

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
        profile: Annotated[
            str,
            Field(
                description="Name of the new profile (e.g. 'cml-xrd'). Must be unique.",
                min_length=1,
                max_length=200,
            ),
        ],
        ssh_username: Annotated[
            str | None,
            Field(
                description="SSH login user (e.g. 'cisco'). Requires ssh_password.", max_length=200
            ),
        ] = None,
        ssh_password: Annotated[
            str | None,
            Field(description="SSH login password. Requires ssh_username.", max_length=500),
        ] = None,
        http_username: Annotated[
            str | None,
            Field(
                description="HTTP login user (e.g. 'cisco'). Requires http_password.",
                max_length=200,
            ),
        ] = None,
        http_password: Annotated[
            str | None,
            Field(description="HTTP login password. Requires http_username.", max_length=500),
        ] = None,
        https_username: Annotated[
            str | None,
            Field(
                description="HTTPS login user (e.g. 'admin'). Requires https_password.",
                max_length=200,
            ),
        ] = None,
        https_password: Annotated[
            str | None,
            Field(description="HTTPS login password. Requires https_username.", max_length=500),
        ] = None,
        snmpv2_read_community: Annotated[
            str | None,
            Field(description="SNMPv2c read community (e.g. 'public').", max_length=200),
        ] = None,
        snmpv2_write_community: Annotated[
            str | None,
            Field(description="SNMPv2c write community (e.g. 'private').", max_length=200),
        ] = None,
        enable_password: Annotated[
            str | None,
            Field(
                description=(
                    "Enable/privileged-mode password for the SSH credential (IOS-style "
                    "devices). Only valid together with ssh_username/ssh_password."
                ),
                max_length=500,
            ),
        ] = None,
    ) -> str:
        """Create a credential profile holding SSH / HTTP / HTTPS logins and SNMPv2 communities.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true. Create the
        profile BEFORE adding devices or providers that reference it by name.

        At least one credential must be given; usernames and passwords come in pairs
        (ssh_username + ssh_password, ...). enable_password is attached to the SSH
        credential only. Typical lab profile: ssh_username/ssh_password plus
        snmpv2_read_community='public'. Every string argument is stripped and a
        whitespace-only value counts as not given.

        Verified live: the SSH + HTTP pair + SNMPv2 read-community shape (captured
        from the UI). Expected but unverified live (confirm in the write-phase smoke
        run): SNMPv2-only profiles (no user/password pair — "user_pass" is omitted
        from the body), HTTPS pairs, snmpv2_write_community and enable_password.

        Not supported by this tool (wire enums unverified): NETCONF, gNMI, gRPC,
        Telnet and SNMPv3 credentials — add those in the Crosswork UI.

        The POST is not auto-retried (a lost response could otherwise create the
        profile twice, which the platform would reject as a duplicate name).
        Submitted secrets are scrubbed ("******") from any error text returned, so
        an error message shows "******" wherever a secret's text happens to occur
        (e.g. in a profile name that contains the password).

        Args:
            profile: unique profile name.
            ssh_username/ssh_password, http_username/http_password,
            https_username/https_password: login pairs, each optional as a pair.
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
            On failure: "Error: Create credential profile ... failed (job ..., state
            JOB_FAILED): <platform reason>" (e.g. a profile with that name already
            exists), or "Error: <validation message>" before any request is sent.
        """
        secrets = (
            ssh_password,
            http_password,
            https_password,
            enable_password,
            snmpv2_read_community,
            snmpv2_write_community,
        )
        try:
            name = _profile_name(profile)
            body = build_create_body(
                profile=name,
                ssh_username=ssh_username,
                ssh_password=ssh_password,
                http_username=http_username,
                http_password=http_password,
                https_username=https_username,
                https_password=https_password,
                snmpv2_read_community=snmpv2_read_community,
                snmpv2_write_community=snmpv2_write_community,
                enable_password=enable_password,
            )
            result = await client.request_json("POST", CREDENTIALS_PATH, json_body=body)
            envelope = credential_job(result, f"Create credential profile '{name}'")
            return finalize(to_json(envelope), settings)
        except Exception as e:
            # Both check_job (non-envelope echo) and http_error (platform detail) can
            # reflect the request body; never let a submitted secret reach the agent.
            return scrub_secrets(format_error(e), (_clean(s) for s in secrets))

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
