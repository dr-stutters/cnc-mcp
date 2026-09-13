"""Credential-profile tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not via tools/__init__.py) so these tests do
not depend on ALL_MODULES. All HTTP is mocked with respx.
"""

from __future__ import annotations

import json

import httpx
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import credentials
from tests.conftest import BASE_URL, call_tool_text

QUERY_URL = f"{BASE_URL}/crosswork/inventory/v1/credentials/query"
WRITE_URL = f"{BASE_URL}/crosswork/inventory/v1/credentials"

NSO = {
    "profile": "nso",
    "user_pass": [
        {"user_name": "admin", "password": "******", "type": "ROBOT_USERPASS_SSH"},
        {"user_name": "admin", "password": "******", "type": "ROBOT_USERPASS_HTTP"},
        {"user_name": "admin", "password": "******", "type": "ROBOT_USERPASS_HTTPS"},
    ],
}
# The real API masks secrets on read ("******", as in NSO above). This fixture
# deliberately carries clear-text-looking values so the markdown tests can prove
# the renderer never prints secret fields, whatever the API returns.
XRD_SECRET_PASSWORD = "xrd-p4ss-clear"
XRD_SECRET_COMMUNITY = "c0mmunity-xyz"
XRD = {
    "profile": "cml-xrd",
    "user_pass": [
        {
            "user_name": "cisco",
            "password": XRD_SECRET_PASSWORD,
            "enable_password_data": "",
            "type": "ROBOT_USERPASS_SSH",
        }
    ],
    "v2_info": {"read_community": XRD_SECRET_COMMUNITY},
}
LISTING = {"data": [NSO, XRD], "total_count": 3, "result_count": 3}
NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})

# Distinctive secret used by the create tests: must never appear in tool output.
SECRET = "S3cret-XYZ-9"

# What the safety read (POST credentials/query, filter profile=<name>) answers.
# result_count is omitted when nothing matched, as the platform does.
NO_MATCH = {"total_count": 3}
# The lab profile as it reads live after the 2026-09-14 gNMI onboarding (masked).
XRD_LIVE = {
    "profile": "cml-xrd",
    "user_pass": [
        {
            "user_name": "cisco",
            "password": "******",
            "enable_password_data": "",
            "type": "ROBOT_USERPASS_SSH",
        },
        {"user_name": "cisco", "password": "******", "type": "ROBOT_USERPASS_HTTP"},
        {"user_name": "cisco", "password": "******", "type": "ROBOT_USERPASS_GRPC"},
        {"user_name": "cisco", "password": "******", "type": "ROBOT_USERPASS_GNMI"},
    ],
    "v2_info": {"read_community": "******"},
}


def found(*items: dict) -> dict:
    """A credentials/query response carrying the given profiles."""
    return {"data": list(items), "total_count": 3, "result_count": len(items)}


def mock_lookup(*responses: dict):
    """Mock the safety read: one response per call (the last one repeats)."""
    if len(responses) == 1:
        return respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json=responses[0]))
    return respx.post(QUERY_URL).mock(side_effect=[httpx.Response(200, json=r) for r in responses])


def build(settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    credentials.register(mcp, ctx)
    return mcp


# --- registration / gating -------------------------------------------------


WRITE_TOOLS = {
    "cnc_create_credential_profile",
    "cnc_update_credential_profile",
    "cnc_delete_credential_profile",
}


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert {"cnc_list_credential_profiles", "cnc_get_credential_profile"} <= names
    assert not (WRITE_TOOLS & names)

    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert WRITE_TOOLS <= set(tools)
    assert tools["cnc_create_credential_profile"].annotations.read_only_hint is False
    assert tools["cnc_create_credential_profile"].annotations.destructive_hint is False
    assert tools["cnc_delete_credential_profile"].annotations.destructive_hint is True
    assert tools["cnc_list_credential_profiles"].annotations.read_only_hint is True
    # PUT re-sends the whole profile (existing passwords overwritten; unsupported
    # types dropped under force): destructive, idempotent.
    update = tools["cnc_update_credential_profile"].annotations
    assert update.read_only_hint is False
    assert update.destructive_hint is True
    assert update.idempotent_hint is True


async def test_credential_arguments_are_flat_and_identical_for_create_and_update(make_settings):
    # Flat parameters (no $ref / nested model) and the same credential set on both
    # tools, so an agent can re-send a create's arguments to an update unchanged
    # (update only adds the optional force flag).
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    create = tools["cnc_create_credential_profile"].input_schema
    update = tools["cnc_update_credential_profile"].input_schema
    assert "$ref" not in json.dumps(create) and "$ref" not in json.dumps(update)
    assert set(update["properties"]) - set(create["properties"]) == {"force"}
    assert set(create["properties"]) <= set(update["properties"])
    assert update["properties"]["force"]["default"] is False
    assert create["required"] == ["profile"] and update["required"] == ["profile"]
    for pair in ("ssh", "http", "https", "grpc", "gnmi", "netconf"):
        assert {f"{pair}_username", f"{pair}_password"} <= set(update["properties"]), pair


def test_unsupported_credential_types_names_what_the_put_would_drop():
    assert credentials.unsupported_credential_types(XRD_LIVE) == []
    assert credentials.unsupported_credential_types(NSO) == []
    mixed = {
        "profile": "mixed",
        "user_pass": [
            {"user_name": "cisco", "password": "******", "type": "ROBOT_USERPASS_SSH"},
            {"user_name": "tel", "password": "******", "type": "ROBOT_USERPASS_TELNET"},
            {"user_name": "adm", "password": "******", "type": "ROBOT_USERPASS_ADMIN"},
            {"user_name": "x", "password": "******"},  # no type at all
            "not-a-dict",
        ],
        "v2_info": {"read_community": "******"},
        "v3_info": {"user_name": "v3u", "security_level": "SL_AUTH_PRIV"},
    }
    assert credentials.unsupported_credential_types(mixed) == [
        "TELNET (tel)",
        "ADMIN (adm)",
        "? (x)",
        "SNMPv3",
    ]


# --- cnc_list_credential_profiles -----------------------------------------


@respx.mock
async def test_list_profiles_markdown_and_query_body(settings):
    route = respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json=LISTING))
    text = await call_tool_text(
        build(settings), "cnc_list_credential_profiles", {"profile": "*", "page_size": 2}
    )
    assert json.loads(route.calls[0].request.content) == {
        "filter": {"profile": "*"},
        "filterData": {"PageSize": 2, "PageNum": 0, "Criteria": ""},
    }
    assert "**nso** — types: SSH (admin), HTTP (admin), HTTPS (admin)" in text
    assert "**cml-xrd** — types: SSH (cisco), SNMPv2" in text
    assert "page=1" in text  # has_more: 2 of 3 shown
    # Markdown never prints secret fields: neither the API's mask nor the
    # clear-text-looking fixture values, nor the field names themselves.
    assert "******" not in text and "password" not in text
    assert XRD_SECRET_PASSWORD not in text and XRD_SECRET_COMMUNITY not in text


@respx.mock
async def test_list_profiles_strips_filter_and_blank_means_no_filter(settings):
    route = respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json=LISTING))
    mcp = build(settings)
    await call_tool_text(mcp, "cnc_list_credential_profiles", {"profile": "  nso  "})
    assert json.loads(route.calls[0].request.content)["filter"] == {"profile": "nso"}
    await call_tool_text(mcp, "cnc_list_credential_profiles", {"profile": "   "})
    assert json.loads(route.calls[1].request.content)["filter"] == {}


@respx.mock
async def test_list_profiles_json_envelope_uses_page_terms(settings):
    route = respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json=LISTING))
    text = await call_tool_text(
        build(settings),
        "cnc_list_credential_profiles",
        {"page_size": 2, "page": 1, "response_format": "json"},
    )
    body = json.loads(route.calls[0].request.content)
    assert body["filter"] == {} and body["filterData"]["PageNum"] == 1
    assert "offset" not in body and "limit" not in body
    data = json.loads(text)
    assert data["total"] == 3 and data["collection_total"] == 3
    assert data["count"] == 2 and data["page"] == 1 and data["page_size"] == 2
    assert data["has_more"] is False and data["next_page"] is None
    assert data["items"][0]["profile"] == "nso"


@respx.mock
async def test_list_profiles_empty_inventory_is_bare_dict(settings):
    respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(build(settings), "cnc_list_credential_profiles", {})
    assert not text.startswith("Error:")
    assert "0 shown" in text and "No credential profiles matched" in text


@respx.mock
async def test_list_profiles_error_is_string(make_settings):
    respx.post(QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_credential_profiles", {}
    )
    assert text.startswith("Error:") and "500" in text
    assert "malformed request body" in text  # errors.py NATS hint


# --- cnc_get_credential_profile -------------------------------------------


@respx.mock
async def test_get_profile_returns_full_record(settings):
    route = respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json={"data": [NSO], "total_count": 3, "result_count": 1})
    )
    text = await call_tool_text(build(settings), "cnc_get_credential_profile", {"profile": "NSO"})
    assert json.loads(route.calls[0].request.content)["filter"] == {"profile": "NSO"}
    assert json.loads(text) == NSO


@respx.mock
async def test_get_profile_strips_name_on_the_wire(settings):
    # The platform matches exactly: a padded filter would come back 'not found'.
    route = respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json={"data": [NSO], "total_count": 3, "result_count": 1})
    )
    text = await call_tool_text(
        build(settings), "cnc_get_credential_profile", {"profile": "  nso  "}
    )
    assert json.loads(route.calls[0].request.content)["filter"] == {"profile": "nso"}
    assert json.loads(text) == NSO


@respx.mock
async def test_get_profile_blank_name_is_error_without_request(settings):
    route = respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json=LISTING))
    text = await call_tool_text(build(settings), "cnc_get_credential_profile", {"profile": "   "})
    assert text.startswith("Error:") and "must not be empty" in text
    assert not route.called


@respx.mock
async def test_get_profile_not_found(settings):
    respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json={"total_count": 3}))
    text = await call_tool_text(
        build(settings), "cnc_get_credential_profile", {"profile": "missing"}
    )
    assert text.startswith("Error:") and "'missing' not found" in text


@respx.mock
async def test_get_profile_wildcard_without_exact_match(settings):
    respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json=LISTING))
    text = await call_tool_text(build(settings), "cnc_get_credential_profile", {"profile": "*"})
    assert text.startswith("Error:") and "several profiles (nso, cml-xrd)" in text


@respx.mock
async def test_get_profile_api_error_is_string(make_settings):
    respx.post(QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_credential_profile", {"profile": "nso"}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_create_credential_profile ----------------------------------------


@respx.mock
async def test_create_profile_sends_ui_shaped_body(make_settings):
    lookup = mock_lookup(NO_MATCH)
    route = respx.post(WRITE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "job_id": "j-1",
                "state": "JOB_COMPLETED",
                "type": "1 credential(s) added successfully",
                "impacted": ["cml-xrd"],
            },
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {
            "profile": "cml-xrd",
            "ssh_username": "cisco",
            "ssh_password": "cisco",
            "http_username": "cisco",
            "http_password": "cisco",
            "snmpv2_read_community": "public",
        },
    )
    # Safety read first (exact-name filter), then the POST.
    assert json.loads(lookup.calls[0].request.content)["filter"] == {"profile": "cml-xrd"}
    assert json.loads(route.calls[0].request.content) == {
        "data": [
            {
                "profile": "cml-xrd",
                "user_pass": [
                    {
                        "user_name": "cisco",
                        "password": "cisco",
                        "enable_password_data": "",
                        "type": "ROBOT_USERPASS_SSH",
                    },
                    {"user_name": "cisco", "password": "cisco", "type": "ROBOT_USERPASS_HTTP"},
                ],
                "v2_info": {"read_community": "public"},
            }
        ]
    }
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED" and data["job_id"] == "j-1"
    # Profiles have no UUID: the raw impacted entry is exposed under "profile".
    assert data["impacted_objects"] == [{"profile": "cml-xrd"}]


@respx.mock
async def test_create_profile_refuses_existing_name_and_sends_nothing(make_settings):
    # The API document calls POST /credentials "Add or Overwrite": a create with
    # an existing name must never reach the platform.
    lookup = mock_lookup(found(XRD_LIVE))
    route = respx.post(WRITE_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {"profile": "CML-XRD", "ssh_username": "cisco", "ssh_password": SECRET},
    )
    assert text.startswith("Error:") and "'cml-xrd' already exists" in text
    assert "SSH (cisco), HTTP (cisco), GRPC (cisco), GNMI (cisco), SNMPv2" in text
    assert "nothing was sent" in text and "cnc_update_credential_profile" in text
    assert SECRET not in text and "******" not in text
    assert json.loads(lookup.calls[0].request.content)["filter"] == {"profile": "CML-XRD"}
    assert not route.called


@respx.mock
async def test_create_profile_proceeds_when_lookup_matches_only_other_names(make_settings):
    # A wildcard-shaped name may match other profiles; only an exact
    # (case-insensitive) match blocks the create.
    mock_lookup(found(XRD_LIVE))
    route = respx.post(WRITE_URL).mock(
        return_value=httpx.Response(200, json={"job_id": "j-1d", "state": "JOB_COMPLETED"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {"profile": "cml-xrd-2", "ssh_username": "cisco", "ssh_password": SECRET},
    )
    assert not text.startswith("Error:") and route.called


@respx.mock
async def test_create_profile_failed_safety_read_sends_nothing(make_settings):
    mock = respx.post(QUERY_URL).mock(return_value=NATS_500)
    route = respx.post(WRITE_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_create_credential_profile",
        {"profile": "p", "ssh_username": "u", "ssh_password": SECRET},
    )
    assert text.startswith("Error:") and "500" in text
    assert mock.called and not route.called
    assert SECRET not in text


@respx.mock
async def test_create_profile_impacted_entry_is_never_whitespace_split(make_settings):
    # Unlike devices/providers ("<uuid> <name> [<ip>]"), a credential entry is
    # passed through verbatim so a name containing spaces stays intact.
    mock_lookup(NO_MATCH)
    respx.post(WRITE_URL).mock(
        return_value=httpx.Response(
            200,
            json={"job_id": "j-1b", "state": "JOB_COMPLETED", "impacted": ["lab profile one", 7]},
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {"profile": "lab profile one", "ssh_username": "u", "ssh_password": SECRET},
    )
    data = json.loads(text)
    assert data["impacted_objects"] == [{"profile": "lab profile one"}]
    assert "uuid" not in text


@respx.mock
async def test_create_profile_strips_arguments_and_ignores_whitespace_only(make_settings):
    mock_lookup(NO_MATCH)
    route = respx.post(WRITE_URL).mock(
        return_value=httpx.Response(
            200, json={"job_id": "j-1c", "state": "JOB_COMPLETED", "impacted": ["padded"]}
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {
            "profile": "  padded  ",
            "ssh_username": " cisco ",
            "ssh_password": f" {SECRET} ",
            "enable_password": "   ",  # whitespace-only -> unset
            "snmpv2_read_community": " public ",
            "snmpv2_write_community": " ",  # whitespace-only -> unset
        },
    )
    assert json.loads(route.calls[0].request.content) == {
        "data": [
            {
                "profile": "padded",
                "user_pass": [
                    {
                        "user_name": "cisco",
                        "password": SECRET,
                        "enable_password_data": "",
                        "type": "ROBOT_USERPASS_SSH",
                    }
                ],
                "v2_info": {"read_community": "public"},
            }
        ]
    }
    assert json.loads(text)["impacted_objects"] == [{"profile": "padded"}]


@respx.mock
async def test_create_profile_whitespace_only_pair_is_not_a_credential(make_settings):
    # A whitespace-only username/password used to pass bool() validation and be
    # sent as a real SSH credential; now it counts as unset.
    route = respx.post(WRITE_URL).mock(return_value=httpx.Response(200, json={}))
    mcp = build(make_settings(enable_writes=True))
    text = await call_tool_text(
        mcp,
        "cnc_create_credential_profile",
        {"profile": "p", "ssh_username": " ", "ssh_password": " "},
    )
    assert text.startswith("Error:") and "at least one credential" in text
    text = await call_tool_text(
        mcp,
        "cnc_create_credential_profile",
        {"profile": "p", "ssh_username": "u", "ssh_password": " "},
    )
    assert text.startswith("Error:") and "ssh_username and ssh_password" in text
    text = await call_tool_text(
        mcp,
        "cnc_create_credential_profile",
        {"profile": "   ", "ssh_username": "u", "ssh_password": SECRET},
    )
    assert text.startswith("Error:") and "must not be empty" in text
    assert not route.called


@respx.mock
async def test_create_profile_https_enable_and_write_community(make_settings):
    mock_lookup(NO_MATCH)
    route = respx.post(WRITE_URL).mock(
        return_value=httpx.Response(200, json={"job_id": "j-2", "state": "JOB_COMPLETED"})
    )
    await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {
            "profile": "p",
            "ssh_username": "u",
            "ssh_password": "s",
            "enable_password": "en",
            "https_username": "hu",
            "https_password": "hp",
            "snmpv2_write_community": "private",
        },
    )
    item = json.loads(route.calls[0].request.content)["data"][0]
    assert item["user_pass"] == [
        {
            "user_name": "u",
            "password": "s",
            "enable_password_data": "en",
            "type": "ROBOT_USERPASS_SSH",
        },
        {"user_name": "hu", "password": "hp", "type": "ROBOT_USERPASS_HTTPS"},
    ]
    assert item["v2_info"] == {"write_community": "private"}


@respx.mock
async def test_create_profile_grpc_gnmi_netconf_pairs(make_settings):
    # gRPC / gNMI enums verified live 2026-09-14 (lab profile cml-xrd carries
    # SSH+HTTP+GRPC+GNMI); NETCONF is the API document's example shape. Entry
    # order: SSH, HTTP, HTTPS, GRPC, GNMI, NETCONF.
    mock_lookup(NO_MATCH)
    route = respx.post(WRITE_URL).mock(
        return_value=httpx.Response(
            200, json={"job_id": "j-6", "state": "JOB_COMPLETED", "impacted": ["cml-xrd"]}
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {
            "profile": "cml-xrd",
            "netconf_username": "nc",
            "netconf_password": "nc-pw",
            "gnmi_username": "cisco",
            "gnmi_password": "gnmi-pw",
            "grpc_username": "cisco",
            "grpc_password": "grpc-pw",
            "ssh_username": "cisco",
            "ssh_password": "ssh-pw",
        },
    )
    item = json.loads(route.calls[0].request.content)["data"][0]
    assert item["user_pass"] == [
        {
            "user_name": "cisco",
            "password": "ssh-pw",
            "enable_password_data": "",
            "type": "ROBOT_USERPASS_SSH",
        },
        {"user_name": "cisco", "password": "grpc-pw", "type": "ROBOT_USERPASS_GRPC"},
        {"user_name": "cisco", "password": "gnmi-pw", "type": "ROBOT_USERPASS_GNMI"},
        {"user_name": "nc", "password": "nc-pw", "type": "ROBOT_USERPASS_NETCONF"},
    ]
    assert "v2_info" not in item
    assert json.loads(text)["impacted_objects"] == [{"profile": "cml-xrd"}]


@respx.mock
async def test_create_profile_gnmi_only_is_a_valid_profile(make_settings):
    # A single gRPC/gNMI/NETCONF pair satisfies "at least one credential".
    mock_lookup(NO_MATCH)
    route = respx.post(WRITE_URL).mock(
        return_value=httpx.Response(200, json={"job_id": "j-6b", "state": "JOB_COMPLETED"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {"profile": "gnmi-only", "gnmi_username": " cisco ", "gnmi_password": f" {SECRET} "},
    )
    assert not text.startswith("Error:")
    assert json.loads(route.calls[0].request.content)["data"][0] == {
        "profile": "gnmi-only",
        "user_pass": [{"user_name": "cisco", "password": SECRET, "type": "ROBOT_USERPASS_GNMI"}],
    }


@respx.mock
async def test_create_profile_snmp_only_omits_user_pass(make_settings):
    # No user/password pair -> "user_pass" is omitted (not sent as []), the
    # same way v2_info is omitted when no community is given. Unverified live.
    mock_lookup(NO_MATCH)
    route = respx.post(WRITE_URL).mock(
        return_value=httpx.Response(200, json={"job_id": "j-3", "state": "JOB_COMPLETED"})
    )
    await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {"profile": "snmp-only", "snmpv2_read_community": "public"},
    )
    item = json.loads(route.calls[0].request.content)["data"][0]
    assert item == {"profile": "snmp-only", "v2_info": {"read_community": "public"}}
    assert "user_pass" not in item


@respx.mock
async def test_create_profile_validation_errors_send_nothing(make_settings):
    # Validation runs before the safety read: neither request goes out.
    lookup = mock_lookup(NO_MATCH)
    route = respx.post(WRITE_URL).mock(return_value=httpx.Response(200, json={}))
    mcp = build(make_settings(enable_writes=True))
    # Secrets are realistic-length values: every submitted secret is scrubbed
    # from error text, so a one-character sentinel would mangle the message.
    cases = [
        ({"profile": "p"}, "at least one credential"),
        ({"profile": "p", "ssh_username": "u"}, "ssh_username and ssh_password"),
        ({"profile": "p", "http_password": SECRET}, "http_username and http_password"),
        ({"profile": "p", "https_username": "x"}, "https_username and https_password"),
        ({"profile": "p", "grpc_username": "x"}, "grpc_username and grpc_password"),
        ({"profile": "p", "grpc_password": SECRET}, "grpc_username and grpc_password"),
        ({"profile": "p", "gnmi_username": "x"}, "gnmi_username and gnmi_password"),
        ({"profile": "p", "gnmi_password": SECRET}, "gnmi_username and gnmi_password"),
        ({"profile": "p", "netconf_username": "x"}, "netconf_username and netconf_password"),
        (
            {"profile": "p", "netconf_password": SECRET},
            "netconf_username and netconf_password",
        ),
        # a whitespace-only half counts as unset, so this is still a half pair
        (
            {"profile": "p", "gnmi_username": "x", "gnmi_password": "  "},
            "gnmi_username and gnmi_password",
        ),
        (
            {"profile": "p", "enable_password": SECRET, "snmpv2_read_community": "public"},
            "enable_password only applies to the SSH credential",
        ),
    ]
    for args, expected in cases:
        text = await call_tool_text(mcp, "cnc_create_credential_profile", args)
        assert text.startswith("Error:") and expected in text, args
        assert SECRET not in text, args
    assert not route.called and not lookup.called


@respx.mock
async def test_create_profile_failed_job_is_error(make_settings):
    mock_lookup(NO_MATCH)
    respx.post(WRITE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "job_id": "j-9",
                "state": "JOB_FAILED",
                "type": "1 credential(s) addition failed",
                "error": "Profile name contains unsupported characters",
            },
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {"profile": "bad name", "ssh_username": "u", "ssh_password": SECRET},
    )
    assert text.startswith("Error:")
    assert "JOB_FAILED" in text and "unsupported characters" in text and "j-9" in text
    assert SECRET not in text  # password never echoed


@respx.mock
async def test_create_profile_http_error_is_string(make_settings):
    mock_lookup(NO_MATCH)
    respx.post(WRITE_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_create_credential_profile",
        {"profile": "p", "ssh_username": "u", "ssh_password": SECRET},
    )
    assert text.startswith("Error:") and "500" in text
    assert SECRET not in text


# Non-envelope echoes: the tool renders "did not return a job envelope. Response:
# <str(result)[:300]>". Both echoes below are sized so every secret sits INSIDE
# the 300-character window (asserted), so an unscrubbed one would be visible.
ECHO_LIMIT = 300
ALL_SECRET_ARGS = {
    "profile": "echo",
    "ssh_username": "u",
    "ssh_password": SECRET,
    "enable_password": "En4ble-QQ-5",
    "http_username": "hu",
    "http_password": "Http-Pw-Z1",
    "https_username": "su",
    "https_password": "Https-Pw-Z2",
    "grpc_username": "gu",
    "grpc_password": "Grpc-Pw-Z3",
    "gnmi_username": "nu",
    "gnmi_password": "Gnmi-Pw-Z4",
    "netconf_username": "cu",
    "netconf_password": "Netconf-Pw-Z5",
    "snmpv2_read_community": "c0mm-R3ad-77",
    "snmpv2_write_community": "c0mm-Wr1te-88",
}
PASSWORD_KEYS = (
    "ssh_password",
    "http_password",
    "https_password",
    "grpc_password",
    "gnmi_password",
    "netconf_password",
)
OTHER_SECRET_KEYS = ("enable_password", "snmpv2_read_community", "snmpv2_write_community")
# (a) the six user_pass passwords; (b) the enable password and both communities.
ECHO_PASSWORDS = {
    "data": [
        {
            "profile": "echo",
            "user_pass": [{"password": ALL_SECRET_ARGS[k]} for k in PASSWORD_KEYS],
        }
    ]
}
ECHO_OTHERS = {
    "data": [
        {
            "profile": "echo",
            "user_pass": [
                {
                    "user_name": "u",
                    "password": SECRET,
                    "enable_password_data": ALL_SECRET_ARGS["enable_password"],
                }
            ],
            "v2_info": {
                "read_community": ALL_SECRET_ARGS["snmpv2_read_community"],
                "write_community": ALL_SECRET_ARGS["snmpv2_write_community"],
            },
        }
    ]
}


def assert_inside_window(echo: dict, secrets: list[str]) -> None:
    """Self-check: every secret ends before the 300-character cut of str(echo)."""
    raw = str(echo)
    for secret in secrets:
        assert raw.index(secret) + len(secret) <= ECHO_LIMIT, (secret, raw.index(secret))


async def run_write(make_settings, tool: str, method: str, echo: dict, lookup: dict) -> str:
    mock_lookup(lookup)
    getattr(respx, method)(WRITE_URL).mock(return_value=httpx.Response(200, json=echo))
    args = ALL_SECRET_ARGS if tool == "cnc_create_credential_profile" else UPDATE_ALL_ARGS
    return await call_tool_text(build(make_settings(enable_writes=True)), tool, args)


@respx.mock
async def test_create_profile_non_envelope_echo_scrubs_every_password(make_settings):
    passwords = [ALL_SECRET_ARGS[k] for k in PASSWORD_KEYS]
    assert_inside_window(ECHO_PASSWORDS, passwords)
    text = await run_write(
        make_settings, "cnc_create_credential_profile", "post", ECHO_PASSWORDS, NO_MATCH
    )
    assert text.startswith("Error:") and "did not return a job envelope" in text
    for secret in passwords:
        assert secret not in text, secret
    # one mask per password: scrubbed, not silently dropped
    assert text.count("******") == len(passwords)
    assert "'echo'" in text  # non-secret context (profile name) is kept


@respx.mock
async def test_create_profile_non_envelope_echo_scrubs_enable_and_communities(make_settings):
    secrets = [SECRET] + [ALL_SECRET_ARGS[k] for k in OTHER_SECRET_KEYS]
    assert_inside_window(ECHO_OTHERS, secrets)
    text = await run_write(
        make_settings, "cnc_create_credential_profile", "post", ECHO_OTHERS, NO_MATCH
    )
    assert text.startswith("Error:") and "did not return a job envelope" in text
    for secret in secrets:
        assert secret not in text, secret
    assert text.count("******") == len(secrets)
    assert "'u'" in text  # usernames are not secrets


def straddling_echo(secret: str, profile: str) -> dict:
    """An echo whose password starts 10 characters before the 300-character cut.

    Filler in user_name positions it; the self-check asserts it really straddles.
    """

    def echo(filler: int) -> dict:
        return {
            "data": [
                {
                    "profile": profile,
                    "user_pass": [
                        {
                            "user_name": "f" * filler,
                            "password": secret,
                            "type": "ROBOT_USERPASS_SSH",
                        }
                    ],
                }
            ]
        }

    start = ECHO_LIMIT - 10
    result = echo(start - str(echo(0)).index(secret))
    raw = str(result)
    assert raw.index(secret) == start and start + len(secret) > ECHO_LIMIT  # straddles
    return result


@respx.mock
async def test_create_profile_secret_straddling_the_echo_cut_leaves_no_prefix(make_settings):
    # Regression: check_job used to slice the echo to 300 characters BEFORE the
    # scrub, and str.replace only matches whole secrets, so a password crossing
    # the cut came back as its first characters. The 4-character prefix check
    # implies every longer prefix is absent too.
    secret = "Qz7Straddle-" + "k" * 30 + "-END"
    mock_lookup(NO_MATCH)
    respx.post(WRITE_URL).mock(
        return_value=httpx.Response(200, json=straddling_echo(secret, "straddle"))
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {"profile": "straddle", "ssh_username": "u", "ssh_password": secret},
    )
    assert text.startswith("Error:") and "did not return a job envelope" in text
    assert secret[:4] not in text
    assert "******" in text
    # the echo is still capped: the mask replaced the secret before the cut
    response = text.split("Response: ", 1)[1]
    assert len(response) <= ECHO_LIMIT


@respx.mock
async def test_create_profile_4xx_detail_does_not_leak_secrets(make_settings):
    # http_error appends "Platform said: <detail>"; a validation response that
    # quotes the offending value must not hand the password back to the agent.
    mock_lookup(NO_MATCH)
    respx.post(WRITE_URL).mock(
        return_value=httpx.Response(
            400, json={"error": f"invalid value '{SECRET}' for field password"}
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_create_credential_profile",
        {"profile": "p", "ssh_username": "u", "ssh_password": SECRET},
    )
    assert text.startswith("Error:") and "400" in text
    assert SECRET not in text and "invalid value '******'" in text


# --- cnc_update_credential_profile ----------------------------------------

# The live 2026-09-14 gNMI-onboarding call: the lab profile re-sent in full
# (SSH + HTTP + SNMPv2 read community) plus the GRPC and GNMI pairs.
NSO_ADVISORY = (
    "Note, if Credential Profile cml-xrd is used in NSO, any updates to it needs be done "
    "through NSO interface"
)
UPDATE_ARGS = {
    "profile": "cml-xrd",
    "ssh_username": "cisco",
    "ssh_password": SECRET,
    "http_username": "cisco",
    "http_password": SECRET,
    "grpc_username": "cisco",
    "grpc_password": SECRET,
    "gnmi_username": "cisco",
    "gnmi_password": SECRET,
    "snmpv2_read_community": "public",
}
UPDATE_ALL_ARGS = {**ALL_SECRET_ARGS, "profile": "cml-xrd"}
UPDATE_BODY = {
    "data": [
        {
            "profile": "cml-xrd",
            "user_pass": [
                {
                    "user_name": "cisco",
                    "password": SECRET,
                    "enable_password_data": "",
                    "type": "ROBOT_USERPASS_SSH",
                },
                {"user_name": "cisco", "password": SECRET, "type": "ROBOT_USERPASS_HTTP"},
                {"user_name": "cisco", "password": SECRET, "type": "ROBOT_USERPASS_GRPC"},
                {"user_name": "cisco", "password": SECRET, "type": "ROBOT_USERPASS_GNMI"},
            ],
            "v2_info": {"read_community": "public"},
        }
    ]
}
UPDATE_WARNING_JOB = {
    "job_id": "j-7",
    "state": "JOB_COMPLETED_WITH_WARNING",
    "type": "1 credential(s) updated successfully",
    "error": NSO_ADVISORY,
    "impacted": ["cml-xrd"],
}
# A profile the update tool cannot re-send in full: Telnet pair + SNMPv3 block.
MIXED_LIVE = {
    "profile": "mixed",
    "user_pass": [
        {"user_name": "cisco", "password": "******", "type": "ROBOT_USERPASS_SSH"},
        {"user_name": "tel", "password": "******", "type": "ROBOT_USERPASS_TELNET"},
    ],
    "v3_info": {"user_name": "v3u", "security_level": "SL_AUTH_PRIV"},
}


@respx.mock
async def test_update_profile_puts_full_definition_and_renders_advisory(make_settings):
    lookup = mock_lookup(found(XRD_LIVE))
    route = respx.put(WRITE_URL).mock(return_value=httpx.Response(200, json=UPDATE_WARNING_JOB))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_update_credential_profile", UPDATE_ARGS
    )
    # Safety read first (exact-name filter), then the PUT.
    assert json.loads(lookup.calls[0].request.content)["filter"] == {"profile": "cml-xrd"}
    request = route.calls[0].request
    assert request.method == "PUT"
    assert str(request.url) == WRITE_URL  # collection URL; no /credentials/{name}
    assert json.loads(request.content) == UPDATE_BODY
    # JOB_COMPLETED_WITH_WARNING is a success: the NSO advisory is rendered, not raised.
    assert not text.startswith("Error:")
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED_WITH_WARNING" and data["job_id"] == "j-7"
    assert data["warning"] == NSO_ADVISORY
    assert data["impacted_objects"] == [{"profile": "cml-xrd"}]


@respx.mock
async def test_update_profile_plain_completed_has_no_warning(make_settings):
    mock_lookup(found(XRD_LIVE))
    respx.put(WRITE_URL).mock(
        return_value=httpx.Response(
            200, json={"job_id": "j-7b", "state": "JOB_COMPLETED", "impacted": ["cml-xrd"]}
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_update_credential_profile", UPDATE_ARGS
    )
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED" and "warning" not in data


@respx.mock
async def test_update_profile_strips_name_and_omits_unset_entries(make_settings):
    # Only what is given goes on the wire (whether the platform removes an
    # omitted entry or keeps it is unverified live; the tool never claims either).
    mock_lookup(found(XRD_LIVE))
    route = respx.put(WRITE_URL).mock(return_value=httpx.Response(200, json=UPDATE_WARNING_JOB))
    await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_update_credential_profile",
        {"profile": " cml-xrd ", "gnmi_username": "cisco", "gnmi_password": SECRET},
    )
    assert json.loads(route.calls[0].request.content) == {
        "data": [
            {
                "profile": "cml-xrd",
                "user_pass": [
                    {"user_name": "cisco", "password": SECRET, "type": "ROBOT_USERPASS_GNMI"}
                ],
            }
        ]
    }


@respx.mock
async def test_update_profile_refuses_unknown_name_and_sends_nothing(make_settings):
    # What PUT does with an unknown name is unverified: never sent.
    mock_lookup(NO_MATCH)
    route = respx.put(WRITE_URL).mock(return_value=httpx.Response(200, json=UPDATE_WARNING_JOB))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_update_credential_profile",
        {**UPDATE_ARGS, "profile": "nope"},
    )
    assert text.startswith("Error:") and "'nope' not found" in text
    assert "nothing was sent" in text and "cnc_create_credential_profile" in text
    assert SECRET not in text and not route.called


@respx.mock
async def test_update_profile_refuses_to_drop_unsupported_types_unless_forced(make_settings):
    # The PUT re-sends the whole definition: a Telnet pair or SNMPv3 block the
    # tool cannot express would be dropped, so it refuses and names them.
    mock_lookup(found(MIXED_LIVE))
    route = respx.put(WRITE_URL).mock(return_value=httpx.Response(200, json=UPDATE_WARNING_JOB))
    mcp = build(make_settings(enable_writes=True))
    args = {"profile": "mixed", "ssh_username": "cisco", "ssh_password": SECRET}
    text = await call_tool_text(mcp, "cnc_update_credential_profile", args)
    assert text.startswith("Error:")
    assert "cannot re-send: TELNET (tel), SNMPv3" in text
    assert "DROPPED" in text and "nothing was sent" in text and "force=true" in text
    assert SECRET not in text and not route.called
    # force=true: the PUT goes out with only what this tool can express.
    text = await call_tool_text(mcp, "cnc_update_credential_profile", {**args, "force": True})
    assert not text.startswith("Error:") and route.call_count == 1
    item = json.loads(route.calls[0].request.content)["data"][0]
    assert [e["type"] for e in item["user_pass"]] == ["ROBOT_USERPASS_SSH"]
    assert "v3_info" not in item


@respx.mock
async def test_update_profile_force_does_not_skip_the_existence_check(make_settings):
    mock_lookup(NO_MATCH)
    route = respx.put(WRITE_URL).mock(return_value=httpx.Response(200, json=UPDATE_WARNING_JOB))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_update_credential_profile",
        {**UPDATE_ARGS, "force": True},
    )
    assert text.startswith("Error:") and "not found" in text and not route.called


@respx.mock
async def test_update_profile_failed_safety_read_sends_nothing(make_settings):
    respx.post(QUERY_URL).mock(return_value=NATS_500)
    route = respx.put(WRITE_URL).mock(return_value=httpx.Response(200, json=UPDATE_WARNING_JOB))
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_update_credential_profile",
        UPDATE_ARGS,
    )
    assert text.startswith("Error:") and "500" in text
    assert SECRET not in text and not route.called


@respx.mock
async def test_update_profile_failed_job_is_error(make_settings):
    mock_lookup(found(XRD_LIVE))
    respx.put(WRITE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "job_id": "j-8",
                "state": "JOB_FAILED",
                "type": "1 credential(s) updation failed",
                "error": "Credential profile is locked by NSO",
            },
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_update_credential_profile", UPDATE_ARGS
    )
    assert text.startswith("Error:")
    assert "Update credential profile 'cml-xrd'" in text
    assert "JOB_FAILED" in text and "locked by NSO" in text and "j-8" in text
    assert SECRET not in text


@respx.mock
async def test_update_profile_validation_errors_send_nothing(make_settings):
    # Validation runs before the safety read: neither request goes out.
    lookup = mock_lookup(found(XRD_LIVE))
    route = respx.put(WRITE_URL).mock(return_value=httpx.Response(200, json=UPDATE_WARNING_JOB))
    mcp = build(make_settings(enable_writes=True))
    cases = [
        ({"profile": "cml-xrd"}, "at least one credential"),
        ({"profile": "cml-xrd", "gnmi_username": "cisco"}, "gnmi_username and gnmi_password"),
        ({"profile": "cml-xrd", "gnmi_password": SECRET}, "gnmi_username and gnmi_password"),
        ({"profile": "cml-xrd", "grpc_password": SECRET}, "grpc_username and grpc_password"),
        (
            {"profile": "cml-xrd", "netconf_username": "nc"},
            "netconf_username and netconf_password",
        ),
        ({"profile": "cml-xrd", "ssh_username": "u"}, "ssh_username and ssh_password"),
        (
            {
                "profile": "cml-xrd",
                "enable_password": SECRET,
                "gnmi_username": "u",
                "gnmi_password": SECRET,
            },
            "enable_password only applies to the SSH credential",
        ),
        ({"profile": "   ", "gnmi_username": "u", "gnmi_password": SECRET}, "must not be empty"),
    ]
    for args, expected in cases:
        text = await call_tool_text(mcp, "cnc_update_credential_profile", args)
        assert text.startswith("Error:") and expected in text, args
        assert SECRET not in text, args
    assert not route.called and not lookup.called


@respx.mock
async def test_update_profile_4xx_detail_does_not_leak_secrets(make_settings):
    mock_lookup(found(XRD_LIVE))
    respx.put(WRITE_URL).mock(
        return_value=httpx.Response(
            400, json={"error": f"invalid value '{SECRET}' for field password"}
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_update_credential_profile",
        UPDATE_ARGS,
    )
    assert text.startswith("Error:") and "400" in text
    assert SECRET not in text and "invalid value '******'" in text


@respx.mock
async def test_update_profile_non_envelope_echo_scrubs_every_password(make_settings):
    # The update re-sends every entry, so its echoes are the longest: the same
    # in-window echoes as the create tests, one mask per secret.
    passwords = [ALL_SECRET_ARGS[k] for k in PASSWORD_KEYS]
    assert_inside_window(ECHO_PASSWORDS, passwords)
    text = await run_write(
        make_settings, "cnc_update_credential_profile", "put", ECHO_PASSWORDS, found(XRD_LIVE)
    )
    assert text.startswith("Error:") and "did not return a job envelope" in text
    for secret in passwords:
        assert secret not in text, secret
    assert text.count("******") == len(passwords)
    assert "Update credential profile 'cml-xrd'" in text


@respx.mock
async def test_update_profile_non_envelope_echo_scrubs_enable_and_communities(make_settings):
    secrets = [SECRET] + [ALL_SECRET_ARGS[k] for k in OTHER_SECRET_KEYS]
    assert_inside_window(ECHO_OTHERS, secrets)
    text = await run_write(
        make_settings, "cnc_update_credential_profile", "put", ECHO_OTHERS, found(XRD_LIVE)
    )
    assert text.startswith("Error:") and "did not return a job envelope" in text
    for secret in secrets:
        assert secret not in text, secret
    assert text.count("******") == len(secrets)


@respx.mock
async def test_update_profile_secret_straddling_the_echo_cut_leaves_no_prefix(make_settings):
    # Reproduces the live cml-xrd-shaped leak: a long gRPC password crossing the
    # 300-character cut of the echo must not survive as a prefix.
    secret = "Qz7Straddle-" + "g" * 30 + "-END"
    mock_lookup(found(XRD_LIVE))
    respx.put(WRITE_URL).mock(
        return_value=httpx.Response(200, json=straddling_echo(secret, "cml-xrd"))
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_update_credential_profile",
        {**UPDATE_ARGS, "grpc_password": secret},
    )
    assert text.startswith("Error:") and "did not return a job envelope" in text
    assert secret[:4] not in text and SECRET not in text
    assert "******" in text
    assert len(text.split("Response: ", 1)[1]) <= ECHO_LIMIT


@respx.mock
async def test_update_profile_http_error_is_string(make_settings):
    mock_lookup(found(XRD_LIVE))
    respx.put(WRITE_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_update_credential_profile",
        UPDATE_ARGS,
    )
    assert text.startswith("Error:") and "500" in text
    assert SECRET not in text


@respx.mock
async def test_update_profile_put_is_retried_but_create_post_is_not(make_settings):
    # Update's safety read finds the profile; create's (same name) must not.
    mock_lookup(found(XRD_LIVE), NO_MATCH)
    # PUT is idempotent: the client's default retries a 503 and the update succeeds.
    put = respx.put(WRITE_URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json=UPDATE_WARNING_JOB)]
    )
    mcp = build(make_settings(enable_writes=True, max_retries=1))
    text = await call_tool_text(mcp, "cnc_update_credential_profile", UPDATE_ARGS)
    assert put.call_count == 2 and not text.startswith("Error:")
    # A lost POST response leaves the outcome unknown (the API document says the
    # POST overwrites): not retried.
    post = respx.post(WRITE_URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json=UPDATE_WARNING_JOB)]
    )
    text = await call_tool_text(mcp, "cnc_create_credential_profile", UPDATE_ARGS)
    assert post.call_count == 1 and text.startswith("Error:") and "503" in text


# --- cnc_delete_credential_profile ----------------------------------------


@respx.mock
async def test_delete_profile_sends_body_on_collection_url(make_settings):
    route = respx.delete(WRITE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "job_id": "j-4",
                "state": "JOB_COMPLETED",
                "type": "1 credential(s) deleted successfully",
                "impacted": ["cml-xrd"],
            },
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_delete_credential_profile",
        {"profile": " cml-xrd "},  # stripped before it goes on the wire
    )
    request = route.calls[0].request
    assert request.method == "DELETE"
    assert json.loads(request.content) == {"data": [{"profile": "cml-xrd"}]}
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED"
    assert data["impacted_objects"] == [{"profile": "cml-xrd"}]


@respx.mock
async def test_delete_profile_blank_name_is_error_without_request(make_settings):
    route = respx.delete(WRITE_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_delete_credential_profile",
        {"profile": "  "},
    )
    assert text.startswith("Error:") and "must not be empty" in text
    assert not route.called


@respx.mock
async def test_delete_profile_failed_job_is_error(make_settings):
    respx.delete(WRITE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "job_id": "j-5",
                "state": "JOB_FAILED",
                "type": "1 credential(s) deletion failed",
                "error": "Profile is in use by devices",
            },
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_delete_credential_profile",
        {"profile": "nso"},
    )
    assert text.startswith("Error:") and "in use" in text and "JOB_FAILED" in text


@respx.mock
async def test_delete_profile_http_error_is_string(make_settings):
    respx.delete(WRITE_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_delete_credential_profile",
        {"profile": "nso"},
    )
    assert text.startswith("Error:") and "500" in text
