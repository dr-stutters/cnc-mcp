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


def build(settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    credentials.register(mcp, ctx)
    return mcp


# --- registration / gating -------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert {"cnc_list_credential_profiles", "cnc_get_credential_profile"} <= names
    assert not ({"cnc_create_credential_profile", "cnc_delete_credential_profile"} & names)

    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert tools["cnc_create_credential_profile"].annotations.read_only_hint is False
    assert tools["cnc_create_credential_profile"].annotations.destructive_hint is False
    assert tools["cnc_delete_credential_profile"].annotations.destructive_hint is True
    assert tools["cnc_list_credential_profiles"].annotations.read_only_hint is True


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
async def test_create_profile_impacted_entry_is_never_whitespace_split(make_settings):
    # Unlike devices/providers ("<uuid> <name> [<ip>]"), a credential entry is
    # passed through verbatim so a name containing spaces stays intact.
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
async def test_create_profile_snmp_only_omits_user_pass(make_settings):
    # No user/password pair -> "user_pass" is omitted (not sent as []), the
    # same way v2_info is omitted when no community is given. Unverified live.
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
    route = respx.post(WRITE_URL).mock(return_value=httpx.Response(200, json={}))
    mcp = build(make_settings(enable_writes=True))
    # Secrets are realistic-length values: every submitted secret is scrubbed
    # from error text, so a one-character sentinel would mangle the message.
    cases = [
        ({"profile": "p"}, "at least one credential"),
        ({"profile": "p", "ssh_username": "u"}, "ssh_username and ssh_password"),
        ({"profile": "p", "http_password": SECRET}, "http_username and http_password"),
        ({"profile": "p", "https_username": "x"}, "https_username and https_password"),
        (
            {"profile": "p", "enable_password": SECRET, "snmpv2_read_community": "public"},
            "enable_password only applies to the SSH credential",
        ),
    ]
    for args, expected in cases:
        text = await call_tool_text(mcp, "cnc_create_credential_profile", args)
        assert text.startswith("Error:") and expected in text, args
    assert not route.called


@respx.mock
async def test_create_profile_failed_job_is_error(make_settings):
    respx.post(WRITE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "job_id": "j-9",
                "state": "JOB_FAILED",
                "type": "1 credential(s) addition failed",
                "error": "Credential profile already exists",
            },
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {"profile": "nso", "ssh_username": "u", "ssh_password": SECRET},
    )
    assert text.startswith("Error:")
    assert "JOB_FAILED" in text and "already exists" in text and "j-9" in text
    assert SECRET not in text  # password never echoed


@respx.mock
async def test_create_profile_http_error_is_string(make_settings):
    respx.post(WRITE_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_create_credential_profile",
        {"profile": "p", "ssh_username": "u", "ssh_password": SECRET},
    )
    assert text.startswith("Error:") and "500" in text
    assert SECRET not in text


@respx.mock
async def test_create_profile_non_envelope_echo_does_not_leak_secrets(make_settings):
    # check_job echoes a non-envelope body ("Response: ..."); if the platform
    # reflected the request, every submitted secret would come back verbatim.
    community = "c0mm-R3ad-77"
    write_community = "c0mm-Wr1te-88"
    enable = "En4ble-QQ-5"
    http_pw = "Http-Pw-Z1"
    https_pw = "Https-Pw-Z2"
    echo = {
        "data": [
            {
                "profile": "echo",
                "user_pass": [
                    {"user_name": "u", "password": SECRET, "enable_password_data": enable},
                    {"user_name": "hu", "password": http_pw},
                    {"user_name": "su", "password": https_pw},
                ],
                "v2_info": {"read_community": community, "write_community": write_community},
            }
        ]
    }
    respx.post(WRITE_URL).mock(return_value=httpx.Response(200, json=echo))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_credential_profile",
        {
            "profile": "echo",
            "ssh_username": "u",
            "ssh_password": SECRET,
            "enable_password": enable,
            "http_username": "hu",
            "http_password": http_pw,
            "https_username": "su",
            "https_password": https_pw,
            "snmpv2_read_community": community,
            "snmpv2_write_community": write_community,
        },
    )
    assert text.startswith("Error:") and "did not return a job envelope" in text
    for secret in (SECRET, enable, http_pw, https_pw, community, write_community):
        assert secret not in text, secret
    assert "******" in text  # scrubbed, not silently dropped
    assert "'echo'" in text  # non-secret context (profile name) is kept


@respx.mock
async def test_create_profile_4xx_detail_does_not_leak_secrets(make_settings):
    # http_error appends "Platform said: <detail>"; a validation response that
    # quotes the offending value must not hand the password back to the agent.
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
