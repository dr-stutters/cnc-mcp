"""ZTP object writes (configuration files, profiles, serial numbers, static routes,
devices) end-to-end through MCPServer, all HTTP mocked with respx.

Every platform answer below is VERBATIM from the live verification on Crosswork
7.2 (2026-09-15, phase-d-* objects created and removed again): the configsvc
201/409/400/404 bodies, the HTTP-200-with-``code`` verdicts of the ZTP writes
(201 create / route add / route delete, 200 update / profile or device delete,
204 serial delete), the JSON-list ``message`` of a code-422 device write, the
code-200 "does not exist" of a device delete, the code-424 profile-in-use
answer and the asynchronous static-route statuses.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from cnc_mcp.errors import PlatformError
from cnc_mcp.tools.swim_ztp import (
    canonical_config_type,
    check_ztp_write,
    config_update_params,
    config_upload_params,
    default_config_file_name,
    device_body,
    device_not_deleted,
    device_update_body,
    find_route,
    parse_ztp_error_list,
    profile_body,
    profile_update_body,
    references_of,
    route_installed,
    route_settled,
    serial_counts,
    split_csv,
    validate_device_form,
    validate_ipv4_subnet,
)
from tests.conftest import call_tool_text
from tests.test_tools_swim_ztp import (
    CONFIGSVC,
    DEVICE,
    DEVICES_EMPTY,
    DEVICES_URL,
    PROFILE,
    PROFILES_EMPTY,
    PROFILES_URL,
    ROUTES_EMPTY,
    ROUTES_URL,
    SERIALS_EMPTY,
    SERIALS_URL,
    ZTP,
    build,
    sent,
)

CONFIGS_URL = f"{CONFIGSVC}/configs"
UPLOAD_URL = f"{CONFIGSVC}/configs/upload"
FILES_URL = f"{CONFIGSVC}/configs/files"
PROFILES_WRITE_URL = f"{ZTP}/profiles"
DEVICES_WRITE_URL = f"{ZTP}/devices"
SERIALS_WRITE_URL = f"{ZTP}/serialnumbers"
ROUTES_WRITE_URL = f"{ZTP}/staticroutes"

CONF_ID = "1b471b84-8234-480d-8855-9525aa754d1b"
PROFILE_ID = "a86fb7dd-9e2c-4424-a197-56ea9b4ee7b5"
DEVICE_UUID = "9f75f79b-b1ec-4903-99c3-dfebcd5fed1b"
ROUTE_UUID = "7332d85d-9146-49cf-9fe8-c5058d3fadc6"
ZERO = "00000000-0000-0000-0000-000000000000"
BANNER = "!! IOS XR\nhostname phase-d-ztp\n"

# --- configsvc answers (verified) ---------------------------------------------------------

CONFIG_CREATED = {
    "confId": CONF_ID,
    "confName": "phase-d-ztp-cfg",
    "fileName": "phase-d-ztp-cfg.txt",
    "osName": "IOS XR",
    "version": "7.0.2",
    "size": 31,
    "deviceFamily": "CISCO NCS540",
    "createdTime": 1789483159979,
    "modifiedTime": 1789483159979,
    "downloadurl": f"http://<CW_HOST_IP>:30604/crosswork/ztpconfig/v1/config/file/{CONF_ID}",
    "type": "Day0-config",
    "extraPlaceHolders": "",
    "childIds": "",
    "vendor": "Cisco Systems",
}
CONFIG_DUPLICATE = httpx.Response(
    409, json={"message": "Configuration already exists with name phase-d-ztp-cfg", "status": 409}
)
CONFIG_NO_BANNER = httpx.Response(
    400,
    json={
        "message": "Text (.txt) script should have '!! IOS XR' in any of the first three lines",
        "status": 400,
    },
)
CONFIG_NOT_FOUND = httpx.Response(
    404, json={"message": f"Config not found for {CONF_ID}", "status": 404}
)
# A Pre-config script (verified 2026-09-15: needs a secure-ZTP-capable version — 7.0.2 is
# refused as "classic", 7.3.1 accepted) and the secure profile that references it.
PRE_ID = "641e9c7f-e82b-47ce-9b40-185a857b09b4"
PRE_CONFIG = {
    **CONFIG_CREATED,
    "confId": PRE_ID,
    "confName": "phase-d-ztp-pre",
    "fileName": "phase-d-ztp-pre.py",
    "version": "7.3.1",
    "size": 51,
    "type": "Pre-config",
}
CONFIG_CLASSIC_VERSION = httpx.Response(
    400,
    json={
        "message": "Pre-config do not support the classic version 7.0.2 for platform IOS XR",
        "status": 400,
    },
)

# --- ZTP profile answers (verified) ------------------------------------------------------

PROFILE_CREATED = {"code": 201, "message": "Profile Created Successfully"}
PROFILE_DUPLICATE = {
    "code": 400,
    "message": "Profile with name already exist : phase-d-ztp-profile",
}
PROFILE_UPDATED = {"code": 200, "message": "Profile Updated Successfully"}
PROFILE_DELETED = {"code": 200}
PROFILE_NOT_FOUND = {"code": 404, "message": f"Profile with name {ZERO} does not exist"}
PROFILE_IN_USE = {"code": 424, "message": "Profile  can not be deleted"}
MY_PROFILE = {
    "profileId": PROFILE_ID,
    "profileName": "phase-d-ztp-profile",
    "profileDescription": "phase D smoke",
    "osPlatform": "IOS XR",
    "deviceFamily": "CISCO NCS540",
    "version": "7.0.2",
    "config": CONF_ID,
    "isSecureZtp": "false",
    "profileCategory": "0day",
    "lastUpdated": "1789483253878",
    "configName": "phase-d-ztp-cfg",
    "vendor": "Cisco Systems",
}
MY_PROFILES = {
    "ztpProfiles": [MY_PROFILE],
    "code": 200,
    "paginationDetails": {"PageSize": 500, "TotalCount": 1},
}
# The verified record of a secure-ZTP profile carrying a Pre-config: the pre/post ids and
# names appear only when set; isPreConfigInvalid appears once the script is deleted.
SECURE_PROFILE = {
    **MY_PROFILE,
    "profileId": "1efe6e3c-1eaa-4feb-adf9-9762ffb2e222",
    "profileName": "phase-d-ztp-sztp",
    "version": "7.3.1",
    "isSecureZtp": "true",
    "preConfig": PRE_ID,
    "preConfigName": "phase-d-ztp-pre",
}
PROFILE_NEEDS_SECURE = {
    "code": 400,
    "message": (
        "Secure ZTP flag should be enabled to support pre/post configurations for profile "
        "phase-d-ztp-sztp."
    ),
}

# --- ZTP serial-number answers (verified) -------------------------------------------------

SERIALS_ADDED = {"code": 201, "message": "Created Successfully", "processedRecordCount": 2}
SERIALS_DUPLICATE = {"code": 201, "message": "Created Successfully", "duplicateRecordCount": 1}
SERIALS_DELETED = {"code": 204, "message": "Deleted Successfully"}
SERIAL_IN_USE = {
    "code": 400,
    "message": "Serial Number {PHASED0001} is in use, cannot be deleted. ",
}


def serial_rows(*entries: tuple[str, str]) -> dict[str, Any]:
    return {
        "data": [
            {"serialNumber": s, "isOVLinked": "false", "isInUse": u, "modifiedDate": "1789483066"}
            for s, u in entries
        ],
        "pagination": {"TotalCount": len(entries)},
        "code": 200,
        "message": "Get is success",
    }


# --- ZTP static-route answers (verified) --------------------------------------------------

ROUTE_ADD_STARTED = {"code": 201, "message": "Add static route is initiated. Updating the status."}
ROUTE_DUPLICATE = {"code": 400, "message": "192.0.2.0/24 : Route already exists"}
ROUTE_DELETE_STARTED = {
    "code": 201,
    "message": "Delete static route is initiated. Updating the status.",
}
ROUTE_NOT_FOUND = {"code": 400, "message": f"{ZERO} : Route does not exists"}
ROUTE_BUSY = {"code": 400, "message": "192.0.2.0/24 : Route is already in Inprogress state"}


def route_row(status: str, message: str | None = None) -> dict[str, Any]:
    row = {
        "uuid": ROUTE_UUID,
        "subnet": "192.0.2.0",
        "mask": "24",
        "status": status,
        "modifiedDate": "1789483083290",
    }
    if message:
        row["message"] = message
    return row


def routes_answer(*rows: dict[str, Any]) -> dict[str, Any]:
    if not rows:
        return ROUTES_EMPTY
    return {
        "ztpStaticRoutes": list(rows),
        "code": 200,
        "paginationDetails": {"PageSize": 500, "TotalCount": len(rows)},
    }


ROUTE_SUCCESS = route_row("success", "Route-192.0.2.0/24,198.18.134.221-Success")
# Only "success" was seen live; a failed install (spelling unverified) must not read as
# "added".
ROUTE_FAILED = route_row("add-failed", "Route-192.0.2.0/24,198.18.134.221-Failed")

# --- ZTP device answers (verified) --------------------------------------------------------

DEVICE_CREATED = {"code": 201, "message": "Device Added Successfully"}
DEVICE_UPDATED = {"code": 200, "message": "Device Updated Successfully"}
DEVICE_DELETED = {"code": 200}
DEVICE_DELETE_MISSING = {
    "code": 200,
    "message": f"1) Device with UUID : {DEVICE_UUID} does not exist.",
}
DEVICE_PUT_UNKNOWN = {"code": 404, "message": f"1) Device with UUID : {ZERO} does not exist."}


def device_errors(*errors: str, host: str = "phase-d-ztp-node") -> dict[str, Any]:
    return {
        "code": 422,
        "message": json.dumps([{"hostName": host, "errorMsg": e} for e in errors]),
    }


DEVICE_SERIAL_NOT_ALLOWED = device_errors(
    "Serial Number(s) not present in allowed list: PHASED0003"
)
DEVICE_VERSION_MISMATCH = device_errors("Version doesn't match with: Day0-config")
DEVICE_NO_CREDENTIAL = device_errors("Credential Profile not found.", host="phase-d-ztp-node-b")
# Verified 2026-09-15: a secure profile needs a secure device, and a secure device a serial
# with an ownership voucher (OV import is not exposed — no secure device was created live).
DEVICE_SECURE_MISMATCH = device_errors(
    "Cannot associate the Secure ZTP enabled Profile to secure ZTP disabled Device."
)
DEVICE_NO_OV = device_errors(
    "Can not associate serial(s) PHASED0001 with secure ZTP enabled device as OV is not linked."
)
MY_DEVICE = {
    "uuid": DEVICE_UUID,
    "hostName": "phase-d-ztp-node",
    "serialNumber": ["PHASED0001"],
    "credentialProfile": "cml-xrd",
    "ipAddress": {},
    "osPlatform": "IOS XR",
    "version": "7.0.2",
    "deviceFamily": "CISCO NCS540",
    "config": CONF_ID,
    "profileName": "phase-d-ztp-profile",
    "status": "Unprovisioned",
    "providerInfo": {},
    "lastUpdated": "1789483337113",
    "configName": "phase-d-ztp-cfg",
    "isSecureZtp": "false",
    "secureZtpInfo": {},
    "enableOption82": "false",
    "vendor": "Cisco Systems",
}


def devices_answer(*rows: dict[str, Any]) -> dict[str, Any]:
    if not rows:
        return DEVICES_EMPTY
    return {
        "ztpnodes": list(rows),
        "code": 200,
        "paginationDetails": {"PageSize": 500, "TotalCount": len(rows)},
    }


# --- helpers -------------------------------------------------------------------------------


def writes(make_settings):
    return build(make_settings(enable_writes=True))


def mock_json(method: str, url: str, body, status: int = 200) -> respx.Route:
    return getattr(respx, method)(url).mock(return_value=httpx.Response(status, json=body))


def mock_query(url: str, *answers) -> respx.Route:
    """One ZTP query URL answering the given bodies in call order (the last one repeats)."""
    responses = [httpx.Response(200, json=a) for a in answers]
    served = 0

    def side_effect(request):
        nonlocal served
        response = responses[min(served, len(responses) - 1)]
        served += 1
        return response

    return respx.post(url).mock(side_effect=side_effect)


def query_filter(route: respx.Route, index: int = 0) -> dict:
    return sent(route, index)["filter"]


WRITE_TOOLS = {
    "cnc_upload_ztp_config_file": (False, False),
    "cnc_update_ztp_config_file": (True, True),
    "cnc_delete_ztp_config_file": (True, True),
    "cnc_create_ztp_profile": (False, False),
    "cnc_update_ztp_profile": (True, True),
    "cnc_delete_ztp_profile": (True, True),
    "cnc_add_ztp_serial_numbers": (False, True),
    "cnc_delete_ztp_serial_numbers": (True, True),
    "cnc_create_ztp_static_route": (False, False),
    "cnc_delete_ztp_static_route": (True, True),
    "cnc_create_ztp_device": (False, False),
    "cnc_update_ztp_device": (True, True),
    "cnc_delete_ztp_device": (True, True),
}


# --- registration ----------------------------------------------------------------------------


async def test_write_tools_hidden_without_writes_and_annotated_with_them(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert not (set(WRITE_TOOLS) & names)
    tools = {t.name: t for t in await writes(make_settings).list_tools()}
    assert set(WRITE_TOOLS) <= set(tools)
    for name, (destructive, idempotent) in WRITE_TOOLS.items():
        tool = tools[name]
        assert tool.annotations.read_only_hint is False, name
        assert tool.annotations.destructive_hint is destructive, name
        assert tool.annotations.idempotent_hint is idempotent, name
        assert "deprecated in the 7.2 documents" in " ".join(tool.description.split()), name
    upload = tools["cnc_upload_ztp_config_file"].input_schema
    assert upload["required"] == ["name", "platform", "version", "device_family", "content"]
    assert upload["properties"]["config_type"]["default"] == "Day0-config"
    route = tools["cnc_create_ztp_static_route"].input_schema["properties"]
    assert route["wait_seconds"]["default"] == 15 and route["prefix_length"]["maximum"] == 32


# --- pure helpers -----------------------------------------------------------------------------


def test_split_csv_and_ztp_bool_forms():
    assert split_csv(" a, b ,a,,c ") == ["a", "b", "c"]
    assert split_csv(",") == []


def test_parse_ztp_error_list_decodes_the_device_json_list_and_keeps_plain_text():
    assert parse_ztp_error_list(DEVICE_SERIAL_NOT_ALLOWED["message"]) == [
        "phase-d-ztp-node: Serial Number(s) not present in allowed list: PHASED0003"
    ]
    assert parse_ztp_error_list("192.0.2.0/24 : Route already exists") == [
        "192.0.2.0/24 : Route already exists"
    ]
    assert parse_ztp_error_list("[not json") == ["[not json"]
    assert parse_ztp_error_list("   ") == []


def test_check_ztp_write_accepts_the_verified_verdicts_and_hints_device_rules():
    assert check_ztp_write(PROFILE_CREATED, "w") is PROFILE_CREATED
    assert check_ztp_write(PROFILE_DELETED, "w") is PROFILE_DELETED
    assert check_ztp_write(SERIALS_DELETED, "w") is SERIALS_DELETED
    assert check_ztp_write({"ok": True}, "w") == {"ok": True}  # no code: accepted
    with pytest.raises(PlatformError) as info:
        check_ztp_write(DEVICE_SERIAL_NOT_ALLOWED, "ZTP device create")
    text = str(info.value)
    assert text.startswith(
        "ZTP device create failed (ZTP answered code 422): phase-d-ztp-node: Serial Number(s) "
        "not present in allowed list: PHASED0003. register the serial number first"
    )
    # An errorMsg that already ends in "." is not doubled before the hint.
    with pytest.raises(PlatformError) as info:
        check_ztp_write(DEVICE_NO_CREDENTIAL, "ZTP device create")
    assert str(info.value) == (
        "ZTP device create failed (ZTP answered code 422): phase-d-ztp-node-b: Credential "
        "Profile not found. cnc_list_credential_profiles shows the profile names."
    )
    # A plain-text message (route / profile / serial writes) gets no device hints.
    with pytest.raises(PlatformError) as info:
        check_ztp_write(ROUTE_DUPLICATE, "ZTP static route add")
    assert str(info.value) == (
        "ZTP static route add failed (ZTP answered code 400): 192.0.2.0/24 : Route already exists"
    )
    with pytest.raises(PlatformError, match="unexpected response shape"):
        check_ztp_write("nope", "w")


def test_device_not_deleted_reads_the_code_200_miss():
    assert device_not_deleted(DEVICE_DELETE_MISSING).startswith("1) Device with UUID")
    assert device_not_deleted({"code": 200, "message": "1) UUID is missing."})
    assert device_not_deleted(DEVICE_DELETED) is None


def test_profile_bodies_follow_the_document_example_and_never_echo_lastupdated():
    body = profile_body(
        name=" p ",
        config_id="c",
        platform="IOS XR",
        device_family="F",
        version="1",
        secure_ztp=True,
    )
    assert body == {
        "profileName": "p",
        "profileDescription": "",
        "profileCategory": "0day",
        "vendor": "Cisco Systems",
        "osPlatform": "IOS XR",
        "deviceFamily": "F",
        "version": "1",
        "image": "",
        "isSecureZtp": "true",
        "preConfig": "",
        "postConfig": "",
        "config": "c",
    }
    update = profile_update_body(MY_PROFILE, {"description": "new", "image_id": None})
    assert "lastUpdated" not in update and "configName" not in update
    assert update["profileId"] == PROFILE_ID and update["profileName"] == "phase-d-ztp-profile"
    assert update["profileDescription"] == "new" and update["config"] == CONF_ID
    assert update["isSecureZtp"] == "false"
    assert profile_update_body(MY_PROFILE, {"secure_ztp": True})["isSecureZtp"] == "true"


def test_device_bodies_take_exactly_one_form():
    profile_form = device_body(
        host_name="h", serial_number="S1", credential_profile="cp", platform="IOS XR",
        profile_name="p",
    )  # fmt: skip
    assert profile_form == {
        "hostName": "h",
        "serialNumber": ["S1"],
        "credentialProfile": "cp",
        "osPlatform": "IOS XR",
        "status": "Unprovisioned",
        "isSecureZtp": "false",
        "enableOption82": "false",
        "profileName": "p",
    }
    metadata_form = device_body(
        host_name="h", serial_number="S1", credential_profile="cp", platform="IOS XR",
        config_id="c", version="1", device_family="F", uuid="u",
    )  # fmt: skip
    assert "profileName" not in metadata_form and metadata_form["uuid"] == "u"
    assert (metadata_form["config"], metadata_form["version"]) == ("c", "1")
    validate_device_form("p", "", "", "")
    validate_device_form("", "c", "1", "F")
    with pytest.raises(PlatformError, match="either profile_name alone"):
        validate_device_form("p", "c", "", "")
    with pytest.raises(PlatformError, match="all three of config_id"):
        validate_device_form("", "c", "", "F")
    # An update rebuilds the create form from the record: no lastUpdated, no profile-derived
    # metadata next to the profile name; '' switches to the metadata form.
    kept = device_update_body(MY_DEVICE, {"host_name": "renamed"})
    assert kept["profileName"] == "phase-d-ztp-profile" and "version" not in kept
    assert kept["uuid"] == DEVICE_UUID and kept["hostName"] == "renamed"
    assert kept["serialNumber"] == ["PHASED0001"] and "lastUpdated" not in kept
    switched = device_update_body(MY_DEVICE, {"profile_name": "", "serial_number": "S2"})
    assert "profileName" not in switched and switched["config"] == CONF_ID
    assert switched["version"] == "7.0.2" and switched["serialNumber"] == ["S2"]


def test_config_helpers():
    assert config_upload_params(name="n", platform="IOS XR", version="1", device_family="F") == {
        "confname": "n",
        "osname": "IOS XR",
        "version": "1",
        "devicefamily": "F",
        "vendor": "Cisco Systems",
        "type": "Day0-config",
    }
    assert config_update_params(name="", version=" 2 ", vendor="V", other="x") == {
        "version": "2",
        "vendor": "V",
    }
    assert default_config_file_name("ncs540 day0/v2") == "ncs540-day0-v2.txt"
    assert default_config_file_name("  ") == "config.txt"
    assert canonical_config_type("day0-CONFIG") == "Day0-config"
    with pytest.raises(PlatformError, match="config_type must be one of"):
        canonical_config_type("Weird")
    assert references_of([MY_PROFILE], [MY_DEVICE], CONF_ID) == (
        ["phase-d-ztp-profile"],
        ["phase-d-ztp-node"],
    )
    assert references_of([MY_PROFILE], [MY_DEVICE], "other") == ([], [])
    # A script referenced through preConfig / postConfig is a reference too, labelled by
    # field; the same profile answering several queries is listed once per field.
    assert references_of([SECURE_PROFILE, SECURE_PROFILE], [], PRE_ID) == (
        ["phase-d-ztp-sztp (as preConfig)"],
        [],
    )
    both = {**SECURE_PROFILE, "postConfig": PRE_ID}
    assert references_of([both], [MY_DEVICE], PRE_ID)[0] == [
        "phase-d-ztp-sztp (as preConfig)",
        "phase-d-ztp-sztp (as postConfig)",
    ]
    assert references_of([SECURE_PROFILE], [MY_DEVICE, MY_DEVICE], CONF_ID) == (
        ["phase-d-ztp-sztp"],
        ["phase-d-ztp-node"],
    )


def test_route_helpers():
    assert route_settled(None) and route_settled(ROUTE_SUCCESS)
    assert not route_settled(route_row("add-inprogress"))
    assert not route_settled(route_row("delete-inprogress"))
    assert route_installed(ROUTE_SUCCESS) and route_installed(route_row("Success"))
    assert route_settled(ROUTE_FAILED) and not route_installed(ROUTE_FAILED)
    assert not route_installed(None) and not route_installed(route_row("add-inprogress"))
    assert find_route([ROUTE_SUCCESS], "192.0.2.0", "24") is ROUTE_SUCCESS
    assert find_route([ROUTE_SUCCESS], "192.0.2.0", "25") is None
    assert validate_ipv4_subnet(" 10.3.2.0 ", 24) == "10.3.2.0"
    with pytest.raises(PlatformError, match="has host bits set"):
        validate_ipv4_subnet("192.0.2.1", 24)
    with pytest.raises(PlatformError, match="not a valid IPv4 network"):
        validate_ipv4_subnet("nope", 24)
    assert serial_counts(SERIALS_ADDED) == (2, 0)
    assert serial_counts(SERIALS_DUPLICATE) == (0, 1)


# --- configuration files ----------------------------------------------------------------------


@respx.mock
async def test_upload_ztp_config_file_sends_multipart_with_query_metadata(make_settings):
    route = respx.post(UPLOAD_URL).mock(return_value=httpx.Response(201, json=CONFIG_CREATED))
    text = await call_tool_text(
        writes(make_settings),
        "cnc_upload_ztp_config_file",
        {
            "name": "phase-d-ztp-cfg",
            "platform": "IOS XR",
            "version": "7.0.2",
            "device_family": "CISCO NCS540",
            "content": BANNER,
        },
    )
    request = route.calls[0].request
    assert dict(request.url.params) == {
        "confname": "phase-d-ztp-cfg",
        "osname": "IOS XR",
        "version": "7.0.2",
        "devicefamily": "CISCO NCS540",
        "vendor": "Cisco Systems",
        "type": "Day0-config",
    }
    assert request.headers["Content-Type"].startswith("multipart/form-data; boundary=")
    assert b'name="configFile"; filename="phase-d-ztp-cfg.txt"' in request.content
    assert BANNER.encode() in request.content
    assert text.startswith(
        f"ZTP configuration file 'phase-d-ztp-cfg' uploaded (id {CONF_ID}, 31 bytes).\n\n"
    )
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["config"]["confId"] == CONF_ID and payload["sent"]["content_chars"] == 31
    assert BANNER not in text  # the content is never echoed


@respx.mock
async def test_upload_ztp_config_file_errors(make_settings):
    args = {
        "name": "phase-d-ztp-cfg",
        "platform": "IOS XR",
        "version": "7.0.2",
        "device_family": "CISCO NCS540",
        "content": "hostname x\n",
    }
    route = respx.post(UPLOAD_URL).mock(side_effect=[CONFIG_NO_BANNER, CONFIG_DUPLICATE])
    text = await call_tool_text(writes(make_settings), "cnc_upload_ztp_config_file", args)
    assert text.startswith("Error: API request failed with status 400.")
    assert "Text (.txt) script should have '!! IOS XR'" in text
    text = await call_tool_text(writes(make_settings), "cnc_upload_ztp_config_file", args)
    assert "status 409" in text and "Configuration already exists with name" in text
    text = await call_tool_text(
        writes(make_settings), "cnc_upload_ztp_config_file", {**args, "config_type": "Weird"}
    )
    assert text.startswith("Error: config_type must be one of Pre-config, Day0-config, Post-config")
    assert route.call_count == 2
    # A Pre-config for a "classic" version (verified: 7.0.2 refused, 7.3.1 accepted).
    route.mock(return_value=CONFIG_CLASSIC_VERSION)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_upload_ztp_config_file",
        {**args, "name": "phase-d-ztp-pre", "config_type": "Pre-config", "file_name": "x.py"},
    )
    assert "status 400" in text and "do not support the classic version 7.0.2" in text
    assert dict(route.calls[2].request.url.params)["type"] == "Pre-config"


@respx.mock
async def test_update_ztp_config_file_re_sends_the_current_content_when_none_given(make_settings):
    mock_json("get", f"{CONFIGS_URL}/{CONF_ID}", CONFIG_CREATED)
    download = respx.get(f"{FILES_URL}/{CONF_ID}").mock(
        return_value=httpx.Response(200, text=BANNER, headers={"Content-Type": "text/plain"})
    )
    route = respx.put(f"{CONFIGS_URL}/{CONF_ID}").mock(
        return_value=httpx.Response(200, json={**CONFIG_CREATED, "version": "7.0.3"})
    )
    text = await call_tool_text(
        writes(make_settings),
        "cnc_update_ztp_config_file",
        {"config_id": CONF_ID, "version": "7.0.3"},
    )
    assert download.call_count == 1
    request = route.calls[0].request
    assert dict(request.url.params) == {"version": "7.0.3"}
    assert (
        b'filename="phase-d-ztp-cfg.txt"' in request.content and BANNER.encode() in request.content
    )
    assert text.startswith(f"ZTP configuration file {CONF_ID} updated (version).\n\n")
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["content_replaced"] is False and payload["config"]["version"] == "7.0.3"
    # With content given the download is skipped and the new text goes out.
    text = await call_tool_text(
        writes(make_settings),
        "cnc_update_ztp_config_file",
        {"config_id": CONF_ID, "content": BANNER + "!\n"},
    )
    assert download.call_count == 1 and route.calls[1].request.url.params.get("version") is None
    assert (BANNER + "!\n").encode() in route.calls[1].request.content
    assert "updated (content)." in text
    # Whitespace-only content is "keep": the current text is downloaded and re-sent, never
    # a blank file (a Pre/Post-config script has no banner check to catch it).
    text = await call_tool_text(
        writes(make_settings),
        "cnc_update_ztp_config_file",
        {"config_id": CONF_ID, "content": "  \n ", "version": "7.0.4"},
    )
    assert download.call_count == 2 and BANNER.encode() in route.calls[2].request.content
    assert text.startswith(f"ZTP configuration file {CONF_ID} updated (version).")
    assert '"content_replaced": false' in text


@respx.mock
async def test_update_ztp_config_file_errors(make_settings):
    text = await call_tool_text(
        writes(make_settings), "cnc_update_ztp_config_file", {"config_id": CONF_ID}
    )
    assert text.startswith("Error: nothing to change")
    text = await call_tool_text(
        writes(make_settings), "cnc_update_ztp_config_file", {"config_id": CONF_ID, "content": " "}
    )
    assert text.startswith("Error: nothing to change")
    respx.get(f"{CONFIGS_URL}/{ZERO}").mock(return_value=CONFIG_NOT_FOUND)
    text = await call_tool_text(
        writes(make_settings), "cnc_update_ztp_config_file", {"config_id": ZERO, "version": "1"}
    )
    assert text.startswith(f"Error: no ZTP configuration file with id {ZERO}")
    mock_json("get", f"{CONFIGS_URL}/{CONF_ID}", CONFIG_CREATED)
    respx.put(f"{CONFIGS_URL}/{CONF_ID}").mock(return_value=CONFIG_NO_BANNER)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_update_ztp_config_file",
        {"config_id": CONF_ID, "content": "hostname x\n"},
    )
    assert "status 400" in text and "!! IOS XR" in text


@respx.mock
async def test_delete_ztp_config_file_guards_references_and_deletes(make_settings):
    mock_json("get", f"{CONFIGS_URL}/{CONF_ID}", CONFIG_CREATED)
    profiles = mock_query(PROFILES_URL, MY_PROFILES)
    devices = mock_query(DEVICES_URL, devices_answer(MY_DEVICE))
    delete = respx.delete(f"{CONFIGS_URL}/{CONF_ID}").mock(return_value=httpx.Response(204))
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_config_file", {"config_id": CONF_ID}
    )
    assert text.startswith(
        f"Error: ZTP configuration file {CONF_ID} is referenced by profile(s) "
        "phase-d-ztp-profile and device(s) phase-d-ztp-node — repoint or delete them first"
    )
    # The profiles are queried once per reference field (each an exact filter — verified);
    # the same profile answering all three is listed once.
    assert profiles.call_count == 3
    assert [query_filter(profiles, i) for i in range(3)] == [
        {"config": CONF_ID},
        {"preConfig": CONF_ID},
        {"postConfig": CONF_ID},
    ]
    assert query_filter(devices) == {"config": CONF_ID}
    assert delete.call_count == 0
    text = await call_tool_text(
        writes(make_settings),
        "cnc_delete_ztp_config_file",
        {"config_id": CONF_ID, "force": True},
    )
    assert delete.call_count == 1
    assert text.startswith(f"ZTP configuration file 'phase-d-ztp-cfg' ({CONF_ID}) deleted.\n\n")
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["forced"] is True and payload["referenced_by"]["devices"] == ["phase-d-ztp-node"]
    assert payload["referenced_by"]["profiles"] == ["phase-d-ztp-profile"]
    # No references: deleted without force.
    mock_query(PROFILES_URL, PROFILES_EMPTY)
    mock_query(DEVICES_URL, DEVICES_EMPTY)
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_config_file", {"config_id": CONF_ID}
    )
    assert delete.call_count == 2 and '"forced": false' in text


@respx.mock
async def test_delete_ztp_config_file_guards_a_pre_config_referenced_by_a_profile(make_settings):
    """A Pre-config referenced through a profile's preConfig (not its day-0 config) is a
    reference too — verified: the platform deletes it and flags isPreConfigInvalid."""
    mock_json("get", f"{CONFIGS_URL}/{PRE_ID}", PRE_CONFIG)

    def lookup(request):
        wanted = json.loads(request.content)["filter"]
        if wanted == {"preConfig": PRE_ID}:
            return httpx.Response(200, json={**MY_PROFILES, "ztpProfiles": [SECURE_PROFILE]})
        return httpx.Response(200, json=PROFILES_EMPTY)

    respx.post(PROFILES_URL).mock(side_effect=lookup)
    mock_query(DEVICES_URL, DEVICES_EMPTY)
    delete = respx.delete(f"{CONFIGS_URL}/{PRE_ID}").mock(return_value=httpx.Response(204))
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_config_file", {"config_id": PRE_ID}
    )
    assert text.startswith(
        f"Error: ZTP configuration file {PRE_ID} is referenced by profile(s) "
        "phase-d-ztp-sztp (as preConfig) — repoint or delete them first"
    )
    assert "isPreConfigInvalid" in text and delete.call_count == 0
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_config_file", {"config_id": PRE_ID, "force": True}
    )
    assert delete.call_count == 1
    assert text.startswith(f"ZTP configuration file 'phase-d-ztp-pre' ({PRE_ID}) deleted.")
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["referenced_by"]["profiles"] == ["phase-d-ztp-sztp (as preConfig)"]
    assert payload["config"]["type"] == "Pre-config"


@respx.mock
async def test_delete_ztp_config_file_errors(make_settings):
    respx.get(f"{CONFIGS_URL}/{CONF_ID}").mock(return_value=CONFIG_NOT_FOUND)
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_config_file", {"config_id": CONF_ID}
    )
    assert text.startswith(f"Error: no ZTP configuration file with id {CONF_ID}")
    mock_json("get", f"{CONFIGS_URL}/{CONF_ID}", CONFIG_CREATED)
    mock_query(PROFILES_URL, PROFILES_EMPTY)
    mock_query(DEVICES_URL, DEVICES_EMPTY)
    respx.delete(f"{CONFIGS_URL}/{CONF_ID}").mock(return_value=httpx.Response(500, text="boom"))
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_config_file", {"config_id": CONF_ID}
    )
    assert text.startswith("Error: API request failed with status 500")


# --- profiles ---------------------------------------------------------------------------------


@respx.mock
async def test_create_ztp_profile_posts_the_list_form_and_fetches_the_id_by_name(make_settings):
    route = mock_json("post", PROFILES_WRITE_URL, PROFILE_CREATED)
    query = mock_query(PROFILES_URL, MY_PROFILES)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_create_ztp_profile",
        {
            "name": "phase-d-ztp-profile",
            "config_id": CONF_ID,
            "platform": "IOS XR",
            "device_family": "CISCO NCS540",
            "version": "7.0.2",
            "description": "phase D smoke",
        },
    )
    body = sent(route)
    assert list(body) == ["profiles"] and body["profiles"][0]["config"] == CONF_ID
    assert body["profiles"][0]["isSecureZtp"] == "false" and "profileId" not in body["profiles"][0]
    assert query_filter(query) == {"profileName": "phase-d-ztp-profile"}
    assert text.startswith(f"ZTP profile 'phase-d-ztp-profile' created ({PROFILE_ID}).\n\n")
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["profile"]["configName"] == "phase-d-ztp-cfg"
    assert payload["response"] == PROFILE_CREATED


@respx.mock
async def test_create_ztp_profile_errors(make_settings):
    mock_json("post", PROFILES_WRITE_URL, PROFILE_DUPLICATE)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_create_ztp_profile",
        {
            "name": "phase-d-ztp-profile",
            "config_id": CONF_ID,
            "platform": "IOS XR",
            "device_family": "CISCO NCS540",
            "version": "7.0.2",
        },
    )
    assert text == (
        "Error: ZTP profile create failed (ZTP answered code 400): Profile with name already "
        "exist : phase-d-ztp-profile"
    )
    # A Pre-config on a classic-ZTP profile (verified answer).
    route = mock_json("post", PROFILES_WRITE_URL, PROFILE_NEEDS_SECURE)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_create_ztp_profile",
        {
            "name": "phase-d-ztp-sztp",
            "config_id": CONF_ID,
            "platform": "IOS XR",
            "device_family": "CISCO NCS540",
            "version": "7.3.1",
            "pre_config_id": PRE_ID,
        },
    )
    assert sent(route, 1)["profiles"][0]["preConfig"] == PRE_ID
    assert text == (
        "Error: ZTP profile create failed (ZTP answered code 400): Secure ZTP flag should be "
        "enabled to support pre/post configurations for profile phase-d-ztp-sztp."
    )


@respx.mock
async def test_update_ztp_profile_rebuilds_the_form_and_refuses_an_unknown_id(make_settings):
    query = mock_query(PROFILES_URL, MY_PROFILES, {**MY_PROFILES, "ztpProfiles": [
        {**MY_PROFILE, "profileDescription": "updated"}
    ]})  # fmt: skip
    route = mock_json("put", PROFILES_WRITE_URL, PROFILE_UPDATED)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_update_ztp_profile",
        {"profile_id": PROFILE_ID, "description": "updated", "secure_ztp": True},
    )
    assert query_filter(query) == {"profileId": PROFILE_ID}
    body = sent(route)
    assert body["profileId"] == PROFILE_ID and body["profileName"] == "phase-d-ztp-profile"
    assert body["profileDescription"] == "updated" and body["isSecureZtp"] == "true"
    assert "lastUpdated" not in body and body["config"] == CONF_ID
    assert text.startswith(
        f"ZTP profile 'phase-d-ztp-profile' ({PROFILE_ID}) updated (description, secure_ztp)."
    )
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["profile"]["profileDescription"] == "updated"
    assert payload["before"]["profileDescription"] == "phase D smoke"
    # Unknown id: refused BEFORE the PUT (the platform would upsert a second profile).
    mock_query(PROFILES_URL, PROFILES_EMPTY)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_update_ztp_profile",
        {"profile_id": ZERO, "description": "x"},
    )
    assert text.startswith(f"Error: no ZTP profile with id {ZERO}")
    assert "second profile under an unknown id" in text and route.call_count == 1


@respx.mock
async def test_update_ztp_profile_errors(make_settings):
    text = await call_tool_text(
        writes(make_settings), "cnc_update_ztp_profile", {"profile_id": PROFILE_ID}
    )
    assert text.startswith("Error: nothing to change")
    mock_query(PROFILES_URL, MY_PROFILES)
    mock_json("put", PROFILES_WRITE_URL, PROFILE_NOT_FOUND)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_update_ztp_profile",
        {"profile_id": PROFILE_ID, "version": "7.0.3"},
    )
    assert text.startswith("Error: ZTP profile update failed (ZTP answered code 404): Profile with")


@respx.mock
async def test_delete_ztp_profile_guards_devices_and_deletes(make_settings):
    mock_query(PROFILES_URL, MY_PROFILES)
    devices = mock_query(DEVICES_URL, devices_answer(MY_DEVICE))
    route = mock_json("delete", PROFILES_WRITE_URL, PROFILE_DELETED)
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_profile", {"profile_id": PROFILE_ID}
    )
    assert text.startswith(
        "Error: ZTP profile 'phase-d-ztp-profile' is used by device(s) phase-d-ztp-node — "
        "delete or repoint them first"
    )
    assert query_filter(devices) == {"profileName": "phase-d-ztp-profile"}
    assert route.call_count == 0
    text = await call_tool_text(
        writes(make_settings),
        "cnc_delete_ztp_profile",
        {"profile_id": PROFILE_ID, "force": True},
    )
    assert sent(route) == {"profiles": [{"profileId": PROFILE_ID}]}
    assert text.startswith(f"ZTP profile 'phase-d-ztp-profile' ({PROFILE_ID}) deleted.\n\n")
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["forced"] is True and payload["devices_using_it"] == ["phase-d-ztp-node"]


@respx.mock
async def test_delete_ztp_profile_errors(make_settings):
    mock_query(PROFILES_URL, PROFILES_EMPTY)
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_profile", {"profile_id": ZERO}
    )
    assert text.startswith(f"Error: no ZTP profile with id {ZERO}")
    mock_query(PROFILES_URL, MY_PROFILES)
    mock_query(DEVICES_URL, DEVICES_EMPTY)
    mock_json("delete", PROFILES_WRITE_URL, PROFILE_IN_USE)
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_profile", {"profile_id": PROFILE_ID}
    )
    assert text.startswith(
        "Error: ZTP profile delete failed (ZTP answered code 424): Profile  can not be deleted "
        "— a ZTP device references the profile's configuration file directly"
    )


# --- serial numbers ----------------------------------------------------------------------------


@respx.mock
async def test_add_ztp_serial_numbers_counts_new_and_duplicates(make_settings):
    route = respx.post(SERIALS_WRITE_URL).mock(
        side_effect=[
            httpx.Response(200, json=SERIALS_ADDED),
            httpx.Response(200, json=SERIALS_DUPLICATE),
        ]
    )
    text = await call_tool_text(
        writes(make_settings),
        "cnc_add_ztp_serial_numbers",
        {"serial_numbers": "PHASED0001, PHASED0002"},
    )
    assert sent(route) == {"data": [{"serialNumber": "PHASED0001"}, {"serialNumber": "PHASED0002"}]}
    assert text.startswith("2 ZTP serial number(s) registered (0 already registered).\n\n")
    text = await call_tool_text(
        writes(make_settings), "cnc_add_ztp_serial_numbers", {"serial_numbers": "PHASED0001"}
    )
    assert text.startswith("0 ZTP serial number(s) registered (1 already registered).")
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["added"] == 0 and payload["duplicates"] == 1


@respx.mock
async def test_add_ztp_serial_numbers_errors(make_settings):
    text = await call_tool_text(
        writes(make_settings), "cnc_add_ztp_serial_numbers", {"serial_numbers": " , "}
    )
    assert text.startswith("Error: no serial numbers given")
    mock_json("post", SERIALS_WRITE_URL, {"code": 500, "message": "boom"})
    text = await call_tool_text(
        writes(make_settings), "cnc_add_ztp_serial_numbers", {"serial_numbers": "X"}
    )
    assert text == "Error: ZTP serial number add failed (ZTP answered code 500): boom"


@respx.mock
async def test_delete_ztp_serial_numbers_checks_each_then_deletes_the_known(make_settings):
    def lookup(request):
        wanted = json.loads(request.content)["filter"]["serialNumber"]
        if wanted == "PHASED0009":
            return httpx.Response(200, json=SERIALS_EMPTY)
        return httpx.Response(200, json=serial_rows((wanted, "false")))

    queries = respx.post(SERIALS_URL).mock(side_effect=lookup)
    route = mock_json("delete", SERIALS_WRITE_URL, SERIALS_DELETED)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_delete_ztp_serial_numbers",
        {"serial_numbers": "PHASED0001,PHASED0002,PHASED0009"},
    )
    assert queries.call_count == 3
    assert sent(route) == {"data": [{"serialNumber": "PHASED0001"}, {"serialNumber": "PHASED0002"}]}
    assert text.startswith(
        "2 ZTP serial number(s) deleted. Not registered (skipped): PHASED0009.\n\n"
    )
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["deleted"] == ["PHASED0001", "PHASED0002"] and payload["unknown"] == [
        "PHASED0009"
    ]


@respx.mock
async def test_delete_ztp_serial_numbers_refuses_a_mixed_list_before_the_call(make_settings):
    """Verified: one in-use serial makes the platform refuse the WHOLE list (code 400,
    nothing deleted, whichever order) — so a mixed list never reaches the wire."""

    def lookup(request):
        wanted = json.loads(request.content)["filter"]["serialNumber"]
        return httpx.Response(
            200, json=serial_rows((wanted, "true" if wanted == "PHASED0001" else "false"))
        )

    respx.post(SERIALS_URL).mock(side_effect=lookup)
    route = mock_json("delete", SERIALS_WRITE_URL, SERIAL_IN_USE)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_delete_ztp_serial_numbers",
        {"serial_numbers": "PHASED0002,PHASED0001,PHASED0003"},
    )
    assert text == (
        "Error: serial number(s) PHASED0001 are bound to a ZTP device (isInUse) — delete the "
        "device first (cnc_delete_ztp_device) or repoint it (cnc_update_ztp_device), or leave "
        "them out of the list; nothing deleted."
    )
    assert route.call_count == 0


@respx.mock
async def test_delete_ztp_serial_numbers_errors(make_settings):
    mock_query(SERIALS_URL, SERIALS_EMPTY)
    route = mock_json("delete", SERIALS_WRITE_URL, SERIALS_DELETED)
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_serial_numbers", {"serial_numbers": "PHASED0001"}
    )
    assert text.startswith("Error: none of the serial numbers PHASED0001 is registered with ZTP")
    assert route.call_count == 0
    # The serial got bound between the lookup and the DELETE: the platform's own refusal.
    mock_query(SERIALS_URL, serial_rows(("PHASED0001", "false")))
    route = mock_json("delete", SERIALS_WRITE_URL, SERIAL_IN_USE)
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_serial_numbers", {"serial_numbers": "PHASED0001"}
    )
    assert text.startswith(
        "Error: ZTP serial number delete failed (ZTP answered code 400): Serial Number "
        "{PHASED0001} is in use, cannot be deleted. — nothing deleted; a serial bound to a "
        "ZTP device"
    )
    assert route.call_count == 1
    mock_json("delete", SERIALS_WRITE_URL, {"code": 500, "message": "boom"})
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_serial_numbers", {"serial_numbers": "PHASED0001"}
    )
    assert text == "Error: ZTP serial number delete failed (ZTP answered code 500): boom"


# --- static routes ------------------------------------------------------------------------------


@respx.mock
async def test_create_ztp_static_route_waits_for_the_async_add(make_settings):
    route = mock_json("post", ROUTES_WRITE_URL, ROUTE_ADD_STARTED)
    query = mock_query(
        ROUTES_URL, routes_answer(route_row("add-inprogress")), routes_answer(ROUTE_SUCCESS)
    )
    text = await call_tool_text(
        writes(make_settings),
        "cnc_create_ztp_static_route",
        {"subnet": "192.0.2.0", "prefix_length": 24, "wait_seconds": 5},
    )
    assert sent(route) == {"staticroutes": [{"subnet": "192.0.2.0", "mask": "24"}]}
    assert query.call_count == 2
    assert text.startswith(
        f"ZTP static route 192.0.2.0/24 added (uuid {ROUTE_UUID}, status success).\n\n"
    )
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["settled"] is True and payload["route"]["message"].endswith("-Success")
    assert payload["installed"] is True and payload["response"] == ROUTE_ADD_STARTED
    # wait_seconds=0: one look, reported as not settled (not an error).
    mock_query(ROUTES_URL, routes_answer(route_row("add-inprogress")))
    text = await call_tool_text(
        writes(make_settings),
        "cnc_create_ztp_static_route",
        {"subnet": "192.0.2.0", "prefix_length": 24, "wait_seconds": 0},
    )
    assert text.startswith(
        "ZTP static route 192.0.2.0/24 requested but not settled yet (add-inprogress) after 0s"
    )
    assert '"settled": false' in text and '"installed": false' in text


@respx.mock
async def test_create_ztp_static_route_reports_a_settled_failure_as_not_installed(make_settings):
    mock_json("post", ROUTES_WRITE_URL, ROUTE_ADD_STARTED)
    mock_query(ROUTES_URL, routes_answer(route_row("add-inprogress")), routes_answer(ROUTE_FAILED))
    text = await call_tool_text(
        writes(make_settings),
        "cnc_create_ztp_static_route",
        {"subnet": "192.0.2.0", "prefix_length": 24, "wait_seconds": 5},
    )
    assert not text.startswith("Error:") and "added" not in text.split("\n\n", 1)[0]
    assert text.startswith(
        "ZTP static route 192.0.2.0/24 settled with status add-failed — "
        "Route-192.0.2.0/24,198.18.134.221-Failed; the platform did not install it "
        f"(uuid {ROUTE_UUID}: cnc_list_ztp_static_routes shows the record, "
        "cnc_delete_ztp_static_route removes it)."
    )
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["settled"] is True and payload["installed"] is False
    assert payload["route"]["status"] == "add-failed"


@respx.mock
async def test_create_ztp_static_route_errors(make_settings):
    route = mock_json("post", ROUTES_WRITE_URL, ROUTE_DUPLICATE)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_create_ztp_static_route",
        {"subnet": "192.0.2.1", "prefix_length": 24},
    )
    assert text.startswith("Error: subnet '192.0.2.1' with prefix_length 24 is not a valid IPv4")
    assert route.call_count == 0
    text = await call_tool_text(
        writes(make_settings),
        "cnc_create_ztp_static_route",
        {"subnet": "192.0.2.0", "prefix_length": 24},
    )
    assert text == (
        "Error: ZTP static route add failed (ZTP answered code 400): 192.0.2.0/24 : Route "
        "already exists"
    )


@respx.mock
async def test_delete_ztp_static_route_waits_until_gone(make_settings):
    query = mock_query(
        ROUTES_URL,
        routes_answer(ROUTE_SUCCESS),
        routes_answer(route_row("delete-inprogress")),
        ROUTES_EMPTY,
    )
    route = mock_json("delete", ROUTES_WRITE_URL, ROUTE_DELETE_STARTED)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_delete_ztp_static_route",
        {"uuid": ROUTE_UUID, "wait_seconds": 5},
    )
    assert sent(route) == {"staticroutes": [{"uuid": ROUTE_UUID}]}
    assert query.call_count == 3
    assert text.startswith(f"ZTP static route 192.0.2.0/24 ({ROUTE_UUID}) deleted.\n\n")
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["gone"] is True and payload["route"]["status"] == "success"
    mock_query(ROUTES_URL, routes_answer(route_row("delete-inprogress")))
    text = await call_tool_text(
        writes(make_settings),
        "cnc_delete_ztp_static_route",
        {"uuid": ROUTE_UUID, "wait_seconds": 0},
    )
    assert "delete requested, still listed as delete-inprogress after 0s" in text


@respx.mock
async def test_delete_ztp_static_route_errors(make_settings):
    mock_query(ROUTES_URL, ROUTES_EMPTY)
    mock_json("delete", ROUTES_WRITE_URL, ROUTE_NOT_FOUND)
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_static_route", {"uuid": ZERO}
    )
    assert text.startswith(f"Error: no ZTP static route with uuid {ZERO} (ZTP answered code 400")
    mock_query(ROUTES_URL, routes_answer(route_row("delete-inprogress")))
    mock_json("delete", ROUTES_WRITE_URL, ROUTE_BUSY)
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_static_route", {"uuid": ROUTE_UUID}
    )
    assert text == (
        "Error: ZTP static route delete failed (ZTP answered code 400): 192.0.2.0/24 : Route is "
        "already in Inprogress state"
    )


# --- devices -----------------------------------------------------------------------------------


@respx.mock
async def test_create_ztp_device_profile_form_and_register_serial(make_settings):
    serials = mock_json("post", SERIALS_WRITE_URL, SERIALS_DUPLICATE)
    route = mock_json("post", DEVICES_WRITE_URL, DEVICE_CREATED)
    query = mock_query(DEVICES_URL, devices_answer(MY_DEVICE))
    text = await call_tool_text(
        writes(make_settings),
        "cnc_create_ztp_device",
        {
            "host_name": "phase-d-ztp-node",
            "serial_number": "PHASED0001",
            "credential_profile": "cml-xrd",
            "platform": "IOS XR",
            "profile_name": "phase-d-ztp-profile",
            "register_serial": True,
        },
    )
    assert sent(serials) == {"data": [{"serialNumber": "PHASED0001"}]}
    assert sent(route) == {
        "nodes": [
            {
                "hostName": "phase-d-ztp-node",
                "serialNumber": ["PHASED0001"],
                "credentialProfile": "cml-xrd",
                "osPlatform": "IOS XR",
                "status": "Unprovisioned",
                "isSecureZtp": "false",
                "enableOption82": "false",
                "profileName": "phase-d-ztp-profile",
            }
        ]
    }
    assert query_filter(query) == {"hostName": "phase-d-ztp-node"}
    assert text.startswith(
        f"ZTP device 'phase-d-ztp-node' created (uuid {DEVICE_UUID}, status Unprovisioned).\n\n"
    )
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["device"]["configName"] == "phase-d-ztp-cfg"
    assert payload["serial_registered"] == {"added": 0, "duplicates": 1}
    # Metadata form, no serial registration.
    text = await call_tool_text(
        writes(make_settings),
        "cnc_create_ztp_device",
        {
            "host_name": "phase-d-ztp-node",
            "serial_number": "PHASED0001",
            "credential_profile": "cml-xrd",
            "platform": "IOS XR",
            "config_id": CONF_ID,
            "version": "7.0.2",
            "device_family": "CISCO NCS540",
        },
    )
    node = sent(route, 1)["nodes"][0]
    assert "profileName" not in node and node["config"] == CONF_ID
    assert serials.call_count == 1 and '"serial_registered": null' in text


@respx.mock
async def test_create_ztp_device_errors(make_settings):
    args = {
        "host_name": "phase-d-ztp-node",
        "serial_number": "PHASED0003",
        "credential_profile": "cml-xrd",
        "platform": "IOS XR",
        "profile_name": "phase-d-ztp-profile",
    }
    route = mock_json("post", DEVICES_WRITE_URL, DEVICE_SERIAL_NOT_ALLOWED)
    text = await call_tool_text(
        writes(make_settings), "cnc_create_ztp_device", {**args, "version": "7.0.2"}
    )
    assert text.startswith("Error: pass either profile_name alone or config_id + version")
    assert route.call_count == 0
    text = await call_tool_text(writes(make_settings), "cnc_create_ztp_device", args)
    assert text.startswith(
        "Error: ZTP device create failed (ZTP answered code 422): phase-d-ztp-node: Serial "
        "Number(s) not present in allowed list: PHASED0003. register the serial number first "
        "with cnc_add_ztp_serial_numbers (or pass register_serial=true)."
    )
    assert "Note: serial" not in text  # nothing was registered
    # The secure-ZTP rules (verified answers) each carry their hint.
    route.mock(side_effect=[
        httpx.Response(200, json=DEVICE_SECURE_MISMATCH),
        httpx.Response(200, json=DEVICE_NO_OV),
    ])  # fmt: skip
    text = await call_tool_text(writes(make_settings), "cnc_create_ztp_device", args)
    assert text.endswith(
        "secure ZTP disabled Device. a profile with isSecureZtp true (one carrying a "
        "Pre-config / Post-config) can only be used by a device created with secure_ztp=true."
    )
    text = await call_tool_text(
        writes(make_settings), "cnc_create_ztp_device", {**args, "secure_ztp": True}
    )
    assert "as OV is not linked. a secure-ZTP device needs a serial with an ownership" in text
    assert sent(route, 2)["nodes"][0]["isSecureZtp"] == "true"


@respx.mock
async def test_create_ztp_device_reports_the_serial_left_registered_on_failure(make_settings):
    """Verified: a serial registered by register_serial stays registered when the device
    POST then fails (code 422 'Credential Profile not found.')."""
    serials = mock_json("post", SERIALS_WRITE_URL, SERIALS_ADDED)
    route = mock_json("post", DEVICES_WRITE_URL, DEVICE_NO_CREDENTIAL)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_create_ztp_device",
        {
            "host_name": "phase-d-ztp-node-b",
            "serial_number": "PHASED0004",
            "credential_profile": "phase-d-no-such-profile",
            "platform": "IOS XR",
            "profile_name": "phase-d-ztp-profile",
            "register_serial": True,
        },
    )
    assert serials.call_count == 1 and route.call_count == 1
    assert text == (
        "Error: ZTP device create failed (ZTP answered code 422): phase-d-ztp-node-b: "
        "Credential Profile not found. cnc_list_credential_profiles shows the profile names. "
        "Note: serial PHASED0004 was registered by register_serial before the device create "
        "failed (2 added, 0 already registered) and STAYS registered — "
        "cnc_delete_ztp_serial_numbers removes it."
    )


@respx.mock
async def test_update_ztp_device_rebuilds_the_form_and_switches_it(make_settings):
    renamed = {**MY_DEVICE, "hostName": "phase-d-ztp-node-renamed", "serialNumber": ["PHASED0002"]}
    query = mock_query(DEVICES_URL, devices_answer(MY_DEVICE), devices_answer(renamed))
    route = mock_json("put", DEVICES_WRITE_URL, DEVICE_UPDATED)
    text = await call_tool_text(
        writes(make_settings),
        "cnc_update_ztp_device",
        {
            "uuid": DEVICE_UUID,
            "host_name": "phase-d-ztp-node-renamed",
            "serial_number": "PHASED0002",
        },
    )
    assert query_filter(query) == {"uuid": DEVICE_UUID}
    assert sent(route) == {
        "uuid": DEVICE_UUID,
        "hostName": "phase-d-ztp-node-renamed",
        "serialNumber": ["PHASED0002"],
        "credentialProfile": "cml-xrd",
        "osPlatform": "IOS XR",
        "status": "Unprovisioned",
        "isSecureZtp": "false",
        "enableOption82": "false",
        "profileName": "phase-d-ztp-profile",
    }
    assert text.startswith(
        f"ZTP device 'phase-d-ztp-node-renamed' ({DEVICE_UUID}) updated (host_name, "
        "serial_number).\n\n"
    )
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["device"]["serialNumber"] == ["PHASED0002"]
    assert payload["before"]["hostName"] == "phase-d-ztp-node"
    # '' switches to the metadata form with the record's config / version / family.
    mock_query(DEVICES_URL, devices_answer(MY_DEVICE))
    await call_tool_text(
        writes(make_settings),
        "cnc_update_ztp_device",
        {"uuid": DEVICE_UUID, "profile_name": ""},
    )
    body = sent(route, 1)
    assert "profileName" not in body
    assert (body["config"], body["version"], body["deviceFamily"]) == (
        CONF_ID,
        "7.0.2",
        "CISCO NCS540",
    )


@respx.mock
async def test_update_ztp_device_errors(make_settings):
    text = await call_tool_text(
        writes(make_settings), "cnc_update_ztp_device", {"uuid": DEVICE_UUID}
    )
    assert text.startswith("Error: nothing to change")
    mock_query(DEVICES_URL, DEVICES_EMPTY)
    route = mock_json("put", DEVICES_WRITE_URL, DEVICE_PUT_UNKNOWN)
    text = await call_tool_text(
        writes(make_settings), "cnc_update_ztp_device", {"uuid": ZERO, "host_name": "nope"}
    )
    assert text.startswith(f"Error: no ZTP device with uuid {ZERO}") and route.call_count == 0
    mock_query(DEVICES_URL, devices_answer({**MY_DEVICE, "status": "Provisioned"}))
    text = await call_tool_text(
        writes(make_settings), "cnc_update_ztp_device", {"uuid": DEVICE_UUID, "host_name": "x"}
    )
    assert text.startswith("Error: ZTP device phase-d-ztp-node is Provisioned, not Unprovisioned")
    assert route.call_count == 0
    mock_query(DEVICES_URL, devices_answer({**MY_DEVICE, "profileName": ""}))
    mock_json("put", DEVICES_WRITE_URL, DEVICE_VERSION_MISMATCH)
    text = await call_tool_text(
        writes(make_settings), "cnc_update_ztp_device", {"uuid": DEVICE_UUID, "version": "9.9.9"}
    )
    assert text.startswith(
        "Error: ZTP device update failed (ZTP answered code 422): phase-d-ztp-node: Version "
        "doesn't match with: Day0-config. in the metadata form the version must equal"
    )


@respx.mock
async def test_update_ztp_device_refuses_blank_required_fields(make_settings):
    """'' used to go out verbatim as hostName '' (and a blank serial silently kept the
    current one while being listed as changed): the schema refuses '' and the tool refuses
    whitespace, before any call. Only profile_name legitimately takes ''."""
    from mcp.server.mcpserver.exceptions import ToolError

    query = mock_query(DEVICES_URL, devices_answer(MY_DEVICE))
    route = mock_json("put", DEVICES_WRITE_URL, DEVICE_UPDATED)
    mcp = writes(make_settings)
    for field in ("host_name", "serial_number", "credential_profile", "platform"):
        with pytest.raises(ToolError) as info:
            await mcp.call_tool("cnc_update_ztp_device", {"uuid": DEVICE_UUID, field: ""})
        assert field in str(info.value) and "at least 1 character" in str(info.value)
    text = await call_tool_text(
        mcp, "cnc_update_ztp_device", {"uuid": DEVICE_UUID, "host_name": "  ", "serial_number": " "}
    )
    assert text.startswith("Error: host_name, serial_number must not be blank")
    assert query.call_count == 0 and route.call_count == 0
    schema = {t.name: t for t in await mcp.list_tools()}["cnc_update_ztp_device"].input_schema
    assert schema["properties"]["host_name"]["anyOf"][0]["minLength"] == 1
    assert "minLength" not in json.dumps(schema["properties"]["profile_name"])


@respx.mock
async def test_delete_ztp_device_reports_the_released_serial(make_settings):
    mock_query(DEVICES_URL, devices_answer(MY_DEVICE))
    route = mock_json("delete", DEVICES_WRITE_URL, DEVICE_DELETED)
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_device", {"uuid": DEVICE_UUID}
    )
    assert sent(route) == {"nodes": [{"uuid": DEVICE_UUID}]}
    assert text.startswith(
        f"ZTP device 'phase-d-ztp-node' ({DEVICE_UUID}) deleted; serial PHASED0001 released.\n\n"
    )
    payload = json.loads(text.split("\n\n", 1)[1])
    assert payload["device"]["uuid"] == DEVICE_UUID and payload["response"]["code"] == 200


@respx.mock
async def test_delete_ztp_device_errors(make_settings):
    # Unknown uuid: refused after the lookup, before the DELETE (no needless write call).
    mock_query(DEVICES_URL, DEVICES_EMPTY)
    route = mock_json("delete", DEVICES_WRITE_URL, DEVICE_DELETE_MISSING)
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_device", {"uuid": DEVICE_UUID}
    )
    assert text == (
        f"Error: no ZTP device with uuid {DEVICE_UUID} (the uuid query matched nothing; "
        "cnc_list_ztp_devices shows the uuids) — nothing sent."
    )
    assert route.call_count == 0
    # The race: found by the lookup, gone by the DELETE (the platform's verified code-200
    # "does not exist" answer).
    mock_query(DEVICES_URL, devices_answer(MY_DEVICE))
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_device", {"uuid": DEVICE_UUID}
    )
    assert text.startswith(
        f"Error: no ZTP device with uuid {DEVICE_UUID} (ZTP answered code 200: 1) Device with "
        f"UUID : {DEVICE_UUID} does not exist.)"
    )
    assert route.call_count == 1
    mock_json("delete", DEVICES_WRITE_URL, {"code": 500, "message": "boom"})
    text = await call_tool_text(
        writes(make_settings), "cnc_delete_ztp_device", {"uuid": DEVICE_UUID}
    )
    assert text == "Error: ZTP device delete failed (ZTP answered code 500): boom"


# --- the document's example device still renders through the read tool ---------------------------


def test_document_device_example_is_the_profile_form():
    """The 7.2 document's DeviceObjectExample carries both a profileName and the metadata
    — the stored shape (verified: ZTP copies them from the profile), not a valid write."""
    assert DEVICE["profileName"] and DEVICE["config"] and PROFILE["config"]
    with pytest.raises(PlatformError):
        validate_device_form(DEVICE["profileName"], DEVICE["config"], DEVICE["version"], "")
