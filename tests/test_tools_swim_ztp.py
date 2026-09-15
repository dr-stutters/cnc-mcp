"""SWIM / ZTP tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
The EMPTY fixtures are verbatim from the answers verified live on Crosswork
7.2 (2026-09-13, platform notes "SWIM" and "ZTP"): the preference list, the
206 empty repository with its ``Content-Range``, the running-images failure
texts (and the inventory-uuid -> EMF instance id mapping verified 2026-09-14),
the empty job list, the ZTP code-200-without-data bodies, the code-400
"filter not provided" body, the device policy document, the configsvc /
imagesvc empty pages with their bare-int counts and the types / platforms
lists. The POPULATED fixtures follow the 7.2 OpenAPI documents (no populated
answer has been seen live — every one of these services was empty on the lab).
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import swim_ztp
from cnc_mcp.tools.swim_ztp import (
    CONFIGSVC_PARAM_NAMES,
    IMAGESVC_PARAM_NAMES,
    SWIM_DEVICE_ID_CAVEAT,
    as_int,
    check_ztp,
    config_line,
    device_line,
    guarded_page_envelope,
    image_line,
    image_view,
    job_line,
    matches_platform,
    more_note,
    page_envelope,
    parse_bool_text,
    parse_content_range,
    policy_markdown,
    preference_value_of,
    preferences_of,
    profile_line,
    range_header,
    route_line,
    running_image_line,
    serial_line,
    serial_view,
    split_platform,
    string_list,
    svc_params,
    swim_running_error,
    validate_swim_device_id,
    ztp_image_line,
    ztp_past_the_end,
    ztp_query_body,
    ztp_total,
)
from tests.conftest import BASE_URL, call_tool_text

SWIM = f"{BASE_URL}/crosswork/api/v1/op/swim/image"
ZTP = f"{BASE_URL}/crosswork/ztp/v1"
CONFIGSVC = f"{BASE_URL}/crosswork/configsvc/v1"
IMAGESVC = f"{BASE_URL}/crosswork/imagesvc/v1"

PREFERENCES_URL = f"{SWIM}/getSwimPreference"
IMAGES_URL = f"{SWIM}/getImagesForRepository"
RUNNING_URL = f"{SWIM}/getDeviceRunningImages"
JOB_URL = f"{SWIM}/jobAllDetailsById"
PROFILES_URL = f"{ZTP}/profiles/query"
DEVICES_URL = f"{ZTP}/devices/query"
SERIALS_URL = f"{ZTP}/serialnumbers/query"
ROUTES_URL = f"{ZTP}/staticroutes/query"
POLICY_URL = f"{ZTP}/devices/policies/query"
CONFIGS_URL = f"{CONFIGSVC}/configs"
CONFIGS_COUNT_URL = f"{CONFIGSVC}/configs/count"
CONFIG_TYPES_URL = f"{CONFIGSVC}/types"
CONFIG_PLATFORMS_URL = f"{CONFIGSVC}/platforms"
ZTP_IMAGES_URL = f"{IMAGESVC}/images"
ZTP_IMAGES_COUNT_URL = f"{IMAGESVC}/images/count"
ZTP_IMAGE_PLATFORMS_URL = f"{IMAGESVC}/platforms"


def config_params(page: str, size: str, platform: str | None = None) -> dict[str, str]:
    """The configs query as sent: the live-accepted names AND the documented ones."""
    params = {"page": page, "size": size, "PageNum": page, "PageSize": size}
    if platform:
        params.update({"platform": platform, "osname": platform})
    return params


def image_params(page: str, size: str, platform: str | None = None) -> dict[str, str]:
    params = {"page": page, "size": size, "pageNumber": page, "pageSize": size}
    if platform:
        params.update({"platform": platform, "imagePlatform": platform})
    return params


SERVER_ERROR = httpx.Response(500, json={"code": 500, "errorMessage": "boom"})

# --- SWIM fixtures (verified live unless noted) ----------------------------------------

PREFERENCES = {
    "items": [
        {"key": "ContinueDistributionOnFailure", "value": "Y"},
        {"key": "inventoryCollectionTimeOut", "value": "1800000"},
        {"key": "InsertBootCommand", "value": "N"},
        {"key": "copyByServer", "value": "Y"},
        {"key": "ConfigProtocolOrder", "value": "TELNET,SSH"},
        {"key": "TFTPBootLocation", "value": "/tftpboot"},
    ]
}
# Verified: 206 + Content-Range items=0-0/0, no ``items`` key at all.
EMPTY_REPOSITORY = httpx.Response(
    206,
    json={"softwareImageListDTO": {"id": "imageId", "totalCount": 0}},
    headers={"Content-Range": "items=0-0/0"},
)
# 7.2 document (SoftwareImageListDTOWrapper example) — unverified live.
IMAGE = {
    "family": "NCS4200",
    "features": "",
    "filesize": 510412892,
    "imageCheckSum": "efd99856fca8abc6780f5b3624c52dc5",
    "imageId": 463463,
    "imageLocation": "/mnt/xftpdata/swim-images/ncs4201-universalk9_npe.17.09.04a.SPA.bin",
    "imageName": "ncs4201-universalk9_npe.17.09.04a.SPA.bin",
    "imagePlatform": "IOS XE",
    "imageType": "SYSTEM_SW",
    "minBootRom": "UNKNOWN",
    "minFlashSize": "UNKNOWN",
    "minRam": "UNKNOWN",
    "name": "ncs4201-universalk9_npe.17.09.04a.SPA.bin",
    "updatedOn": 1716377324000,
    "upgradeNeeded": False,
    "uploadedBy": "System",
    "vendor": "Cisco Systems",
    "version": "17.09.04a",
}
REPOSITORY = httpx.Response(
    206,
    json={"softwareImageListDTO": {"id": "imageId", "items": [IMAGE], "totalCount": 1}},
    headers={"Content-Range": "items=0-0/1"},
)
# Verified 2026-09-14: the INVENTORY uuid is accepted — SWIM translates it to the EMF
# nd.instanceId itself and answers that numeric id as ``id`` (454455 for the lab's XRd);
# "Invalid Index" means SWIM holds no software-image inventory for the device (XRd is
# DEVICE_SUPPORT_LEVEL_UNCERTIFIED), not that the id is wrong. The numeric id answers the same.
DEVICE_UUID = "af1986fa-2b3c-4d5e-8f90-1234567890ab"
RUNNING_INVALID_INDEX = {
    "runningSoftwareImageDTOList": {
        "id": "454455",
        "totalCount": 0,
        "resultErrMsg": "Get running Image Failed for the Device : Invalid Index",
    }
}
# Verified: a host name is answered with Java's number-parse failure inside HTTP 200 — the
# tool now refuses such an id before the call, so this body only reaches the helper test.
RUNNING_NAME_REFUSED = {
    "runningSoftwareImageDTOList": {
        "id": "PE1",
        "totalCount": 0,
        "resultErrMsg": 'For input string: "PE1"',
    }
}
# 7.2 document example — unverified live.
RUNNING_IMAGE = {
    "deviceId": "460460",
    "deviceName": "ncs540-120.145",
    "imageFileName": "ncs540-xr-24.2.1",
    "imageName": "ncs540-xr-24.2.1",
    "features": "XR",
    "imageFamily": "NCS540",
    "imageType": "XR type",
    "version": "24.2.1",
    "size": "0",
    "installableStatus": "ACTIVE",
    "installedLocation": "disk0",
}
RUNNING_OK = {
    "runningSoftwareImageDTOList": {
        "id": "460460",
        "totalCount": 1,
        "resultErrMsg": "Success",
        "items": [RUNNING_IMAGE],
    }
}
# Verified: an unknown job answers count/totalCount 0 and no items.
JOB_EMPTY = {"swimDashboardJobDetailsListDTO": {"identifier": "jobId", "count": 0, "totalCount": 0}}
# 7.2 document example — unverified live.
JOB = {
    "actualStartTime": "1718025076937",
    "completionTime": "1718025094097",
    "deviceCount": "1",
    "jobDescription": "Distribute/Activate the image to device",
    "jobId": 631640,
    "jobName": "image_distribute_JobName",
    "jobSpecificationId": 627636,
    "jobType": "Software Image Distribution",
    "resultState": "Failure",
    "taskId": "632641",
    "workState": "Completed",
}
JOB_FOUND = {
    "swimDashboardJobDetailsListDTO": {
        "identifier": "jobId",
        "count": 1,
        "items": [JOB],
        "totalCount": 1,
    }
}

# --- ZTP fixtures (verified live unless noted) -----------------------------------------

FILTER_MISSING = {"code": 400, "message": "filter not provided"}
PROFILES_EMPTY = {"code": 200, "paginationDetails": {"PageSize": 30}}
DEVICES_EMPTY = {"code": 200}
SERIALS_EMPTY = {"code": 200, "message": "Get is success"}
ROUTES_EMPTY = {"code": 200, "paginationDetails": {"PageSize": 30}}
POLICY = {
    "policydata": {
        "id": 1,
        "policyFields": [
            "inventoryid",
            "routingInfo.globalospfrouterid",
            "routingInfo.globalisissystemid",
            "routingInfo.teRouterid",
            "routingInfo.ipv6routerid",
        ],
        "existingAttributes": {"inventoryid": "InventoryId"},
        "newAttributes": {
            "routingInfo.globalisissystemid": "string",
            "routingInfo.globalospfrouterid": "string",
            "routingInfo.ipv6routerid": "string",
            "routingInfo.teRouterid": "string",
        },
    },
    "code": 200,
}
# 7.2 document examples — unverified live.
PROFILE = {
    "profileId": "1484035b-56d4-4701-892b-f7ef1f068ffc",
    "profileName": "p1",
    "osPlatform": "IOS XR",
    "deviceFamily": "CISCO NCS540",
    "version": "7.0.2",
    "config": "b4d4504c-2a0f-4b68-84a3-a0273eabcf03",
    "isSecureZtp": "false",
    "profileCategory": "p",
    "lastUpdated": "1685791216517",
    "configName": "cfg2",
}
PROFILES = {
    "ztpProfiles": [PROFILE],
    "code": 200,
    "paginationDetails": {"PageSize": 150, "TotalCount": 1},
}
DEVICE = {
    "uuid": "e1d32c83-9141-4eb5-8105-8afb47c25533",
    "hostName": "test1",
    "serialNumber": ["1"],
    "credentialProfile": "cred1",
    "ipAddress": {},
    "osPlatform": "IOS XR",
    "version": "7.0.2",
    "deviceFamily": "CISCO NCS540",
    "config": "b4d4504c-2a0f-4b68-84a3-a0273eabcf03",
    "profileName": "test-1",
    "status": "Unprovisioned",
    "providerInfo": {},
    "lastUpdated": "1685793663523",
    "configName": "cfg2",
    "additionalAttributes": {"routingInfo.teRouterid": ""},
    "isSecureZtp": "false",
    "secureZtpInfo": {"isEncrypted": "false"},
    "configAttributes": {"hname": "ss"},
    "enableOption82": "false",
}
DEVICES = {
    "ztpnodes": [DEVICE],
    "code": 200,
    "paginationDetails": {"PageSize": 30, "TotalCount": 1},
}
SERIAL = {
    "serialNumber": "2",
    "isOVLinked": "false",
    "isInUse": "false",
    "modifiedDate": 1685733212,
}
SERIALS = {
    "data": [SERIAL, {**SERIAL, "serialNumber": "1", "isInUse": "true"}],
    "pagination": {"TotalCount": 2},
    "code": 200,
    "message": "Get is success",
}
ROUTE = {
    "uuid": "b44f254a-fb70-40a3-a5b4-d654312538ba",
    "subnet": "55.1.1.0",
    "mask": "24",
    "status": "add-inprogress",
    "modifiedDate": 1685727386825,
}
ROUTES = {
    "ztpStaticRoutes": [ROUTE],
    "code": 200,
    "paginationDetails": {"PageSize": 30, "TotalCount": 1},
}
POLICY_NOT_FOUND = {"code": 404, "message": "No polices exits in ztp"}

# --- configsvc / imagesvc fixtures (verified live unless noted) ------------------------

CONFIG_PAGE_EMPTY = {"content": [], "pageNumber": 1, "pageSize": 0}
CONFIG_TYPES = ["Pre-config", "Day0-config", "Post-config"]
CONFIG_PLATFORMS = ["IOS XE", "IOS XR"]
# 7.2 document example — unverified live.
CONFIG = {
    "childIds": "",
    "confId": "b4d4504c-2a0f-4b68-84a3-a0273eabcf03",
    "confName": "cfg2",
    "createdBy": "admin",
    "createdTime": "1686906062163",
    "deviceFamily": "CISCO NCS540",
    "downloadurl": "http://<CW_HOST_IP>:30604/crosswork/configsvc/v1/configs/device/files/b4d4",
    "extraPlaceHolders": "hname",
    "fileName": "ncs5k_day0_w_variables.txt",
    "modifiedBy": "admin",
    "modifiedTime": "1686906062163",
    "osName": "IOS XR",
    "size": 106,
    "type": "Day0-config",
    "vendor": "CISCO",
    "version": "7.0.2",
}
CONFIG_XE = {**CONFIG, "confId": "xe-1", "confName": "xe-day0", "osName": "IOS XE"}
CONFIG_PAGE = {"content": [CONFIG], "pageNumber": 1, "pageSize": 1}
IMAGE_PAGE_EMPTY = {"content": [], "pageNumber": 1, "pageSize": 0}
IMAGE_PLATFORMS = {"content": ["IOS XE", "IOS XR"], "pageNumber": 1, "pageSize": 2}
# 7.2 document example — unverified live.
ZTP_IMAGE = {
    "createdBy": "",
    "createdTime": 1686974151894,
    "deviceFamily": "CISCO NCS5500",
    "downloadURL": "http://<IP>:30604/crosswork/imagesvc/v1/device/files/cw-image-uuid-fa05",
    "id": "cw-image-uuid-fa0541af-88d1-448f-b5fa-b6296ef6bf9f",
    "imageFileName": "ncs5500-mini-x-7.8.1.iso",
    "imagePlatform": "IOS XR",
    "imageSource": "local",
    "imageTitle": "img1",
    "imageType": "Image",
    "imageVersion": "7.3.1",
    "modifiedBy": "",
    "modifiedTime": 1686974192879,
    "vendor": "CISCO",
}
IMAGE_PAGE = {"content": [ZTP_IMAGE], "pageNumber": 1, "pageSize": 1}

TOOLS = {
    "cnc_get_swim_preferences",
    "cnc_list_software_images",
    "cnc_get_device_running_images",
    "cnc_get_swim_job",
    "cnc_list_ztp_profiles",
    "cnc_list_ztp_devices",
    "cnc_list_ztp_serial_numbers",
    "cnc_list_ztp_static_routes",
    "cnc_get_ztp_device_policy",
    "cnc_list_ztp_config_files",
    "cnc_list_ztp_images",
}


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    swim_ztp.register(mcp, ctx)
    return mcp


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def mock_post(url: str, body: dict) -> respx.Route:
    return respx.post(url).mock(return_value=httpx.Response(200, json=body))


def mock_get(url: str, body, status: int = 200) -> respx.Route:
    return respx.get(url).mock(return_value=httpx.Response(status, json=body))


def mock_svc(page_url: str, page: dict, count_url: str, count: int, *lists) -> respx.Route:
    """Mock one configsvc / imagesvc listing: the page, its bare-int count and the
    types / platforms lists ((url, body) pairs)."""
    route = mock_get(page_url, page)
    mock_get(count_url, count)
    for url, body in lists:
        mock_get(url, body)
    return route


# --- registration -------------------------------------------------------------------


async def test_all_tools_are_reads_visible_without_writes(make_settings):
    mcp = build(make_settings(enable_writes=False))
    tools = {t.name: t for t in await mcp.list_tools()}
    assert set(tools) == TOOLS
    for name, tool in tools.items():
        assert tool.annotations.read_only_hint is True, name
        assert tool.annotations.idempotent_hint is True, name
        assert tool.annotations.destructive_hint is False, name


async def test_inputs_are_flat_with_defaults(make_settings):
    tools = {t.name: t for t in await build(make_settings()).list_tools()}
    props = tools["cnc_list_ztp_profiles"].input_schema["properties"]
    assert props["page"]["default"] == 0 and props["page_size"]["default"] == 50
    props = tools["cnc_list_software_images"].input_schema["properties"]
    assert props["page"]["default"] == 1
    props = tools["cnc_list_ztp_config_files"].input_schema["properties"]
    assert props["page"]["default"] == 1
    assert tools["cnc_get_swim_job"].input_schema["required"] == ["job_id"]
    assert tools["cnc_get_device_running_images"].input_schema["required"] == ["device_id"]


# --- pure helpers -------------------------------------------------------------------


def test_ztp_query_body_always_carries_a_filter():
    """An absent filter answers code 400 "filter not provided" (verified); {} is accepted."""
    assert ztp_query_body({}, 30, 0) == {"filter": {}, "filterData": {"PageSize": 30, "PageNum": 0}}
    assert ztp_query_body(None) == {"filter": {}, "filterData": {"PageSize": 50, "PageNum": 0}}
    assert ztp_query_body({"osPlatform": "IOS XR", "vendor": "", "x": None}, 10, 2) == {
        "filter": {"osPlatform": "IOS XR"},
        "filterData": {"PageSize": 10, "PageNum": 2},
    }


def test_check_ztp_applies_the_http_200_with_code_rule():
    assert check_ztp(PROFILES_EMPTY, "q") is PROFILES_EMPTY
    assert check_ztp({"ztpProfiles": []}, "q") == {"ztpProfiles": []}  # no code: accepted
    with pytest.raises(PlatformError, match="q failed \\(ZTP answered code 400\\): filter not"):
        check_ztp(FILTER_MISSING, "q")
    with pytest.raises(PlatformError, match="code 500\\): no message"):
        check_ztp({"code": 500}, "q")
    with pytest.raises(PlatformError, match="unexpected response shape"):
        check_ztp([1, 2], "q")
    # The policy query's documented "no policy" code passes when listed as OK.
    assert check_ztp(POLICY_NOT_FOUND, "q", (200, 404)) is POLICY_NOT_FOUND


def test_ztp_total_reads_both_spellings_and_never_invents_one():
    assert ztp_total(PROFILES) == 1
    assert ztp_total(SERIALS) == 2
    assert ztp_total(PROFILES_EMPTY) is None  # verified: PageSize only, no TotalCount
    assert ztp_total(DEVICES_EMPTY) is None


def test_range_header_and_content_range():
    assert range_header(1, 50) == {"Range": "items=0-49"}
    assert range_header(3, 10) == {"Range": "items=20-29"}
    assert parse_content_range("items=0-0/0") == (0, 0, 0)
    assert parse_content_range("items=0-49/120") == (0, 49, 120)
    assert parse_content_range("items=0-49/*") == (0, 49, None)
    assert parse_content_range("bytes 0-1/2") is None
    assert parse_content_range(None) is None


def test_parse_bool_text():
    assert parse_bool_text("", "in_use") is None
    assert parse_bool_text(" True ", "in_use") == "true"
    assert parse_bool_text("false", "in_use") == "false"
    with pytest.raises(PlatformError, match="in_use must be 'true', 'false' or blank"):
        parse_bool_text("yes", "in_use")


def test_as_int_and_string_list():
    assert as_int("1800000") == 1800000
    assert as_int(3) == 3
    assert as_int(2.0) == 2
    assert as_int(True) is None
    assert as_int("x") is None
    assert as_int(None) is None
    assert string_list(CONFIG_TYPES) == CONFIG_TYPES
    assert string_list(IMAGE_PLATFORMS) == ["IOS XE", "IOS XR"]
    assert string_list({"content": None}) == []
    assert string_list("IOS XR") == []


def test_page_envelope_offsets_for_zero_and_one_based_pages():
    zero = page_envelope([1, 2], total=5, page=0, page_size=2, first_page=0)
    assert zero["offset"] == 0 and zero["has_more"] is True and zero["next_page"] == 1
    one = page_envelope([1, 2], total=5, page=2, page_size=2, first_page=1)
    assert one["offset"] == 2 and one["has_more"] is True and one["next_page"] == 3
    last = page_envelope([1], total=5, page=3, page_size=2, first_page=1)
    assert last["has_more"] is False and last["next_page"] is None
    # No total: a full page means "more" (the template rule), a short page does not.
    assert page_envelope([1, 2], total=None, page=0, page_size=2, first_page=0)["has_more"]
    assert not page_envelope([1], total=None, page=0, page_size=2, first_page=0)["has_more"]
    assert more_note(one, "t") == ["", "(more on server of 5: call t again with page=3.)"]
    assert more_note(last, "t") == []


def test_guarded_page_envelope_pages_on_the_raw_row_count():
    """The platform guard may empty a FULL server page: paging must follow the raw page."""
    env = guarded_page_envelope(["xr"], 2, total_all=10, page=1, page_size=2)
    assert env["count"] == 1 and env["total"] is None and env["offset"] == 0
    assert env["has_more"] is True and env["next_page"] == 2 and env["next_offset"] == 2
    empty = guarded_page_envelope([], 2, total_all=10, page=2, page_size=2)
    assert empty["has_more"] is True and empty["next_page"] == 3 and empty["next_offset"] == 4
    # A short raw page ends the listing however many rows survived.
    assert not guarded_page_envelope(["xr"], 1, total_all=10, page=1, page_size=2)["has_more"]
    # The all-platform total caps a full last page (page 5 of 10 rows by 2).
    last = guarded_page_envelope(["xr", "xr"], 2, total_all=10, page=5, page_size=2)
    assert last["has_more"] is False and last["next_page"] is None
    assert guarded_page_envelope(["xr"], 2, total_all=None, page=5, page_size=2)["has_more"]
    assert more_note(env, "t") == ["", "(more on server: call t again with page=2.)"]


def test_svc_params_sends_both_spellings():
    assert svc_params(1, 50, "", CONFIGSVC_PARAM_NAMES) == {
        "page": 1,
        "size": 50,
        "PageNum": 1,
        "PageSize": 50,
    }
    assert svc_params(2, 20, "IOS XR", CONFIGSVC_PARAM_NAMES) == {
        "page": 2,
        "size": 20,
        "PageNum": 2,
        "PageSize": 20,
        "platform": "IOS XR",
        "osname": "IOS XR",
    }
    assert svc_params(1, 10, "IOS XE", IMAGESVC_PARAM_NAMES) == {
        "page": 1,
        "size": 10,
        "pageNumber": 1,
        "pageSize": 10,
        "platform": "IOS XE",
        "imagePlatform": "IOS XE",
    }


def test_ztp_past_the_end_only_when_a_total_says_so():
    assert ztp_past_the_end("ZTP profiles", "", None, 3) is None
    assert ztp_past_the_end("ZTP profiles", "", 0, 3) is None
    assert ztp_past_the_end("ZTP profiles", " for OS platform 'IOS XR'", 1, 3) == (
        "No ZTP profiles for OS platform 'IOS XR' on page 3 (ZTP reports 1 matching; page 0 is "
        "the first)."
    )


def test_preference_helpers():
    assert preferences_of(PREFERENCES)[0] == {"key": "ContinueDistributionOnFailure", "value": "Y"}
    assert preferences_of({"items": [{"value": "x"}, "junk"]}) == []
    assert preferences_of(None) == []
    assert preference_value_of(httpx.Response(200, text="Y")) == "Y"  # verified: bare text
    assert preference_value_of(httpx.Response(200, text='"Y"')) == "Y"  # documented JSON string
    assert preference_value_of(httpx.Response(200, text="  ")) == ""


def test_image_view_accepts_both_spellings_and_renders():
    view = image_view(IMAGE)
    assert view["family"] == "NCS4200" and view["filesize"] == 510412892
    assert image_view({"imageFamily": "NCS540", "size": "12", "name": "n"}) == {
        **image_view({}),
        "family": "NCS540",
        "filesize": 12,
        "imageName": "n",
    }
    assert image_line(view) == (
        "- **ncs4201-universalk9_npe.17.09.04a.SPA.bin** (id 463463): SYSTEM_SW, IOS XE "
        "NCS4200 v17.09.04a, 486.8 MiB, by System, updated 2024-05-22T11:28:44Z"
    )
    assert running_image_line(swim_ztp.running_image_view(RUNNING_IMAGE)) == (
        "- **ncs540-xr-24.2.1** v24.2.1: ACTIVE on disk0, XR type NCS540, file ncs540-xr-24.2.1"
    )
    assert job_line(swim_ztp.job_view(JOB)) == (
        "- **image_distribute_JobName** (job 631640, spec 627636, task 632641): Software Image "
        "Distribution — Completed / Failure, 1 device(s), started 2024-06-10T13:11:16Z, "
        "completed 2024-06-10T13:11:34Z — Distribute/Activate the image to device"
    )


def test_ztp_lines_follow_the_document():
    assert profile_line(swim_ztp.profile_view(PROFILE)) == (
        "- **p1** (1484035b-56d4-4701-892b-f7ef1f068ffc): IOS XR CISCO NCS540 v7.0.2, config "
        "cfg2, category p, updated 2023-06-03T11:20:16Z"
    )
    secure = {**PROFILE, "isSecureZtp": "true", "imageName": "img", "isConfigInvalid": True}
    assert profile_line(swim_ztp.profile_view(secure)).endswith(
        "(image img; secure ZTP; OUT OF SYNC with its files)"
    )
    # A deleted Pre-config flags isPreConfigInvalid (verified); the view carries the ids.
    stale = {**PROFILE, "preConfig": "pre-1", "preConfigName": "pre", "isPreConfigInvalid": True}
    view = swim_ztp.profile_view(stale)
    assert view["preConfig"] == "pre-1" and view["isPreConfigInvalid"] is True
    assert profile_line(view).endswith("(OUT OF SYNC with its files)")
    assert device_line(swim_ztp.device_view(DEVICE)) == (
        "- **test1** (e1d32c83-9141-4eb5-8105-8afb47c25533): Unprovisioned, serial 1, IOS XR "
        "CISCO NCS540 v7.0.2, profile test-1, credentials cred1, ip -, updated "
        "2023-06-03T12:01:03Z"
    )
    addressed = {**DEVICE, "ipAddress": {"ipaddrs": "10.0.0.3", "mask": 24}, "message": "ok"}
    assert "ip 10.0.0.3/24, updated 2023-06-03T12:01:03Z — ok" in device_line(
        swim_ztp.device_view(addressed)
    )
    assert serial_view(SERIAL)["isOvLinked"] == "false"  # the example's isOVLinked spelling
    assert serial_view({"isOvLinked": "true"})["isOvLinked"] == "true"
    assert serial_line(serial_view(SERIAL)) == (
        "- **2**: free, no ownership voucher, modified 2023-06-02T19:13:32Z"
    )
    linked = {**SERIAL, "isInUse": "true", "isOvLinked": "true", "ovFilename": "ov.xml"}
    assert serial_line(serial_view(linked)) == (
        "- **2**: in use, voucher ov.xml, modified 2023-06-02T19:13:32Z"
    )
    assert route_line(swim_ztp.route_view(ROUTE)) == (
        "- **55.1.1.0/24** (b44f254a-fb70-40a3-a5b4-d654312538ba): add-inprogress, modified "
        "2023-06-02T17:36:26Z"
    )
    text = policy_markdown(POLICY["policydata"])
    assert text.startswith("# ZTP device policy 1\n")
    assert "- policy fields (5): inventoryid, routingInfo.globalospfrouterid" in text
    assert "- existing attributes (1): inventoryid = InventoryId" in text
    assert "- new attributes (4): routingInfo.globalisissystemid = string" in text


def test_svc_lines_and_platform_split():
    assert config_line(swim_ztp.config_view(CONFIG)) == (
        "- **cfg2** (b4d4504c-2a0f-4b68-84a3-a0273eabcf03): Day0-config for IOS XR CISCO "
        "NCS540 v7.0.2, file ncs5k_day0_w_variables.txt (106 B), by admin, modified "
        "2023-06-16T09:01:02Z, placeholders hname"
    )
    assert ztp_image_line(swim_ztp.ztp_image_view(ZTP_IMAGE)) == (
        "- **img1** (cw-image-uuid-fa0541af-88d1-448f-b5fa-b6296ef6bf9f): Image for IOS XR "
        "CISCO NCS5500 v7.3.1, file ncs5500-mini-x-7.8.1.iso, source local, modified "
        "2023-06-17T03:56:32Z"
    )
    assert matches_platform("IOS XR", "ios xr") is True
    assert matches_platform("IOS XE", "IOS XR") is False
    assert matches_platform(None, "") is True
    assert split_platform([CONFIG, CONFIG_XE], "osName", "") == ([CONFIG, CONFIG_XE], 0)
    assert split_platform([CONFIG, CONFIG_XE], "osName", "IOS XR") == ([CONFIG], 1)


# --- cnc_get_swim_preferences ---------------------------------------------------------


@respx.mock
async def test_get_swim_preferences_lists_every_key(make_settings):
    route = mock_get(PREFERENCES_URL, PREFERENCES)
    text = await call_tool_text(build(make_settings()), "cnc_get_swim_preferences", {})
    assert route.called
    assert text.startswith("# SWIM preferences (6)\n")
    assert "- ContinueDistributionOnFailure: Y" in text
    assert "- ConfigProtocolOrder: TELNET,SSH" in text
    data = json.loads(
        await call_tool_text(
            build(make_settings()), "cnc_get_swim_preferences", {"response_format": "json"}
        )
    )
    assert data["count"] == 6 and data["preferences"]["TFTPBootLocation"] == "/tftpboot"
    assert data["items"][0] == {"key": "ContinueDistributionOnFailure", "value": "Y"}


@respx.mock
async def test_get_swim_preferences_one_key_is_bare_text(make_settings):
    route = respx.get(f"{PREFERENCES_URL}/copyByServer").mock(
        return_value=httpx.Response(200, text="Y")
    )
    text = await call_tool_text(
        build(make_settings()), "cnc_get_swim_preferences", {"key": "copyByServer"}
    )
    assert route.called
    assert text == "- copyByServer: Y"
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_get_swim_preferences",
            {"key": "copyByServer", "response_format": "json"},
        )
    )
    assert data == {"key": "copyByServer", "value": "Y"}


@respx.mock
async def test_get_swim_preferences_empty_value_and_errors(make_settings):
    respx.get(f"{PREFERENCES_URL}/nope").mock(return_value=httpx.Response(200, text=""))
    text = await call_tool_text(build(make_settings()), "cnc_get_swim_preferences", {"key": "nope"})
    assert text.startswith("SWIM preference 'nope' has no value")
    respx.get(PREFERENCES_URL).mock(return_value=SERVER_ERROR)
    text = await call_tool_text(build(make_settings()), "cnc_get_swim_preferences", {})
    assert text.startswith("Error: API request failed with status 500")
    respx.get(f"{PREFERENCES_URL}/copyByServer").mock(return_value=SERVER_ERROR)
    text = await call_tool_text(
        build(make_settings()), "cnc_get_swim_preferences", {"key": "copyByServer"}
    )
    assert text.startswith("Error: API request failed with status 500")


# --- cnc_list_software_images ---------------------------------------------------------


@respx.mock
async def test_list_software_images_empty_repository_is_not_an_error(make_settings):
    route = respx.get(IMAGES_URL).mock(return_value=EMPTY_REPOSITORY)
    text = await call_tool_text(build(make_settings()), "cnc_list_software_images", {})
    assert route.calls[0].request.headers["Range"] == "items=0-49"
    assert text.startswith("The SWIM image repository is empty.")
    data = json.loads(
        await call_tool_text(
            build(make_settings()), "cnc_list_software_images", {"response_format": "json"}
        )
    )
    assert data["total"] == 0 and data["count"] == 0 and data["has_more"] is False
    assert data["content_range"] == "items=0-0/0" and data["image_type"] is None


@respx.mock
async def test_list_software_images_by_type_and_page(make_settings):
    route = respx.get(f"{IMAGES_URL}/SYSTEM_SW").mock(return_value=REPOSITORY)
    text = await call_tool_text(
        build(make_settings()),
        "cnc_list_software_images",
        {"image_type": "SYSTEM_SW", "page": 2, "page_size": 10},
    )
    assert route.calls[0].request.headers["Range"] == "items=10-19"
    assert text.startswith("# SWIM image repository (1 of 1, type SYSTEM_SW)\n")
    assert "- **ncs4201-universalk9_npe.17.09.04a.SPA.bin** (id 463463): SYSTEM_SW" in text
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_list_software_images",
            {"image_type": "SYSTEM_SW", "response_format": "json"},
        )
    )
    assert data["items"][0]["imageId"] == 463463 and data["image_type"] == "SYSTEM_SW"
    assert data["total"] == 1 and data["page"] == 1 and data["has_more"] is False


@respx.mock
async def test_list_software_images_empty_type_and_errors(make_settings):
    respx.get(f"{IMAGES_URL}/XR").mock(return_value=EMPTY_REPOSITORY)
    text = await call_tool_text(
        build(make_settings()), "cnc_list_software_images", {"image_type": "XR"}
    )
    assert text.startswith("The SWIM image repository holds no 'XR' images.")
    respx.get(IMAGES_URL).mock(return_value=SERVER_ERROR)
    text = await call_tool_text(build(make_settings()), "cnc_list_software_images", {})
    assert text.startswith("Error: API request failed with status 500")
    with pytest.raises(ToolError):  # schema: page >= 1
        await call_tool_text(build(make_settings()), "cnc_list_software_images", {"page": 0})


# --- cnc_get_device_running_images ----------------------------------------------------


def test_validate_swim_device_id_accepts_uuid_or_digits_only():
    """Verified: SWIM resolves the inventory uuid and the numeric EMF instance id; a host
    name gets 'For input string' — refused here, before any call, with that explanation."""
    assert validate_swim_device_id(f" {DEVICE_UUID} ") == DEVICE_UUID  # verbatim, stripped
    assert validate_swim_device_id(DEVICE_UUID.upper()) == DEVICE_UUID.upper()
    assert validate_swim_device_id("454455") == "454455"
    for bad in ("PE1", "10.0.0.1", "af1986fa2b3c4d5e8f901234567890ab", "{" + DEVICE_UUID + "}"):
        with pytest.raises(PlatformError) as info:
            validate_swim_device_id(bad)
        assert str(info.value).startswith(
            f"device_id '{bad}' is neither an inventory uuid nor a numeric EMF instance id — "
            f"SWIM would answer 'For input string: \"{bad}\"'"
        )
        assert SWIM_DEVICE_ID_CAVEAT in str(info.value)
        assert f"cnc_get_device(host_name='{bad}')" in str(info.value)


def test_swim_running_error_explains_each_verified_verdict():
    invalid = swim_running_error(
        DEVICE_UUID, "Get running Image Failed for the Device : Invalid Index", "454455"
    )
    assert str(invalid) == (
        f"SWIM holds no software-image inventory for device {DEVICE_UUID} (SWIM answered: Get "
        "running Image Failed for the Device : Invalid Index) — the device's platform is not "
        "SWIM-certified (a containerised XRd is DEVICE_SUPPORT_LEVEL_UNCERTIFIED and SWIM's XR "
        "image collector has nothing to parse there) or its image inventory was never "
        "collected; the inventory uuid is the right id (SWIM maps it to EMF instance id 454455)."
    )
    # No ``id`` in the answer: the generic mapping sentence, never an invented id.
    assert str(swim_running_error("454455", "Invalid Index")).endswith(
        "the inventory uuid is the right id (SWIM maps it to the EMF instance id itself)."
    )
    # The verified host-name verdict (only reachable if SWIM's parsing changes).
    parse = swim_running_error("PE1", 'For input string: "PE1"', "PE1")
    assert str(parse) == (
        "SWIM could not parse device id 'PE1' (SWIM answered: For input string: \"PE1\") — "
        f"{SWIM_DEVICE_ID_CAVEAT}."
    )
    other = swim_running_error("454455", "Device not reachable", "454455")
    assert str(other) == (
        "SWIM could not read the running images of device 454455 (SWIM answered: Device not "
        f"reachable); {SWIM_DEVICE_ID_CAVEAT}."
    )


@respx.mock
async def test_get_device_running_images_by_inventory_uuid(make_settings):
    """Verified 2026-09-14: the inventory uuid is sent verbatim; SWIM answers the EMF
    instance id it mapped it to as ``id``, which the tool surfaces."""
    route = mock_get(f"{RUNNING_URL}/{DEVICE_UUID}", RUNNING_OK)
    text = await call_tool_text(
        build(make_settings()), "cnc_get_device_running_images", {"device_id": DEVICE_UUID}
    )
    assert route.calls[0].request.url.path.endswith(f"/getDeviceRunningImages/{DEVICE_UUID}")
    assert text.startswith(
        f"# Running images of ncs540-120.145 (device {DEVICE_UUID} = EMF instance id 460460): 1\n"
    )
    assert "- **ncs540-xr-24.2.1** v24.2.1: ACTIVE on disk0" in text
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_get_device_running_images",
            {"device_id": f" {DEVICE_UUID} ", "response_format": "json"},
        )
    )
    assert data["device_id"] == DEVICE_UUID and data["emf_instance_id"] == "460460"
    assert data["device_name"] == "ncs540-120.145" and data["total"] == 1
    assert data["items"][0]["installableStatus"] == "ACTIVE"


@respx.mock
async def test_get_device_running_images_numeric_id_still_accepted(make_settings):
    route = mock_get(f"{RUNNING_URL}/460460", RUNNING_OK)
    text = await call_tool_text(
        build(make_settings()), "cnc_get_device_running_images", {"device_id": "460460"}
    )
    assert route.called
    # The answer's id equals the given one: no "= EMF instance id" repetition.
    assert text.startswith("# Running images of ncs540-120.145 (device 460460): 1\n")
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_get_device_running_images",
            {"device_id": "460460", "response_format": "json"},
        )
    )
    assert data["device_id"] == "460460" and data["emf_instance_id"] == "460460"


@respx.mock
async def test_get_device_running_images_invalid_index_is_a_platform_limitation(make_settings):
    """Verified 2026-09-14: the uuid maps to EMF instance id 454455 and "Invalid Index" says
    SWIM holds no image inventory for that (uncertified XRd) device — not a wrong id."""
    mock_get(f"{RUNNING_URL}/{DEVICE_UUID}", RUNNING_INVALID_INDEX)
    text = await call_tool_text(
        build(make_settings()), "cnc_get_device_running_images", {"device_id": DEVICE_UUID}
    )
    assert text == (
        f"Error: SWIM holds no software-image inventory for device {DEVICE_UUID} (SWIM answered: "
        "Get running Image Failed for the Device : Invalid Index) — the device's platform is not "
        "SWIM-certified (a containerised XRd is DEVICE_SUPPORT_LEVEL_UNCERTIFIED and SWIM's XR "
        "image collector has nothing to parse there) or its image inventory was never "
        "collected; the inventory uuid is the right id (SWIM maps it to EMF instance id 454455)."
    )
    # The numeric EMF instance id answers the same verdict (verified 2026-09-13).
    mock_get(f"{RUNNING_URL}/454455", RUNNING_INVALID_INDEX)
    text = await call_tool_text(
        build(make_settings()),
        "cnc_get_device_running_images",
        {"device_id": "454455", "response_format": "json"},
    )
    assert text.startswith("Error: SWIM holds no software-image inventory for device 454455 (")
    assert text.endswith("(SWIM maps it to EMF instance id 454455).")


@respx.mock
async def test_get_device_running_images_refuses_a_host_name_before_any_call(make_settings):
    route = mock_get(f"{RUNNING_URL}/PE1", RUNNING_NAME_REFUSED)
    text = await call_tool_text(
        build(make_settings()), "cnc_get_device_running_images", {"device_id": "PE1"}
    )
    assert text.startswith(
        "Error: device_id 'PE1' is neither an inventory uuid nor a numeric EMF instance id — "
        "SWIM would answer 'For input string: \"PE1\"'"
    )
    assert "cnc_get_device(host_name='PE1')" in text
    # The same verdict in JSON form is still an Error string; still no call.
    text = await call_tool_text(
        build(make_settings()),
        "cnc_get_device_running_images",
        {"device_id": "PE1", "response_format": "json"},
    )
    assert text.startswith("Error: device_id 'PE1' is neither")
    assert not route.called


@respx.mock
async def test_get_device_running_images_empty_and_errors(make_settings):
    mock_get(
        f"{RUNNING_URL}/7",
        {"runningSoftwareImageDTOList": {"id": "7", "totalCount": 0, "resultErrMsg": "Success"}},
    )
    text = await call_tool_text(
        build(make_settings()), "cnc_get_device_running_images", {"device_id": "7"}
    )
    assert text.startswith("No running image reported for device 7 (SWIM answered Success")
    mock_get(
        f"{RUNNING_URL}/{DEVICE_UUID}",
        {"runningSoftwareImageDTOList": {"id": "7", "totalCount": 0, "resultErrMsg": "Success"}},
    )
    text = await call_tool_text(
        build(make_settings()), "cnc_get_device_running_images", {"device_id": DEVICE_UUID}
    )
    assert text.startswith(
        f"No running image reported for device {DEVICE_UUID} = EMF instance id 7 (SWIM answered "
        "Success with an empty list)."
    )
    respx.get(f"{RUNNING_URL}/8").mock(return_value=SERVER_ERROR)
    text = await call_tool_text(
        build(make_settings()), "cnc_get_device_running_images", {"device_id": "8"}
    )
    assert text.startswith("Error: API request failed with status 500")
    with pytest.raises(ToolError):  # schema: device_id required, min_length 1
        await call_tool_text(
            build(make_settings()), "cnc_get_device_running_images", {"device_id": ""}
        )


# --- cnc_get_swim_job -------------------------------------------------------------------


@respx.mock
async def test_get_swim_job_found_and_unknown(make_settings):
    route = mock_get(f"{JOB_URL}/627636", JOB_FOUND)
    text = await call_tool_text(build(make_settings()), "cnc_get_swim_job", {"job_id": 627636})
    assert route.called
    assert text.startswith("# SWIM job 627636 (1)\n")
    assert "- **image_distribute_JobName** (job 631640, spec 627636, task 632641)" in text
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_get_swim_job",
            {"job_id": 627636, "response_format": "json"},
        )
    )
    assert data["total"] == 1 and data["identifier"] == "jobId"
    assert data["items"][0]["deviceCount"] == 1 and data["items"][0]["resultState"] == "Failure"
    mock_get(f"{JOB_URL}/1", JOB_EMPTY)  # verified: unknown job -> totalCount 0
    text = await call_tool_text(build(make_settings()), "cnc_get_swim_job", {"job_id": 1})
    assert text.startswith("No SWIM job 1. SWIM answered totalCount 0")
    data = json.loads(
        await call_tool_text(
            build(make_settings()), "cnc_get_swim_job", {"job_id": 1, "response_format": "json"}
        )
    )
    assert data == {"job_id": 1, "count": 0, "total": 0, "identifier": "jobId", "items": []}


@respx.mock
async def test_get_swim_job_errors(make_settings):
    respx.get(f"{JOB_URL}/2").mock(return_value=SERVER_ERROR)
    text = await call_tool_text(build(make_settings()), "cnc_get_swim_job", {"job_id": 2})
    assert text.startswith("Error: API request failed with status 500")
    with pytest.raises(ToolError):  # schema: job_id >= 1
        await call_tool_text(build(make_settings()), "cnc_get_swim_job", {"job_id": 0})
    with pytest.raises(ToolError):  # schema: job_id required
        await call_tool_text(build(make_settings()), "cnc_get_swim_job", {})


# --- cnc_list_ztp_profiles --------------------------------------------------------------


@respx.mock
async def test_list_ztp_profiles_sends_filter_and_renders(make_settings):
    route = mock_post(PROFILES_URL, PROFILES)
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_profiles", {"os_platform": "IOS XR"}
    )
    assert sent(route) == {
        "filter": {"osPlatform": "IOS XR"},
        "filterData": {"PageSize": 50, "PageNum": 0},
    }
    assert text.startswith("# ZTP profiles (1 of 1)\n")
    assert "- **p1** (1484035b-56d4-4701-892b-f7ef1f068ffc): IOS XR CISCO NCS540 v7.0.2" in text
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_list_ztp_profiles",
            {"page_size": 10, "page": 1, "response_format": "json"},
        )
    )
    assert sent(route, 1) == {"filter": {}, "filterData": {"PageSize": 10, "PageNum": 1}}
    assert data["total"] == 1 and data["code"] == 200 and data["os_platform"] is None
    assert data["items"][0]["profileName"] == "p1" and data["page"] == 1


@respx.mock
async def test_list_ztp_profiles_empty_and_errors(make_settings):
    route = mock_post(PROFILES_URL, PROFILES_EMPTY)  # verified: no ztpProfiles key
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_profiles", {})
    assert "filter" in sent(route)
    assert text.startswith("No ZTP profiles.")
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_profiles", {"os_platform": "IOS XE"}
    )
    assert text.startswith("No ZTP profiles for OS platform 'IOS XE'.")
    data = json.loads(
        await call_tool_text(
            build(make_settings()), "cnc_list_ztp_profiles", {"response_format": "json"}
        )
    )
    assert data["count"] == 0 and data["items"] == [] and data["total"] is None
    mock_post(PROFILES_URL, FILTER_MISSING)  # verified body of the code-400 verdict
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_profiles", {})
    assert text == "Error: ZTP profile query failed (ZTP answered code 400): filter not provided"


PAST_THE_END = {"code": 200, "paginationDetails": {"TotalCount": 1}}  # data key absent
SERIALS_PAST_THE_END = {"code": 200, "message": "Get is success", "pagination": {"TotalCount": 1}}


@respx.mock
async def test_ztp_lists_name_a_page_past_the_end(make_settings):
    """TotalCount > 0 with the data key absent (unverified shape) is a page past the end,
    not "there is none" — every ZTP list tool says so and points at page 0."""
    route = mock_post(PROFILES_URL, PAST_THE_END)
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_profiles", {"page": 3, "os_platform": "IOS XR"}
    )
    assert sent(route)["filterData"] == {"PageSize": 50, "PageNum": 3}
    assert text == (
        "No ZTP profiles for OS platform 'IOS XR' on page 3 (ZTP reports 1 matching; page 0 is "
        "the first)."
    )
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_list_ztp_profiles",
            {"page": 3, "response_format": "json"},
        )
    )
    assert data["total"] == 1 and data["count"] == 0 and data["has_more"] is False
    mock_post(DEVICES_URL, PAST_THE_END)
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_devices", {"page": 3, "status": "Onboarded"}
    )
    assert text == (
        "No ZTP devices matching status 'Onboarded' on page 3 (ZTP reports 1 matching; page 0 "
        "is the first)."
    )
    mock_post(SERIALS_URL, SERIALS_PAST_THE_END)
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_serial_numbers", {"page": 3, "in_use": "false"}
    )
    assert text == (
        "No ZTP serial numbers free (not in use) on page 3 (ZTP reports 1 matching; page 0 is "
        "the first)."
    )
    mock_post(ROUTES_URL, PAST_THE_END)
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_static_routes", {"page": 3})
    assert text == "No ZTP static routes on page 3 (ZTP reports 1 matching; page 0 is the first)."
    respx.post(PROFILES_URL).mock(return_value=SERVER_ERROR)
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_profiles", {})
    assert text.startswith("Error: API request failed with status 500")


# --- cnc_list_ztp_devices ---------------------------------------------------------------


@respx.mock
async def test_list_ztp_devices_sends_filters_and_renders(make_settings):
    route = mock_post(DEVICES_URL, DEVICES)
    text = await call_tool_text(
        build(make_settings()),
        "cnc_list_ztp_devices",
        {"status": "Unprovisioned*", "host_name": "test1", "page_size": 30},
    )
    assert sent(route) == {
        "filter": {"status": "Unprovisioned*", "hostName": "test1"},
        "filterData": {"PageSize": 30, "PageNum": 0},
    }
    assert text.startswith("# ZTP devices (1 of 1)\n")
    assert "- **test1** (e1d32c83-9141-4eb5-8105-8afb47c25533): Unprovisioned, serial 1" in text
    assert "Statuses: Unprovisioned, InProgress, Provisioned" in text
    data = json.loads(
        await call_tool_text(
            build(make_settings()), "cnc_list_ztp_devices", {"response_format": "json"}
        )
    )
    assert sent(route, 1)["filter"] == {}
    assert data["items"][0]["serialNumber"] == ["1"] and data["items"][0]["providerName"] is None
    assert data["status"] is None and data["host_name"] is None and data["total"] == 1


@respx.mock
async def test_list_ztp_devices_empty_and_errors(make_settings):
    mock_post(DEVICES_URL, DEVICES_EMPTY)  # verified: bare {"code": 200}
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_devices", {})
    assert text.startswith("No ZTP devices.")
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_devices", {"status": "Onboarded"}
    )
    assert text.startswith("No ZTP devices matching status 'Onboarded'.")
    mock_post(DEVICES_URL, FILTER_MISSING)
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_devices", {})
    assert text == "Error: ZTP device query failed (ZTP answered code 400): filter not provided"
    respx.post(DEVICES_URL).mock(return_value=SERVER_ERROR)
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_devices", {})
    assert text.startswith("Error: API request failed with status 500")


# --- cnc_list_ztp_serial_numbers --------------------------------------------------------


@respx.mock
async def test_list_ztp_serial_numbers_filter_and_render(make_settings):
    route = mock_post(SERIALS_URL, SERIALS)
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_serial_numbers", {"in_use": "false"}
    )
    assert sent(route) == {
        "filter": {"isInUse": "false"},
        "filterData": {"PageSize": 50, "PageNum": 0},
    }
    assert text.startswith("# ZTP serial numbers (2 of 2)\n")
    assert "- **2**: free, no ownership voucher, modified 2023-06-02T19:13:32Z" in text
    assert "- **1**: in use, no ownership voucher" in text
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_list_ztp_serial_numbers",
            {"in_use": "TRUE", "response_format": "json"},
        )
    )
    assert sent(route, 1)["filter"] == {"isInUse": "true"}
    assert data["in_use"] == "true" and data["total"] == 2 and data["message"] == "Get is success"
    assert data["items"][0]["isOvLinked"] == "false"


@respx.mock
async def test_list_ztp_serial_numbers_empty_and_errors(make_settings):
    route = mock_post(SERIALS_URL, SERIALS_EMPTY)  # verified: "Get is success", no data key
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_serial_numbers", {})
    assert sent(route)["filter"] == {}
    assert text.startswith("No ZTP serial numbers.")
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_serial_numbers", {"in_use": "false"}
    )
    assert text.startswith("No ZTP serial numbers free (not in use).")
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_serial_numbers", {"in_use": "maybe"}
    )
    assert text == "Error: in_use must be 'true', 'false' or blank, got 'maybe'."
    assert len(route.calls) == 2  # the bad value was refused before any call
    mock_post(SERIALS_URL, FILTER_MISSING)
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_serial_numbers", {})
    assert text.startswith("Error: ZTP serial number query failed (ZTP answered code 400)")
    respx.post(SERIALS_URL).mock(return_value=SERVER_ERROR)
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_serial_numbers", {})
    assert text.startswith("Error: API request failed with status 500")


# --- cnc_list_ztp_static_routes ---------------------------------------------------------


@respx.mock
async def test_list_ztp_static_routes(make_settings):
    route = mock_post(ROUTES_URL, ROUTES)
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_static_routes", {"page_size": 30, "page": 1}
    )
    assert sent(route) == {"filter": {}, "filterData": {"PageSize": 30, "PageNum": 1}}
    assert text.startswith("# ZTP static routes (1 of 1)\n")
    assert "- **55.1.1.0/24** (b44f254a-fb70-40a3-a5b4-d654312538ba): add-inprogress" in text
    data = json.loads(
        await call_tool_text(
            build(make_settings()), "cnc_list_ztp_static_routes", {"response_format": "json"}
        )
    )
    assert data["items"][0]["subnet"] == "55.1.1.0" and data["total"] == 1
    mock_post(ROUTES_URL, ROUTES_EMPTY)  # verified: paginationDetails only
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_static_routes", {})
    assert text.startswith("No ZTP static routes.")
    mock_post(ROUTES_URL, FILTER_MISSING)
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_static_routes", {})
    assert (
        text == "Error: ZTP static route query failed (ZTP answered code 400): filter not provided"
    )
    respx.post(ROUTES_URL).mock(return_value=SERVER_ERROR)
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_static_routes", {})
    assert text.startswith("Error: API request failed with status 500")


# --- cnc_get_ztp_device_policy ----------------------------------------------------------


@respx.mock
async def test_get_ztp_device_policy(make_settings):
    route = mock_post(POLICY_URL, POLICY)  # verified document
    text = await call_tool_text(build(make_settings()), "cnc_get_ztp_device_policy", {})
    assert sent(route) == {}
    assert text.startswith("# ZTP device policy 1\n")
    assert "- policy fields (5): inventoryid, routingInfo.globalospfrouterid," in text
    assert "- new attributes (4): routingInfo.globalisissystemid = string" in text
    data = json.loads(
        await call_tool_text(
            build(make_settings()), "cnc_get_ztp_device_policy", {"response_format": "json"}
        )
    )
    assert data["policy"] == POLICY["policydata"] and data["code"] == 200
    mock_post(POLICY_URL, POLICY_NOT_FOUND)  # documented "no policy" answer, not seen live
    text = await call_tool_text(build(make_settings()), "cnc_get_ztp_device_policy", {})
    assert (
        text == "No ZTP device policy is defined (ZTP answered code 404: No polices exits in ztp)."
    )
    data = json.loads(
        await call_tool_text(
            build(make_settings()), "cnc_get_ztp_device_policy", {"response_format": "json"}
        )
    )
    assert data == {"policy": None, "code": 404, "message": "No polices exits in ztp"}
    mock_post(POLICY_URL, {"code": 500, "message": "ID: e97f doesn't exist."})
    text = await call_tool_text(build(make_settings()), "cnc_get_ztp_device_policy", {})
    assert (
        text
        == "Error: ZTP device policy query failed (ZTP answered code 500): ID: e97f doesn't exist."
    )
    respx.post(POLICY_URL).mock(return_value=SERVER_ERROR)
    text = await call_tool_text(build(make_settings()), "cnc_get_ztp_device_policy", {})
    assert text.startswith("Error: API request failed with status 500")


# --- cnc_list_ztp_config_files ----------------------------------------------------------


def config_lists() -> tuple:
    return (CONFIG_TYPES_URL, CONFIG_TYPES), (CONFIG_PLATFORMS_URL, CONFIG_PLATFORMS)


@respx.mock
async def test_list_ztp_config_files_empty_lists_types_and_platforms(make_settings):
    route = mock_svc(CONFIGS_URL, CONFIG_PAGE_EMPTY, CONFIGS_COUNT_URL, 0, *config_lists())
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_config_files", {})
    assert dict(route.calls[0].request.url.params) == config_params("1", "50")
    assert text.splitlines()[:3] == [
        "No ZTP configuration files.",
        "- types: Pre-config, Day0-config, Post-config",
        "- platforms: IOS XE, IOS XR",
    ]
    data = json.loads(
        await call_tool_text(
            build(make_settings()), "cnc_list_ztp_config_files", {"response_format": "json"}
        )
    )
    assert data["types"] == CONFIG_TYPES and data["platforms"] == CONFIG_PLATFORMS
    assert data["total_all_platforms"] == 0 and data["count"] == 0 and data["has_more"] is False
    assert data["page_number"] == 1 and data["page_size_reported"] == 0


@respx.mock
async def test_list_ztp_config_files_platform_filter_and_client_side_guard(make_settings):
    route = mock_svc(
        CONFIGS_URL,
        {"content": [CONFIG, CONFIG_XE], "pageNumber": 1, "pageSize": 2},
        CONFIGS_COUNT_URL,
        2,
        *config_lists(),
    )
    text = await call_tool_text(
        build(make_settings()),
        "cnc_list_ztp_config_files",
        {"platform": "IOS XR", "page": 2, "page_size": 20},
    )
    assert dict(route.calls[0].request.url.params) == config_params("2", "20", "IOS XR")
    assert text.startswith(
        "# ZTP configuration files (1 on this page; 2 in total over every platform; platform "
        "IOS XR)\n- types: Pre-config, Day0-config, Post-config\n- platforms: IOS XE, IOS XR\n"
    )
    assert "- **cfg2** (b4d4504c-2a0f-4b68-84a3-a0273eabcf03): Day0-config for IOS XR" in text
    assert "xe-day0" not in text
    assert "(1 file(s) of other platforms on this page were dropped client-side" in text
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_list_ztp_config_files",
            {"platform": "IOS XR", "response_format": "json"},
        )
    )
    assert data["dropped_by_platform"] == 1 and data["count"] == 1 and data["total"] is None
    assert data["items"][0]["confName"] == "cfg2" and data["platform"] == "IOS XR"
    assert data["has_more"] is False and data["next_page"] is None  # a short raw page ends it


@respx.mock
async def test_list_ztp_config_files_platform_guard_pages_on_the_full_raw_page(make_settings):
    """A FULL server page of mixed platforms (the service ignoring the platform parameter)
    must still page: has_more comes from the raw page, not from what the guard kept."""
    route = mock_svc(
        CONFIGS_URL,
        {"content": [CONFIG, CONFIG_XE], "pageNumber": 1, "pageSize": 2},
        CONFIGS_COUNT_URL,
        10,
        *config_lists(),
    )
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_list_ztp_config_files",
            {"platform": "IOS XR", "page_size": 2, "response_format": "json"},
        )
    )
    assert dict(route.calls[0].request.url.params) == config_params("1", "2", "IOS XR")
    assert data["count"] == 1 and data["dropped_by_platform"] == 1 and data["total"] is None
    assert data["has_more"] is True and data["next_page"] == 2 and data["next_offset"] == 2
    assert data["total_all_platforms"] == 10
    text = await call_tool_text(
        build(make_settings()),
        "cnc_list_ztp_config_files",
        {"platform": "IOS XR", "page_size": 2},
    )
    assert text.startswith("# ZTP configuration files (1 on this page; 10 in total")
    assert "(1 file(s) of other platforms on this page were dropped client-side" in text
    assert text.endswith("(more on server: call cnc_list_ztp_config_files again with page=2.)")
    # Every row dropped (a platform absent from the page): the empty wording still points at
    # the next page — the raw page was full.
    text = await call_tool_text(
        build(make_settings()),
        "cnc_list_ztp_config_files",
        {"platform": "NX-OS", "page_size": 2, "page": 2},
    )
    assert text.startswith("No ZTP configuration files for platform 'NX-OS' on page 2.\n")
    assert "- (2 file(s) of other platforms on this page were dropped client-side" in text
    assert text.endswith("(more on server: call cnc_list_ztp_config_files again with page=3.)")
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_list_ztp_config_files",
            {"platform": "NX-OS", "page_size": 2, "page": 2, "response_format": "json"},
        )
    )
    assert data["count"] == 0 and data["dropped_by_platform"] == 2
    assert data["has_more"] is True and data["next_page"] == 3 and data["next_offset"] == 4
    # The all-platform total caps it: a full raw page that ends the store is the last.
    mock_svc(
        CONFIGS_URL,
        {"content": [CONFIG, CONFIG_XE], "pageNumber": 5, "pageSize": 2},
        CONFIGS_COUNT_URL,
        10,
        *config_lists(),
    )
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_list_ztp_config_files",
            {"platform": "IOS XR", "page_size": 2, "page": 5, "response_format": "json"},
        )
    )
    assert data["has_more"] is False and data["next_page"] is None and data["offset"] == 8


@respx.mock
async def test_list_ztp_config_files_unfiltered_page_and_errors(make_settings):
    mock_svc(CONFIGS_URL, CONFIG_PAGE, CONFIGS_COUNT_URL, 1, *config_lists())
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_config_files", {})
    assert text.startswith(
        "# ZTP configuration files (1 on this page; 1 in total over every platform)\n"
    )
    assert "dropped client-side" not in text
    mock_svc(CONFIGS_URL, CONFIG_PAGE_EMPTY, CONFIGS_COUNT_URL, 1, *config_lists())
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_config_files", {"page": 2})
    assert text.startswith("No ZTP configuration files on page 2 (the service holds 1).\n")
    respx.get(CONFIGS_COUNT_URL).mock(return_value=SERVER_ERROR)
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_config_files", {})
    assert text.startswith("Error: API request failed with status 500")


# --- cnc_list_ztp_images ----------------------------------------------------------------


@respx.mock
async def test_list_ztp_images_empty_and_populated(make_settings):
    route = mock_svc(
        ZTP_IMAGES_URL,
        IMAGE_PAGE_EMPTY,
        ZTP_IMAGES_COUNT_URL,
        0,
        (ZTP_IMAGE_PLATFORMS_URL, IMAGE_PLATFORMS),
    )
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_images", {})
    assert dict(route.calls[0].request.url.params) == image_params("1", "50")
    assert text.splitlines()[:2] == ["No ZTP images.", "- platforms: IOS XE, IOS XR"]
    mock_svc(
        ZTP_IMAGES_URL,
        IMAGE_PAGE,
        ZTP_IMAGES_COUNT_URL,
        1,
        (ZTP_IMAGE_PLATFORMS_URL, IMAGE_PLATFORMS),
    )
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_images", {"platform": "IOS XR", "page_size": 10}
    )
    assert dict(route.calls[-1].request.url.params) == image_params("1", "10", "IOS XR")
    assert text.startswith(
        "# ZTP images (1 on this page; 1 in total over every platform; platform IOS XR)\n"
        "- platforms: IOS XE, IOS XR\n"
    )
    assert (
        "- **img1** (cw-image-uuid-fa0541af-88d1-448f-b5fa-b6296ef6bf9f): Image for IOS XR" in text
    )
    data = json.loads(
        await call_tool_text(
            build(make_settings()), "cnc_list_ztp_images", {"response_format": "json"}
        )
    )
    assert data["platforms"] == ["IOS XE", "IOS XR"] and data["total_all_platforms"] == 1
    assert data["items"][0]["id"] == ZTP_IMAGE["id"] and data["dropped_by_platform"] == 0
    assert data["total"] == 1 and data["has_more"] is False


@respx.mock
async def test_list_ztp_images_platform_guard_and_errors(make_settings):
    mock_svc(
        ZTP_IMAGES_URL,
        IMAGE_PAGE,
        ZTP_IMAGES_COUNT_URL,
        1,
        (ZTP_IMAGE_PLATFORMS_URL, IMAGE_PLATFORMS),
    )
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_images", {"platform": "IOS XE"}
    )
    assert text.startswith(
        "No ZTP images for platform 'IOS XE' on page 1.\n- platforms: IOS XE, IOS XR\n"
    )
    assert "- (1 image(s) of other platforms on this page were dropped client-side" in text
    assert "(more on server" not in text  # a short raw page: nothing more
    respx.get(ZTP_IMAGES_URL).mock(return_value=SERVER_ERROR)
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_images", {})
    assert text.startswith("Error: API request failed with status 500")


ZTP_IMAGE_XE = {
    **ZTP_IMAGE,
    "id": "cw-image-uuid-xe",
    "imageTitle": "xe-img",
    "imagePlatform": "IOS XE",
}


@respx.mock
async def test_list_ztp_images_platform_guard_pages_on_the_full_raw_page(make_settings):
    """Same as the configsvc case: a full mixed page with the platform filter still pages."""
    route = mock_svc(
        ZTP_IMAGES_URL,
        {"content": [ZTP_IMAGE, ZTP_IMAGE_XE], "pageNumber": 1, "pageSize": 2},
        ZTP_IMAGES_COUNT_URL,
        10,
        (ZTP_IMAGE_PLATFORMS_URL, IMAGE_PLATFORMS),
    )
    data = json.loads(
        await call_tool_text(
            build(make_settings()),
            "cnc_list_ztp_images",
            {"platform": "IOS XR", "page_size": 2, "response_format": "json"},
        )
    )
    assert dict(route.calls[0].request.url.params) == image_params("1", "2", "IOS XR")
    assert data["count"] == 1 and data["dropped_by_platform"] == 1 and data["total"] is None
    assert data["has_more"] is True and data["next_page"] == 2 and data["next_offset"] == 2
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_images", {"platform": "IOS XR", "page_size": 2}
    )
    assert text.startswith("# ZTP images (1 on this page; 10 in total over every platform")
    assert "xe-img" not in text and "(1 image(s) of other platforms" in text
    assert text.endswith("(more on server: call cnc_list_ztp_images again with page=2.)")
    text = await call_tool_text(
        build(make_settings()), "cnc_list_ztp_images", {"platform": "NX-OS", "page_size": 2}
    )
    assert text.startswith("No ZTP images for platform 'NX-OS' on page 1.\n")
    assert "- (2 image(s) of other platforms on this page were dropped client-side" in text
    assert text.endswith("(more on server: call cnc_list_ztp_images again with page=2.)")
    # A page past the end without a filter names the total.
    mock_svc(
        ZTP_IMAGES_URL,
        IMAGE_PAGE_EMPTY,
        ZTP_IMAGES_COUNT_URL,
        1,
        (ZTP_IMAGE_PLATFORMS_URL, IMAGE_PLATFORMS),
    )
    text = await call_tool_text(build(make_settings()), "cnc_list_ztp_images", {"page": 2})
    assert text.startswith("No ZTP images on page 2 (the service holds 1).\n")
