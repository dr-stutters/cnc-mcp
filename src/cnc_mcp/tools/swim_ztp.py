"""SWIM and ZTP tools — software image management and zero-touch provisioning, read
only, over three small services (four base paths) of Crosswork Network Controller.

**SWIM** (``/crosswork/api/v1/op/swim/image``, Spring JSON, Bearer) is the
software image management service: an image **repository** (images imported
from a device, a URL or a file, keyed by a numeric ``imageId`` and typed
``SYSTEM_SW`` / ``XR type`` ...), a per-device view of the **running images**,
the SWIM **preferences** (``ContinueDistributionOnFailure``, ``copyByServer``,
``TFTPBootLocation``, ...) and the **jobs** of the SWIM dashboard — import
(``Software Image Import``), distribution / activation
(``Software Image Distribution``) and IOS XR commit (``Commit_Operations``).
This module reads all four. The write operations — ``collect`` (import),
``distribute``, ``activate``, ``commit`` and ``deleteImage`` — are NOT
exposed: none of them was exercised live (the lab repository is empty) and
each one changes the software a device runs or boots from. Ordering facts
from the platform notes, for whoever adds them: distribution must precede
activation (or ``distributeIfNeeded``), an image with ``imported=false`` is a
catalog record and not usable, and deleting an image neither removes it from
device flash nor changes boot behaviour.

**ZTP** (``/crosswork/ztp/v1``, JSON-over-POST queries) is zero-touch
provisioning: **profiles** (an OS platform + device family + version bundle
of a day-0 configuration file and an image), **devices** (the ZTP nodes —
host name, serial numbers, credential profile, profile and onboarding
``status`` Unprovisioned | InProgress | Provisioned | ProvisioningError |
ZtpError | Onboarded | OnboardingError), **serial numbers** (the device
serials ZTP will answer, with an optional ownership voucher for secure ZTP),
**static routes** (subnets the ZTP DHCP relay reaches) and the **device
policy** (the attributes ZTP writes onto the inventory record of an
onboarded device). The day-0 files themselves live in two sibling services:
**configsvc** (``/crosswork/configsvc/v1`` — Pre-config / Day0-config /
Post-config files per platform) and **imagesvc** (``/crosswork/imagesvc/v1``
— the ZTP image files, distinct from the SWIM repository). Every ZTP read is
exposed here, and so are the ZTP object writes (configuration files,
profiles, serial numbers, static routes, devices — see "ZTP writes" below).
Not exposed: serial-number CSV / ownership-voucher import, the device CSV
import/export, the device status PATCH (a booting device's state machine),
and the image upload / delete (the lab has no image; ``DELETE
imagesvc/images/<id>`` answers 204 for an unknown id too, so not even its
error path can be told apart).

Wire facts (verified live on Crosswork 7.2, 2026-09-13 — every one of these
services was EMPTY on the lab, so the empty answers are verbatim and the
populated item shapes follow the 7.2 OpenAPI documents; "unverified" marks
the latter):

- **ZTP HTTP-200-with-code rule**: every ``POST /crosswork/ztp/v1/*/query``
  answers HTTP 200 and the verdict is ``code`` in the body — ``{"code": 400,
  "message": "filter not provided"}`` when the ``filter`` key is absent
  (``filter: {}`` is accepted, so the tools always send one), ``{"code":
  200}`` / ``{"code": 200, "paginationDetails": {"PageSize": 30}}`` /
  ``{"code": 200, "message": "Get is success"}`` when nothing matches — the
  data key (``ztpProfiles``, ``ztpnodes``, ``data``, ``ztpStaticRoutes``) is
  simply ABSENT, never an empty list. :func:`check_ztp` turns any ``code``
  other than 200 into an ``Error:`` carrying the message; an absent data key
  is an empty list. Paging is ``filterData: {"PageSize", "PageNum"}`` with a
  0-based ``PageNum``; the answer's ``paginationDetails.TotalCount``
  (``pagination.TotalCount`` on the serial-number query) is the match count
  when the platform reports one (it did not on the empty lab).
- ``POST devices/policies/query {}`` answers ``{"policydata": {id,
  policyFields[], existingAttributes{}, newAttributes{}}, "code": 200}``.
- **SWIM**: ``GET getSwimPreference`` → ``{"items": [{"key", "value"}]}``;
  ``GET getSwimPreference/<key>`` → the bare value text (``Y``);
  ``GET getImagesForRepository[/<imageType>]`` with ``Range: items=<a>-<b>``
  → HTTP **206** ``Content-Range: items=0-0/0`` ``{"softwareImageListDTO":
  {"id": "imageId", "totalCount": 0}}`` when the repository is empty
  (``items[]`` when populated — unverified; the guides' base
  ``/crosswork/swim/v1`` is routed too and ``GET /crosswork/swim/v1/images``
  is the same repository read with the same 206 answer — this module keeps
  the ``op/swim/image`` spelling; ``devices`` / ``jobs`` under the guides'
  base answer a Spring 404); ``GET getDeviceRunningImages/<id>`` → HTTP 200
  ``{"runningSoftwareImageDTOList": {"id", "totalCount": 0, "resultErrMsg":
  ...}}``. **The device id is the INVENTORY UUID (verified 2026-09-14)**:
  ``getDeviceRunningImages/<inventory uuid>`` answers ``{"id": "454455",
  ...}`` — SWIM translates the uuid to the EMF ``nd.instanceId`` itself and
  the answer's ``id`` is that numeric id (which is accepted directly too).
  ``resultErrMsg`` "Get running Image Failed for the Device : Invalid
  Index" means SWIM holds NO software-image inventory for the device —
  the lab's containerised XRd is ``DEVICE_SUPPORT_LEVEL_UNCERTIFIED`` and
  SWIM's XR image collector has nothing to parse there — a platform
  limitation, not an id problem; ``"For input string: \\"PE1\\""`` means a
  non-uuid / non-numeric id (a host name) was given, which the tool now
  refuses before the call; ``resultErrMsg`` is ``Success`` when it works
  (per the document — no certified device was available to verify it);
  ``GET jobAllDetailsById/<n>`` → ``{"swimDashboardJobDetailsListDTO":
  {"identifier": "jobId", "count": 0, "totalCount": 0}}`` for an unknown
  job. Not called: ``jobResultDetailsById/<n>`` (a 500 NullPointer text for
  an unknown job) and ``isJobRunning/<n>`` (406 — it wants a non-JSON
  Accept).
- **configsvc**: ``GET configs?page=&size=[&platform=]`` → ``{"content":
  [], "pageNumber": 1, "pageSize": 0}``; ``GET configs/count`` → a bare
  ``0``; ``GET types`` → ``["Pre-config", "Day0-config", "Post-config"]``;
  ``GET platforms`` → ``["IOS XE", "IOS XR"]``. **imagesvc**: ``GET
  images?page=&size=`` → the same ``content`` page; ``GET images/count`` →
  ``0``; ``GET platforms`` → ``{"content": ["IOS XE", "IOS XR"], ...}``.
  The ``page`` / ``size`` / ``platform`` parameters were ACCEPTED without
  error on an empty store — whether any of them is honoured is UNVERIFIED
  (an empty ``content`` looks the same when a parameter is ignored, and
  the page value sent live is not on record). The 7.2 documents spell
  them ``PageNum`` / ``PageSize`` / ``osname`` (configsvc) and
  ``pageNumber`` / ``pageSize`` / ``imagePlatform`` (imagesvc), so the
  tools send BOTH spellings of each with the same value — Spring ignores
  query parameters it does not bind, and the live call already carried
  the undocumented names without complaint — and still re-filter the
  platform client-side and derive "more pages" from the RAW server page
  (a full page means more, whatever the guard dropped). Whether the page
  counts from 0 or 1 is unverified either way; the answer's ``pageNumber``
  echo is reported so the two can be compared on a populated instance.

**ZTP writes (verified live on Crosswork 7.2, 2026-09-15, with phase-d-*
objects created and removed again)** — every ``/crosswork/ztp/v1`` write
answers HTTP 200 with the verdict in the body's ``code``, like the queries:

- **configsvc** is the exception: plain HTTP statuses. ``POST
  configs/upload`` is ``multipart/form-data`` with ONE part ``configFile``
  (filename, bytes, text/plain) and the metadata in the QUERY STRING
  (``confname``, ``osname``, ``version``, ``devicefamily`` required;
  ``vendor``, ``type`` default ``Day0-config``) -> **201** with the ConfigDto
  (``confId`` uuid, ``confName``, ``fileName``, ``osName``, ``version``,
  ``size``, ``deviceFamily``, ``type``, ``vendor``, ``extraPlaceHolders``,
  ``createdTime`` / ``modifiedTime`` epoch ms, ``downloadurl``). A
  ``Day0-config`` ``.txt`` file MUST carry ``!! IOS XR`` (the platform
  banner) in one of its first three lines — else 400 "Text (.txt) script
  should have '!! IOS XR' in any of the first three lines"; ``Pre-config``
  wants a script — 400 "Pre-config should have script files (PY/SH)" —
  whose first line is a shebang (400 "Python (PY) and Shell (SH) script's
  first line should start with #!") AND a secure-ZTP-capable version:
  ``version`` 7.0.2 -> 400 "Pre-config do not support the classic version
  7.0.2 for platform IOS XR" (same for Post-config), 7.3.1 -> 201 (a
  ``.py`` Pre-config and a ``.sh`` Post-config, verified); a duplicate
  ``confname`` -> 409 "Configuration already exists with name
  X"; an unknown ``type`` -> 400 "Type X is not supported."; ``osname`` is
  NOT validated ("IOS XQ" was accepted — use the values of ``GET
  platforms``); a wrong part name or a missing required parameter -> a bare
  Spring 400. ``PUT configs/<confId>`` takes the same multipart form with
  any subset of the metadata parameters: the metadata changes and the file
  content is replaced (verified by downloading ``GET configs/files/<confId>``
  — text/plain), but the stored ``size`` is NOT recomputed (stale). ``DELETE
  configs/<confId>`` -> 204 empty; unknown id -> 404 {"message": "Config not
  found for <id>", "status": 404} (``GET configs/<confId>`` and ``PUT``
  answer the same 404). Deleting a file that a profile or a device still
  references is ALLOWED and flips their ``isConfigInvalid`` to true — a
  profile's Pre-config / Post-config likewise (204; the profile then
  carries ``isPreConfigInvalid: true`` / ``isPostConfigInvalid``, the id
  and the name stay — verified) — the tool guards all three: ``force``.
  ``GET configs`` paging, now seen on a
  populated store: the documented ``PageNum`` (1-based — ``PageNum=0`` is a
  Spring 500) / ``PageSize`` / ``osname`` (case-insensitive) ARE honoured
  and the ``page`` / ``size`` / ``platform`` spellings are ignored.
- **profiles**: ``POST profiles {"profiles": [{profileName, profileDescription,
  profileCategory, vendor, osPlatform, deviceFamily, version, image,
  isSecureZtp "false", preConfig, postConfig, config: <confId>}]}`` ->
  ``{"code": 201, "message": "Profile Created Successfully"}`` — NO id in
  the answer; ``POST profiles/query {"filter": {"profileName": ...}}`` (exact;
  ``profileId``, ``config``, ``preConfig`` and ``postConfig`` are exact
  filters too — and an UNKNOWN filter key is silently ignored, i.e. matches
  everything, so a misspelt key looks like "all profiles") fetches it. The
  record carries ``preConfig`` / ``postConfig`` / ``preConfigName`` /
  ``postConfigName`` only when set (blank keys are omitted). Duplicate
  name -> code 400 "Profile with name already exist : X"; no config -> 400
  "Config field is Mandatory"; unknown config -> 400 "Invalid Config IDs ::
  X"; a Pre-config / Post-config with ``isSecureZtp`` "false" -> 400
  "Secure ZTP flag should be enabled to support pre/post configurations for
  profile X." (all verified). ``PUT profiles {<the create form> +
  profileId}`` -> code 200 "Profile
  Updated Successfully" — echoing the query record back fails with code 422
  "json: cannot unmarshal string into Go struct field ZtpProfile.lastUpdated
  of type int64" (the query spells ``lastUpdated`` as a string); the
  ``profileName`` MUST be the existing name (a new name -> code 404
  "Profile with name X does not exist" — renaming is impossible), and
  **an unknown ``profileId`` with an existing name UPSERTS a second profile
  under that id** (verified — the tool refuses an unknown id before the
  call). ``DELETE profiles {"profiles": [{"profileId": ...}]}`` -> ``{"code":
  200}``; unknown -> code 404 "Profile with name <id> does not exist"; code
  424 "Profile  can not be deleted" (sic) while a ZTP device references the
  profile's config file DIRECTLY (metadata form); a device referencing the
  profile by ``profileName`` does NOT stop the delete (verified: code 200,
  the device keeps a dangling ``profileName``) — the tool guards it.
- **serial numbers**: ``POST serialnumbers {"data": [{"serialNumber"}...]}`` ->
  code 201 "Created Successfully" with ``processedRecordCount`` (new) and /
  or ``duplicateRecordCount`` (already registered; a key is ABSENT when its
  count is 0) — duplicates are never refused. ``DELETE serialnumbers {"data":
  [...]}`` -> code 204 "Deleted Successfully" EVEN when none of the serials
  exists (the tool checks first, one exact ``serialNumber`` query each);
  a serial bound to a device -> code 400 "Serial Number {X} is in use,
  cannot be deleted. " and the WHOLE list is refused — a free serial sent
  alongside an in-use one stays registered whichever comes first
  (verified; the tool refuses such a list before the call). Entries:
  ``serialNumber``, ``isInUse`` /
  ``isOVLinked`` ("true"/"false" strings — the example's spelling, not the
  document's ``isOvLinked``), ``modifiedDate`` (epoch SECONDS string).
- **static routes**: ``POST staticroutes {"staticroutes": [{"subnet", "mask":
  "<prefix length>"}]}`` -> code 201 "Add static route is initiated. Updating
  the status." — ASYNC: the route appears with ``status`` ``add-inprogress``
  and settles to ``success`` with ``message`` "Route-192.0.2.0/24,<crosswork
  data ip>-Success" within ~3 s; duplicate -> code 400 "X/Y : Route already
  exists". ``DELETE staticroutes {"staticroutes": [{"uuid"}]}`` -> code 201
  "Delete static route is initiated. Updating the status." — the route
  shows ``delete-inprogress`` and is gone within ~5 s; unknown uuid -> code
  400 "<uuid> : Route does not exists"; while in progress -> code 400 "X/Y :
  Route is already in Inprogress state". ``modifiedDate`` is epoch ms.
- **devices**: ``POST devices {"nodes": [{hostName, serialNumber: [ONE],
  credentialProfile, osPlatform, status: "Unprovisioned", isSecureZtp
  "false", enableOption82 "false", and EITHER profileName OR config +
  version + deviceFamily}]}`` -> code 201 "Device Added Successfully" (no
  uuid; ``devices/query`` with an exact ``hostName`` / ``uuid`` /
  ``profileName`` / ``config`` filter fetches it — a ``serialNumber`` filter
  must be a LIST, a string is a code-422 unmarshal error). Failures are code
  422 with ``message`` a JSON-ENCODED LIST ``[{"hostName", "errorMsg"}]``:
  "Serial Number(s) not present in allowed list: X" (register the serial
  FIRST), "Status field is Mandatory", "Status is Onboarded, status must be
  Unprovisioned only", "OS Platform is required." (even with a profile),
  "Cannot specify the 'Version' / 'Device Family' / config Id along with
  profile.", "Maximum of 1 serial number(s) are allowed.", "Credential
  Profile not found.", "Profile with name X does not exist", "Device with
  HostName X already exist.", "Device with SerialNumber X already exist.",
  "Version doesn't match with: Day0-config" (metadata form: version must
  equal the config file's), "Cannot associate the Secure ZTP enabled
  Profile to secure ZTP disabled Device." (a secure profile needs
  ``isSecureZtp`` "true" on the device too), "Can not associate serial(s)
  X with secure ZTP enabled device as OV is not linked." (a secure device
  needs an ownership voucher on its serial — the OV import is not exposed,
  so no secure device was ever created live). A failed create has no side
  effect on ZTP
  itself, but a serial registered just before it (the tool's
  ``register_serial``) STAYS registered (verified). The stored record
  copies ``config`` /
  ``configName`` / ``version`` / ``deviceFamily`` / ``vendor`` from the
  profile and binds the serial (``isInUse`` "true"). ``PUT devices {<the
  same create form> + uuid}`` -> code 200 "Device Updated Successfully"
  (rename and serial swap verified — the old serial is released; the
  record's ``lastUpdated`` string and profile-derived fields must NOT be
  echoed back; ``profileName: ""`` + config/version/deviceFamily switches a
  device to the metadata form); no uuid -> code 404 "UUID is empty, couldn't
  fetch the device."; unknown -> code 404 "1) Device with UUID : X does not
  exist."; a status other than Unprovisioned -> code 304 "[...] status must
  be Unprovisioned only"; missing status -> code 304. ``DELETE devices
  {"nodes": [{"uuid"}]}`` -> ``{"code": 200}`` and the serial is released;
  an unknown uuid is ALSO code 200, with ``message`` "1) Device with UUID :
  X does not exist." (a null uuid: "1) UUID is missing."; the other entries
  of the list are still deleted). ``PATCH devices`` (status) is not exposed.

All of SWIM, ZTP, configsvc and imagesvc are flagged ``deprecated: true``
on every operation of the 7.2 OpenAPI set (the ZTP documents are the only
ZTP API routed on this build); they are still routed and answering on the
lab.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from typing import Annotated, Any
from urllib.parse import quote

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, epoch_iso, finalize, pagination_envelope, to_json
from cnc_mcp.polling import wait_until
from cnc_mcp.safety import AppContext, register_tool

SWIM = "/crosswork/api/v1/op/swim/image"
ZTP = "/crosswork/ztp/v1"
CONFIGSVC = "/crosswork/configsvc/v1"
IMAGESVC = "/crosswork/imagesvc/v1"

SWIM_PREFERENCES_URL = f"{SWIM}/getSwimPreference"
SWIM_IMAGES_URL = f"{SWIM}/getImagesForRepository"
SWIM_RUNNING_IMAGES_URL = f"{SWIM}/getDeviceRunningImages"
SWIM_JOB_URL = f"{SWIM}/jobAllDetailsById"
ZTP_PROFILES_QUERY_URL = f"{ZTP}/profiles/query"
ZTP_DEVICES_QUERY_URL = f"{ZTP}/devices/query"
ZTP_SERIALS_QUERY_URL = f"{ZTP}/serialnumbers/query"
ZTP_STATIC_ROUTES_QUERY_URL = f"{ZTP}/staticroutes/query"
ZTP_POLICY_QUERY_URL = f"{ZTP}/devices/policies/query"
ZTP_PROFILES_URL = f"{ZTP}/profiles"
ZTP_DEVICES_URL = f"{ZTP}/devices"
ZTP_SERIALS_URL = f"{ZTP}/serialnumbers"
ZTP_STATIC_ROUTES_URL = f"{ZTP}/staticroutes"
CONFIGS_URL = f"{CONFIGSVC}/configs"
CONFIGS_UPLOAD_URL = f"{CONFIGSVC}/configs/upload"
CONFIG_FILES_URL = f"{CONFIGSVC}/configs/files"
CONFIGS_COUNT_URL = f"{CONFIGSVC}/configs/count"
CONFIG_TYPES_URL = f"{CONFIGSVC}/types"
CONFIG_PLATFORMS_URL = f"{CONFIGSVC}/platforms"
IMAGES_URL = f"{IMAGESVC}/images"
IMAGES_COUNT_URL = f"{IMAGESVC}/images/count"
IMAGE_PLATFORMS_URL = f"{IMAGESVC}/platforms"
# The 7.2 documents' (page, size, platform) query parameter names of ``configs`` and
# ``images`` — sent alongside the ``page`` / ``size`` / ``platform`` names that were accepted
# live, since neither spelling has been seen honoured on a populated store (svc_params).
CONFIGSVC_PARAM_NAMES = ("PageNum", "PageSize", "osname")
IMAGESVC_PARAM_NAMES = ("pageNumber", "pageSize", "imagePlatform")

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
ZTP_OK = 200
# The documented "Polciy Not Found" answer of devices/policies/query (code 404 inside HTTP
# 200, "No polices exits in ztp") — a normal "no policy" result, not a failure.
ZTP_POLICY_NOT_FOUND = 404
# The ZTP write verdicts (verified): 201 for a create / route add / route delete
# (both async), 200 for a profile or device update / delete, 204 for a serial delete.
ZTP_WRITE_OK = (200, 201, 204)
ZTP_NOT_FOUND = 404
# ``DELETE profiles`` while a device references the profile's config file directly.
ZTP_PROFILE_IN_USE = 424
ZTP_UNPROVISIONED = "Unprovisioned"
ZTP_FALSE = "false"
ZTP_TRUE = "true"
# configsvc file types (``GET types``, verified) and the one the upload defaults to.
CONFIG_TYPES = ("Pre-config", "Day0-config", "Post-config")
DEFAULT_CONFIG_TYPE = "Day0-config"
DEFAULT_VENDOR = "Cisco Systems"
DEFAULT_PROFILE_CATEGORY = "0day"
CONFIG_FILE_PART = "configFile"
CONFIG_FILE_MEDIA_TYPE = "text/plain"
MAX_CONFIG_CONTENT_CHARS = 200_000
MAX_SERIALS_PER_CALL = 100
# A static-route status still settling (``add-inprogress`` / ``delete-inprogress``), and the
# one terminal status seen live (``success``) — any other settled status is reported as a
# failed install, not as "added".
ROUTE_IN_PROGRESS = "inprogress"
ROUTE_SUCCESS = "success"
# The profile fields that reference a configsvc file (verified: each is an exact query
# filter, and the record carries the pre/post ids only when set).
PROFILE_CONFIG_FIELDS = ("config", "preConfig", "postConfig")
ROUTE_POLL_SECONDS = 1.0
DEFAULT_ROUTE_WAIT_SECONDS = 15
MAX_ROUTE_WAIT_SECONDS = 120
# The message fragments of ``DELETE devices`` (code 200 even then — verified) that mean
# nothing was deleted for that uuid.
DEVICE_NOT_DELETED_MARKERS = ("does not exist", "is missing")
# Hints keyed on the verified ``errorMsg`` texts of the device writes.
ZTP_DEVICE_HINTS = (
    (
        "not present in allowed list",
        "register the serial number first with cnc_add_ztp_serial_numbers (or pass "
        "register_serial=true)",
    ),
    ("credential profile not found", "cnc_list_credential_profiles shows the profile names"),
    ("profile with name", "cnc_list_ztp_profiles shows the profile names"),
    (
        "along with profile",
        "a device that names a profile takes its version / device family / config from it — "
        "pass profile_name alone, or config_id + version + device_family without a profile",
    ),
    (
        "version doesn't match",
        "in the metadata form the version must equal the config file's version "
        "(cnc_list_ztp_config_files)",
    ),
    ("already exist", "host names and serial numbers are unique across ZTP devices"),
    (
        "must be unprovisioned",
        "ZTP creates and updates devices in the Unprovisioned state only",
    ),
    (
        "secure ztp enabled profile",
        "a profile with isSecureZtp true (one carrying a Pre-config / Post-config) can only "
        "be used by a device created with secure_ztp=true",
    ),
    (
        "ov is not linked",
        "a secure-ZTP device needs a serial with an ownership voucher (isOVLinked true) — "
        "the OV import is not exposed here (Crosswork UI: Device Management > Serial Number "
        "and OV Import)",
    ),
)
SWIM_SUCCESS = "Success"
# ZTP device onboarding statuses (7.2 document; the lab had no device).
ZTP_DEVICE_STATUSES = (
    "Unprovisioned",
    "InProgress",
    "Provisioned",
    "ProvisioningError",
    "ZtpError",
    "Onboarded",
    "OnboardingError",
)
SWIM_DEVICE_ID_CAVEAT = (
    "the device_id must be the device's inventory uuid (SWIM maps it to its EMF instance id "
    "itself — verified) or that numeric EMF instance id; a host name is refused by SWIM with "
    "'For input string: \"<name>\"'"
)
SWIM_INVALID_INDEX = "invalid index"
SWIM_FOR_INPUT_STRING = "for input string"

_CONTENT_RANGE_RE = re.compile(r"items=(\d+)-(\d+)/(\d+|\*)")
# The two id spellings SWIM resolves (verified): the inventory uuid (canonical hyphenated form,
# any hex case) and the numeric EMF instance id. Anything else gets "For input string".
_SWIM_DEVICE_ID_RE = re.compile(
    r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.IGNORECASE
)

_RESPONSE_FORMAT_DESC = "'markdown' for human-readable output, 'json' for complete data."
_ZTP_PAGE_SIZE_DESC = "Entries per page (filterData.PageSize, e.g. 50)."
_ZTP_PAGE_DESC = "0-based page number (filterData.PageNum, e.g. 0 for the first page)."
_SVC_PAGE_DESC = (
    "Page number (e.g. 1), sent as the 'page' parameter that was accepted live AND as the "
    "documented 'PageNum' / 'pageNumber'. Whether the service honours it, and whether it counts "
    "from 0 or 1, is unverified (the empty verified store echoed pageNumber 1): if page 1 comes "
    "back empty while the count is not 0, try page=0."
)
_SVC_PAGE_SIZE_DESC = (
    "Entries per page (e.g. 50), sent as 'size' and as the documented 'PageSize' / 'pageSize'; "
    "whether it is honoured is unverified."
)
_CONFIGSVC_PAGE_DESC = (
    "1-based page number (e.g. 1), sent as the documented 'PageNum' (honoured — verified on a "
    "populated store; PageNum=0 is a server 500, hence the minimum of 1) and as 'page' "
    "(ignored)."
)


# --- pure helpers: requests ---------------------------------------------------------


def ztp_query_body(
    filters: dict[str, Any] | None, page_size: int = DEFAULT_PAGE_SIZE, page: int = 0
) -> dict[str, Any]:
    """The verified ZTP query body: ``{"filter": {...}, "filterData": {"PageSize", "PageNum"}}``.

    The ``filter`` key is ALWAYS present (an absent one answers ``code 400
    "filter not provided"``; ``{}`` is accepted); blank / None values are
    dropped from it. ``PageNum`` is 0-based.
    """
    clean = {k: v for k, v in (filters or {}).items() if v not in (None, "")}
    return {"filter": clean, "filterData": {"PageSize": page_size, "PageNum": page}}


def range_header(page: int, page_size: int) -> dict[str, str]:
    """``Range: items=<start>-<end>`` for a 1-based ``page`` of ``page_size`` SWIM images.

    ``getImagesForRepository`` answered 206 with ``Content-Range: items=0-0/0``
    on the empty verified repository; the header form is the document's
    (``items=0-49`` for the first page of 50). The Range value sent live is
    not on record, so whether the window is honoured is unverified.
    """
    start = (page - 1) * page_size
    return {"Range": f"items={start}-{start + page_size - 1}"}


def parse_content_range(value: str | None) -> tuple[int, int, int | None] | None:
    """``items=0-0/0`` -> ``(0, 0, 0)``; ``items=0-49/*`` -> ``(0, 49, None)``; else None."""
    if not isinstance(value, str):
        return None
    match = _CONTENT_RANGE_RE.search(value)
    if not match:
        return None
    total = None if match.group(3) == "*" else int(match.group(3))
    return int(match.group(1)), int(match.group(2)), total


def parse_bool_text(value: str, what: str) -> str | None:
    """``'true'`` / ``'false'`` (any case, stripped) -> the ZTP wire string; blank -> None.

    ZTP booleans are STRINGS on the wire (``"isInUse": "false"``, per the 7.2
    document and its examples). Anything else is a PlatformError.
    """
    text = value.strip().lower()
    if not text:
        return None
    if text in ("true", "false"):
        return text
    raise PlatformError(f"{what} must be 'true', 'false' or blank, got '{value}'.")


# --- pure helpers: responses ----------------------------------------------------------


def as_int(value: Any) -> int | None:
    """An int from an int, float or numeric string; None otherwise (never an invented 0)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def string_list(value: Any) -> list[str]:
    """A bare list of strings (configsvc ``types`` / ``platforms``) or the ``content`` of a
    ``{"content": [...]}`` page (imagesvc ``platforms``) -> list of str; else []."""
    if isinstance(value, dict):
        value = value.get("content")
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str | int | float)]


def check_ztp(data: Any, what: str, ok_codes: tuple[int, ...] = (ZTP_OK,)) -> dict[str, Any]:
    """Apply the ZTP HTTP-200-with-code rule: raise PlatformError unless ``code`` is OK.

    Verified live: every ZTP query answers HTTP 200 and the verdict is the
    body's ``code`` — 400 "filter not provided" for a body without ``filter``;
    200 (with the data key absent) when nothing matches. A body without a
    ``code`` is accepted as-is (the platform always sent one, but a missing
    verdict is not proof of failure); a non-dict body is an error.
    """
    if not isinstance(data, dict):
        raise PlatformError(
            f"{what}: the ZTP service returned an unexpected response shape: {str(data)[:300]}"
        )
    code = as_int(data.get("code"))
    if code is not None and code not in ok_codes:
        message = data.get("message")
        reason = message.strip() if isinstance(message, str) and message.strip() else "no message"
        raise PlatformError(f"{what} failed (ZTP answered code {code}): {reason}")
    return data


def ztp_code(data: dict[str, Any]) -> int | None:
    return as_int(data.get("code"))


def ztp_total(data: dict[str, Any]) -> int | None:
    """``paginationDetails.TotalCount`` (profiles / devices / routes) or
    ``pagination.TotalCount`` (serial numbers) — None when the platform sent neither
    (verified: the empty lab answers carried no TotalCount)."""
    for key in ("paginationDetails", "pagination"):
        block = data.get(key)
        if isinstance(block, dict):
            total = as_int(block.get("TotalCount"))
            if total is not None:
                return total
    return None


def page_envelope(
    items: list[Any], *, total: int | None, page: int, page_size: int, first_page: int
) -> dict[str, Any]:
    """The template's :func:`pagination_envelope` in page terms.

    ``first_page`` is 0 for the ZTP queries (``PageNum``) and 1 for the SWIM
    Range paging and the ``page`` parameter of configsvc / imagesvc, so
    ``offset`` is right whichever convention the service uses. Without a
    total, ``has_more`` falls back to "the page came back full".
    """
    offset = max(page - first_page, 0) * page_size
    env = pagination_envelope(items, total=total, offset=offset, limit=page_size)
    env["page"] = page
    env["page_size"] = page_size
    env["next_page"] = page + 1 if env["has_more"] else None
    return env


def guarded_page_envelope(
    views: list[Any], raw_count: int, *, total_all: int | None, page: int, page_size: int
) -> dict[str, Any]:
    """:func:`page_envelope` for a configsvc / imagesvc page re-filtered client-side.

    ``total`` is None (the count endpoint counts every platform, not the
    filtered rows) and ``has_more`` / ``next_page`` / ``next_offset`` are
    derived from the RAW server page, not from what survived the platform
    guard: a full server page means more, whatever the guard dropped from
    it. The guard exists for the case where the service ignores its platform
    parameter — exactly the case where a full page of mixed platforms would
    otherwise look short and stop the agent early. The all-platform total
    caps it (``offset + raw_count < total_all``), so the last page of a
    store never points at an empty one.
    """
    env = page_envelope(views, total=None, page=page, page_size=page_size, first_page=1)
    offset = env["offset"]
    has_more = raw_count >= page_size and (total_all is None or offset + raw_count < total_all)
    env["has_more"] = has_more
    env["next_offset"] = offset + raw_count if has_more else None
    env["next_page"] = page + 1 if has_more else None
    return env


def more_note(env: dict[str, Any], tool: str) -> list[str]:
    if not env.get("has_more"):
        return []
    known = f" of {env['total']}" if env.get("total") is not None else ""
    return [
        "",
        f"(more on server{known}: call {tool} again with page={env['next_page']}.)",
    ]


def ztp_past_the_end(what: str, scope: str, total: int | None, page: int) -> str | None:
    """The non-error text for an empty ZTP page while ``TotalCount`` says matches exist —
    a page past the end (unverified: the empty lab sent no TotalCount) — else None."""
    if not total:
        return None
    return f"No {what}{scope} on page {page} (ZTP reports {total} matching; page 0 is the first)."


def _text(value: Any, default: str = "?") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _bytes(value: Any) -> str:
    number = as_int(value)
    if number is None:
        return "-"
    if number >= 1024**3:
        return f"{number / 1024**3:.1f} GiB"
    if number >= 1024**2:
        return f"{number / 1024**2:.1f} MiB"
    if number >= 1024:
        return f"{number / 1024:.1f} KiB"
    return f"{number} B"


def matches_platform(value: Any, wanted: str) -> bool:
    """Case-insensitive exact match of a row's platform against the filter ('' matches all)."""
    if not wanted.strip():
        return True
    return _text(value, "").strip().lower() == wanted.strip().lower()


# --- SWIM views ---------------------------------------------------------------------


def preferences_of(data: Any) -> list[dict[str, Any]]:
    """The ``items`` of ``getSwimPreference`` as ``[{key, value}]`` (verified shape)."""
    items = data.get("items") if isinstance(data, dict) else None
    out = []
    for item in dict_list(items):
        if "key" in item:
            out.append({"key": str(item.get("key")), "value": item.get("value")})
    return out


def preference_value_of(response: httpx.Response) -> str:
    """The value text of ``getSwimPreference/<key>``: verified as the bare text ``Y``; a
    JSON string (``"Y"``, the documented media type) is unquoted; blank -> ''."""
    text = response.text.strip()
    if text.startswith('"'):
        try:
            parsed = json.loads(text)
        except ValueError:
            return text
        return str(parsed) if parsed is not None else ""
    return text


def image_list_of(data: Any) -> dict[str, Any]:
    """The ``softwareImageListDTO`` wrapper of ``getImagesForRepository`` (``{}`` if absent)."""
    block = data.get("softwareImageListDTO") if isinstance(data, dict) else None
    return block if isinstance(block, dict) else {}


def image_view(image: dict[str, Any]) -> dict[str, Any]:
    """Curated SoftwareImageDTO fields (7.2 document — no populated repository seen live).

    The document spells the family ``family`` and the size ``filesize``;
    ``imageFamily`` / ``size`` (the running-image spelling) are accepted too.
    """
    return {
        "imageId": image.get("imageId"),
        "imageName": image.get("imageName") or image.get("name"),
        "imageType": image.get("imageType"),
        "imagePlatform": image.get("imagePlatform"),
        "family": image.get("family") or image.get("imageFamily"),
        "version": image.get("version"),
        "filesize": as_int(image.get("filesize", image.get("size"))),
        "vendor": image.get("vendor"),
        "features": image.get("features"),
        "imageLocation": image.get("imageLocation"),
        "imageCheckSum": image.get("imageCheckSum"),
        "uploadedBy": image.get("uploadedBy"),
        "updatedOn": image.get("updatedOn"),
        "upgradeNeeded": image.get("upgradeNeeded"),
        "description": image.get("description"),
    }


def image_line(view: dict[str, Any]) -> str:
    return (
        f"- **{_text(view.get('imageName'))}** (id {_text(view.get('imageId'))}): "
        f"{_text(view.get('imageType'))}, {_text(view.get('imagePlatform'))} "
        f"{_text(view.get('family'))} v{_text(view.get('version'))}, "
        f"{_bytes(view.get('filesize'))}, by {_text(view.get('uploadedBy'), '-')}, "
        f"updated {epoch_iso(view.get('updatedOn'))}"
    )


def running_list_of(data: Any) -> dict[str, Any]:
    block = data.get("runningSoftwareImageDTOList") if isinstance(data, dict) else None
    return block if isinstance(block, dict) else {}


def running_image_view(image: dict[str, Any]) -> dict[str, Any]:
    return {
        "deviceId": image.get("deviceId"),
        "deviceName": image.get("deviceName"),
        "imageName": image.get("imageName"),
        "imageFileName": image.get("imageFileName"),
        "imageType": image.get("imageType"),
        "imageFamily": image.get("imageFamily") or image.get("deviceFamily"),
        "version": image.get("version"),
        "features": image.get("features"),
        "size": image.get("size"),
        "installableStatus": image.get("installableStatus"),
        "installableType": image.get("installableType"),
        "installedLocation": image.get("installedLocation"),
        "inRepository": image.get("inRepository"),
        "ipAddress": image.get("ipAddress"),
    }


def running_image_line(view: dict[str, Any]) -> str:
    return (
        f"- **{_text(view.get('imageName'))}** v{_text(view.get('version'))}: "
        f"{_text(view.get('installableStatus'))} on {_text(view.get('installedLocation'))}, "
        f"{_text(view.get('imageType'))} {_text(view.get('imageFamily'))}, file "
        f"{_text(view.get('imageFileName'), '-')}"
    )


def validate_swim_device_id(value: str) -> str:
    """The stripped ``device_id`` when it is an inventory uuid or a numeric EMF instance id;
    PlatformError (before any call) for anything else.

    Verified live: SWIM resolves the inventory uuid (it maps it to the EMF
    instance id itself) and the numeric id; a host name is answered inside
    HTTP 200 with ``resultErrMsg`` ``For input string: "PE1"`` — Java's
    number-parse failure — so the refusal is made here, with the same
    explanation, and the accepted text is sent VERBATIM (SWIM did the uuid
    translation on the spelling the inventory shows).
    """
    text = value.strip()
    if _SWIM_DEVICE_ID_RE.match(text):
        return text
    raise PlatformError(
        f"device_id '{text}' is neither an inventory uuid nor a numeric EMF instance id — SWIM "
        f"would answer 'For input string: \"{text}\"' (a host name gets exactly that); "
        f"{SWIM_DEVICE_ID_CAVEAT}. cnc_get_device(host_name='{text}') or cnc_list_devices "
        "shows the uuid."
    )


def emf_mapping(device_id: str, emf_id: Any) -> str:
    """``SWIM maps it to EMF instance id <id>`` from the answer's ``id`` (the EMF instance id
    SWIM translated the given uuid to — verified), or the generic form when SWIM sent none."""
    mapped = _text(emf_id, "")
    if mapped:
        return f"SWIM maps it to EMF instance id {mapped}"
    return "SWIM maps it to the EMF instance id itself"


def swim_running_error(device_id: str, message: str, emf_id: Any = None) -> PlatformError:
    """The Error for a non-``Success`` ``resultErrMsg`` of ``getDeviceRunningImages``.

    Verified meanings: "Invalid Index" = SWIM holds no software-image inventory
    for the device (uncertified platform such as a containerised XRd, or
    the inventory was never collected) — NOT a wrong id; "For input string"
    = a non-uuid / non-numeric id (refused client-side before the call, so
    only reachable if SWIM changes its parsing). Anything else is reported
    verbatim with the id rule.
    """
    lowered = message.lower()
    if SWIM_INVALID_INDEX in lowered:
        return PlatformError(
            f"SWIM holds no software-image inventory for device {device_id} (SWIM answered: "
            f"{message}) — the device's platform is not SWIM-certified (a containerised XRd is "
            "DEVICE_SUPPORT_LEVEL_UNCERTIFIED and SWIM's XR image collector has nothing to "
            "parse there) or its image inventory was never collected; the inventory uuid is "
            f"the right id ({emf_mapping(device_id, emf_id)})."
        )
    if lowered.startswith(SWIM_FOR_INPUT_STRING):
        return PlatformError(
            f"SWIM could not parse device id '{device_id}' (SWIM answered: {message}) — "
            f"{SWIM_DEVICE_ID_CAVEAT}."
        )
    return PlatformError(
        f"SWIM could not read the running images of device {device_id} (SWIM answered: "
        f"{message}); {SWIM_DEVICE_ID_CAVEAT}."
    )


def job_list_of(data: Any) -> dict[str, Any]:
    block = data.get("swimDashboardJobDetailsListDTO") if isinstance(data, dict) else None
    return block if isinstance(block, dict) else {}


def job_view(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "jobId": job.get("jobId"),
        "jobName": job.get("jobName"),
        "jobType": job.get("jobType"),
        "jobDescription": job.get("jobDescription"),
        "workState": job.get("workState"),
        "resultState": job.get("resultState"),
        "deviceCount": as_int(job.get("deviceCount")),
        "actualStartTime": job.get("actualStartTime"),
        "completionTime": job.get("completionTime"),
        "jobSpecificationId": job.get("jobSpecificationId"),
        "taskId": job.get("taskId"),
    }


def job_line(view: dict[str, Any]) -> str:
    devices = view.get("deviceCount")
    return (
        f"- **{_text(view.get('jobName'))}** (job {_text(view.get('jobId'))}, spec "
        f"{_text(view.get('jobSpecificationId'))}, task {_text(view.get('taskId'), '-')}): "
        f"{_text(view.get('jobType'))} — {_text(view.get('workState'))} / "
        f"{_text(view.get('resultState'))}, {devices if devices is not None else '?'} "
        f"device(s), started {epoch_iso(view.get('actualStartTime'))}, completed "
        f"{epoch_iso(view.get('completionTime'))}"
        + (f" — {view['jobDescription']}" if view.get("jobDescription") else "")
    )


# --- ZTP views ----------------------------------------------------------------------


def profile_view(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "profileId": profile.get("profileId"),
        "profileName": profile.get("profileName"),
        "osPlatform": profile.get("osPlatform"),
        "deviceFamily": profile.get("deviceFamily"),
        "version": profile.get("version"),
        "vendor": profile.get("vendor"),
        "config": profile.get("config"),
        "configName": profile.get("configName"),
        "image": profile.get("image"),
        "imageName": profile.get("imageName"),
        "preConfig": profile.get("preConfig"),
        "preConfigName": profile.get("preConfigName"),
        "postConfig": profile.get("postConfig"),
        "postConfigName": profile.get("postConfigName"),
        "isSecureZtp": profile.get("isSecureZtp"),
        "profileCategory": profile.get("profileCategory"),
        "profileDescription": profile.get("profileDescription"),
        "isConfigInvalid": profile.get("isConfigInvalid"),
        "isImageInvalid": profile.get("isImageInvalid"),
        "isPreConfigInvalid": profile.get("isPreConfigInvalid"),
        "isPostConfigInvalid": profile.get("isPostConfigInvalid"),
        "lastUpdated": profile.get("lastUpdated"),
    }


def profile_line(view: dict[str, Any]) -> str:
    extras = []
    if view.get("imageName"):
        extras.append(f"image {view['imageName']}")
    if str(view.get("isSecureZtp")).lower() == "true":
        extras.append("secure ZTP")
    if any(
        view.get(k)
        for k in ("isConfigInvalid", "isImageInvalid", "isPreConfigInvalid", "isPostConfigInvalid")
    ):
        extras.append("OUT OF SYNC with its files")
    tail = f" ({'; '.join(extras)})" if extras else ""
    return (
        f"- **{_text(view.get('profileName'))}** ({_text(view.get('profileId'))}): "
        f"{_text(view.get('osPlatform'))} {_text(view.get('deviceFamily'))} "
        f"v{_text(view.get('version'))}, config {_text(view.get('configName'), '-')}, "
        f"category {_text(view.get('profileCategory'), '-')}, updated "
        f"{epoch_iso(view.get('lastUpdated'))}{tail}"
    )


def _ip_text(address: Any) -> str:
    if not isinstance(address, dict):
        return "-"
    ip = _text(address.get("ipaddrs"), "")
    if not ip:
        return "-"
    mask = address.get("mask")
    return f"{ip}/{mask}" if mask not in (None, "") else ip


def device_view(node: dict[str, Any]) -> dict[str, Any]:
    serials = node.get("serialNumber")
    provider = node.get("providerInfo")
    return {
        "uuid": node.get("uuid"),
        "hostName": node.get("hostName"),
        "serialNumber": [str(s) for s in serials] if isinstance(serials, list) else [],
        "credentialProfile": node.get("credentialProfile"),
        "osPlatform": node.get("osPlatform"),
        "version": node.get("version"),
        "deviceFamily": node.get("deviceFamily"),
        "profileName": node.get("profileName"),
        "configName": node.get("configName"),
        "imageName": node.get("imageName"),
        "status": node.get("status"),
        "message": node.get("message"),
        "ipAddress": node.get("ipAddress"),
        "macAddress": node.get("macAddress"),
        "inventoryId": node.get("inventoryId"),
        "providerName": provider.get("providerName") if isinstance(provider, dict) else None,
        "isSecureZtp": node.get("isSecureZtp"),
        "enableOption82": node.get("enableOption82"),
        "lastUpdated": node.get("lastUpdated"),
    }


def device_line(view: dict[str, Any]) -> str:
    serials = ", ".join(view.get("serialNumber") or []) or "-"
    message = _text(view.get("message"), "")
    tail = f" — {message}" if message else ""
    return (
        f"- **{_text(view.get('hostName'))}** ({_text(view.get('uuid'))}): "
        f"{_text(view.get('status'))}, serial {serials}, {_text(view.get('osPlatform'))} "
        f"{_text(view.get('deviceFamily'))} v{_text(view.get('version'))}, profile "
        f"{_text(view.get('profileName'), '-')}, credentials "
        f"{_text(view.get('credentialProfile'), '-')}, ip {_ip_text(view.get('ipAddress'))}, "
        f"updated {epoch_iso(view.get('lastUpdated'))}{tail}"
    )


def serial_view(serial: dict[str, Any]) -> dict[str, Any]:
    """The document spells the voucher flag ``isOvLinked``; its example says ``isOVLinked``."""
    return {
        "serialNumber": serial.get("serialNumber"),
        "isInUse": serial.get("isInUse"),
        "isOvLinked": serial.get("isOvLinked", serial.get("isOVLinked")),
        "ovFilename": serial.get("ovFilename"),
        "modifiedDate": serial.get("modifiedDate"),
    }


def serial_line(view: dict[str, Any]) -> str:
    in_use = str(view.get("isInUse")).lower() == "true"
    ov = str(view.get("isOvLinked")).lower() == "true"
    voucher = f"voucher {view['ovFilename']}" if ov and view.get("ovFilename") else None
    return (
        f"- **{_text(view.get('serialNumber'))}**: {'in use' if in_use else 'free'}, "
        f"{voucher or ('ownership voucher linked' if ov else 'no ownership voucher')}, "
        f"modified {epoch_iso(view.get('modifiedDate'))}"
    )


def route_view(route: dict[str, Any]) -> dict[str, Any]:
    return {
        "uuid": route.get("uuid"),
        "subnet": route.get("subnet"),
        "mask": route.get("mask"),
        "status": route.get("status"),
        "message": route.get("message"),
        "modifiedDate": route.get("modifiedDate"),
    }


def route_line(view: dict[str, Any]) -> str:
    message = _text(view.get("message"), "")
    return (
        f"- **{_text(view.get('subnet'))}/{_text(view.get('mask'))}** "
        f"({_text(view.get('uuid'))}): {_text(view.get('status'))}, modified "
        f"{epoch_iso(view.get('modifiedDate'))}" + (f" — {message}" if message else "")
    )


def policy_of(data: dict[str, Any]) -> dict[str, Any]:
    block = data.get("policydata")
    return block if isinstance(block, dict) else {}


def policy_markdown(policy: dict[str, Any]) -> str:
    fields = policy.get("policyFields")
    fields = [str(f) for f in fields] if isinstance(fields, list) else []
    existing = policy.get("existingAttributes")
    existing = existing if isinstance(existing, dict) else {}
    new = policy.get("newAttributes")
    new = new if isinstance(new, dict) else {}
    lines = [
        f"# ZTP device policy {_text(policy.get('id'))}",
        "",
        f"- policy fields ({len(fields)}): {', '.join(fields) or '-'}",
        f"- existing attributes ({len(existing)}): "
        + (", ".join(f"{k} = {v}" for k, v in existing.items()) or "-"),
        f"- new attributes ({len(new)}): "
        + (", ".join(f"{k} = {v}" for k, v in new.items()) or "-"),
        "",
        "The policy names the attributes ZTP writes onto the inventory record of a device it "
        "onboards (existing: already in the inventory model; new: added by ZTP, e.g. the "
        "routingInfo.* router-ids).",
    ]
    return "\n".join(lines)


# --- configsvc / imagesvc views -------------------------------------------------------


def page_content_of(data: Any) -> list[dict[str, Any]]:
    return dict_list(data.get("content")) if isinstance(data, dict) else []


def config_view(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "confId": config.get("confId"),
        "confName": config.get("confName"),
        "type": config.get("type"),
        "osName": config.get("osName"),
        "deviceFamily": config.get("deviceFamily"),
        "version": config.get("version"),
        "vendor": config.get("vendor"),
        "fileName": config.get("fileName"),
        "size": as_int(config.get("size")),
        "extraPlaceHolders": config.get("extraPlaceHolders"),
        "childIds": config.get("childIds"),
        "createdBy": config.get("createdBy"),
        "createdTime": config.get("createdTime"),
        "modifiedBy": config.get("modifiedBy"),
        "modifiedTime": config.get("modifiedTime"),
        "downloadurl": config.get("downloadurl"),
    }


def config_line(view: dict[str, Any]) -> str:
    placeholders = _text(view.get("extraPlaceHolders"), "")
    tail = f", placeholders {placeholders}" if placeholders else ""
    return (
        f"- **{_text(view.get('confName'))}** ({_text(view.get('confId'))}): "
        f"{_text(view.get('type'))} for {_text(view.get('osName'))} "
        f"{_text(view.get('deviceFamily'))} v{_text(view.get('version'))}, file "
        f"{_text(view.get('fileName'), '-')} ({_bytes(view.get('size'))}), by "
        f"{_text(view.get('createdBy'), '-')}, modified {epoch_iso(view.get('modifiedTime'))}"
        f"{tail}"
    )


def ztp_image_view(image: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": image.get("id"),
        "imageTitle": image.get("imageTitle"),
        "imageFileName": image.get("imageFileName"),
        "imageType": image.get("imageType"),
        "imagePlatform": image.get("imagePlatform"),
        "imageVersion": image.get("imageVersion"),
        "deviceFamily": image.get("deviceFamily"),
        "vendor": image.get("vendor"),
        "imageSource": image.get("imageSource"),
        "createdBy": image.get("createdBy"),
        "createdTime": image.get("createdTime"),
        "modifiedBy": image.get("modifiedBy"),
        "modifiedTime": image.get("modifiedTime"),
        "downloadURL": image.get("downloadURL"),
    }


def ztp_image_line(view: dict[str, Any]) -> str:
    return (
        f"- **{_text(view.get('imageTitle'))}** ({_text(view.get('id'))}): "
        f"{_text(view.get('imageType'))} for {_text(view.get('imagePlatform'))} "
        f"{_text(view.get('deviceFamily'))} v{_text(view.get('imageVersion'))}, file "
        f"{_text(view.get('imageFileName'), '-')}, source {_text(view.get('imageSource'), '-')}, "
        f"modified {epoch_iso(view.get('modifiedTime'))}"
    )


def split_platform(
    rows: list[dict[str, Any]], key: str, platform: str
) -> tuple[list[dict[str, Any]], int]:
    """Keep the rows whose ``key`` matches ``platform`` -> (kept, dropped count).

    Whether the services honour their ``platform`` query parameter could
    not be told on an empty instance, so the tools re-filter the page
    client-side and say how many rows they dropped.
    """
    if not platform.strip():
        return rows, 0
    kept = [r for r in rows if matches_platform(r.get(key), platform)]
    return kept, len(rows) - len(kept)


def svc_params(
    page: int, page_size: int, platform: str, documented: tuple[str, str, str]
) -> dict[str, Any]:
    """The ``configs`` / ``images`` query parameters, in BOTH spellings.

    ``page`` / ``size`` / ``platform`` were accepted live on an empty store
    (whether honoured is unverified); ``documented`` is the 7.2 document's
    (page, size, platform) names — CONFIGSVC_PARAM_NAMES or
    IMAGESVC_PARAM_NAMES — sent with the same values so whichever the
    service binds takes effect (Spring ignores the rest). Blank ``platform``
    sends neither platform name.
    """
    page_name, size_name, platform_name = documented
    params: dict[str, Any] = {"page": page, "size": page_size, page_name: page}
    params[size_name] = page_size
    if platform:
        params["platform"] = platform
        params[platform_name] = platform
    return params


# --- ZTP write helpers ------------------------------------------------------------------


def split_csv(value: str) -> list[str]:
    """Comma-separated text -> stripped, de-duplicated, order-preserving list (blanks dropped)."""
    seen: list[str] = []
    for item in value.split(","):
        text = item.strip()
        if text and text not in seen:
            seen.append(text)
    return seen


def ztp_bool(value: bool) -> str:
    """A Python bool -> the ZTP wire string (``"true"`` / ``"false"`` — verified)."""
    return ZTP_TRUE if value else ZTP_FALSE


def ztp_message(data: dict[str, Any]) -> str:
    message = data.get("message")
    return message.strip() if isinstance(message, str) else ""


def parse_ztp_error_list(message: str) -> list[str]:
    """The device writes pack their per-device errors into ``message`` as a JSON-ENCODED
    list ``[{"hostName", "errorMsg"}]`` (verified) -> ``["<host>: <errorMsg>", ...]``;
    any other text -> ``[message]`` (blank -> [])."""
    text = message.strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            out = []
            for entry in parsed:
                if isinstance(entry, dict):
                    host = _text(entry.get("hostName"), "")
                    error = _text(entry.get("errorMsg"), "")
                    out.append(f"{host}: {error}" if host else error)
                else:
                    out.append(str(entry))
            return [line for line in out if line]
    return [text]


def device_error_hints(errors: list[str]) -> list[str]:
    """The agent-actionable hints for the verified device-write ``errorMsg`` texts."""
    lowered = " ".join(errors).lower()
    return [hint for marker, hint in ZTP_DEVICE_HINTS if marker in lowered]


def check_ztp_write(
    data: Any, what: str, ok_codes: tuple[int, ...] = ZTP_WRITE_OK
) -> dict[str, Any]:
    """The ZTP HTTP-200-with-code rule for a write: raise PlatformError unless ``code`` is
    one of ``ok_codes`` (verified verdicts: 201 create / route add / route delete, 200
    update / profile or device delete, 204 serial delete); the error text carries every
    per-device line of a JSON-list ``message`` (the device writes' form) plus the hints
    for the known device rules — a plain-text message (profiles, serials, routes) is
    reported verbatim, without those hints."""
    if not isinstance(data, dict):
        raise PlatformError(
            f"{what}: the ZTP service returned an unexpected response shape: {str(data)[:300]}"
        )
    code = as_int(data.get("code"))
    if code is None or code in ok_codes:
        return data
    message = ztp_message(data)
    errors = parse_ztp_error_list(message) or ["no message"]
    text = f"{what} failed (ZTP answered code {code}): " + "; ".join(errors)
    hints = device_error_hints(errors) if message.startswith("[") else []
    if hints:
        # Several errorMsg texts end in "." already ("Credential Profile not found.").
        text = text.rstrip(".") + ". " + ". ".join(hints) + "."
    raise PlatformError(text)


def device_not_deleted(data: dict[str, Any]) -> str | None:
    """The ``message`` of a ``DELETE devices`` answer that deleted nothing — verified: an
    unknown uuid is STILL code 200, with "1) Device with UUID : <uuid> does not exist."
    (a null uuid: "1) UUID is missing.") — else None."""
    message = ztp_message(data)
    lowered = message.lower()
    if any(marker in lowered for marker in DEVICE_NOT_DELETED_MARKERS):
        return message
    return None


def profile_body(
    *,
    name: str,
    config_id: str,
    platform: str,
    device_family: str,
    version: str,
    description: str = "",
    category: str = DEFAULT_PROFILE_CATEGORY,
    vendor: str = DEFAULT_VENDOR,
    image_id: str = "",
    secure_ztp: bool = False,
    pre_config_id: str = "",
    post_config_id: str = "",
    profile_id: str | None = None,
) -> dict[str, Any]:
    """The verified ``POST profiles`` entry / ``PUT profiles`` body (the 7.2 document's
    example form): every key present, blanks as ``""``; ``profileId`` only on a PUT."""
    body: dict[str, Any] = {
        "profileName": name.strip(),
        "profileDescription": description.strip(),
        "profileCategory": category.strip(),
        "vendor": vendor.strip(),
        "osPlatform": platform.strip(),
        "deviceFamily": device_family.strip(),
        "version": version.strip(),
        "image": image_id.strip(),
        "isSecureZtp": ztp_bool(secure_ztp),
        "preConfig": pre_config_id.strip(),
        "postConfig": post_config_id.strip(),
        "config": config_id.strip(),
    }
    if profile_id is not None:
        body = {"profileId": profile_id.strip(), **body}
    return body


def profile_update_body(current: dict[str, Any], changes: dict[str, str | bool | None]) -> dict:
    """The PUT body for an existing profile: the create form rebuilt from the QUERY record
    (never echoed back as-is — its string ``lastUpdated`` is a code-422 unmarshal error
    and the ``configName`` / ``is*Invalid`` fields are derived) with the non-None
    ``changes`` applied. ``profileName`` is always the current one: ZTP looks the profile
    up by name and a new name answers code 404 (verified — no rename)."""

    def pick(key: str, current_key: str) -> str:
        value = changes.get(key)
        if value is None:
            return _text(current.get(current_key), "")
        return str(value)

    secure = changes.get("secure_ztp")
    if secure is None:
        secure = str(current.get("isSecureZtp")).lower() == ZTP_TRUE
    return profile_body(
        profile_id=_text(current.get("profileId"), ""),
        name=_text(current.get("profileName"), ""),
        config_id=pick("config_id", "config"),
        platform=pick("platform", "osPlatform"),
        device_family=pick("device_family", "deviceFamily"),
        version=pick("version", "version"),
        description=pick("description", "profileDescription"),
        category=pick("category", "profileCategory"),
        vendor=pick("vendor", "vendor"),
        image_id=pick("image_id", "image"),
        secure_ztp=bool(secure),
        pre_config_id=pick("pre_config_id", "preConfig"),
        post_config_id=pick("post_config_id", "postConfig"),
    )


def device_body(
    *,
    host_name: str,
    serial_number: str,
    credential_profile: str,
    platform: str,
    profile_name: str = "",
    config_id: str = "",
    version: str = "",
    device_family: str = "",
    secure_ztp: bool = False,
    uuid: str | None = None,
) -> dict[str, Any]:
    """The verified ``POST devices`` node / ``PUT devices`` body.

    Two forms, exclusive (verified): the PROFILE form names ``profileName``
    and nothing else of the metadata (ZTP copies version / family / config
    from the profile; "Cannot specify the 'Version' along with profile."),
    the METADATA form carries ``config`` + ``version`` + ``deviceFamily``.
    ``osPlatform`` is required in both ("OS Platform is required."),
    ``status`` must be ``Unprovisioned``, one serial only, ``enableOption82``
    false (the Option-82 remote-id / circuit-id form is not exposed).
    ``uuid`` only on a PUT.
    """
    body: dict[str, Any] = {
        "hostName": host_name.strip(),
        "serialNumber": [serial_number.strip()],
        "credentialProfile": credential_profile.strip(),
        "osPlatform": platform.strip(),
        "status": ZTP_UNPROVISIONED,
        "isSecureZtp": ztp_bool(secure_ztp),
        "enableOption82": ZTP_FALSE,
    }
    if profile_name.strip():
        body["profileName"] = profile_name.strip()
    else:
        body["config"] = config_id.strip()
        body["version"] = version.strip()
        body["deviceFamily"] = device_family.strip()
    if uuid is not None:
        body = {"uuid": uuid.strip(), **body}
    return body


def validate_device_form(
    profile_name: str, config_id: str, version: str, device_family: str
) -> None:
    """PlatformError (before any call) unless exactly one form is complete: a profile
    name alone, or config id + version + device family without one."""
    metadata = [config_id.strip(), version.strip(), device_family.strip()]
    if profile_name.strip():
        if any(metadata):
            raise PlatformError(
                "pass either profile_name alone or config_id + version + device_family: ZTP "
                "refuses a profile together with metadata ('Cannot specify profile along with "
                "metadata (image, config, family, platform, version, pre-config, "
                "post-config)') — a device that names a profile takes those from it."
            )
        return
    if not all(metadata):
        raise PlatformError(
            "pass either profile_name (cnc_list_ztp_profiles) or all three of config_id "
            "(cnc_list_ztp_config_files), version and device_family — the version and family "
            "must match the config file's."
        )


def device_update_body(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """The PUT body for an existing device: the create form rebuilt from the QUERY record
    (never echoed back — its string ``lastUpdated`` and the profile-derived version /
    family / config are refused by ZTP) with the non-None ``changes`` applied.

    ``profile_name`` None keeps the device's form; ``""`` switches it to the
    metadata form (config / version / family from the changes, else from the
    record — the record carries the profile's copies); a name switches it to
    the profile form.
    """

    def pick(key: str, current_key: str) -> str:
        value = changes.get(key)
        if value is None:
            return _text(current.get(current_key), "")
        return str(value)

    serials = current.get("serialNumber")
    current_serial = str(serials[0]) if isinstance(serials, list) and serials else ""
    profile_change = changes.get("profile_name")
    profile = _text(current.get("profileName"), "") if profile_change is None else profile_change
    secure = changes.get("secure_ztp")
    if secure is None:
        secure = str(current.get("isSecureZtp")).lower() == ZTP_TRUE
    return device_body(
        uuid=_text(current.get("uuid"), ""),
        host_name=pick("host_name", "hostName"),
        serial_number=changes.get("serial_number") or current_serial,
        credential_profile=pick("credential_profile", "credentialProfile"),
        platform=pick("platform", "osPlatform"),
        profile_name=str(profile),
        config_id=pick("config_id", "config"),
        version=pick("version", "version"),
        device_family=pick("device_family", "deviceFamily"),
        secure_ztp=bool(secure),
    )


def config_upload_params(
    *,
    name: str,
    platform: str,
    version: str,
    device_family: str,
    vendor: str = DEFAULT_VENDOR,
    config_type: str = DEFAULT_CONFIG_TYPE,
) -> dict[str, str]:
    """The verified query-string metadata of ``POST configs/upload``."""
    return {
        "confname": name.strip(),
        "osname": platform.strip(),
        "version": version.strip(),
        "devicefamily": device_family.strip(),
        "vendor": vendor.strip(),
        "type": config_type.strip(),
    }


def config_update_params(**values: str) -> dict[str, str]:
    """The ``PUT configs/<confId>`` metadata: only the non-blank values (the rest is kept)."""
    names = {
        "name": "confname",
        "platform": "osname",
        "version": "version",
        "device_family": "devicefamily",
        "vendor": "vendor",
        "config_type": "type",
    }
    return {names[k]: v.strip() for k, v in values.items() if k in names and v and v.strip()}


def config_file_part(file_name: str, content: str) -> dict[str, tuple[str, bytes, str]]:
    """The one multipart part of the configsvc upload / update (verified: ``configFile``,
    text/plain)."""
    return {CONFIG_FILE_PART: (file_name, content.encode("utf-8"), CONFIG_FILE_MEDIA_TYPE)}


def default_config_file_name(name: str) -> str:
    """``<name>.txt`` with anything but letters, digits, dot, underscore and dash replaced
    by a dash — the stored ``fileName``, whose extension the platform's content checks key
    on (``.txt`` day-0 files must carry the ``!! IOS XR`` banner)."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip()).strip("-.") or "config"
    return f"{cleaned}.txt"


def canonical_config_type(value: str) -> str:
    """Case-insensitive match against ``CONFIG_TYPES`` -> the wire spelling; PlatformError
    otherwise (the platform answers 400 "Type X is not supported." — refused earlier)."""
    wanted = value.strip().lower()
    for known in CONFIG_TYPES:
        if known.lower() == wanted:
            return known
    raise PlatformError(
        f"config_type must be one of {', '.join(CONFIG_TYPES)} (got '{value}'); "
        "cnc_list_ztp_config_files lists the types the service accepts."
    )


def route_settled(route: dict[str, Any] | None) -> bool:
    """A static route is settled when it is absent or its ``status`` no longer says
    ``inprogress`` (``add-inprogress`` / ``delete-inprogress`` — verified)."""
    if route is None:
        return True
    return ROUTE_IN_PROGRESS not in _text(route.get("status"), "").lower()


def route_installed(route: dict[str, Any] | None) -> bool:
    """A settled static route whose ``status`` is the verified terminal ``success``; any
    other settled status (the installer's failure spellings are unverified) is a route
    the platform did NOT install."""
    return route is not None and _text(route.get("status"), "").lower() == ROUTE_SUCCESS


def find_route(routes: list[dict[str, Any]], subnet: str, mask: str) -> dict[str, Any] | None:
    for route in routes:
        if _text(route.get("subnet"), "") == subnet and _text(route.get("mask"), "") == mask:
            return route
    return None


def find_route_by_uuid(routes: list[dict[str, Any]], uuid: str) -> dict[str, Any] | None:
    for route in routes:
        if _text(route.get("uuid"), "") == uuid:
            return route
    return None


def validate_ipv4_subnet(subnet: str, prefix_length: int) -> str:
    """The stripped dotted-quad ``subnet`` when it is a valid IPv4 network address for
    ``prefix_length``; PlatformError otherwise (ZTP's own answer to a bad subnet is
    unverified — the check is made here)."""
    text = subnet.strip()
    try:
        network = ipaddress.IPv4Network(f"{text}/{prefix_length}", strict=True)
    except ValueError as e:
        raise PlatformError(
            f"subnet '{text}' with prefix_length {prefix_length} is not a valid IPv4 network "
            f"address ({e}); pass the network address, e.g. subnet='10.3.2.0', "
            "prefix_length=24."
        ) from None
    return str(network.network_address)


def serial_in_use(entry: dict[str, Any]) -> bool:
    return str(entry.get("isInUse")).lower() == ZTP_TRUE


def serial_counts(data: dict[str, Any]) -> tuple[int, int]:
    """``(processedRecordCount, duplicateRecordCount)`` of a serial add — a key is ABSENT
    when its count is 0 (verified), so absent reads as 0."""
    return as_int(data.get("processedRecordCount")) or 0, as_int(
        data.get("duplicateRecordCount")
    ) or 0


def references_of(
    profiles: list[dict[str, Any]], devices: list[dict[str, Any]], config_id: str
) -> tuple[list[str], list[str]]:
    """The profiles referencing ``config_id`` through ANY of ``config`` (day-0),
    ``preConfig`` or ``postConfig`` — as "<name>" for the day-0 file and "<name> (as
    preConfig)" / "(as postConfig)" for the scripts — and the host names of the devices
    whose ``config`` is ``config_id`` (a device record carries no pre/post fields —
    7.2 schema). Re-checked client-side whatever the server filters did; a profile is
    listed once per referencing field, duplicates across the queries dropped."""
    names: list[str] = []
    for profile in profiles:
        label = _text(profile.get("profileName"), _text(profile.get("profileId")))
        for field in PROFILE_CONFIG_FIELDS:
            if _text(profile.get(field), "") != config_id:
                continue
            entry = label if field == "config" else f"{label} (as {field})"
            if entry not in names:
                names.append(entry)
    hosts: list[str] = []
    for device in devices:
        if _text(device.get("config"), "") != config_id:
            continue
        host = _text(device.get("hostName"), _text(device.get("uuid")))
        if host not in hosts:
            hosts.append(host)
    return names, hosts


def devices_using_profile(devices: list[dict[str, Any]], name: str) -> list[str]:
    return [
        _text(d.get("hostName"), _text(d.get("uuid")))
        for d in devices
        if _text(d.get("profileName"), "") == name
    ]


# --- registration ---------------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def ztp_query(url: str, body: dict[str, Any], what: str) -> dict[str, Any]:
        """POST one ZTP query (a read: ``retryable=True``) and apply the code rule."""
        data = await client.request_json("POST", url, json_body=body, retryable=True)
        return check_ztp(data, what)

    async def get_json(url: str, params: dict[str, Any] | None = None) -> Any:
        return await client.request_json("GET", url, params=params)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_swim_preferences",
        title="Get SWIM Preferences",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_swim_preferences(
        key: Annotated[
            str,
            Field(
                description=(
                    "One preference key to read (e.g. 'ContinueDistributionOnFailure', "
                    "'copyByServer', 'TFTPBootLocation'); blank for every preference."
                ),
                max_length=200,
            ),
        ] = "",
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the SWIM (software image management) preferences — the knobs that govern
        image import, distribution and activation.

        Read-only. Blank ``key``: ``GET /crosswork/api/v1/op/swim/image/
        getSwimPreference`` (verified) -> ``{"items": [{"key", "value"}]}``
        — e.g. ``ContinueDistributionOnFailure`` Y, ``inventoryCollectionTimeOut``
        1800000 (ms), ``InsertBootCommand`` N, ``copyByServer`` Y,
        ``ConfigProtocolOrder`` "TELNET,SSH", ``TFTPBootLocation`` /tftpboot,
        ``DistributeParallelly``, ``SmartFlashDeleteBeforeDistribution``,
        ``UseSSHForImageUpgradeAndImport``, ``RecommendLatestMR`` ... (Y/N
        flags and a few numbers/paths, all strings on the wire). With a
        ``key``: ``GET getSwimPreference/<key>`` (verified) -> the bare value
        text (``Y``). What an unknown key answers is unverified; an empty
        value is reported as such, not as an error. Use it to explain how a
        distribution/activation job will behave (parallel or serial, whether
        a failure stops the rest, the transfer protocol order) before
        someone starts one in the UI. Changing preferences
        (``PUT updateSwimPreference``) is not exposed.

        Args:
            key: one preference key, or blank for all.
            response_format: markdown or json.

        Returns:
            str: Markdown "# SWIM preferences (N)" with one "- key: value"
            line each, or JSON {"count": int, "items": [{"key", "value"}],
            "preferences": {key: value}}; with ``key``: "- <key>: <value>"
            or JSON {"key", "value"}. "SWIM preference '<key>' has no value
            ..." when the platform answered an empty body. "Error: ..." on
            an API failure (a 404 with the home-app fallback means SWIM is
            not routed on this instance).
        """
        try:
            wanted = key.strip()
            if wanted:
                response = await client.request(
                    "GET", f"{SWIM_PREFERENCES_URL}/{quote(wanted, safe='')}"
                )
                value = preference_value_of(response)
                if response_format is ResponseFormat.JSON:
                    return finalize(to_json({"key": wanted, "value": value}), settings)
                if not value:
                    return finalize(
                        f"SWIM preference '{wanted}' has no value (or the key is unknown — the "
                        "answer for an unknown key is unverified; call without a key to list "
                        "the keys SWIM knows).",
                        settings,
                    )
                return finalize(f"- {wanted}: {value}", settings)
            data = await get_json(SWIM_PREFERENCES_URL)
            items = preferences_of(data)
            if response_format is ResponseFormat.JSON:
                payload = {
                    "count": len(items),
                    "items": items,
                    "preferences": {i["key"]: i["value"] for i in items},
                }
                return finalize(to_json(payload), settings)
            if not items:
                return finalize("SWIM reported no preferences (an empty 'items' list).", settings)
            lines = [f"# SWIM preferences ({len(items)})", ""]
            lines.extend(f"- {i['key']}: {_text(i.get('value'), '-')}" for i in items)
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_software_images",
        title="List Software Images",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_software_images(
        image_type: Annotated[
            str,
            Field(
                description=(
                    "Image type to list (the path segment of getImagesForRepository/<imageType>, "
                    "e.g. 'SYSTEM_SW'); blank for every image in the repository."
                ),
                max_length=100,
            ),
        ] = "",
        page_size: Annotated[
            int, Field(description="Images per page (the Range window, e.g. 50).", ge=1, le=500)
        ] = DEFAULT_PAGE_SIZE,
        page: Annotated[
            int, Field(description="1-based page number (e.g. 1 for the first page).", ge=1)
        ] = 1,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the images in the SWIM software image repository — what could be
        distributed to devices.

        Read-only. ``GET /crosswork/api/v1/op/swim/image/getImagesForRepository``
        (or ``.../getImagesForRepository/<imageType>``) with a ``Range:
        items=<start>-<end>`` header (page 1 of 50 sends ``items=0-49``;
        accepted live, but an empty answer cannot show whether the window
        is honoured) -> HTTP **206** with ``Content-Range: items=<a>-<b>/
        <total>`` and ``{"softwareImageListDTO": {"id": "imageId",
        "totalCount": N, "items": [...]}}``. The lab repository is empty
        (verified: ``Content-Range: items=0-0/0``, ``totalCount`` 0 and no
        ``items`` key) — reported as the non-error "The SWIM image
        repository is empty."; the item shape follows the 7.2 document
        (unverified): ``imageId`` (the numeric id the SWIM writes use),
        ``imageName``, ``imageType`` (``SYSTEM_SW`` ...), ``imagePlatform``
        (``IOS XE`` / ``IOS XR``), ``family``, ``version``, ``filesize``,
        ``vendor``, ``imageLocation``, ``imageCheckSum``, ``uploadedBy``,
        ``updatedOn`` (epoch ms), ``upgradeNeeded``. An image that is only a
        Cisco.com catalog record (``imported=false`` in the UI) is not
        usable for distribution. Importing, distributing, activating and
        deleting images is NOT exposed (unverified, and they change device
        software) — use the Crosswork UI. The SWIM repository is distinct
        from the ZTP image files (cnc_list_ztp_images).

        Args:
            image_type: the imageType path filter, blank for all.
            page_size / page: the Range window (1-based page).
            response_format: markdown or json.

        Returns:
            str: Markdown "# SWIM image repository (N of T)" with one
            "- **name** (id): type, platform family vversion, size, by user,
            updated <ISO>" line per image and a "(more on server ...)" note,
            or JSON {"image_type", "total", "count", "offset", "items":
            [<image view>], "has_more", "next_offset", "page", "page_size",
            "next_page", "content_range": "<header>"}. "The SWIM image
            repository is empty." (with the type when one was given) when
            totalCount is 0. "Error: ..." on an API failure.
        """
        try:
            wanted = image_type.strip()
            url = SWIM_IMAGES_URL
            if wanted:
                url = f"{SWIM_IMAGES_URL}/{quote(wanted, safe='')}"
            # 206 Partial Content is a 2xx: the client accepts it without ok_statuses.
            response = await client.request("GET", url, headers=range_header(page, page_size))
            try:
                data = response.json() if response.content else None
            except ValueError:
                raise PlatformError(
                    "SWIM returned a non-JSON body for getImagesForRepository."
                ) from None
            listing = image_list_of(data)
            images = dict_list(listing.get("items"))
            content_range = response.headers.get("Content-Range")
            parsed = parse_content_range(content_range)
            total = as_int(listing.get("totalCount"))
            if total is None and parsed is not None:
                total = parsed[2]
            views = [image_view(i) for i in images]
            env = page_envelope(views, total=total, page=page, page_size=page_size, first_page=1)
            if response_format is ResponseFormat.JSON:
                payload = {"image_type": wanted or None, **env, "content_range": content_range}
                return finalize(to_json(payload), settings)
            if not views:
                if total:
                    return finalize(
                        f"No images on page {page} (the repository holds {total}; page 1 is "
                        "the first).",
                        settings,
                    )
                scope = f" holds no '{wanted}' images" if wanted else " is empty"
                return finalize(
                    f"The SWIM image repository{scope}. Import images in the Crosswork UI "
                    "(Administration > Software Image Management); the ZTP image files are "
                    "a separate store (cnc_list_ztp_images).",
                    settings,
                )
            heading = f"# SWIM image repository ({len(views)}"
            heading += f" of {total}" if total is not None else ""
            heading += f", type {wanted})" if wanted else ")"
            lines = [heading, ""]
            lines.extend(image_line(v) for v in views)
            lines.extend(more_note(env, "cnc_list_software_images"))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_device_running_images",
        title="Get Device Running Images",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_device_running_images(
        device_id: Annotated[
            str,
            Field(
                description=(
                    "The device's INVENTORY uuid (e.g. 'af1986fa-2b3c-4d5e-8f90-1234567890ab', "
                    "as cnc_get_device / cnc_list_devices show it) — SWIM maps it to its EMF "
                    "instance id itself (verified). The numeric EMF instance id (e.g. '454455') "
                    "is accepted too. NOT a host name (refused before the call: SWIM answers "
                    "'For input string: \"PE1\"')."
                ),
                min_length=1,
                max_length=100,
            ),
        ],
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the software images SWIM sees running / installed on one device.

        Read-only. ``GET /crosswork/api/v1/op/swim/image/getDeviceRunningImages/
        <device_id>`` -> HTTP 200 ``{"runningSoftwareImageDTOList": {"id",
        "totalCount", "resultErrMsg", "items": [...]}}``. **Device id
        (verified live 2026-09-14)**: pass the device's INVENTORY uuid —
        SWIM translates it to the EMF ``nd.instanceId`` itself and the
        answer's ``id`` is that numeric id (reported as ``emf_instance_id``;
        the numeric id is accepted directly too). The uuid is sent verbatim
        (strip only); anything that is neither a uuid nor digits — a host
        name — is refused BEFORE the call, because SWIM answers it with
        ``resultErrMsg`` "For input string: \\"PE1\\"" (Java's number-parse
        failure) inside HTTP 200. ``resultErrMsg`` "Get running Image Failed
        for the Device : Invalid Index" means SWIM holds NO software-image
        inventory for that device — the platform is not SWIM-certified
        (the lab's containerised XRd is ``DEVICE_SUPPORT_LEVEL_UNCERTIFIED``
        and SWIM's XR image collector has nothing to parse there) or its
        image inventory was never collected — a platform limitation, NOT a
        wrong id: reported as "Error: SWIM holds no software-image
        inventory for device <id> ...". ``Success`` with no items is the
        non-error "No running image". The item shape follows the 7.2
        document (unverified — no SWIM-certified device was available):
        ``deviceName``, ``imageName`` / ``imageFileName``, ``version``,
        ``imageType``, ``imageFamily``, ``features``, ``size``,
        ``installableStatus`` (ACTIVE / INACTIVE / COMMITTED ...),
        ``installedLocation`` (disk0 ...), ``inRepository``. For the
        software version Crosswork's inventory reports use cnc_get_device
        instead — it works for every device, certified or not.

        Args:
            device_id: the device's inventory uuid (or its numeric EMF instance id).
            response_format: markdown or json.

        Returns:
            str: Markdown "# Running images of <deviceName> (device <id> =
            EMF instance id <n>): N" with one "- **image** vversion: status
            on location, type family, file ..." line each, or JSON
            {"device_id" (as given), "emf_instance_id" (the answer's id),
            "device_name", "count", "total", "items": [<running image
            view>]}. "No running image reported for device <id> ..." when
            the list is empty. "Error: SWIM holds no software-image
            inventory for device <id> (SWIM answered: <resultErrMsg>) — the
            device's platform is not SWIM-certified ... or its image
            inventory was never collected; the inventory uuid is the right
            id (SWIM maps it to EMF instance id <n>)." for Invalid Index;
            "Error: device_id '<text>' is neither an inventory uuid nor a
            numeric EMF instance id ..." for a host name (no call made);
            "Error: ..." on an API failure.
        """
        try:
            wanted = validate_swim_device_id(device_id)
            data = await get_json(f"{SWIM_RUNNING_IMAGES_URL}/{quote(wanted, safe='')}")
            listing = running_list_of(data)
            emf_id = listing.get("id")
            message = listing.get("resultErrMsg")
            if isinstance(message, str) and message.strip():
                if message.strip().lower() != SWIM_SUCCESS.lower():
                    raise swim_running_error(wanted, message.strip(), emf_id)
            images = dict_list(listing.get("items"))
            views = [running_image_view(i) for i in images]
            device_name = next((v["deviceName"] for v in views if v.get("deviceName")), None)
            if response_format is ResponseFormat.JSON:
                payload = {
                    "device_id": wanted,
                    "emf_instance_id": _text(emf_id, "") or None,
                    "device_name": device_name,
                    "count": len(views),
                    "total": as_int(listing.get("totalCount")),
                    "items": views,
                }
                return finalize(to_json(payload), settings)
            mapped = _text(emf_id, "")
            label = f"device {wanted}"
            if mapped and mapped != wanted:
                label += f" = EMF instance id {mapped}"
            if not views:
                return finalize(
                    f"No running image reported for {label} (SWIM answered "
                    f"{_text(message, 'no resultErrMsg')} with an empty list).",
                    settings,
                )
            lines = [
                f"# Running images of {device_name or '?'} ({label}): {len(views)}",
                "",
            ]
            lines.extend(running_image_line(v) for v in views)
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_swim_job",
        title="Get SWIM Job",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_swim_job(
        job_id: Annotated[
            int,
            Field(
                description=(
                    "SWIM job specification id (jobSpecId, e.g. 627636) — the id the SWIM "
                    "dashboard shows for an import / distribution / commit job."
                ),
                ge=1,
            ),
        ],
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get a SWIM dashboard job — an image import, distribution/activation or
        commit job — with its work and result state.

        Read-only. ``GET /crosswork/api/v1/op/swim/image/jobAllDetailsById/
        <job_id>`` (verified) -> ``{"swimDashboardJobDetailsListDTO":
        {"identifier": "jobId", "count", "totalCount", "items": [...]}}``.
        An unknown id answers ``totalCount`` 0 with no items (verified) —
        the non-error "No SWIM job <id>." The item shape follows the 7.2
        document (unverified): ``jobId``, ``jobName``, ``jobType``
        (``Software Image Import`` | ``Software Image Distribution`` |
        ``Commit_Operations``), ``jobDescription``, ``workState``
        (``Completed`` ...), ``resultState`` (``Success`` | ``Failure``
        ...), ``deviceCount``, ``actualStartTime`` / ``completionTime``
        (epoch ms strings), ``jobSpecificationId``, ``taskId``. Not called
        on purpose: ``jobResultDetailsById/<id>`` (a 500 NullPointer text
        for an unknown job) and ``isJobRunning/<id>`` (406 — it wants a
        non-JSON Accept); the per-device result lines of a job are therefore
        not available here — read them in the SWIM dashboard.

        Args:
            job_id: the SWIM job specification id.
            response_format: markdown or json.

        Returns:
            str: Markdown "# SWIM job <id> (N)" with one "- **name** (job,
            spec, task): type — workState / resultState, N device(s),
            started <ISO>, completed <ISO> — description" line each, or
            JSON {"job_id", "count", "total", "identifier", "items":
            [<job view>]}. "No SWIM job <id>." when totalCount is 0.
            "Error: ..." on an API failure.
        """
        try:
            data = await get_json(f"{SWIM_JOB_URL}/{job_id}")
            listing = job_list_of(data)
            views = [job_view(j) for j in dict_list(listing.get("items"))]
            total = as_int(listing.get("totalCount"))
            if response_format is ResponseFormat.JSON:
                payload = {
                    "job_id": job_id,
                    "count": len(views),
                    "total": total,
                    "identifier": listing.get("identifier"),
                    "items": views,
                }
                return finalize(to_json(payload), settings)
            if not views:
                reported = total if total is not None else "?"
                return finalize(
                    f"No SWIM job {job_id}. SWIM answered totalCount {reported} for that job "
                    "specification id (the SWIM dashboard lists the ids).",
                    settings,
                )
            lines = [f"# SWIM job {job_id} ({len(views)})", ""]
            lines.extend(job_line(v) for v in views)
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_ztp_profiles",
        title="List ZTP Profiles",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_ztp_profiles(
        os_platform: Annotated[
            str,
            Field(
                description="OS platform filter (filter.osPlatform, e.g. 'IOS XR'); blank for all.",
                max_length=100,
            ),
        ] = "",
        page_size: Annotated[
            int, Field(description=_ZTP_PAGE_SIZE_DESC, ge=1, le=MAX_PAGE_SIZE)
        ] = DEFAULT_PAGE_SIZE,
        page: Annotated[int, Field(description=_ZTP_PAGE_DESC, ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the ZTP profiles — the platform/family/version bundles of a day-0
        configuration file and an image that ZTP devices are onboarded with.

        Read-only. ``POST /crosswork/ztp/v1/profiles/query`` with
        ``{"filter": {"osPlatform": ...}, "filterData": {"PageSize": N,
        "PageNum": p}}`` (verified; ``filter`` is always sent — an absent one
        answers code 400 "filter not provided"). Answers HTTP 200 always;
        the verdict is the body's ``code`` (any value but 200 is an Error
        with the message) and a match list ``ztpProfiles[]`` that is simply
        ABSENT when nothing matches (verified on the empty lab — the
        non-error "No ZTP profiles."). Profile fields (7.2 document,
        unverified): ``profileId`` (uuid), ``profileName``, ``osPlatform``
        (``IOS XR`` / ``IOS XE``), ``deviceFamily``, ``version``,
        ``config`` / ``configName`` (the day-0 file — cnc_list_ztp_config_files),
        ``image`` / ``imageName`` (cnc_list_ztp_images), ``preConfigName`` /
        ``postConfigName`` (secure ZTP), ``isSecureZtp`` ("true"/"false"
        strings), ``profileCategory``, ``isConfigInvalid`` /
        ``isImageInvalid`` (the profile is out of sync with its files),
        ``lastUpdated`` (epoch ms string). ``paginationDetails.TotalCount``
        is the match count when the platform reports it. Devices using a
        profile: cnc_list_ztp_devices. Writes: cnc_create_ztp_profile,
        cnc_update_ztp_profile, cnc_delete_ztp_profile.

        Args:
            os_platform: filter.osPlatform, blank for all.
            page_size / page: filterData paging (0-based page).
            response_format: markdown or json.

        Returns:
            str: Markdown "# ZTP profiles (N[ of T])" with one "- **name**
            (id): platform family vversion, config ..., category ...,
            updated <ISO> (image ...; secure ZTP; OUT OF SYNC ...)" line
            each and a "(more on server ...)" note, or JSON {"os_platform",
            "total", "count", "offset", "items": [<profile view>],
            "has_more", "next_offset", "page", "page_size", "next_page",
            "code", "message"}. "No ZTP profiles." when the list is absent
            ("No ZTP profiles on page P (ZTP reports T matching; page 0 is
            the first)." when TotalCount says there are matches — a page
            past the end, unverified).
            "Error: ZTP profile query failed (ZTP answered code N): <msg>"
            for a non-200 code; "Error: ..." on an API failure.
        """
        try:
            body = ztp_query_body({"osPlatform": os_platform.strip()}, page_size, page)
            data = await ztp_query(ZTP_PROFILES_QUERY_URL, body, "ZTP profile query")
            views = [profile_view(p) for p in dict_list(data.get("ztpProfiles"))]
            env = page_envelope(
                views, total=ztp_total(data), page=page, page_size=page_size, first_page=0
            )
            if response_format is ResponseFormat.JSON:
                payload = {
                    "os_platform": os_platform.strip() or None,
                    **env,
                    "code": ztp_code(data),
                    "message": data.get("message"),
                }
                return finalize(to_json(payload), settings)
            if not views:
                scope = f" for OS platform '{os_platform.strip()}'" if os_platform.strip() else ""
                past = ztp_past_the_end("ZTP profiles", scope, env["total"], page)
                if past:
                    return finalize(past, settings)
                return finalize(
                    f"No ZTP profiles{scope}. Profiles are created with cnc_create_ztp_profile "
                    "(or in the Crosswork UI, Device Management > Zero Touch Profiles) from a "
                    "day-0 configuration file (cnc_list_ztp_config_files / "
                    "cnc_upload_ztp_config_file) and optionally an image (cnc_list_ztp_images).",
                    settings,
                )
            heading = f"# ZTP profiles ({len(views)}"
            heading += f" of {env['total']})" if env["total"] is not None else ")"
            lines = [heading, ""]
            lines.extend(profile_line(v) for v in views)
            lines.extend(more_note(env, "cnc_list_ztp_profiles"))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_ztp_devices",
        title="List ZTP Devices",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_ztp_devices(
        status: Annotated[
            str,
            Field(
                description=(
                    "Onboarding status filter (filter.status): Unprovisioned, InProgress, "
                    "Provisioned, ProvisioningError, ZtpError, Onboarded, OnboardingError; the "
                    "document's example uses a trailing '*' wildcard ('Unprovisioned*'). Blank "
                    "for all."
                ),
                max_length=100,
            ),
        ] = "",
        host_name: Annotated[
            str,
            Field(
                description="Host name filter (filter.hostName, e.g. 'PE1'); blank for all.",
                max_length=253,
            ),
        ] = "",
        page_size: Annotated[
            int, Field(description=_ZTP_PAGE_SIZE_DESC, ge=1, le=MAX_PAGE_SIZE)
        ] = DEFAULT_PAGE_SIZE,
        page: Annotated[int, Field(description=_ZTP_PAGE_DESC, ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the ZTP devices — the nodes registered for zero-touch onboarding, with
        their serial numbers, profile and onboarding status.

        Read-only. ``POST /crosswork/ztp/v1/devices/query`` with ``{"filter":
        {"status": ..., "hostName": ...}, "filterData": {"PageSize", "PageNum"}}``
        (verified; ``filter`` always sent). HTTP 200 always — the body's
        ``code`` is the verdict and ``ztpnodes[]`` is ABSENT when nothing
        matches (verified on the empty lab — "No ZTP devices."). Device
        fields (7.2 document, unverified): ``uuid``, ``hostName``,
        ``serialNumber[]``, ``credentialProfile``, ``osPlatform``,
        ``version``, ``deviceFamily``, ``profileName`` / ``config`` /
        ``configName`` / ``imageName``, ``status`` (Unprovisioned →
        InProgress → Provisioned → Onboarded, or ProvisioningError /
        ZtpError / OnboardingError) with ``message`` (the onboarding status
        text), ``ipAddress`` {ipaddrs, mask, inetAddressFamily},
        ``macAddress``, ``inventoryId`` (the inventory record once
        onboarded), ``providerInfo.providerName``, ``isSecureZtp``,
        ``enableOption82``, ``lastUpdated`` (epoch ms string). A device that
        finished onboarding also appears in cnc_list_devices. Writes:
        cnc_create_ztp_device, cnc_update_ztp_device, cnc_delete_ztp_device.

        Args:
            status / host_name: filter values (blank = all).
            page_size / page: filterData paging (0-based page).
            response_format: markdown or json.

        Returns:
            str: Markdown "# ZTP devices (N[ of T])" with one "- **host**
            (uuid): status, serial ..., platform family vversion, profile
            ..., credentials ..., ip ..., updated <ISO> — message" line
            each and a "(more on server ...)" note, or JSON {"status",
            "host_name", "total", "count", "offset", "items": [<device
            view>], "has_more", "next_offset", "page", "page_size",
            "next_page", "code", "message"}. "No ZTP devices." when the
            list is absent ("No ZTP devices on page P (ZTP reports T
            matching; page 0 is the first)." when TotalCount says there are
            matches — a page past the end, unverified). "Error: ZTP device
            query failed (ZTP answered code N): <msg>" for a non-200 code;
            "Error: ..." on an API failure.
        """
        try:
            filters = {"status": status.strip(), "hostName": host_name.strip()}
            body = ztp_query_body(filters, page_size, page)
            data = await ztp_query(ZTP_DEVICES_QUERY_URL, body, "ZTP device query")
            views = [device_view(n) for n in dict_list(data.get("ztpnodes"))]
            env = page_envelope(
                views, total=ztp_total(data), page=page, page_size=page_size, first_page=0
            )
            if response_format is ResponseFormat.JSON:
                payload = {
                    "status": status.strip() or None,
                    "host_name": host_name.strip() or None,
                    **env,
                    "code": ztp_code(data),
                    "message": data.get("message"),
                }
                return finalize(to_json(payload), settings)
            if not views:
                applied = ", ".join(f"{k} '{v}'" for k, v in body["filter"].items())
                scope = f" matching {applied}" if applied else ""
                past = ztp_past_the_end("ZTP devices", scope, env["total"], page)
                if past:
                    return finalize(past, settings)
                return finalize(
                    f"No ZTP devices{scope}. Devices are registered for ZTP with "
                    "cnc_create_ztp_device (or in the Crosswork UI, Device Management > Zero "
                    "Touch Devices, or by CSV import); onboarded devices are listed by "
                    "cnc_list_devices.",
                    settings,
                )
            heading = f"# ZTP devices ({len(views)}"
            heading += f" of {env['total']})" if env["total"] is not None else ")"
            lines = [heading, ""]
            lines.extend(device_line(v) for v in views)
            lines.extend(more_note(env, "cnc_list_ztp_devices"))
            lines.extend(
                [
                    "",
                    "Statuses: " + ", ".join(ZTP_DEVICE_STATUSES) + ".",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_ztp_serial_numbers",
        title="List ZTP Serial Numbers",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_ztp_serial_numbers(
        in_use: Annotated[
            str,
            Field(
                description=(
                    "'true' for serials already bound to a ZTP device, 'false' for free ones "
                    "(filter.isInUse — a string on the wire); blank for all."
                ),
                max_length=5,
            ),
        ] = "",
        page_size: Annotated[
            int, Field(description=_ZTP_PAGE_SIZE_DESC, ge=1, le=MAX_PAGE_SIZE)
        ] = DEFAULT_PAGE_SIZE,
        page: Annotated[int, Field(description=_ZTP_PAGE_DESC, ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the device serial numbers registered with ZTP — the serials ZTP will
        answer a DHCP/SZTP request from — and whether each is in use or has an
        ownership voucher.

        Read-only. ``POST /crosswork/ztp/v1/serialnumbers/query`` with
        ``{"filter": {"isInUse": "true"|"false"}, "filterData": {"PageSize",
        "PageNum"}}`` (verified; ``filter`` always sent). HTTP 200 always —
        ``code`` is the verdict and ``data[]`` is ABSENT when nothing
        matches (verified on the empty lab, which answered ``{"code": 200,
        "message": "Get is success"}`` — "No ZTP serial numbers."). Entry
        fields (7.2 document, unverified): ``serialNumber``, ``isInUse``
        and ``isOvLinked`` (``"true"``/``"false"`` strings; the document's
        example spells the latter ``isOVLinked`` — both are read),
        ``ovFilename`` (the ownership voucher for secure ZTP),
        ``modifiedDate`` (epoch seconds). ``pagination.TotalCount`` is the
        match count when reported. The document also lists ``serialNumber``,
        ``isOvLinked``, ``modifiedDate`` and ``ovFileName`` as filterable
        fields — not exposed (``serialNumber`` is an exact filter, verified;
        the rest unverified). Writes: cnc_add_ztp_serial_numbers,
        cnc_delete_ztp_serial_numbers (CSV / ownership-voucher import is not
        exposed).

        Args:
            in_use: 'true' / 'false' / blank.
            page_size / page: filterData paging (0-based page).
            response_format: markdown or json.

        Returns:
            str: Markdown "# ZTP serial numbers (N[ of T])" with one
            "- **serial**: in use|free, voucher ...|no ownership voucher,
            modified <ISO>" line each and a "(more on server ...)" note, or
            JSON {"in_use", "total", "count", "offset", "items": [<serial
            view>], "has_more", "next_offset", "page", "page_size",
            "next_page", "code", "message"}. "No ZTP serial numbers." when
            the list is absent ("No ZTP serial numbers on page P (ZTP
            reports T matching; page 0 is the first)." when TotalCount says
            there are matches — a page past the end, unverified). "Error:
            in_use must be 'true', 'false' or
            blank" (nothing sent); "Error: ZTP serial number query failed
            (ZTP answered code N): <msg>"; "Error: ..." on an API failure.
        """
        try:
            wanted = parse_bool_text(in_use, "in_use")
            body = ztp_query_body({"isInUse": wanted}, page_size, page)
            data = await ztp_query(ZTP_SERIALS_QUERY_URL, body, "ZTP serial number query")
            views = [serial_view(s) for s in dict_list(data.get("data"))]
            env = page_envelope(
                views, total=ztp_total(data), page=page, page_size=page_size, first_page=0
            )
            if response_format is ResponseFormat.JSON:
                payload = {
                    "in_use": wanted,
                    **env,
                    "code": ztp_code(data),
                    "message": data.get("message"),
                }
                return finalize(to_json(payload), settings)
            if not views:
                scope = ""
                if wanted == "true":
                    scope = " in use"
                elif wanted == "false":
                    scope = " free (not in use)"
                past = ztp_past_the_end("ZTP serial numbers", scope, env["total"], page)
                if past:
                    return finalize(past, settings)
                return finalize(
                    f"No ZTP serial numbers{scope}. Serials are added with "
                    "cnc_add_ztp_serial_numbers (or in the Crosswork UI, Device Management > "
                    "Serial Number and OV Import, or by CSV / ownership voucher import).",
                    settings,
                )
            heading = f"# ZTP serial numbers ({len(views)}"
            heading += f" of {env['total']})" if env["total"] is not None else ")"
            lines = [heading, ""]
            lines.extend(serial_line(v) for v in views)
            lines.extend(more_note(env, "cnc_list_ztp_serial_numbers"))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_ztp_static_routes",
        title="List ZTP Static Routes",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_ztp_static_routes(
        page_size: Annotated[
            int, Field(description=_ZTP_PAGE_SIZE_DESC, ge=1, le=MAX_PAGE_SIZE)
        ] = DEFAULT_PAGE_SIZE,
        page: Annotated[int, Field(description=_ZTP_PAGE_DESC, ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the ZTP static routes — the subnets Crosswork adds routes for so the ZTP
        DHCP relay can reach devices that are not on the Crosswork data network.

        Read-only. ``POST /crosswork/ztp/v1/staticroutes/query`` with
        ``{"filter": {}, "filterData": {"PageSize", "PageNum"}}`` (verified;
        ``filter`` always sent). HTTP 200 always — ``code`` is the verdict
        and ``ztpStaticRoutes[]`` is ABSENT when there is none (verified on
        the empty lab — "No ZTP static routes."). Route fields (7.2
        document, unverified): ``uuid``, ``subnet``, ``mask`` (prefix
        length as a string), ``status`` (``add-inprogress`` and the like —
        the add/delete operation state), ``message``, ``modifiedDate``
        (epoch ms). The document's ``filter.subnet`` is not exposed
        (unverified). Writes: cnc_create_ztp_static_route,
        cnc_delete_ztp_static_route (both asynchronous on the platform).

        Args:
            page_size / page: filterData paging (0-based page).
            response_format: markdown or json.

        Returns:
            str: Markdown "# ZTP static routes (N[ of T])" with one
            "- **subnet/mask** (uuid): status, modified <ISO> — message"
            line each and a "(more on server ...)" note, or JSON {"total",
            "count", "offset", "items": [<route view>], "has_more",
            "next_offset", "page", "page_size", "next_page", "code",
            "message"}. "No ZTP static routes." when the list is absent
            ("No ZTP static routes on page P (ZTP reports T matching; page
            0 is the first)." when TotalCount says there are — a page past
            the end, unverified).
            "Error: ZTP static route query failed (ZTP answered code N):
            <msg>"; "Error: ..." on an API failure.
        """
        try:
            body = ztp_query_body({}, page_size, page)
            data = await ztp_query(ZTP_STATIC_ROUTES_QUERY_URL, body, "ZTP static route query")
            views = [route_view(r) for r in dict_list(data.get("ztpStaticRoutes"))]
            env = page_envelope(
                views, total=ztp_total(data), page=page, page_size=page_size, first_page=0
            )
            if response_format is ResponseFormat.JSON:
                payload = {**env, "code": ztp_code(data), "message": data.get("message")}
                return finalize(to_json(payload), settings)
            if not views:
                past = ztp_past_the_end("ZTP static routes", "", env["total"], page)
                if past:
                    return finalize(past, settings)
                return finalize(
                    "No ZTP static routes. Routes are added with cnc_create_ztp_static_route "
                    "(or in the Crosswork UI, Device Management > Zero Touch Provisioning > "
                    "Static Routes) when ZTP devices sit behind a relay off the Crosswork data "
                    "network.",
                    settings,
                )
            heading = f"# ZTP static routes ({len(views)}"
            heading += f" of {env['total']})" if env["total"] is not None else ")"
            lines = [heading, ""]
            lines.extend(route_line(v) for v in views)
            lines.extend(more_note(env, "cnc_list_ztp_static_routes"))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_ztp_device_policy",
        title="Get ZTP Device Policy",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_ztp_device_policy(
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the ZTP device policy — the attributes ZTP writes onto the inventory
        record of a device it onboards (inventory id, router-ids, ...).

        Read-only. ``POST /crosswork/ztp/v1/devices/policies/query`` with the
        body ``{}`` (verified; the document says the body is "currently
        ignored") -> ``{"policydata": {"id", "policyFields": [...],
        "existingAttributes": {...}, "newAttributes": {...}}, "code":
        200}``. ``policyFields`` names every attribute the policy manages
        (e.g. ``inventoryid``, ``routingInfo.globalospfrouterid``,
        ``routingInfo.globalisissystemid``, ``routingInfo.teRouterid``,
        ``routingInfo.ipv6routerid``); ``existingAttributes`` maps those
        already in the inventory model, ``newAttributes`` those ZTP adds
        (they show up as ``additionalAttributes`` on a ZTP device —
        cnc_list_ztp_devices). The document's "no policy" answer is code
        404 "No polices exits in ztp" inside HTTP 200 — reported as the
        non-error "No ZTP device policy is defined." (not seen live; the
        lab answered a policy); any other non-200 code is an Error.

        Args:
            response_format: markdown or json.

        Returns:
            str: Markdown "# ZTP device policy <id>" with the policy fields,
            existing attributes and new attributes, or JSON {"policy":
            {"id", "policyFields", "existingAttributes", "newAttributes"},
            "code", "message"}. "No ZTP device policy is defined ..." for
            the code-404 answer. "Error: ZTP device policy query failed (ZTP
            answered code N): <msg>"; "Error: ..." on an API failure.
        """
        try:
            data = await client.request_json(
                "POST", ZTP_POLICY_QUERY_URL, json_body={}, retryable=True
            )
            data = check_ztp(data, "ZTP device policy query", (ZTP_OK, ZTP_POLICY_NOT_FOUND))
            policy = policy_of(data)
            code = ztp_code(data)
            if response_format is ResponseFormat.JSON:
                payload = {
                    "policy": policy or None,
                    "code": code,
                    "message": data.get("message"),
                }
                return finalize(to_json(payload), settings)
            if not policy:
                return finalize(
                    "No ZTP device policy is defined (ZTP answered code "
                    f"{code if code is not None else '?'}: "
                    f"{_text(data.get('message'), 'no policydata in the answer')}).",
                    settings,
                )
            return finalize(policy_markdown(policy), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_ztp_config_files",
        title="List ZTP Configuration Files",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_ztp_config_files(
        platform: Annotated[
            str,
            Field(
                description=(
                    "OS platform filter (e.g. 'IOS XR'), sent as 'platform' and as the documented "
                    "'osname' and re-checked client-side; the supported values come from GET "
                    "platforms — 'IOS XE', 'IOS XR' on the verified build. Blank for all."
                ),
                max_length=100,
            ),
        ] = "",
        page: Annotated[int, Field(description=_CONFIGSVC_PAGE_DESC, ge=1)] = 1,
        page_size: Annotated[
            int, Field(description=_SVC_PAGE_SIZE_DESC, ge=1, le=MAX_PAGE_SIZE)
        ] = DEFAULT_PAGE_SIZE,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the ZTP configuration files — the Pre-config / Day0-config / Post-config
        files ZTP profiles bundle — with the supported types and platforms.

        Read-only. Four GETs on ``/crosswork/configsvc/v1`` in parallel:
        ``configs?page=&size=[&platform=]`` (accepted live on an empty
        store — whether honoured is unverified — so the documented
        ``PageNum`` / ``PageSize`` / ``osname`` are sent alongside with the
        same values) -> ``{"content": [...], "pageNumber", "pageSize"}``,
        ``configs/count`` (verified) -> a bare
        integer (the total over every platform), ``types`` (verified) ->
        ``["Pre-config", "Day0-config", "Post-config"]`` and ``platforms``
        (verified) -> ``["IOS XE", "IOS XR"]``. The lab holds no file
        (``content: []``, count 0 — verified), reported as the non-error
        "No ZTP configuration files."; the file shape follows the 7.2
        document (unverified): ``confId`` (uuid), ``confName``, ``type``,
        ``osName``, ``deviceFamily``, ``version``, ``vendor``, ``fileName``,
        ``size`` (bytes), ``extraPlaceHolders`` (the ``{{hname}}``-style
        variables the file needs), ``childIds``, ``createdBy`` /
        ``createdTime``, ``modifiedBy`` / ``modifiedTime`` (epoch ms),
        ``downloadurl``. Whether ``platform`` / ``osname`` is honoured
        server-side and whether ``page`` counts from 0 or 1 could not be
        told on an empty instance: the tool re-filters the page on
        ``osName`` client-side, says how many rows it dropped, and derives
        "more pages" from the RAW server page (a full page means more,
        whatever the guard dropped). Seen since on a populated store
        (2026-09-15): the documented ``PageNum`` (1-based; ``PageNum=0`` is
        a Spring 500 — never send page=0) / ``PageSize`` / ``osname``
        (case-insensitive) ARE honoured and ``page`` / ``size`` /
        ``platform`` are ignored, so the client-side guard is belt and
        braces. The file text is not exposed (``configs/files/<confId>``
        is a text/plain download). Writes: cnc_upload_ztp_config_file,
        cnc_update_ztp_config_file, cnc_delete_ztp_config_file.

        Args:
            platform: OS platform filter (blank = all).
            page / page_size: the service's page and size parameters.
            response_format: markdown or json.

        Returns:
            str: Markdown "# ZTP configuration files (N on this page; T in
            total)" with "- types: ..." / "- platforms: ..." header lines,
            one "- **name** (id): type for platform family vversion, file
            ... (size), by user, modified <ISO>, placeholders ..." line per
            file and a "(more on server ...)" note, or JSON {"platform",
            "types": [str], "platforms": [str], "total_all_platforms": int,
            "dropped_by_platform": int, "count", "offset", "items":
            [<config view>], "has_more", "next_offset", "page", "page_size",
            "next_page", "page_number": <echoed>, "page_size_reported":
            <echoed>}. "No ZTP configuration files." (with the types and
            platforms, and the "(more on server ...)" note when the raw
            page was full) when the page is empty. "Error: ..." on an API
            failure of any of the four calls.
        """
        try:
            wanted = platform.strip()
            params = svc_params(page, page_size, wanted, CONFIGSVC_PARAM_NAMES)
            page_data, count_data, types_data, platforms_data = await asyncio.gather(
                get_json(CONFIGS_URL, params),
                get_json(CONFIGS_COUNT_URL),
                get_json(CONFIG_TYPES_URL),
                get_json(CONFIG_PLATFORMS_URL),
            )
            raw = page_content_of(page_data)
            rows, dropped = split_platform(raw, "osName", wanted)
            views = [config_view(c) for c in rows]
            total = as_int(count_data)
            types = string_list(types_data)
            platforms = string_list(platforms_data)
            if wanted:
                env = guarded_page_envelope(
                    views, len(raw), total_all=total, page=page, page_size=page_size
                )
            else:
                env = page_envelope(
                    views, total=total, page=page, page_size=page_size, first_page=1
                )
            echoed = page_data if isinstance(page_data, dict) else {}
            if response_format is ResponseFormat.JSON:
                payload = {
                    "platform": wanted or None,
                    "types": types,
                    "platforms": platforms,
                    "total_all_platforms": total,
                    "dropped_by_platform": dropped,
                    **env,
                    "page_number": echoed.get("pageNumber"),
                    "page_size_reported": echoed.get("pageSize"),
                }
                return finalize(to_json(payload), settings)
            header = [
                f"- types: {', '.join(types) or '-'}",
                f"- platforms: {', '.join(platforms) or '-'}",
            ]
            if not views:
                scope = f" for platform '{wanted}' on page {page}" if wanted else ""
                if not wanted and total:
                    scope = f" on page {page} (the service holds {total})"
                lines = [f"No ZTP configuration files{scope}.", *header]
                if dropped:
                    lines.append(
                        f"- ({dropped} file(s) of other platforms on this page were dropped "
                        "client-side — the service may ignore the platform parameter.)"
                    )
                lines.append(
                    "Files are uploaded with cnc_upload_ztp_config_file (or in the Crosswork "
                    "UI, Device Management > Zero Touch Provisioning > Configuration Files)."
                )
                lines.extend(more_note(env, "cnc_list_ztp_config_files"))
                return finalize("\n".join(lines), settings)
            heading = f"# ZTP configuration files ({len(views)} on this page"
            if total is not None:
                heading += f"; {total} in total over every platform"
            heading += f"; platform {wanted})" if wanted else ")"
            lines = [heading, *header, ""]
            lines.extend(config_line(v) for v in views)
            if dropped:
                lines.append(
                    f"\n({dropped} file(s) of other platforms on this page were dropped "
                    "client-side — the service may ignore the platform parameter.)"
                )
            lines.extend(more_note(env, "cnc_list_ztp_config_files"))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_ztp_images",
        title="List ZTP Images",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_ztp_images(
        platform: Annotated[
            str,
            Field(
                description=(
                    "OS platform filter (e.g. 'IOS XR'), sent as 'platform' and as the documented "
                    "'imagePlatform' and re-checked client-side; the supported values come from "
                    "GET platforms — 'IOS XE', 'IOS XR' on the verified build. Blank for all."
                ),
                max_length=100,
            ),
        ] = "",
        page: Annotated[int, Field(description=_SVC_PAGE_DESC, ge=0)] = 1,
        page_size: Annotated[
            int, Field(description=_SVC_PAGE_SIZE_DESC, ge=1, le=MAX_PAGE_SIZE)
        ] = DEFAULT_PAGE_SIZE,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the ZTP image files — the software images ZTP profiles bundle for
        day-0 install (a store separate from the SWIM repository).

        Read-only. Three GETs on ``/crosswork/imagesvc/v1`` in parallel:
        ``images?page=&size=[&platform=]`` (``page`` / ``size`` accepted
        live on an empty store — whether honoured is unverified — so the
        documented ``pageNumber`` / ``pageSize`` / ``imagePlatform`` are
        sent alongside with the same values) ->
        ``{"content": [...], "pageNumber", "pageSize"}``, ``images/count``
        (verified) -> a bare integer (the total over every platform) and
        ``platforms`` (verified) -> ``{"content": ["IOS XE", "IOS XR"]}``.
        The lab holds no image (``content: []``, count 0 — verified),
        reported as the non-error "No ZTP images."; the image shape follows
        the 7.2 document (unverified): ``id`` (``cw-image-uuid-...``),
        ``imageTitle``, ``imageFileName``, ``imageType`` (``Image`` ...),
        ``imagePlatform``, ``imageVersion``, ``deviceFamily``, ``vendor``,
        ``imageSource`` (``local`` ...), ``createdBy`` / ``createdTime``,
        ``modifiedBy`` / ``modifiedTime`` (epoch ms), ``downloadURL``. The
        ``platform`` parameter mirrors the configsvc form (the document
        calls it ``imagePlatform`` — both are sent) and is UNVERIFIED here,
        as is whether ``page`` counts from 0 or 1: the tool re-filters the
        page on ``imagePlatform`` client-side, says how many rows it
        dropped, and derives "more pages" from the RAW server page (a full
        page means more, whatever the guard dropped). If page 1 comes back
        empty while the count is not 0, the service counts from 0 — call
        again with page=0 — but note that on the sibling configsvc
        ``PageNum=0`` is a Spring 500 and the documented names are the ones
        honoured (verified 2026-09-15), so imagesvc most likely counts from
        1 as well. The SWIM repository (images for distribution/activation
        on managed devices) is cnc_list_software_images. Uploading /
        deleting ZTP images is not exposed (no image on the lab to verify
        with; ``DELETE images/<id>`` answers 204 for an unknown id).

        Args:
            platform: OS platform filter (blank = all).
            page / page_size: the service's page and size parameters.
            response_format: markdown or json.

        Returns:
            str: Markdown "# ZTP images (N on this page; T in total)" with a
            "- platforms: ..." header line, one "- **title** (id): type for
            platform family vversion, file ..., source ..., modified <ISO>"
            line per image and a "(more on server ...)" note, or JSON
            {"platform", "platforms": [str], "total_all_platforms": int,
            "dropped_by_platform": int, "count", "offset", "items": [<image
            view>], "has_more", "next_offset", "page", "page_size",
            "next_page", "page_number": <echoed>, "page_size_reported":
            <echoed>}. "No ZTP images." (with the platforms, and the "(more
            on server ...)" note when the raw page was full) when the page
            is empty. "Error: ..." on an API failure of any of the three
            calls.
        """
        try:
            wanted = platform.strip()
            params = svc_params(page, page_size, wanted, IMAGESVC_PARAM_NAMES)
            page_data, count_data, platforms_data = await asyncio.gather(
                get_json(IMAGES_URL, params),
                get_json(IMAGES_COUNT_URL),
                get_json(IMAGE_PLATFORMS_URL),
            )
            raw = page_content_of(page_data)
            rows, dropped = split_platform(raw, "imagePlatform", wanted)
            views = [ztp_image_view(i) for i in rows]
            total = as_int(count_data)
            platforms = string_list(platforms_data)
            if wanted:
                env = guarded_page_envelope(
                    views, len(raw), total_all=total, page=page, page_size=page_size
                )
            else:
                env = page_envelope(
                    views, total=total, page=page, page_size=page_size, first_page=1
                )
            echoed = page_data if isinstance(page_data, dict) else {}
            if response_format is ResponseFormat.JSON:
                payload = {
                    "platform": wanted or None,
                    "platforms": platforms,
                    "total_all_platforms": total,
                    "dropped_by_platform": dropped,
                    **env,
                    "page_number": echoed.get("pageNumber"),
                    "page_size_reported": echoed.get("pageSize"),
                }
                return finalize(to_json(payload), settings)
            header = [f"- platforms: {', '.join(platforms) or '-'}"]
            if not views:
                scope = f" for platform '{wanted}' on page {page}" if wanted else ""
                if not wanted and total:
                    scope = f" on page {page} (the service holds {total})"
                lines = [f"No ZTP images{scope}.", *header]
                if dropped:
                    lines.append(
                        f"- ({dropped} image(s) of other platforms on this page were dropped "
                        "client-side — the service may ignore the platform parameter.)"
                    )
                lines.append(
                    "Images are uploaded in the Crosswork UI (Device Management > Zero Touch "
                    "Provisioning > Images); the SWIM repository is a separate store "
                    "(cnc_list_software_images)."
                )
                lines.extend(more_note(env, "cnc_list_ztp_images"))
                return finalize("\n".join(lines), settings)
            heading = f"# ZTP images ({len(views)} on this page"
            if total is not None:
                heading += f"; {total} in total over every platform"
            heading += f"; platform {wanted})" if wanted else ")"
            lines = [heading, *header, ""]
            lines.extend(ztp_image_line(v) for v in views)
            if dropped:
                lines.append(
                    f"\n({dropped} image(s) of other platforms on this page were dropped "
                    "client-side — the service may ignore the platform parameter.)"
                )
            lines.extend(more_note(env, "cnc_list_ztp_images"))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    # --- ZTP writes ---------------------------------------------------------------------

    async def ztp_write(method: str, url: str, body: dict[str, Any], what: str) -> dict[str, Any]:
        """One ZTP write (POST / PUT / DELETE with a JSON body) under the code rule.

        PUT and DELETE keep the client's idempotent auto-retry (a repeat is
        refused or a no-op on this platform — verified); a POST is never
        auto-retried, so a lost answer cannot create twice.
        """
        data = await client.request_json(method, url, json_body=body)
        return check_ztp_write(data, what)

    async def ztp_find(url: str, filters: dict[str, Any], key: str, what: str) -> list[dict]:
        """One exact-filter ZTP query (verified filters: profileName / profileId / config
        on profiles, hostName / uuid / profileName / config on devices, serialNumber on
        serials) -> the data rows (``[]`` when the key is absent)."""
        body = ztp_query_body(filters, MAX_PAGE_SIZE, 0)
        data = await ztp_query(url, body, what)
        return dict_list(data.get(key))

    async def profile_by_id(profile_id: str) -> dict[str, Any] | None:
        rows = await ztp_find(
            ZTP_PROFILES_QUERY_URL, {"profileId": profile_id}, "ztpProfiles", "ZTP profile query"
        )
        return next((r for r in rows if _text(r.get("profileId"), "") == profile_id), None)

    async def profile_by_name(name: str) -> dict[str, Any] | None:
        rows = await ztp_find(
            ZTP_PROFILES_QUERY_URL, {"profileName": name}, "ztpProfiles", "ZTP profile query"
        )
        return next((r for r in rows if _text(r.get("profileName"), "") == name), None)

    async def device_by_uuid(uuid: str) -> dict[str, Any] | None:
        rows = await ztp_find(ZTP_DEVICES_QUERY_URL, {"uuid": uuid}, "ztpnodes", "ZTP device query")
        return next((r for r in rows if _text(r.get("uuid"), "") == uuid), None)

    async def device_by_host(host_name: str) -> dict[str, Any] | None:
        rows = await ztp_find(
            ZTP_DEVICES_QUERY_URL, {"hostName": host_name}, "ztpnodes", "ZTP device query"
        )
        return next((r for r in rows if _text(r.get("hostName"), "") == host_name), None)

    async def routes_now() -> list[dict[str, Any]]:
        body = ztp_query_body({}, MAX_PAGE_SIZE, 0)
        data = await ztp_query(ZTP_STATIC_ROUTES_QUERY_URL, body, "ZTP static route query")
        return dict_list(data.get("ztpStaticRoutes"))

    async def config_by_id(config_id: str) -> dict[str, Any] | None:
        """``GET configs/<confId>`` -> the ConfigDto, or None on the verified 404."""
        response = await client.request(
            "GET", f"{CONFIGS_URL}/{quote(config_id, safe='')}", ok_statuses={404}
        )
        if response.status_code == 404:
            return None
        data = response.json() if response.content else None
        return data if isinstance(data, dict) else None

    def config_error(response: httpx.Response, config_id: str) -> PlatformError:
        """The configsvc error: a verified 404 becomes "no ZTP configuration file <id>"."""
        if response.status_code == 404:
            return PlatformError(
                f"no ZTP configuration file with id {config_id} (configsvc answered 404 "
                "'Config not found'); cnc_list_ztp_config_files shows the ids."
            )
        return http_error(response)

    @register_tool(
        mcp,
        ctx,
        name="cnc_upload_ztp_config_file",
        title="Upload ZTP Configuration File",
        read_only=False,
        idempotent=False,
        redact=("content",),
    )
    async def cnc_upload_ztp_config_file(
        name: Annotated[
            str,
            Field(
                description="Unique configuration name (confname, e.g. 'ncs540-day0').",
                min_length=1,
                max_length=200,
            ),
        ],
        platform: Annotated[
            str,
            Field(
                description=(
                    "OS platform (osname) — one of cnc_list_ztp_config_files' platforms, "
                    "'IOS XR' or 'IOS XE' on the verified build. NOT validated by the service "
                    "(any text is stored), so spell it exactly."
                ),
                min_length=1,
                max_length=100,
            ),
        ],
        version: Annotated[
            str,
            Field(
                description=(
                    "Software version the file is for (e.g. '7.9.2'); a ZTP device in the "
                    "metadata form must carry the same version."
                ),
                min_length=1,
                max_length=100,
            ),
        ],
        device_family: Annotated[
            str,
            Field(
                description="Device family (devicefamily, e.g. 'CISCO NCS540').",
                min_length=1,
                max_length=100,
            ),
        ],
        content: Annotated[
            str,
            Field(
                description=(
                    "The file text. A Day0-config .txt file for IOS XR MUST carry the line "
                    "'!! IOS XR' in its first three lines (e.g. '!! IOS XR\\nhostname pe9\\n'); "
                    "Pre-config / Post-config files must be scripts (.py / .sh) whose first "
                    "line is a shebang ('#!/usr/bin/env python3')."
                ),
                min_length=1,
                max_length=MAX_CONFIG_CONTENT_CHARS,
            ),
        ],
        config_type: Annotated[
            str,
            Field(
                description="'Day0-config' (default), 'Pre-config' or 'Post-config'.",
                max_length=40,
            ),
        ] = DEFAULT_CONFIG_TYPE,
        file_name: Annotated[
            str,
            Field(
                description=(
                    "Stored file name (fileName, e.g. 'ncs540-day0.txt'); blank derives "
                    "'<name>.txt'. The extension drives the content checks (.txt: the '!! IOS "
                    "XR' banner; .py/.sh for pre/post-config scripts)."
                ),
                max_length=200,
            ),
        ] = "",
        vendor: Annotated[
            str, Field(description="Vendor text (e.g. 'Cisco Systems').", max_length=100)
        ] = DEFAULT_VENDOR,
    ) -> str:
        """Upload a ZTP configuration file — the day-0 (or pre/post) file a ZTP profile or
        device hands a booting device.

        Write — only registered when *_ENABLE_WRITES=true; the multipart POST is
        never auto-retried. ``POST /crosswork/configsvc/v1/configs/upload``
        (deprecated in the 7.2 documents but the only ZTP API routed on this
        build) as ``multipart/form-data`` with one ``configFile`` part and
        the metadata as query parameters ``confname`` / ``osname`` /
        ``version`` / ``devicefamily`` / ``vendor`` / ``type`` (verified live
        2026-09-15) -> HTTP 201 with the ConfigDto (``confId`` — the id
        profiles and devices reference, ``fileName``, ``size``,
        ``extraPlaceHolders`` — the {{placeholders}} the file needs —
        ``createdTime``, ``downloadurl``).

        Platform checks (verified): a ``Day0-config`` ``.txt`` file must
        carry ``!! IOS XR`` in its first three lines (400 "Text (.txt) script
        should have '!! IOS XR' in any of the first three lines"); a
        ``Pre-config`` / ``Post-config`` must be a .py/.sh script (400
        "Pre-config should have script files (PY/SH)") starting with a
        shebang (400 "Python (PY) and Shell (SH) script's first line should
        start with #!") for a secure-ZTP-capable ``version`` (400
        "Pre-config do not support the classic version 7.0.2 for platform
        IOS XR"; 7.3.1 was accepted); the name must be unique (409 "Configuration
        already exists with name X"); the type must be one of the three
        (refused here before the call); the platform text is NOT validated.
        Then: cnc_create_ztp_profile bundles the file into a profile, or
        cnc_create_ztp_device references it directly. The content is never
        echoed back (redacted in dry-run previews too) — it may carry
        credentials.

        Args:
            name, platform, version, device_family, content: required.
            config_type, file_name, vendor: optional.

        Returns:
            str: "ZTP configuration file '<name>' uploaded (id <confId>, N
            bytes)." followed by JSON {"config": <config view>, "sent":
            {<metadata>, "file_name", "content_chars"}}. "Error: config_type
            must be one of ..." (no call made); "Error: API request failed
            with status 400/409 ... Platform said: <message>" for the
            platform's checks; "Error: ..." on any other API failure.
        """
        try:
            wire_type = canonical_config_type(config_type)
            params = config_upload_params(
                name=name,
                platform=platform,
                version=version,
                device_family=device_family,
                vendor=vendor,
                config_type=wire_type,
            )
            stored_name = file_name.strip() or default_config_file_name(name)
            response = await client.request(
                "POST",
                CONFIGS_UPLOAD_URL,
                params=params,
                files=config_file_part(stored_name, content),
            )
            data = response.json() if response.content else {}
            view = config_view(data) if isinstance(data, dict) else {}
            sent = {**params, "file_name": stored_name, "content_chars": len(content)}
            size = view.get("size")
            text = (
                f"ZTP configuration file '{params['confname']}' uploaded (id "
                f"{_text(view.get('confId'))}, {size if size is not None else '?'} bytes)."
            )
            return finalize(f"{text}\n\n{to_json({'config': view, 'sent': sent})}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_ztp_config_file",
        title="Update ZTP Configuration File",
        read_only=False,
        destructive=True,
        idempotent=True,
        redact=("content",),
    )
    async def cnc_update_ztp_config_file(
        config_id: Annotated[
            str,
            Field(
                description="confId of the file (from cnc_list_ztp_config_files).",
                min_length=1,
                max_length=100,
            ),
        ],
        content: Annotated[
            str,
            Field(
                description=(
                    "New file text (replaces the stored file; same checks as the upload — a "
                    "Day0-config .txt needs '!! IOS XR' in its first three lines). Blank or "
                    "whitespace-only keeps the current content (it is downloaded and re-sent, "
                    "because the platform's PUT always takes a file)."
                ),
                max_length=MAX_CONFIG_CONTENT_CHARS,
            ),
        ] = "",
        name: Annotated[
            str, Field(description="New configuration name; blank keeps it.", max_length=200)
        ] = "",
        platform: Annotated[
            str, Field(description="New OS platform text; blank keeps it.", max_length=100)
        ] = "",
        version: Annotated[
            str, Field(description="New version; blank keeps it.", max_length=100)
        ] = "",
        device_family: Annotated[
            str, Field(description="New device family; blank keeps it.", max_length=100)
        ] = "",
        vendor: Annotated[
            str, Field(description="New vendor text; blank keeps it.", max_length=100)
        ] = "",
        config_type: Annotated[
            str,
            Field(
                description="New type (Day0-config / Pre-config / Post-config); blank keeps it.",
                max_length=40,
            ),
        ] = "",
    ) -> str:
        """Update a ZTP configuration file's metadata and/or replace its content.

        Write, destructive (the stored file is overwritten) — only registered
        when *_ENABLE_WRITES=true. ``PUT /crosswork/configsvc/v1/configs/
        <confId>`` (deprecated in the 7.2 documents; the only ZTP API routed
        here) as the same multipart form as the upload: the ``configFile``
        part is mandatory, the metadata query parameters (``confname``,
        ``osname``, ``version``, ``devicefamily``, ``vendor``, ``type``) are
        each optional and only the given ones change (verified live
        2026-09-15: a PUT with ``confname`` + ``version`` renamed and
        re-versioned the file and replaced its content). With blank (or
        whitespace-only) ``content`` the tool first downloads the current
        text (``GET configs/files/<confId>``, text/plain — verified) and
        re-sends it, so a metadata-only change is possible and a script can
        never be wiped by accident. Caveat (verified): the stored
        ``size`` is NOT recomputed after a content replacement — it stays the
        upload's. Profiles and devices referencing the file keep referencing
        it (``isConfigInvalid`` marks a profile whose file was DELETED, not
        changed). Unknown id -> 404 "Config not found" (reported as not
        found, nothing sent).

        Args:
            config_id: the file's confId.
            content, name, platform, version, device_family, vendor, config_type:
                the changes (blank = keep).

        Returns:
            str: "ZTP configuration file <id> updated (<changed keys>)."
            followed by JSON {"config": <config view after>, "changed":
            {<metadata sent>}, "content_replaced": bool, "content_chars"}.
            "Error: no ZTP configuration file with id <id> ..." for an
            unknown id; "Error: nothing to change ..." when every argument
            is blank (nothing sent); "Error: API request failed with status
            400 ... Platform said: <message>" for the content checks;
            "Error: ..." on any other API failure.
        """
        try:
            wanted = config_id.strip()
            wire_type = canonical_config_type(config_type) if config_type.strip() else ""
            params = config_update_params(
                name=name,
                platform=platform,
                version=version,
                device_family=device_family,
                vendor=vendor,
                config_type=wire_type,
            )
            # Whitespace-only content is "keep", never a blank file (a Pre/Post-config
            # script would otherwise be wiped — the banner check only guards .txt files).
            new_content = content if content.strip() else ""
            if not params and not new_content:
                raise PlatformError(
                    "nothing to change: pass new content and/or at least one metadata value."
                )
            current = await config_by_id(wanted)
            if current is None:
                raise PlatformError(
                    f"no ZTP configuration file with id {wanted} (configsvc answered 404 "
                    "'Config not found'); cnc_list_ztp_config_files shows the ids."
                )
            text = new_content
            if not text:
                download = await client.request(
                    "GET", f"{CONFIG_FILES_URL}/{quote(wanted, safe='')}"
                )
                text = download.text
            stored_name = _text(current.get("fileName"), "") or default_config_file_name(
                _text(current.get("confName"), wanted)
            )
            response = await client.request(
                "PUT",
                f"{CONFIGS_URL}/{quote(wanted, safe='')}",
                params=params or None,
                files=config_file_part(stored_name, text),
                raise_on_error=False,
            )
            if not response.is_success:
                raise config_error(response, wanted)
            data = response.json() if response.content else {}
            view = config_view(data) if isinstance(data, dict) else {}
            changed = list(params) + (["content"] if new_content else [])
            payload = {
                "config": view,
                "changed": params,
                "content_replaced": bool(new_content),
                "content_chars": len(text),
            }
            return finalize(
                f"ZTP configuration file {wanted} updated ({', '.join(changed)}).\n\n"
                f"{to_json(payload)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_ztp_config_file",
        title="Delete ZTP Configuration File",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_ztp_config_file(
        config_id: Annotated[
            str,
            Field(
                description="confId of the file to delete (from cnc_list_ztp_config_files).",
                min_length=1,
                max_length=100,
            ),
        ],
        force: Annotated[
            bool,
            Field(
                description=(
                    "Delete even when ZTP profiles or devices still reference the file (they "
                    "are left with isConfigInvalid / isPreConfigInvalid / isPostConfigInvalid "
                    "= true). Default false: refuse and list them."
                ),
            ),
        ] = False,
    ) -> str:
        """Delete a ZTP configuration file (a Day0-config, Pre-config or Post-config).

        DESTRUCTIVE write — only registered when *_ENABLE_WRITES=true. ``DELETE
        /crosswork/configsvc/v1/configs/<confId>`` (deprecated in the 7.2
        documents; the only ZTP API routed here) -> 204 (verified live
        2026-09-15); unknown id -> 404 "Config not found for <id>" (reported
        as not found). Ordering rule (verified): the platform DOES delete a
        file that profiles or devices still reference and only flags them —
        a profile's ``isConfigInvalid`` (day-0 file), ``isPreConfigInvalid``
        or ``isPostConfigInvalid`` (scripts), a device's ``isConfigInvalid``
        — so the tool first queries the profiles by each of the three
        reference fields (``filter.config`` / ``preConfig`` / ``postConfig``,
        every one an exact filter — verified) and the devices
        (``filter.config``; a device record has no pre/post fields — 7.2
        schema), re-checks the matches client-side, and refuses unless
        ``force``. Preferred sequence: repoint or delete the profiles
        (cnc_update_ztp_profile / cnc_delete_ztp_profile) and devices
        (cnc_update_ztp_device / cnc_delete_ztp_device) first, then delete
        the file.

        Args:
            config_id: the file's confId.
            force: delete despite references.

        Returns:
            str: "ZTP configuration file '<name>' (<id>) deleted." followed
            by JSON {"config": <the view before deletion>, "referenced_by":
            {"profiles": ["<name>" for a day-0 reference, "<name> (as
            preConfig)" / "(as postConfig)" for a script], "devices": [host
            names]}, "forced": bool}. "Error: no ZTP configuration file with
            id <id> ..." for an unknown id; "Error: ZTP configuration file
            <id> is referenced by profile(s) ... / device(s) ... — repoint or
            delete them first, or pass force=true ..." when references exist
            and force is false (nothing deleted); "Error: ..." on an API
            failure.
        """
        try:
            wanted = config_id.strip()
            current = await config_by_id(wanted)
            if current is None:
                raise PlatformError(
                    f"no ZTP configuration file with id {wanted} (configsvc answered 404 "
                    "'Config not found'); cnc_list_ztp_config_files shows the ids."
                )
            *profile_pages, devices = await asyncio.gather(
                *(
                    ztp_find(
                        ZTP_PROFILES_QUERY_URL, {field: wanted}, "ztpProfiles", "ZTP profile query"
                    )
                    for field in PROFILE_CONFIG_FIELDS
                ),
                ztp_find(ZTP_DEVICES_QUERY_URL, {"config": wanted}, "ztpnodes", "ZTP device query"),
            )
            profiles = [p for page in profile_pages for p in page]
            names, hosts = references_of(profiles, devices, wanted)
            if (names or hosts) and not force:
                parts = []
                if names:
                    parts.append(f"profile(s) {', '.join(names)}")
                if hosts:
                    parts.append(f"device(s) {', '.join(hosts)}")
                raise PlatformError(
                    f"ZTP configuration file {wanted} is referenced by {' and '.join(parts)} — "
                    "repoint or delete them first (cnc_update_ztp_profile / "
                    "cnc_delete_ztp_profile, cnc_update_ztp_device / cnc_delete_ztp_device), or "
                    "pass force=true to delete the file anyway and leave them flagged "
                    "isConfigInvalid / isPreConfigInvalid / isPostConfigInvalid (the platform "
                    "allows it — verified)."
                )
            response = await client.request(
                "DELETE", f"{CONFIGS_URL}/{quote(wanted, safe='')}", raise_on_error=False
            )
            if not response.is_success:
                raise config_error(response, wanted)
            view = config_view(current)
            payload = {
                "config": view,
                "referenced_by": {"profiles": names, "devices": hosts},
                "forced": bool(force and (names or hosts)),
            }
            return finalize(
                f"ZTP configuration file '{_text(view.get('confName'))}' ({wanted}) deleted."
                f"\n\n{to_json(payload)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_ztp_profile",
        title="Create ZTP Profile",
        read_only=False,
        idempotent=False,
    )
    async def cnc_create_ztp_profile(
        name: Annotated[
            str,
            Field(
                description="Unique profile name (e.g. 'ncs540-7.9.2-day0').",
                min_length=1,
                max_length=200,
            ),
        ],
        config_id: Annotated[
            str,
            Field(
                description=(
                    "confId of the day-0 configuration file (cnc_list_ztp_config_files / "
                    "cnc_upload_ztp_config_file). Mandatory: ZTP refuses a profile without one."
                ),
                min_length=1,
                max_length=100,
            ),
        ],
        platform: Annotated[
            str,
            Field(
                description="OS platform (osPlatform, e.g. 'IOS XR').", min_length=1, max_length=100
            ),
        ],
        device_family: Annotated[
            str,
            Field(description="Device family (e.g. 'CISCO NCS540').", min_length=1, max_length=100),
        ],
        version: Annotated[
            str,
            Field(description="Software version (e.g. '7.9.2').", min_length=1, max_length=100),
        ],
        description: Annotated[
            str, Field(description="Free-text description.", max_length=1000)
        ] = "",
        image_id: Annotated[
            str,
            Field(
                description=(
                    "id of a ZTP image (cnc_list_ztp_images) to install at day 0; blank for "
                    "none (the verified profile carried none — the lab has no image)."
                ),
                max_length=100,
            ),
        ] = "",
        secure_ztp: Annotated[
            bool,
            Field(description="Secure ZTP (SZTP) profile; default false = classic ZTP."),
        ] = False,
        pre_config_id: Annotated[
            str,
            Field(
                description=(
                    "confId of a Pre-config script; blank for none. Needs secure_ztp=true "
                    "(ZTP refuses it otherwise — verified)."
                ),
                max_length=100,
            ),
        ] = "",
        post_config_id: Annotated[
            str,
            Field(
                description=(
                    "confId of a Post-config script; blank for none. Needs secure_ztp=true "
                    "(ZTP refuses it otherwise — verified)."
                ),
                max_length=100,
            ),
        ] = "",
        category: Annotated[
            str,
            Field(
                description="profileCategory text (the 7.2 document's example uses '0day').",
                max_length=100,
            ),
        ] = DEFAULT_PROFILE_CATEGORY,
        vendor: Annotated[
            str, Field(description="Vendor text (e.g. 'Cisco Systems').", max_length=100)
        ] = DEFAULT_VENDOR,
    ) -> str:
        """Create a ZTP profile — the platform / family / version bundle of a day-0
        configuration file (and optionally an image) that ZTP devices are onboarded
        with.

        Write — only registered when *_ENABLE_WRITES=true; the POST is never
        auto-retried. ``POST /crosswork/ztp/v1/profiles {"profiles": [{...}]}``
        (deprecated in the 7.2 documents but the only ZTP API routed on this
        build) answers HTTP 200 with the verdict in the body: ``code`` 201
        "Profile Created Successfully" (verified live 2026-09-15) — WITHOUT
        the new id, so the tool then queries the profile by its exact name
        and returns the record (``profileId``, ``configName`` resolved from
        the config id, ``lastUpdated``; ``preConfig`` / ``postConfig`` and
        their ``*Name`` only when set). Verified failures: code 400
        "Profile with name already exist : X" (names are unique), 400
        "Config field is Mandatory", 400 "Invalid Config IDs :: X" (unknown
        config_id), 400 "Secure ZTP flag should be enabled to support
        pre/post configurations for profile X." (a pre_config_id /
        post_config_id with secure_ztp false). Ordering: upload the files
        first (cnc_upload_ztp_config_file — a Pre-config / Post-config
        needs a secure-ZTP-capable version, e.g. 7.3.1; 7.0.2 is refused as
        "classic"). Not idempotent: a repeat with the same name fails
        rather than duplicating.

        Args:
            name, config_id, platform, device_family, version: required.
            description, image_id, secure_ztp, pre_config_id, post_config_id,
                category, vendor: optional.

        Returns:
            str: "ZTP profile '<name>' created (id <profileId>)." followed by
            JSON {"profile": <profile view>, "sent": {<body>}, "response":
            {"code", "message"}}. "Error: ZTP profile create failed (ZTP
            answered code 400): Profile with name already exist : X" and the
            other verified texts; "Error: ..." on an API failure.
        """
        try:
            body = profile_body(
                name=name,
                config_id=config_id,
                platform=platform,
                device_family=device_family,
                version=version,
                description=description,
                category=category,
                vendor=vendor,
                image_id=image_id,
                secure_ztp=secure_ztp,
                pre_config_id=pre_config_id,
                post_config_id=post_config_id,
            )
            data = await ztp_write(
                "POST", ZTP_PROFILES_URL, {"profiles": [body]}, "ZTP profile create"
            )
            record = await profile_by_name(body["profileName"])
            view = profile_view(record) if record else {}
            payload = {
                "profile": view or None,
                "sent": body,
                "response": {"code": ztp_code(data), "message": data.get("message")},
            }
            ident = _text(view.get("profileId"), "id not found by name — cnc_list_ztp_profiles")
            return finalize(
                f"ZTP profile '{body['profileName']}' created ({ident}).\n\n{to_json(payload)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_ztp_profile",
        title="Update ZTP Profile",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_update_ztp_profile(
        profile_id: Annotated[
            str,
            Field(
                description="profileId of the profile (from cnc_list_ztp_profiles).",
                min_length=1,
                max_length=100,
            ),
        ],
        description: Annotated[
            str | None, Field(description="New description; omit to keep.", max_length=1000)
        ] = None,
        config_id: Annotated[
            str | None,
            Field(description="New day-0 configuration confId; omit to keep.", max_length=100),
        ] = None,
        image_id: Annotated[
            str | None,
            Field(description="New ZTP image id ('' to clear); omit to keep.", max_length=100),
        ] = None,
        version: Annotated[
            str | None, Field(description="New version; omit to keep.", max_length=100)
        ] = None,
        device_family: Annotated[
            str | None, Field(description="New device family; omit to keep.", max_length=100)
        ] = None,
        platform: Annotated[
            str | None, Field(description="New OS platform; omit to keep.", max_length=100)
        ] = None,
        secure_ztp: Annotated[
            bool | None, Field(description="Secure ZTP flag; omit to keep.")
        ] = None,
        pre_config_id: Annotated[
            str | None,
            Field(description="New Pre-config confId ('' to clear); omit to keep.", max_length=100),
        ] = None,
        post_config_id: Annotated[
            str | None,
            Field(
                description="New Post-config confId ('' to clear); omit to keep.", max_length=100
            ),
        ] = None,
        category: Annotated[
            str | None, Field(description="New profileCategory; omit to keep.", max_length=100)
        ] = None,
        vendor: Annotated[
            str | None, Field(description="New vendor text; omit to keep.", max_length=100)
        ] = None,
    ) -> str:
        """Update a ZTP profile in place (description, files, image, platform / family /
        version, secure-ZTP flag). The name cannot be changed.

        Write, destructive (the profile is overwritten) — only registered when
        *_ENABLE_WRITES=true. The tool queries the profile by ``profileId``
        (exact filter, verified), rebuilds the full create form from the
        record with the given changes applied, and sends ``PUT
        /crosswork/ztp/v1/profiles`` (deprecated in the 7.2 documents; the
        only ZTP API routed here) -> code 200 "Profile Updated Successfully"
        (verified live 2026-09-15), then queries it again and returns it.
        Why this dance (all verified): echoing the query record back is a
        code-422 "cannot unmarshal string into ... lastUpdated of type int64";
        ZTP looks the profile up by NAME, so a changed name answers code
        404 "Profile with name X does not exist" (no rename — create a new
        profile instead); and a PUT with an UNKNOWN ``profileId`` and an
        existing name silently UPSERTS a second profile under that id — the
        tool refuses an unknown id before sending anything. Per the 7.2
        document (unverified — the lab has no booting device): the update
        is refused with code 424 "Crosswork can update profiles only when
        the devices associated with this profile are in Unprovisioned,
        ZTPError or Onboarded status" unless every device using it is in
        one of those three states; toggling ``secure_ztp`` is refused with
        code 400 "X can not be updated, as profile is associated with secure
        ZTP disabled device." while a classic-ZTP device uses the profile;
        and (verified) a pre_config_id / post_config_id needs
        ``secure_ztp`` true ("Secure ZTP flag should be enabled to support
        pre/post configurations for profile X.").

        Args:
            profile_id: the profile's id.
            description, config_id, image_id, version, device_family, platform,
                secure_ztp, pre_config_id, post_config_id, category, vendor:
                the changes (omit = keep).

        Returns:
            str: "ZTP profile '<name>' (<id>) updated (<changed keys>)."
            followed by JSON {"profile": <profile view after>, "before":
            <view before>, "sent": {<PUT body>}, "response": {"code",
            "message"}}. "Error: no ZTP profile with id <id> ..." (nothing
            sent); "Error: nothing to change ..." (nothing sent); "Error: ZTP
            profile update failed (ZTP answered code N): <message>";
            "Error: ..." on an API failure.
        """
        try:
            wanted = profile_id.strip()
            changes = {
                "description": description,
                "config_id": config_id,
                "image_id": image_id,
                "version": version,
                "device_family": device_family,
                "platform": platform,
                "secure_ztp": secure_ztp,
                "pre_config_id": pre_config_id,
                "post_config_id": post_config_id,
                "category": category,
                "vendor": vendor,
            }
            changed = [k for k, v in changes.items() if v is not None]
            if not changed:
                raise PlatformError("nothing to change: pass at least one value to update.")
            current = await profile_by_id(wanted)
            if current is None:
                raise PlatformError(
                    f"no ZTP profile with id {wanted} (the profileId query matched nothing; "
                    "cnc_list_ztp_profiles shows the ids) — refused before the call, because "
                    "ZTP's PUT would create a second profile under an unknown id."
                )
            body = profile_update_body(current, changes)
            data = await ztp_write("PUT", ZTP_PROFILES_URL, body, "ZTP profile update")
            after = await profile_by_id(wanted)
            payload = {
                "profile": profile_view(after) if after else None,
                "before": profile_view(current),
                "sent": body,
                "response": {"code": ztp_code(data), "message": data.get("message")},
            }
            return finalize(
                f"ZTP profile '{body['profileName']}' ({wanted}) updated ({', '.join(changed)})."
                f"\n\n{to_json(payload)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_ztp_profile",
        title="Delete ZTP Profile",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_ztp_profile(
        profile_id: Annotated[
            str,
            Field(
                description="profileId of the profile to delete (from cnc_list_ztp_profiles).",
                min_length=1,
                max_length=100,
            ),
        ],
        force: Annotated[
            bool,
            Field(
                description=(
                    "Delete even when ZTP devices still name the profile (they are left with a "
                    "dangling profileName). Default false: refuse and list them."
                ),
            ),
        ] = False,
    ) -> str:
        """Delete a ZTP profile.

        DESTRUCTIVE write — only registered when *_ENABLE_WRITES=true. ``DELETE
        /crosswork/ztp/v1/profiles {"profiles": [{"profileId": ...}]}``
        (deprecated in the 7.2 documents; the only ZTP API routed here) ->
        ``{"code": 200}`` (verified live 2026-09-15); unknown id -> code 404
        "Profile with name <id> does not exist" (reported as not found).
        Ordering rules (verified): the platform DOES delete a profile that a
        ZTP device names in ``profileName`` (the device keeps the dangling
        name), so the tool queries the devices using the profile
        (``filter.profileName``) and refuses unless ``force``; it REFUSES
        with code 424 "Profile  can not be deleted" while a device
        references the profile's configuration file directly (metadata
        form) — delete or repoint that device first (cnc_delete_ztp_device /
        cnc_update_ztp_device). The configuration file itself is not
        deleted (cnc_delete_ztp_config_file).

        Args:
            profile_id: the profile's id.
            force: delete despite devices naming the profile.

        Returns:
            str: "ZTP profile '<name>' (<id>) deleted." followed by JSON
            {"profile": <the view before deletion>, "devices_using_it":
            [host names], "forced": bool, "response": {"code", "message"}}.
            "Error: no ZTP profile with id <id> ..."; "Error: ZTP profile
            '<name>' is used by device(s) ... — delete or repoint them
            first, or pass force=true" (nothing deleted); "Error: ZTP
            profile delete failed (ZTP answered code 424): Profile  can not
            be deleted — a ZTP device references its configuration file
            directly ..."; "Error: ..." on an API failure.
        """
        try:
            wanted = profile_id.strip()
            current = await profile_by_id(wanted)
            if current is None:
                raise PlatformError(
                    f"no ZTP profile with id {wanted} (the profileId query matched nothing; "
                    "cnc_list_ztp_profiles shows the ids)."
                )
            name = _text(current.get("profileName"), "")
            devices = await ztp_find(
                ZTP_DEVICES_QUERY_URL, {"profileName": name}, "ztpnodes", "ZTP device query"
            )
            hosts = devices_using_profile(devices, name)
            if hosts and not force:
                raise PlatformError(
                    f"ZTP profile '{name}' is used by device(s) {', '.join(hosts)} — delete or "
                    "repoint them first (cnc_delete_ztp_device / cnc_update_ztp_device), or pass "
                    "force=true to delete the profile anyway and leave them with a dangling "
                    "profileName (the platform allows it — verified)."
                )
            data = await client.request_json(
                "DELETE", ZTP_PROFILES_URL, json_body={"profiles": [{"profileId": wanted}]}
            )
            if isinstance(data, dict) and as_int(data.get("code")) == ZTP_PROFILE_IN_USE:
                raise PlatformError(
                    f"ZTP profile delete failed (ZTP answered code {ZTP_PROFILE_IN_USE}): "
                    f"{ztp_message(data) or 'Profile can not be deleted'} — a ZTP device "
                    "references the profile's configuration file directly (verified); delete or "
                    "repoint that device first (cnc_list_ztp_devices shows the config ids)."
                )
            data = check_ztp_write(data, "ZTP profile delete")
            payload = {
                "profile": profile_view(current),
                "devices_using_it": hosts,
                "forced": bool(force and hosts),
                "response": {"code": ztp_code(data), "message": data.get("message")},
            }
            return finalize(
                f"ZTP profile '{name}' ({wanted}) deleted.\n\n{to_json(payload)}", settings
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_add_ztp_serial_numbers",
        title="Add ZTP Serial Numbers",
        read_only=False,
        idempotent=True,
    )
    async def cnc_add_ztp_serial_numbers(
        serial_numbers: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated device serial numbers to register (e.g. "
                    "'FOC2329R0CX,FOC2329R0CY'), up to 100 per call."
                ),
                min_length=1,
                max_length=4000,
            ),
        ],
    ) -> str:
        """Register device serial numbers with ZTP — the allow-list a ZTP device's
        serial must be on before the device can be added, and the serials ZTP will
        answer a DHCP request from.

        Write — only registered when *_ENABLE_WRITES=true; idempotent (the
        platform counts an already-registered serial as a duplicate, never
        refuses it), so the POST is sent with auto-retry enabled. ``POST
        /crosswork/ztp/v1/serialnumbers {"data": [{"serialNumber": ...}]}``
        (deprecated in the 7.2 documents but the only ZTP API routed on this
        build) answers HTTP 200 with code 201 "Created Successfully" and
        ``processedRecordCount`` (newly added) / ``duplicateRecordCount``
        (already there) — a key absent when its count is 0 (verified live
        2026-09-15). Ownership vouchers (secure ZTP) and CSV import are not
        exposed. Ordering: register the serial FIRST, then
        cnc_create_ztp_device ("Serial Number(s) not present in allowed
        list" otherwise — or let that tool register it with
        register_serial=true).

        Args:
            serial_numbers: comma-separated serials.

        Returns:
            str: "N ZTP serial number(s) registered (M already registered)."
            followed by JSON {"serial_numbers": [sent], "added": int,
            "duplicates": int, "response": {"code", "message"}}. "Error: no
            serial numbers given" (nothing sent); "Error: ZTP serial number
            add failed (ZTP answered code N): <message>"; "Error: ..." on an
            API failure.
        """
        try:
            serials = split_csv(serial_numbers)
            if not serials:
                raise PlatformError("no serial numbers given (blank after trimming).")
            if len(serials) > MAX_SERIALS_PER_CALL:
                raise PlatformError(
                    f"{len(serials)} serial numbers given; at most {MAX_SERIALS_PER_CALL} per call."
                )
            body = {"data": [{"serialNumber": s} for s in serials]}
            data = await client.request_json(
                "POST", ZTP_SERIALS_URL, json_body=body, retryable=True
            )
            data = check_ztp_write(data, "ZTP serial number add")
            added, duplicates = serial_counts(data)
            payload = {
                "serial_numbers": serials,
                "added": added,
                "duplicates": duplicates,
                "response": {"code": ztp_code(data), "message": data.get("message")},
            }
            return finalize(
                f"{added} ZTP serial number(s) registered ({duplicates} already registered)."
                f"\n\n{to_json(payload)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_ztp_serial_numbers",
        title="Delete ZTP Serial Numbers",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_ztp_serial_numbers(
        serial_numbers: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated serial numbers to remove (e.g. 'FOC2329R0CX'), up to 100 "
                    "per call; each must be registered (cnc_list_ztp_serial_numbers)."
                ),
                min_length=1,
                max_length=4000,
            ),
        ],
    ) -> str:
        """Remove device serial numbers from the ZTP allow-list.

        DESTRUCTIVE write — only registered when *_ENABLE_WRITES=true.
        ``DELETE /crosswork/ztp/v1/serialnumbers {"data": [{"serialNumber":
        ...}]}`` (deprecated in the 7.2 documents; the only ZTP API routed
        here) -> code 204 "Deleted Successfully" — EVEN when none of the
        serials exists (verified live 2026-09-15), so the tool first checks
        each one with an exact ``serialNumber`` query and reports the
        unknown ones (an Error when none exists; the known ones are deleted
        and the unknown ones listed otherwise). Ordering rule (verified): a
        serial bound to a ZTP device (``isInUse`` "true") is refused with
        code 400 "Serial Number {X} is in use, cannot be deleted. " and the
        platform then deletes NOTHING from the list — a free serial sent
        alongside an in-use one stays registered, whichever comes first
        (verified with a mixed list, both orders). The tool therefore
        refuses the whole call BEFORE it when any listed serial is in use:
        delete the device first (cnc_delete_ztp_device releases the serial)
        or repoint it (cnc_update_ztp_device with another serial), or leave
        the in-use serial out of the list.

        Args:
            serial_numbers: comma-separated serials.

        Returns:
            str: "N ZTP serial number(s) deleted." followed by JSON
            {"deleted": [serials], "unknown": [serials], "response":
            {"code", "message"}}. "Error: none of the serial numbers ... is
            registered" (nothing sent); "Error: serial number(s) X are bound
            to a ZTP device (isInUse) — delete the device first ... nothing
            deleted" (nothing sent); "Error: ZTP serial number delete failed
            (ZTP answered code 400): Serial Number {X} is in use, cannot be
            deleted. ..." should a serial be bound between the check and the
            call (nothing deleted — verified); "Error: ..." on an API
            failure.
        """
        try:
            serials = split_csv(serial_numbers)
            if not serials:
                raise PlatformError("no serial numbers given (blank after trimming).")
            if len(serials) > MAX_SERIALS_PER_CALL:
                raise PlatformError(
                    f"{len(serials)} serial numbers given; at most {MAX_SERIALS_PER_CALL} per call."
                )
            lookups = await asyncio.gather(
                *(
                    ztp_find(
                        ZTP_SERIALS_QUERY_URL,
                        {"serialNumber": s},
                        "data",
                        "ZTP serial number query",
                    )
                    for s in serials
                )
            )
            known: list[str] = []
            in_use: list[str] = []
            for serial, rows in zip(serials, lookups, strict=True):
                match = next((r for r in rows if _text(r.get("serialNumber"), "") == serial), None)
                if match is None:
                    continue
                known.append(serial)
                if serial_in_use(match):
                    in_use.append(serial)
            unknown = [s for s in serials if s not in known]
            if not known:
                raise PlatformError(
                    f"none of the serial numbers {', '.join(serials)} is registered with ZTP "
                    "(cnc_list_ztp_serial_numbers) — nothing to delete."
                )
            if in_use:
                # Verified: the platform refuses the WHOLE list when one serial is in use, so
                # a mixed list can never partially delete — refuse it here, before the call.
                raise PlatformError(
                    f"serial number(s) {', '.join(in_use)} are bound to a ZTP device (isInUse) "
                    "— delete the device first (cnc_delete_ztp_device) or repoint it "
                    "(cnc_update_ztp_device), or leave them out of the list; nothing deleted."
                )
            body = {"data": [{"serialNumber": s} for s in known]}
            data = await client.request_json("DELETE", ZTP_SERIALS_URL, json_body=body)
            if (
                isinstance(data, dict)
                and as_int(data.get("code")) not in ZTP_WRITE_OK
                and "in use" in ztp_message(data).lower()
            ):
                # A serial bound between the check and the call (the platform's verified
                # answer — nothing deleted).
                raise PlatformError(
                    f"ZTP serial number delete failed (ZTP answered code "
                    f"{as_int(data.get('code'))}): {ztp_message(data)} — nothing deleted; a "
                    "serial bound to a ZTP device cannot be removed: delete the device first "
                    "(cnc_delete_ztp_device) or give it another serial (cnc_update_ztp_device)."
                )
            data = check_ztp_write(data, "ZTP serial number delete")
            payload = {
                "deleted": known,
                "unknown": unknown,
                "response": {"code": ztp_code(data), "message": data.get("message")},
            }
            text = f"{len(known)} ZTP serial number(s) deleted."
            if unknown:
                text += f" Not registered (skipped): {', '.join(unknown)}."
            return finalize(f"{text}\n\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_ztp_static_route",
        title="Create ZTP Static Route",
        read_only=False,
        idempotent=False,
    )
    async def cnc_create_ztp_static_route(
        subnet: Annotated[
            str,
            Field(
                description="IPv4 network address of the ZTP device subnet (e.g. '10.3.2.0').",
                min_length=7,
                max_length=15,
            ),
        ],
        prefix_length: Annotated[
            int, Field(description="Prefix length of the subnet (e.g. 24).", ge=1, le=32)
        ],
        wait_seconds: Annotated[
            int,
            Field(
                description=(
                    "How long to wait for the asynchronous add to settle (the route settles to "
                    "'success' within ~3 s — verified); 0 returns right after the request."
                ),
                ge=0,
                le=MAX_ROUTE_WAIT_SECONDS,
            ),
        ] = DEFAULT_ROUTE_WAIT_SECONDS,
    ) -> str:
        """Add a ZTP static route — a subnet Crosswork routes towards the ZTP DHCP
        relay's gateway so devices off the Crosswork data network can be onboarded.

        Write — only registered when *_ENABLE_WRITES=true; the POST is never
        auto-retried. ``POST /crosswork/ztp/v1/staticroutes {"staticroutes":
        [{"subnet", "mask": "<prefix length>"}]}`` (deprecated in the 7.2
        documents but the only ZTP API routed on this build) -> code 201
        "Add static route is initiated. Updating the status." — the platform
        installs the route ASYNCHRONOUSLY: the route appears in
        cnc_list_ztp_static_routes as ``add-inprogress`` and settles to
        ``status`` "success" with ``message`` "Route-<subnet>/<mask>,<data
        ip>-Success" within about 3 s (verified live 2026-09-15). The tool
        polls the routes every second for ``wait_seconds`` and returns the
        settled record (uuid, status, message). Only ``success`` was seen
        as the terminal status; a route that settles to anything else (the
        installer's failure spellings are unverified — e.g. an unreachable
        gateway) is reported as NOT installed, with the record's ``message``.
        Duplicate -> code 400 "<subnet>/<mask> : Route already exists". The
        subnet is validated here as an IPv4 network address for the prefix
        (ZTP's own answer to a host address is unverified). The route
        changes the Crosswork host's routing — remove it with
        cnc_delete_ztp_static_route.

        Args:
            subnet, prefix_length: the network.
            wait_seconds: settle wait (0 = none).

        Returns:
            str: "ZTP static route <subnet>/<mask> added (uuid <uuid>, status
            success)." followed by JSON {"route": <route view>, "settled":
            bool, "installed": bool, "elapsed_seconds", "response": {"code",
            "message"}}; when the route settled to another status: "...
            settled with status <status> — <message>; the platform did not
            install it (cnc_list_ztp_static_routes shows the record,
            cnc_delete_ztp_static_route removes it)" with installed=false;
            when it is still in progress after the wait the text says so
            ("... not settled yet (add-inprogress) after Ns; call
            cnc_list_ztp_static_routes") — neither is an "Error:". "Error:
            subnet ... is not a valid IPv4 network address ..." (nothing
            sent); "Error: ZTP static route add failed (ZTP answered code
            400): <subnet>/<mask> : Route already exists"; "Error: ..." on an
            API failure.
        """
        try:
            network = validate_ipv4_subnet(subnet, prefix_length)
            mask = str(prefix_length)
            body = {"staticroutes": [{"subnet": network, "mask": mask}]}
            data = await ztp_write("POST", ZTP_STATIC_ROUTES_URL, body, "ZTP static route add")
            finished, route, elapsed = await wait_until(
                lambda: routes_now(),
                lambda routes: (
                    route_settled(find_route(routes, network, mask))
                    and find_route(routes, network, mask) is not None
                ),
                timeout_seconds=float(wait_seconds),
                interval_seconds=ROUTE_POLL_SECONDS,
            )
            record = find_route(route, network, mask)
            view = route_view(record) if record else None
            settled = bool(finished and record)
            installed = settled and route_installed(record)
            payload = {
                "route": view,
                "settled": settled,
                "installed": installed,
                "elapsed_seconds": round(elapsed, 1),
                "response": {"code": ztp_code(data), "message": data.get("message")},
            }
            label = f"ZTP static route {network}/{mask}"
            if record and installed:
                text = (
                    f"{label} added (uuid {_text(record.get('uuid'))}, status "
                    f"{_text(record.get('status'))})."
                )
            elif record and settled:
                text = (
                    f"{label} settled with status {_text(record.get('status'))} — "
                    f"{_text(record.get('message'), 'no message')}; the platform did not "
                    f"install it (uuid {_text(record.get('uuid'))}: cnc_list_ztp_static_routes "
                    "shows the record, cnc_delete_ztp_static_route removes it)."
                )
            elif record:
                text = (
                    f"{label} requested but not settled yet ({_text(record.get('status'))}) "
                    f"after {elapsed:.0f}s; call cnc_list_ztp_static_routes to see it settle."
                )
            else:
                text = (
                    f"{label} requested (ZTP answered code {ztp_code(data)}: "
                    f"{_text(data.get('message'), '-')}); the route was not listed yet after "
                    f"{elapsed:.0f}s — call cnc_list_ztp_static_routes."
                )
            return finalize(f"{text}\n\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_ztp_static_route",
        title="Delete ZTP Static Route",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_ztp_static_route(
        uuid: Annotated[
            str,
            Field(
                description="uuid of the route (from cnc_list_ztp_static_routes).",
                min_length=1,
                max_length=100,
            ),
        ],
        wait_seconds: Annotated[
            int,
            Field(
                description=(
                    "How long to wait for the asynchronous delete to finish (the route is gone "
                    "within ~5 s — verified); 0 returns right after the request."
                ),
                ge=0,
                le=MAX_ROUTE_WAIT_SECONDS,
            ),
        ] = DEFAULT_ROUTE_WAIT_SECONDS,
    ) -> str:
        """Delete a ZTP static route.

        DESTRUCTIVE write — only registered when *_ENABLE_WRITES=true. ``DELETE
        /crosswork/ztp/v1/staticroutes {"staticroutes": [{"uuid": ...}]}``
        (deprecated in the 7.2 documents; the only ZTP API routed here) ->
        code 201 "Delete static route is initiated. Updating the status." —
        ASYNCHRONOUS: the route shows ``delete-inprogress`` and disappears
        within about 5 s (verified live 2026-09-15); the tool polls every
        second for ``wait_seconds`` and reports whether it is gone. Unknown
        uuid -> code 400 "<uuid> : Route does not exists" (reported as not
        found); a route still settling -> code 400 "<subnet>/<mask> : Route is
        already in Inprogress state" (wait and retry).

        Args:
            uuid: the route's uuid.
            wait_seconds: completion wait (0 = none).

        Returns:
            str: "ZTP static route <subnet>/<mask> (<uuid>) deleted." followed
            by JSON {"route": <the view before>, "gone": bool,
            "elapsed_seconds", "response": {"code", "message"}}; when the
            route is still listed after the wait: "... delete requested, still
            listed as <status> after Ns ..." (not an error). "Error: no ZTP
            static route with uuid <uuid> ..." for the verified not-found
            answer; "Error: ZTP static route delete failed (ZTP answered code
            400): ... Route is already in Inprogress state"; "Error: ..." on
            an API failure.
        """
        try:
            wanted = uuid.strip()
            before = find_route_by_uuid(await routes_now(), wanted)
            body = {"staticroutes": [{"uuid": wanted}]}
            data = await client.request_json("DELETE", ZTP_STATIC_ROUTES_URL, json_body=body)
            if isinstance(data, dict) and "does not exist" in ztp_message(data).lower():
                raise PlatformError(
                    f"no ZTP static route with uuid {wanted} (ZTP answered code "
                    f"{as_int(data.get('code'))}: {ztp_message(data)}); "
                    "cnc_list_ztp_static_routes shows the uuids."
                )
            data = check_ztp_write(data, "ZTP static route delete")
            finished, routes, elapsed = await wait_until(
                lambda: routes_now(),
                lambda routes: find_route_by_uuid(routes, wanted) is None,
                timeout_seconds=float(wait_seconds),
                interval_seconds=ROUTE_POLL_SECONDS,
            )
            still = find_route_by_uuid(routes, wanted)
            view = route_view(before) if before else None
            label = (
                f"ZTP static route {_text(before.get('subnet'))}/{_text(before.get('mask'))} "
                f"({wanted})"
                if before
                else f"ZTP static route {wanted}"
            )
            payload = {
                "route": view,
                "gone": still is None,
                "elapsed_seconds": round(elapsed, 1),
                "response": {"code": ztp_code(data), "message": data.get("message")},
            }
            if still is None:
                text = f"{label} deleted."
            else:
                text = (
                    f"{label} delete requested, still listed as {_text(still.get('status'))} "
                    f"after {elapsed:.0f}s; call cnc_list_ztp_static_routes to see it go."
                )
            return finalize(f"{text}\n\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_ztp_device",
        title="Create ZTP Device",
        read_only=False,
        idempotent=False,
    )
    async def cnc_create_ztp_device(
        host_name: Annotated[
            str,
            Field(
                description="Unique host name for the device (e.g. 'pe9').",
                min_length=1,
                max_length=253,
            ),
        ],
        serial_number: Annotated[
            str,
            Field(
                description=(
                    "The device's serial number (ONE — ZTP allows a single serial per device), "
                    "e.g. 'FOC2329R0CX'. Must be registered first (cnc_add_ztp_serial_numbers) "
                    "unless register_serial is true."
                ),
                min_length=1,
                max_length=100,
            ),
        ],
        credential_profile: Annotated[
            str,
            Field(
                description="Name of an existing credential profile (e.g. 'cml-xrd').",
                min_length=1,
                max_length=100,
            ),
        ],
        platform: Annotated[
            str,
            Field(
                description=(
                    "OS platform (osPlatform, e.g. 'IOS XR') — required even with a profile."
                ),
                min_length=1,
                max_length=100,
            ),
        ],
        profile_name: Annotated[
            str,
            Field(
                description=(
                    "Name of the ZTP profile to onboard with (cnc_list_ztp_profiles) — the "
                    "PROFILE form: version / family / config come from it. Blank for the "
                    "metadata form (config_id + version + device_family)."
                ),
                max_length=200,
            ),
        ] = "",
        config_id: Annotated[
            str,
            Field(
                description="Metadata form: confId of the day-0 file (cnc_list_ztp_config_files).",
                max_length=100,
            ),
        ] = "",
        version: Annotated[
            str,
            Field(
                description="Metadata form: software version — must equal the config file's.",
                max_length=100,
            ),
        ] = "",
        device_family: Annotated[
            str,
            Field(
                description="Metadata form: device family (e.g. 'CISCO NCS540').", max_length=100
            ),
        ] = "",
        secure_ztp: Annotated[
            bool,
            Field(
                description=(
                    "Secure ZTP (SZTP) device; default false = classic ZTP. Required with a "
                    "secure profile, and then the serial needs an ownership voucher (OV import "
                    "is not exposed here)."
                )
            ),
        ] = False,
        register_serial: Annotated[
            bool,
            Field(
                description=(
                    "Register the serial number first (cnc_add_ztp_serial_numbers) so the "
                    "create does not fail with 'Serial Number(s) not present in allowed list'. "
                    "The registration is NOT rolled back when the device create then fails "
                    "(cnc_delete_ztp_serial_numbers removes it)."
                ),
            ),
        ] = False,
    ) -> str:
        """Register a device for zero-touch onboarding — a ZTP device record (host name,
        serial, credential profile, and the profile or day-0 file it boots with) that
        stays ``Unprovisioned`` until the device actually boots and calls in.

        Write — only registered when *_ENABLE_WRITES=true; the POST is never
        auto-retried. ``POST /crosswork/ztp/v1/devices {"nodes": [{hostName,
        serialNumber: [one], credentialProfile, osPlatform, status:
        "Unprovisioned", isSecureZtp, enableOption82: "false", profileName |
        config + version + deviceFamily}]}`` (deprecated in the 7.2 documents
        but the only ZTP API routed on this build) -> code 201 "Device Added
        Successfully" (verified live 2026-09-15) — WITHOUT the uuid, so the
        tool then queries the device by its exact host name and returns the
        record (``uuid``, the profile-derived ``config`` / ``configName`` /
        ``version`` / ``deviceFamily``, ``status``). The serial becomes
        ``isInUse`` "true".

        Ordering rules (all verified — a failure is code 422 with one line per
        rule, reported verbatim with a hint): the serial must be registered
        FIRST ("Serial Number(s) not present in allowed list: X" —
        cnc_add_ztp_serial_numbers, or ``register_serial``); the credential
        profile must exist ("Credential Profile not found."); with a profile,
        do not pass version / family / config ("Cannot specify the 'Version'
        along with profile."); the profile must exist ("Profile with name X
        does not exist"); in the metadata form the version must equal the
        config file's ("Version doesn't match with: Day0-config"); host names
        and serials are unique ("Device with HostName X already exist.",
        "Device with SerialNumber X already exist."); one serial only
        ("Maximum of 1 serial number(s) are allowed."); a secure-ZTP profile
        (isSecureZtp true — any profile carrying a Pre-config / Post-config)
        needs ``secure_ztp`` true on the device ("Cannot associate the
        Secure ZTP enabled Profile to secure ZTP disabled Device."), and a
        secure device needs an ownership voucher on its serial ("Can not
        associate serial(s) X with secure ZTP enabled device as OV is not
        linked." — the OV import is not exposed, so ``secure_ztp`` could
        not be exercised to a successful create). The DHCP Option-82
        (remote-id / circuit-id) form, IP/MAC pre-assignment and the
        Crosswork provider binding are not exposed. Not idempotent: a repeat
        fails on the unique host name. With ``register_serial`` the serial
        is registered FIRST and stays registered when the device create then
        fails (verified — e.g. "Credential Profile not found."): the error
        says so; cnc_delete_ztp_serial_numbers removes it.

        Args:
            host_name, serial_number, credential_profile, platform: required.
            profile_name OR config_id + version + device_family: the boot bundle.
            secure_ztp, register_serial: optional.

        Returns:
            str: "ZTP device '<host>' created (uuid <uuid>, status
            Unprovisioned)." followed by JSON {"device": <device view>,
            "sent": {<node>}, "serial_registered": {"added", "duplicates"} |
            null, "response": {"code", "message"}}. "Error: pass either
            profile_name alone or config_id + version + device_family ..."
            (nothing sent); "Error: ZTP device create failed (ZTP answered
            code 422): <host>: <errorMsg>; ... <hints>" — followed by "Note:
            serial <serial> was registered by register_serial ... and STAYS
            registered" when the registration happened; "Error: ..." on an
            API failure.
        """
        try:
            validate_device_form(profile_name, config_id, version, device_family)
            node = device_body(
                host_name=host_name,
                serial_number=serial_number,
                credential_profile=credential_profile,
                platform=platform,
                profile_name=profile_name,
                config_id=config_id,
                version=version,
                device_family=device_family,
                secure_ztp=secure_ztp,
            )
            registered = None
            if register_serial:
                serial_data = await client.request_json(
                    "POST",
                    ZTP_SERIALS_URL,
                    json_body={"data": [{"serialNumber": node["serialNumber"][0]}]},
                    retryable=True,
                )
                serial_data = check_ztp_write(serial_data, "ZTP serial number add")
                added, duplicates = serial_counts(serial_data)
                registered = {"added": added, "duplicates": duplicates}
            try:
                data = await ztp_write(
                    "POST", ZTP_DEVICES_URL, {"nodes": [node]}, "ZTP device create"
                )
            except Exception as e:
                if registered is None:
                    raise
                # Verified: the registration is not rolled back by a failed device create.
                serial = node["serialNumber"][0]
                return (
                    f"{format_error(e)} Note: serial {serial} was registered by register_serial "
                    f"before the device create failed ({registered['added']} added, "
                    f"{registered['duplicates']} already registered) and STAYS registered — "
                    "cnc_delete_ztp_serial_numbers removes it."
                )
            record = await device_by_host(node["hostName"])
            view = device_view(record) if record else {}
            payload = {
                "device": view or None,
                "sent": node,
                "serial_registered": registered,
                "response": {"code": ztp_code(data), "message": data.get("message")},
            }
            ident = _text(view.get("uuid"), "uuid not found by host name — cnc_list_ztp_devices")
            return finalize(
                f"ZTP device '{node['hostName']}' created (uuid {ident}, status "
                f"{_text(view.get('status'), ZTP_UNPROVISIONED)}).\n\n{to_json(payload)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_ztp_device",
        title="Update ZTP Device",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_update_ztp_device(
        uuid: Annotated[
            str,
            Field(
                description="uuid of the ZTP device (from cnc_list_ztp_devices).",
                min_length=1,
                max_length=100,
            ),
        ],
        host_name: Annotated[
            str | None,
            Field(
                description="New host name (e.g. 'pe9'); omit to keep (never blank).",
                min_length=1,
                max_length=253,
            ),
        ] = None,
        serial_number: Annotated[
            str | None,
            Field(
                description=(
                    "New serial number (e.g. 'FOC2329R0CY', registered first — "
                    "cnc_add_ztp_serial_numbers); the old one is released. Omit to keep "
                    "(never blank)."
                ),
                min_length=1,
                max_length=100,
            ),
        ] = None,
        credential_profile: Annotated[
            str | None,
            Field(
                description="New credential profile name (e.g. 'cml-xrd'); omit to keep.",
                min_length=1,
                max_length=100,
            ),
        ] = None,
        platform: Annotated[
            str | None,
            Field(
                description="New OS platform (e.g. 'IOS XR'); omit to keep.",
                min_length=1,
                max_length=100,
            ),
        ] = None,
        profile_name: Annotated[
            str | None,
            Field(
                description=(
                    "New ZTP profile name (switches to the profile form); '' switches to the "
                    "metadata form (config_id / version / device_family, else the device's "
                    "current values); omit to keep the current form."
                ),
                max_length=200,
            ),
        ] = None,
        config_id: Annotated[
            str | None,
            Field(description="Metadata form: new day-0 confId; omit to keep.", max_length=100),
        ] = None,
        version: Annotated[
            str | None,
            Field(
                description="Metadata form: new version (must equal the file's); omit to keep.",
                max_length=100,
            ),
        ] = None,
        device_family: Annotated[
            str | None,
            Field(description="Metadata form: new device family; omit to keep.", max_length=100),
        ] = None,
        secure_ztp: Annotated[
            bool | None, Field(description="Secure ZTP flag; omit to keep.")
        ] = None,
    ) -> str:
        """Update an Unprovisioned ZTP device — host name, serial, credential profile,
        platform, secure-ZTP flag, or the profile / day-0 file it will boot with.

        Write, destructive (the record is overwritten) — only registered when
        *_ENABLE_WRITES=true. The tool queries the device by ``uuid`` (exact
        filter, verified), rebuilds the create form from the record with the
        given changes and sends ``PUT /crosswork/ztp/v1/devices`` (deprecated
        in the 7.2 documents; the only ZTP API routed here) -> code 200
        "Device Updated Successfully" (verified live 2026-09-15: rename and
        serial swap — the old serial goes back to ``isInUse`` "false"; a
        profile-form device switched to the metadata form with
        ``profileName: ""`` + config / version / family), then queries it
        again and returns it. Why the rebuild (verified): echoing the query
        record back fails — its string ``lastUpdated`` is a code-422
        unmarshal error and its profile-derived ``version`` / ``deviceFamily``
        / ``config`` are refused next to ``profileName`` ("Cannot specify the
        'Version' along with profile."). Rules (verified): the body must carry
        ``status`` "Unprovisioned" (anything else is code 304 "status must be
        Unprovisioned only"; the document allows updates only while the
        device IS Unprovisioned — the tool refuses a device in any other
        status before the call, since it has started booting); one serial;
        metadata-form version must equal the file's ("Version doesn't match
        with: Day0-config"); unknown uuid -> code 404 "1) Device with UUID :
        X does not exist.". The onboarding status itself is not changeable
        here (``PATCH devices`` is not exposed).

        Args:
            uuid: the device's uuid.
            host_name, serial_number, credential_profile, platform, profile_name,
                config_id, version, device_family, secure_ztp: the changes
                (omit = keep). host_name, serial_number, credential_profile
                and platform are required fields of the record and cannot be
                blanked (schema min_length 1; whitespace-only is refused
                here) — only profile_name legitimately takes ''.

        Returns:
            str: "ZTP device '<host>' (<uuid>) updated (<changed keys>)."
            followed by JSON {"device": <view after>, "before": <view
            before>, "sent": {<PUT body>}, "response": {"code",
            "message"}}. "Error: no ZTP device with uuid <uuid> ..."
            (nothing sent); "Error: ZTP device <host> is <status>, not
            Unprovisioned — ..." (nothing sent); "Error: nothing to change
            ..."; "Error: host_name / ... must not be blank" (nothing sent);
            "Error: ZTP device update failed (ZTP answered code N): <host>:
            <errorMsg>; ... <hints>"; "Error: ..." on an API failure.
        """
        try:
            wanted = uuid.strip()
            changes: dict[str, Any] = {
                "host_name": host_name,
                "serial_number": serial_number,
                "credential_profile": credential_profile,
                "platform": platform,
                "profile_name": profile_name,
                "config_id": config_id,
                "version": version,
                "device_family": device_family,
                "secure_ztp": secure_ztp,
            }
            changed = [k for k, v in changes.items() if v is not None]
            if not changed:
                raise PlatformError("nothing to change: pass at least one value to update.")
            blank = [
                k
                for k in ("host_name", "serial_number", "credential_profile", "platform")
                if isinstance(changes[k], str) and not changes[k].strip()
            ]
            if blank:
                raise PlatformError(
                    f"{', '.join(blank)} must not be blank — these are required fields of the "
                    "device record; omit them to keep the current values."
                )
            current = await device_by_uuid(wanted)
            if current is None:
                raise PlatformError(
                    f"no ZTP device with uuid {wanted} (the uuid query matched nothing; "
                    "cnc_list_ztp_devices shows the uuids)."
                )
            status = _text(current.get("status"), "")
            if status.lower() != ZTP_UNPROVISIONED.lower():
                raise PlatformError(
                    f"ZTP device {_text(current.get('hostName'))} is {status or '?'}, not "
                    "Unprovisioned — ZTP updates a device only before it starts booting "
                    "(refused before the call; the platform answers code 304 'status must be "
                    "Unprovisioned only' for any other status)."
                )
            body = device_update_body(current, changes)
            data = await ztp_write("PUT", ZTP_DEVICES_URL, body, "ZTP device update")
            after = await device_by_uuid(wanted)
            payload = {
                "device": device_view(after) if after else None,
                "before": device_view(current),
                "sent": body,
                "response": {"code": ztp_code(data), "message": data.get("message")},
            }
            return finalize(
                f"ZTP device '{body['hostName']}' ({wanted}) updated ({', '.join(changed)})."
                f"\n\n{to_json(payload)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_ztp_device",
        title="Delete ZTP Device",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_ztp_device(
        uuid: Annotated[
            str,
            Field(
                description="uuid of the ZTP device to delete (from cnc_list_ztp_devices).",
                min_length=1,
                max_length=100,
            ),
        ],
    ) -> str:
        """Delete a ZTP device record and release its serial number.

        DESTRUCTIVE write — only registered when *_ENABLE_WRITES=true. ``DELETE
        /crosswork/ztp/v1/devices {"nodes": [{"uuid": ...}]}`` (deprecated in
        the 7.2 documents; the only ZTP API routed here) -> ``{"code": 200}``
        and the serial's ``isInUse`` goes back to "false" (verified live
        2026-09-15). The tool queries the device by ``uuid`` first (exact
        filter, verified) and refuses an unknown uuid before the call; the
        platform's own answer for one is ALSO code 200, with ``message``
        "1) Device with UUID : X does not exist." — reported as not found
        should the device vanish between the two calls. The record only (a
        device that already onboarded stays in the inventory —
        cnc_delete_device removes it there); the serial number and the
        profile / file it referenced are kept.

        Args:
            uuid: the device's uuid.

        Returns:
            str: "ZTP device '<host>' (<uuid>) deleted; serial <serial>
            released." followed by JSON {"device": <the view before>,
            "response": {"code", "message"}}. "Error: no ZTP device with
            uuid <uuid> (the uuid query matched nothing ...)" (nothing
            sent); "Error: no ZTP device with uuid <uuid> (ZTP answered
            ...)" for the race; "Error: ZTP device delete failed (ZTP
            answered code N): <message>"; "Error: ..." on an API failure.
        """
        try:
            wanted = uuid.strip()
            before = await device_by_uuid(wanted)
            if before is None:
                raise PlatformError(
                    f"no ZTP device with uuid {wanted} (the uuid query matched nothing; "
                    "cnc_list_ztp_devices shows the uuids) — nothing sent."
                )
            data = await client.request_json(
                "DELETE", ZTP_DEVICES_URL, json_body={"nodes": [{"uuid": wanted}]}
            )
            data = check_ztp_write(data, "ZTP device delete")
            missing = device_not_deleted(data)
            if missing:
                raise PlatformError(
                    f"no ZTP device with uuid {wanted} (ZTP answered code {ztp_code(data)}: "
                    f"{missing}); cnc_list_ztp_devices shows the uuids."
                )
            view = device_view(before) if before else None
            serials = ", ".join((view or {}).get("serialNumber") or []) or "-"
            host = _text((view or {}).get("hostName"), "?")
            payload = {
                "device": view,
                "response": {"code": ztp_code(data), "message": data.get("message")},
            }
            return finalize(
                f"ZTP device '{host}' ({wanted}) deleted; serial {serials} released."
                f"\n\n{to_json(payload)}",
                settings,
            )
        except Exception as e:
            return format_error(e)
