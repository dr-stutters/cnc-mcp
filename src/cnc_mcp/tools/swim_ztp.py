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
exposed here; the ZTP writes (add/import/delete of serials, profiles,
devices, routes) are not.

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

All of SWIM, ZTP, configsvc and imagesvc are flagged ``deprecated: true``
on every operation of the 7.2 OpenAPI set; they are still routed and
answering on the lab.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Annotated, Any
from urllib.parse import quote

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.errors import PlatformError, format_error
from cnc_mcp.formatting import ResponseFormat, epoch_iso, finalize, pagination_envelope, to_json
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
CONFIGS_URL = f"{CONFIGSVC}/configs"
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
        "preConfigName": profile.get("preConfigName"),
        "postConfigName": profile.get("postConfigName"),
        "isSecureZtp": profile.get("isSecureZtp"),
        "profileCategory": profile.get("profileCategory"),
        "profileDescription": profile.get("profileDescription"),
        "isConfigInvalid": profile.get("isConfigInvalid"),
        "isImageInvalid": profile.get("isImageInvalid"),
        "lastUpdated": profile.get("lastUpdated"),
    }


def profile_line(view: dict[str, Any]) -> str:
    extras = []
    if view.get("imageName"):
        extras.append(f"image {view['imageName']}")
    if str(view.get("isSecureZtp")).lower() == "true":
        extras.append("secure ZTP")
    if view.get("isConfigInvalid") or view.get("isImageInvalid"):
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
        profile: cnc_list_ztp_devices. Creating/deleting profiles is not
        exposed.

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
                    f"No ZTP profiles{scope}. Profiles are created in the Crosswork UI (Device "
                    "Management > Zero Touch Profiles) from a day-0 configuration file "
                    "(cnc_list_ztp_config_files) and an image (cnc_list_ztp_images).",
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
        finished onboarding also appears in cnc_list_devices. Adding /
        updating / deleting ZTP devices is not exposed.

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
                    f"No ZTP devices{scope}. Devices are registered for ZTP in the Crosswork "
                    "UI (Device Management > Zero Touch Devices) or by CSV import; onboarded "
                    "devices are listed by cnc_list_devices.",
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
        fields — not exposed (unverified). Adding / importing / deleting
        serials is not exposed.

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
                    f"No ZTP serial numbers{scope}. Serials are added in the Crosswork UI "
                    "(Device Management > Serial Number and OV Import) or by CSV / ownership "
                    "voucher import.",
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
        (unverified). Adding / deleting routes is not exposed.

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
                    "No ZTP static routes. Routes are added in the Crosswork UI (Device "
                    "Management > Zero Touch Provisioning > Static Routes) when ZTP devices sit "
                    "behind a relay off the Crosswork data network.",
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
        page: Annotated[int, Field(description=_SVC_PAGE_DESC, ge=0)] = 1,
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
        whatever the guard dropped). If page 1 comes back empty while the
        count is not 0, the service counts from 0 — call again with
        page=0. The file text is not exposed
        (``configs/files/<confId>`` is a download); uploading / deleting
        files is not exposed.

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
                    "Files are uploaded in the Crosswork UI (Device Management > Zero Touch "
                    "Provisioning > Configuration Files)."
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
        again with page=0.
        The SWIM repository (images for distribution/activation on managed
        devices) is cnc_list_software_images. Uploading / deleting ZTP
        images is not exposed.

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
