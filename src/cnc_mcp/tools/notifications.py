"""Notifications: the streams catalogue, webhook (connection-less) subscriptions,
external Kafka/gRPC subscriptions and the per-topic clear.

Crosswork can push alarm and inventory notifications to external consumers in
three ways (the streams document, ``cnc_list_notification_streams``, lists
them as the platform advertises them):

1. **Connection-less webhook subscriptions** — the caller registers an HTTP(S)
   URL and a topic (``alarm`` | ``inventory``) with a format (``json`` |
   ``xml``); the platform then POSTs every notification of that topic to the
   URL as JSON or XML. These are what ``cnc_create_webhook_subscription`` /
   ``cnc_delete_notification_subscription`` drive, and what the subscription
   list/get tools show (``connection-type "connection-less"``).
2. **WebSocket streams (connection-oriented)** — a client opens
   ``wss://.../crosswork/notification/restconf/streams/v2/alarm.json`` (or the
   inventory / filtered variants) and receives notifications while the socket
   is up. NOT driven by these tools (an MCP tool call cannot hold a socket);
   the streams tool only reports the locations. Such sessions appear in the
   admin subscription list while they are open.
3. **Kafka / gRPC ("external") subscriptions**
   (``/crosswork/notification/v2/subscription``) — the platform publishes a
   data type (alarms, inventory changes, system audit, the PM feeds) to a
   Kafka or gRPC Data Destination on a topic of the caller's choosing.
   ``cnc_list_kafka_subscriptions`` reads the list;
   ``cnc_create_external_subscription`` / ``cnc_delete_external_subscription``
   create and delete them (see the wire facts below).

Wire facts (verified live 2026-09-13 on the 7.2 lab with a real webhook sink —
an nginx that answers 200 ``{}`` to everything):

- Base :data:`NOTIFICATIONS` = ``/crosswork/notification/restconf/data/v2``,
  EMF dialect: JSON only for exactly ``Accept: application/json``
  (:data:`cnc_mcp.emf.EMF_HEADERS`), the ``com.response-message`` envelope,
  errors as ``rc.errors`` with a single ``error`` OBJECT carrying an
  ``error-app-tag`` (``NOT.xxxx``). Every payload key is the verbatim
  ``ietf-restconf:notification.<field>`` name — the bare spelling
  (``clientUrl``) is answered 400 Bad Request.
- ``GET notifications:subscription`` (own) / ``notifications:subscription-admin``
  (every user) answer the same envelope; **a single subscription is an OBJECT
  under ``ietf-restconf:notification.subscription``, several are a list**,
  none is ``com.lastIndex -1`` without ``com.data`` — :func:`cnc_mcp.emf.unwrap`
  handles all three (the object becomes a one-item list). Both GETs document
  ``.startIndex`` / ``.maxCount`` paging with the EMF 100-object cap (7.2 spec;
  the paging parameters themselves were not exercised live on this base).
  :func:`subscription_items` also accepts, defensively, a bare subscription
  object or a bare ``{"ietf-restconf:notification.subscription": ...}`` and
  RAISES for any other document, so an answer the tool does not understand is
  never reported as "no subscriptions" / "not found".
- **The client-url MUST carry an explicit port**: ``http://h/path`` is answered
  with a bare Spring ``500 Internal Server Error`` (the body was not recorded),
  ``http://h:80/path`` works. :func:`validate_client_url` refuses a URL without
  one before anything is sent. An empty-bodied 500 that still comes back is
  reported by :func:`bare_500_error` as the platform rejecting a client-url
  form it cannot use (or a failed reachability probe) — the only verified
  causes on this endpoint — never with the generic empty-500 hint of
  :func:`cnc_mcp.errors.http_error`, which describes other services.
- **The platform probes the endpoint before subscribing**: an unreachable URL
  is 500 ``rc.errors`` ``NOT.0029 "The endpoint is not reachable."``; a
  reachable endpoint that answers non-2xx to the probe also fails (its error
  tag was not recorded). A duplicate (same topic + URL + format) is 500
  ``NOT.0006 "Subscription already exists for the given topic, endpoint (and
  format)"``.
- ``GET notifications:subscription/<id>`` → the object (the tool re-checks the
  id client-side, as Crosswork RESTCONF keyed GETs have been seen to ignore
  their key elsewhere); unknown id → 400 ``NOT.0016 "Unable to find
  subscription"``. ``DELETE`` → 200 with the text ``Success``; unknown id → 400
  ``NOT.0037 "There is no subscription for given subscriptionId"``. Any OTHER
  ``rc.errors`` answer — on EVERY tool of this base, the list and streams GETs
  included — is rendered by this module as "EMF RESTCONF rejected the request
  (HTTP <n>): <error-tag> [<error-app-tag>]: <error-message>" so the
  notification service's own NOT.xxxx tags reach the agent verbatim
  (:func:`rejection` / :func:`emf_body` are the one ladder every tool uses:
  rc.errors → :func:`emf_rejection`, else :func:`cnc_mcp.errors.http_error`).
  A 2xx DELETE whose body is not the verified ``Success`` text is reported as
  unconfirmed rather than as deleted (this platform routinely rides
  application failures inside HTTP 200).
- ``GET /crosswork/notification/v2/subscription`` (Kafka/gRPC) → 200 with an
  EMPTY body when there are none; with some (verified live 2026-09-15)
  ``{"subscriptionList": [{"createTime", "destinationName", "destinationType",
  "filter", "subscriptionData", "subscriptionDataType", "topicName",
  "userName"}]}``.

External (Kafka/gRPC) subscription writes — verified live 2026-09-15 against
throwaway ``phase-d-kafka`` / ``phase-d-grpc`` destinations created with
``DISPATCH_SOURCE application`` (plain JSON Spring service, no envelope;
**every application failure of the POST rides inside HTTP 200**):

- ``POST /crosswork/notification/v2/subscription {"destinationName",
  "destinationType": "Kafka"|"gRPC", "topicName", "subscriptionDataType",
  "subscriptionData"?, "filter"?}`` → 200 ``{"result": "Create Successful"}``.
  200 ``{"result": "A subscription with this topic name already exists. Please
  choose a different topic name."}`` — the topic name is the platform-wide
  key. 200 ``{"result": "Destination does not exist or might be a data-gateway
  destination, which is not allowed for external subscriptions."}`` for an
  unknown destination name, a destination whose ``DISPATCH_SOURCE`` is
  ``datagateway`` (every system-defined one, ``CW_KAFKA_DESTINATION`` and
  ``cdg-common-pipeline`` included — external subscriptions need a destination
  created with ``DISPATCH_SOURCE`` ``application`` or ``any``), AND for a
  ``destinationType`` that does not match the destination's kind (a gRPC
  destination named with type Kafka, or the reverse), AND for the right name
  in the wrong case (``Phase-D-KAFKA`` for ``phase-d-kafka``): the lookup is
  by exact name + type. Parameter validation is 400 ``{"error": "Following
  param(s) are invalid : <Name>[, <Name>]"}`` with the names ``Topic Name`` (blank),
  ``Destination Name`` (blank), ``Destination Type`` (not exactly ``Kafka`` /
  ``gRPC`` — case-sensitive — or gRPC with a data type other than
  Device_/Network_Performance_Monitoring), ``Subscription Data Type`` (unknown
  or missing; then ``Subscription Data`` is listed too), ``Subscription Data``
  (Network_Performance_Monitoring without ``SR_PM_Interface`` /
  ``SR_PM_Policy``; Device_Performance_Monitoring without a selector;
  Service_Health_Monitoring with a value other than ``Y1731_Probes`` /
  ``PCA_Probes``; ANY subscriptionData on Alarm — the non-PM types take none)
  and ``Filter`` (a filter on a data type other than Inventory_Changes).
  Accepted: ``Inventory_Changes`` with ``filter "Routers"``, ``Alarm`` /
  ``System_Audit`` without extras — with the optional keys absent OR sent as
  explicit ``null`` as in the spec's example — ``Network_Performance_Monitoring``
  + ``SR_PM_Interface`` (Kafka and gRPC), ``Service_Health_Monitoring`` +
  ``Y1731_Probes`` (accepted although Service Health is not installed on the
  lab), ``Device_Performance_Monitoring`` + ``policy_type=OpticalSFP,
  policy_instance=instance1`` (no such policy exists — the selector's content
  is not validated, only its presence).
- ``DELETE /crosswork/notification/v2/subscription {"subscriptionList":
  [{"topicName": ...}]}`` → 200 ``{"result": "Delete Successful"}``. The
  match is on ``topicName`` ALONE: a body with a wrong destinationName,
  destinationType or subscriptionDataType still deleted the subscription of
  that topic, and ``{"topicName"}`` by itself works. Unknown topic → 400
  ``{"result": "Following subscription(s) not found and could not be deleted
  :[<topic>]"}`` (note ``result``, not ``error``); an empty list → 400
  ``{"result": "Please provide at least one valid subscription data to
  delete"}``; no body at all → Spring 415.
- ``POST /crosswork/notification/restconf/data/v2/clear-by-topic/<topic>``
  (no body) → 200 with the text ``Clear successful`` — for a topic with
  subscriptions (a phase-d webhook subscription of topic ``inventory`` was
  gone from ``notifications:subscription-admin`` afterwards), for a topic with
  none (``alarm``) AND for a topic the platform does not know (``nope``): the
  operation validates nothing and reports no count, so
  ``cnc_clear_notification_subscriptions_by_topic`` lists the admin view
  before and after to say what it removed.

Not exposed: ``clear-all-subscriptions`` and ``clear-connection-less`` (one
unscoped call wipes every user's subscriptions of both topics — WebSocket
sessions included, per the spec — with no per-topic limit; the per-topic
clear covers the scoped need) and ``clear-sockets``.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any
from urllib.parse import urlsplit

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.emf import (
    DEFAULT_MAX_COUNT,
    EMF_HEADERS,
    MAX_COUNT,
    decode_json,
    page_envelope_from,
    page_params,
    unwrap,
)
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.safety import AppContext, register_tool
from cnc_mcp.tools.fault import canonical

logger = logging.getLogger(__name__)

NOTIFICATIONS = "/crosswork/notification/restconf/data/v2"
STREAMS_PATH = f"{NOTIFICATIONS}/ietf-restconf-monitoring:restconf-state/streams"
SUBSCRIPTION_PATH = f"{NOTIFICATIONS}/notifications:subscription"
SUBSCRIPTION_ADMIN_PATH = f"{NOTIFICATIONS}/notifications:subscription-admin"
# Kafka/gRPC subscriptions live on a plain-JSON Spring service, not the EMF base.
KAFKA_SUBSCRIPTION_PATH = "/crosswork/notification/v2/subscription"
# Bulk clear of one topic's webhook/WebSocket subscriptions (EMF base, text answer).
CLEAR_BY_TOPIC_PATH = f"{NOTIFICATIONS}/clear-by-topic"
# Read only to EXPLAIN a refused destination (the Data Gateway destinations list).
DESTINATIONS_QUERY_PATH = "/crosswork/dg-manager/v1/destinations/query"
DESTINATIONS_QUERY_BODY: dict[str, Any] = {"limit": 100, "filter": {}}

# External subscription vocabulary (spelling verified live: destinationType is
# case-sensitive on the wire, the data types are the spec's).
DESTINATION_TYPES = ("Kafka", "gRPC")
DATA_TYPES = (
    "Inventory_Changes",
    "Alarm",
    "System_Audit",
    "Device_Performance_Monitoring",
    "Network_Performance_Monitoring",
    "Service_Health_Monitoring",
)
# gRPC destinations take only the two PM feeds (verified: anything else is 400
# "Destination Type").
GRPC_DATA_TYPES = ("Device_Performance_Monitoring", "Network_Performance_Monitoring")
# subscriptionData vocabularies (both verified live: required, closed — an unknown
# value is 400 "Subscription Data"; SHM Y1731_Probes was accepted with Service
# Health not installed).
NPM_SUBSCRIPTION_DATA = ("SR_PM_Interface", "SR_PM_Policy")
SHM_SUBSCRIPTION_DATA = ("Y1731_Probes", "PCA_Probes")
DPM_DATA_TYPE = "Device_Performance_Monitoring"
NPM_DATA_TYPE = "Network_Performance_Monitoring"
SHM_DATA_TYPE = "Service_Health_Monitoring"
FILTER_DATA_TYPE = "Inventory_Changes"
# The three result texts verified live (compared case-insensitively).
EXTERNAL_CREATE_OK = "Create Successful"
EXTERNAL_DELETE_OK = "Delete Successful"
CLEAR_OK = "Clear successful"
# Result-message markers verified live (the service has no error codes).
_EXT_DUPLICATE_MARKER = "already exists"
_EXT_DESTINATION_MARKER = "destination does not exist"
_EXT_NOT_FOUND_MARKER = "not found and could not be deleted"
_EXT_INVALID_MARKER = "are invalid"
# Destination properties (Data Gateway destinations list) read by the diagnosis.
_DISPATCH_ALLOWED = ("application", "any")
_DESTINATION_KIND = {"destination_type_kafka": "Kafka", "destination_type_grpc": "gRPC"}

# Every subscription field on the wire is spelled with this prefix (verbatim).
NS = "ietf-restconf:notification."
SUBSCRIPTION_KEY = f"{NS}subscription"
# Streams document keys (verbatim).
STREAMS_KEY = "rcmon.streams"
STREAM_KEY = "rcmon.stream"

TOPICS = ("alarm", "inventory")
FORMATS = ("json", "xml")
URL_SCHEMES = ("http", "https")

# rc.errors error-app-tags verified live.
APP_TAG_UNREACHABLE = "NOT.0029"  # "The endpoint is not reachable."
APP_TAG_DUPLICATE = "NOT.0006"  # "Subscription already exists for the given topic, endpoint ..."
APP_TAG_GET_UNKNOWN = "NOT.0016"  # "Unable to find subscription"
APP_TAG_DELETE_UNKNOWN = "NOT.0037"  # "There is no subscription for given subscriptionId"
# Message markers used as a fallback when the app tag is absent or re-numbered.
_UNREACHABLE_MARKER = "not reachable"
_DUPLICATE_MARKER = "already exists"
_GET_UNKNOWN_MARKER = "unable to find subscription"
_DELETE_UNKNOWN_MARKER = "no subscription for given"

# Subscription fields rendered in the detail view, in this order (verbatim names
# minus the prefix). Anything else the platform adds is listed after them.
_DETAIL_FIELDS = (
    ("topic", "Topic"),
    ("format", "Format"),
    ("client-url", "Client URL"),
    ("connection-type", "Connection type"),
    ("subscribed-user", "Subscribed user"),
    ("client-ip", "Client IP"),
    ("session-id", "Session ID"),
    ("creation-time", "Created"),
    ("time-of-update", "Updated"),
)


# --- pure helpers (no I/O) -----------------------------------------------------


def field(sub: dict[str, Any], name: str) -> Any:
    """``sub["ietf-restconf:notification.<name>"]`` (bare ``name`` as a fallback), else None."""
    if f"{NS}{name}" in sub:
        return sub[f"{NS}{name}"]
    return sub.get(name)


def validate_client_url(url: str) -> str:
    """The stripped ``client_url`` when it is one the platform accepts, else PlatformError.

    Verified live: a client-url without an explicit port (``http://h/path``) is
    answered with a bare Spring HTTP 500 (the body was not recorded), so the
    tool refuses it BEFORE sending anything and shows the corrected form —
    rebuilt from the host (bracketed for IPv6) and any userinfo, so an empty
    port (``http://h:/path``) is corrected to ``http://h:80/path`` rather than
    ``http://h::80/path``. Also refuses a scheme other than http/https, a
    missing host, and a non-numeric port.
    """
    value = (url or "").strip()
    if not value:
        raise PlatformError("client_url must not be blank (e.g. 'http://sink.example:80/hook').")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as e:
        raise PlatformError(
            f"client_url '{value}' is not a valid URL ({e}); use the form "
            "'http://<host>:<port>/<path>', e.g. 'http://sink.example:80/hook'."
        ) from e
    scheme = (parts.scheme or "").lower()
    if scheme not in URL_SCHEMES:
        raise PlatformError(
            f"client_url '{value}' must use the http or https scheme (got "
            f"'{parts.scheme or 'none'}'), e.g. 'http://sink.example:80/hook'."
        )
    if not parts.hostname:
        raise PlatformError(
            f"client_url '{value}' has no host; use 'http://<host>:<port>/<path>', "
            "e.g. 'http://sink.example:80/hook'."
        )
    if port is None:
        default_port = 443 if scheme == "https" else 80
        path = parts.path or "/"
        # Rebuilt from the parsed parts, not parts.netloc: the netloc keeps an
        # empty ":" (http://h:/path) and would yield "h::80".
        host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        userinfo = ""
        if parts.username is not None:
            userinfo = parts.username
            if parts.password is not None:
                userinfo += f":{parts.password}"
            userinfo += "@"
        corrected = f"{scheme}://{userinfo}{host}:{default_port}{path}"
        if parts.query:
            corrected += f"?{parts.query}"
        raise PlatformError(
            f"client_url '{value}' has no explicit port. Crosswork answers a client-url "
            "without one with a bare HTTP 500 (verified live), so the request was not sent. "
            f"Add the port even when it is the scheme default, e.g. '{corrected}'."
        )
    return value


def rc_error(data: Any) -> dict[str, str]:
    """``{"tag", "app_tag", "message"}`` of the first ``rc.errors`` entry ("" when absent).

    The EMF services answer errors as ``{"rc.errors": {"error": {...}}}`` with a
    single error OBJECT (verified live); a list is accepted too. Any other
    document yields empty strings, so callers can test ``app_tag`` directly.
    """
    empty = {"tag": "", "app_tag": "", "message": ""}
    if not isinstance(data, dict):
        return empty
    block = data.get("rc.errors")
    if not isinstance(block, dict):
        return empty
    entries = block.get("error")
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        return empty
    for entry in entries:
        if isinstance(entry, dict):
            return {
                "tag": str(entry.get("error-tag") or "").strip(),
                "app_tag": str(entry.get("error-app-tag") or "").strip().upper(),
                "message": str(entry.get("error-message") or "").strip(),
            }
    return empty


def error_matches(err: dict[str, str], app_tag: str, marker: str) -> bool:
    """True when an ``rc_error`` result carries ``app_tag`` or ``marker`` in its message."""
    return err["app_tag"] == app_tag.upper() or marker in err["message"].lower()


def is_rc_error(err: dict[str, str]) -> bool:
    """True when an ``rc_error`` result came from a real ``rc.errors`` document (any field set)."""
    return any(err.values())


def emf_rejection(status: int, err: dict[str, str]) -> PlatformError:
    """The PlatformError for an ``rc.errors`` answer none of the verified tags explain.

    Rendered here, not by :func:`cnc_mcp.errors.http_error`: the generic
    RESTCONF hints there describe the topology NBI's YANG keys and would
    misdirect an agent, and this keeps the tools' error texts independent of
    how the shared error module spells RESTCONF documents. Format:
    ``EMF RESTCONF rejected the request (HTTP 400): operation-failed
    [NOT.0001]: Invalid input``.
    """
    detail = err["tag"] or "error"
    if err["app_tag"]:
        detail += f" [{err['app_tag']}]"
    if err["message"]:
        detail += f": {err['message'].rstrip('.')}"
    return PlatformError(
        f"EMF RESTCONF rejected the request (HTTP {status}): {detail}. The error-tag / "
        "error-app-tag / error-message are the notification service's own (NOT.xxxx tags); "
        "check the subscription id or body this tool sent. Verified tags: NOT.0029 endpoint "
        "unreachable, NOT.0006 duplicate, NOT.0016 unknown id (GET), NOT.0037 unknown id "
        "(DELETE)."
    )


def rejection(response: httpx.Response) -> PlatformError:
    """The PlatformError for a non-success answer none of the verified tags explain.

    The one ladder every tool of this module ends in, AFTER its own tag checks
    (NOT.0029 / NOT.0006 / NOT.0016 / NOT.0037): an ``rc.errors`` document,
    whatever the status, becomes :func:`emf_rejection` so the service's own
    NOT.xxxx tags reach the agent verbatim; anything else goes through
    :func:`cnc_mcp.errors.http_error` (403 privilege/path hint, home-app
    fallback, Spring "No static resource", ...). Never called for an
    ``rc.errors`` answer by way of ``ApiClient.request(raise_on_error=True)``
    on purpose: the generic RESTCONF hints there describe the topology NBI's
    YANG keys and would misdirect an agent of this service.
    """
    err = rc_error(_parse_json(response))
    if is_rc_error(err):
        return emf_rejection(response.status_code, err)
    return http_error(response)


def emf_body(response: httpx.Response) -> Any:
    """The decoded body of a notification-service answer, or the PlatformError it means.

    Non-success answers raise :func:`rejection` (rc.errors → the NOT.xxxx tags
    verbatim, else the generic HTTP hint); a 2xx body is decoded with
    :func:`cnc_mcp.emf.decode_json` (empty → None, XML → the Accept-header
    explanation). The read tools call ``client.request(..., raise_on_error=False)``
    and hand the response here so no answer of this base is ever rendered by the
    client's generic RESTCONF hints.
    """
    if not response.is_success:
        raise rejection(response)
    return decode_json(response.text)


def bare_500_error(url: str) -> PlatformError:
    """The PlatformError for an empty-bodied HTTP 500 to the subscription POST.

    Rendered here, not by :func:`cnc_mcp.errors.http_error`, whose empty-500
    hint (OPM package service, Optimization Engine RPC inputs) describes other
    services. On this endpoint the only cause verified live is a client-url
    form the service cannot use (a URL without a port — refused client-side
    by :func:`validate_client_url` — was the one exercised; userinfo, an IPv6
    literal, port 0 or no path are unverified); a reachable endpoint that
    answers non-2xx to the reachability probe also fails, and its failure
    form was not recorded, so it may surface the same way.
    """
    return PlatformError(
        f"Crosswork answered a bare HTTP 500 (empty body) to the subscription request for "
        f"{url}. Verified live, that is how this service rejects a client-url form it cannot "
        "use (e.g. a URL without a port; forms with userinfo, an IPv6 literal, port 0 or no "
        "path are unverified) and it is also how a failed reachability probe may surface. "
        f"Check the URL form, that {url} answers 2xx from the Crosswork cluster, and list "
        "with cnc_list_notification_subscriptions to confirm nothing was created."
    )


DELETE_SUCCESS_TEXT = "Success"


def delete_confirmed(body: str | None) -> bool:
    """True when a 2xx DELETE body is the verified ``Success`` text (case-insensitive).

    Surrounding whitespace and one pair of double quotes (a JSON-encoded
    ``"Success"``) are tolerated; anything else — an empty body, ``Failed``,
    an envelope — is NOT confirmation: this platform routinely rides
    application failures inside HTTP 200 (alarm/v1 ``state Fail``, the NSO
    proxy's ``result:false``), so the delete is reported as unconfirmed.
    """
    if not isinstance(body, str):
        return False
    return body.strip().strip('"').strip().lower() == DELETE_SUCCESS_TEXT.lower()


def delete_unconfirmed(subscription_id: int, status: int, body: str | None) -> PlatformError:
    """The PlatformError for a 2xx DELETE whose body is not the verified ``Success`` text."""
    said = (body or "").strip()[:200] or "(empty body)"
    return PlatformError(
        f"the platform answered HTTP {status} to the delete of subscription {subscription_id} "
        f'but not the verified "Success" text: {said}. The delete is unconfirmed (this '
        "platform rides application failures inside HTTP 200); check with "
        "cnc_get_notification_subscription before assuming it is gone."
    )


def streams_from(data: Any) -> list[dict[str, Any]]:
    """The ``rcmon.stream`` entries of a streams document (a single object is accepted).

    Raises PlatformError when the body carries no ``rcmon.streams`` at all — the
    verified answer always does, so its absence means the wrong endpoint or a
    changed document rather than "no streams".
    """
    if not isinstance(data, dict) or not isinstance(data.get(STREAMS_KEY), dict):
        raise PlatformError(
            "The streams document did not carry 'rcmon.streams' (unexpected answer from "
            f"{STREAMS_PATH}): {str(data)[:200]}"
        )
    streams = data[STREAMS_KEY].get(STREAM_KEY)
    if isinstance(streams, dict):
        streams = [streams]
    if not isinstance(streams, list):
        return []
    return [s for s in streams if isinstance(s, dict)]


def streams_markdown(streams: list[dict[str, Any]]) -> str:
    """One section per stream: name, description, then ``- <encoding>: <location>`` lines."""
    lines = [f"# Notification streams ({len(streams)})"]
    for stream in streams:
        lines.extend(["", f"## {stream.get('rcmon.name') or '?'}"])
        if stream.get("rcmon.description"):
            lines.append(str(stream["rcmon.description"]))
        access = stream.get("rcmon.access")
        if isinstance(access, dict):
            access = [access]
        entries = [a for a in (access or []) if isinstance(a, dict)] if access else []
        if not entries:
            lines.append("- (no access entries)")
        for entry in entries:
            lines.append(
                f"- {entry.get('rcmon.encoding') or '?'}: {entry.get('rcmon.location') or '?'}"
            )
    return "\n".join(lines)


def subscription_line(sub: dict[str, Any]) -> str:
    """``- <id>: <topic> as <format> -> <url> (user <u>, <connection-type>, created <t>)``."""
    return (
        f"- {field(sub, 'subscription-id') if field(sub, 'subscription-id') is not None else '?'}: "
        f"{field(sub, 'topic') or '?'} as {field(sub, 'format') or '?'} -> "
        f"{field(sub, 'client-url') or '?'} (user {field(sub, 'subscribed-user') or '?'}, "
        f"{field(sub, 'connection-type') or '?'}, created {field(sub, 'creation-time') or '?'})"
    )


def subscription_markdown(sub: dict[str, Any]) -> str:
    """Full detail of one subscription; unknown extra fields are listed after the known ones."""
    sub_id = field(sub, "subscription-id")
    lines = [f"# Notification subscription {sub_id if sub_id is not None else '?'}", ""]
    shown = {f"{NS}subscription-id", "subscription-id"}
    for name, label in _DETAIL_FIELDS:
        value = field(sub, name)
        shown.update({f"{NS}{name}", name})
        lines.append(f"- {label}: {value if value not in (None, '') else '-'}")
    for key, value in sub.items():
        if key in shown:
            continue
        label = key[len(NS) :] if str(key).startswith(NS) else str(key)
        lines.append(f"- {label}: {value}")
    return "\n".join(lines)


def kafka_entries(data: Any) -> list[dict[str, Any]] | None:
    """The documented ``subscriptionList`` entries, or None when the body has another shape."""
    if isinstance(data, dict) and isinstance(data.get("subscriptionList"), list):
        return [e for e in data["subscriptionList"] if isinstance(e, dict)]
    return None


def kafka_line(entry: dict[str, Any]) -> str:
    """One list line per external subscription.

    ``- <topicName> -> <destinationName> (<type>; data <data type>[ <subscriptionData>]
    [; filter <filter>]; user <userName>; created <createTime>)``.
    """
    data = entry.get("subscriptionDataType") or "?"
    if entry.get("subscriptionData"):
        data += f" {entry['subscriptionData']}"
    filt = f"; filter {entry['filter']}" if entry.get("filter") else ""
    return (
        f"- {entry.get('topicName') or '?'} -> {entry.get('destinationName') or '?'} "
        f"({entry.get('destinationType') or '?'}; data {data}{filt}; "
        f"user {entry.get('userName') or '?'}; created {entry.get('createTime') or '?'})"
    )


# --- external (Kafka/gRPC) subscription helpers ---------------------------------


def match_choice(value: str | None, allowed: tuple[str, ...]) -> str:
    """The canonical spelling of ``value`` when it matches one of ``allowed``
    case-insensitively, else ``value`` stripped (the platform decides; "" for None).

    Unlike :func:`cnc_mcp.tools.fault.canonical` this never refuses: the caller
    decides what an unmatched value means (the NPM and SHM vocabularies are
    closed — verified live — the DPM selector is free text).
    """
    text = (value or "").strip()
    for candidate in allowed:
        if candidate.lower() == text.lower():
            return candidate
    return text


def build_external_subscription(
    destination_name: str,
    destination_type: str,
    topic_name: str,
    data_type: str,
    subscription_data: str | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """The verified POST body for an external subscription, or PlatformError.

    Refuses BEFORE anything is sent exactly what the platform was seen to
    refuse with 400 "Following param(s) are invalid" (every rule verified
    live, 2026-09-15): a blank topic or destination name, a destinationType
    other than Kafka/gRPC (matched case-insensitively here, sent in the
    platform's case-sensitive spelling), an unknown subscriptionDataType, gRPC
    with a data type other than the two PM feeds,
    Network_Performance_Monitoring without SR_PM_Interface / SR_PM_Policy,
    Service_Health_Monitoring without Y1731_Probes / PCA_Probes (Y1731_Probes
    was accepted with Service Health not installed), Device_Performance_Monitoring
    without a selector (its content is passed through — the platform accepted
    ``policy_type=OpticalSFP,policy_instance=instance1`` with no such policy),
    a subscriptionData on any non-PM data type, and a filter on a data type
    other than Inventory_Changes. ``subscription_data`` / ``filter`` may be
    None, "" or whitespace alike (the spec's example sends explicit nulls; the
    platform accepted both absent and null keys): the optional keys are sent
    only when a value is given. The destination name is sent verbatim
    (trimmed): the platform's lookup is case-sensitive.
    """
    name = (destination_name or "").strip()
    topic = (topic_name or "").strip()
    if not name:
        raise PlatformError(
            "destination_name must not be blank: the name of a Data Destination as listed by "
            "cnc_list_data_destinations (e.g. 'ext-kafka')."
        )
    if not topic:
        raise PlatformError("topic_name must not be blank (e.g. 'cnc-alarms').")
    wire_type = canonical(destination_type, DESTINATION_TYPES, "destination_type")
    if wire_type is None:
        raise PlatformError(
            f"destination_type must not be blank. Use one of: {', '.join(DESTINATION_TYPES)}."
        )
    wire_data_type = canonical(data_type, DATA_TYPES, "data_type")
    if wire_data_type is None:
        raise PlatformError(f"data_type must not be blank. Use one of: {', '.join(DATA_TYPES)}.")
    if wire_type == "gRPC" and wire_data_type not in GRPC_DATA_TYPES:
        raise PlatformError(
            f"a gRPC destination cannot receive {wire_data_type}: gRPC subscriptions take only "
            f"{' or '.join(GRPC_DATA_TYPES)} (verified live: the platform answers 400 "
            "'Destination Type'); use a Kafka destination for the other data types."
        )
    data = (subscription_data or "").strip()
    if wire_data_type == NPM_DATA_TYPE:
        data = match_choice(data, NPM_SUBSCRIPTION_DATA)
        if data not in NPM_SUBSCRIPTION_DATA:
            raise PlatformError(
                f"{NPM_DATA_TYPE} needs subscription_data "
                f"{' or '.join(repr(v) for v in NPM_SUBSCRIPTION_DATA)} (got "
                f"{data!r}; verified live: the platform answers 400 'Subscription Data')."
            )
    elif wire_data_type == SHM_DATA_TYPE:
        data = match_choice(data, SHM_SUBSCRIPTION_DATA)
        if data not in SHM_SUBSCRIPTION_DATA:
            raise PlatformError(
                f"{SHM_DATA_TYPE} needs subscription_data "
                f"{' or '.join(repr(v) for v in SHM_SUBSCRIPTION_DATA)} (got "
                f"{data!r}; verified live: the platform answers 400 'Subscription Data' to "
                "any other value)."
            )
    elif wire_data_type == DPM_DATA_TYPE:
        if not data:
            raise PlatformError(
                f"{DPM_DATA_TYPE} needs subscription_data "
                "'policy_type=<type>,policy_instance=<policy name>' (e.g. "
                "'policy_type=OpticalSFP,policy_instance=instance1'; the platform does not "
                "check that the policy exists — verified live)."
            )
    elif data:
        raise PlatformError(
            f"subscription_data is only accepted with the performance-monitoring data types "
            f"({', '.join((DPM_DATA_TYPE, NPM_DATA_TYPE, SHM_DATA_TYPE))}); verified live: "
            f"{wire_data_type} with a subscriptionData is answered 400 'Subscription Data'. "
            "Leave it empty."
        )
    filt = (filter or "").strip()
    if filt and wire_data_type != FILTER_DATA_TYPE:
        raise PlatformError(
            f"filter is only accepted with data_type {FILTER_DATA_TYPE} (verified live: a "
            f"filter on {wire_data_type} is answered 400 'Filter'); drop it or subscribe "
            f"{FILTER_DATA_TYPE}."
        )
    body: dict[str, Any] = {
        "destinationName": name,
        "destinationType": wire_type,
        "topicName": topic,
        "subscriptionDataType": wire_data_type,
    }
    if data:
        body["subscriptionData"] = data
    if filt:
        body["filter"] = filt
    return body


def external_result(data: Any) -> str:
    """The ``result`` (or ``error``) text of a v2 subscription answer, "" when absent.

    Verified live: successes and application failures alike answer HTTP 200
    ``{"result": "<text>"}``; parameter validation answers 400
    ``{"error": "Following param(s) are invalid : ..."}``; the delete's
    not-found answer is 400 with ``result``.
    """
    if not isinstance(data, dict):
        return ""
    for key in ("result", "error"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def result_is(text: str, expected: str) -> bool:
    """True when a result text equals ``expected`` (case- and whitespace-insensitive)."""
    return text.strip().rstrip(".").lower() == expected.lower()


def invalid_params_error(status: int, message: str, body: dict[str, Any]) -> PlatformError:
    """The PlatformError for a 400 ``Following param(s) are invalid : ...`` answer.

    Adds, per parameter the platform names, the rule verified live for it, so
    the agent learns the constraint rather than only the field name.
    """
    hints = {
        "topic name": "topicName must not be blank",
        "destination name": "destinationName must not be blank",
        "destination type": "destinationType must be exactly 'Kafka' or 'gRPC' (case-sensitive), "
        "and a gRPC destination takes only Device_/Network_Performance_Monitoring",
        "subscription data type": f"subscriptionDataType must be one of {', '.join(DATA_TYPES)}",
        "subscription data": "subscriptionData is required for Network_Performance_Monitoring "
        "(SR_PM_Interface | SR_PM_Policy), Service_Health_Monitoring (Y1731_Probes | "
        "PCA_Probes) and Device_Performance_Monitoring "
        "('policy_type=<type>,policy_instance=<name>')",
        "filter": "filter is only accepted with subscriptionDataType Inventory_Changes",
    }
    named = message.split(":", 1)[1] if ":" in message else message
    lines = []
    for raw in named.split(","):
        rule = hints.get(raw.strip().lower())
        if rule:
            lines.append(rule)
    detail = ("; ".join(lines) + ". ") if lines else ""
    return PlatformError(
        f"the platform rejected the subscription (HTTP {status}): {message}. {detail}"
        f"Body sent: {to_json(body)}"
    )


def destination_diagnosis(destinations: list[dict[str, Any]], name: str, wire_type: str) -> str:
    """Why the platform refused ``name`` as an external ``wire_type`` destination,
    from the Data Gateway destinations list.

    The platform's single message covers four verified causes: the name is
    unknown; the name differs from an existing destination's only in case (the
    platform's lookup is case-sensitive — verified live with ``Phase-D-KAFKA``
    for ``phase-d-kafka`` — while the match here is case-insensitive so the
    exact spelling can be named); the destination exists but its
    ``DISPATCH_SOURCE`` is ``datagateway`` (every system-defined one); the
    destination exists but is of the other kind (``DESTINATION_TYPE``
    destination_type_grpc asked for as Kafka, or the reverse). A destination
    that passes every check is reported as such, with the raw properties, so
    the agent is never told a wrong cause.
    """
    given = name.strip()
    wanted = given.lower()
    match = None
    for dest in destinations:
        if str(dest.get("name") or "").strip().lower() == wanted:
            match = dest
            break
    if match is None:
        known = sorted(str(d.get("name") or "?") for d in destinations)
        return (
            f"no Data Destination is named '{name}' (known: {', '.join(known) or 'none'}); "
            "list them with cnc_list_data_destinations."
        )
    exact = str(match.get("name") or "").strip()
    props = match.get("properties") if isinstance(match.get("properties"), dict) else {}
    dispatch = str(props.get("DISPATCH_SOURCE") or "").strip().lower()
    kind = _DESTINATION_KIND.get(str(props.get("DESTINATION_TYPE") or "").strip().lower())
    reasons = []
    if exact != given:
        reasons.append(
            f"the name was sent as '{given}' — the platform looks the destination up by "
            f"exact, case-sensitive name (verified live); retry with destination_name "
            f"'{exact}'"
        )
    if dispatch not in _DISPATCH_ALLOWED:
        reasons.append(
            f"its DISPATCH_SOURCE is '{dispatch or 'unset'}' — external subscriptions need a "
            "destination created with DISPATCH_SOURCE 'application' or 'any' (system-defined "
            "and data-gateway destinations are refused)"
        )
    if kind and kind != wire_type:
        reasons.append(
            f"it is a {kind} destination (DESTINATION_TYPE {props.get('DESTINATION_TYPE')}) "
            f"while destination_type '{wire_type}' was requested — the lookup is by name AND "
            "type"
        )
    if not reasons:
        return (
            f"Data Destination '{match.get('name')}' exists, its DISPATCH_SOURCE is "
            f"'{dispatch or 'unset'}' and its kind matches; the refusal has a cause this tool "
            f"does not know. Properties: {to_json(props)}"
        )
    return f"Data Destination '{match.get('name')}' exists but " + "; and ".join(reasons) + "."


def clear_confirmed(body: str | None) -> bool:
    """True when a 2xx clear-by-topic body is the verified ``Clear successful`` text."""
    if not isinstance(body, str):
        return False
    return body.strip().strip('"').strip().lower() == CLEAR_OK.lower()


def subscriptions_of_topic(subs: list[dict[str, Any]], topic: str) -> list[dict[str, Any]]:
    """The entries whose ``topic`` equals ``topic`` (case-insensitive)."""
    wanted = topic.strip().lower()
    return [s for s in subs if str(field(s, "topic") or "").strip().lower() == wanted]


def _parse_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def _no_header() -> dict[str, int | None]:
    return {"first_index": None, "last_index": None, "iterator_id": None}


def subscription_items(data: Any, path: str) -> tuple[list[dict[str, Any]], dict[str, int | None]]:
    """``(subscriptions, header)`` of a subscription answer, else PlatformError.

    The verified answer is the ``com.response-message`` envelope — a single
    subscription as an OBJECT under ``ietf-restconf:notification.subscription``,
    several as a list, none as ``com.lastIndex -1`` without ``com.data`` — and
    :func:`cnc_mcp.emf.unwrap` normalises all three (``header`` is its
    ``{"first_index", "last_index", "iterator_id"}``). Defensively, a bare
    subscription object (one carrying ``ietf-restconf:notification.subscription-id``)
    and a bare ``{"ietf-restconf:notification.subscription": <object | list>}``
    are accepted too, with every header position None. Anything else — an empty
    body, ``{}``, an envelope without ``com.lastIndex``, a document from another
    endpoint — raises naming ``path`` and a 200-character excerpt, so a caller
    never reports "no subscriptions" or "not found" for an answer it did not
    understand (``unwrap`` leaves every header position None for such a body).
    """
    if isinstance(data, dict):
        if f"{NS}subscription-id" in data:
            return [data], _no_header()
        if SUBSCRIPTION_KEY in data:
            raw = data[SUBSCRIPTION_KEY]
            if isinstance(raw, dict):
                raw = [raw]
            if isinstance(raw, list):
                return [s for s in raw if isinstance(s, dict)], _no_header()
    items, header = unwrap(data)
    if header.get("last_index") is None:
        excerpt = "an empty body" if data is None else str(data)[:200]
        raise PlatformError(
            f"unexpected answer from {path}: neither the com.response-message envelope "
            f"(com.header.com.lastIndex is missing) nor a subscription object: {excerpt}"
        )
    return [s for s in items if isinstance(s, dict)], header


def subscription_with_id(subs: list[dict[str, Any]], subscription_id: int) -> dict[str, Any] | None:
    """The entry whose ``subscription-id`` equals ``subscription_id`` (as text), else None.

    Re-checked client-side on purpose: Crosswork RESTCONF keyed GETs have been
    seen to ignore their key (the te_state module re-checks for the same
    reason), so a multi-entry or key-ignoring answer must not be rendered as
    the requested subscription. Compared on the text form of both sides so a
    stringified id on the wire still matches the tool's integer argument.
    """
    wanted = str(subscription_id)
    for sub in subs:
        value = field(sub, "subscription-id")
        if value is not None and not isinstance(value, bool) and str(value).strip() == wanted:
            return sub
    return None


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    def not_found(subscription_id: int) -> PlatformError:
        return PlatformError(
            f"no subscription {subscription_id} (list with cnc_list_notification_subscriptions)"
        )

    # --- reads ---------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_notification_streams",
        title="List Notification Streams",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_notification_streams(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the notification streams Crosswork advertises: the connection-less
        (webhook) subscription endpoint and the WebSocket alarm / inventory
        streams, with the URL and encoding of each.

        Read-only. Use it to discover how notifications can be consumed on this
        instance and to get the exact wss:// locations for a WebSocket client
        (those streams are not driven by this server — an MCP tool cannot hold a
        socket; use cnc_create_webhook_subscription for push delivery instead).
        Reads GET /crosswork/notification/restconf/data/v2/
        ietf-restconf-monitoring:restconf-state/streams with the EMF dialect
        (exactly 'Accept: application/json'). Any rc.errors answer is reported
        as "EMF RESTCONF rejected the request (HTTP <n>): <error-tag>
        [<error-app-tag>]: <error-message>" with the service's own NOT.xxxx tag.

        Returns:
            str: Markdown, one section per stream — its name, description and
            one "<encoding>: <location>" line per access entry (e.g.
            "json: wss://host:30603/crosswork/notification/restconf/streams/v2/alarm.json",
            "xml: POST https://host:30603/.../cisco-notifications:subscription");
            or JSON {"count": int, "items": [{"rcmon.name", "rcmon.description",
            "rcmon.access": [{"rcmon.encoding": "json"|"xml", "rcmon.location"}]}]}
            with the verbatim keys. "No notification streams are advertised."
            when the list is empty (not an error). On failure:
            "Error: <actionable message>".
        """
        try:
            response = await client.request(
                "GET", STREAMS_PATH, headers=EMF_HEADERS, raise_on_error=False
            )
            streams = streams_from(emf_body(response))
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(streams), "items": streams}), settings)
            if not streams:
                return finalize("No notification streams are advertised.", settings)
            return finalize(streams_markdown(streams), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_notification_subscriptions",
        title="List Notification Subscriptions",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_notification_subscriptions(
        all_users: Annotated[
            bool,
            Field(
                description="False (default) lists the configured user's own subscriptions "
                "(notifications:subscription); True lists every user's, including open "
                "WebSocket sessions (notifications:subscription-admin — presumably an "
                "administrator view; the required role is not documented or verified)."
            ),
        ] = False,
        limit: Annotated[
            int,
            Field(
                description="Subscriptions per page (.maxCount), 1..100 — the EMF cap (e.g. 50).",
                ge=1,
                le=MAX_COUNT,
            ),
        ] = DEFAULT_MAX_COUNT,
        offset: Annotated[
            int, Field(description="0-based object offset (.startIndex), e.g. 0.", ge=0)
        ] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List notification subscriptions — the webhook (connection-less)
        subscriptions of the configured user, or with all_users=True every
        user's subscriptions including connection-oriented WebSocket sessions.

        Read-only. Use it to find a subscription's id before
        cnc_get_notification_subscription / cnc_delete_notification_subscription,
        or to check whether a duplicate already exists before creating one.
        Reads GET /crosswork/notification/restconf/data/v2/notifications:subscription
        (own) or .../notifications:subscription-admin (all users), EMF dialect,
        with .startIndex/.maxCount paging (documented for both endpoints with the
        EMF 100-object cap; the paging parameters were not exercised live on
        this base). The admin view lists every user's WebSocket sessions too, so
        it can exceed one page: follow has_more / next_offset. VERIFIED: a single
        subscription comes back as an OBJECT under
        "ietf-restconf:notification.subscription", several as a list, none as
        com.lastIndex -1 without com.data — all three are normalised here; an
        answer of any other shape is reported as an error, never as "none".
        Any rc.errors answer (e.g. to a paging parameter this service will
        not take) is reported as "EMF RESTCONF rejected the request (HTTP <n>):
        <error-tag> [<error-app-tag>]: <error-message>" with the service's own
        NOT.xxxx tag.

        Args:
            all_users: True for the admin (every user) view.
            limit / offset: EMF page size (1..100) and 0-based start index.

        Returns:
            str: Markdown, one line per subscription
            "<subscription-id>: <topic> as <format> -> <client-url> (user <u>,
            <connection-type>, created <creation-time>)", then "More available:
            repeat with offset=<n>." when the page was full; or JSON
            {"total": null, "count": int, "scope": "own"|"all_users", "offset": int,
             "items": [{"ietf-restconf:notification.subscription-id": int,
                        "ietf-restconf:notification.topic", ".format", ".client-url",
                        ".client-ip", ".session-id", ".subscribed-user",
                        ".connection-type", ".creation-time", ".time-of-update"}],
             "has_more": bool, "next_offset": int|null, "first_index", "last_index",
             "iterator_id", "start_index", "max_count", "next_start_index"}
            (verbatim item keys). "No notification subscriptions." when there
            are none (not an error). On failure: "Error: <actionable message>".
        """
        try:
            path = SUBSCRIPTION_ADMIN_PATH if all_users else SUBSCRIPTION_PATH
            response = await client.request(
                "GET",
                path,
                headers=EMF_HEADERS,
                params=page_params(offset, limit),
                raise_on_error=False,
            )
            subs, header = subscription_items(emf_body(response), path)
            scope = "all_users" if all_users else "own"
            envelope = page_envelope_from(subs, header, offset, limit)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({**envelope, "scope": scope}), settings)
            if not subs:
                hint = (
                    "Scope: every user."
                    if all_users
                    else "Scope: the configured user (all_users=True lists every user's)."
                )
                where = f" at offset {offset}" if offset else ""
                return finalize(f"No notification subscriptions{where}. {hint}", settings)
            who = "all users" if all_users else "configured user"
            lines = [f"# Notification subscriptions ({len(subs)}, {who})", ""]
            lines.extend(subscription_line(s) for s in subs)
            if envelope.get("has_more"):
                lines.extend(["", f"More available: repeat with offset={envelope['next_offset']}."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_notification_subscription",
        title="Get Notification Subscription",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_notification_subscription(
        subscription_id: Annotated[
            int,
            Field(
                description="subscription-id as listed by cnc_list_notification_subscriptions "
                "(an integer, e.g. 12).",
                ge=0,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one notification subscription by its subscription-id.

        Read-only. Reads GET /crosswork/notification/restconf/data/v2/
        notifications:subscription/<id> (EMF dialect). An unknown id is answered
        HTTP 400 rc.errors NOT.0016 "Unable to find subscription" (verified
        live) and reported as not found; any other rc.errors answer is reported
        as "EMF RESTCONF rejected the request (HTTP <n>): <error-tag>
        [<error-app-tag>]: <error-message>". The answer is re-checked
        client-side: only the entry whose subscription-id equals the requested
        id is rendered (a keyed GET that ignores its key, or answers several
        entries, is not mistaken for the requested subscription); none matching
        is reported as not found.

        Args:
            subscription_id: the integer id.

        Returns:
            str: Markdown with topic, format, client URL, connection type,
            subscribed user, client IP, session id, created / updated times
            (as the platform spells them) and any further fields; or the
            subscription JSON with its verbatim "ietf-restconf:notification.*"
            keys. "Error: no subscription <id> (list with
            cnc_list_notification_subscriptions)" when it does not exist; other
            failures: "Error: <actionable message>".
        """
        try:
            path = f"{SUBSCRIPTION_PATH}/{subscription_id}"
            response = await client.request("GET", path, headers=EMF_HEADERS, raise_on_error=False)
            if not response.is_success:
                err = rc_error(_parse_json(response))
                if response.status_code == 400 and error_matches(
                    err, APP_TAG_GET_UNKNOWN, _GET_UNKNOWN_MARKER
                ):
                    raise not_found(subscription_id)
                raise rejection(response)
            subs, _ = subscription_items(decode_json(response.text), path)
            sub = subscription_with_id(subs, subscription_id)
            if sub is None:
                raise not_found(subscription_id)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(sub), settings)
            return finalize(subscription_markdown(sub), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_kafka_subscriptions",
        title="List Kafka Subscriptions",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_kafka_subscriptions(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the external Kafka / gRPC notification subscriptions (platform
        data — alarms, inventory changes, system audit, PM feeds — published to
        a Kafka or gRPC Data Destination on a named topic).

        Read-only. Reads GET /crosswork/notification/v2/subscription (a plain
        JSON service, not the RESTCONF base). VERIFIED LIVE: with no
        subscriptions the platform answers HTTP 200 with an EMPTY body, which is
        reported as "No Kafka/gRPC subscriptions."; with some it answers
        {"subscriptionList": [{"topicName", "destinationName",
        "destinationType": "Kafka"|"gRPC", "subscriptionDataType",
        "subscriptionData", "filter", "userName", "createTime"}]} (there is no
        id: the topicName is the platform-wide key, and what
        cnc_delete_external_subscription takes). A body of any other shape is
        shown as JSON, as-is, with a note. Create with
        cnc_create_external_subscription.

        Returns:
            str: Markdown lines "<topicName> -> <destinationName>
            (<destinationType>; data <subscriptionDataType> [<subscriptionData>]
            [; filter <filter>]; user <u>; created <t>)" or the raw JSON body
            when its shape is not the verified one; JSON: always the same
            envelope {"count": int, "items": [<entry>, ...]} — "items" are the
            subscriptionList entries (empty for the verified empty body and for
            an empty list) — plus "raw": <body> when the body's shape is not
            the verified one (items are then empty). "No Kafka/gRPC
            subscriptions." when the body is empty (not an error). On failure:
            "Error: <actionable message>".
        """
        try:
            data = await client.request_json("GET", KAFKA_SUBSCRIPTION_PATH)
            known_empty = data is None or data == {} or data == []
            entries = [] if known_empty else kafka_entries(data)
            unknown_shape = entries is None
            entries = entries or []
            if response_format is ResponseFormat.JSON:
                payload: dict[str, Any] = {"count": len(entries), "items": entries}
                if unknown_shape:
                    payload["raw"] = data
                return finalize(to_json(payload), settings)
            if unknown_shape:
                return finalize(
                    "# Kafka/gRPC subscriptions (shape not the verified one — body as-is)\n\n"
                    'Note: the verified answer is {"subscriptionList": [...]}; this body is '
                    f"shown unparsed.\n\n{to_json(data)}",
                    settings,
                )
            if not entries:
                return finalize("No Kafka/gRPC subscriptions.", settings)
            lines = [f"# Kafka/gRPC subscriptions ({len(entries)})", ""]
            lines.extend(kafka_line(e) for e in entries)
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    # --- writes --------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_webhook_subscription",
        title="Create Webhook Subscription",
        read_only=False,
        destructive=False,
        idempotent=False,
        # The URL may carry userinfo (https://user:secret@host:443/hook).
        redact=("client_url",),
    )
    async def cnc_create_webhook_subscription(
        client_url: Annotated[
            str,
            Field(
                description="HTTP(S) URL Crosswork will POST notifications to, WITH AN EXPLICIT "
                "PORT (required by the platform even for 80/443), e.g. "
                "'http://198.18.140.17:80/hook'. The endpoint must be reachable from the "
                "Crosswork cluster and answer 2xx to a probe.",
                min_length=1,
                max_length=2000,
            ),
        ],
        topic: Annotated[
            str,
            Field(description="Notification topic: 'alarm' or 'inventory'.", max_length=20),
        ],
        format: Annotated[
            str,
            Field(
                description="Payload format the platform posts: 'json' (default) or 'xml'.",
                max_length=10,
            ),
        ] = "json",
    ) -> str:
        """Create a connection-less (webhook) notification subscription: from then
        on Crosswork POSTs every notification of the topic (alarm or inventory)
        to client_url as JSON or XML.

        Write. Sends POST /crosswork/notification/restconf/data/v2/
        notifications:subscription {"ietf-restconf:notification.client-url",
        "ietf-restconf:notification.topic", "ietf-restconf:notification.format"}
        (EMF dialect; bare key names are rejected with 400). RULES VERIFIED
        LIVE: (1) the URL MUST carry an explicit port — without one the platform
        answers a bare Spring 500 (body not recorded), so the tool refuses such
        a URL before sending and shows the corrected form; (2) the platform
        PROBES the endpoint before subscribing: an endpoint it cannot reach is
        refused with NOT.0029 "The endpoint is not reachable.", and a reachable
        endpoint that answers non-2xx to the probe also fails (its error tag
        was not recorded) — the endpoint must be up, reachable from the
        Crosswork cluster (not merely from the caller) and answer 2xx; (3) a
        duplicate (same topic, URL and format) is refused with NOT.0006
        "Subscription already exists" — find the existing id with
        cnc_list_notification_subscriptions. Not idempotent: a repeat fails as
        a duplicate rather than creating a second subscription. The POST is not
        auto-retried (a lost answer could mean the subscription exists; list
        before repeating).

        Args:
            client_url: http(s)://<host>:<port>/<path>.
            topic: 'alarm' | 'inventory' (case-insensitive).
            format: 'json' | 'xml' (case-insensitive).

        Returns:
            str: "Webhook subscription <id> created: topic <topic>, format
            <format>, url <url>." followed by the subscription JSON (verbatim
            "ietf-restconf:notification.*" keys: subscription-id, subscribed-user,
            client-url, client-ip, session-id, topic, creation-time,
            time-of-update, format, connection-type "connection-less"). A 2xx
            whose body carries no subscription object is reported as accepted
            (not an error) with a pointer to the list tool.
            "Error: client_url '<url>' has no explicit port ..." (nothing sent);
            "Error: Unknown topic ..." / "Error: Unknown format ..." (nothing sent);
            "Error: the platform could not reach <url> (it probes the endpoint
            before subscribing) ..." for NOT.0029; "Error: a subscription for
            topic <topic> at <url> (format <format>) already exists ..." for
            NOT.0006; "Error: EMF RESTCONF rejected the request (HTTP <n>): ..."
            for any other rc.errors answer; "Error: Crosswork answered a bare
            HTTP 500 (empty body) to the subscription request for <url> ..."
            for an empty-bodied 500 — verified live, that is how this service
            rejects a client-url form it cannot use (the port-less form is
            refused client-side; other forms are unverified), and a failed
            reachability probe may surface the same way, so the URL form and
            the endpoint are the things to check (and list to confirm nothing
            was created); other failures: "Error: <actionable message>".
        """
        try:
            wire_topic = canonical(topic, TOPICS, "topic")
            wire_format = canonical(format, FORMATS, "format")
            if wire_topic is None:
                raise PlatformError(f"topic must not be blank. Use one of: {', '.join(TOPICS)}.")
            if wire_format is None:
                wire_format = "json"
            url = validate_client_url(client_url)
            body = {
                f"{NS}client-url": url,
                f"{NS}topic": wire_topic,
                f"{NS}format": wire_format,
            }
            # Default POST retry policy (none): a lost answer may mean the
            # subscription was created; the agent lists before repeating.
            response = await client.request(
                "POST", SUBSCRIPTION_PATH, json_body=body, headers=EMF_HEADERS, raise_on_error=False
            )
            if not response.is_success:
                err = rc_error(_parse_json(response))
                if error_matches(err, APP_TAG_UNREACHABLE, _UNREACHABLE_MARKER):
                    raise PlatformError(
                        f"the platform could not reach {url} (it probes the endpoint before "
                        "subscribing): the endpoint must be up, reachable from the Crosswork "
                        "cluster itself and answer 2xx to the probe. Platform said: "
                        f"{err['message'] or 'The endpoint is not reachable.'}"
                    )
                if error_matches(err, APP_TAG_DUPLICATE, _DUPLICATE_MARKER):
                    raise PlatformError(
                        f"a subscription for topic {wire_topic} at {url} (format {wire_format}) "
                        "already exists; find its id with cnc_list_notification_subscriptions. "
                        f"Platform said: {err['message'] or 'Subscription already exists'}"
                    )
                if response.status_code == 500 and not response.text.strip():
                    # The only verified cause of a bare 500 here is a client-url
                    # form the service cannot use (a failed probe may look the
                    # same); http_error's empty-500 hint describes other services.
                    raise bare_500_error(url)
                raise rejection(response)
            data = decode_json(response.text)
            try:
                subs, _ = subscription_items(data, SUBSCRIPTION_PATH)
            except PlatformError:
                # A 2xx of an unrecognised shape: the subscription may well exist,
                # so this is reported as accepted-but-unconfirmed, not as an error.
                subs = []
            if not subs:
                return finalize(
                    f"The platform accepted the {wire_topic} subscription for {url} but its "
                    "answer carried no subscription object; find the id with "
                    f"cnc_list_notification_subscriptions. Response: {response.text[:300]}",
                    settings,
                )
            sub = subs[0]
            sub_id = field(sub, "subscription-id")
            created_topic = field(sub, "topic") or wire_topic
            created_format = field(sub, "format") or wire_format
            created_url = field(sub, "client-url") or url
            return finalize(
                f"Webhook subscription {sub_id if sub_id is not None else '?'} created: topic "
                f"{created_topic}, format {created_format}, url {created_url}.\n\n{to_json(sub)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_notification_subscription",
        title="Delete Notification Subscription",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_notification_subscription(
        subscription_id: Annotated[
            int,
            Field(
                description="subscription-id to delete, as listed by "
                "cnc_list_notification_subscriptions (an integer, e.g. 12).",
                ge=0,
            ),
        ],
    ) -> str:
        """Delete a notification subscription by subscription-id — the platform
        stops posting to its URL.

        Write, destructive. Sends DELETE /crosswork/notification/restconf/data/v2/
        notifications:subscription/<id> (EMF dialect); success is HTTP 200 with
        the text body "Success" (verified live) — ONLY that body confirms the
        delete: a 2xx with any other body (empty, "Failed", an envelope) is
        reported as unconfirmed, because this platform routinely rides
        application failures inside HTTP 200. An unknown id — including one
        already deleted — is answered 400 rc.errors NOT.0037 "There is no
        subscription for given subscriptionId" and reported as not found, so a
        repeat is harmless (the DELETE keeps the client's idempotent auto-retry).
        Any other rc.errors answer is reported as "EMF RESTCONF rejected the
        request (HTTP <n>): <error-tag> [<error-app-tag>]: <error-message>".

        Args:
            subscription_id: the integer id.

        Returns:
            str: "Notification subscription <id> deleted. Platform said: Success".
            "Error: no subscription <id> (list with cnc_list_notification_subscriptions)"
            when it does not exist; "Error: the platform answered HTTP <status>
            to the delete of subscription <id> but not the verified "Success"
            text: <body> ..." (check with cnc_get_notification_subscription)
            for a 2xx without that text; other failures: "Error: <actionable
            message>".
        """
        try:
            path = f"{SUBSCRIPTION_PATH}/{subscription_id}"
            response = await client.request(
                "DELETE", path, headers=EMF_HEADERS, raise_on_error=False
            )
            if not response.is_success:
                err = rc_error(_parse_json(response))
                if response.status_code == 400 and error_matches(
                    err, APP_TAG_DELETE_UNKNOWN, _DELETE_UNKNOWN_MARKER
                ):
                    raise not_found(subscription_id)
                raise rejection(response)
            if not delete_confirmed(response.text):
                raise delete_unconfirmed(subscription_id, response.status_code, response.text)
            return finalize(
                f"Notification subscription {subscription_id} deleted. Platform said: "
                f"{response.text.strip()[:200]}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    # --- external (Kafka/gRPC) subscription writes ---------------------------

    async def explain_destination(name: str, wire_type: str) -> str:
        """The :func:`destination_diagnosis` for the platform's destination refusal,
        or a pointer to the list tool when the destinations cannot be read."""
        try:
            data = await client.request_json(
                "POST", DESTINATIONS_QUERY_PATH, json_body=DESTINATIONS_QUERY_BODY
            )
        except Exception as e:  # the diagnosis must never mask the refusal itself
            logger.info("destination lookup for the diagnosis failed: %s", e)
            return (
                "check the name, its DISPATCH_SOURCE (must be 'application' or 'any') and its "
                "kind with cnc_list_data_destinations (the lookup for this hint failed: "
                f"{format_error(e)[:200]})."
            )
        items = data.get("data") if isinstance(data, dict) else None
        destinations = [d for d in items if isinstance(d, dict)] if isinstance(items, list) else []
        return destination_diagnosis(destinations, name, wire_type)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_external_subscription",
        title="Create External Kafka/gRPC Subscription",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_create_external_subscription(
        destination_name: Annotated[
            str,
            Field(
                description="Name of the Data Destination to publish to, exactly as listed "
                "by cnc_list_data_destinations (e.g. 'ext-kafka'; case-sensitive). It must "
                "have been created with DISPATCH_SOURCE 'application' or 'any' — in the UI "
                "(Administration > Data Gateway > Data Destinations) or the dg-manager API; "
                "no cnc_create_data_destination tool exists — because the system-defined "
                "CW_KAFKA_DESTINATION / cdg-common-pipeline and every 'datagateway' "
                "destination are refused.",
                min_length=1,
                max_length=200,
            ),
        ],
        destination_type: Annotated[
            str,
            Field(
                description="Kind of the destination: 'Kafka' or 'gRPC' (case-insensitive here; "
                "must match the destination's own kind).",
                max_length=10,
            ),
        ],
        topic_name: Annotated[
            str,
            Field(
                description="Kafka topic (or gRPC topic label) the data is published on, "
                "e.g. 'cnc-alarms'. Unique platform-wide: it is the subscription's key "
                "(cnc_delete_external_subscription takes it) and a second subscription "
                "with the same topic is refused whatever its destination.",
                min_length=1,
                max_length=249,
            ),
        ],
        data_type: Annotated[
            str,
            Field(
                description="What to publish (subscriptionDataType): 'Alarm', "
                "'Inventory_Changes', 'System_Audit' (JSON encoded), "
                "'Device_Performance_Monitoring', 'Network_Performance_Monitoring', "
                "'Service_Health_Monitoring' (GPB-KV encoded). gRPC destinations take only "
                "the two *_Performance_Monitoring types.",
                max_length=40,
            ),
        ],
        subscription_data: Annotated[
            str | None,
            Field(
                description="Feed selector (subscriptionData), required by the PM data types "
                "and otherwise omitted (null or empty): Network_Performance_Monitoring -> "
                "'SR_PM_Interface' or 'SR_PM_Policy'; Service_Health_Monitoring -> "
                "'Y1731_Probes' or 'PCA_Probes'; Device_Performance_Monitoring -> "
                "'policy_type=<type>,policy_instance=<policy name>' (e.g. "
                "'policy_type=OpticalSFP,policy_instance=instance1').",
                max_length=500,
            ),
        ] = None,
        filter: Annotated[
            str | None,
            Field(
                description="Inventory_Changes only: comma-separated device product "
                "families / series / types, OR-ed — a change is forwarded when the device "
                "matches any (e.g. 'Routers,Switches and Hubs' or 'Cisco 8000 Series "
                "Routers'). Refused with any other data_type; null or empty otherwise.",
                max_length=2000,
            ),
        ] = None,
    ) -> str:
        """Create an external subscription: from then on Crosswork publishes the
        chosen data type (alarms, inventory changes, system audit events or a
        performance-monitoring feed) to a Kafka or gRPC Data Destination on the
        given topic.

        Write. Sends POST /crosswork/notification/v2/subscription
        {"destinationName", "destinationType": "Kafka"|"gRPC", "topicName",
        "subscriptionDataType", "subscriptionData"?, "filter"?} (plain JSON
        service; the optional keys only when a value is given — the platform
        accepts them absent or as explicit null alike). RULES VERIFIED LIVE
        (2026-09-15, each one exercised against a throwaway destination):
        (1) the destination must exist under Data Gateway > Data Destinations
        with DISPATCH_SOURCE 'application' or 'any' — one created for the
        data gateways (DISPATCH_SOURCE 'datagateway', which includes every
        system-defined destination) is refused; no tool here creates a
        destination (UI or dg-manager API) — its name must match EXACTLY
        (case-sensitive: 'Phase-D-KAFKA' does not find 'phase-d-kafka') AND
        destination_type must match its kind (the lookup is by name and type);
        the platform gives one message for all four cases, HTTP 200 {"result":
        "Destination does not exist or might be a data-gateway destination,
        which is not allowed for external subscriptions."}, so this tool reads
        the destinations list and says which one applies; (2) the topic name
        is the platform-wide key: a second subscription with the same topic,
        to any destination, is HTTP 200 {"result": "A subscription with this
        topic name already exists ..."}; (3) destinationType is case-sensitive
        on the wire ('Kafka' / 'gRPC' — normalised here), gRPC takes only
        Device_/Network_Performance_Monitoring, the PM data types need their
        subscription_data (Network_: SR_PM_Interface | SR_PM_Policy;
        Service_Health_: Y1731_Probes | PCA_Probes — closed vocabularies,
        Y1731_Probes accepted with Service Health not installed; Device_:
        'policy_type=...,policy_instance=...' — required, its content not
        validated against the policies), the non-PM types take NONE, and
        filter is accepted only with Inventory_Changes — each of those is
        refused here before anything is sent; whatever else the
        platform rejects comes back as HTTP 400 {"error": "Following param(s)
        are invalid : <Name>, ..."} and is reported with the rule per named
        parameter. Success is HTTP 200 {"result": "Create Successful"} — ONLY
        that text confirms the create (every application failure of this
        endpoint rides inside HTTP 200). Not idempotent: a repeat fails as a
        duplicate topic. The POST is not auto-retried (a lost answer may mean
        the subscription exists: list before repeating). A destination whose
        broker/server is down is not probed at create time (verified: the
        throwaway destinations pointed at nothing).

        Args:
            destination_name: Data Destination name (cnc_list_data_destinations).
            destination_type: 'Kafka' | 'gRPC'.
            topic_name: unique topic (the key).
            data_type: Alarm | Inventory_Changes | System_Audit |
                Device_Performance_Monitoring | Network_Performance_Monitoring |
                Service_Health_Monitoring (case-insensitive).
            subscription_data: PM feed selector (see the argument description);
                null / empty otherwise.
            filter: Inventory_Changes device-type filter, OR-ed, comma-separated;
                null / empty otherwise.

        Returns:
            str: "External subscription created: topic <topic> -> <destination>
            (<type>), data <data_type>[ <subscription_data>][, filter <filter>].
            Platform said: Create Successful" followed by the JSON body sent
            (there is no id: the topic is the key; cnc_list_kafka_subscriptions
            shows the record with its createTime and userName).
            "Error: ... must not be blank" / "Error: Unknown destination_type
            ..." / "Error: a gRPC destination cannot receive <type> ..." /
            "Error: <PM type> needs subscription_data ..." / "Error:
            subscription_data is only accepted with the performance-monitoring
            data types ..." / "Error: filter is only accepted with data_type
            Inventory_Changes ..." (nothing sent); "Error: a subscription with topic '<topic>'
            already exists ..." for the duplicate; "Error: the platform refused
            destination '<name>' as a <type> destination: <diagnosis> ..." for
            the destination refusal; "Error: the platform rejected the
            subscription (HTTP 400): Following param(s) are invalid : ..." with
            the per-parameter rule; "Error: the platform answered HTTP <n> to
            the subscription request but not the verified "Create Successful"
            text: <body> ..." for any other 2xx (unconfirmed — list to check);
            other failures: "Error: <actionable message>".
        """
        try:
            body = build_external_subscription(
                destination_name, destination_type, topic_name, data_type, subscription_data, filter
            )
            # Default POST retry policy (none): a lost answer may mean the
            # subscription was created; the agent lists before repeating.
            response = await client.request(
                "POST",
                KAFKA_SUBSCRIPTION_PATH,
                json_body=body,
                headers=EMF_HEADERS,
                raise_on_error=False,
            )
            data = _parse_json(response)
            result = external_result(data)
            if not response.is_success:
                if response.status_code == 400 and _EXT_INVALID_MARKER in result.lower():
                    raise invalid_params_error(response.status_code, result, body)
                raise http_error(response)
            if result_is(result, EXTERNAL_CREATE_OK):
                summary = (
                    f"topic {body['topicName']} -> {body['destinationName']} "
                    f"({body['destinationType']}), data {body['subscriptionDataType']}"
                )
                if body.get("subscriptionData"):
                    summary += f" {body['subscriptionData']}"
                if body.get("filter"):
                    summary += f", filter {body['filter']}"
                return finalize(
                    f"External subscription created: {summary}. Platform said: {result}\n\n"
                    f"{to_json(body)}",
                    settings,
                )
            lowered = result.lower()
            if _EXT_DUPLICATE_MARKER in lowered:
                raise PlatformError(
                    f"a subscription with topic '{body['topicName']}' already exists (the topic "
                    "name is the platform-wide key, whatever the destination); see it with "
                    "cnc_list_kafka_subscriptions, delete it with "
                    f"cnc_delete_external_subscription or choose another topic. Platform said: "
                    f"{result}"
                )
            if _EXT_DESTINATION_MARKER in lowered:
                why = await explain_destination(body["destinationName"], body["destinationType"])
                raise PlatformError(
                    f"the platform refused destination '{body['destinationName']}' as a "
                    f"{body['destinationType']} destination: {why} Platform said: {result}"
                )
            raise PlatformError(
                f"the platform answered HTTP {response.status_code} to the subscription "
                f'request but not the verified "{EXTERNAL_CREATE_OK}" text: '
                f"{result or response.text.strip()[:200] or '(empty body)'}. The create is "
                "unconfirmed (this endpoint rides application failures inside HTTP 200); "
                "check with cnc_list_kafka_subscriptions before repeating."
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_external_subscription",
        title="Delete External Kafka/gRPC Subscription",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_external_subscription(
        topic_name: Annotated[
            str,
            Field(
                description="topicName of the subscription to delete, as listed by "
                "cnc_list_kafka_subscriptions (e.g. 'cnc-alarms'). The topic is the key: "
                "the platform matches on it alone.",
                min_length=1,
                max_length=249,
            ),
        ],
        destination_name: Annotated[
            str | None,
            Field(
                description="Optional destinationName of the subscription, sent along when "
                "given (e.g. 'ext-kafka'; null or empty to omit). On 7.2 the platform "
                "ignores it and matches on the topic alone (verified live); pass it on a "
                "build that keys on more.",
                max_length=200,
            ),
        ] = None,
        destination_type: Annotated[
            str | None,
            Field(
                description="Optional destinationType, 'Kafka' or 'gRPC', sent along when "
                "given (null or empty to omit); ignored by 7.2 (matches on the topic alone).",
                max_length=10,
            ),
        ] = None,
    ) -> str:
        """Delete an external Kafka/gRPC subscription by topic name — the platform
        stops publishing that data type to the destination's topic.

        Write, destructive. Sends DELETE /crosswork/notification/v2/subscription
        {"subscriptionList": [{"topicName": <topic>[, "destinationName",
        "destinationType"]}]} (plain JSON service). VERIFIED LIVE (2026-09-15):
        the platform matches on topicName ALONE — a body naming a wrong
        destination name, type or data type still deleted the subscription of
        that topic — so the topic is all that is required; the optional fields
        are sent verbatim when given for builds that key on more. Success is
        HTTP 200 {"result": "Delete Successful"} — ONLY that text confirms the
        delete; a 2xx with any other body is reported as unconfirmed (this
        platform rides application failures inside HTTP 200). An unknown topic
        — including one already deleted — is HTTP 400 {"result": "Following
        subscription(s) not found and could not be deleted :[<topic>]"} and is
        reported as not found, so a repeat is harmless (the DELETE keeps the
        client's idempotent auto-retry).

        Args:
            topic_name: the topic (key).
            destination_name / destination_type: optional (null or empty to
                omit), sent when given.

        Returns:
            str: "External subscription for topic '<topic>' deleted. Platform
            said: Delete Successful". "Error: no external subscription for topic
            '<topic>' (list with cnc_list_kafka_subscriptions)" when it does not
            exist; "Error: the platform answered HTTP <n> to the delete of topic
            '<topic>' but not the verified "Delete Successful" text: <body> ..."
            for a 2xx without that text; other failures: "Error: <actionable
            message>".
        """
        try:
            topic = topic_name.strip()
            if not topic:
                raise PlatformError("topic_name must not be blank (e.g. 'cnc-alarms').")
            entry: dict[str, Any] = {"topicName": topic}
            if (destination_name or "").strip():
                entry["destinationName"] = (destination_name or "").strip()
            wire_type = canonical(destination_type, DESTINATION_TYPES, "destination_type")
            if wire_type is not None:
                entry["destinationType"] = wire_type
            response = await client.request(
                "DELETE",
                KAFKA_SUBSCRIPTION_PATH,
                json_body={"subscriptionList": [entry]},
                headers=EMF_HEADERS,
                raise_on_error=False,
            )
            result = external_result(_parse_json(response))
            if not response.is_success:
                if response.status_code == 400 and _EXT_NOT_FOUND_MARKER in result.lower():
                    raise PlatformError(
                        f"no external subscription for topic '{topic}' (list with "
                        "cnc_list_kafka_subscriptions)"
                    )
                raise http_error(response)
            if not result_is(result, EXTERNAL_DELETE_OK):
                said = result or response.text.strip()[:200] or "(empty body)"
                raise PlatformError(
                    f"the platform answered HTTP {response.status_code} to the delete of topic "
                    f"'{topic}' but not the verified \"{EXTERNAL_DELETE_OK}\" text: {said}. The "
                    "delete is unconfirmed (this platform rides application failures inside "
                    "HTTP 200); check with cnc_list_kafka_subscriptions before assuming it is "
                    "gone."
                )
            return finalize(
                f"External subscription for topic '{topic}' deleted. Platform said: {result}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_clear_notification_subscriptions_by_topic",
        title="Clear Notification Subscriptions By Topic",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_clear_notification_subscriptions_by_topic(
        topic: Annotated[
            str,
            Field(
                description="Notification topic to clear: 'alarm' or 'inventory'.",
                max_length=20,
            ),
        ],
    ) -> str:
        """Clear EVERY notification subscription of one topic (alarm or
        inventory) in a single call — the webhook (connection-less)
        subscriptions and, per the spec, the open WebSocket sessions of that
        topic, across users.

        Write, destructive, bulk: prefer cnc_delete_notification_subscription
        for one subscription; use this only to sweep a topic (e.g. after a
        consumer was decommissioned and left subscriptions behind). Sends POST
        /crosswork/notification/restconf/data/v2/clear-by-topic/<topic> (EMF
        base, no body). VERIFIED LIVE (2026-09-15): the answer is HTTP 200 with
        the text "Clear successful" whether the topic had subscriptions (a
        webhook subscription of topic inventory was gone from the admin list
        afterwards), had none, or is not even a known topic — the operation
        validates nothing and reports no count. So this tool (1) refuses a topic
        other than alarm/inventory before sending, (2) lists every user's
        subscriptions (notifications:subscription-admin, first page of 100)
        BEFORE the clear and answers "nothing to clear" WITHOUT sending when
        the topic has none, (3) lists again AFTER and reports what was removed
        and what, if anything, of that topic still remains (reported as an
        error, since the platform said success). Verified on the configured
        user's own webhook subscription; that the sweep also covers other users'
        subscriptions and WebSocket sessions follows the spec and was not
        exercised. Only the "Clear successful" text confirms the clear.

        Args:
            topic: 'alarm' | 'inventory' (case-insensitive).

        Returns:
            str: "Cleared <n> notification subscription(s) of topic <topic>
            (ids <id>, ...). Platform said: Clear successful" — the ids are the
            subscription-ids the admin list showed before the clear, each with
            its client URL and user; "No notification subscriptions of topic
            <topic> to clear (every user's view); nothing sent." when there were
            none (not an error). "Error: Unknown topic ..." (nothing sent);
            "Error: the platform answered HTTP <n> to clear-by-topic/<topic> but
            not the verified "Clear successful" text: <body> ..." for a 2xx
            without that text; "Error: the platform said "Clear successful" for
            topic <topic> but <k> subscription(s) of that topic remain: ..." when
            the after-list still shows some; "Error: EMF RESTCONF rejected the
            request (HTTP <n>): ..." for an rc.errors answer; other failures:
            "Error: <actionable message>".
        """
        try:
            wire_topic = canonical(topic, TOPICS, "topic")
            if wire_topic is None:
                raise PlatformError(f"topic must not be blank. Use one of: {', '.join(TOPICS)}.")

            async def admin_page() -> tuple[list[dict[str, Any]], bool]:
                response = await client.request(
                    "GET",
                    SUBSCRIPTION_ADMIN_PATH,
                    headers=EMF_HEADERS,
                    params=page_params(0, MAX_COUNT),
                    raise_on_error=False,
                )
                subs, header = subscription_items(emf_body(response), SUBSCRIPTION_ADMIN_PATH)
                envelope = page_envelope_from(subs, header, 0, MAX_COUNT)
                return subscriptions_of_topic(subs, wire_topic), bool(envelope.get("has_more"))

            before, more_before = await admin_page()
            if not before:
                note = (
                    " (the admin view was a full page of 100 — the topic may have more beyond it)"
                    if more_before
                    else ""
                )
                return finalize(
                    f"No notification subscriptions of topic {wire_topic} to clear (every "
                    f"user's view){note}; nothing sent.",
                    settings,
                )
            response = await client.request(
                "POST",
                f"{CLEAR_BY_TOPIC_PATH}/{wire_topic}",
                headers=EMF_HEADERS,
                raise_on_error=False,
            )
            if not response.is_success:
                raise rejection(response)
            if not clear_confirmed(response.text):
                said = response.text.strip()[:200] or "(empty body)"
                raise PlatformError(
                    f"the platform answered HTTP {response.status_code} to "
                    f'clear-by-topic/{wire_topic} but not the verified "{CLEAR_OK}" text: '
                    f"{said}. The clear is unconfirmed (this platform rides application "
                    "failures inside HTTP 200); check with cnc_list_notification_subscriptions "
                    "all_users=True."
                )
            after, _ = await admin_page()
            if after:
                remaining = ", ".join(
                    f"{field(s, 'subscription-id')} ({field(s, 'client-url') or '?'}, user "
                    f"{field(s, 'subscribed-user') or '?'})"
                    for s in after
                )
                raise PlatformError(
                    f'the platform said "{response.text.strip()}" for topic {wire_topic} but '
                    f"{len(after)} subscription(s) of that topic remain in the admin view: "
                    f"{remaining}. Delete them singly with cnc_delete_notification_subscription."
                )
            cleared = ", ".join(
                f"{field(s, 'subscription-id')} ({field(s, 'client-url') or '?'}, user "
                f"{field(s, 'subscribed-user') or '?'})"
                for s in before
            )
            more = (
                " The admin view was a full page of 100 before the clear, so the count is a "
                "lower bound."
                if more_before
                else ""
            )
            return finalize(
                f"Cleared {len(before)} notification subscription(s) of topic {wire_topic} "
                f"(ids {cleared}). Platform said: {response.text.strip()[:200]}{more}",
                settings,
            )
        except Exception as e:
            return format_error(e)
