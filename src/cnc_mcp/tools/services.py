"""Service inventory tools — the read side of Crosswork's service layer: the CAT
(Crosswork Active Topology) service inventory, NSO's own service objects and
nano plans through the RESTCONF proxy, the L3/L2 VPN operational data and the
T-SDN function-pack deployment state.

What CAT is. Crosswork Network Controller provisions transport and VPN
services through NSO's **T-SDN core function packs** (CFPs): the SR-TE CFP
(``cisco-sr-te-cfp``: SR policies, ODN templates, SID lists), the
circuit-style SR-TE CFP, the IETF L3NM / L2NM VPN models (``ietf-l3vpn-ntw`` /
``ietf-l2vpn-ntw`` as deviated by NSO), the IETF network-slice model and
``ietf-te`` tunnels. The **CAT inventory** (``/crosswork/nbi/cat-inventory/v1/
restconf``) is the index Crosswork builds over those NSO services — what the
"Services & Traffic Engineering" UI lists — and answers *which* services exist,
of which type, and whether each one's NSO plan is ``completed`` / ``failed`` /
``in-progress``. The service objects themselves stay in NSO and are read
through the proxy (``/crosswork/proxy/nso/restconf/data/<yang-path>``).

Path conventions (verified live 2026-09-13, see the platform notes):

- ``yang-path`` is the service's RESTCONF data path **relative to the proxy's
  ``/data/``**, e.g. ``cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/
  odn-template=mcp-odn-90``; ``plan-yang-path`` is the nano plan of that
  service. **The plan list is NOT derivable by a naming rule**: only the
  SR-TE CFP's ``odn-template`` / ``policy`` lists have a sibling
  ``<list>-plan`` (verified live). The other five live elsewhere — the
  circuit-style policy's plan is the top-level ``cisco-cs-sr-te-cfp:
  cs-sr-te-plan``, the VPN / slice / tunnel plans are augments of a
  ``cisco-*`` module (``vpn-services/cisco-l3vpn-ntw:vpn-service-plan``,
  ``tunnels/cisco-te:tunnel-plan``, ...). The seven pairs, as the function-
  pack deployment manager documents them (``packagesInfo[].service-path`` /
  ``plan-path``, matching the CFP YANG), are in :data:`SERVICE_TYPES`;
  :func:`plan_path_of` maps through that table and only falls back to the
  ``<list>-plan`` guess for a list it does not know — prefer the
  ``plan-yang-path`` CAT returns whenever you have it.
- Service types are QNames ``{<namespace>}<local-name>`` — the seven types of
  a 7.2 instance are in :data:`SERVICE_TYPES` with a short label each
  (``policy``, ``odn-template``, ``cs-sr-te-policy``, ``ietf-l3vpn``,
  ``ietf-l2vpn``, ``slice-service``, ``tunnel``); every tool accepts either
  the label or the QName. ``cnc_list_service_types`` is the live authority.
- CAT RPCs are ``POST operations/cat-inventory-rpc:<rpc>`` with
  ``Content-Type``/``Accept: application/yang-data+json`` and the body
  ``{"cat-inventory-rpc:input": {"cat-inventory-rpc:<rpc>-request": {...}}}``;
  they answer ``{"cat-inventory-rpc:output": {"<rpc>-response": {...}}}`` —
  the response key has NO module prefix — and ``{"cat-inventory-rpc:output":
  {}}`` when an association is empty.
- Not-found spellings: the CAT data GETs answer ``409 data-missing`` (bare
  ``errors`` key; the *batch* VPN list answers the same 409 when no service
  exists at all), the NSO proxy ``404`` with an ``ietf-restconf:errors``
  document (``invalid-value`` "uri keypath not found"), and an unknown plan
  path answers HTTP 200 with ``status "unknown"`` / "service plan data not
  found".

Two things this module is NOT: writes (creating / changing / deleting
services through the proxy — the ``service_provisioning`` module:
cnc_create_odn_template, cnc_create_cfp_sr_policy, ...), and the
**PCE-initiated** SR policies of the Optimization Engine
(cnc_list_sr_policies / cnc_create_sr_policy in ``te_state`` /
``sr_te_operations``) — those are programmed by the SR-PCE over PCEP and are
not NSO services, so they never appear in CAT; the ``policy`` type here is the
SR-TE CFP's *configured* policy, rendered on the head-end by NSO.
"""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any, NamedTuple

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import INVENTORY, unwrap
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, finalize, pagination_envelope, to_json
from cnc_mcp.polling import wait_until
from cnc_mcp.restconf import (
    CAT_INVENTORY_NBI,
    NSO_PROXY,
    YANG_ACCEPT,
    YANG_HEADERS,
    encode_key,
    is_not_found,
    rpc_output,
    rpc_path,
    unwrap_list,
)
from cnc_mcp.safety import AppContext, register_tool
from cnc_mcp.tools.te_state import kv_text

CAT_DATA = f"{CAT_INVENTORY_NBI}/data"
CAT_RPC_MODULE = "cat-inventory-rpc"
NSO_DATA = f"{NSO_PROXY}/data"
NSO_DATA_PREFIX = f"{NSO_DATA}/"
# Function-pack deployment manager: plain JSON, no YANG headers (verified live).
FP_BASE = "/crosswork/cat/cat-fp-deployment-manager-service/v1/twophasecommitrunner"
FP_PACKAGES_URL = f"{FP_BASE}/packages"
FP_DEPLOYMENT_INFO_URL = f"{FP_BASE}/getDeploymentInfo"
# Inventory lookup used to turn a TE router-id into the NSO device name (the
# head-end key of get-associated-services-for-transport), as Cisco's own
# service-underlay-change example does before calling the RPC.
NODES_QUERY_URL = f"{INVENTORY}/nodes/query"
NSO_PROVIDER_FAMILY = "ROBOT_PROVIDER_NSO"
NODE_LOOKUP_PAGE_SIZE = 200

# CAT RPC names (all verified live).
RPC_SERVICE_TYPES = "get-available-service-types"
RPC_SERVICES_COUNT = "get-services-count"
RPC_ALL_SERVICES = "get-all-services"
RPC_PLAN_DATA = "get-service-plan-data"
RPC_SUB_SERVICE_COUNT = "get-sub-service-count"
RPC_SUB_SERVICE_PATHS = "get-sub-service-paths"
RPC_SERVICES_FOR_TRANSPORT = "get-associated-services-for-transport"

PLAN_STATUSES = ("completed", "failed", "in-progress", "delete-in-progress", "unknown")
PLAN_NOT_FOUND_MARKER = "service plan data not found"
DEFAULT_WAIT_TARGET = "completed"


class ServiceType(NamedTuple):
    """One CAT service type: the label the tools accept, its QName parts, NSO's list paths.

    ``service_path`` / ``plan_path`` are the service list and its nano-plan
    list relative to the proxy's ``/data/`` — the pairs the function-pack
    deployment manager documents as ``packagesInfo[].service-path`` /
    ``plan-path`` (they match the CFP YANG: ``cisco-cs-sr-te-cfp.yang`` defines
    the top-level ``cs-sr-te-plan`` list, ``cisco-l3vpn-ntw.yang`` /
    ``cisco-l2vpn-ntw.yang`` augment ``vpn-services`` with ``vpn-service-plan``).
    """

    label: str
    namespace: str
    local: str
    service_path: str
    plan_path: str
    description: str

    @property
    def qname(self) -> str:
        return f"{{{self.namespace}}}{self.local}"


# The seven service types of a 7.2 instance, QNames VERBATIM from a live
# ``get-available-service-types`` (2026-09-13). Six namespaces are those of the
# YANG modules NSO serves; the policy type is the exception — CAT reports its own
# ``cisco-ts-sr-policies`` namespace, NOT the YANG module's
# ``cisco-tsdn-sr-te-sr-policies`` (the function-pack deployment manager's
# ``packagesInfo`` spelling), and a type filter must send what CAT reports. The plan
# lists are the deployment manager's documented ``plan-path`` per package: only
# the two SR-TE CFP lists follow the ``<list>-plan`` sibling rule (verified live);
# the others are a different list name or a ``cisco-*`` augment.
SERVICE_TYPES: tuple[ServiceType, ...] = (
    ServiceType(
        "policy",
        "http://cisco.com/ns/nso/cfp/cisco-ts-sr-policies",
        "policy",
        "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy",
        "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy-plan",
        "SR-TE policy configured on the head-end by the SR-TE CFP (not a PCE-initiated one)",
    ),
    ServiceType(
        "odn-template",
        "http://cisco.com/ns/nso/cfp/cisco-tsdn-sr-te-sr-odn",
        "odn-template",
        "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template",
        "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template-plan",
        "on-demand next-hop template (color + head-ends + dynamic/explicit path)",
    ),
    ServiceType(
        "cs-sr-te-policy",
        "http://cisco.com/ns/nso/cfp/cisco-cs-sr-te-cfp",
        "cs-sr-te-policy",
        "cisco-cs-sr-te-cfp:cs-sr-te-policy",
        "cisco-cs-sr-te-cfp:cs-sr-te-plan",
        "circuit-style SR-TE policy (bidirectional, protected, bandwidth-guaranteed)",
    ),
    ServiceType(
        "ietf-l3vpn",
        "urn:ietf:params:xml:ns:yang:ietf-l3vpn-ntw",
        "vpn-service",
        "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service",
        "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/cisco-l3vpn-ntw:vpn-service-plan",
        "L3VPN service (IETF L3NM, RFC 9182 as deviated by NSO)",
    ),
    ServiceType(
        "ietf-l2vpn",
        "urn:ietf:params:xml:ns:yang:ietf-l2vpn-ntw",
        "vpn-service",
        "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service",
        "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/cisco-l2vpn-ntw:vpn-service-plan",
        "L2VPN / EVPN service (IETF L2NM, RFC 9291 as deviated by NSO)",
    ),
    ServiceType(
        "slice-service",
        "urn:ietf:params:xml:ns:yang:ietf-network-slice-service",
        "slice-service",
        "ietf-network-slice-service:network-slice-services/slice-service",
        "ietf-network-slice-service:network-slice-services/"
        "cisco-network-slice-service:slice-service-plan",
        "IETF network slice service",
    ),
    ServiceType(
        "tunnel",
        "urn:ietf:params:xml:ns:yang:ietf-te",
        "tunnel",
        "ietf-te:te/tunnels/tunnel",
        "ietf-te:te/tunnels/cisco-te:tunnel-plan",
        "RSVP-TE tunnel (IETF TE model)",
    ),
)
SERVICE_TYPE_LABELS = tuple(t.label for t in SERVICE_TYPES)
_TYPES_BY_LABEL = {t.label: t for t in SERVICE_TYPES}
_TYPES_BY_QNAME = {t.qname: t for t in SERVICE_TYPES}
# Service list path -> plan list path (and back) for the seven documented types.
PLAN_LIST_OF: dict[str, str] = {t.service_path: t.plan_path for t in SERVICE_TYPES}
SERVICE_LIST_OF: dict[str, str] = {t.plan_path: t.service_path for t in SERVICE_TYPES}
# Friendly spellings agents reach for; each maps to a label above.
_TYPE_ALIASES = {
    "sr-policy": "policy",
    "sr-te-policy": "policy",
    "odn": "odn-template",
    "cs-sr-te": "cs-sr-te-policy",
    "cs-policy": "cs-sr-te-policy",
    "l3vpn": "ietf-l3vpn",
    "l3": "ietf-l3vpn",
    "l2vpn": "ietf-l2vpn",
    "l2": "ietf-l2vpn",
    "slice": "slice-service",
    "network-slice": "slice-service",
    "te-tunnel": "tunnel",
    "rsvp-te-tunnel": "tunnel",
}
_LABEL_CHOICES = ", ".join(SERVICE_TYPE_LABELS)


class VpnLayer(NamedTuple):
    """The module names of one VPN network model on the CAT NBI."""

    layer: str
    module: str  # ietf-l3vpn-ntw / ietf-l2vpn-ntw
    root: str  # l3vpn-ntw / l2vpn-ntw
    cisco_module: str  # cisco-l3vpn-ntw / cisco-l2vpn-ntw (the discovered-underlay augment)


VPN_LAYERS: dict[str, VpnLayer] = {
    "l3": VpnLayer("l3", "ietf-l3vpn-ntw", "l3vpn-ntw", "cisco-l3vpn-ntw"),
    "l2": VpnLayer("l2", "ietf-l2vpn-ntw", "l2vpn-ntw", "cisco-l2vpn-ntw"),
}

_RESPONSE_FORMAT_DESC = "'markdown' for human-readable output, 'json' for the raw platform data."
_LAYER_DESC = "'l3' (ietf-l3vpn-ntw, default) or 'l2' (ietf-l2vpn-ntw)."
_VPN_ID_DESC = (
    "The VPN service id (the vpn-id list key, exact and case-sensitive, e.g. 'mcp-l3vpn-91'); "
    "find it with cnc_list_vpn_services or cnc_list_services(service_type='ietf-l3vpn')."
)
_YANG_PATH_DESC = (
    "The service's yang-path as cnc_list_services returns it, relative to the NSO proxy's "
    "/data/ (e.g. 'cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template=mcp-odn-90'); "
    "a leading '/' or the full '/crosswork/proxy/nso/restconf/data/' prefix is accepted."
)
_PLAN_PATH_DESC = (
    "The plan-yang-path as cnc_list_services returns it (e.g. 'cisco-sr-te-cfp:sr-te/"
    "cisco-sr-te-cfp-sr-odn:odn/odn-template-plan=mcp-odn-90'). A service yang-path of one "
    "of the seven known types is accepted too and mapped to that type's plan list (e.g. "
    "'cisco-cs-sr-te-cfp:cs-sr-te-policy=cs1' -> 'cisco-cs-sr-te-cfp:cs-sr-te-plan=cs1', "
    "'ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=v1' -> '.../vpn-services/"
    "cisco-l3vpn-ntw:vpn-service-plan=v1'); for any other service list the plan path is only "
    "guessed (<list>-plan), so pass the plan-yang-path itself."
)
_SERVICE_TYPE_HELP = (
    f"a label ({_LABEL_CHOICES}) or the QName '{{<namespace>}}<local-name>' "
    "cnc_list_service_types shows"
)


# --- URL / body builders ---------------------------------------------------------


def cat_rpc_url(rpc: str) -> str:
    """``/crosswork/nbi/cat-inventory/v1/restconf/operations/cat-inventory-rpc:<rpc>``."""
    return rpc_path(CAT_INVENTORY_NBI, CAT_RPC_MODULE, rpc)


def cat_rpc_body(rpc: str, request: dict[str, Any] | None) -> dict[str, Any]:
    """The verified CAT RPC envelope.

    ``{"cat-inventory-rpc:input": {"cat-inventory-rpc:<rpc>-request": {...}}}``,
    or ``{"cat-inventory-rpc:input": {}}`` when ``request`` is None (the form
    ``get-available-service-types`` takes — it has no request container).
    """
    if request is None:
        return {f"{CAT_RPC_MODULE}:input": {}}
    return {f"{CAT_RPC_MODULE}:input": {f"{CAT_RPC_MODULE}:{rpc}-request": request}}


def cat_rpc_response(data: Any, rpc: str) -> dict[str, Any]:
    """The ``<rpc>-response`` container of a CAT RPC answer (``{}`` when absent).

    Verified: the answer is ``{"cat-inventory-rpc:output": {"<rpc>-response":
    {...}}}`` with NO module prefix on the response key (a prefixed one is
    tolerated), and ``{"cat-inventory-rpc:output": {}}`` for an empty
    association — which is the ``{}`` this returns.
    """
    output = rpc_output(data, CAT_RPC_MODULE)
    for key in (f"{rpc}-response", f"{CAT_RPC_MODULE}:{rpc}-response"):
        value = output.get(key)
        if isinstance(value, dict):
            return value
    return {}


def normalize_yang_path(path: str) -> str:
    """A service/plan path as the proxy wants it after ``/data/`` (no leading slash).

    Accepts the relative form CAT returns, a leading ``/``, and the full
    ``/crosswork/proxy/nso/restconf/data/<path>`` (or ``.../restconf/data/``,
    ``data/``) URL forms. PlatformError when nothing is left.
    """
    text = (path or "").strip()
    marker = "/restconf/data/"
    if marker in text:
        text = text.split(marker, 1)[1]
    else:
        text = text.lstrip("/")
        if text.startswith("data/"):
            text = text[len("data/") :]
    text = text.strip("/")
    if not text:
        raise PlatformError(
            "yang_path is empty: pass the service's yang-path as cnc_list_services returns it "
            "(e.g. 'cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template=mcp-odn-90')."
        )
    return text


def _split_last_segment(path: str) -> tuple[str, str, str]:
    """``(parent-with-slash, list-name, key)`` of the last ``<list>=<key>`` segment."""
    head, sep, last = path.rpartition("/")
    if "=" not in last:
        raise PlatformError(
            f"'{path}' is not a keyed service path: expected '.../<list>=<key>' such as "
            "'cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template=mcp-odn-90' "
            "(cnc_list_services returns the exact paths)."
        )
    list_name, key = last.split("=", 1)
    return f"{head}{sep}", list_name, key


def _list_path_variants(parent: str, list_name: str) -> tuple[str, ...]:
    """The list path as given and, when its last segment carries a module prefix, without it.

    CAT returns ``.../policies/policy=<n>`` while the proxy also accepts the
    module-qualified ``.../policies/cisco-sr-te-cfp-sr-policies:policy=<n>``
    (the form the verified PUTs used); both must find the table entry.
    """
    as_given = f"{parent}{list_name}"
    if ":" in list_name:
        return as_given, f"{parent}{list_name.rsplit(':', 1)[1]}"
    return (as_given,)


def resolve_plan_path(path: str) -> tuple[str, bool]:
    """``(plan_path, known)`` for a service or plan path.

    ``known`` is True when the path's list is one of the seven documented
    service or plan lists (:data:`PLAN_LIST_OF` / :data:`SERVICE_LIST_OF`) —
    the plan path is then the deployment manager's documented one. For any
    other list the ``<list>=<key>`` -> ``<list>-plan=<key>`` sibling rule
    (verified only for the SR-TE CFP's odn-template and policy) is applied as a
    guess and ``known`` is False; a list name already ending in ``-plan`` is
    returned unchanged. PlatformError for an unkeyed path.
    """
    normalized = normalize_yang_path(path)
    parent, list_name, key = _split_last_segment(normalized)
    for candidate in _list_path_variants(parent, list_name):
        if candidate in PLAN_LIST_OF:
            return f"{PLAN_LIST_OF[candidate]}={key}", True
        if candidate in SERVICE_LIST_OF:
            return f"{candidate}={key}", True
    if list_name.endswith("-plan"):
        return normalized, False
    return f"{parent}{list_name}-plan={key}", False


def plan_path_of(path: str) -> str:
    """The plan path of a service path — through the documented per-type table, else the
    ``<list>-plan`` guess (see :func:`resolve_plan_path`).

    A path that already names a plan list is returned unchanged, so both the
    service and the plan path can be passed wherever a plan is needed.
    """
    return resolve_plan_path(path)[0]


def is_plan_path(path: str) -> bool:
    """True when the path names a documented plan list, or its list name ends in ``-plan``."""
    parent, list_name, _key = _split_last_segment(normalize_yang_path(path))
    if any(c in SERVICE_LIST_OF for c in _list_path_variants(parent, list_name)):
        return True
    return list_name.endswith("-plan")


def service_path_of(path: str) -> str:
    """The service path of a plan path (the inverse of :func:`plan_path_of`)."""
    normalized = normalize_yang_path(path)
    parent, list_name, key = _split_last_segment(normalized)
    for candidate in _list_path_variants(parent, list_name):
        if candidate in SERVICE_LIST_OF:
            return f"{SERVICE_LIST_OF[candidate]}={key}"
        if candidate in PLAN_LIST_OF:
            return f"{candidate}={key}"
    if list_name.endswith("-plan"):
        return f"{parent}{list_name[: -len('-plan')]}={key}"
    return normalized


def nso_data_url(yang_path: str) -> str:
    """``/crosswork/proxy/nso/restconf/data/<path>`` — the path verbatim as CAT returned it."""
    return f"{NSO_DATA}/{normalize_yang_path(yang_path)}"


def vpn_layer(layer: str) -> VpnLayer:
    """``'l3'`` / ``'L2'`` / ``'l3vpn'`` -> the :data:`VPN_LAYERS` entry; else PlatformError."""
    key = (layer or "").strip().lower()
    if key.endswith("vpn"):
        key = key[:-3]
    if key not in VPN_LAYERS:
        raise PlatformError(
            f"Unknown VPN layer '{layer}': use 'l3' (ietf-l3vpn-ntw) or 'l2' (ietf-l2vpn-ntw)."
        )
    return VPN_LAYERS[key]


def vpn_services_url(layer: VpnLayer) -> str:
    """``CAT/data/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service`` (batch form)."""
    return f"{CAT_DATA}/{layer.module}:{layer.root}/vpn-services/vpn-service"


def vpn_service_url(layer: VpnLayer, vpn_id: str) -> str:
    """The keyed CAT GET for one VPN service (``vpn-id`` percent-encoded as one key)."""
    return f"{vpn_services_url(layer)}={encode_key(vpn_id)}"


# Verified 2026-09-14 with a live L3VPN: the batch list and the per-service
# oper-status are readable ONLY with ``content=nonconfig`` — without it the batch
# GET answers 409 data-missing even when services exist, and the ``/status/oper-status``
# sub-path answers 409 for an existing service (only the node itself is readable).
NONCONFIG = {"content": "nonconfig"}


def vpn_oper_status_url(layer: VpnLayer, vpn_id: str) -> str:
    """The keyed CAT GET read with ``content=nonconfig`` — the oper-status view of one VPN."""
    return vpn_service_url(layer, vpn_id)


def vpn_underlay_url(layer: VpnLayer, vpn_id: str) -> str:
    return (
        f"{vpn_service_url(layer, vpn_id)}/underlay-transport/"
        f"{layer.cisco_module}:discovered-underlay-transport"
    )


# --- service types -----------------------------------------------------------------


def service_type_qname(value: str) -> str:
    """A label / alias / QName -> the QName CAT filters on; PlatformError for an unknown label.

    A value starting with ``{`` is taken as a QName verbatim (CAT is the
    authority on those); anything else must be one of :data:`SERVICE_TYPE_LABELS`
    (case-insensitive, underscores accepted) or a friendly alias.
    """
    text = (value or "").strip()
    if text.startswith("{"):
        if "}" not in text[1:] or text.endswith("}"):
            raise PlatformError(
                f"'{text}' is not a service-type QName: the form is '{{<namespace>}}<local-name>' "
                "as cnc_list_service_types shows it."
            )
        return text
    key = text.lower().replace("_", "-")
    key = _TYPE_ALIASES.get(key, key)
    entry = _TYPES_BY_LABEL.get(key)
    if entry is None:
        raise PlatformError(
            f"Unknown service type '{value}'. Use one of the labels {_LABEL_CHOICES}, or the "
            "QName '{<namespace>}<local-name>' from cnc_list_service_types."
        )
    return entry.qname


def service_type_label(qname: Any) -> str:
    """The label for a known QName, else the QName's local name, else the raw text."""
    text = str(qname or "").strip()
    entry = _TYPES_BY_QNAME.get(text)
    if entry is not None:
        return entry.label
    if text.startswith("{") and "}" in text:
        return text.split("}", 1)[1] or text
    return text or "?"


def parse_service_types(text: str) -> list[str]:
    """``'policy, odn-template'`` -> QNames (``[]`` when blank); PlatformError on an unknown one."""
    return [service_type_qname(part) for part in (text or "").split(",") if part.strip()]


# --- pure helpers: shapes ------------------------------------------------------------


def dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def field(data: Any, name: str) -> Any:
    """``data[name]``, tolerating a module-prefixed key (``cisco-l3vpn-ntw:headend``).

    The CAT OpenAPI documents spell every leaf inside the augment containers
    with its module prefix; RFC 7951 JSON carries the prefix only where the
    module changes. Both are read.
    """
    if not isinstance(data, dict):
        return None
    if name in data:
        return data[name]
    suffix = f":{name}"
    for key, value in data.items():
        if str(key).endswith(suffix):
            return value
    return None


def _int_or(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def service_object(data: Any) -> dict[str, Any] | None:
    """The one service entry of a keyed proxy GET (``{"<module>:<list>": [entry]}``), or None.

    A bare dict value (a container GET) is returned as-is; an empty body
    (204) or an empty list is ``None``.
    """
    if not isinstance(data, dict) or not data:
        return None
    for value in data.values():
        if isinstance(value, list):
            entries = dict_list(value)
            return entries[0] if entries else None
        if isinstance(value, dict):
            return value
    return None


_NSO_BOOKKEEPING = (
    "created",
    "last-modified",
    "last-run",
    "modified",
    "directly-modified",
    "plan-location",
    "log",
    "commit-queue",
)
_SERVICE_KEY_LEAVES = ("name", "vpn-id", "id", "slice-service-id")


def service_key_of(service: dict[str, Any]) -> str:
    """The list key of a service object (``name`` / ``vpn-id`` / ``id``), else '?'."""
    for leaf in _SERVICE_KEY_LEAVES:
        value = service.get(leaf)
        if value not in (None, ""):
            return str(value)
    return "?"


def split_bookkeeping(service: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """``(nso_bookkeeping, service_body)`` — NSO's service metadata apart from the config."""
    meta = {k: v for k, v in service.items() if k in _NSO_BOOKKEEPING}
    body = {k: v for k, v in service.items() if k not in _NSO_BOOKKEEPING}
    return meta, body


def _modified_summary(meta: dict[str, Any]) -> str:
    modified = meta.get("modified")
    if not isinstance(modified, dict):
        return "-"
    devices = modified.get("devices")
    services = modified.get("services")
    parts = []
    if isinstance(devices, list):
        parts.append(f"devices={','.join(str(d) for d in devices) or '(none)'}")
    if isinstance(services, list):
        parts.append(f"services={','.join(str(s) for s in services) or '(none)'}")
    return " ".join(parts) or kv_text(modified)


def plan_entry_of(response: dict[str, Any], plan_path: str) -> dict[str, Any] | None:
    """The ``service-plan-data`` entry for ``plan_path`` (the first one when no path matches)."""
    entries = dict_list(response.get("service-plan-data"))
    for entry in entries:
        if str(entry.get("yang-path") or "").strip("/") == plan_path.strip("/"):
            return entry
    return entries[0] if entries else None


def plan_status(entry: dict[str, Any] | None) -> str:
    return str((entry or {}).get("status") or "unknown").strip().lower()


def plan_error_message(entry: dict[str, Any] | None) -> str | None:
    info = (entry or {}).get("error-info")
    if isinstance(info, dict):
        message = info.get("message")
        if isinstance(message, str) and message.strip():
            return message.strip()
    elif isinstance(info, str) and info.strip():
        return info.strip()
    return None


def plan_not_found(entry: dict[str, Any] | None) -> bool:
    """True for the verified "no such plan" answer: status ``unknown`` (+ "service plan data
    not found"), or no entry at all."""
    if entry is None:
        return True
    if plan_status(entry) != "unknown":
        return False
    message = plan_error_message(entry) or ""
    return not message or PLAN_NOT_FOUND_MARKER in message.lower()


def normalize_plan_status(value: str) -> str:
    """``' Completed '`` / ``'in_progress'`` -> a :data:`PLAN_STATUSES` member, else error."""
    key = (value or "").strip().lower().replace("_", "-")
    if key not in PLAN_STATUSES:
        raise PlatformError(
            f"Unknown plan status '{value}'. Use one of: {', '.join(PLAN_STATUSES)}."
        )
    return key


def plan_components(plan_object: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The nano-plan ``plan.component`` list of a ``<list>-plan`` entry (``[]`` when absent)."""
    if not isinstance(plan_object, dict):
        return []
    plan = plan_object.get("plan")
    if not isinstance(plan, dict):
        return []
    return dict_list(plan.get("component"))


def _short_type(value: Any) -> str:
    """``tailf-ncs:self`` -> ``self``; ``...nano-plan-services:head-end`` -> ``head-end``."""
    text = str(value or "?")
    return text.rsplit(":", 1)[-1]


def _state_text(state: dict[str, Any]) -> str:
    text = f"{_short_type(state.get('name'))}={state.get('status', '?')}"
    when = state.get("when")
    if when:
        text += f"@{when}"
    return text


def component_line(component: dict[str, Any]) -> str:
    """One markdown line per nano-plan component: type/name, each state, back-track."""
    states = dict_list(component.get("state"))
    line = (
        f"- **{_short_type(component.get('type'))}** {component.get('name', '?')}: "
        f"{' '.join(_state_text(s) for s in states) or '(no states)'}"
    )
    if component.get("back-track") not in (None, False, "false"):
        line += f" back-track={component.get('back-track')}"
    other = {k: v for k, v in component.items() if k not in ("type", "name", "state", "back-track")}
    if other:
        line += f" {kv_text(other)}"
    return line


def transport_ref(
    *,
    headend: str,
    color: int,
    endpoint: str,
    tunnel_id: str,
    source: str,
    destination: str,
) -> dict[str, dict[str, str]]:
    """The ``sr-policy-ref`` or ``te-tunnel-ref`` request object; PlatformError when incomplete.

    A head-end selects the SR-policy form (``color`` sent as a string —
    verified) and then needs color and endpoint; otherwise a tunnel-id
    selects the RSVP-TE form and needs source and destination. Nothing is
    sent for a half-given reference. ``headend`` is passed through as given:
    the tool resolves a router-id to the NSO device name before calling this
    (see :func:`looks_like_ip_address`).
    """
    head = headend.strip()
    end = endpoint.strip()
    tunnel = tunnel_id.strip()
    src = source.strip()
    dst = destination.strip()
    if head:
        missing = [n for n, v in (("color", color > 0), ("endpoint", bool(end))) if not v]
        if missing:
            raise PlatformError(
                f"An SR policy reference needs headend, color and endpoint; missing: "
                f"{', '.join(missing)}. Keys come from cnc_get_vpn_underlay_transport (headend = "
                "the NSO device name, i.e. the inventory host_name, e.g. 'PE1'; endpoint = the "
                "policy endpoint IP). cnc_list_sr_policies keys on TE router-ids instead — a "
                "dotted-quad headend is resolved to the device name through the inventory."
            )
        return {"sr-policy-ref": {"headend": head, "color": str(color), "endpoint": end}}
    if tunnel:
        missing = [n for n, v in (("source", bool(src)), ("destination", bool(dst))) if not v]
        if missing:
            raise PlatformError(
                f"An RSVP-TE tunnel reference needs tunnel_id, source and destination; missing: "
                f"{', '.join(missing)} (cnc_list_rsvp_te_tunnels shows the keys)."
            )
        return {"te-tunnel-ref": {"tunnel-id": tunnel, "source": src, "destination": dst}}
    raise PlatformError(
        "Give either an SR policy (headend + color + endpoint) or an RSVP-TE tunnel (tunnel_id "
        "+ source + destination) to look up; nothing was sent."
    )


def looks_like_ip_address(value: str) -> bool:
    """True for a dotted-quad / IPv6 literal — a TE router-id where a device name belongs."""
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def te_router_id_query(router_id: str) -> dict[str, Any]:
    """The ``nodes/query`` body Cisco's own underlay-change example sends to map a router-id
    to its NSO node id: a nested ``routing_info.te_router_id`` filter (the filter is a
    ``RobotNodeData`` object in the DLM document), with the verified ``filterData`` paging."""
    return {
        "filter": {"routing_info": {"te_router_id": router_id}},
        "filterData": {"PageSize": NODE_LOOKUP_PAGE_SIZE, "PageNum": 0, "Criteria": ""},
    }


def nso_node_id_of(node: dict[str, Any]) -> str | None:
    """The NSO device name of an inventory node.

    Cisco's example reads ``providers_family.ROBOT_PROVIDER_NSO.providers[]
    .provider_node_id`` (the name NSO knows the device by); ``host_name`` is
    the fallback — CNC onboards devices to NSO under their host name. The
    ``providers`` member is a dict keyed by provider name on this build (a
    list is tolerated).
    """
    families = node.get("providers_family")
    family = families.get(NSO_PROVIDER_FAMILY) if isinstance(families, dict) else None
    providers = family.get("providers") if isinstance(family, dict) else None
    entries = list(providers.values()) if isinstance(providers, dict) else providers
    for entry in entries if isinstance(entries, list) else []:
        node_id = entry.get("provider_node_id") if isinstance(entry, dict) else None
        if isinstance(node_id, str) and node_id.strip():
            return node_id.strip()
    host = node.get("host_name")
    return host.strip() if isinstance(host, str) and host.strip() else None


def nodes_with_te_router_id(nodes: list[dict[str, Any]], router_id: str) -> list[dict[str, Any]]:
    """The nodes whose ``routing_info.te_router_id`` is ``router_id`` (client-side check: an
    inventory filter Crosswork does not honour silently returns the unfiltered set)."""
    matches = []
    for node in nodes:
        routing = node.get("routing_info")
        if isinstance(routing, dict) and str(routing.get("te_router_id") or "") == router_id:
            matches.append(node)
    return matches


# --- markdown renderers -------------------------------------------------------------


def service_info_line(info: dict[str, Any]) -> str:
    return (
        f"- **{info.get('service-name', '?')}** "
        f"type={service_type_label(info.get('service-type'))} "
        f"yang-path={info.get('yang-path', '?')} plan={info.get('plan-yang-path', '-')}"
    )


def plan_data_lines(
    entry: dict[str, Any] | None, plan_path: str, *, service_exists: bool = False
) -> list[str]:
    """Markdown lines for one ``service-plan-data`` entry (or the not-found wording).

    ``service_exists`` picks the not-found wording: when the caller has just
    read the service from NSO, "the service does not exist" would be false —
    CAT has not indexed it yet, or tracks it under another plan path.
    """
    if entry is None or plan_not_found(entry):
        if service_exists:
            return [
                f"- plan {plan_path}: no plan data in CAT for this path (CAT has not indexed "
                "the service yet, or tracks it under a different plan path — "
                "cnc_list_services shows each service's plan-yang-path)"
            ]
        return [
            f"- plan {plan_path}: no plan data (the service does not exist or was never committed)"
        ]
    lines = [
        f"- plan {entry.get('yang-path') or plan_path}: status **{plan_status(entry)}** "
        f"created={entry.get('creation-time') or '-'} "
        f"last-updated={entry.get('last-updated-time') or '-'}"
    ]
    message = plan_error_message(entry)
    if message:
        lines.append(f"  error-info: {message}")
    return lines


def service_markdown(
    yang_path: str,
    service: dict[str, Any],
    plan_path: str | None,
    plan_entry: dict[str, Any] | None,
    plan_note: str | None,
) -> str:
    meta, body = split_bookkeeping(service)
    lines = [
        f"# Service {service_key_of(service)} ({yang_path})",
        "",
        f"- created={meta.get('created') or '-'} last-modified={meta.get('last-modified') or '-'} "
        f"last-run={meta.get('last-run') or '-'} plan-location={meta.get('plan-location') or '-'}",
        f"- modified: {_modified_summary(meta)}"
        + (
            f" directly-modified: {_modified_summary({'modified': meta['directly-modified']})}"
            if isinstance(meta.get("directly-modified"), dict)
            else ""
        ),
    ]
    if plan_note:
        lines.append(f"- plan {plan_path or '-'}: {plan_note}")
    elif plan_path is not None:
        lines.extend(plan_data_lines(plan_entry, plan_path, service_exists=True))
    lines.extend(["", "Service body as NSO holds it:", to_json(body)])
    return "\n".join(lines)


def plan_markdown(
    plan_path: str, entry: dict[str, Any] | None, plan_object: dict[str, Any] | None
) -> str:
    lines = [f"# Service plan {plan_path}", ""]
    lines.extend(plan_data_lines(entry, plan_path))
    if plan_object is not None:
        components = plan_components(plan_object)
        lines.extend(["", f"Nano-plan components ({len(components)}):"])
        if not components:
            lines.append("- (none reported)")
        lines.extend(component_line(c) for c in components)
        other = {k: v for k, v in plan_object.items() if k not in ("plan",) and k != "name"}
        if other:
            lines.append(f"- other: {kv_text(other)}")
    lines.extend(
        [
            "",
            "Statuses: completed = NSO applied the service (every component reached "
            "tailf-ncs:ready), in-progress / delete-in-progress = still converging, failed = "
            "read error-info (and the plan detail), unknown = no plan data.",
        ]
    )
    return "\n".join(lines)


def vpn_nodes(service: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = field(service, "vpn-nodes")
    return dict_list(field(nodes, "vpn-node")) if isinstance(nodes, dict) else []


def vpn_accesses(node: dict[str, Any]) -> list[dict[str, Any]]:
    accesses = field(node, "vpn-network-accesses")
    return dict_list(field(accesses, "vpn-network-access")) if isinstance(accesses, dict) else []


def vpn_oper_status(service: dict[str, Any]) -> dict[str, Any]:
    status = field(service, "status")
    oper = field(status, "oper-status") if isinstance(status, dict) else None
    return oper if isinstance(oper, dict) else {}


def _short_identity(value: Any) -> str:
    """``ietf-vpn-common:op-up`` -> ``op-up`` (identityrefs carry their module prefix)."""
    return str(value).rsplit(":", 1)[-1] if value not in (None, "") else "?"


def vpn_underlay_container(service: dict[str, Any]) -> dict[str, Any]:
    """The ``underlay-transport/<cisco-*>:discovered-underlay-transport`` container of a CAT
    VPN entry (``{}`` when absent)."""
    underlay = field(service, "underlay-transport")
    if not isinstance(underlay, dict):
        return {}
    container = field(underlay, "discovered-underlay-transport")
    return container if isinstance(container, dict) else {}


def underlay_lists(container: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """``(sr_policy_refs, te_tunnel_refs)`` of a ``discovered-underlay-transport`` container."""
    if not isinstance(container, dict):
        return [], []
    return dict_list(field(container, "sr-policy-ref")), dict_list(
        field(container, "te-tunnel-ref")
    )


def underlay_lines(container: Any) -> list[str]:
    """The SR policy and RSVP-TE tunnel references of a discovered-underlay container."""
    policies, tunnels = underlay_lists(container)
    lines = [f"SR policies ({len(policies)}):"]
    if not policies:
        lines.append("- (none discovered)")
    for ref in policies:
        lines.append(
            f"- headend={field(ref, 'headend') or '?'} color={field(ref, 'color') or '?'} "
            f"endpoint={field(ref, 'endpoint') or '?'}"
        )
    lines.extend(["", f"RSVP-TE tunnels ({len(tunnels)}):"])
    if not tunnels:
        lines.append("- (none discovered)")
    for ref in tunnels:
        lines.append(
            f"- tunnel-id={field(ref, 'tunnel-id') or '?'} source={field(ref, 'source') or '?'} "
            f"destination={field(ref, 'destination') or '?'}"
        )
    return lines


def vpn_service_line(service: dict[str, Any]) -> str:
    """One line of *operational* data per CAT VPN entry.

    Cisco's own capture of this GET carries only ``vpn-id``, ``status.
    oper-status`` and the discovered underlay — never the topology or the
    nodes (those are configuration intent, served by the NSO proxy). The
    topology / node fields are shown only when an entry actually carries them,
    so an absent key is never rendered as "nodes=0".
    """
    oper = vpn_oper_status(service)
    line = (
        f"- **{field(service, 'vpn-id') or '?'}** "
        f"oper-status={_short_identity(field(oper, 'status'))}"
    )
    if field(oper, "last-change"):
        line += f" last-change={field(oper, 'last-change')}"
    policies, tunnels = underlay_lists(vpn_underlay_container(service))
    line += f" underlay: {len(policies)} SR policies, {len(tunnels)} RSVP-TE tunnels"
    if field(service, "vpn-service-topology") not in (None, ""):
        line += f" topology={_short_identity(field(service, 'vpn-service-topology'))}"
    if isinstance(field(service, "vpn-nodes"), dict):
        nodes = vpn_nodes(service)
        line += f" nodes={len(nodes)}"
        if nodes:
            line += f" [{', '.join(str(field(n, 'vpn-node-id') or '?') for n in nodes)}]"
    return line


def vpn_service_markdown(layer: VpnLayer, service: dict[str, Any]) -> str:
    vpn_id = field(service, "vpn-id") or "?"
    lines = [f"# {layer.layer.upper()} VPN service {vpn_id}", ""]
    lines.append(vpn_service_line(service))
    lines.extend(["", "Discovered underlay transport:"])
    lines.extend(underlay_lines(vpn_underlay_container(service)))
    if isinstance(field(service, "vpn-nodes"), dict):
        nodes = vpn_nodes(service)
        lines.extend(["", f"Nodes ({len(nodes)}):"])
        if not nodes:
            lines.append("- (none)")
        for node in nodes:
            accesses = vpn_accesses(node)
            lines.append(
                f"- **{field(node, 'vpn-node-id') or '?'}** "
                f"local-as={field(node, 'local-as') or '-'} accesses={len(accesses)}"
            )
            for access in accesses:
                ip = field(field(access, "ip-connection"), "ipv4")
                ip_text = (
                    f" {field(ip, 'local-address')}/{field(ip, 'prefix-length')}"
                    if isinstance(ip, dict)
                    else ""
                )
                lines.append(
                    f"  - access {field(access, 'id') or '?'} "
                    f"interface={field(access, 'interface-id') or '-'}"
                    f"{ip_text}"
                )
    else:
        lines.extend(
            [
                "",
                "This is Crosswork's operational view only: the VPN's nodes, network accesses "
                "and topology are configuration intent, read with cnc_get_service(yang_path="
                f"'{layer.module}:{layer.root}/vpn-services/vpn-service={vpn_id}').",
            ]
        )
    lines.extend(["", "Service as the CAT NBI returns it:", to_json(service)])
    return "\n".join(lines)


def underlay_markdown(layer: VpnLayer, vpn_id: str, container: dict[str, Any]) -> str:
    lines = [f"# Underlay transport of {layer.layer.upper()} VPN service {vpn_id}", ""]
    lines.extend(underlay_lines(container))
    lines.extend(
        [
            "",
            "These are the transport objects Crosswork discovered the VPN riding on; "
            "cnc_find_services_on_transport answers the inverse question (pass headend exactly "
            "as shown — it is the NSO device name). cnc_get_sr_policy / cnc_get_rsvp_te_tunnel "
            "show the transport itself but key on TE router-ids, not device names: map the "
            "headend through cnc_get_device (routing_info.te_router_id) first.",
        ]
    )
    return "\n".join(lines)


def _package_type(namespace: Any) -> str | None:
    for entry in SERVICE_TYPES:
        if entry.namespace == namespace:
            return entry.label
    return None


def function_packs_markdown(info: dict[str, Any], packages: list[dict[str, Any]]) -> str:
    lines = [
        "# T-SDN function packs",
        "",
        f"- deploymentState={info.get('deploymentState') or '?'} "
        f"etcdCfpArchiveVersion={info.get('etcdCfpArchiveVersion') or '-'} "
        f"etcdPodVersion={info.get('etcdPodVersion') or '-'} "
        f"deploymentTime={info.get('deploymentTime') or '-'}",
        "",
        f"Packages ({len(packages)}):",
    ]
    if not packages:
        lines.append("- (none reported)")
    for package in packages:
        namespace = package.get("namespace")
        label = _package_type(namespace)
        head = f"- **{namespace or '?'}**"
        if label:
            head += f" (service type '{label}')"
        head += f" model-version={package.get('model-version') or '-'}"
        if package.get("service-layer"):
            head += f" service-layer={package['service-layer']}"
        if package.get("service-path"):
            head += f" service-path={package['service-path']}"
        if package.get("plan-path"):
            head += f" plan-path={package['plan-path']}"
        lines.append(head)
        for resource in dict_list(package.get("resources")):
            lines.append(
                f"  - {resource.get('label') or '?'}: {resource.get('path') or '?'} "
                f"scope={resource.get('scope') or '-'}"
            )
    return "\n".join(lines)


# --- registration --------------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def call_cat_rpc(rpc: str, request: dict[str, Any] | None) -> dict[str, Any]:
        """POST one CAT RPC (YANG headers, auto-retried: every CAT RPC is a read) -> response."""
        data = await client.request_json(
            "POST",
            cat_rpc_url(rpc),
            json_body=cat_rpc_body(rpc, request),
            headers=YANG_HEADERS,
            retryable=True,
        )
        return cat_rpc_response(data, rpc)

    async def fetch_plan_entry(plan_path: str) -> dict[str, Any] | None:
        """``get-service-plan-data`` for one plan path -> its entry (None when none came back)."""
        response = await call_cat_rpc(RPC_PLAN_DATA, {"service-plan-yang-path": [plan_path]})
        return plan_entry_of(response, plan_path)

    async def resolve_headend_device(router_id: str) -> str:
        """A TE router-id -> the NSO device name of the one inventory node that carries it.

        ``POST nodes/query`` with the nested ``routing_info.te_router_id``
        filter (Cisco's example), re-checked client-side because an inventory
        filter Crosswork does not honour returns the unfiltered set.
        PlatformError when no node (or more than one) has that router-id.
        """
        data = await client.request_json(
            "POST", NODES_QUERY_URL, json_body=te_router_id_query(router_id), retryable=True
        )
        items, _result_count, _total = unwrap(data, "data")
        matches = nodes_with_te_router_id([n for n in items if isinstance(n, dict)], router_id)
        if len(matches) != 1:
            if not matches:
                raise PlatformError(
                    f"no inventory device has te_router_id {router_id} (checked the first "
                    f"{NODE_LOOKUP_PAGE_SIZE} nodes), so the head-end cannot be mapped to its "
                    "NSO device name. Pass the device name (the inventory host_name) as headend "
                    "— cnc_get_vpn_underlay_transport shows it as the service records it."
                )
            names = ", ".join(str(n.get("host_name")) for n in matches[:5])
            raise PlatformError(
                f"te_router_id {router_id} belongs to {len(matches)} inventory devices ({names}); "
                "pass the head-end's device name (host_name) as headend instead."
            )
        name = nso_node_id_of(matches[0])
        if not name:
            raise PlatformError(
                f"the inventory device with te_router_id {router_id} has neither an NSO "
                "provider_node_id nor a host_name; pass the head-end's NSO device name as headend."
            )
        return name

    async def restconf_get(url: str, params: dict[str, Any] | None = None) -> tuple[bool, Any]:
        """GET with ``Accept: application/yang-data+json`` -> ``(found, data)``.

        Not-found is gated per surface, each on its own verified spelling:

        - the NSO proxy (``url`` under ``NSO_DATA``): 404 **with** a RESTCONF
          error document (``invalid-value`` "uri keypath not found") — and
          409 ``data-missing``, which :func:`is_not_found` also accepts;
        - the CAT NBI (everything else): **409 ``data-missing`` only**, as
          te_state / sr_te_operations do on Crosswork's own NBIs. A 404 there —
          bare or with a document — is a malformed / unrouted URL, never a
          missing object, and is raised through http_error with that
          explanation.

        Any other failure is raised through http_error, a non-JSON body as
        PlatformError. A 204 / empty body is ``(True, None)``.
        """
        response = await client.request(
            "GET", url, params=params, headers=YANG_ACCEPT, raise_on_error=False
        )
        data: Any = None
        if response.content:
            try:
                data = response.json()
            except ValueError:
                data = None
        status = response.status_code
        on_proxy = url.startswith(NSO_DATA_PREFIX)
        if is_not_found(status, data) and (on_proxy or status == 409):
            return False, data
        if not response.is_success:
            error = http_error(response)
            if status == 404 and not on_proxy:
                raise PlatformError(
                    f"{error} On the CAT NBI a 404 means the URL was not routed (a malformed "
                    "key or an absent path), never that the object is missing — a missing "
                    "entry answers 409 data-missing."
                )
            raise error
        if response.content and data is None:
            raise PlatformError(
                "The RESTCONF service returned a non-JSON response where YANG JSON was expected."
            )
        return True, data

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_service_types",
        title="List CAT Service Types",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_service_types(
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the service types the CAT inventory knows on this instance (the QName of each).

        Read-only. ``POST .../operations/cat-inventory-rpc:get-available-
        service-types`` with ``{"cat-inventory-rpc:input": {}}`` (the RPC has
        no request container). Each entry is ``service-type`` — the QName
        ``{<namespace>}<local-name>`` every type filter uses — and CAT's
        ``service-type-label``. The seven types of a 7.2 instance and the
        labels this server accepts for them (``policy``, ``odn-template``,
        ``cs-sr-te-policy``, ``ietf-l3vpn``, ``ietf-l2vpn``, ``slice-service``,
        ``tunnel``) are in the module table; a type CAT reports that the table
        does not know is shown with its local name and can be passed to the
        other tools as its QName. Use it to learn what can be provisioned
        before cnc_list_services / cnc_get_service_counts.

        Args:
            response_format: markdown (one line per type: this server's
                label, CAT's label, the QName) or json (the raw
                ``service-type-info`` entries).

        Returns:
            str: Markdown, or JSON {"count": int, "items": [{"service-type":
            "{urn:...}vpn-service", "service-type-label": str, "label": str}]}.
            "Error: ..." on an API failure (a bare 404 -> the CAT inventory
            NBI is not routed on this instance).
        """
        try:
            response = await call_cat_rpc(RPC_SERVICE_TYPES, None)
            infos = dict_list(response.get("service-type-info"))
            items = [
                {**info, "label": service_type_label(info.get("service-type"))} for info in infos
            ]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(items), "items": items}), settings)
            lines = [f"# CAT service types ({len(items)})", ""]
            if not items:
                lines.append("CAT reported no service types (no T-SDN function pack deployed?).")
            for item in items:
                lines.append(
                    f"- **{item['label']}** (CAT label '{item.get('service-type-label') or '-'}'): "
                    f"{item.get('service-type') or '?'}"
                )
            lines.extend(
                [
                    "",
                    "Pass the bold label (or the QName) as service_type to cnc_list_services; "
                    "cnc_list_function_packs shows the models behind them.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_service_counts",
        title="Get Service Counts per Type",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_service_counts(
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Count the provisioned services per type (and in total) in the CAT inventory.

        Read-only. ``POST .../cat-inventory-rpc:get-services-count`` with the
        empty request ``{"cat-inventory-rpc:get-services-count-request": {}}``
        — the RPC takes NO filter on this build (verified: a
        ``service-type-filters`` body answers 400 malformed-message "Schema
        node ... was not found"), so this is always the whole inventory.
        Answers ``services-count-per-type[{service-type, count}]`` plus
        ``total-services-count``; a type with no services is simply absent.
        The cheapest "is anything provisioned?" check, and the number to page
        cnc_list_services against.

        Args:
            response_format: markdown (one line per type with its label and
                count, then the total) or json (the raw response).

        Returns:
            str: Markdown, or JSON {"total": int, "per_type": [{"service-type",
            "label", "count": int}]}. "No services are provisioned." (not an
            error) when the total is zero. "Error: ..." on an API failure.
        """
        try:
            response = await call_cat_rpc(RPC_SERVICES_COUNT, {})
            per_type = [
                {
                    "service-type": entry.get("service-type"),
                    "label": service_type_label(entry.get("service-type")),
                    "count": _int_or(entry.get("count")),
                }
                for entry in dict_list(response.get("services-count-per-type"))
            ]
            total = _int_or(response.get("total-services-count"), sum(e["count"] for e in per_type))
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"total": total, "per_type": per_type}), settings)
            if total == 0 and not per_type:
                return finalize(
                    "No services are provisioned. The CAT inventory is empty — create one through "
                    "the service_provisioning tools (e.g. cnc_create_odn_template) or the "
                    "Services & Traffic Engineering UI.",
                    settings,
                )
            lines = [f"# Services in the CAT inventory ({total} total)", ""]
            for entry in per_type:
                lines.append(f"- **{entry['label']}**: {entry['count']} ({entry['service-type']})")
            lines.extend(["", "List them with cnc_list_services (filter by service_type)."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_services",
        title="List Services (CAT inventory)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_services(
        service_type: Annotated[
            str,
            Field(
                description=(
                    f"Only these service types, comma-separated — each {_SERVICE_TYPE_HELP} "
                    "(e.g. 'odn-template' or 'policy,odn-template'). Empty = every type."
                ),
                max_length=2000,
            ),
        ] = "",
        exclude_types: Annotated[
            str,
            Field(
                description=(
                    "Service types to leave out, comma-separated, same forms as service_type "
                    "(e.g. 'ietf-l3vpn,ietf-l2vpn')."
                ),
                max_length=2000,
            ),
        ] = "",
        name_prefix: Annotated[
            str,
            Field(
                description=(
                    "Only services whose name starts with this text (e.g. 'mcp-'); see "
                    "case_sensitive."
                ),
                max_length=253,
            ),
        ] = "",
        case_sensitive: Annotated[
            bool,
            Field(description="Match name_prefix case-sensitively (default false)."),
        ] = False,
        offset: Annotated[
            int, Field(description="Index of the first service to return (e.g. 0).", ge=0)
        ] = 0,
        limit: Annotated[int, Field(description="Page size (e.g. 50).", ge=1, le=500)] = 50,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the services in the CAT inventory: name, type, and the NSO paths of the
        service object and its plan.

        Read-only. ``POST .../cat-inventory-rpc:get-all-services`` with
        ``collection-header {"offset": N, "limit": "N"}`` — ``limit`` MUST be
        a numeric string on the wire (verified: an integer or text answers
        400 malformed-message NumberFormatException) — and, only when a
        filter is given, ``query-criteria`` with ``service-type-filters.
        includes / excludes.service-type[<QNames>]`` and
        ``service-name-filters {start-with, case-sensitive "true"|"false"}``.
        The answer's ``collection-data.service-info[]`` carries, per service,
        ``service-name``, ``service-type`` (QName), ``yang-path`` (the NSO
        object, relative to the proxy's ``/data/``) and ``plan-yang-path``;
        with no match the ``collection-data`` container is absent altogether
        (verified) and the tool says "No services match." Paging: CAT reports
        no total, so ``has_more`` is inferred from a full page (count ==
        limit) — cnc_get_service_counts gives the totals. Feed ``yang-path``
        to cnc_get_service and ``plan-yang-path`` to cnc_get_service_plan.

        Args:
            service_type / exclude_types: comma-separated labels or QNames
                (unknown labels are refused before anything is sent).
            name_prefix, case_sensitive: the start-with name filter.
            offset, limit: the page.
            response_format: markdown (one line per service) or json.

        Returns:
            str: Markdown, or JSON {"total": null, "count": int, "offset": int,
            "items": [{"service-name", "service-type", "label", "yang-path",
            "plan-yang-path"}], "has_more": bool, "next_offset": int|null,
            "collection_header": {...}, "filter": {...}}. "No services match
            ..." (not an error) when the page is empty. "Error: Unknown
            service type ..." for a bad label (nothing sent); "Error: ..." on
            an API failure.
        """
        try:
            includes = parse_service_types(service_type)
            excludes = parse_service_types(exclude_types)
            prefix = name_prefix.strip()
            request: dict[str, Any] = {"collection-header": {"offset": offset, "limit": str(limit)}}
            criteria: dict[str, Any] = {}
            type_filters: dict[str, Any] = {}
            if includes:
                type_filters["includes"] = {"service-type": includes}
            if excludes:
                type_filters["excludes"] = {"service-type": excludes}
            if type_filters:
                criteria["service-type-filters"] = type_filters
            if prefix:
                criteria["service-name-filters"] = {
                    "start-with": prefix,
                    "case-sensitive": "true" if case_sensitive else "false",
                }
            if criteria:
                request["query-criteria"] = criteria
            response = await call_cat_rpc(RPC_ALL_SERVICES, request)
            collection = response.get("collection-data")
            infos = (
                dict_list(collection.get("service-info")) if isinstance(collection, dict) else []
            )
            items = [
                {**info, "label": service_type_label(info.get("service-type"))} for info in infos
            ]
            header = response.get("collection-header")
            filters = {
                "service_type": [service_type_label(q) for q in includes] or None,
                "exclude_types": [service_type_label(q) for q in excludes] or None,
                "name_prefix": prefix or None,
                "case_sensitive": case_sensitive if prefix else None,
            }
            envelope = pagination_envelope(items, total=None, offset=offset, limit=limit)
            if response_format is ResponseFormat.JSON:
                payload = {
                    **envelope,
                    "collection_header": header if isinstance(header, dict) else {},
                    "filter": filters,
                }
                return finalize(to_json(payload), settings)
            active = {k: v for k, v in filters.items() if v is not None}
            filter_text = (
                ", ".join(f"{k}={v}" for k, v in active.items()) if active else "no filter"
            )
            if not items:
                return finalize(
                    f"No services match ({filter_text}, offset {offset}). "
                    "cnc_get_service_counts shows what is provisioned per type.",
                    settings,
                )
            lines = [f"# Services ({len(items)} on this page, offset {offset}, {filter_text})", ""]
            lines.extend(service_info_line(i) for i in items)
            lines.append("")
            if envelope["has_more"]:
                lines.append(
                    f"The page came back full: call again with offset={envelope['next_offset']} "
                    "for more."
                )
            lines.append(
                "cnc_get_service reads a service by its yang-path, cnc_get_service_plan its "
                "plan by plan-yang-path."
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_service",
        title="Get Service (NSO object)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_service(
        yang_path: Annotated[
            str, Field(description=_YANG_PATH_DESC, min_length=1, max_length=2000)
        ],
        include_plan: Annotated[
            bool,
            Field(
                description=(
                    "Also read the service's plan status from CAT (get-service-plan-data on the "
                    "type's plan list — the documented one for the seven known types, a "
                    "<list>-plan guess otherwise). Default true."
                ),
            ),
        ] = True,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one service object as NSO holds it (through the RESTCONF proxy), with its
        bookkeeping and, by default, the CAT plan status.

        Read-only. ``GET /crosswork/proxy/nso/restconf/data/<yang-path>`` with
        ``Accept: application/yang-data+json`` — the answer is ``{"<module>:
        <list>": [<the entry>]}`` (verified for an ODN template: ``name``,
        ``head-end[]``, ``color``, ``dynamic{}`` plus NSO's ``created``,
        ``last-modified``, ``last-run``, ``modified{devices[], services[]}``,
        ``directly-modified``, ``plan-location``). The bookkeeping says when
        the service was committed and which devices it touched; the rest is
        the service configuration in the CFP's YANG. The path is what
        cnc_list_services returned as ``yang-path`` (a leading ``/`` or the
        full proxy URL is normalised) and MUST be keyed (``.../<list>=<key>``):
        an unkeyed list path is refused before anything is sent, because the
        proxy would answer the whole list and only one entry could be shown.
        With ``include_plan`` the tool also POSTs ``get-service-plan-data``
        for the service's plan path — the documented plan list of its type
        for the seven known types (``policy`` / ``odn-template`` ->
        ``<list>-plan``, ``cs-sr-te-policy`` -> ``cisco-cs-sr-te-cfp:
        cs-sr-te-plan``, ``vpn-service`` -> ``vpn-services/cisco-l3vpn-ntw:
        vpn-service-plan`` (``cisco-l2vpn-ntw:`` for L2), ``slice-service`` ->
        ``cisco-network-slice-service:slice-service-plan``, ``tunnel`` ->
        ``tunnels/cisco-te:tunnel-plan``), a ``<list>-plan`` guess for any
        other list (the plan line says so) — and shows status / last-updated /
        error-info; cnc_get_service_plan(detail=true) has the per-component
        nano plan. A missing service answers 404 with an
        ``ietf-restconf:errors`` document (``invalid-value`` "uri keypath not
        found", verified) and is reported as "no service at <path>".

        Args:
            yang_path: the service's keyed data path relative to the proxy's
                /data/.
            include_plan: also fetch the CAT plan status (default true).
            response_format: markdown (key, bookkeeping, plan line, then the
                service body as JSON) or json.

        Returns:
            str: Markdown, or JSON {"yang_path", "plan_yang_path",
            "plan_path_known": bool, "service": {...the entry...}, "plan":
            {"yang-path", "status", "creation-time", "last-updated-time",
            "error-info"?} | null, "plan_note"?}. "Error: no service at <path>
            ..." when NSO has none (list with cnc_list_services); "Error: ...
            is not a keyed service path" for an unkeyed path (nothing sent);
            "Error: ..." on an API failure (a plain 404 without a RESTCONF
            document = the path is not routed; 400 unknown-element = a wrong
            module prefix).
        """
        try:
            path = normalize_yang_path(yang_path)
            _split_last_segment(path)  # refuse an unkeyed list path before the GET
            found, data = await restconf_get(nso_data_url(path))
            service = service_object(data) if found else None
            if service is None:
                raise PlatformError(
                    f"no service at {path} (list the provisioned services and their exact "
                    "yang-path with cnc_list_services; a plan path belongs to "
                    "cnc_get_service_plan)."
                )
            plan_path: str | None = None
            plan_known = False
            plan_entry: dict[str, Any] | None = None
            plan_note: str | None = None
            if include_plan:
                plan_path, plan_known = resolve_plan_path(path)
                try:
                    plan_entry = await fetch_plan_entry(plan_path)
                except PlatformError as e:
                    plan_note = f"plan status unavailable: {e}"
                if plan_note is None and not plan_known and plan_not_found(plan_entry):
                    plan_note = (
                        "no plan data in CAT — this plan path is only a <list>-plan guess (the "
                        "service list is not one of the seven documented types); read the plan "
                        "with cnc_get_service_plan on the plan-yang-path cnc_list_services shows."
                    )
            if response_format is ResponseFormat.JSON:
                payload: dict[str, Any] = {
                    "yang_path": path,
                    "plan_yang_path": plan_path,
                    "plan_path_known": plan_known,
                    "service": service,
                    "plan": None if plan_not_found(plan_entry) else plan_entry,
                }
                if plan_note:
                    payload["plan_note"] = plan_note
                return finalize(to_json(payload), settings)
            return finalize(
                service_markdown(path, service, plan_path, plan_entry, plan_note), settings
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_service_plan",
        title="Get Service Plan Status",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_service_plan(
        plan_yang_path: Annotated[
            str, Field(description=_PLAN_PATH_DESC, min_length=1, max_length=2000)
        ],
        detail: Annotated[
            bool,
            Field(
                description=(
                    "Also read the nano plan from NSO (GET the plan path through the proxy) and "
                    "show every component and state. Default false."
                ),
            ),
        ] = False,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get a service's plan status from CAT (completed / failed / in-progress ...) and,
        optionally, the NSO nano plan behind it.

        Read-only. ``POST .../cat-inventory-rpc:get-service-plan-data`` with
        ``{"service-plan-yang-path": ["<plan path>"]}`` -> ``service-plan-data
        [{yang-path, status, creation-time, last-updated-time, error-info
        {message}?}]``. ``status`` is ``completed`` (NSO applied the service),
        ``in-progress`` / ``delete-in-progress`` (converging), ``failed``
        (read ``error-info`` and the nano plan) or ``unknown`` — verified: an
        unknown plan path answers HTTP 200 with ``unknown`` and "service plan
        data not found", which the tool reports as "No plan data for <path>"
        (not an error: the service does not exist, was never committed, or —
        for a guessed plan path — is tracked under another list). A service
        path is accepted and mapped to its plan path through the documented
        per-type table (``cs-sr-te-policy`` -> ``cisco-cs-sr-te-cfp:
        cs-sr-te-plan``, ``vpn-service`` -> ``vpn-services/cisco-l3vpn-ntw:
        vpn-service-plan``, ``tunnel`` -> ``tunnels/cisco-te:tunnel-plan``,
        ...); only a list outside the seven known types gets the ``<list>-plan``
        guess, so prefer the ``plan-yang-path`` from cnc_list_services for
        anything else. ``detail=true`` adds ``GET /crosswork/proxy/nso/
        restconf/data/<plan path>`` — the nano plan ``plan.component[{type
        (tailf-ncs:self | ...:head-end), name, state[{name tailf-ncs:init |
        ...:config-apply | tailf-ncs:ready, status reached | not-reached |
        failed, when}], back-track}]`` (verified shape); a 404 there means NSO
        holds no plan (after a delete the plan may linger briefly with ``init
        not-reached``).

        Args:
            plan_yang_path: the plan (or service) path.
            detail: also fetch the nano plan from NSO.
            response_format: markdown (the status line, then the components
                with each state's status and time) or json.

        Returns:
            str: Markdown, or JSON {"plan_yang_path", "plan_data": {...}|null,
            "plan": {"name", "plan": {"component": [...]}} | null (only with
            detail), "found": bool}. "No plan data for <path> (...)" (not an
            error) when CAT has none; "Error: ..." for an unkeyed path or an
            API failure.
        """
        try:
            plan_path = plan_path_of(plan_yang_path)
            entry = await fetch_plan_entry(plan_path)
            plan_object: dict[str, Any] | None = None
            plan_missing = False
            if detail:
                found, data = await restconf_get(nso_data_url(plan_path))
                plan_object = service_object(data) if found else None
                plan_missing = plan_object is None
            not_found = plan_not_found(entry)
            if response_format is ResponseFormat.JSON:
                payload: dict[str, Any] = {
                    "plan_yang_path": plan_path,
                    "found": not not_found,
                    "plan_data": None if not_found else entry,
                }
                if detail:
                    payload["plan"] = plan_object
                return finalize(to_json(payload), settings)
            if not_found and (not detail or plan_missing):
                return finalize(
                    f"No plan data for {plan_path} (the service does not exist or was never "
                    "committed). cnc_list_services shows the provisioned services with their "
                    "plan-yang-path.",
                    settings,
                )
            text = plan_markdown(plan_path, entry, plan_object)
            if detail and plan_missing:
                text += "\n\nNSO holds no nano plan at this path (404 uri keypath not found)."
            return finalize(text, settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_wait_for_service_plan",
        title="Wait for Service Plan Status",
        read_only=True,
        idempotent=True,
    )
    async def cnc_wait_for_service_plan(
        plan_yang_path: Annotated[
            str, Field(description=_PLAN_PATH_DESC, min_length=1, max_length=2000)
        ],
        target: Annotated[
            str,
            Field(
                description=(
                    "The plan status that ends the wait: 'completed' (default), 'in-progress', "
                    "'delete-in-progress', 'failed', or 'unknown' (= the plan is gone, after a "
                    "delete)."
                ),
                min_length=1,
                max_length=40,
            ),
        ] = DEFAULT_WAIT_TARGET,
        timeout_seconds: Annotated[
            int, Field(description="How long to wait in total, seconds (e.g. 120).", ge=5, le=600)
        ] = 120,
        interval_seconds: Annotated[
            int, Field(description="Seconds between polls (e.g. 5).", ge=1, le=60)
        ] = 5,
    ) -> str:
        """Poll a service's CAT plan status until it reaches ``target`` (or fails).

        Read-only convergence wait. Call it after a provisioning write
        (cnc_create_odn_template, cnc_create_l3vpn, a delete, ...) instead of
        polling cnc_get_service_plan in a loop. Polls ``get-service-plan-
        data`` every ``interval_seconds``:

        - status == ``target`` -> success ("... is completed after Ns");
        - status ``failed`` (and target is not 'failed') -> the wait ends at
          once with "Error: ..." carrying ``error-info`` — that is the
          commit's outcome, not a timeout (cnc_get_service_plan(detail=true)
          shows which component failed);
        - anything else (``in-progress``, ``delete-in-progress``, or
          ``unknown`` while CAT has not indexed a just-committed service yet)
          keeps polling until ``timeout_seconds``, then returns a non-error
          "not finished yet, current status: ..." — call again to keep
          waiting. For a delete, wait with target='unknown': the plan data
          disappears once NSO has removed the service.

        Args:
            plan_yang_path: the plan (or service) path.
            target: the status to wait for (default 'completed').
            timeout_seconds, interval_seconds: the polling budget.

        Returns:
            str: "Service plan <path> is <target> after Ns." plus the JSON
            plan entry; on timeout (NOT an error) "Service plan <path> not
            <target> after Ns; current status: ..." plus the last entry.
            "Error: service plan <path> FAILED ..." with error-info when the
            plan fails; "Error: ..." for an unknown target / unkeyed path or
            an API failure.
        """
        try:
            wanted = normalize_plan_status(target)
            plan_path = plan_path_of(plan_yang_path)
            stop = {wanted, "failed"}
            finished, entry, elapsed = await wait_until(
                lambda: fetch_plan_entry(plan_path),
                lambda e: plan_status(e) in stop,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
            )
            status = plan_status(entry)
            body = to_json(entry if entry is not None else {"status": "unknown"})
            if finished and status == wanted:
                head = f"Service plan {plan_path} is {wanted} after {elapsed:.0f}s."
            elif finished:
                message = plan_error_message(entry) or "no error-info given"
                raise PlatformError(
                    f"service plan {plan_path} FAILED after {elapsed:.0f}s (waiting for {wanted}). "
                    f"error-info: {message}. cnc_get_service_plan(detail=true) shows the failed "
                    f"component; fix the cause and re-commit.\n{body}"
                )
            else:
                current = status
                if plan_not_found(entry):
                    current = "unknown (no plan data yet — CAT has not indexed the service)"
                head = (
                    f"Service plan {plan_path} not {wanted} after {elapsed:.0f}s; current "
                    f"status: {current}. Call again to keep waiting, or read "
                    "cnc_get_service_plan(detail=true)."
                )
            return finalize(f"{head}\n{body}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_vpn_services",
        title="List VPN Services (L3/L2 operational data)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_vpn_services(
        layer: Annotated[str, Field(description=_LAYER_DESC, max_length=8)] = "l3",
        offset: Annotated[
            int, Field(description="Index of the first service to return (e.g. 0).", ge=0)
        ] = 0,
        limit: Annotated[int, Field(description="Page size (e.g. 50).", ge=1, le=500)] = 50,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the L3 (or L2) VPN services with their operational data from the CAT NBI.

        Read-only. ``GET /crosswork/nbi/cat-inventory/v1/restconf/data/
        ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service?offset=N&limit=N&
        content=nonconfig`` (``ietf-l2vpn-ntw:l2vpn-ntw`` for l2) with
        ``Accept: application/yang-data+json`` — the batch form. Verified
        2026-09-14 with a live L3VPN: ``content=nonconfig`` is REQUIRED —
        without it (or with config/all) the batch GET answers 409
        data-missing even when services exist; without offset/limit it
        answers 400 missing-attribute. **When no service exists the batch GET
        answers 409 data-missing** too — reported as "No L3 VPN services."
        rather than an error. The verified 200 shape:
        ``ietf-l3vpn-ntw:vpn-service[{vpn-id, status{oper-status{status
        "ietf-vpn-common:op-up|op-down|op-unknown", last-change?}},
        underlay-transport{cisco-l3vpn-ntw:discovered-underlay-transport
        {sr-policy-ref[{headend, color, endpoint}], te-tunnel-ref[{tunnel-id,
        source, destination}]}}?}]`` — **operational data only** (op-unknown
        while Service Health is not monitoring the VPN): the topology and the
        nodes are configuration intent, read with cnc_get_vpn_service (the
        keyed CAT GET carries them) or cnc_get_service. Each line shows
        vpn-id, oper-status and the discovered underlay counts; keys the
        renderer does not know stay in the JSON output.

        Args:
            layer: 'l3' | 'l2'.
            offset, limit: the page (no total is reported; has_more = a full page).
            response_format: markdown (one line per service: vpn-id,
                oper-status, discovered SR policy / tunnel counts) or json.

        Returns:
            str: Markdown, or JSON {"layer", "total": null, "count", "offset",
            "items": [...], "has_more", "next_offset"}. "No L3 VPN services."
            (not an error) when none exists. "Error: ..." for an unknown layer
            or an API failure.
        """
        try:
            model = vpn_layer(layer)
            found, data = await restconf_get(
                vpn_services_url(model), params={"offset": offset, "limit": limit, **NONCONFIG}
            )
            services = (
                [s for s in unwrap_list(data, model.module, "vpn-service") if isinstance(s, dict)]
                if found
                else []
            )
            envelope = pagination_envelope(services, total=None, offset=offset, limit=limit)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"layer": model.layer, **envelope}), settings)
            if not services:
                return finalize(
                    f"No {model.layer.upper()} VPN services"
                    + (f" at offset {offset}." if offset else ".")
                    + " (The CAT NBI answers 409 data-missing for an empty list.) Provision one "
                    "with the service_provisioning tools or list every service type with "
                    "cnc_list_services.",
                    settings,
                )
            lines = [
                f"# {model.layer.upper()} VPN services ({len(services)} on this page, "
                f"offset {offset})",
                "",
            ]
            lines.extend(vpn_service_line(s) for s in services)
            lines.append("")
            if envelope["has_more"]:
                lines.append(
                    f"The page came back full: call again with offset={envelope['next_offset']}."
                )
            lines.append(
                "cnc_get_vpn_service shows one service's discovered underlay in full, "
                "cnc_get_vpn_service_health its oper-status; the nodes and accesses are "
                "configuration intent: cnc_get_service(yang_path=<the service's NSO path>)."
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_vpn_service",
        title="Get VPN Service (operational data)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_vpn_service(
        vpn_id: Annotated[str, Field(description=_VPN_ID_DESC, min_length=1, max_length=253)],
        layer: Annotated[str, Field(description=_LAYER_DESC, max_length=8)] = "l3",
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one L3/L2 VPN service's operational data: oper-status and the discovered
        underlay transport (SR policies / RSVP-TE tunnels).

        Read-only. ``GET .../data/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/
        vpn-service=<vpn-id>`` on the CAT NBI (the id percent-encoded as one
        list key; ``ietf-l2vpn-ntw:l2vpn-ntw`` for l2) with ``Accept:
        application/yang-data+json``. A missing service answers ``409
        data-missing`` "Data does not exist" (verified) and is reported as
        "Error: no L3 VPN service '<id>'". The 200 shape is the one in
        Cisco's own capture (see cnc_list_vpn_services): ``vpn-id``,
        ``status.oper-status{status, last-change?}`` and ``underlay-transport.
        cisco-l3vpn-ntw:discovered-underlay-transport{sr-policy-ref[{headend
        (the NSO device name), color, endpoint}], te-tunnel-ref[{tunnel-id,
        source, destination}]}`` — nothing else: the VPN's nodes, network
        accesses and topology are configuration intent, NOT returned here.
        For those use cnc_get_service with the service's yang-path
        (``ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=<id>``); should
        an entry ever carry ``vpn-nodes`` they are rendered too.

        Args:
            vpn_id: the vpn-id.
            layer: 'l3' | 'l2'.
            response_format: markdown (summary line, the discovered SR
                policies and tunnels, then the whole entry as JSON) or json.

        Returns:
            str: Markdown, or the JSON ``vpn-service`` entry. "Error: no L3
            VPN service '<id>' ..." when it does not exist; "Error: ..." on an
            API failure.
        """
        try:
            model = vpn_layer(layer)
            key = vpn_id.strip()
            found, data = await restconf_get(vpn_service_url(model, key))
            entries = unwrap_list(data, model.module, "vpn-service") if found else []
            services = [s for s in entries if isinstance(s, dict)]
            if not services:
                raise PlatformError(
                    f"no {model.layer.upper()} VPN service '{key}' (409 data-missing). Ids are "
                    "exact and case-sensitive; list them with cnc_list_vpn_services."
                )
            service = services[0]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(service), settings)
            return finalize(vpn_service_markdown(model, service), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_vpn_service_health",
        title="Get VPN Service Oper-Status",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_vpn_service_health(
        vpn_id: Annotated[str, Field(description=_VPN_ID_DESC, min_length=1, max_length=253)],
        layer: Annotated[str, Field(description=_LAYER_DESC, max_length=8)] = "l3",
    ) -> str:
        """Get the operational status (health) of one L3/L2 VPN service.

        Read-only. ``GET .../vpn-service=<vpn-id>?content=nonconfig`` on the
        CAT NBI -> ``{"ietf-l3vpn-ntw:vpn-service": [{"vpn-id", "status":
        {"oper-status": {"status": "<identity>", "last-change"?}}}]}``
        (verified 2026-09-14 on a live L3VPN: ``ietf-vpn-common:op-unknown``
        while Service Health is not monitoring it; the identities are
        ``op-up`` / ``op-down`` / ``op-unknown``). The document's
        ``/status/oper-status`` sub-path answers 409 data-missing even for an
        existing service (verified), so the tool reads the node itself. This
        is the service-assurance verdict Crosswork derives for the VPN,
        distinct from NSO's plan status (cnc_get_service_plan: did the commit
        apply?). A missing service answers 409 data-missing (verified) ->
        "Error: no ... VPN service".

        Args:
            vpn_id: the vpn-id.
            layer: 'l3' | 'l2'.

        Returns:
            str: "L3 VPN service <id>: oper-status <status> (last change
            <time>)" followed by the JSON object. "Error: no L3 VPN service
            '<id>'" when it does not exist; "Error: ..." on an API failure.
        """
        try:
            model = vpn_layer(layer)
            key = vpn_id.strip()
            found, data = await restconf_get(vpn_oper_status_url(model, key), params=NONCONFIG)
            if not found:
                raise PlatformError(
                    f"no {model.layer.upper()} VPN service '{key}' (409 data-missing); list them "
                    "with cnc_list_vpn_services."
                )
            entries = [
                e for e in unwrap_list(data, model.module, "vpn-service") if isinstance(e, dict)
            ]
            status_node = field(entries[0], "status") if entries else None
            oper = field(status_node, "oper-status") if isinstance(status_node, dict) else None
            if not isinstance(oper, dict):
                oper = {}
            status = _short_identity(field(oper, "status"))
            head = f"{model.layer.upper()} VPN service {key}: oper-status {status}"
            if field(oper, "last-change"):
                head += f" (last change {field(oper, 'last-change')})"
            if not oper:
                head += " — the NBI returned no oper-status content (service assurance may be off)"
            return finalize(f"{head}\n{to_json(oper)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_vpn_underlay_transport",
        title="Get VPN Underlay Transport",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_vpn_underlay_transport(
        vpn_id: Annotated[str, Field(description=_VPN_ID_DESC, min_length=1, max_length=253)],
        layer: Annotated[str, Field(description=_LAYER_DESC, max_length=8)] = "l3",
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the SR policies / RSVP-TE tunnels Crosswork discovered a VPN service riding on.

        Read-only. ``GET .../vpn-service=<vpn-id>/underlay-transport/
        cisco-l3vpn-ntw:discovered-underlay-transport`` (``cisco-l2vpn-ntw:``
        for l2) on the CAT NBI -> ``{"cisco-l3vpn-ntw:discovered-underlay-
        transport": {"sr-policy-ref": [{headend, color, endpoint}],
        "te-tunnel-ref": [{tunnel-id, source, destination}]}}`` (the YANG
        augment as NSO serves it; the document spells each leaf with its
        module prefix — both are read). It is the VPN-to-transport mapping
        the "Services" UI draws; cnc_find_services_on_transport is the
        inverse lookup. **A 409 data-missing answers BOTH "no such VPN
        service" and "the service has no discovered transport yet"**
        (verified on an unknown id; the container is non-presence) — the
        tool says so rather than guess; confirm the service with
        cnc_get_vpn_service.

        Args:
            vpn_id: the vpn-id.
            layer: 'l3' | 'l2'.
            response_format: markdown (the policy and tunnel references) or
                json (the container).

        Returns:
            str: Markdown, or JSON {"vpn_id", "layer", "sr_policy_refs":
            [...], "te_tunnel_refs": [...]}. "No discovered underlay transport
            for ... (no such VPN service, or nothing discovered yet)" (not an
            error) on 409; "Error: ..." on an API failure.
        """
        try:
            model = vpn_layer(layer)
            key = vpn_id.strip()
            found, data = await restconf_get(vpn_underlay_url(model, key))
            container = field(data, "discovered-underlay-transport") if found else None
            if not isinstance(container, dict):
                container = data if found and isinstance(data, dict) else {}
            policies, tunnels = underlay_lists(container)
            if response_format is ResponseFormat.JSON:
                payload = {
                    "vpn_id": key,
                    "layer": model.layer,
                    "found": found,
                    "sr_policy_refs": policies,
                    "te_tunnel_refs": tunnels,
                }
                return finalize(to_json(payload), settings)
            if not found:
                return finalize(
                    f"No discovered underlay transport for {model.layer.upper()} VPN service "
                    f"'{key}': the CAT NBI answered 409 data-missing, which means EITHER no such "
                    "VPN service OR nothing discovered for it yet — confirm the service with "
                    "cnc_get_vpn_service.",
                    settings,
                )
            return finalize(underlay_markdown(model, key, container), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_sub_services",
        title="List Sub-Services of a Service",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_sub_services(
        service_yang_path: Annotated[
            str,
            Field(
                description=(
                    "The parent service's yang-path as cnc_list_services returns it (e.g. "
                    "'ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-91')."
                ),
                min_length=1,
                max_length=2000,
            ),
        ],
        offset: Annotated[
            int, Field(description="Index of the first sub-service path (e.g. 0).", ge=0)
        ] = 0,
        limit: Annotated[int, Field(description="Page size (e.g. 50).", ge=1, le=500)] = 50,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the sub-services (the internal per-node / per-transport services NSO stacks
        under a service) of one service in the CAT inventory.

        Read-only. Two RPCs: ``get-sub-service-count`` and ``get-sub-service-
        paths`` (``collection-header {offset, limit "N"}``), both with
        ``service-instance-path`` — **required** (verified: without it the
        RPC answers 500 operation-failed NullPointer "svcInstPath is null"),
        so a blank path is refused before anything is sent. A service without
        sub-services (an ODN template, a simple policy) answers count 0 and an
        empty page — a normal result. The IETF L3NM/L2NM and slice services
        are the ones that stack sub-services (per-node RFS services, the
        transport they instantiate). The document says a type that does not
        support sub-services answers an "unsupported" error.

        Args:
            service_yang_path: the parent service path.
            offset, limit: the page.
            response_format: markdown or json.

        Returns:
            str: Markdown, or JSON {"service_yang_path", "sub_service_count":
            int, "total": null, "count", "offset", "items": [<path>],
            "has_more", "next_offset"}. "No sub-services under <path>." (not
            an error) when there are none; "Error: ..." for a blank path
            (nothing sent) or an API failure.
        """
        try:
            path = normalize_yang_path(service_yang_path)
            count_response = await call_cat_rpc(
                RPC_SUB_SERVICE_COUNT, {"service-instance-path": path}
            )
            count = _int_or(count_response.get("sub-service-count"))
            paths_response = await call_cat_rpc(
                RPC_SUB_SERVICE_PATHS,
                {
                    "collection-header": {"offset": offset, "limit": str(limit)},
                    "service-instance-path": path,
                },
            )
            raw = paths_response.get("sub-service-path")
            items = [str(p) for p in raw] if isinstance(raw, list) else []
            envelope = pagination_envelope(items, total=None, offset=offset, limit=limit)
            if response_format is ResponseFormat.JSON:
                payload = {"service_yang_path": path, "sub_service_count": count, **envelope}
                return finalize(to_json(payload), settings)
            if not items and count == 0:
                return finalize(
                    f"No sub-services under {path} (sub-service-count 0). Only the VPN and "
                    "slice models stack sub-services; an ODN template or SR policy has none.",
                    settings,
                )
            lines = [
                f"# Sub-services of {path} ({count} in total, {len(items)} on this page, "
                f"offset {offset})",
                "",
            ]
            lines.extend(f"- {p}" for p in items)
            if not items:
                lines.append("- (none on this page)")
            if envelope["has_more"]:
                lines.extend(["", f"Call again with offset={envelope['next_offset']} for more."])
            lines.extend(["", "Read a sub-service with cnc_get_service(yang_path=<path>)."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_find_services_on_transport",
        title="Find Services on a Transport (SR policy / RSVP-TE tunnel)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_find_services_on_transport(
        headend: Annotated[
            str,
            Field(
                description=(
                    "SR policy head-end as the NSO device name (= the inventory host_name, e.g. "
                    "'PE1' — what cnc_get_vpn_underlay_transport shows); selects the SR-policy "
                    "lookup and needs color + endpoint. A TE router-id (e.g. '10.0.0.1', the "
                    "headend cnc_list_sr_policies reports) is accepted and resolved to the "
                    "device name through the inventory first."
                ),
                max_length=253,
            ),
        ] = "",
        color: Annotated[
            int, Field(description="SR policy color (e.g. 100).", ge=0, le=4294967295)
        ] = 0,
        endpoint: Annotated[
            str,
            Field(description="SR policy endpoint IP (e.g. '10.0.0.3').", max_length=64),
        ] = "",
        tunnel_id: Annotated[
            str,
            Field(
                description=(
                    "RSVP-TE tunnel id (e.g. '1'); selects the tunnel lookup (when no headend is "
                    "given) and needs source + destination."
                ),
                max_length=64,
            ),
        ] = "",
        source: Annotated[
            str, Field(description="RSVP-TE tunnel source IP (e.g. '10.0.0.1').", max_length=64)
        ] = "",
        destination: Annotated[
            str,
            Field(description="RSVP-TE tunnel destination IP (e.g. '10.0.0.3').", max_length=64),
        ] = "",
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Find the VPN services that use a given underlay transport (an SR policy or an
        RSVP-TE tunnel) — the inverse of cnc_get_vpn_underlay_transport.

        Read-only. ``POST .../cat-inventory-rpc:get-associated-services-for-
        transport`` with ``sr-policy-ref {headend, color (a string on the
        wire — verified), endpoint}`` when a headend is given, else
        ``te-tunnel-ref {tunnel-id, source, destination}`` (the document's
        ``transport-yang-path`` form is NOT accepted by this build). A
        half-given reference is refused before anything is sent. **The
        head-end key is the NSO device name** ("SR policy Headend Device ID"
        in the CFP YANG; the inventory ``host_name``, as
        cnc_get_vpn_underlay_transport shows it) — a TE router-id, which is
        what cnc_list_sr_policies / the SR-PCE report, silently matches
        nothing. So a headend that is an IP literal is first resolved through
        ``POST /crosswork/inventory/v1/nodes/query`` with the
        ``routing_info.te_router_id`` filter (the lookup Cisco's own
        underlay-change example performs before this RPC) to the node's NSO
        id (``providers_family.ROBOT_PROVIDER_NSO.providers[].
        provider_node_id``, else ``host_name``); no or several matching
        devices is an error. The answer is ``service-path[]`` (service
        instance paths — feed them to cnc_get_service), or
        ``{"cat-inventory-rpc:output": {}}`` when nothing is associated
        (verified), reported as "No service uses that transport." Use it
        before touching a policy or tunnel to see which customer services
        would be affected.

        Args:
            headend, color, endpoint: the SR policy key (all three); headend
                is the NSO device name or a TE router-id to resolve.
            tunnel_id, source, destination: the RSVP-TE tunnel key (all three).
            response_format: markdown or json.

        Returns:
            str: Markdown, or JSON {"transport": {...the reference sent...},
            "headend_resolved_from": "<router-id>"?, "count": int,
            "service_paths": [str]}. "No service uses that transport ..."
            (not an error) when the association is empty; "Error: ..." for
            an incomplete reference (nothing sent), a router-id no (or more
            than one) inventory device carries, or an API failure.
        """
        try:
            reference = transport_ref(
                headend=headend,
                color=color,
                endpoint=endpoint,
                tunnel_id=tunnel_id,
                source=source,
                destination=destination,
            )
            resolved_from: str | None = None
            sr_ref = reference.get("sr-policy-ref")
            if sr_ref is not None and looks_like_ip_address(sr_ref["headend"]):
                resolved_from = sr_ref["headend"]
                sr_ref["headend"] = await resolve_headend_device(resolved_from)
            response = await call_cat_rpc(RPC_SERVICES_FOR_TRANSPORT, reference)
            raw = response.get("service-path")
            paths = [str(p) for p in raw] if isinstance(raw, list) else []
            kind, ref = next(iter(reference.items()))
            label = (
                f"SR policy {ref['headend']} color {ref['color']} -> {ref['endpoint']}"
                if kind == "sr-policy-ref"
                else f"RSVP-TE tunnel {ref['tunnel-id']} {ref['source']} -> {ref['destination']}"
            )
            if resolved_from:
                label += f" (headend resolved from router-id {resolved_from})"
            if response_format is ResponseFormat.JSON:
                payload: dict[str, Any] = {"transport": reference}
                if resolved_from:
                    payload["headend_resolved_from"] = resolved_from
                payload.update({"count": len(paths), "service_paths": paths})
                return finalize(to_json(payload), settings)
            if not paths:
                return finalize(
                    f"No service uses that transport ({label}): CAT has no VPN service "
                    "associated with it. The association exists only for services whose "
                    "discovered underlay names this policy/tunnel "
                    "(cnc_get_vpn_underlay_transport shows the exact headend / color / "
                    "endpoint to pass).",
                    settings,
                )
            lines = [f"# Services on {label} ({len(paths)})", ""]
            lines.extend(f"- {p}" for p in paths)
            lines.extend(["", "Read one with cnc_get_service(yang_path=<path>)."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_function_packs",
        title="List T-SDN Function Packs",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_function_packs(
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the deployed T-SDN function packs (the CFP models behind the service types)
        and the deployment state of the pack archive.

        Read-only. Two plain-JSON GETs on the function-pack deployment
        manager (no YANG headers): ``/crosswork/cat/cat-fp-deployment-
        manager-service/v1/twophasecommitrunner/getDeploymentInfo`` ->
        ``deploymentInfo {deploymentState "DEPLOYED", etcdCfpArchiveVersion
        "7.2.43", etcdPodVersion, deploymentTime}`` and ``.../packages`` ->
        ``packagesInfo[{namespace, model-version, service-layer?, service-path?,
        plan-path?, resources[{path, resourceIdField(s), scope, label}]}]``
        (both verified live). A package's ``namespace`` is the namespace part
        of the service-type QName (the tool names the matching label), its
        ``resources`` are the supporting objects the UI offers for it (SID
        lists, resource pools, routing policies, VPN profiles, SLO/SLE
        templates ...). Use it to confirm a model is deployed before
        provisioning against it, or to read the exact list paths of the
        resources.

        Args:
            response_format: markdown (the deployment line, then one line per
                package with its resources) or json.

        Returns:
            str: Markdown, or JSON {"deployment": {...deploymentInfo...},
            "packages": [...packagesInfo...]}. "Error: ..." on an API failure
            (a bare 404 -> the deployment manager is not routed here).
        """
        try:
            info_data = await client.request_json("GET", FP_DEPLOYMENT_INFO_URL)
            packages_data = await client.request_json("GET", FP_PACKAGES_URL)
            info = info_data.get("deploymentInfo") if isinstance(info_data, dict) else None
            info = info if isinstance(info, dict) else {}
            packages = (
                dict_list(packages_data.get("packagesInfo"))
                if isinstance(packages_data, dict)
                else []
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"deployment": info, "packages": packages}), settings)
            return finalize(function_packs_markdown(info, packages), settings)
        except Exception as e:
            return format_error(e)
