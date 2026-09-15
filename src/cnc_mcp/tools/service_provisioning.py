"""Service provisioning tools — T-SDN function-pack services committed through
Crosswork's NSO proxy.

What this module writes. Crosswork Network Controller ships the Cisco
Transport-SDN core function packs (CFPs) inside its embedded NSO: SR-TE
(``cisco-sr-te-cfp`` — ODN templates, SR policies, SID lists),
circuit-style SR-TE (``cisco-cs-sr-te-cfp``), the IETF L3NM / L2NM network
models (``ietf-l3vpn-ntw``, ``ietf-l2vpn-ntw``, RFC 9182 / RFC 9291 as
deviated by Cisco), network slices (``ietf-network-slice-service``) and
routing policies. A service is provisioned by writing its YANG instance into
NSO through the transparent proxy ``/crosswork/proxy/nso/restconf/data/...``
(``Content-Type`` and ``Accept: application/yang-data+json`` both ways —
verified live 2026-09-13); NSO's CFP validates it, renders the device
configuration through the NED and commits it to every device the service
touches in one transaction. The read side — the Crosswork Active Topology
service inventory (``/crosswork/nbi/cat-inventory/v1/restconf``:
``cnc_list_services`` / ``cnc_get_service`` / ``cnc_get_service_plan`` /
``cnc_wait_for_service_plan`` / ``cnc_get_vpn_service``) — is
:mod:`cnc_mcp.tools.services`; NSO's own device list is
``cnc_list_nso_devices`` (:mod:`cnc_mcp.tools.nso`).

NOT the Optimization Engine. ``cnc_create_sr_policy`` / ``cnc_update_sr_policy``
/ ``cnc_delete_sr_policy`` (:mod:`cnc_mcp.tools.sr_te_operations`) make the
SR-PCE *instantiate* a policy on the head-end over PCEP: nothing is written to
the router's configuration, the policy lives in the COE's config DB and shows
``pcep-flag-c: 1`` on the topology NBI. The tools here are the other model:
``cnc_create_sr_policy_service`` makes NSO *configure* the policy on the
head-end (``segment-routing traffic-eng policy srte_c_<color>_ep_<tail-end>``
with ``candidate-paths / preference / dynamic / pce`` — a PCC-initiated,
optionally PCE-delegated policy); it is a service instance with a plan, it
survives an SR-PCE restart, and it is removed by deleting the service. Both
kinds appear in ``cnc_list_sr_policies`` once PCEP reports them; only the
NSO-provisioned ones exist in the CAT service inventory. ODN templates and
SID lists have no Optimization Engine counterpart at all.

Dry run first (verified live). Every write tool takes ``dry_run``: the same
request is sent with ``?dry-run=native`` and NSO answers ``201``/``200`` with
``{"dry-run-result": {"native": {"device": [{"name": "PE1", "data": "<CLI>"}]}}}``
— the exact configuration it would push to each device — and commits nothing.
CFP validation runs inside the dry run too (an unknown head-end, an
out-of-model node or a TSDN-* validation failure surface exactly as on a
commit), so a dry run is a complete pre-flight; run it before the first
commit of any new shape. A ``DELETE`` dry run renders the ``no ...`` lines.

Outcomes (verified live). ``PUT`` answers ``201`` when the entry was created
and ``204`` when it replaced an existing one (a re-PUT of the same body is
idempotent); ``PATCH`` answers ``204`` (merge of the given leaves into the
existing entry); ``DELETE`` answers ``204`` (and ``404`` ``uri keypath not
found`` when the entry does not exist). After a committed create / replace /
update the tools read the service's nano plan once —
``<parent>/<list>-plan=<key>`` (the verified rule: ``odn-template=<n>`` ->
``odn-template-plan=<n>``, ``policy=<n>`` -> ``policy-plan=<n>``,
``vpn-service=<n>`` -> ``vpn-service-plan=<n>``; spelled without a module
prefix on the plan segment, the way CAT's ``plan-yang-path`` reports it and the
verified proxy GETs ``.../odn/odn-template-plan=<n>`` / ``.../policies/
policy-plan=<n>`` used it — the plan path the tools hand to
``cnc_wait_for_service_plan`` / ``cnc_get_service_plan``) — and summarise it per
component: ``self`` (the service) and one component per device
(``head-end``), each walking the states ``init`` -> ``config-apply`` ->
``ready`` with status ``reached`` | ``not-reached`` | ``failed``. ``self``
at ``ready reached`` is a fully deployed service; a ``failed`` state names
the device and step that broke. A missing plan (204 / 404) right after the
commit is reported, not treated as an error — the CFP may still be creating
it; after a delete the plan may linger briefly with ``init not-reached``.

**Two plan vocabularies.** The "Plan:" line above speaks NSO's **nano-plan**
language (``ready`` / ``in-progress`` / ``failed`` summarising the component
states ``init`` / ``config-apply`` / ``ready``). The services tools —
``cnc_get_service_plan`` and the ``cnc_wait_for_service_plan`` targets —
speak the **CAT plan status**: ``completed`` / ``in-progress`` /
``delete-in-progress`` / ``failed`` / ``unknown``. They describe the same
service one layer apart (verified live 2026-09-14: the service the create
tool printed as "Plan: ready" is "status completed" in CAT), so every "Plan:"
line names its CAT equivalent; wait with ``target='completed'`` (``'ready'``
is accepted as an alias), never with a component state.

Preconditions that only bite at runtime (all verified live, all explained in
the error texts):

- **The head-end must be in sync with NSO.** A device NSO considers out of
  sync (any out-of-band change — a console edit, a config restore — does it)
  makes the commit fail with ``502 operation-failed "Network Element Driver:
  device PE1: out of sync"``. Run ``cnc_nso_device_action(action='sync-from',
  host_name='PE1')`` first, then retry.
- **The head-end must be an NSO device** (``cnc_list_nso_devices``): an
  unknown name is ``400 invalid-value "illegal reference .../head-end{X}/name"``
  (L3NM: ``.../vpn-nodes/vpn-node{X}/vpn-node-id`` — the deviated model makes
  ``vpn-node-id`` a leafref into NSO's dispatch-map).
- **Delete order: the policy before its SID list.** A SID list referenced by a
  policy's explicit path cannot be deleted (``400 invalid-value "illegal
  reference .../explicit/sid-list{N}/name"``); delete or re-path the policy
  first.
- **L3VPN and BGP (verified live 2026-09-13 in dry-run)**: when every endpoint
  carries ``local_as``, the L3NM CFP renders ``router bgp <as> / vrf <vpn-id> /
  rd ... / address-family ipv4 unicast`` itself — creating the BGP process on a
  PE that has none (the lab PEs had no ``router bgp``; the dry run rendered it).
  WITHOUT ``local_as`` the CFP validates that a BGP process already exists and
  answers ``400 malformed-message`` with ``STATUS_CODE: TSDN-L3VPN-415 /
  REASON: BGP routing process is not configured on the device``. The rendered
  VRF also carries an auto-allocated route-target (``1:1`` on the lab, from the
  CFP's ``ietf-l3vpn-ntw-rt-pool``) beside the ones given — read the dry run.
  **Deleting the service takes back the VRF, the interface's VRF membership
  and the BGP VRF stanza (``router bgp <as> / no vrf <vpn-id>``) but NOT the
  ``router bgp <as>`` process** (verified live 2026-09-14 in a delete dry run
  on PEs whose process pre-existed; see cnc_delete_vpn_service).
- ``400 unknown-element`` means the body carries a node the (Cisco-deviated)
  model does not know — e.g. the L3NM ``ip-connection/ipv4`` holds ONLY
  ``local-address`` + ``prefix-length`` (``static-addresses`` and
  ``address-allocation-type`` are NSO-REMOVED); ``vpn-node-id`` is the NSO
  device name and there is no ``ne-id``.

SRv6 (verified 2026-09-15 in ``?dry-run=native`` ONLY — the lab had no SRv6
underlay: no locators, no IPv6 loopbacks; what is verified is the CFPs'
validation and the NED rendering, never device behaviour). The SR-TE CFP's
shared ``srv6-grp`` (``cisco-sr-te-cfp-sr-common``) hangs ``srv6 {presence} /
locator {presence} / locator-name (string 1..64, mandatory)`` off ``policy``
and ``odn-template``; its ``behavior`` (only ``ub6-insert-reduced``) and
``binding-sid-type`` (only ``srv6-dynamic``) are single-value enums with
those defaults, so the tools never send them (sending them explicitly
rendered byte-identical CLI). ``cnc_create_sr_policy_service``,
``cnc_create_odn_template`` and ``cnc_create_l3vpn_service`` take
``srv6_locator`` (the L3NM one also per endpoint); each docstring carries the
CLI the dry run rendered through that very tool. The CFP rules, each seen as
a live ``400`` and each refused by the tools BEFORE anything is sent: an
SRv6 policy needs an IPv6 tail-end and an IPv6 tail-end needs ``srv6``
(``invalid-value`` "tail-end must be IPv6 address for SRv6 TE policy" /
"SRv6 TE policy must be configured if tail-end is IPv6 address"; the ODN
template has the same rule for an IPv6 ``source-address``); the explicit
path, ``bandwidth`` and ``binding-sid`` are ``when "not(../srv6)"`` (each a
live ``400 malformed-message`` ".../<leaf>: the 'when' expression
\\"not(../srv6)\\" failed"); the YANG puts the same when-rule on
``auto-route``, not exercised — no tool sends it. ``srv6-dynamic`` is NOT a
path type (an SRv6 policy is the srv6 container plus an ordinary ``dynamic``
path; sending it as one is ``400 unknown-element``). The bare presence form
``"srv6": {}`` (no locator: the router's default locator) is accepted by
both CFPs — dry-run rendered as a bare ``srv6`` block, device behaviour not
verified — and is not an argument of any tool: send it through
``cnc_provision_service``. The L3NM's ``cisco-l3vpn-ntw:srv6
{address-family [{name, locator-name?}]}`` (``min-elements 1``) sits on the
vpn-instance-profile (service-wide) and on each vpn-node's
active-vpn-instance-profile entry (per node; the node entry wins — verified).
NSO validates NEITHER the locator name NOR the IPv6 tail-end against the
routers or the topology (``LOC1`` / ``2001:db8::3`` existed nowhere and
rendered fine): a committed SRv6 service only comes up once the head-end
holds that locator and reaches that loopback — read the dry run, then check
the underlay (``cnc_get_topology_node``) before committing. The IPv6
tail-end goes on the wire canonical (lowercase, compressed:
``2001:DB8:0:0::3`` -> ``2001:db8::3``, the spelling NSO renders into the
policy name — dry-run verified). ``cnc_update_sr_policy_service`` only
merges ``bandwidth`` / ``binding-sid`` (both ``when "not(../srv6)"`` —
refused by the CFP on an SRv6 policy); it cannot add ``srv6``. Whether a
hand-built PATCH of ``tail-end`` + ``srv6`` through ``cnc_provision_service``
converts a committed SR-MPLS policy was NOT tested (no commit was allowed);
the supported path is re-running ``cnc_create_sr_policy_service`` — the PUT
replaces the entry and the CFP renames the policy with the new tail-end.
Until the underlay exists every SRv6 fact here is dry-run rendered, not
device-proven.

Retries: PUT and DELETE are idempotent and keep the client's default retry on
5xx/transport errors (a re-PUT after a lost answer only reports "replaced"
instead of "created"); PATCH and the resync POST are sent once. No write here
passes ``retryable=True``. The cost of that judgement call: the out-of-sync
``502`` is a 5xx, so a PUT/DELETE against an out-of-sync head-end is
re-attempted ``max_retries`` more times (four commit attempts at the default
of 3, each failing identically) before the precise error is reported — a
sync-from first avoids the whole sequence.

``cnc_resync_service_inventory`` is different in kind: it is the CAT
NSO-connector's resync (``POST /crosswork/cat/nso-connector/v1/api/
{fullResync,typeResync,serviceResync}``) that re-reads services from NSO into
the Crosswork service inventory — documented in the 7.2 API, NOT verified
live.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Annotated, Any
from urllib.parse import unquote

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import finalize, to_json
from cnc_mcp.restconf import (
    NSO_PROXY,
    YANG_ACCEPT,
    YANG_HEADERS,
    encode_key,
    parse_restconf_errors,
    restconf_error_message,
    unwrap_list,
)
from cnc_mcp.safety import AppContext, register_tool

DATA_ROOT = f"{NSO_PROXY}/data"
# ``?dry-run=native`` — NSO renders the native (CLI) diff per device and commits nothing.
DRY_RUN_PARAMS: dict[str, str] = {"dry-run": "native"}

# T-SDN model paths, relative to ``<NSO_PROXY>/data/`` (every one verified live).
SR_TE_MODULE = "cisco-sr-te-cfp"
SR_TE_PATH = f"{SR_TE_MODULE}:sr-te"
ODN_MODULE = "cisco-sr-te-cfp-sr-odn"
ODN_TEMPLATE_PATH = f"{SR_TE_PATH}/{ODN_MODULE}:odn/{ODN_MODULE}:odn-template"
SR_POLICIES_MODULE = "cisco-sr-te-cfp-sr-policies"
SR_POLICIES_PATH = f"{SR_TE_PATH}/{SR_POLICIES_MODULE}:policies"
SR_POLICY_PATH = f"{SR_POLICIES_PATH}/{SR_POLICIES_MODULE}:policy"
SID_LIST_PATH = f"{SR_POLICIES_PATH}/{SR_POLICIES_MODULE}:sid-list"
L3VPN_MODULE = "ietf-l3vpn-ntw"
L3VPN_SERVICE_PATH = f"{L3VPN_MODULE}:l3vpn-ntw/vpn-services/vpn-service"
L2VPN_MODULE = "ietf-l2vpn-ntw"
L2VPN_SERVICE_PATH = f"{L2VPN_MODULE}:l2vpn-ntw/vpn-services/vpn-service"
VPN_COMMON_MODULE = "ietf-vpn-common"

# The CAT NSO-connector resync API (7.2 OpenAPI ``nso_connector_service_ap_is_7_2_0.json``;
# plain JSON, query parameters only, empty body). UNVERIFIED live.
NSO_CONNECTOR = "/crosswork/cat/nso-connector/v1/api"
FULL_RESYNC_URL = f"{NSO_CONNECTOR}/fullResync"
TYPE_RESYNC_URL = f"{NSO_CONNECTOR}/typeResync"
SERVICE_RESYNC_URL = f"{NSO_CONNECTOR}/serviceResync"
RESYNC_SUCCESS = "SUCCESS"

# CAT service-type labels (the 7 types ``get-available-service-types`` reports on 7.2) and
# the NSO list path the NSO-connector calls ``typePath``. ``tunnel`` is a guess from the
# ietf-te model (the others follow the verified CAT ``yang-path`` spellings).
SERVICE_TYPE_PATHS: dict[str, str] = {
    "policy": f"{SR_POLICIES_PATH}/policy",
    "odn-template": f"{SR_TE_PATH}/{ODN_MODULE}:odn/odn-template",
    "cs-sr-te-policy": "cisco-cs-sr-te-cfp:cs-sr-te-policy",
    "ietf-l3vpn": L3VPN_SERVICE_PATH,
    "ietf-l2vpn": L2VPN_SERVICE_PATH,
    "slice-service": "ietf-network-slice-service:network-slice-services/slice-service",
    "tunnel": "ietf-te:te/tunnels/tunnel",
}
SERVICE_TYPE_ALIASES: dict[str, str] = {
    "sr-policy": "policy",
    "sr-te-policy": "policy",
    "odn": "odn-template",
    "cs-policy": "cs-sr-te-policy",
    "circuit-style": "cs-sr-te-policy",
    "l3vpn": "ietf-l3vpn",
    "l3": "ietf-l3vpn",
    "l3vpn-ntw": "ietf-l3vpn",
    "ietf-l3vpn-ntw": "ietf-l3vpn",
    "l2vpn": "ietf-l2vpn",
    "l2": "ietf-l2vpn",
    "l2vpn-ntw": "ietf-l2vpn",
    "ietf-l2vpn-ntw": "ietf-l2vpn",
    "slice": "slice-service",
    "network-slice": "slice-service",
    "te-tunnel": "tunnel",
    "ietf-te": "tunnel",
}
_SERVICE_TYPE_CHOICES = ", ".join(SERVICE_TYPE_PATHS)

METRIC_TYPES = ("igp", "te", "latency", "hopcount")
PATH_TYPES = ("dynamic", "explicit")
TOPOLOGIES = ("any-to-any", "hub-spoke", "custom")
VPN_LAYERS = ("l3", "l2")
WRITE_METHODS = ("put", "patch")
ROUTE_TARGET_TYPE = "both"
MAX_MPLS_LABEL = 1048575
# SRv6 (dry-run verified 2026-09-15; see the module docstring). The SR-TE CFP's ``srv6-grp``
# (cisco-sr-te-cfp-sr-common, shared by ``policy`` and ``odn-template``): ``srv6 {presence}
# / locator {presence} / locator-name string 1..64 (mandatory)``; ``behavior`` and
# ``binding-sid-type`` are single-value enums (``ub6-insert-reduced`` / ``srv6-dynamic``,
# both defaults) and are never sent. The L3NM augments ``cisco-l3vpn-ntw:srv6 {
# address-family [{name, locator-name?}] }`` onto the vpn-instance-profile (service-wide)
# and onto each vpn-node's active-vpn-instance-profile (per node; the node entry wins).
SRV6_LOCATOR_MAX = 64
L3VPN_SRV6_KEY = "cisco-l3vpn-ntw:srv6"

# Verified NSO error spellings, matched against error-message + error-path.
_HEAD_END_REF = re.compile(r"head-end\{([^}]*)\}/name")
# The deviated L3NM makes vpn-node-id a leafref into NSO's dispatch-map
# (ietf-l3vpn-ntw-deviations.yang), so an unknown PE is an illegal reference whose
# path ends in ``.../vpn-nodes/vpn-node{X}/vpn-node-id`` — the same shape as the verified
# head-end one.
_VPN_NODE_REF = re.compile(r"vpn-node\{([^}]*)\}/vpn-node-id")
_SID_LIST_REF = re.compile(r"sid-list\{([^}]*)\}/name")
_OUT_OF_SYNC = re.compile(r"device\s+(\S+?):\s+out of sync", re.IGNORECASE)
_STATUS_CODE = re.compile(r"STATUS_CODE:\s*(\S+)")
_REASON = re.compile(r"REASON:\s*(.+)")
# Verified SRv6 CFP refusals (2026-09-15, ?dry-run=native — CFP validation runs in a dry run):
# the two ``must`` rules pairing an IPv6 tail-end / source-address with the srv6 container
# (``400 invalid-value``), the ``when "not(../srv6)"`` leaves (``400 malformed-message`` naming
# the leaf in the message path: ``.../binding-sid``, ``.../bandwidth``, ``.../path{100}/
# explicit``), the mandatory locator-name and the L3NM's ``min-elements 1`` address-family.
_SRV6_NEEDS_IPV6_TAIL = "tail-end must be IPv6 address for SRv6 TE policy"
_SRV6_REQUIRED = re.compile(
    r"SRv6 TE policy must be configured if (tail-end|source-address) is IPv6 address"
)
_SRV6_WHEN = re.compile(r"/([^/:]+): the 'when' expression \"not\(\.\./srv6\)\" failed")
_SRV6_WHEN_LEAVES = {
    "binding-sid": "binding_sid",
    "bandwidth": "bandwidth_kbps",
    "explicit": "an explicit path (path_type='explicit' / sid_list)",
}
_SRV6_LOCATOR_NAME_MISSING = "srv6/locator/locator-name is not configured"
_SRV6_L3NM_NO_AF = re.compile(r"too few .*srv6/address-family")
_ENDPOINT_KEYS = frozenset(
    {"node", "interface", "address", "prefix_length", "local_as", "id", "srv6_locator"}
)
_ENDPOINT_REQUIRED = ("node", "interface", "address", "prefix_length")
_ENDPOINT_EXAMPLE = (
    '[{"node": "PE1", "interface": "Loopback91", "address": "10.91.1.1", "prefix_length": 30}]'
)

_DRY_RUN_DESC = (
    "true: send the request with ?dry-run=native and return the device CLI NSO would push, "
    "committing NOTHING (CFP validation still runs). Recommended before the first real commit "
    "of a new shape. false (default): commit."
)
_NAME_DESC = "Service instance name, the NSO list key — exact and case-sensitive (e.g. '{}')."
_COLOR_DESC = "SR policy color (e.g. 91)."


@dataclass
class ServiceTarget:
    """Where a write goes: the keyed data path plus what to call it in messages."""

    kind: str  # "ODN template", "SR policy service", ...
    name: str  # the list key (for messages)
    path: str  # data/-relative, keyed, percent-encoded

    @property
    def label(self) -> str:
        return f"{self.kind} '{self.name}'"


@dataclass
class DryRunDevice:
    device: str
    cli: str


# --- pure helpers: paths ---------------------------------------------------------------


def data_url(yang_path: str) -> str:
    """``<NSO_PROXY>/data/<yang_path>`` — the proxy URL of a data/-relative path."""
    return f"{DATA_ROOT}/{yang_path}"


def keyed_path(list_path: str, key: str) -> str:
    """``<list_path>=<percent-encoded key>``."""
    return f"{list_path}={encode_key(key)}"


def normalize_yang_path(path: str) -> str:
    """A caller-given YANG data path -> the data/-relative form the proxy URL takes.

    Accepts the bare form (``ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=x``),
    a leading ``/``, a ``data/`` or ``restconf/data/`` prefix, or the whole proxy
    prefix ``/crosswork/proxy/nso/restconf/data/``. PlatformError when nothing is
    left, or when the text carries a query string / fragment / whitespace (the
    tools add their own ``?dry-run=native``).
    """
    text = path.strip().lstrip("/")
    for prefix in (f"{DATA_ROOT.lstrip('/')}/", "restconf/data/", "data/"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    text = text.strip("/")
    if not text:
        raise PlatformError(
            "yang_path is empty: give the service's data path relative to the NSO proxy's "
            "data/ root, e.g. 'ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-1'."
        )
    if any(ch in text for ch in "?#") or any(ch.isspace() for ch in text):
        raise PlatformError(
            f"yang_path '{path}' must be a bare data path: no query string, fragment or "
            "whitespace (percent-encode '/' and spaces inside a list key; dry_run adds "
            "?dry-run=native itself)."
        )
    return text


def plan_path_of(yang_path: str) -> str | None:
    """The nano-plan path of a keyed service path, or None when the path has no key.

    Verified rule: the service's ``<list>=<key>`` becomes ``<list>-plan=<key>`` in
    the same parent (``.../odn-template=x`` -> ``.../odn-template-plan=x``,
    ``.../policy=x`` -> ``.../policy-plan=x``, ``.../vpn-service=x`` ->
    ``.../vpn-service-plan=x``). The plan segment is spelled the way CAT reports
    ``plan-yang-path`` and the verified proxy plan GETs used it: a module
    prefix on the last segment is dropped when it merely repeats the nearest
    prefixed ancestor's module (``.../cisco-sr-te-cfp-sr-odn:odn/
    cisco-sr-te-cfp-sr-odn:odn-template=x`` -> ``.../cisco-sr-te-cfp-sr-odn:odn/
    odn-template-plan=x``); a prefix that differs (a top-level list, a list
    augmented in from another module) stays.
    """
    head, _, last = yang_path.rpartition("/")
    if "=" not in last:
        return None
    list_name, _, key = last.partition("=")
    module, _, local = list_name.rpartition(":")
    if module and head and module == list_identity(head)[0]:
        list_name = local
    segment = f"{list_name}-plan={key}"
    return f"{head}/{segment}" if head else segment


def list_identity(yang_path: str) -> tuple[str, str]:
    """``(module, local list name)`` of the last segment of a data path.

    ``a:x/b:y=k`` -> ``("b", "y")``; an unprefixed last segment inherits the
    nearest prefixed ancestor's module (``ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/
    vpn-service=k`` -> ``("ietf-l3vpn-ntw", "vpn-service")``); ``("", name)``
    when no segment carries a prefix.
    """
    segments = yang_path.split("/")
    last = segments[-1].partition("=")[0]
    module = ""
    for segment in reversed(segments):
        node = segment.partition("=")[0]
        if ":" in node:
            module = node.partition(":")[0]
            break
    local = last.partition(":")[2] if ":" in last else last
    return module, local


def generic_kind(yang_path: str) -> str:
    """What to call an entry of an arbitrary list in messages: ``vpn-service`` /
    ``slice-service`` as they are, ``cs-sr-te-policy service`` otherwise."""
    _module, local = list_identity(yang_path)
    return local if local.endswith("service") else f"{local} service"


def key_of(yang_path: str) -> str | None:
    """The (decoded) key of the last segment of a data path, or None when unkeyed."""
    last = yang_path.rpartition("/")[2]
    if "=" not in last:
        return None
    return unquote(last.partition("=")[2])


# --- pure helpers: argument parsing -------------------------------------------------


def _choice(value: str, choices: tuple[str, ...], what: str) -> str:
    key = value.strip().lower().replace("_", "-")
    if key not in choices:
        raise PlatformError(f"Unknown {what} '{value}'. Use one of: {', '.join(choices)}.")
    return key


def parse_names(text: str, what: str, example: str) -> list[str]:
    """``'PE1, PE2'`` -> ``['PE1', 'PE2']`` (order kept, duplicates dropped); PlatformError
    when nothing is left."""
    names: list[str] = []
    for part in text.split(","):
        name = part.strip()
        if name and name not in names:
            names.append(name)
    if not names:
        raise PlatformError(
            f"{what} is empty: give one or more NSO device names separated by commas "
            f"(e.g. '{example}'; list them with cnc_list_nso_devices)."
        )
    return names


def parse_labels(text: str) -> list[int]:
    """``'16003, 16002'`` -> ``[16003, 16002]``; PlatformError for an empty list or a value
    outside 0..1048575 (the MPLS label space)."""
    labels: list[int] = []
    for part in text.split(","):
        raw = part.strip()
        if not raw:
            continue
        try:
            label = int(raw)
        except ValueError:
            raise PlatformError(
                f"labels: '{raw}' is not an MPLS label. Give comma-separated integers in path "
                "order, e.g. '16003,16002'."
            ) from None
        if not 0 <= label <= MAX_MPLS_LABEL:
            raise PlatformError(
                f"labels: {label} is outside the MPLS label range 0..{MAX_MPLS_LABEL}."
            )
        labels.append(label)
    if not labels:
        raise PlatformError(
            "labels is empty: give the SIDs of the path as comma-separated MPLS labels in "
            "order, e.g. '16003,16002' (the prefix-SIDs of the hops)."
        )
    return labels


def require_ip(value: str, what: str) -> str:
    """``value`` as a canonical IP address text: IPv4 unchanged, IPv6 lowercase and
    compressed (``2001:DB8:0:0::3`` -> ``2001:db8::3`` — the form NSO renders into the
    CFP's policy name ``srte_c_<color>_ep_<tail-end>`` and the ``end-point ipv6`` line,
    dry-run verified 2026-09-15, so the body, the name and the hints all agree).
    PlatformError when it is not an IP address, or when it carries a zone id
    (``2001:db8::3%eth0`` — :mod:`ipaddress` accepts one, no tail-end takes one)."""
    text = value.strip()
    if "%" in text:
        raise PlatformError(
            f"{what} '{value}' carries a zone id ('%...'), which no tail-end takes: give the "
            "bare address (e.g. 2001:db8::3)."
        )
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise PlatformError(
            f"{what} '{value}' is not an IP address. Give the TE router-id (the Loopback0 "
            "address the topology reports, e.g. 10.0.0.3) — not a host name and not the "
            "management address; look it up with cnc_get_topology_node."
        ) from None


def locator_name(value: str, what: str) -> str:
    """An SRv6 locator name as the CFPs take it: stripped, 1..64 characters, no whitespace
    (``srv6-grp`` / ``srv6-grouping`` type it ``string 1..64``; NSO does NOT check it
    against the routers — a name no device holds renders fine and only fails on the
    box). PlatformError otherwise."""
    name = value.strip()
    if not name or len(name) > SRV6_LOCATOR_MAX or any(ch.isspace() for ch in name):
        raise PlatformError(
            f"{what} '{value}' must be an SRv6 locator name of 1..{SRV6_LOCATOR_MAX} characters "
            "without whitespace (the name under 'segment-routing srv6 locators' on the "
            "router, e.g. 'LOC1')."
        )
    return name


def _is_ipv6(text: str) -> bool:
    try:
        return ipaddress.ip_address(text.strip()).version == 6
    except ValueError:
        return False


def parse_endpoints(text: str) -> list[dict[str, Any]]:
    """The ``endpoints`` JSON of cnc_create_l3vpn_service -> validated endpoint dicts.

    Each endpoint needs ``node`` (NSO device name), ``interface`` (e.g.
    ``Loopback91``), ``address`` (IPv4) and ``prefix_length`` (0..32);
    optional ``local_as`` (1..4294967295), ``id`` (the access id, default
    the endpoint's ordinal within its node) and ``srv6_locator`` (the node's
    SRv6 locator name, 1..64 characters — a per-node override of the
    service-wide ``srv6_locator``). A single object is accepted as a
    one-entry list. PlatformError names the offending endpoint and key —
    unknown keys are refused too, so a mis-spelt key cannot vanish silently.
    """
    try:
        data = json.loads(text)
    except ValueError as e:
        raise PlatformError(
            f"endpoints is not valid JSON ({e}). Expected a list such as {_ENDPOINT_EXAMPLE}."
        ) from None
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not data:
        raise PlatformError(
            f"endpoints must be a non-empty JSON list of endpoint objects, e.g. "
            f"{_ENDPOINT_EXAMPLE}."
        )
    endpoints: list[dict[str, Any]] = []
    for index, item in enumerate(data, 1):
        if not isinstance(item, dict):
            raise PlatformError(
                f"endpoints[{index}] is not an object; expected {_ENDPOINT_EXAMPLE}."
            )
        unknown = sorted(set(item) - _ENDPOINT_KEYS)
        if unknown:
            raise PlatformError(
                f"endpoints[{index}] has unknown key(s) {', '.join(unknown)}; allowed: "
                f"{', '.join(sorted(_ENDPOINT_KEYS))}."
            )
        missing = [k for k in _ENDPOINT_REQUIRED if item.get(k) in (None, "")]
        if missing:
            raise PlatformError(
                f"endpoints[{index}] is missing required key(s) {', '.join(missing)}; each "
                f"endpoint needs {', '.join(_ENDPOINT_REQUIRED)}."
            )
        endpoint: dict[str, Any] = {
            "node": str(item["node"]).strip(),
            "interface": str(item["interface"]).strip(),
            "address": str(item["address"]).strip(),
        }
        try:
            ipaddress.IPv4Address(endpoint["address"])
        except ValueError:
            raise PlatformError(
                f"endpoints[{index}].address '{item['address']}' is not an IPv4 address."
            ) from None
        endpoint["prefix_length"] = _int_in_range(
            item["prefix_length"], 0, 32, f"endpoints[{index}].prefix_length"
        )
        if item.get("local_as") not in (None, ""):
            endpoint["local_as"] = _int_in_range(
                item["local_as"], 1, 4294967295, f"endpoints[{index}].local_as"
            )
        if item.get("id") not in (None, ""):
            endpoint["id"] = str(item["id"]).strip()
        if item.get("srv6_locator") not in (None, ""):
            endpoint["srv6_locator"] = locator_name(
                str(item["srv6_locator"]), f"endpoints[{index}].srv6_locator"
            )
        endpoints.append(endpoint)
    return endpoints


def _int_in_range(value: Any, low: int, high: int, what: str) -> int:
    if isinstance(value, bool):
        raise PlatformError(f"{what} must be an integer {low}..{high}, not a boolean.")
    try:
        number = int(str(value).strip())
    except ValueError:
        raise PlatformError(f"{what} '{value}' must be an integer {low}..{high}.") from None
    if not low <= number <= high:
        raise PlatformError(f"{what} {number} is outside {low}..{high}.")
    return number


def validate_service_body(body_json: str, yang_path: str) -> tuple[str, dict[str, Any]]:
    """The ``body_json`` of cnc_provision_service -> ``(top key, body)``.

    Rules (each PlatformError names the one it failed): valid JSON; a JSON
    object; exactly one top-level key; that key module-prefixed
    (``<module>:<list>``); its value a list holding exactly one object (the
    RESTCONF instance form ``{"<module>:<list>": [{...}]}`` every verified
    CFP body takes); and the key's local name equal to the list the path
    addresses (``.../policy=x`` takes ``cisco-sr-te-cfp-sr-policies:policy``).
    """
    try:
        body = json.loads(body_json)
    except ValueError as e:
        raise PlatformError(f"body_json is not valid JSON ({e}).") from None
    if not isinstance(body, dict):
        raise PlatformError(
            "body_json must be a JSON object with one module-prefixed key, e.g. "
            '{"cisco-sr-te-cfp-sr-policies:policy": [{"name": "x", ...}]}.'
        )
    if len(body) != 1:
        raise PlatformError(
            f"body_json must have exactly one top-level key (the service list, "
            f"'<module>:<list>'); it has {len(body)}: {', '.join(map(str, body)) or 'none'}."
        )
    key = next(iter(body))
    if not isinstance(key, str) or ":" not in key or not key.partition(":")[2]:
        raise PlatformError(
            f"body_json's top-level key '{key}' must be module-prefixed ('<module>:<list>', "
            "e.g. 'ietf-l3vpn-ntw:vpn-service')."
        )
    value = body[key]
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise PlatformError(
            f"body_json['{key}'] must be a list holding exactly one object (the service "
            'instance): {"' + key + '": [{...}]}.'
        )
    _module, local = list_identity(yang_path)
    if key.partition(":")[2] != local:
        raise PlatformError(
            f"body_json's top-level key '{key}' does not match the list the yang_path "
            f"addresses ('{local}'): a RESTCONF PUT/PATCH body is keyed by the list name of "
            "the path's last segment."
        )
    return key, body


def resolve_type_path(service_type: str) -> str:
    """A CAT service-type label / QName / raw list path -> the NSO-connector ``typePath``.

    Labels (:data:`SERVICE_TYPE_PATHS` keys and :data:`SERVICE_TYPE_ALIASES`) are
    case-insensitive; the CAT QName form ``{<namespace>}<local>`` is reduced to
    its local name, with ``vpn-service`` told apart by ``l3vpn`` / ``l2vpn`` in
    the namespace; a text containing ``/`` is taken as a type path verbatim.
    """
    text = service_type.strip()
    if not text:
        raise PlatformError(f"service_type is empty. Use one of: {_SERVICE_TYPE_CHOICES}.")
    namespace = ""
    if text.startswith("{"):
        namespace, _, text = text[1:].partition("}")
        text = text.strip()
    elif "/" in text:
        return text.strip("/")
    key = text.lower().replace("_", "-")
    if key == "vpn-service":
        if "l3vpn" in namespace:
            key = "ietf-l3vpn"
        elif "l2vpn" in namespace:
            key = "ietf-l2vpn"
        else:
            raise PlatformError(
                "service_type 'vpn-service' is ambiguous: say 'ietf-l3vpn' or 'ietf-l2vpn' "
                "(or give the CAT QName with its namespace)."
            )
    key = SERVICE_TYPE_ALIASES.get(key, key)
    if key not in SERVICE_TYPE_PATHS:
        raise PlatformError(
            f"Unknown service_type '{service_type}'. Use one of: {_SERVICE_TYPE_CHOICES} "
            "(a CAT QName '{ns}local' or a raw NSO list path is accepted too)."
        )
    return SERVICE_TYPE_PATHS[key]


# --- pure helpers: bodies (verified shapes) --------------------------------------------


def srv6_block(locator: str) -> dict[str, Any]:
    """The SR-TE CFP's ``srv6`` container for a locator name: ``{"locator": {"locator-name":
    <name>}}`` — ``behavior`` (only ``ub6-insert-reduced``) and ``binding-sid-type`` (only
    ``srv6-dynamic``) are left to their defaults (verified: sending them explicitly renders
    byte-identical CLI)."""
    return {"locator": {"locator-name": locator}}


def build_odn_template_body(
    name: str,
    color: int,
    head_ends: list[str],
    metric_type: str,
    delegate_to_pce: bool,
    bandwidth_kbps: int,
    maximum_sid_depth: int,
    flex_algo: int,
    srv6_locator: str = "",
) -> dict[str, Any]:
    """``{"cisco-sr-te-cfp-sr-odn:odn-template": [{...}]}`` — the verified PUT body.

    ``srv6_locator`` adds ``"srv6": {"locator": {"locator-name": ...}}`` (dry-run
    verified 2026-09-15); PlatformError with ``bandwidth_kbps`` beside it — the
    ODN model's ``bandwidth`` is ``when "not(../srv6)"``.
    """
    locator = locator_name(srv6_locator, "srv6_locator") if srv6_locator.strip() else ""
    if locator and bandwidth_kbps:
        raise PlatformError(
            "srv6_locator and bandwidth_kbps are incompatible: the ODN model allows bandwidth "
            'only without srv6 (when "not(../srv6)" — SR-MPLS only in this release). Drop '
            "bandwidth_kbps for an SRv6 template, or srv6_locator for SR-MPLS."
        )
    dynamic: dict[str, Any] = {"metric-type": metric_type}
    if delegate_to_pce:
        dynamic["pce"] = {}
    if flex_algo:
        dynamic["flex-alg"] = flex_algo
    entry: dict[str, Any] = {
        "name": name,
        "color": color,
        "head-end": [{"name": head_end} for head_end in head_ends],
        "dynamic": dynamic,
    }
    if locator:
        entry["srv6"] = srv6_block(locator)
    if bandwidth_kbps:
        entry["bandwidth"] = bandwidth_kbps
    if maximum_sid_depth:
        entry["maximum-sid-depth"] = maximum_sid_depth
    return {f"{ODN_MODULE}:odn-template": [entry]}


def build_sr_policy_body(
    name: str,
    head_end: str,
    tail_end: str,
    color: int,
    preference: int,
    path_type: str,
    metric_type: str,
    delegate_to_pce: bool,
    sid_list: str,
    bandwidth_kbps: int,
    binding_sid: int,
    srv6_locator: str = "",
) -> dict[str, Any]:
    """``{"cisco-sr-te-cfp-sr-policies:policy": [{...}]}`` — the verified PUT body.

    ``path_type`` ``dynamic`` -> ``{"preference", "dynamic": {"metric-type", "pce": {}}}``;
    ``explicit`` -> ``{"preference", "explicit": {"sid-list": [{"name": sid_list}]}}``
    (PlatformError without a ``sid_list``, or with one on a dynamic path).

    ``srv6_locator`` adds ``"srv6": {"locator": {"locator-name": ...}}`` and enforces
    the SR-TE CFP's SRv6 rules BEFORE anything is sent (each one verified as a
    400 from the CFP in dry-run, 2026-09-15): the tail-end must be IPv6
    (``must "not(srv6) or contains(string(tail-end),':')"``); an IPv6 tail-end
    conversely needs the srv6 container (``must "not(contains(string(tail-end),
    ':')) or srv6"``); the explicit path, ``bandwidth`` and ``binding-sid`` are
    ``when "not(../srv6)"``. ``srv6-dynamic`` is not a path type (it is the only
    value of ``srv6/locator/binding-sid-type``): an SRv6 policy is the srv6
    container plus an ordinary ``dynamic`` candidate path.
    """
    locator = locator_name(srv6_locator, "srv6_locator") if srv6_locator.strip() else ""
    ipv6_tail = _is_ipv6(tail_end)
    if locator:
        if not ipv6_tail:
            raise PlatformError(
                f"srv6_locator makes this an SRv6 policy, and an SRv6 policy needs an IPv6 "
                f"tail_end (the SR-TE CFP rule: 'tail-end must be IPv6 address for SRv6 TE "
                f"policy'); tail_end '{tail_end}' is IPv4. Give the tail-end's IPv6 loopback "
                "(e.g. 2001:db8::3), or drop srv6_locator for an SR-MPLS policy."
            )
        if path_type != "dynamic":
            raise PlatformError(
                "srv6_locator needs path_type='dynamic': an SRv6 policy takes a dynamic "
                "candidate path only — the explicit path (sid_list), bandwidth_kbps and "
                "binding_sid are SR-MPLS only in this release (the model's when "
                "\"not(../srv6)\"). 'srv6-dynamic' is not a path type: it is the policy's "
                "(only) binding-sid-type, applied automatically."
            )
        if bandwidth_kbps or binding_sid:
            offending = " and ".join(
                what
                for what, given in (
                    ("bandwidth_kbps", bandwidth_kbps),
                    ("binding_sid", binding_sid),
                )
                if given
            )
            raise PlatformError(
                f"{offending} cannot be set on an SRv6 policy (the model's bandwidth and "
                'binding-sid are when "not(../srv6)" — SR-MPLS only in this release; the '
                "SRv6 binding SID is always dynamic). Use 0, or drop srv6_locator for SR-MPLS."
            )
    elif ipv6_tail:
        raise PlatformError(
            f"tail_end '{tail_end}' is IPv6, which makes this an SRv6 policy (the SR-TE CFP "
            "rule: 'SRv6 TE policy must be configured if tail-end is IPv6 address'): give "
            "srv6_locator — the head-end's SRv6 locator name, e.g. 'LOC1' — or an IPv4 "
            "tail_end for an SR-MPLS policy. For the router's default locator (the bare "
            'presence form "srv6": {} — dry-run verified, device behaviour not) send the '
            "body through cnc_provision_service."
        )
    path: dict[str, Any] = {"preference": preference}
    if path_type == "explicit":
        if not sid_list.strip():
            raise PlatformError(
                "path_type='explicit' needs sid_list: the name of an existing SID list "
                "(create one with cnc_create_sid_list first, e.g. 'mcp-sl-1')."
            )
        path["explicit"] = {"sid-list": [{"name": sid_list.strip()}]}
    else:
        if sid_list.strip():
            raise PlatformError(
                "sid_list only applies to path_type='explicit'; a dynamic path is computed "
                "(by the PCE when delegate_to_pce is true, else by the head-end)."
            )
        dynamic: dict[str, Any] = {"metric-type": metric_type}
        if delegate_to_pce:
            dynamic["pce"] = {}
        path["dynamic"] = dynamic
    entry: dict[str, Any] = {
        "name": name,
        "head-end": [{"name": head_end}],
        "tail-end": tail_end,
        "color": color,
        "path": [path],
    }
    if locator:
        entry["srv6"] = srv6_block(locator)
    if bandwidth_kbps:
        entry["bandwidth"] = bandwidth_kbps
    if binding_sid:
        entry["binding-sid"] = binding_sid
    return {f"{SR_POLICIES_MODULE}:policy": [entry]}


def build_sr_policy_patch(name: str, bandwidth_kbps: int, binding_sid: int) -> dict[str, Any]:
    """The PATCH (merge) body carrying only the given leaves; PlatformError when none is."""
    entry: dict[str, Any] = {"name": name}
    if bandwidth_kbps:
        entry["bandwidth"] = bandwidth_kbps
    if binding_sid:
        entry["binding-sid"] = binding_sid
    if len(entry) == 1:
        raise PlatformError(
            "Nothing to update: give bandwidth_kbps and/or binding_sid (non-zero). To change "
            "the path, head-end, tail-end, color or the SRv6 locator, re-create the service "
            "with cnc_create_sr_policy_service (a PUT replaces the whole entry)."
        )
    return {f"{SR_POLICIES_MODULE}:policy": [entry]}


def build_sid_list_body(name: str, labels: list[int]) -> dict[str, Any]:
    """``{"cisco-sr-te-cfp-sr-policies:sid-list": [{"name", "sid": [{"index", "mpls":
    {"label"}}]}]}`` — the verified PUT body."""
    sids = [{"index": index, "mpls": {"label": label}} for index, label in enumerate(labels, 1)]
    return {f"{SR_POLICIES_MODULE}:sid-list": [{"name": name, "sid": sids}]}


def build_l3vpn_body(
    vpn_id: str,
    route_distinguisher: str,
    route_target: str,
    endpoints: list[dict[str, Any]],
    topology: str,
    profile_id: str,
    srv6_locator: str = "",
) -> dict[str, Any]:
    """``{"ietf-l3vpn-ntw:vpn-service": [{...}]}`` — the verified L3NM body.

    One ``vpn-instance-profile`` (rd + one ipv4 address-family with a single
    ``both`` route-target), one ``vpn-node`` per distinct endpoint node
    (``local-as`` from the first endpoint of that node that gives one — a
    conflicting second value is refused), one ``vpn-network-access`` per
    endpoint under its node (ids default to 1, 2, ... per node).

    SRv6 (dry-run verified 2026-09-15): ``srv6_locator`` puts ``"cisco-l3vpn-ntw:
    srv6": {"address-family": [{"name": "ietf-vpn-common:ipv4", "locator-name":
    ...}]}`` on the profile (service-wide; the list mirrors the profile's one
    ipv4 address-family — an entry for an address-family the profile lacks is
    silently ignored by the CFP), and an endpoint's ``srv6_locator`` puts the
    same container on that node's ``active-vpn-instance-profiles`` entry
    (per node; a node-level entry overrides the profile-level one — verified;
    two endpoints of one node giving different names are refused).
    """
    service_locator = locator_name(srv6_locator, "srv6_locator") if srv6_locator.strip() else ""
    nodes: dict[str, dict[str, Any]] = {}
    for endpoint in endpoints:
        node = nodes.get(endpoint["node"])
        if node is None:
            node = {
                "vpn-node-id": endpoint["node"],
                "active-vpn-instance-profiles": {
                    "vpn-instance-profile": [{"profile-id": profile_id}]
                },
                "vpn-network-accesses": {"vpn-network-access": []},
            }
            nodes[endpoint["node"]] = node
        local_as = endpoint.get("local_as")
        if local_as is not None:
            if "local-as" in node and node["local-as"] != local_as:
                raise PlatformError(
                    f"endpoints on node '{endpoint['node']}' give different local_as values "
                    f"({node['local-as']} and {local_as}); local-as is per node."
                )
            node["local-as"] = local_as
        node_locator = endpoint.get("srv6_locator")
        if node_locator:
            active = node["active-vpn-instance-profiles"]["vpn-instance-profile"][0]
            held = active.get(L3VPN_SRV6_KEY, {}).get("address-family", [{}])[0].get("locator-name")
            if held is not None and held != node_locator:
                raise PlatformError(
                    f"endpoints on node '{endpoint['node']}' give different srv6_locator values "
                    f"('{held}' and '{node_locator}'); the locator is per node."
                )
            active[L3VPN_SRV6_KEY] = l3vpn_srv6_block(node_locator)
        accesses = node["vpn-network-accesses"]["vpn-network-access"]
        accesses.append(
            {
                "id": endpoint.get("id") or str(len(accesses) + 1),
                "interface-id": endpoint["interface"],
                "ip-connection": {
                    "ipv4": {
                        "local-address": endpoint["address"],
                        "prefix-length": endpoint["prefix_length"],
                    }
                },
            }
        )
    for node in nodes.values():  # local-as before the profile block, as the verified body has it
        if "local-as" in node:
            ordered = {"vpn-node-id": node["vpn-node-id"], "local-as": node["local-as"]}
            ordered.update((k, v) for k, v in node.items() if k not in ordered)
            node.clear()
            node.update(ordered)
    profile: dict[str, Any] = {
        "profile-id": profile_id,
        "rd": route_distinguisher,
        "address-family": [
            {
                "address-family": f"{VPN_COMMON_MODULE}:ipv4",
                "vpn-targets": {
                    "vpn-target": [
                        {
                            "id": 1,
                            "route-targets": [{"route-target": route_target}],
                            "route-target-type": ROUTE_TARGET_TYPE,
                        }
                    ]
                },
            }
        ],
    }
    if service_locator:
        profile[L3VPN_SRV6_KEY] = l3vpn_srv6_block(service_locator)
    return {
        f"{L3VPN_MODULE}:vpn-service": [
            {
                "vpn-id": vpn_id,
                "vpn-service-topology": f"{VPN_COMMON_MODULE}:{topology}",
                "vpn-instance-profiles": {"vpn-instance-profile": [profile]},
                "vpn-nodes": {"vpn-node": list(nodes.values())},
            }
        ]
    }


def l3vpn_srv6_block(locator: str) -> dict[str, Any]:
    """The L3NM ``cisco-l3vpn-ntw:srv6`` container for this tool's single ipv4 address-family:
    ``{"address-family": [{"name": "ietf-vpn-common:ipv4", "locator-name": <name>}]}`` (the
    verified profile-level and node-level shape; the flat ``{"locator-name"}`` form the SR-TE
    CFP uses is ``400 unknown-element`` here)."""
    return {"address-family": [{"name": f"{VPN_COMMON_MODULE}:ipv4", "locator-name": locator}]}


def _l3vpn_uses_srv6(body: dict[str, Any]) -> bool:
    """True when the built L3NM body carries an srv6 container on the profile or on any node."""
    service = body[f"{L3VPN_MODULE}:vpn-service"][0]
    profiles = service["vpn-instance-profiles"]["vpn-instance-profile"]
    if any(L3VPN_SRV6_KEY in profile for profile in profiles):
        return True
    return any(
        L3VPN_SRV6_KEY in active
        for node in service["vpn-nodes"]["vpn-node"]
        for active in node["active-vpn-instance-profiles"]["vpn-instance-profile"]
    )


# --- pure helpers: responses ----------------------------------------------------------


def _json_or_none(response: httpx.Response) -> Any:
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def explain_write_failure(
    status: int, data: Any, *, method: str, target: ServiceTarget
) -> str | None:
    """The precise text for a verified NSO proxy failure, or None for anything else.

    Verified live (see the module docstring): the unknown head-end and the
    referenced SID list (``400 invalid-value "illegal reference ..."``), an
    out-of-model body node (``400 unknown-element``), a CFP validation
    verdict (``400 malformed-message`` with ``STATUS_CODE: TSDN-...`` /
    ``REASON: ...`` lines), a head-end out of sync (``502 operation-failed
    "... device X: out of sync"``), a missing entry on DELETE (``404``
    ``uri keypath not found``) and on PATCH (``404 invalid-value "patch to a
    nonexistent resource"``, verified 2026-09-15), and the SRv6 rules of the
    SR-TE CFP / L3NM (verified in dry-run 2026-09-15): ``400 invalid-value``
    "tail-end must be IPv6 address for SRv6 TE policy" / "SRv6 TE policy must
    be configured if tail-end|source-address is IPv6 address", ``400
    malformed-message`` ".../<leaf>: the 'when' expression \\"not(../srv6)\\"
    failed" (``binding-sid``, ``bandwidth``, ``path{N}/explicit``), ".../srv6/
    locator/locator-name is not configured" and the L3NM's "too few .../srv6/
    address-family, 0 configured". Any other RESTCONF error document falls
    back to :func:`cnc_mcp.restconf.restconf_error_message`.
    """
    errors = parse_restconf_errors(data)
    if not errors:
        return None
    for err in errors:
        tag = (err["tag"] or "").lower()
        message = err["message"] or ""
        haystack = f"{message} {err['path'] or ''}"
        if status == 400 and tag == "invalid-value":
            srv6 = _explain_srv6_rule(message)
            if srv6:
                return srv6
        if status == 400 and tag == "invalid-value" and "illegal reference" in message:
            for what, pattern in (("head-end", _HEAD_END_REF), ("vpn-node", _VPN_NODE_REF)):
                found = pattern.search(haystack)
                if found:
                    return (
                        f"{what} '{found.group(1)}' is not an NSO device (list NSO's devices "
                        "with cnc_list_nso_devices; a Crosswork device reaches NSO once its "
                        "nso_state is SYNCED)."
                    )
            found = _SID_LIST_REF.search(haystack)
            if found:
                if method == "DELETE":
                    return (
                        f"SID list {found.group(1)} is still referenced by a policy — delete "
                        "the policy first (cnc_delete_sr_policy_service), then the SID list."
                    )
                return (
                    f"SID list '{found.group(1)}' does not exist — create it first with "
                    "cnc_create_sid_list, then reference it from the explicit path."
                )
            return f"the body references something NSO does not hold: {message}"
        if status == 400 and tag == "unknown-element":
            return (
                f"the body has a node the model does not know: {message} (check the leaf "
                "names against the YANG as NSO serves it — the Cisco deviations remove "
                "several RFC nodes)."
            )
        code_match = _STATUS_CODE.search(message) if tag == "malformed-message" else None
        if status == 400 and code_match:
            code = code_match.group(1)
            reason = _REASON.search(message)
            text = (
                f"the function pack rejected the service: "
                f"{reason.group(1).strip() if reason else message.strip()} ({code})"
            )
            if code.upper() == "TSDN-L3VPN-415" or "bgp" in message.lower():
                text += (
                    " — the head-end has no BGP routing process: give local_as on its "
                    "endpoints (the CFP then renders 'router bgp <as>' itself) or configure "
                    "'router bgp <asn>' on the device first."
                )
            return text
        if status == 400 and tag == "malformed-message":
            srv6 = _explain_srv6_rule(message)
            if srv6:
                return srv6
        if status == 502 and "out of sync" in message.lower():
            found = _OUT_OF_SYNC.search(message)
            device = found.group(1) if found else "the head-end"
            return (
                f"NSO considers {device} out of sync — run cnc_nso_device_action("
                f"action='sync-from', host_name='{device}') then retry."
            )
        if status == 404 and method in ("DELETE", "GET", "PATCH"):
            return f"no {target.label} (names are exact and case-sensitive)."
    return restconf_error_message(status, data)


def _explain_srv6_rule(message: str) -> str | None:
    """The agent-facing text for one of the verified SRv6 CFP refusals in ``message``, or
    None. The tools' own pre-flight refuses every shape that triggers these before sending,
    so they are reached through cnc_provision_service / cnc_update_sr_policy_service (a
    PATCH of bandwidth or binding-sid onto an SRv6 policy) or a CFP newer than the one
    verified."""
    if _SRV6_NEEDS_IPV6_TAIL in message:
        return (
            "an SRv6 policy (the srv6 container / srv6_locator) needs an IPv6 tail-end — the "
            "SR-TE CFP refuses an IPv4 one ('tail-end must be IPv6 address for SRv6 TE "
            "policy'): give the tail-end's IPv6 loopback (e.g. 2001:db8::3) as tail_end, or "
            "drop srv6_locator for an SR-MPLS policy."
        )
    found = _SRV6_REQUIRED.search(message)
    if found:
        leaf = found.group(1)
        kind = "policy" if leaf == "tail-end" else "ODN template"
        return (
            f"an IPv6 {leaf} makes this an SRv6 {kind}, and the SR-TE CFP then requires the "
            f"srv6 container ('SRv6 TE policy must be configured if {leaf} is IPv6 address'): "
            "give srv6_locator (the head-end's SRv6 locator name, e.g. 'LOC1'), or an IPv4 "
            f"{leaf} for SR-MPLS."
        )
    found = _SRV6_WHEN.search(message)
    if found:
        leaf = found.group(1)
        what = _SRV6_WHEN_LEAVES.get(leaf, leaf)
        return (
            f"{what} is not allowed on an SRv6 policy or template (the model's when "
            '"not(../srv6)": explicit paths, bandwidth, binding-sid and auto-route are '
            "SR-MPLS only in this release; the SRv6 binding SID is always dynamic). Drop it, "
            "or drop srv6_locator for SR-MPLS."
        )
    if _SRV6_LOCATOR_NAME_MISSING in message:
        return (
            "the srv6 locator container needs its mandatory locator-name: give srv6_locator "
            "(the head-end's SRv6 locator name, e.g. 'LOC1'; NSO does not check it against "
            "the router)."
        )
    if _SRV6_L3NM_NO_AF.search(message):
        return (
            "the L3NM srv6 container needs at least one address-family entry "
            '({"address-family": [{"name": "ietf-vpn-common:ipv4", "locator-name": '
            "...}]}); cnc_create_l3vpn_service's srv6_locator builds it."
        )
    return None


def dry_run_devices(data: Any) -> list[DryRunDevice] | None:
    """``[{device, cli}]`` from ``{"dry-run-result": {"native": {"device": [...]}}}``,
    or None when the body is not a dry-run result."""
    if not isinstance(data, dict) or not isinstance(data.get("dry-run-result"), dict):
        return None
    native = data["dry-run-result"].get("native")
    devices = native.get("device") if isinstance(native, dict) else None
    if not isinstance(devices, list):
        return []
    return [
        DryRunDevice(str(d.get("name") or "?"), str(d.get("data") or "").rstrip())
        for d in devices
        if isinstance(d, dict)
    ]


def _local(name: Any) -> str:
    """``tailf-ncs:init`` -> ``init``; ``...nano-plan-services:head-end`` -> ``head-end``."""
    text = str(name or "")
    return text.rpartition(":")[2] if ":" in text else text


def summarize_plan(data: Any, module: str, list_name: str) -> dict[str, Any] | None:
    """A nano plan GET body -> ``{"status", "components": [...], "failed"?}`` or None.

    Verified plan shape: ``{"<module>:<list>-plan": [{name, plan: {component:
    [{type, name, state: [{name, status, when}], back-track}]}}]}``. ``status``
    is ``failed`` when any state failed, ``ready`` when the ``self`` component
    reached ``ready``, else ``in-progress``. Each component reports its type
    (``self`` / ``head-end``), name, the last state reached, the failed state
    if any, and every state as ``<name>=<status>``.
    """
    entries = unwrap_list(data, module, f"{list_name}-plan")
    if not entries and isinstance(data, dict):
        for key, value in data.items():
            if str(key).endswith("-plan") and isinstance(value, list):
                entries = value
                break
    entry = next((e for e in entries if isinstance(e, dict)), None)
    if entry is None:
        return None
    plan = entry.get("plan") if isinstance(entry.get("plan"), dict) else {}
    components: list[dict[str, Any]] = []
    failed = False
    ready = False
    for comp in plan.get("component") or []:
        if not isinstance(comp, dict):
            continue
        states = [
            {"name": _local(s.get("name")), "status": str(s.get("status") or "")}
            for s in comp.get("state") or []
            if isinstance(s, dict)
        ]
        reached = [s["name"] for s in states if s["status"] == "reached"]
        broken = [s["name"] for s in states if s["status"] == "failed"]
        ctype = _local(comp.get("type"))
        if ctype == "self" and "ready" in reached:
            ready = True
        failed = failed or bool(broken)
        components.append(
            {
                "type": ctype,
                "name": str(comp.get("name") or ""),
                "reached": reached[-1] if reached else None,
                "failed": broken[0] if broken else None,
                "states": [f"{s['name']}={s['status']}" for s in states],
            }
        )
    summary: dict[str, Any] = {
        "status": "failed" if failed else "ready" if ready else "in-progress",
        "components": components,
    }
    if plan.get("failed") is not None:
        summary["failed"] = True
    info = plan.get("error-info")
    if isinstance(info, dict) and info.get("message"):
        summary["error"] = str(info["message"])
    return summary


def plan_line(summary: dict[str, Any] | None, note: str | None = None) -> str:
    """One line describing the plan summary (or why there is none)."""
    if summary is None:
        return f"Plan: {note or 'not available'}."
    parts = []
    for comp in summary["components"]:
        label = comp["type"]
        if comp["name"] and comp["type"] != "self":
            label += f" {comp['name']}"
        parts.append(f"{label}: {', '.join(comp['states']) or 'no states'}")
    text = f"Plan: {summary['status']}"
    if summary.get("error"):
        text += f" ({summary['error']})"
    if parts:
        text += " — " + "; ".join(parts)
    return f"{text}. {plan_layer_note(summary['status'])}"


# NSO nano-plan summary word -> the CAT plan status the services tools report for it.
_CAT_STATUS_OF_NANO = {"ready": "completed", "in-progress": "in-progress", "failed": "failed"}


def plan_layer_note(status: str) -> str:
    """The sentence that keeps the two plan vocabularies apart on the "Plan:" line.

    The line summarises NSO's **nano plan** (component states init /
    config-apply / ready, read through the proxy right after the commit);
    the services tools speak the **CAT plan status** (completed /
    in-progress / delete-in-progress / failed / unknown). Verified live: the
    service the create tool calls "ready" is "completed" in CAT, so the note
    names the CAT equivalent and the target to wait for.
    """
    cat_status = _CAT_STATUS_OF_NANO.get(status, status)
    return (
        f"(NSO nano-plan states; CAT plan status: '{cat_status}' — the vocabulary of "
        "cnc_get_service_plan / cnc_wait_for_service_plan, whose target for a deployed "
        "service is 'completed', with 'ready' accepted as its alias.)"
    )


def outcome_of(method: str, status: int) -> str:
    """``created`` / ``replaced`` / ``merged`` / ``deleted`` from the verified status codes;
    ``accepted (HTTP n)`` for any other 2xx."""
    if method == "PUT" and status == 201:
        return "created"
    if method == "PUT" and status == 204:
        return "replaced"
    if method == "PATCH" and status in (200, 204):
        return "merged"
    if method == "DELETE" and status in (200, 204):
        return "deleted"
    return f"accepted (HTTP {status})"


def outcome_sentence(outcome: str, target: ServiceTarget, method: str, status: int) -> str:
    where = f"{method} .../{target.path} -> {status}"
    if outcome == "created":
        return f"Created {target.label}: NSO committed the service ({where})."
    if outcome == "replaced":
        return (
            f"Replaced {target.label}: it already existed and NSO committed the new definition "
            f"({where}; the PUT is idempotent)."
        )
    if outcome == "merged":
        return f"Updated {target.label}: NSO merged the given leaves and re-deployed ({where})."
    if outcome == "deleted":
        return (
            f"Deleted {target.label}: NSO removed it and any device configuration it rendered "
            f"({where})."
        )
    return f"NSO {outcome} the {method} for {target.label} ({where}); verify the service state."


def dry_run_text(devices: list[DryRunDevice], operation: str, target: ServiceTarget) -> str:
    head = (
        f"Dry run only — nothing was committed. NSO would push this to {operation} {target.label}:"
    )
    if not devices:
        return (
            f"{head}\n\nNo device changes: the rendered configuration already matches what "
            "the devices hold (or the service touches no device)."
        )
    blocks = [f"### {d.device}\n```\n{d.cli or '(empty)'}\n```" for d in devices]
    return head + "\n\n" + "\n\n".join(blocks)


# --- registration ---------------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    client, settings = ctx.client, ctx.settings

    async def send(
        method: str, target: ServiceTarget, body: dict[str, Any] | None, *, dry_run: bool
    ) -> tuple[httpx.Response, Any]:
        """One proxy write. YANG headers on a body, Accept only on a bodiless DELETE
        (the verified live forms); ``?dry-run=native`` when asked. Never raises for a
        non-2xx: the caller maps the RESTCONF error document."""
        response = await client.request(
            method,
            data_url(target.path),
            params=DRY_RUN_PARAMS if dry_run else None,
            json_body=body,
            headers=YANG_HEADERS if body is not None else YANG_ACCEPT,
            raise_on_error=False,
        )
        return response, _json_or_none(response)

    async def read_plan(target: ServiceTarget) -> tuple[dict[str, Any] | None, str | None]:
        """The plan summary after a commit, or ``(None, why)``. Never raises: a missing
        plan is information, not a failure of the write that already happened."""
        path = plan_path_of(target.path)
        if path is None:
            return None, "no plan path for an unkeyed target"
        try:
            response = await client.request(
                "GET", data_url(path), headers=YANG_ACCEPT, raise_on_error=False
            )
        except PlatformError as e:
            return None, f"could not be read ({e})"
        if response.status_code in (204, 404) or not response.content:
            return None, (
                f"not available yet (GET .../{path} -> {response.status_code}); the CFP may "
                f"still be creating it — cnc_get_service_plan(plan_yang_path='{path}', "
                "detail=true) re-reads it"
            )
        if not response.is_success:
            return None, f"could not be read (GET .../{path} -> {response.status_code})"
        module, list_name = list_identity(target.path)
        summary = summarize_plan(_json_or_none(response), module, list_name)
        if summary is None:
            return None, f"GET .../{path} answered 200 without a recognisable plan"
        return summary, None

    async def provision(
        method: str,
        target: ServiceTarget,
        body: dict[str, Any] | None,
        *,
        dry_run: bool,
        operation: str,
        next_hint: str,
    ) -> str:
        """Send, map failures, then render either the dry run or the committed outcome
        (+ plan summary for create/replace/update)."""
        response, data = await send(method, target, body, dry_run=dry_run)
        status = response.status_code
        if not response.is_success:
            precise = explain_write_failure(status, data, method=method, target=target)
            if precise:
                raise PlatformError(precise)
            raise http_error(response)
        if dry_run:
            devices = dry_run_devices(data)
            if devices is None:
                raise PlatformError(
                    f"NSO answered {status} to the dry run but without a dry-run-result "
                    "(nothing was committed: ?dry-run=native never commits). Body: "
                    f"{to_json(data)[:300]}"
                )
            return finalize(dry_run_text(devices, operation, target), settings)
        outcome = outcome_of(method, status)
        lines = [outcome_sentence(outcome, target, method, status)]
        if method != "DELETE":
            summary, note = await read_plan(target)
            line = plan_line(summary, note)
            plan_path = plan_path_of(target.path)
            if plan_path and (summary is None or summary["status"] == "in-progress"):
                line += (
                    f" Wait for it with cnc_wait_for_service_plan(plan_yang_path='{plan_path}')."
                )
            lines.append(line)
        lines.append(f"Next: {next_hint}")
        return finalize("\n".join(lines), settings)

    # --- ODN templates ------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_odn_template",
        title="Create ODN Template (NSO)",
        read_only=False,
        destructive=True,  # a PUT replaces an existing entry of that name wholesale
        idempotent=True,
    )
    async def cnc_create_odn_template(
        name: Annotated[
            str, Field(description=_NAME_DESC.format("mcp-odn-90"), min_length=1, max_length=128)
        ],
        color: Annotated[
            int,
            Field(
                description="The ODN color: prefixes carrying this color community trigger "
                "the on-demand policy (e.g. 90).",
                ge=1,
                le=4294967295,
            ),
        ],
        head_ends: Annotated[
            str,
            Field(
                description="Comma-separated NSO device names that get the template (e.g. "
                "'PE1,PE2'; cnc_list_nso_devices).",
                min_length=1,
                max_length=2000,
            ),
        ],
        metric_type: Annotated[
            str,
            Field(description="Dynamic path metric: igp (default) | te | latency | hopcount."),
        ] = "igp",
        delegate_to_pce: Annotated[
            bool,
            Field(
                description="true (default): the path is computed by the SR-PCE ('pce' under "
                "dynamic); false: the head-end computes it locally."
            ),
        ] = True,
        bandwidth_kbps: Annotated[
            int,
            Field(
                description="Requested bandwidth in kbps; 0 (default) omits it.",
                ge=0,
                le=4294967295,
            ),
        ] = 0,
        maximum_sid_depth: Annotated[
            int,
            Field(
                description="Maximum SID depth for the computed path; 0 (default) omits it.",
                ge=0,
                le=255,
            ),
        ] = 0,
        flex_algo: Annotated[
            int,
            Field(
                description="Flex-Algo number the dynamic path must use (128..255); 0 (default) "
                "omits it.",
                ge=0,
                le=255,
            ),
        ] = 0,
        srv6_locator: Annotated[
            str,
            Field(
                description="SRv6 template: the head-ends' SRv6 locator name (e.g. 'LOC1' — the "
                "name under 'segment-routing srv6 locators' on the routers), sent as "
                "srv6/locator/locator-name; the on-demand policies then get a dynamic SRv6 "
                "binding SID with behavior ub6-insert-reduced. Incompatible with "
                "bandwidth_kbps. Blank (default) = SR-MPLS template.",
                max_length=SRV6_LOCATOR_MAX,
            ),
        ] = "",
        dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = False,
    ) -> str:
        """Create (or replace) an SR-TE On-Demand Next-hop template on one or more head-ends
        through NSO's SR-TE function pack — SR-MPLS, or SRv6 with ``srv6_locator``.

        WRITE / DESTRUCTIVE — only registered when CNC_MCP_ENABLE_WRITES=true;
        destructive because a PUT of a name that already exists replaces that
        entry wholesale (every leaf not in the new body is gone).
        Prefer ``dry_run=true`` first: it returns the exact CLI (``segment-routing
        traffic-eng on-demand color <color> dynamic pce metric type igp ...``)
        without committing, and the function pack's validation runs in it.
        NSO-provisioned (a service with a plan) — there is no Optimization
        Engine equivalent for ODN templates.

        Sends ``PUT /crosswork/proxy/nso/restconf/data/cisco-sr-te-cfp:sr-te/
        cisco-sr-te-cfp-sr-odn:odn/cisco-sr-te-cfp-sr-odn:odn-template=<name>``
        with the verified body ``{"cisco-sr-te-cfp-sr-odn:odn-template": [{"name",
        "color", "head-end": [{"name": ...}], "dynamic": {"metric-type", "pce": {},
        "flex-alg"?}, "bandwidth"?, "maximum-sid-depth"?}]}`` (YANG JSON both
        ways). ``201`` = created, ``204`` = replaced (an existing template of that
        name is overwritten — idempotent re-PUT). Then the plan
        ``.../odn-template-plan=<name>`` is read once and summarised.

        Preconditions: every head-end must be an NSO device and in sync with
        NSO (out-of-band changes break that — ``cnc_nso_device_action(
        action='sync-from', host_name=...)`` fixes it; the 502 error text says
        which device).

        SRv6 (``srv6_locator``; verified 2026-09-15 in dry run through this
        tool — the lab has no SRv6 underlay yet, so the rendering is verified,
        device behaviour is not): the body gains ``"srv6": {"locator":
        {"locator-name": <srv6_locator>}}`` and NSO renders, on every
        head-end (``head_ends='PE1,PE2'``, ``color=601``, ``srv6_locator=
        'LOC1'``)::

            segment-routing
             traffic-eng
              on-demand color 601
               srv6
                locator LOC1 binding-sid dynamic behavior ub6-insert-reduced
               exit
               dynamic
                pce
                exit
                metric
                 type igp
                exit
               exit
              exit

        The on-demand policies get a dynamic SRv6 binding SID with the uSID
        behaviour ``ub6-insert-reduced`` — the model's only values for
        ``binding-sid-type`` / ``behavior``, so nothing else is sent. An ODN
        template has no tail-end, so an SRv6 template needs no IPv6 anywhere;
        ``metric_type``, ``delegate_to_pce``, ``maximum_sid_depth`` and
        ``flex_algo`` work as for SR-MPLS. Rules (each a live ``400`` from the
        CFP, refused here before anything is sent): ``bandwidth_kbps`` is
        incompatible with ``srv6_locator`` (the ODN model's ``bandwidth`` is
        ``when "not(../srv6)"``). An IPv6 ``source-address`` — not an
        argument of this tool; send it with cnc_provision_service — requires
        the srv6 container too ("SRv6 TE policy must be configured if
        source-address is IPv6 address"). NSO does NOT check the locator name
        against the head-ends: a name no router holds renders fine and the
        on-demand policies simply never come up — confirm the locator on the
        head-ends first. The bare presence form ``"srv6": {}`` (no locator:
        the router's default one; dry-run rendered a bare ``srv6`` block,
        device behaviour not verified) is not an argument of this tool —
        send it through cnc_provision_service. Until the lab's SRv6 underlay
        exists nothing beyond the rendering is verified.

        Args:
            name: template (service) name — the NSO list key.
            color: ODN color.
            head_ends: comma-separated NSO device names.
            metric_type, delegate_to_pce, bandwidth_kbps, maximum_sid_depth,
                flex_algo: the dynamic path definition (zeros are omitted).
            srv6_locator: blank (SR-MPLS) or the head-ends' SRv6 locator name
                (e.g. 'LOC1'; 1..64 characters, no whitespace).
            dry_run: preview the device CLI without committing.

        Returns:
            str: the dry-run CLI per device, or "Created|Replaced ODN template
            '<name>' ..." plus a "Plan: ready|in-progress|failed — self: ...;
            head-end PE1: init=reached, config-apply=reached, ready=reached.
            (NSO nano-plan states; CAT plan status: 'completed' ...)" line
            (the nano-plan summary with its CAT-status equivalent — the
            vocabulary cnc_wait_for_service_plan takes) and a "Next:" hint.
            "Error: head-end 'X' is not an NSO
            device", "Error: NSO considers PE1 out of sync — run
            cnc_nso_device_action(...)", "Error: the body has a node the
            model does not know: ...", "Error: the function pack rejected the
            service: <reason> (<code>)", "Error: srv6_locator and
            bandwidth_kbps are incompatible: ..." / "Error: srv6_locator 'X'
            must be an SRv6 locator name of 1..64 characters ..." (nothing
            sent), "Error: bandwidth_kbps is not allowed on an SRv6 policy or
            template ..." / "Error: an IPv6 source-address makes this an SRv6
            ODN template ..." (the CFP's own SRv6 refusals, reachable through
            cnc_provision_service), or "Error: ..." for an invalid argument
            (nothing sent) or another API failure.
        """
        try:
            key = name.strip()
            body = build_odn_template_body(
                key,
                color,
                parse_names(head_ends, "head_ends", "PE1,PE2"),
                _choice(metric_type, METRIC_TYPES, "metric_type"),
                delegate_to_pce,
                bandwidth_kbps,
                maximum_sid_depth,
                _flex_algo(flex_algo),
                srv6_locator,
            )
            target = ServiceTarget("ODN template", key, keyed_path(ODN_TEMPLATE_PATH, key))
            return await provision(
                "PUT",
                target,
                body,
                dry_run=dry_run,
                operation="create",
                next_hint=(
                    f"the head-ends now instantiate an SR policy for every prefix tagged with "
                    f"color {color}; cnc_list_services / cnc_get_service show the template in "
                    "the CAT inventory. Remove it with cnc_delete_odn_template."
                ),
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_odn_template",
        title="Delete ODN Template (NSO)",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_odn_template(
        name: Annotated[
            str, Field(description=_NAME_DESC.format("mcp-odn-90"), min_length=1, max_length=128)
        ],
        dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = False,
    ) -> str:
        """Delete an ODN template: NSO removes the ``on-demand color`` configuration from
        every head-end of the template in one transaction.

        WRITE / DESTRUCTIVE — only registered when CNC_MCP_ENABLE_WRITES=true.
        ``DELETE .../cisco-sr-te-cfp-sr-odn:odn-template=<name>`` (``204`` =
        deleted; ``404`` "uri keypath not found" = no such template).
        ``dry_run=true`` renders the ``no on-demand color ...`` lines instead.
        Policies the template instantiated on the head-ends disappear with it;
        the plan may linger for a moment with ``init not-reached``.

        Args:
            name: the template name (exact).
            dry_run: preview instead of committing.

        Returns:
            str: "Deleted ODN template '<name>' ..." (or the dry-run CLI);
            "Error: no ODN template '<name>'", "Error: NSO considers <device>
            out of sync — ...", or "Error: ..." on another API failure.
        """
        try:
            key = name.strip()
            target = ServiceTarget("ODN template", key, keyed_path(ODN_TEMPLATE_PATH, key))
            return await provision(
                "DELETE",
                target,
                None,
                dry_run=dry_run,
                operation="delete",
                next_hint="cnc_list_services drops the template within seconds.",
            )
        except Exception as e:
            return format_error(e)

    # --- SR policy services ---------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_sr_policy_service",
        title="Create SR Policy Service (NSO)",
        read_only=False,
        destructive=True,  # a PUT replaces an existing entry of that name wholesale
        idempotent=True,
    )
    async def cnc_create_sr_policy_service(
        name: Annotated[
            str, Field(description=_NAME_DESC.format("mcp-pol-91"), min_length=1, max_length=128)
        ],
        head_end: Annotated[
            str,
            Field(
                description="NSO device name of the head-end (e.g. 'PE1'; cnc_list_nso_devices).",
                min_length=1,
                max_length=253,
            ),
        ],
        tail_end: Annotated[
            str,
            Field(
                description="The tail-end's TE router-id — its Loopback0 / topology router-id "
                "(e.g. '10.0.0.3'), NOT its host name and NOT the management address "
                "(cnc_get_topology_node shows router-ids). With srv6_locator: the tail-end's "
                "IPv6 loopback (e.g. '2001:db8::3') — an SRv6 policy needs an IPv6 tail-end; "
                "it is sent canonical (lowercase, compressed: '2001:DB8:0:0::3' becomes "
                "'2001:db8::3', the spelling in the policy name), and a zone id ('%eth0') is "
                "refused.",
                min_length=1,
                max_length=64,
            ),
        ],
        color: Annotated[int, Field(description=_COLOR_DESC, ge=1, le=4294967295)],
        preference: Annotated[
            int,
            Field(description="Candidate-path preference (default 100).", ge=1, le=65535),
        ] = 100,
        path_type: Annotated[
            str,
            Field(
                description="dynamic (default; computed path) | explicit (a SID list named by "
                "sid_list)."
            ),
        ] = "dynamic",
        metric_type: Annotated[
            str,
            Field(description="Dynamic path metric: igp (default) | te | latency | hopcount."),
        ] = "igp",
        delegate_to_pce: Annotated[
            bool,
            Field(
                description="Dynamic path only. true (default): delegated to the SR-PCE ('pce'); "
                "false: computed on the head-end."
            ),
        ] = True,
        sid_list: Annotated[
            str,
            Field(
                description="Explicit path only: name of an existing SID list "
                "(cnc_create_sid_list), e.g. 'mcp-sl-1'.",
                max_length=128,
            ),
        ] = "",
        bandwidth_kbps: Annotated[
            int,
            Field(
                description="Requested bandwidth in kbps; 0 (default) omits it.",
                ge=0,
                le=4294967295,
            ),
        ] = 0,
        binding_sid: Annotated[
            int,
            Field(
                description="Binding SID label (16..1048575, from the head-end's SRLB); 0 "
                "(default) omits it. SR-MPLS only (must be 0 with srv6_locator).",
                ge=0,
                le=MAX_MPLS_LABEL,
            ),
        ] = 0,
        srv6_locator: Annotated[
            str,
            Field(
                description="SRv6 policy: the head-end's SRv6 locator name (e.g. 'LOC1' — the "
                "name under 'segment-routing srv6 locators' on the router), sent as "
                "srv6/locator/locator-name; the binding SID is then dynamic SRv6 with "
                "behavior ub6-insert-reduced. Requires an IPv6 tail_end (e.g. "
                "'2001:db8::3') and path_type='dynamic'; bandwidth_kbps and binding_sid must "
                "stay 0. Blank (default) = SR-MPLS policy (IPv4 tail_end).",
                max_length=SRV6_LOCATOR_MAX,
            ),
        ] = "",
        dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = False,
    ) -> str:
        """Create (or replace) an SR-TE policy as an NSO-provisioned service: NSO configures
        ``policy srte_c_<color>_ep_<tail-end>`` on the head-end — SR-MPLS (IPv4 tail-end)
        or, with ``srv6_locator``, SRv6 (IPv6 tail-end).

        WRITE / DESTRUCTIVE — only registered when CNC_MCP_ENABLE_WRITES=true;
        destructive because a PUT of a name that already exists replaces that
        entry wholesale (every leaf not in the new body is gone).
        Prefer ``dry_run=true`` first: it returns the exact CLI (``segment-routing
        traffic-eng policy srte_c_91_ep_10.0.0.3 / color 91 end-point ipv4
        10.0.0.3 / candidate-paths preference 100 dynamic pce metric type igp``)
        without committing, and CFP validation runs in it.

        NOT the Optimization Engine's ``cnc_create_sr_policy``: that one makes
        the SR-PCE instantiate a policy over PCEP (nothing in the router
        configuration, ``pcep-flag-c: 1``). This tool writes configuration on
        the head-end through NSO — a PCC-initiated policy, delegated to the
        PCE when ``delegate_to_pce`` is true — as a service with a plan, in
        the CAT service inventory, removed with cnc_delete_sr_policy_service
        (the Optimization Engine's delete refuses it). Once PCEP reports it
        the policy appears in cnc_list_sr_policies / cnc_get_sr_policy(
        headend=<head-end router-id>, endpoint=<tail_end>, color=<color>);
        cnc_wait_for_sr_policy_oper_state waits for it to come up.

        Sends ``PUT .../data/cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:
        policies/cisco-sr-te-cfp-sr-policies:policy=<name>`` with the verified
        body ``{"cisco-sr-te-cfp-sr-policies:policy": [{"name", "head-end":
        [{"name": head_end}], "tail-end", "color", "path": [{"preference",
        "dynamic": {"metric-type", "pce": {}}} | {"preference", "explicit":
        {"sid-list": [{"name": sid_list}]}}], "bandwidth"?, "binding-sid"?}]}``.
        ``201`` = created, ``204`` = replaced (same name: the whole entry is
        overwritten). Then ``.../policy-plan=<name>`` is read once.

        Preconditions: the head-end must be an NSO device and in sync with NSO
        (``cnc_nso_device_action(action='sync-from', ...)`` after out-of-band
        changes — the 502 text names the device); an explicit path needs its
        SID list to exist first (cnc_create_sid_list). ``tail_end`` must be an
        IP address (checked before sending) — IPv4 for SR-MPLS, IPv6 for SRv6.

        SRv6 (``srv6_locator``; verified 2026-09-15 in dry run through this
        tool — the lab has no SRv6 underlay yet, so the rendering is verified,
        device behaviour is not): the body gains ``"srv6": {"locator":
        {"locator-name": <srv6_locator>}}`` and NSO renders on the head-end
        (``tail_end='2001:db8::3'``, ``color=600``, ``srv6_locator='LOC1'``)::

            segment-routing
             traffic-eng
              policy srte_c_600_ep_2001:db8::3
               srv6
                locator LOC1 binding-sid dynamic behavior ub6-insert-reduced
               !
               color 600 end-point ipv6 2001:db8::3
               candidate-paths
                preference 100
                 dynamic
                  pce
                  !
                  metric
                   type igp

        (``delegate_to_pce=false`` drops the ``pce`` line; ``metric_type``
        renders as for SR-MPLS.) The policy name keeps the CFP rule
        ``srte_c_<color>_ep_<tail-end>`` — with the colons of the IPv6
        tail-end in it, in its canonical spelling: the tool sends the
        tail-end lowercase and compressed (``'2001:DB8:0:0::3'`` ->
        ``2001:db8::3``, dry-run verified: NSO rendered ``policy
        srte_c_620_ep_2001:db8::3 / end-point ipv6 2001:db8::3`` for that
        input), so the body, the policy name and the "Next:" hint agree; a
        zone id (``%eth0``) is refused. The binding SID is dynamic SRv6 with
        behaviour ``ub6-insert-reduced``: the model's only values for
        ``binding-sid-type`` / ``behavior``, so nothing else is sent. Rules
        of the SR-TE CFP, every one refused here BEFORE anything is sent:
        ``srv6_locator`` needs an IPv6 ``tail_end`` ("tail-end must be IPv6
        address for SRv6 TE policy") and an IPv6 ``tail_end`` needs
        ``srv6_locator`` ("SRv6 TE policy must be configured if tail-end is
        IPv6 address"); ``path_type`` must be ``dynamic`` and
        ``bandwidth_kbps`` / ``binding_sid`` must stay 0 — the explicit
        path, bandwidth and binding-sid are ``when "not(../srv6)"`` (each a
        live ``400``; SR-MPLS only in this release); the YANG puts the same
        when-rule on ``auto-route``, not exercised — no tool sends it.
        ``srv6-dynamic`` is NOT a path type: it is the (only)
        ``binding-sid-type``, applied automatically. The bare presence form
        ``"srv6": {}`` (no locator: the router's default one; dry-run
        rendered a bare ``srv6`` block, device behaviour not verified) is
        not an argument of this tool — send it through cnc_provision_service.
        NSO checks NEITHER the locator name NOR the IPv6 tail-end against the
        head-end or the topology (both existed nowhere on the lab and
        rendered fine): the policy comes up only when the head-end holds
        that locator (``segment-routing srv6 locators``) and reaches the
        tail-end's IPv6 loopback — read the dry run, then check the underlay
        before committing. cnc_update_sr_policy_service cannot add ``srv6``
        (it merges bandwidth / binding-sid only, both refused on an SRv6
        policy); whether a hand-built PATCH of tail-end + srv6 through
        cnc_provision_service converts a committed SR-MPLS policy was NOT
        tested — re-run this tool: the PUT replaces the entry and the CFP
        renames the policy with the new tail-end. Until the lab's SRv6
        underlay exists nothing beyond the rendering is verified.

        Args:
            name: service name (NSO list key).
            head_end: NSO device name.
            tail_end: tail-end TE router-id (IPv4) or, with srv6_locator,
                the tail-end's IPv6 loopback (sent canonical: lowercase,
                compressed; no zone id).
            color, preference: policy color and candidate-path preference.
            path_type: dynamic | explicit (dynamic only with srv6_locator).
            metric_type, delegate_to_pce: the dynamic path.
            sid_list: the explicit path's SID list name.
            bandwidth_kbps, binding_sid: optional leaves (0 = omitted;
                must be 0 with srv6_locator).
            srv6_locator: blank (SR-MPLS) or the head-end's SRv6 locator name
                (e.g. 'LOC1'; 1..64 characters, no whitespace).
            dry_run: preview the device CLI without committing.

        Returns:
            str: the dry-run CLI per device, or "Created|Replaced SR policy
            service '<name>' ..." plus the plan line and a "Next:" hint (for
            an SRv6 policy it names the locator and says NSO checked neither
            it nor the tail-end). "Error: head-end 'X' is not an NSO device",
            "Error: SID list 'N' does not exist", "Error: NSO considers PE1
            out of sync — ...", "Error: path_type='explicit' needs sid_list"
            / "Error: tail_end 'PE2' is not an IP address" / "Error: tail_end
            '2001:db8::3%eth0' carries a zone id ..." / "Error:
            srv6_locator makes this an SRv6 policy, and an SRv6 policy needs
            an IPv6 tail_end ..." / "Error: tail_end '2001:db8::3' is IPv6,
            which makes this an SRv6 policy ...: give srv6_locator" / "Error:
            srv6_locator needs path_type='dynamic' ..." / "Error:
            bandwidth_kbps and binding_sid cannot be set on an SRv6 policy
            ..." / "Error: srv6_locator 'X' must be an SRv6 locator name ..."
            (nothing sent); the CFP's own SRv6 refusals — "Error: an SRv6
            policy ... needs an IPv6 tail-end", "Error: an IPv6 tail-end
            makes this an SRv6 policy ...", "Error: an explicit path ... is
            not allowed on an SRv6 policy or template", "Error: the srv6
            locator container needs its mandatory locator-name" — for bodies
            sent through cnc_provision_service; or "Error: ..." on another
            API failure.
        """
        try:
            key = name.strip()
            # Canonical (IPv6: lowercase, compressed) — what goes on the wire, and the
            # spelling NSO renders into ``srte_c_<color>_ep_<tail-end>`` (dry-run verified).
            tail = require_ip(tail_end, "tail_end")
            body = build_sr_policy_body(
                key,
                head_end.strip(),
                tail,
                color,
                preference,
                _choice(path_type, PATH_TYPES, "path_type"),
                _choice(metric_type, METRIC_TYPES, "metric_type"),
                delegate_to_pce,
                sid_list,
                bandwidth_kbps,
                _binding_sid(binding_sid),
                srv6_locator,
            )
            target = ServiceTarget("SR policy service", key, keyed_path(SR_POLICY_PATH, key))
            if srv6_locator.strip():
                next_hint = (
                    f"the head-end now holds SRv6 policy srte_c_{color}_ep_{tail} with locator "
                    f"{srv6_locator.strip()}; it comes up only when the head-end holds that "
                    "locator and reaches the tail-end's IPv6 loopback (NSO checked neither). "
                    "Once PCEP reports it, cnc_get_sr_policy(headend=<head-end router-id>, "
                    f"endpoint='{tail}', color={color}) shows it and "
                    "cnc_wait_for_sr_policy_oper_state waits for UP. To change the locator, "
                    "re-run this tool (the PUT replaces the entry); remove with "
                    "cnc_delete_sr_policy_service."
                )
            else:
                next_hint = (
                    f"the head-end now holds policy srte_c_{color}_ep_{tail}; once PCEP "
                    "reports it, cnc_get_sr_policy(headend=<head-end router-id>, "
                    f"endpoint='{tail}', color={color}) shows it and "
                    "cnc_wait_for_sr_policy_oper_state waits for UP. Change bandwidth / "
                    "binding-sid with cnc_update_sr_policy_service; remove with "
                    "cnc_delete_sr_policy_service."
                )
            return await provision(
                "PUT", target, body, dry_run=dry_run, operation="create", next_hint=next_hint
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_sr_policy_service",
        title="Update SR Policy Service (NSO)",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_update_sr_policy_service(
        name: Annotated[
            str, Field(description=_NAME_DESC.format("mcp-pol-91"), min_length=1, max_length=128)
        ],
        bandwidth_kbps: Annotated[
            int,
            Field(
                description="New requested bandwidth in kbps; 0 (default) leaves it alone.",
                ge=0,
                le=4294967295,
            ),
        ] = 0,
        binding_sid: Annotated[
            int,
            Field(
                description="New binding SID label (16..1048575); 0 (default) leaves it alone.",
                ge=0,
                le=MAX_MPLS_LABEL,
            ),
        ] = 0,
        dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = False,
    ) -> str:
        """Merge new bandwidth and/or binding-SID leaves into an existing NSO-provisioned SR
        policy service (``PATCH`` = merge; the path, head-end, tail-end and color stay).

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        ``PATCH .../cisco-sr-te-cfp-sr-policies:policy=<name>`` with
        ``{"cisco-sr-te-cfp-sr-policies:policy": [{"name", "bandwidth"?,
        "binding-sid"?}]}`` — verified live with ``bandwidth`` (``204``). NSO
        re-deploys the policy on the head-end. To change anything else,
        re-create with cnc_create_sr_policy_service (a PUT replaces the entry).
        Not the Optimization Engine's cnc_update_sr_policy (PCE-initiated
        policies). ``dry_run=true`` renders the CLI delta instead.

        SR-MPLS only. Both leaves are ``when "not(../srv6)"`` in the SR-TE
        CFP model, so a PATCH of either onto an SRv6 policy (one created with
        ``srv6_locator``) is refused by the CFP with ``400 malformed-message
        ".../<leaf>: the 'when' expression \\"not(../srv6)\\" failed"``
        (verified 2026-09-15 in dry run on a PUT carrying the same leaves;
        reported as "Error: bandwidth_kbps|binding_sid is not allowed on an
        SRv6 policy or template ..."). This tool only merges bandwidth /
        binding-sid: it cannot add ``srv6`` or change the tail-end. Whether
        a hand-built PATCH of ``tail-end`` + ``srv6`` through
        cnc_provision_service converts a committed SR-MPLS policy into an
        SRv6 one was NOT tested (no committed policy to merge into; commits
        were not allowed) — the supported path is re-running
        cnc_create_sr_policy_service: the PUT replaces the entry and the CFP
        renames the policy ``srte_c_<color>_ep_<tail-end>`` with the new
        tail-end. What IS verified (2026-09-15, dry run): a PATCH never
        creates — ``404 invalid-value "patch to a nonexistent resource"``
        for an unknown name.

        Args:
            name: service name (exact).
            bandwidth_kbps, binding_sid: the leaves to merge (at least one
                non-zero, else nothing is sent).
            dry_run: preview instead of committing.

        Returns:
            str: "Updated SR policy service '<name>' ..." plus the plan line
            (or the dry-run CLI); "Error: Nothing to update: ..." (nothing
            sent); "Error: no SR policy service '<name>'" on the verified 404
            ("patch to a nonexistent resource"); "Error: bandwidth_kbps is not
            allowed on an SRv6 policy or template ..." (the CFP's when-rule on
            an SRv6 policy); "Error: NSO considers PE1 out of sync — ...";
            "Error: ..." on another API failure.
        """
        try:
            key = name.strip()
            body = build_sr_policy_patch(key, bandwidth_kbps, _binding_sid(binding_sid))
            target = ServiceTarget("SR policy service", key, keyed_path(SR_POLICY_PATH, key))
            return await provision(
                "PATCH",
                target,
                body,
                dry_run=dry_run,
                operation="update",
                next_hint="cnc_get_sr_policy shows the policy as the head-end now reports it.",
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_sr_policy_service",
        title="Delete SR Policy Service (NSO)",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_sr_policy_service(
        name: Annotated[
            str, Field(description=_NAME_DESC.format("mcp-pol-91"), min_length=1, max_length=128)
        ],
        dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = False,
    ) -> str:
        """Delete an NSO-provisioned SR policy service: NSO removes ``policy
        srte_c_<color>_ep_<tail-end>`` from the head-end.

        WRITE / DESTRUCTIVE — only registered when CNC_MCP_ENABLE_WRITES=true.
        ``DELETE .../cisco-sr-te-cfp-sr-policies:policy=<name>`` (``204`` =
        deleted; ``404`` = no such service). Delete the policy BEFORE its SID
        list (cnc_delete_sid_list refuses a referenced list). Not for
        PCE-initiated policies — those are cnc_delete_sr_policy (Optimization
        Engine). ``dry_run=true`` renders the ``no policy ...`` lines instead.
        The plan may linger briefly with ``init not-reached`` after the delete.

        Args:
            name: service name (exact).
            dry_run: preview instead of committing.

        Returns:
            str: "Deleted SR policy service '<name>' ..." (or the dry-run
            CLI); "Error: no SR policy service '<name>'", "Error: NSO considers
            <device> out of sync — ...", or "Error: ..." on another failure.
        """
        try:
            key = name.strip()
            target = ServiceTarget("SR policy service", key, keyed_path(SR_POLICY_PATH, key))
            return await provision(
                "DELETE",
                target,
                None,
                dry_run=dry_run,
                operation="delete",
                next_hint=(
                    "the policy leaves cnc_list_sr_policies once PCEP reports its withdrawal; "
                    "a SID list it referenced can now be deleted (cnc_delete_sid_list)."
                ),
            )
        except Exception as e:
            return format_error(e)

    # --- SID lists ------------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_sid_list",
        title="Create SID List (NSO)",
        read_only=False,
        destructive=True,  # a PUT replaces an existing entry of that name wholesale
        idempotent=True,
    )
    async def cnc_create_sid_list(
        name: Annotated[
            str, Field(description=_NAME_DESC.format("mcp-sl-1"), min_length=1, max_length=128)
        ],
        labels: Annotated[
            str,
            Field(
                description="Comma-separated MPLS labels in path order, e.g. '16003,16002' "
                "(node prefix-SIDs from cnc_get_topology_node; 0..1048575 each).",
                min_length=1,
                max_length=4000,
            ),
        ],
        dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = False,
    ) -> str:
        """Create (or replace) a named SID list for explicit SR policy paths.

        WRITE / DESTRUCTIVE — only registered when CNC_MCP_ENABLE_WRITES=true;
        destructive because a PUT of a name that already exists replaces that
        entry wholesale (every leaf not in the new body is gone).
        ``PUT .../cisco-sr-te-cfp-sr-policies:sid-list=<name>`` with the
        verified body ``{"cisco-sr-te-cfp-sr-policies:sid-list": [{"name",
        "sid": [{"index": 1, "mpls": {"label": 16003}}, {"index": 2, ...}]}]}``
        (indices 1-based in the given order). ``201`` = created, ``204`` =
        replaced. The list is NSO data only until a policy's explicit path
        references it (cnc_create_sr_policy_service with path_type='explicit',
        sid_list=<name>) — that policy's dry run renders ``segment-list <name>
        / index 1 mpls label 16003 ...`` on the head-end. Delete order: the
        policy first, then the list (cnc_delete_sid_list). A dry run of the
        list itself usually shows no device change.

        Args:
            name: SID list name.
            labels: comma-separated labels in path order.
            dry_run: preview instead of committing.

        Returns:
            str: "Created|Replaced SID list '<name>' ..." plus the plan line
            (SID lists have no plan on this CFP — "Plan: not available" is
            expected), or the dry-run result; "Error: labels: ..." (nothing
            sent) or "Error: ..." on an API failure.
        """
        try:
            key = name.strip()
            body = build_sid_list_body(key, parse_labels(labels))
            target = ServiceTarget("SID list", key, keyed_path(SID_LIST_PATH, key))
            return await provision(
                "PUT",
                target,
                body,
                dry_run=dry_run,
                operation="create",
                next_hint=(
                    f"reference it with cnc_create_sr_policy_service(path_type='explicit', "
                    f"sid_list='{key}', ...)."
                ),
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_sid_list",
        title="Delete SID List (NSO)",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_sid_list(
        name: Annotated[
            str, Field(description=_NAME_DESC.format("mcp-sl-1"), min_length=1, max_length=128)
        ],
        dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = False,
    ) -> str:
        """Delete a SID list (``DELETE .../cisco-sr-te-cfp-sr-policies:sid-list=<name>``).

        WRITE / DESTRUCTIVE — only registered when CNC_MCP_ENABLE_WRITES=true.
        Ordering rule (verified live): a SID list still referenced by a
        policy's explicit path cannot be deleted — NSO answers ``400
        invalid-value "illegal reference .../explicit/sid-list{<name>}/name"``,
        reported as "Error: SID list <name> is still referenced by a policy —
        delete the policy first". ``204`` = deleted; ``404`` = no such list.

        Args:
            name: SID list name (exact).
            dry_run: preview instead of committing.

        Returns:
            str: "Deleted SID list '<name>' ..." (or the dry-run result);
            "Error: SID list <name> is still referenced by a policy — delete
            the policy first ...", "Error: no SID list '<name>'", or
            "Error: ..." on another failure.
        """
        try:
            key = name.strip()
            target = ServiceTarget("SID list", key, keyed_path(SID_LIST_PATH, key))
            return await provision(
                "DELETE",
                target,
                None,
                dry_run=dry_run,
                operation="delete",
                next_hint="nothing else to do; the list was NSO data only.",
            )
        except Exception as e:
            return format_error(e)

    # --- L3VPN / VPN services -------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_l3vpn_service",
        title="Create L3VPN Service (NSO)",
        read_only=False,
        destructive=True,  # a PUT replaces an existing entry of that name wholesale
        idempotent=True,
    )
    async def cnc_create_l3vpn_service(
        vpn_id: Annotated[
            str,
            Field(
                description="The L3NM vpn-id — service name and NSO list key (e.g. 'mcp-l3vpn-1').",
                min_length=1,
                max_length=128,
            ),
        ],
        route_distinguisher: Annotated[
            str,
            Field(
                description="The VRF's route distinguisher (e.g. '0:65091:91').",
                min_length=1,
                max_length=64,
            ),
        ],
        route_target: Annotated[
            str,
            Field(
                description="The route target, imported AND exported (type 'both'), e.g. "
                "'0:65091:91'.",
                min_length=1,
                max_length=64,
            ),
        ],
        endpoints: Annotated[
            str,
            Field(
                description='JSON list of PE attachments: [{"node": "PE1" (NSO device name), '
                '"interface": "Loopback91", "address": "10.91.1.1", "prefix_length": 30, '
                '"local_as": 65000 (optional), "id": "1" (optional access id), '
                '"srv6_locator": "LOC1" (optional: this node\'s SRv6 locator, overriding the '
                "service-wide srv6_locator)}, ...].",
                min_length=2,
                max_length=20000,
            ),
        ],
        topology: Annotated[
            str,
            Field(description="VPN service topology: any-to-any (default) | hub-spoke | custom."),
        ] = "any-to-any",
        profile_id: Annotated[
            str,
            Field(
                description="Name of the single vpn-instance-profile (default 'p1').",
                min_length=1,
                max_length=64,
            ),
        ] = "p1",
        srv6_locator: Annotated[
            str,
            Field(
                description="SRv6 transport for the VPN: the SRv6 locator name every PE uses for "
                "the VRF's per-VRF SIDs (e.g. 'LOC1'), set service-wide on the "
                'vpn-instance-profile; an endpoint\'s own "srv6_locator" key overrides it '
                "for that node. Blank (default) = MPLS transport (no srv6 container).",
                max_length=SRV6_LOCATOR_MAX,
            ),
        ] = "",
        dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = False,
    ) -> str:
        """Create (or replace) an IPv4 L3VPN through NSO's L3NM function pack: one VRF
        (rd + route-target) on each endpoint's PE with one interface attached per endpoint —
        over MPLS, or over SRv6 with ``srv6_locator``.

        WRITE / DESTRUCTIVE — only registered when CNC_MCP_ENABLE_WRITES=true;
        destructive because a PUT of a name that already exists replaces that
        entry wholesale (every leaf not in the new body is gone).
        Prefer ``dry_run=true`` first — it renders the ``vrf <vpn-id> / rd /
        address-family ipv4 unicast / import|export route-target`` and interface
        CLI per PE without committing, and the CFP validates the service in it.

        Sends ``PUT .../data/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=
        <vpn_id>`` with the verified L3NM body ``{"ietf-l3vpn-ntw:vpn-service":
        [{"vpn-id", "vpn-service-topology": "ietf-vpn-common:<topology>",
        "vpn-instance-profiles": {"vpn-instance-profile": [{"profile-id", "rd",
        "address-family": [{"address-family": "ietf-vpn-common:ipv4",
        "vpn-targets": {"vpn-target": [{"id": 1, "route-targets":
        [{"route-target"}], "route-target-type": "both"}]}}]}]}, "vpn-nodes":
        {"vpn-node": [{"vpn-node-id": <NSO device>, "local-as"?,
        "active-vpn-instance-profiles": {"vpn-instance-profile": [{"profile-id"}]},
        "vpn-network-accesses": {"vpn-network-access": [{"id", "interface-id",
        "ip-connection": {"ipv4": {"local-address", "prefix-length"}}}]}}]}}]}``.
        Endpoints on the same node become one ``vpn-node`` with several
        accesses. ``201`` = created, ``204`` = replaced; then the plan
        ``.../vpn-service-plan=<vpn_id>`` is read once.

        BGP (verified live in dry-run): with ``local_as`` on the endpoints the
        CFP renders ``router bgp <as> / vrf <vpn_id> / rd ...`` itself, creating
        the BGP process on a PE that has none; WITHOUT ``local_as`` the PE must
        already run BGP or the CFP answers ``TSDN-L3VPN-415 "BGP routing
        process is not configured on the device"`` (reported as "Error: the
        function pack rejected the service: ... (TSDN-L3VPN-415) — the head-end
        has no BGP routing process: give local_as ..."). Always give local_as
        unless the PEs already run BGP. The rendered VRF carries an extra
        auto-allocated route-target (``1:1`` on the lab) from the CFP's RT pool
        beside the ones given — check the dry run. Cleanup: cnc_delete_vpn_service
        removes the VRF, the interface's VRF membership and the BGP VRF
        stanza, but leaves the ``router bgp <as>`` process on the PE
        (verified in dry run on PEs whose process pre-existed; unverified
        for a process the CFP created itself). The PEs must also be NSO
        devices in sync with NSO: the
        deviated L3NM makes ``vpn-node-id`` a leafref into NSO's device
        dispatch-map, so an unknown ``endpoints[].node`` is ``400 invalid-value
        "illegal reference .../vpn-nodes/vpn-node{X}/vpn-node-id"`` (reported
        as "Error: vpn-node 'X' is not an NSO device").

        SRv6 transport (``srv6_locator``; verified 2026-09-15 in dry run
        through this tool — the lab has no SRv6 underlay yet, so the
        rendering is verified, device behaviour is not): the profile gains
        ``"cisco-l3vpn-ntw:srv6": {"address-family": [{"name":
        "ietf-vpn-common:ipv4", "locator-name": <srv6_locator>}]}`` (the list
        mirrors this tool's single ipv4 address-family; the CFP silently
        ignores an entry for an address-family the profile lacks), and an
        endpoint's own ``"srv6_locator"`` puts the same container on that
        node's ``active-vpn-instance-profiles`` entry — the node-level entry
        wins over the service-wide one for that PE (verified: profile LOC1 +
        PE2 override LOC2 rendered LOC1 on PE1 and LOC2 on PE2; a node-level
        entry alone leaves the other PEs without any srv6 block). The whole
        rendering delta is one block inside the BGP VRF address-family — the
        VRF, interface and ``router bgp`` lines are exactly the MPLS ones::

            router bgp 65000
             vrf <vpn_id>
              rd 65091:91
              address-family ipv4 unicast
               segment-routing srv6
                locator LOC1
                alloc mode per-vrf

        ``alloc mode per-vrf`` is fixed by the CFP (no per-CE knob in the
        model). Give ``local_as`` on the endpoints as for MPLS — the block
        lives under the BGP VRF, which the CFP renders only then (or when the
        PE already runs BGP). NSO does NOT check the locator name against the
        PEs (``LOC1`` existed nowhere on the lab and rendered fine): the VRF's
        SRv6 SIDs are allocated only once the PE holds that locator
        (``segment-routing srv6 locators``) — confirm it before committing.
        The flat ``{"locator-name": ...}`` shape the SR-TE CFP uses is ``400
        unknown-element`` on the L3NM (the tool never sends it). Until the
        lab's SRv6 underlay exists nothing beyond the rendering is verified.

        This tool covers the minimal verified shape. For the full L3NM (BGP
        CE peering ``routing-protocols``, ``connection.encapsulation`` with a
        dot1q VLAN, ``service.mtu``/QoS, IPv6 / dual-stack — ``ip-connection.
        ipv6 {local-address, prefix-length}`` plus an ipv6 address-family in
        the profile, with an ipv6 entry in the srv6 address-family list for
        SRv6 (dry-run verified), multicast) build the body yourself and send
        it with cnc_provision_service.

        Args:
            vpn_id: service name / NSO key.
            route_distinguisher, route_target: RD and RT (RT type both).
            endpoints: JSON list (see the parameter description) — invalid
                JSON or a missing key is refused before anything is sent;
                an endpoint's optional "srv6_locator" is that node's locator.
            topology: any-to-any | hub-spoke | custom.
            profile_id: the vpn-instance-profile name.
            srv6_locator: blank (MPLS transport) or the service-wide SRv6
                locator name (e.g. 'LOC1'; 1..64 characters, no whitespace).
            dry_run: preview the device CLI without committing.

        Returns:
            str: the dry-run CLI per PE, or "Created|Replaced L3VPN service
            '<vpn_id>' ..." plus the plan line; "Error: endpoints ..." /
            "Error: Unknown topology ..." / "Error: srv6_locator 'X' must be
            an SRv6 locator name ..." / "Error: endpoints on node 'PE1' give
            different srv6_locator values ..." (nothing sent), "Error: the
            function pack rejected the service: ...", "Error: vpn-node 'X'
            is not an NSO device" (an unknown endpoints[].node), "Error: NSO
            considers PE1 out of sync — ...", "Error: the body has a node the
            model does not know: ...", "Error: the L3NM srv6 container needs
            at least one address-family entry ..." (an empty srv6 container
            sent through cnc_provision_service), or "Error: ..." on another
            failure.
        """
        try:
            key = vpn_id.strip()
            body = build_l3vpn_body(
                key,
                route_distinguisher.strip(),
                route_target.strip(),
                parse_endpoints(endpoints),
                _choice(topology, TOPOLOGIES, "topology"),
                profile_id.strip(),
                srv6_locator,
            )
            target = ServiceTarget("L3VPN service", key, keyed_path(L3VPN_SERVICE_PATH, key))
            next_hint = (
                f"cnc_get_vpn_service(vpn_id='{key}') / cnc_get_vpn_service_health show "
                "the VPN and its oper-status from the CAT inventory; remove it with "
                "cnc_delete_vpn_service(layer='l3')."
            )
            if _l3vpn_uses_srv6(body):
                next_hint = (
                    "the VRF is bound to SRv6 (segment-routing srv6 / locator / alloc mode "
                    "per-vrf under its BGP address-family); its SIDs are allocated only where "
                    "the PE holds that locator (NSO checked nothing). "
                ) + next_hint
            return await provision(
                "PUT", target, body, dry_run=dry_run, operation="create", next_hint=next_hint
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_vpn_service",
        title="Delete VPN Service (NSO)",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_vpn_service(
        vpn_id: Annotated[
            str,
            Field(
                description="The vpn-id of the L3NM / L2NM service (e.g. 'mcp-l3vpn-1').",
                min_length=1,
                max_length=128,
            ),
        ],
        layer: Annotated[
            str,
            Field(description="l3 (default; ietf-l3vpn-ntw) | l2 (ietf-l2vpn-ntw)."),
        ] = "l3",
        dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = False,
    ) -> str:
        """Delete an L3VPN or L2VPN service: NSO removes the VRF / bridge domain and the
        attachment configuration from every PE of the service in one transaction.

        WRITE / DESTRUCTIVE — only registered when CNC_MCP_ENABLE_WRITES=true.
        ``DELETE .../data/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=
        <vpn_id>`` (or ``ietf-l2vpn-ntw:l2vpn-ntw/...`` for layer l2). ``204``
        = deleted; ``404`` = no such service. ``dry_run=true`` renders the
        ``no ...`` lines instead. The plan may linger for a moment.

        What an L3VPN delete removes — and what it leaves (verified live
        2026-09-14, dry-run delete of an L3VPN created by
        cnc_create_l3vpn_service with ``local_as`` between PE1 and PE2): on
        each PE NSO renders the reverse of what the service rendered — the
        VRF (``no vrf <vpn_id>``), the attachment interface's VRF membership
        (the loopback's ``vrf <vpn_id>`` line) and the BGP VRF stanza
        (``router bgp <as> / no vrf <vpn_id>``). **The ``router bgp <as>``
        process itself is NOT removed**: the dry run enters ``router bgp
        65000`` only to remove ``vrf <vpn_id>``, and the process, its
        address-families and neighbors stay on the PE. That was verified on
        PEs whose ``router bgp 65000`` pre-existed the service (the lab's
        state since 2026-09-14); whether a process the CFP rendered itself
        for a PE that had none (the ``local_as`` case of
        cnc_create_l3vpn_service) is taken back with the service has NOT been
        verified — run ``dry_run=true`` first and read the CLI: everything
        the delete will push is in it, and anything it does not list stays.
        To prove the residue on the PE, take a backup
        (cnc_backup_device_config, then cnc_wait_for_config_backup_job) and
        read it with cnc_get_device_backup — the stored running configuration
        (secrets masked); NSO's copy is reachable through the proxy (``GET
        data/tailf-ncs:devices/device=<name>/config/...``) but is not exposed
        as a tool.

        Args:
            vpn_id: the service's vpn-id (exact).
            layer: l3 | l2.
            dry_run: preview instead of committing.

        Returns:
            str: "Deleted L3VPN|L2VPN service '<vpn_id>' ..." (or the dry-run
            CLI); "Error: no L3VPN service '<vpn_id>'", "Error: NSO considers
            <device> out of sync — ...", or "Error: ..." on another failure.
        """
        try:
            key = vpn_id.strip()
            which = _choice(layer, VPN_LAYERS, "layer")
            list_path = L3VPN_SERVICE_PATH if which == "l3" else L2VPN_SERVICE_PATH
            target = ServiceTarget(f"{which.upper()}VPN service", key, keyed_path(list_path, key))
            return await provision(
                "DELETE",
                target,
                None,
                dry_run=dry_run,
                operation="delete",
                next_hint="cnc_list_vpn_services drops the service within seconds.",
            )
        except Exception as e:
            return format_error(e)

    # --- generic escape hatch ---------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_provision_service",
        title="Provision Service (any T-SDN model, NSO)",
        read_only=False,
        destructive=True,  # a PUT replaces an existing entry of that name wholesale
        idempotent=True,
    )
    async def cnc_provision_service(
        yang_path: Annotated[
            str,
            Field(
                description="The keyed service path relative to the NSO proxy's data/ root, e.g. "
                "'ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service=mcp-l2vpn-1' or "
                "'cisco-cs-sr-te-cfp:cs-sr-te-policy=mcp-cs-1' (a leading '/', 'data/' or the "
                "full proxy prefix is tolerated; percent-encode '/' inside a key).",
                min_length=1,
                max_length=2000,
            ),
        ],
        body_json: Annotated[
            str,
            Field(
                description="The RESTCONF instance body as JSON: one module-prefixed top-level "
                "key whose value is a one-item list, e.g. "
                '{"cisco-cs-sr-te-cfp:cs-sr-te-policy": [{"name": "mcp-cs-1", ...}]}.',
                min_length=2,
                max_length=200000,
            ),
        ],
        method: Annotated[
            str,
            Field(
                description="put (default; create or replace the whole entry) | patch (merge "
                "the given leaves)."
            ),
        ] = "put",
        dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = False,
    ) -> str:
        """Provision ANY T-SDN function-pack service through the NSO proxy from a body you
        build yourself — the escape hatch for models the dedicated tools do not cover.

        WRITE / DESTRUCTIVE — only registered when CNC_MCP_ENABLE_WRITES=true;
        destructive because a PUT of a name that already exists replaces that
        entry wholesale (every leaf not in the new body is gone).
        Use it for L2VPN (``ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service=
        <id>``, body key ``ietf-l2vpn-ntw:vpn-service``), circuit-style SR-TE
        (``cisco-cs-sr-te-cfp:cs-sr-te-policy=<name>``), network slices
        (``ietf-network-slice-service:network-slice-services/slice-service=
        <id>``), routing policies, or a full L3NM body (BGP CE peering,
        encapsulation, QoS) beyond cnc_create_l3vpn_service — all installed
        on this NSO (verified: the containers exist), only the SR-TE and L3NM
        shapes were committed live. Workflow: build the body from the YANG
        as NSO serves it (``GET data/ietf-yang-library:modules-state`` then
        the schema URL — the Cisco deviations remove RFC nodes, which answer
        ``400 unknown-element``), run it with ``dry_run=true`` until the CLI
        looks right, then commit.

        Sends ``PUT`` (create/replace: ``201``/``204``) or ``PATCH`` (merge:
        ``204``) to ``/crosswork/proxy/nso/restconf/data/<yang_path>`` with
        YANG JSON both ways. The path and body are checked client-side before
        anything is sent: the path must be keyed (``.../<list>=<key>`` — a
        PUT to the bare list would replace EVERY entry of that list in one
        commit, so an unkeyed path is refused, exactly as cnc_delete_service
        refuses one); the body a JSON object with exactly one module-prefixed
        key (``<module>:<list>``) whose value is a list of exactly one object,
        the key's list name matching the path's last segment. After a commit
        the plan at ``<list>-plan=<key>`` is read once (not every model keeps
        a plan — "Plan: not available" is normal for those).

        Args:
            yang_path: data/-relative keyed path.
            body_json: the instance body.
            method: put | patch.
            dry_run: preview the device CLI without committing.

        Returns:
            str: the dry-run CLI per device, or "Created|Replaced|Updated
            service '<key>' ..." plus the plan line; "Error: body_json ..."
            / "Error: yang_path '<p>' has no key: ..." / "Error: yang_path
            ..." (nothing sent); the precise texts for the verified failures
            (unknown head-end, out of sync, unknown element, TSDN-*
            validation) or "Error: ..." otherwise.
        """
        try:
            path = normalize_yang_path(yang_path)
            verb = _choice(method, WRITE_METHODS, "method").upper()
            _key, body = validate_service_body(body_json, path)
            name = key_of(path)
            if name is None:
                raise PlatformError(
                    f"yang_path '{path}' has no key: this tool writes one service entry "
                    "('<list>=<key>'), never a whole list — a PUT to the bare list would "
                    "replace every entry in it."
                )
            target = ServiceTarget(generic_kind(path), name, path)
            return await provision(
                verb,
                target,
                body,
                dry_run=dry_run,
                operation="create" if verb == "PUT" else "update",
                next_hint=(
                    "cnc_get_service / cnc_list_services read it back from the CAT inventory; "
                    f"remove it with cnc_delete_service(yang_path='{path}')."
                ),
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_service",
        title="Delete Service (any T-SDN model, NSO)",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_service(
        yang_path: Annotated[
            str,
            Field(
                description="The keyed service path relative to the NSO proxy's data/ root, e.g. "
                "'cisco-cs-sr-te-cfp:cs-sr-te-policy=mcp-cs-1'.",
                min_length=1,
                max_length=2000,
            ),
        ],
        dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = False,
    ) -> str:
        """Delete ANY T-SDN service entry through the NSO proxy by its data path.

        WRITE / DESTRUCTIVE — only registered when CNC_MCP_ENABLE_WRITES=true.
        ``DELETE /crosswork/proxy/nso/restconf/data/<yang_path>`` (``204`` =
        deleted; ``404`` "uri keypath not found" = nothing there). NSO removes
        the service's configuration from every device it touched in one
        transaction — a keyed path is required (the tool refuses to delete a
        whole list or container). ``dry_run=true`` renders the ``no ...``
        lines instead. Ordering rules apply (a policy before its SID list).

        Args:
            yang_path: data/-relative keyed path.
            dry_run: preview instead of committing.

        Returns:
            str: "Deleted <list> service '<key>' ..." (or the dry-run CLI);
            "Error: no <list> service '<key>'", "Error: SID list N is still
            referenced ...", "Error: NSO considers <device> out of sync", or
            "Error: ..." otherwise.
        """
        try:
            path = normalize_yang_path(yang_path)
            name = key_of(path)
            if name is None:
                raise PlatformError(
                    f"yang_path '{path}' has no key: this tool deletes one service entry "
                    "('<list>=<key>'), never a whole list or container."
                )
            target = ServiceTarget(generic_kind(path), name, path)
            return await provision(
                "DELETE",
                target,
                None,
                dry_run=dry_run,
                operation="delete",
                next_hint="cnc_list_services drops the entry within seconds.",
            )
        except Exception as e:
            return format_error(e)

    # --- CAT NSO-connector resync -----------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_resync_service_inventory",
        title="Resync Service Inventory from NSO",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_resync_service_inventory(
        service_type: Annotated[
            str,
            Field(
                description=f"Limit the resync to one CAT service type: {_SERVICE_TYPE_CHOICES} "
                "(a CAT QName '{ns}local' or a raw NSO list path also works). Blank (default) "
                "= full resync of every type.",
                max_length=500,
            ),
        ] = "",
        service_name: Annotated[
            str,
            Field(
                description="With service_type: resync only this service instance (its NSO "
                "key, e.g. 'mcp-l3vpn-1').",
                max_length=256,
            ),
        ] = "",
        force: Annotated[
            bool,
            Field(
                description="Force the resync even when the connector believes the inventory "
                "is current (full and type resync only)."
            ),
        ] = False,
    ) -> str:
        """Ask the CAT NSO-connector to re-read services from NSO into Crosswork's service
        inventory (the source of the services module's list/count/plan data).

        WRITE operation (it rewrites Crosswork's inventory, not NSO or devices)
        — only registered when CNC_MCP_ENABLE_WRITES=true. Use it when the
        service inventory disagrees with NSO — a service provisioned directly
        in NSO not showing up, a stale plan status. Normally unnecessary: the
        inventory reflected every service committed here within seconds
        (verified live).

        UNVERIFIED LIVE — from the 7.2 document ``nso_connector_service_ap_is_
        7_2_0.json``: ``POST /crosswork/cat/nso-connector/v1/api/fullResync?
        force=<bool>`` (no service_type), ``.../typeResync?typePath=<path>&
        force=<bool>`` (service_type only), ``.../serviceResync?typePath=<path>
        &serviceName=<name>`` (both); query parameters, empty body, plain JSON.
        The documented reply is ``{"syncResponse": {"syncDescription": "...",
        "syncStatus": "SUCCESS"}, "status": "OK"}`` — the sync itself runs in
        the background. Type labels map to NSO list paths (``policy`` ->
        ``cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy``,
        ``ietf-l3vpn`` -> ``ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service``
        ...); ``tunnel`` -> ``ietf-te:te/tunnels/tunnel`` is a guess.

        Args:
            service_type: blank | a type label / QName / raw type path.
            service_name: one service (needs service_type).
            force: force flag for full/type resync.

        Returns:
            str: JSON {"scope": "full"|"type"|"service", "type_path"?,
            "service_name"?, "force"?, "sync_status", "description",
            "status", "note": "unverified live ..."}. "Error: service_name
            needs service_type" / "Error: Unknown service_type ..." (nothing
            sent); "Error: the NSO-connector reported <status>: <description>"
            when syncStatus is not SUCCESS; "Error: ..." on an API failure
            (a bare 404 = the nso-connector API is not routed on this build).
        """
        try:
            type_text = service_type.strip()
            name = service_name.strip()
            if name and not type_text:
                raise PlatformError(
                    "service_name needs service_type: say which type the service belongs to "
                    f"(one of {_SERVICE_TYPE_CHOICES})."
                )
            result: dict[str, Any] = {}
            if not type_text:
                url, params = FULL_RESYNC_URL, {"force": str(force).lower()}
                result["scope"] = "full"
                result["force"] = force
            else:
                type_path = resolve_type_path(type_text)
                result["type_path"] = type_path
                if name:
                    url, params = SERVICE_RESYNC_URL, {"typePath": type_path, "serviceName": name}
                    result["scope"] = "service"
                    result["service_name"] = name
                else:
                    url = TYPE_RESYNC_URL
                    params = {"typePath": type_path, "force": str(force).lower()}
                    result["scope"] = "type"
                    result["force"] = force
            data = await client.request_json("POST", url, params=params)
            if isinstance(data, str):  # the document types the reply as a JSON string
                try:
                    data = json.loads(data)
                except ValueError:
                    data = {"syncResponse": {"syncDescription": data}}
            sync = data.get("syncResponse") if isinstance(data, dict) else None
            sync = sync if isinstance(sync, dict) else {}
            status = str(sync.get("syncStatus") or "").strip()
            description = str(sync.get("syncDescription") or "").strip()
            if status.upper() != RESYNC_SUCCESS:
                raise PlatformError(
                    f"the NSO-connector reported {status or 'no syncStatus'}: "
                    f"{description or to_json(data)[:300]}"
                )
            result.update(
                {
                    "sync_status": status,
                    "description": description,
                    "status": data.get("status") if isinstance(data, dict) else None,
                    "note": (
                        "unverified live: the NSO-connector resync is documented in the 7.2 "
                        "API but was not exercised on a real instance; the sync runs in the "
                        "background — re-read the service inventory in a moment."
                    ),
                }
            )
            return finalize(to_json(result), settings)
        except Exception as e:
            return format_error(e)


def _flex_algo(value: int) -> int:
    """0 (omitted) or 128..255 — the Flex-Algo number space; PlatformError otherwise."""
    if value and not 128 <= value <= 255:
        raise PlatformError(
            f"flex_algo {value} is outside 128..255 (Flex-Algo numbers); use 0 to omit it."
        )
    return value


def _binding_sid(value: int) -> int:
    """0 (omitted) or 16..1048575 — the policy's binding-sid range; PlatformError otherwise."""
    if value and not 16 <= value <= MAX_MPLS_LABEL:
        raise PlatformError(
            f"binding_sid {value} is outside 16..{MAX_MPLS_LABEL}; use 0 to omit it."
        )
    return value
