"""Topology tools — the IETF network-topology view on the RESTCONF topology NBI.

Base :data:`cnc_mcp.restconf.TOPOLOGY_NBI` (``/crosswork/nbi/topology/v3/
restconf``), container ``ietf-network-state:networks`` (RFC 8345 network /
node / termination-point / link model with the IETF L3-unicast, L2, SR-MPLS
and Cisco Crosswork augmentations). Everything below was verified live on
Crosswork 7.2 on 2026-09-13 (see the platform notes, "Topology NBI"); this
module replaces the earlier one built on the UI-internal
``/crosswork/topology/v1/topology-service`` API, which is not a published API
and only ever showed the L2 links.

**Where the data comes from.** CNC 7.x learns the L3 topology from an SR-PCE
provider over the XR *service-layer gRPC* (LSLib server, port 57400) — the
provider needs both an HTTP (8080) and a GRPC (57400) ``connectivity_info``
entry and the credential profile a ``ROBOT_USERPASS_GRPC`` password. That feed
supplies the IS-IS nodes and adjacencies (link ids ending ``ISIS_IPV4_L2``),
the SR-MPLS data (SRGB/SRLB, MSD, prefix-SIDs, adjacency-SIDs), the IGP
metrics and bandwidths and the PCEP sessions. The L2 links (ids ending
``ETHERNET``) come from LLDP device collection through the Data Gateway and
exist without any SR-PCE. **A topology whose links are all ``ETHERNET`` means
the SR-PCE gRPC feed is not up** (provider missing, no GRPC endpoint, PCE not
running ``lslib-server`` / ``grpc ... service-layer`` / ``pce distribute
link-state``) — the inventory still fills and the devices stay reachable.
Device reachability, admin/oper state and collection status are NOT in this
view: read them with ``cnc_list_devices`` / ``cnc_get_device``; a topology
``node-id`` equals the inventory ``host_name``.

**Keys and encoding.** Every list key on this NBI — node ids, termination-point
ids (interface names such as ``GigabitEthernet0/0/0/0``) and link ids
(``"PE1 : GigabitEthernet0/0/0/0 : P1 : GigabitEthernet0/0/0/0 : ISIS_IPV4_L2"``,
spaces and colons included, listed once per direction) — is placed in the URL
through :func:`cnc_mcp.restconf.encode_key` (``quote(key, safe="")``) — though
this module no longer sends a link id in any URL (see "Shallow keyed GETs"). An
unencoded ``/`` breaks the route and the gateway answers a **plain 404** (no
RESTCONF error document); that 404 means "malformed URL" — or, for the same
bare answer from the home app, "NBI prefix not routed" — never "no such
object". Every keyed GET goes through ``keyed_get`` below, which turns such a
404 into :func:`plain_404_error` so the agent is never told the object is
missing (the generic 404 hint of :func:`cnc_mcp.errors.http_error` would say
exactly that).

**Not-found semantics.** A properly encoded key that matches nothing answers
``409`` with a bare-``errors`` RESTCONF document tagged ``data-missing``
(:func:`cnc_mcp.restconf.is_not_found`); the keyed tools turn that into
``Error: no <thing> '<key>' ...`` naming the list tool that shows the valid
keys. The network key is the exception: ``network=<unknown>`` answers the
WHOLE ``networks`` list with the key ignored, so the network is selected
client-side (:func:`select_by_field`) and an unknown id is reported as "no
network" from that check — but only when other networks ARE present. An empty
``networks`` container (``{}``, or the 204 the 7.2 OpenAPI documents for this
GET — a fresh instance before anything is discovered) is not an error: the
summary answers zeros and the list tools "No nodes / No links", each carrying
:data:`NO_NETWORKS_NOTE`. The ``node`` and ``link`` sub-lists cannot be listed
on their own (``400 missing-attribute``), so the list tools fetch the network
and filter / page client-side. A network without nodes or links is likewise a
normal "no nodes / no links" answer. Every request is a GET with
``Accept: application/yang-data+json``.

**Shallow keyed GETs.** Two keyed reads answer LESS than the collection: the
``network=<id>`` GET (nodes carry only ``name``/``router-id``, no topology
attributes — verified 2026-09-13) and the ``link=<id>`` GET, which omits the
link's ``ietf-sr-mpls-topology-state:sr-mpls`` container (its adjacency SIDs)
while the unkeyed ``networks`` collection carries it for every IS-IS link
(verified 2026-09-15 on two link ids, re-verified the same day from this
module — the old keyed read printed ``adj-sid=-`` for links that have one).
The SRv6 End.X list sits in the same ``l3-link-attributes`` subtree, so it is
assumed dropped too. Hence :func:`fetch_network` and ``cnc_get_topology_link``
both read the collection and select the id client-side; the keyed
``node=<id>`` and termination-point GETs are full (verified) and stay keyed.

Member naming follows RFC 7951: a member is prefixed with its module only
where that differs from its parent's (``node-id``, ``tp-id``, ``link-id``,
``source``/``destination`` are bare; ``ietf-l3-unicast-topology-state:
l3-node-attributes``, ``ietf-sr-mpls-topology-state:sr-mpls``,
``cisco-crosswork-l3-te-topology:node-pcep-sessions`` are prefixed). The 7.2
OpenAPI documents prefix every member instead; :func:`field` accepts both, and
the client-side key re-selection (:func:`select_by_field`) is built on it, so
the tools survive either spelling.

**SRv6 (added 2026-09-15; rendering built from the 7.2 OpenAPI model, NOT yet
seen live).** The lab runs SR-MPLS only, so every SRv6 member below is absent
on the wire today (verified: ``grep -i srv6`` over the live node, link,
network and termination-point captures finds nothing) and the renderers print
an explicit "no SRv6" line / ``dataplane=sr-mpls`` instead. The member names
and nesting come from the 7.2 topology OpenAPI (module
``cisco-crosswork-srv6-topology-state``), spelled here the RFC 7951 way the
live SR-MPLS members are spelled (prefixed list, bare children):

- network ``network-types`` → ``ietf-l3-unicast-topology-state:
  l3-unicast-topology`` → ``cisco-crosswork-srv6-topology-state:srv6: {}``
  (presence container, sibling of the live ``ietf-sr-mpls-topology-state:
  sr-mpls: {}``) — the cheapest "is there SRv6 anywhere" flag;
- node ``l3-node-attributes`` → ``cisco-crosswork-l3-te-topology:
  ipv6-router-id[]`` (leaf-list) and, INSIDE EACH IGP instance entry
  (``cisco-crosswork-isis-topology:isis-node-attributes[]`` /
  ``cisco-crosswork-ospf-topology:ospf-node-attributes[]``),
  ``cisco-crosswork-srv6-topology-state:srv6-node-sid[]`` = ``{sid,
  endpoint-behavior, algorithm, srv6-sid-structure{lb-length, ln-length,
  func-length, arg-length}}`` and ``cisco-crosswork-flex-algo:flex-algo[]``;
- link ``l3-link-attributes`` → ``isis-link-attributes`` /
  ``ospf-link-attributes`` → ``cisco-crosswork-srv6-topology-state:
  srv6-adjacency-sid[]`` = ``{sid, endpoint-behavior, protected, flags,
  algorithm, weight, srv6-sid-structure}`` (the End.X SIDs — NOT inside the
  SR-MPLS ``sr-mpls.sids[]`` list).

**There is no locator object in the model**: a locator is derived here as the
SID masked to ``lb-length + ln-length`` bits (``fc00:0:1::`` with 32/16 →
``fc00:0:1::/48``), labelled ``uSID F3216`` when lb=32, ln=16 and func=16
(or no func-length at all; arg-length is not part of the check) and
``classic`` otherwise. Which of these the SR-PCE gRPC feed actually
populates once the routers advertise SRv6 locators, the wire type of the
uint32 leaves (int or string — both are parsed) and whether
``node-capabilities.transport-planes[]`` ever names an SRv6 transport are
the facts that await the SRv6 underlay; the tests carry spec-shaped
fixtures only.

NOT in scope of this module: SR / P2MP policies, RSVP-TE tunnels and the
per-link / per-policy performance metrics on the same NBI (their own modules).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Any, NamedTuple

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import page_envelope
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.restconf import (
    TOPOLOGY_NBI,
    YANG_ACCEPT,
    encode_key,
    is_not_found,
    parse_restconf_errors,
    unwrap_list,
)
from cnc_mcp.safety import AppContext, register_tool

DEFAULT_NETWORK = "Default-network"
NETWORK_MODULE = "ietf-network-state"
TOPOLOGY_MODULE = "ietf-network-topology-state"
NETWORKS_URL = f"{TOPOLOGY_NBI}/data/{NETWORK_MODULE}:networks"

# Verbatim member names verified live (RFC 7951 prefixing — see the module docstring).
L3_TOPOLOGY_ATTRIBUTES = "ietf-l3-unicast-topology-state:l3-topology-attributes"
ISIS_TOPOLOGY_ATTRIBUTES = "cisco-crosswork-isis-topology:isis-topology-attributes"
TERMINATION_POINT = f"{TOPOLOGY_MODULE}:termination-point"
TP_ATTRIBUTES = "cisco-crosswork-topology-state:termination-point-attributes"
L3_NODE_ATTRIBUTES = "ietf-l3-unicast-topology-state:l3-node-attributes"
ISIS_NODE_ATTRIBUTES = "cisco-crosswork-isis-topology:isis-node-attributes"
SR_MPLS = "ietf-sr-mpls-topology-state:sr-mpls"
PCEP_SESSIONS = "cisco-crosswork-l3-te-topology:node-pcep-sessions"
LINK = f"{TOPOLOGY_MODULE}:link"
L3_LINK_ATTRIBUTES = "ietf-l3-unicast-topology-state:l3-link-attributes"
TE_LINK_ATTRIBUTES = "cisco-crosswork-l3-te-topology:l3-link-attributes"
ISIS_LINK_ATTRIBUTES = "cisco-crosswork-isis-topology:isis-link-attributes"
L2_LINK_ATTRIBUTES = "ietf-l2-topology-state:l2-link-attributes"
# Member names from the 7.2 topology OpenAPI, spelled the RFC 7951 way (see the module
# docstring, "SRv6"): none of these has been seen live yet — the lab is SR-MPLS only.
L3_UNICAST_TOPOLOGY = "ietf-l3-unicast-topology-state:l3-unicast-topology"
SRV6_NETWORK_TYPE = "cisco-crosswork-srv6-topology-state:srv6"
IPV6_ROUTER_ID = "cisco-crosswork-l3-te-topology:ipv6-router-id"
OSPF_NODE_ATTRIBUTES = "cisco-crosswork-ospf-topology:ospf-node-attributes"
OSPF_LINK_ATTRIBUTES = "cisco-crosswork-ospf-topology:ospf-link-attributes"
SRV6_NODE_SID = "cisco-crosswork-srv6-topology-state:srv6-node-sid"
SRV6_ADJACENCY_SID = "cisco-crosswork-srv6-topology-state:srv6-adjacency-sid"
SRV6_SID_STRUCTURE = "cisco-crosswork-srv6-topology-state:srv6-sid-structure"
FLEX_ALGO = "cisco-crosswork-flex-algo:flex-algo"
FLEX_ALGO_LINK_ATTRIBUTES = "cisco-crosswork-flex-algo:link-attributes"

# The dataplane a node advertises, from what its IGP instances carry: SR-MPLS = the
# ietf-sr-mpls-topology-state:sr-mpls presence container, SRv6 = at least one srv6-node-sid.
DATAPLANE_SR_MPLS = "sr-mpls"
DATAPLANE_SRV6 = "srv6"
DATAPLANE_BOTH = "both"
DATAPLANE_NONE = "none"
DATAPLANES = (DATAPLANE_SR_MPLS, DATAPLANE_SRV6, DATAPLANE_BOTH, DATAPLANE_NONE)
_DATAPLANE_CHOICES = ", ".join(DATAPLANES)
# SID-structure formats: the uSID F3216 format (32-bit block, 16-bit node id, 16-bit
# function) is the one XR uses for micro-segments; anything else — including a /48
# locator whose function field is not 16 bits — is labelled classic (full-length SIDs).
SID_FORMAT_USID_F3216 = "uSID F3216"
SID_FORMAT_CLASSIC = "classic"
SID_FORMAT_UNKNOWN = "unknown structure"

# The link-id suffix names the link's type (verified: exactly these two on the lab).
LINK_ID_SEPARATOR = " : "
LINK_TYPE_ISIS = "ISIS_IPV4_L2"
LINK_TYPE_ETHERNET = "ETHERNET"
LINK_TYPES = ("all", "isis", "ethernet", "other")
_LINK_TYPE_CHOICES = ", ".join(LINK_TYPES)

_NETWORK_FIELD = Field(
    description=(
        f"Topology network id (e.g. '{DEFAULT_NETWORK}', the only network on a standard "
        "deployment)."
    ),
    min_length=1,
    max_length=200,
)
_FORMAT_FIELD = Field(
    description="'markdown' for human-readable output, 'json' for the raw platform objects."
)

_L2_ONLY_NOTE = (
    "Every link is ETHERNET (L2, from LLDP collection) and no IS-IS/SR data is present: the "
    "SR-PCE gRPC feed is not up. Check the SR-PCE provider (cnc_list_providers: it needs an "
    "HTTP 8080 and a GRPC 57400 connectivity entry, both reachable) and that the PCE runs "
    "lslib-server, 'grpc ... service-layer' and 'pce distribute link-state'."
)
# The networks container answered empty ({} or 204): a fresh instance, not a failure.
NO_NETWORKS_NOTE = (
    "the topology NBI reports no networks yet - the networks container is populated once "
    "devices are onboarded and collected (L2 links, via LLDP) and the SR-PCE gRPC feed is up "
    "(L3 nodes and links). Check onboarding with cnc_list_devices and the SR-PCE provider "
    "with cnc_list_providers."
)
# A PCEP session's pce-address as the SR-PCE feed reports it (verified live 2026-09-14): the
# address the PCE identifies itself by towards Crosswork = the SR-PCE provider's endpoint
# address (cnc_list_providers), NOT necessarily the 'pce address ipv4 <loopback>' peer the
# router is configured with — on the lab the two differ (provider management address vs the
# PCE's loopback), and the feed never carries the router-side peer address.
PCE_ADDRESS_NOTE = (
    "  (pce = the address the SR-PCE feed identifies itself by, i.e. the SR-PCE provider's "
    "endpoint address in cnc_list_providers; it may differ from the 'pce address ipv4' peer "
    "configured on the router, which only the device configuration / backup shows)"
)
# What has to exist before the topology can show SRv6 (the maintainer's underlay plan). All
# three router lines below — 'locators locator <name> prefix <block>::/48', 'micro-segment
# behavior unode psp-usd' and 'router isis ... address-family ipv6 unicast segment-routing
# srv6 locator <name>' — plus the hw-module profile line were rendered by the NSO XR NED in
# a ?dry-run=native probe on 2026-09-15 (nothing committed); none has run on a router yet.
SRV6_UNDERLAY_HINT = (
    "SRv6 state appears in the topology once the routers run an SRv6 locator (XR: "
    "'segment-routing srv6 locators locator <name> prefix <block>::/48' with "
    "'micro-segment behavior unode psp-usd' for uSID; uSID additionally needs 'hw-module "
    "profile segment-routing srv6 mode micro-segment format f3216' on each XR router, which "
    "takes effect only after a reload), the IGP advertises it (IS-IS 'address-family ipv6 "
    "unicast segment-routing srv6 locator <name>' with IPv6 loopbacks and router-ids) and "
    "the SR-PCE gRPC feed carries it to Crosswork; SR-MPLS and SRv6 coexist on a node "
    "(dataplane=both). The rendering here follows the 7.2 topology model and has not been "
    "verified against a live SRv6 feed yet."
)
NO_SRV6_LOCATORS = "No SRv6 locators are advertised in the topology"


class FetchedNetwork(NamedTuple):
    """One ``network`` entry plus the note explaining an empty ``networks`` container.

    ``note`` is :data:`NO_NETWORKS_NOTE` when the NBI reported no networks at
    all — ``network`` is then a placeholder ``{"network-id": <requested id>}``
    so the callers count zeros — and ``None`` when the entry is real.
    """

    network: dict[str, Any]
    note: str | None


def plain_404_error(url: str) -> PlatformError:
    """The explanation for a 404 that carries no RESTCONF error document.

    Verified live on this NBI: an unencoded ``/`` in a list key breaks the
    route and the gateway answers a plain 404 — "malformed URL", never "no
    such object" (that is spelled ``409 data-missing``). The home app answers
    the same bare 404 when the NBI prefix is not routed at all. Either way the
    generic "Resource not found. Check that the ID or name is correct" hint of
    :func:`cnc_mcp.errors.http_error` would mislead the agent, so ``keyed_get``
    raises this instead. The message keeps the ``API request failed with
    status 404.`` prefix every other API failure carries.
    """
    return PlatformError(
        f"API request failed with status 404. The topology NBI answered a plain 404 (no "
        f"RESTCONF error document) for GET {url}: on this gateway that means the URL is "
        "malformed or the NBI prefix is not routed, NOT that the object is missing (a "
        "properly encoded key that matches nothing answers 409 data-missing). The key was "
        f"sent percent-encoded; check that {TOPOLOGY_NBI} is routed on this instance and "
        "that the data path matches this build's YANG model."
    )


# --- URL builders -------------------------------------------------------------


def network_url(network: str) -> str:
    """``.../networks/network=<id>`` (the id percent-encoded as one list key)."""
    return f"{NETWORKS_URL}/network={encode_key(network)}"


def node_url(network: str, node_id: str) -> str:
    """``.../network=<id>/node=<node-id>`` — answers a list of one node."""
    return f"{network_url(network)}/node={encode_key(node_id)}"


def termination_point_url(network: str, node_id: str, tp_id: str) -> str:
    """``.../node=<node-id>/ietf-network-topology-state:termination-point=<tp-id>``.

    Interface names carry ``/`` and MUST be encoded (``GigabitEthernet0%2F0%2F0%2F0``).
    """
    return f"{node_url(network, node_id)}/{TERMINATION_POINT}={encode_key(tp_id)}"


# There is deliberately no link_url(): the keyed ``.../network=<id>/ietf-network-topology-
# state:link=<link-id>`` GET is SHALLOW (verified live 2026-09-15 — it omits the link's
# ``sr-mpls`` container), so cnc_get_topology_link reads the collection instead (module
# docstring, "Shallow keyed GETs"); scripts/live_plumbing_check.py builds the URL for probes.


# --- YANG-JSON accessors (pure functions) ------------------------------------


def field(obj: Any, key: str, default: Any = None) -> Any:
    """A YANG-JSON member by its verbatim key, tolerating the module-prefix variants.

    RFC 7951 prefixes a member only where its module differs from the parent's
    (verified live: ``node-id`` and ``tp-id`` are bare while
    ``ietf-sr-mpls-topology-state:sr-mpls`` is prefixed), whereas the 7.2
    OpenAPI documents prefix every member. The lookup tries ``key`` as given,
    then its bare local name, then any ``<module>:<local name>`` member, so a
    build that spells a prefix differently degrades to nothing worse than the
    same value. Non-dict ``obj`` → ``default``.
    """
    if not isinstance(obj, dict):
        return default
    if key in obj:
        return obj[key]
    local = key.rsplit(":", 1)[-1]
    if local in obj:
        return obj[local]
    suffix = f":{local}"
    for name, value in obj.items():
        if isinstance(name, str) and name.endswith(suffix):
            return value
    return default


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    """A list as-is, a lone dict wrapped, anything else → []."""
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def dict_items(value: Any) -> list[dict[str, Any]]:
    return [item for item in as_list(value) if isinstance(item, dict)]


def select_by_field(items: Any, key_field: str, key: str) -> list[dict[str, Any]]:
    """Client-side exact, case-sensitive key filter tolerant of the module-prefix spellings.

    The topology NBI ignores a key on the top-level ``network`` list and may
    answer a keyed GET with a different entry, so every keyed answer is
    re-matched here. Unlike :func:`cnc_mcp.restconf.select_key`, which reads the
    member by its bare name only, the value is looked up through :func:`field`,
    so a build that spells the key ``ietf-network-state:node-id`` (the 7.2
    OpenAPI form) matches like the live bare ``node-id``. A non-string stored
    value matches its string form (URL keys are always strings); non-dict items
    are dropped.
    """
    matches: list[dict[str, Any]] = []
    for item in dict_items(items):
        value = field(item, key_field)
        if value is None or isinstance(value, (dict, list)):
            continue
        if value == key or str(value) == key:
            matches.append(item)
    return matches


def node_id_matches(pattern: str, node_id: Any) -> bool:
    """Case-insensitive exact match where ``*`` in ``pattern`` is a wildcard.

    Same semantics as the inventory filters (exact, case-insensitive, ``*``
    anywhere) so agents get one behaviour across the server; ``?`` and ``%``
    are literal characters.
    """
    if not isinstance(node_id, str):
        return False
    regex = ".*".join(re.escape(part) for part in pattern.strip().split("*"))
    return re.fullmatch(regex, node_id, re.IGNORECASE) is not None


def link_type_of(link_id: Any) -> str:
    """The type suffix of a link id: what follows the last ``" : "`` (``''`` when absent)."""
    if not isinstance(link_id, str):
        return ""
    _head, sep, tail = link_id.rpartition(LINK_ID_SEPARATOR)
    return tail.strip() if sep else ""


def classify_link(link_id: Any) -> str:
    """``'isis'`` for an ``ISIS_IPV4_L2`` id, ``'ethernet'`` for ``ETHERNET``, else ``'other'``."""
    kind = link_type_of(link_id).upper()
    if kind == LINK_TYPE_ISIS:
        return "isis"
    if kind == LINK_TYPE_ETHERNET:
        return "ethernet"
    return "other"


def normalize_link_type(link_type: str) -> str:
    """'ISIS' / ' ethernet ' -> the LINK_TYPES entry; PlatformError when unknown."""
    key = link_type.strip().lower()
    if key not in LINK_TYPES:
        raise PlatformError(
            f"Unknown link_type '{link_type}'. Use one of: {_LINK_TYPE_CHOICES} "
            f"('isis' = link ids ending {LINK_TYPE_ISIS}, 'ethernet' = ids ending "
            f"{LINK_TYPE_ETHERNET}, 'other' = any other suffix)."
        )
    return key


# Nodes ------------------------------------------------------------------------


def node_id_of(node: dict[str, Any]) -> str:
    return str(field(node, "node-id") or "?")


def node_l3(node: dict[str, Any]) -> dict[str, Any]:
    """The node's ``l3-node-attributes`` (``{}`` for an L2-only node)."""
    return as_dict(field(node, L3_NODE_ATTRIBUTES))


def node_termination_points(node: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(node, TERMINATION_POINT))


def router_ids(l3: dict[str, Any]) -> list[str]:
    return [str(r) for r in as_list(field(l3, "router-id"))]


def isis_of(l3: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(l3, ISIS_NODE_ATTRIBUTES))


def sr_mpls_of(l3: dict[str, Any]) -> dict[str, Any] | None:
    """The ``sr-mpls`` presence container, or None when the node advertises no SR."""
    value = field(l3, SR_MPLS)
    return value if isinstance(value, dict) else None


def prefixes_of(l3: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(l3, "prefix"))


def prefix_sids_of(prefix: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(prefix, SR_MPLS))


def srgb_lower_bound(l3: dict[str, Any]) -> int | None:
    """The first SRGB block's ``lower-bound`` (16000 on the lab), or None."""
    sr = sr_mpls_of(l3)
    for block in dict_items(field(sr, "srgb") if sr else None):
        lower = field(block, "lower-bound")
        try:
            return int(lower)
        except (TypeError, ValueError):
            continue
    return None


def prefix_sid_label(entry: dict[str, Any], srgb_lower: int | None) -> int | None:
    """The absolute MPLS label of one prefix-SID entry, or None.

    Verified live: the feed publishes prefix-SIDs as
    ``{"value-type": "index", "start-sid": 4, "range": 1, "algorithm-value": 0,
    ...}`` — an INDEX into the SRGB, so the label is ``srgb.lower-bound +
    start-sid`` (16000 + 4 = 16004, the value the PCE expects in
    ``node-ipv4-sid``). ``value-type: "absolute"`` carries the label itself in
    ``start-sid``. A bare ``sid`` key (the OpenAPI spelling) is accepted as an
    absolute label too. An index without a known SRGB yields None.
    """
    for key in ("start-sid", "sid"):
        raw = field(entry, key)
        if raw is None:
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        kind = str(field(entry, "value-type") or ("absolute" if key == "sid" else "index"))
        if kind.lower() == "absolute":
            return value
        return srgb_lower + value if srgb_lower is not None else None
    return None


def prefix_sid_count(l3: dict[str, Any]) -> int:
    """How many of the node's prefixes carry SR-MPLS SID entries."""
    return sum(1 for p in prefixes_of(l3) if prefix_sids_of(p))


def pcep_sessions_of(l3: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(l3, PCEP_SESSIONS))


def transport_planes(sr: dict[str, Any] | None) -> list[str]:
    """The ``node-capabilities.transport-planes[].transport-plane`` identities, module prefix
    dropped (live: ``segment-routing-transport-mpls``; an SRv6 identity is unverified)."""
    planes = as_dict(field(sr, "node-capabilities")) if sr else {}
    names: list[str] = []
    for plane in dict_items(field(planes, "transport-planes")):
        value = field(plane, "transport-plane")
        if value is not None:
            names.append(str(value).rsplit(":", 1)[-1])
    return names


# SRv6 / IPv6 / Flex-Algo node members (7.2 OpenAPI shapes; none seen live yet — module doc).


def int_or_none(value: Any) -> int | None:
    """``int(value)`` or None: the feed types numbers inconsistently (int or string)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def ipv6_router_ids(l3: dict[str, Any]) -> list[str]:
    """The node's ``cisco-crosswork-l3-te-topology:ipv6-router-id`` leaf-list ([] live today)."""
    return [str(r) for r in as_list(field(l3, IPV6_ROUTER_ID))]


def all_router_ids(l3: dict[str, Any]) -> list[str]:
    """The IPv4 ``router-id[]`` entries followed by the IPv6 ones, duplicates dropped.

    The same IPv4-then-IPv6 order ``te_state.node_te_router_ids`` uses for
    its router-id -> host name map (``router_id_names``), so an SRv6 policy
    keyed by an IPv6 TE router-id resolves to the same node as its IPv4
    key; te_state walks the two leaf-lists itself and does not import this
    helper.
    """
    ids: list[str] = []
    for value in [*router_ids(l3), *ipv6_router_ids(l3)]:
        if value not in ids:
            ids.append(value)
    return ids


def ospf_of(l3: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(l3, OSPF_NODE_ATTRIBUTES))


def igp_instances(l3: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """``[("isis", entry), ..., ("ospf", entry), ...]``: every IGP instance entry of the node.

    The SRv6 node SIDs and the Flex-Algo definitions hang off each instance
    entry (not off ``l3-node-attributes``), so everything SRv6 walks these.
    """
    return [("isis", e) for e in isis_of(l3)] + [("ospf", e) for e in ospf_of(l3)]


def ospf_area_text(entry: dict[str, Any]) -> str:
    """The OSPF ``area-id`` of a node instance entry: a leaf-list in the 7.2 model
    (``0.0.0.0,0.0.0.1`` when several), a lone string accepted too, '?' when absent."""
    areas = field(entry, "area-id")
    if areas is None:
        return "?"
    if isinstance(areas, list):
        return ",".join(str(a) for a in areas) or "?"
    return str(areas)


def igp_instance_text(kind: str, entry: dict[str, Any]) -> str:
    """``IS-IS level-2`` / ``OSPF area 0.0.0.0``: the instance an SRv6 SID was learnt from."""
    if kind == "isis":
        return f"IS-IS {field(entry, 'level', '?')}"
    return f"OSPF area {ospf_area_text(entry)}"


def srv6_node_sids_of(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """The ``srv6-node-sid[]`` list of one IGP instance entry."""
    return dict_items(field(entry, SRV6_NODE_SID))


def node_srv6_sids(l3: dict[str, Any]) -> list[dict[str, Any]]:
    """Every ``srv6-node-sid`` entry of the node, across its IS-IS and OSPF instances."""
    return [sid for _kind, entry in igp_instances(l3) for sid in srv6_node_sids_of(entry)]


def flex_algos_of(entry: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(entry, FLEX_ALGO))


def node_flex_algos(l3: dict[str, Any]) -> list[dict[str, Any]]:
    """Every ``cisco-crosswork-flex-algo:flex-algo`` entry across the node's IGP instances."""
    return [algo for _kind, entry in igp_instances(l3) for algo in flex_algos_of(entry)]


def flex_algo_ids(l3: dict[str, Any]) -> list[int]:
    """The distinct ``flex-algo-id`` values the node advertises, sorted."""
    ids = {int_or_none(field(a, "flex-algo-id")) for a in node_flex_algos(l3)}
    return sorted(i for i in ids if i is not None)


def sid_structure(entry: dict[str, Any]) -> dict[str, int | None]:
    """``{"lb", "ln", "func", "arg"}`` bit lengths of an SRv6 SID entry (None where absent).

    ``srv6-sid-structure`` is a non-presence container: a SID may come
    without one, in which case no locator can be derived.
    """
    structure = as_dict(field(entry, SRV6_SID_STRUCTURE))
    return {
        "lb": int_or_none(field(structure, "lb-length")),
        "ln": int_or_none(field(structure, "ln-length")),
        "func": int_or_none(field(structure, "func-length")),
        "arg": int_or_none(field(structure, "arg-length")),
    }


def structure_text(structure: dict[str, int | None]) -> str:
    """``32/16/16/0`` (lb/ln/func/arg, '?' for a missing length; '-' when none is known)."""
    if all(structure[k] is None for k in ("lb", "ln", "func", "arg")):
        return "-"
    return "/".join(
        "?" if structure[k] is None else str(structure[k]) for k in ("lb", "ln", "func", "arg")
    )


def sid_format(structure: dict[str, int | None]) -> str:
    """``uSID F3216`` for a 32-bit block + 16-bit node id + 16-bit function, ``classic`` for
    any other structure, ``unknown structure`` when the SID carries no block/node lengths.

    F3216 is the 32/16/16 format, so a ``func-length`` other than 16 (a
    classic SID under a /48 locator) is ``classic`` even with lb 32 / ln
    16; a SID whose structure carries no ``func-length`` is still F3216
    on lb/ln alone. ``arg-length`` is not part of the check.
    """
    lb, ln, func = structure["lb"], structure["ln"], structure["func"]
    if lb is None or ln is None:
        return SID_FORMAT_UNKNOWN
    if lb == 32 and ln == 16 and (func is None or func == 16):
        return SID_FORMAT_USID_F3216
    return SID_FORMAT_CLASSIC


def srv6_locator(sid: Any, structure: dict[str, int | None]) -> str | None:
    """The locator prefix a SID belongs to: the SID masked to ``lb-length + ln-length`` bits.

    ``fc00:0:1::`` with lb 32 / ln 16 -> ``fc00:0:1::/48``. The 7.2 topology
    model has no locator object, so this derivation is the only locator view
    the NBI affords. None when the SID is not an IPv6 address or the lengths
    are missing / out of range.
    """
    lb, ln = structure["lb"], structure["ln"]
    if lb is None or ln is None or not 0 <= lb + ln <= 128:
        return None
    try:
        address = ipaddress.IPv6Address(str(sid).strip())
    except (ValueError, TypeError):
        return None
    return str(ipaddress.IPv6Network((address, lb + ln), strict=False))


def node_dataplane(l3: dict[str, Any]) -> str:
    """``sr-mpls`` / ``srv6`` / ``both`` / ``none`` from what the node advertises.

    SR-MPLS = the ``ietf-sr-mpls-topology-state:sr-mpls`` presence container
    (SRGB/SRLB/MSD); SRv6 = at least one ``srv6-node-sid`` under an IGP
    instance. A node known from L2 (LLDP) discovery only is ``none``.
    """
    mpls = sr_mpls_of(l3) is not None
    srv6 = bool(node_srv6_sids(l3))
    if mpls and srv6:
        return DATAPLANE_BOTH
    if srv6:
        return DATAPLANE_SRV6
    if mpls:
        return DATAPLANE_SR_MPLS
    return DATAPLANE_NONE


def normalize_dataplane(dataplane: str) -> str:
    """'SR_MPLS' / ' srv6 ' -> the DATAPLANES entry; PlatformError when unknown."""
    key = dataplane.strip().lower().replace("_", "-")
    if key not in DATAPLANES:
        raise PlatformError(
            f"Unknown dataplane '{dataplane}'. Use one of: {_DATAPLANE_CHOICES} ('sr-mpls' = "
            "nodes advertising SR-MPLS (dataplane sr-mpls or both), 'srv6' = nodes advertising "
            "SRv6 node SIDs (srv6 or both), 'both' = nodes advertising both, 'none' = nodes "
            "advertising neither)."
        )
    return key


def dataplane_matches(wanted: str, actual: str) -> bool:
    """The inclusive filter semantics of ``normalize_dataplane``'s choices."""
    if wanted in (DATAPLANE_BOTH, DATAPLANE_NONE):
        return actual == wanted
    return actual in (wanted, DATAPLANE_BOTH)


def _ranges_text(ranges: Any) -> str:
    """``[{lower-bound, upper-bound}]`` -> ``16000-23999`` (several joined by ','; '-' if none)."""
    parts = []
    for block in dict_items(ranges):
        lower, upper = field(block, "lower-bound"), field(block, "upper-bound")
        if lower is None and upper is None:
            continue
        parts.append(f"{lower if lower is not None else '?'}-{upper if upper is not None else '?'}")
    return ",".join(parts) or "-"


def _isis_text(l3: dict[str, Any]) -> str:
    entries = [
        f"{field(e, 'level', '?')}/{field(e, 'system-id', '?')}"
        for e in isis_of(l3)
        if field(e, "level") is not None or field(e, "system-id") is not None
    ]
    return ",".join(entries) or "-"


def node_line(node: dict[str, Any]) -> str:
    """One markdown line for a node (the list tool's row; '-' where an attribute is absent).

    ``router-id=`` lists the IPv4 router-ids then the IPv6 ones (spec-only
    today); ``dataplane=`` is :func:`node_dataplane` and ``srv6-sids=`` the
    node's SRv6 node-SID count — 0 / ``sr-mpls`` on the SR-MPLS-only lab.
    """
    l3 = node_l3(node)
    sr = sr_mpls_of(l3)
    msd = field(sr, "msd") if sr is not None else None
    return (
        f"- **{node_id_of(node)}** router-id={','.join(all_router_ids(l3)) or '-'} "
        f"isis={_isis_text(l3)} srgb={_ranges_text(field(sr, 'srgb')) if sr else '-'} "
        f"msd={msd if msd is not None else '-'} prefix-sids={prefix_sid_count(l3)} "
        f"srv6-sids={len(node_srv6_sids(l3))} dataplane={node_dataplane(l3)} "
        f"pcep={len(pcep_sessions_of(l3))} tps={len(node_termination_points(node))}"
    )


# Termination points -----------------------------------------------------------


def tp_id_of(tp: dict[str, Any]) -> str:
    return str(field(tp, "tp-id") or "?")


def tp_ip_addresses(tp: dict[str, Any]) -> list[str]:
    """Every IP address on a termination point, from any of the containers that carry one.

    Verified live under ``cisco-crosswork-topology-state:termination-point-attributes``:
    ``l3-termination-point-attributes.ip-address[]`` plus the per-family
    ``ipv4-`` / ``ipv6-termination-point-attributes.l3-termination-point-attributes``;
    the documented plain ``ietf-l3-unicast-topology-state:l3-termination-point-attributes``
    on the TP itself is read too. Duplicates are dropped, order kept.
    """
    attrs = as_dict(field(tp, TP_ATTRIBUTES))
    containers = [
        field(attrs, "l3-termination-point-attributes"),
        field(
            as_dict(field(attrs, "ipv4-termination-point-attributes")),
            "l3-termination-point-attributes",
        ),
        field(
            as_dict(field(attrs, "ipv6-termination-point-attributes")),
            "l3-termination-point-attributes",
        ),
        field(tp, "ietf-l3-unicast-topology-state:l3-termination-point-attributes"),
    ]
    addresses: list[str] = []
    for container in containers:
        for address in as_list(field(as_dict(container), "ip-address")):
            text = str(address)
            if text not in addresses:
                addresses.append(text)
    return addresses


def tp_l2(tp: dict[str, Any]) -> dict[str, Any]:
    """The TP's L2 attributes (Crosswork's container first, the documented IETF one after)."""
    attrs = as_dict(field(tp, TP_ATTRIBUTES))
    return as_dict(field(attrs, "l2-termination-point-attributes")) or as_dict(
        field(tp, "ietf-l2-topology-state:l2-termination-point-attributes")
    )


def tp_summary(tp: dict[str, Any]) -> dict[str, Any]:
    """The curated view of one termination point (what the markdown lines show)."""
    l2 = tp_l2(tp)
    return {
        "tp-id": tp_id_of(tp),
        "ip-address": tp_ip_addresses(tp),
        "mac-address": field(l2, "mac-address"),
        "unnumbered-id": [str(u) for u in as_list(field(l2, "unnumbered-id"))],
        "encapsulation": field(l2, "encapsulation-type"),
    }


def tp_line(tp: dict[str, Any]) -> str:
    s = tp_summary(tp)
    return (
        f"- {s['tp-id']} ip={','.join(s['ip-address']) or '-'} mac={s['mac-address'] or '-'} "
        f"unnumbered={','.join(s['unnumbered-id']) or '-'} encap={s['encapsulation'] or '-'}"
    )


# Links ------------------------------------------------------------------------


def link_id_of(link: dict[str, Any]) -> str:
    return str(field(link, "link-id") or "?")


def link_ends(link: dict[str, Any]) -> tuple[str, str, str, str]:
    """``(source-node, source-tp, dest-node, dest-tp)`` ('?' where absent)."""
    source = as_dict(field(link, "source"))
    destination = as_dict(field(link, "destination"))
    return (
        str(field(source, "source-node") or "?"),
        str(field(source, "source-tp") or "?"),
        str(field(destination, "dest-node") or "?"),
        str(field(destination, "dest-tp") or "?"),
    )


def link_touches(link: dict[str, Any], node_id: str) -> bool:
    """True when ``node_id`` (case-insensitive, exact) is either end of the link."""
    src, _src_tp, dst, _dst_tp = link_ends(link)
    wanted = node_id.strip().lower()
    return src.lower() == wanted or dst.lower() == wanted


def link_l3(link: dict[str, Any]) -> dict[str, Any]:
    return as_dict(field(link, L3_LINK_ATTRIBUTES))


def link_l2(link: dict[str, Any]) -> dict[str, Any]:
    return as_dict(field(link, L2_LINK_ATTRIBUTES))


def adjacency_sids(l3: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(as_dict(field(l3, SR_MPLS)), "sids"))


def link_igp_attributes(l3: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """``[("isis", isis-link-attributes), ("ospf", ospf-link-attributes)]`` — those present."""
    found = []
    for kind, key in (("isis", ISIS_LINK_ATTRIBUTES), ("ospf", OSPF_LINK_ATTRIBUTES)):
        attrs = as_dict(field(l3, key))
        if attrs:
            found.append((kind, attrs))
    return found


def srv6_adjacency_sids(l3: dict[str, Any]) -> list[dict[str, Any]]:
    """The link's End.X SIDs: ``srv6-adjacency-sid[]`` under its IS-IS / OSPF link attributes
    (7.2 OpenAPI; never seen live — the lab advertises SR-MPLS adjacency SIDs only)."""
    return [
        sid
        for _kind, attrs in link_igp_attributes(l3)
        for sid in dict_items(field(attrs, SRV6_ADJACENCY_SID))
    ]


def _sids_text(sids: list[dict[str, Any]]) -> str:
    return ",".join(str(field(s, "sid")) for s in sids if field(s, "sid") is not None) or "-"


def _scalars_text(attrs: dict[str, Any]) -> str:
    """``k=v`` for every scalar member (nested containers/lists skipped), '-' when none."""
    parts = [
        f"{str(k).rsplit(':', 1)[-1]}={v}"
        for k, v in attrs.items()
        if not isinstance(v, (dict, list))
    ]
    return " ".join(parts) or "-"


def link_line(link: dict[str, Any]) -> str:
    """One markdown line for a link: endpoints, [type], then the L3 or L2 essentials."""
    src, src_tp, dst, dst_tp = link_ends(link)
    kind = link_type_of(link_id_of(link)) or "?"
    head = f"- {src}:{src_tp} -> {dst}:{dst_tp} [{kind}]"
    l3 = link_l3(link)
    if l3:
        te = as_dict(field(l3, TE_LINK_ATTRIBUTES))
        metric = field(l3, "metric1")
        bandwidth = field(te, "max-bandwidth-kbps")
        return (
            f"{head} metric={metric if metric is not None else '-'} "
            f"adj-sid={_sids_text(adjacency_sids(l3))} "
            f"srv6-adj-sid={_sids_text(srv6_adjacency_sids(l3))} "
            f"bw={f'{bandwidth}kbps' if bandwidth is not None else '-'}"
        )
    l2 = link_l2(link)
    return f"{head} {_scalars_text(l2)}" if l2 else f"{head} (no attributes)"


# Network ----------------------------------------------------------------------


def network_id_of(network: dict[str, Any]) -> str:
    return str(field(network, "network-id") or "?")


def network_nodes(network: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(network, "node"))


def network_links(network: dict[str, Any]) -> list[dict[str, Any]]:
    return dict_items(field(network, LINK))


def isis_area_of(network: dict[str, Any]) -> str | None:
    topo = as_dict(field(network, L3_TOPOLOGY_ATTRIBUTES))
    area = field(as_dict(field(topo, ISIS_TOPOLOGY_ATTRIBUTES)), "area")
    if area is None:
        return None
    return ",".join(str(a) for a in area) if isinstance(area, list) else str(area)


def srv6_network_type(network: dict[str, Any]) -> bool:
    """True when ``network-types`` carries the ``cisco-crosswork-srv6-topology-state:srv6``
    presence container (live today: only ``ietf-sr-mpls-topology-state:sr-mpls`` is there)."""
    types = as_dict(field(network, "network-types"))
    l3 = as_dict(field(types, L3_UNICAST_TOPOLOGY))
    return field(l3, SRV6_NETWORK_TYPE) is not None


def summarize_network(network: dict[str, Any]) -> dict[str, Any]:
    """The cnc_get_topology_summary payload for one network object."""
    nodes = network_nodes(network)
    links = network_links(network)
    kinds = {"isis": 0, "ethernet": 0, "other": 0}
    for link in links:
        kinds[classify_link(link_id_of(link))] += 1
    l3s = [node_l3(n) for n in nodes]
    dataplanes = dict.fromkeys(DATAPLANES, 0)
    for l3 in l3s:
        dataplanes[node_dataplane(l3)] += 1
    summary: dict[str, Any] = {
        "network_id": network_id_of(network),
        "isis_area": isis_area_of(network),
        "nodes": len(nodes),
        "links": {
            "total": len(links),
            "isis_ipv4_l2": kinds["isis"],
            "ethernet": kinds["ethernet"],
            "other": kinds["other"],
        },
        "sr_capable_nodes": sum(1 for l3 in l3s if sr_mpls_of(l3) is not None),
        "pcep_session_nodes": sum(1 for l3 in l3s if pcep_sessions_of(l3)),
        "prefix_sids": sum(prefix_sid_count(l3) for l3 in l3s),
        "srv6_network_type": srv6_network_type(network),
        "srv6_capable_nodes": sum(1 for l3 in l3s if node_srv6_sids(l3)),
        "srv6_node_sids": sum(len(node_srv6_sids(l3)) for l3 in l3s),
        "srv6_adjacency_links": sum(1 for ln in links if srv6_adjacency_sids(link_l3(ln))),
        "ipv6_router_id_nodes": sum(1 for l3 in l3s if ipv6_router_ids(l3)),
        "flex_algos": sorted({algo for l3 in l3s for algo in flex_algo_ids(l3)}),
        "node_dataplanes": dataplanes,
        "termination_points": sum(len(node_termination_points(n)) for n in nodes),
    }
    if (
        links
        and kinds["isis"] == 0
        and kinds["other"] == 0
        and summary["sr_capable_nodes"] == 0
        and summary["srv6_capable_nodes"] == 0
    ):
        summary["note"] = _L2_ONLY_NOTE
    return summary


def srv6_locator_rows(network: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per node x locator, derived from every ``srv6-node-sid`` in the network.

    Rows are keyed on ``(node-id, locator)`` where the locator is
    :func:`srv6_locator` (the SID masked to lb + ln bits); a SID without a
    structure gets its own row with ``locator`` None. Each row aggregates the
    SIDs' algorithms, endpoint behaviours and IGP instances and keeps the raw
    SID entries under ``sids``. Empty on the SR-MPLS-only lab.
    """
    rows: dict[tuple[str, str | None, str], dict[str, Any]] = {}
    for node in network_nodes(network):
        name = node_id_of(node)
        for kind, entry in igp_instances(node_l3(node)):
            igp = igp_instance_text(kind, entry)
            for sid in srv6_node_sids_of(entry):
                structure = sid_structure(sid)
                sid_value = str(field(sid, "sid", "?"))
                locator = srv6_locator(sid_value, structure)
                key = (name, locator, "" if locator else sid_value)
                row = rows.setdefault(
                    key,
                    {
                        "node": name,
                        "locator": locator,
                        "lb_length": structure["lb"],
                        "ln_length": structure["ln"],
                        "func_length": structure["func"],
                        "arg_length": structure["arg"],
                        "format": sid_format(structure),
                        "algorithms": [],
                        "endpoint_behaviors": [],
                        "igp": [],
                        "sid_count": 0,
                        "sids": [],
                    },
                )
                algorithm = field(sid, "algorithm")
                algorithm = int_or_none(algorithm) if algorithm is not None else None
                if algorithm is not None and algorithm not in row["algorithms"]:
                    row["algorithms"].append(algorithm)
                behavior = field(sid, "endpoint-behavior")
                if behavior is not None and str(behavior) not in row["endpoint_behaviors"]:
                    row["endpoint_behaviors"].append(str(behavior))
                if igp not in row["igp"]:
                    row["igp"].append(igp)
                row["sid_count"] += 1
                row["sids"].append(sid)
    for row in rows.values():
        row["algorithms"].sort()
    return list(rows.values())


# --- Markdown renderers ---------------------------------------------------------


def _paging_note(envelope: dict[str, Any]) -> list[str]:
    if envelope["has_more"]:
        return ["", f"More available: repeat with page={envelope['next_page']}."]
    return []


def _no_nodes_matched_text(dataplane: str | None, srv6_nodes: int) -> str:
    """The "No nodes matched" sentence; the SRv6 clause only when the dataplane filter asked
    for SRv6 ('srv6' / 'both'), and then true to the network: whether ANY node advertises an
    srv6-node-sid (``srv6_nodes``) or none does yet (the SR-MPLS-only lab)."""
    text = (
        "No nodes matched the filter (name is exact, case-insensitive, '*' wildcard; "
        f"dataplane is one of {_DATAPLANE_CHOICES})."
    )
    if dataplane in (DATAPLANE_SRV6, DATAPLANE_BOTH):
        if srv6_nodes:
            text += (
                f" '{dataplane}' matches only nodes advertising srv6-node-sids ({srv6_nodes} in "
                "this network — cnc_list_srv6_locators shows which)."
            )
        else:
            text += (
                f" '{dataplane}' matches nothing here: no node of the network advertises an "
                "srv6-node-sid yet (cnc_list_srv6_locators says what the underlay needs)."
            )
    return text


def _nodes_markdown(
    network_id: str,
    nodes: list[dict[str, Any]],
    envelope: dict[str, Any],
    filtered: bool,
    note: str | None = None,
    dataplane: str | None = None,
    srv6_nodes: int = 0,
) -> str:
    lines = [
        f"# Topology nodes in {network_id} ({envelope['count']} shown, matching "
        f"{envelope['total']}, collection {envelope['collection_total']}; page {envelope['page']})",
        "",
    ]
    if note:
        lines.append(f"No nodes: {note}")
    elif not envelope["collection_total"]:
        lines.append(
            f"No nodes: the platform reports none for network '{network_id}'. Nodes appear "
            "once devices are onboarded and collected (L2) or reported by the SR-PCE feed (L3)."
        )
    elif not nodes and filtered:
        lines.append(_no_nodes_matched_text(dataplane, srv6_nodes))
    lines.extend(node_line(n) for n in nodes)
    lines.extend(_paging_note(envelope))
    lines.append("")
    lines.append(
        "node-id = inventory host_name; reachability and collection state are in "
        "cnc_list_devices. Details per node: cnc_get_topology_node."
    )
    return "\n".join(lines)


def _srv6_sid_text(sid: dict[str, Any]) -> str:
    """``fc00:0:1:: behavior=uN algorithm=0 structure=32/16/16/0 (lb/ln/func/arg)
    locator=fc00:0:1::/48 (uSID F3216)`` — shared by the node-SID and End.X lines."""
    structure = sid_structure(sid)
    locator = srv6_locator(field(sid, "sid"), structure)
    return (
        f"{field(sid, 'sid', '?')} behavior={field(sid, 'endpoint-behavior', '?')} "
        f"algorithm={field(sid, 'algorithm', '?')} structure={structure_text(structure)} "
        f"(lb/ln/func/arg) locator={locator or '?'} ({sid_format(structure)})"
    )


def _srv6_node_sid_lines(l3: dict[str, Any]) -> list[str]:
    """The ``SRv6 node SIDs (N):`` block of a node, one line per SID with its IGP instance.

    Symmetric with the SR-MPLS prefix-SID block: the count is always printed
    and an L3 node without any SRv6 node SID gets an explicit "none" line
    that says what it means (every lab node today).
    """
    entries = [
        (igp_instance_text(kind, entry), sid)
        for kind, entry in igp_instances(l3)
        for sid in srv6_node_sids_of(entry)
    ]
    lines = [f"SRv6 node SIDs ({len(entries)}):"]
    if not entries:
        lines.append(
            "- (none: no srv6-node-sid under the node's IS-IS/OSPF instances — the router "
            "advertises no SRv6 locator in the IGP, or the SR-PCE feed carries no SRv6 state "
            "yet; SR-MPLS is unaffected)"
        )
    lines.extend(f"- {_srv6_sid_text(sid)} via {igp}" for igp, sid in entries)
    return lines


def _flex_algo_lines(l3: dict[str, Any]) -> list[str]:
    """``Flex-Algos (N):`` block — only when the node advertises Flex-Algo definitions."""
    algos = [
        (igp_instance_text(kind, entry), algo)
        for kind, entry in igp_instances(l3)
        for algo in flex_algos_of(entry)
    ]
    if not algos:
        return []
    lines = [f"Flex-Algos ({len(algos)}):"]
    for igp, algo in algos:
        metric = str(field(algo, "metric-type", "?")).rsplit(":", 1)[-1]
        lines.append(
            f"- {field(algo, 'flex-algo-id', '?')} metric-type={metric} "
            f"priority={field(algo, 'priority', '?')} elected={field(algo, 'elected', '?')} "
            f"participated={field(algo, 'participated', '?')} "
            f"include-any={field(algo, 'include-any') or '-'} "
            f"include-all={field(algo, 'include-all') or '-'} "
            f"exclude-any={field(algo, 'exclude-any') or '-'} via {igp}"
        )
    return lines


def _srv6_adjacency_sid_lines(l3: dict[str, Any]) -> list[str]:
    """The ``SRv6 adjacency SIDs (N):`` block of an L3 link (End.X), parallel to the SR-MPLS
    ``Adjacency SIDs`` block; an explicit "none" line when the link carries no End.X SID."""
    sids = srv6_adjacency_sids(l3)
    lines = [f"SRv6 adjacency SIDs ({len(sids)}):"]
    if not sids:
        lines.append(
            "- (none: no End.X SID (srv6-adjacency-sid) advertised on this adjacency — the "
            "routers advertise no SRv6 locator, or the SR-PCE feed carries no SRv6 state yet)"
        )
    for s in sids:
        lines.append(
            f"- {_srv6_sid_text(s)} protected={field(s, 'protected', '?')} "
            f"flags={field(s, 'flags', '?')} weight={field(s, 'weight', '?')}"
        )
    return lines


def _node_markdown(network_id: str, node: dict[str, Any]) -> str:
    l3 = node_l3(node)
    lines = [f"# Topology node {node_id_of(node)} (network {network_id})", "", node_line(node), ""]
    if not l3:
        lines.append(
            "No L3 node attributes: this node is known from L2 (LLDP) discovery only — the "
            "SR-PCE gRPC feed has not reported it (see cnc_get_topology_summary)."
        )
    else:
        lines.append(f"Router IDs: {', '.join(router_ids(l3)) or '-'}")
        ipv6_ids = ipv6_router_ids(l3)
        if ipv6_ids:
            lines.append(f"IPv6 router IDs: {', '.join(ipv6_ids)}")
        isis = isis_of(l3)
        if isis:
            lines.append(
                "IS-IS: "
                + "; ".join(
                    f"level {field(e, 'level', '?')} system-id {field(e, 'system-id', '?')}"
                    for e in isis
                )
            )
        ospf = ospf_of(l3)
        if ospf:
            lines.append(
                "OSPF: "
                + "; ".join(
                    f"router-id {field(e, 'ospf-router-id', '?')} area {ospf_area_text(e)}"
                    for e in ospf
                )
            )
        sr = sr_mpls_of(l3)
        if sr is not None:
            msd = field(sr, "msd")
            lines.append(
                f"SR-MPLS: srgb={_ranges_text(field(sr, 'srgb'))} "
                f"srlb={_ranges_text(field(sr, 'srlb'))} msd={msd if msd is not None else '-'} "
                f"transport={','.join(transport_planes(sr)) or '-'}"
            )
        lines.extend(_srv6_node_sid_lines(l3))
        lines.extend(_flex_algo_lines(l3))
        prefixes = prefixes_of(l3)
        lines.append(f"Prefixes ({len(prefixes)}, {prefix_sid_count(l3)} with SR-MPLS SIDs):")
        if not prefixes:
            lines.append("- (none)")
        for prefix in prefixes:
            sids = prefix_sids_of(prefix)
            if sids:
                srgb_lower = srgb_lower_bound(l3)
                sid_text = ", ".join(
                    f"sid {prefix_sid_label(s, srgb_lower) or '?'} "
                    f"({field(s, 'value-type', '?')} "
                    f"{field(s, 'start-sid', field(s, 'sid', '?'))}) "
                    f"algorithm {field(s, 'algorithm-value', '?')}"
                    for s in sids
                )
            else:
                sid_text = "no SID"
            lines.append(f"- {field(prefix, 'prefix', '?')} -> {sid_text}")
        sessions = pcep_sessions_of(l3)
        # Verified: the feed carries no state leaf (pcc/pce address, capabilities, stateful,
        # msd only). NOT verified: that a down session is omitted — only Up sessions have
        # been observed live — so the header states the fact and the 'none' line marks the
        # omission as an assumption instead of reading 0 as "PCEP down".
        lines.append(f"PCEP sessions ({len(sessions)}; the feed carries no state leaf):")
        if not sessions:
            lines.append(
                "- (none: no PCEP session with the SR-PCE in the feed — a down or "
                "never-established session is presumably absent rather than listed as down "
                "(assumed, not verified live); a configured PCC showing 0 should be checked "
                "on the router (cnc_get_device_backup) and against cnc_list_providers)"
            )
        for s in sessions:
            lines.append(
                f"- pcc {field(s, 'pcc-address', '?')} -> pce {field(s, 'pce-address', '?')} "
                f"stateful={field(s, 'stateful', '?')} sr={field(s, 'capability-sr', '?')} "
                f"update={field(s, 'capability-update', '?')} "
                f"instantiate={field(s, 'capability-instantiate', '?')} msd={field(s, 'msd', '?')}"
            )
        if sessions:
            lines.append(PCE_ADDRESS_NOTE)
    tps = node_termination_points(node)
    lines.append(f"Termination points ({len(tps)}):")
    if not tps:
        lines.append("- (none)")
    lines.extend(tp_line(tp) for tp in tps)
    return "\n".join(lines)


def _interfaces_markdown(network_id: str, node_id: str, tps: list[dict[str, Any]]) -> str:
    lines = [f"# Interfaces of {node_id} in {network_id} ({len(tps)} termination points)", ""]
    if not tps:
        lines.append(f"No termination points: the platform reports none for node '{node_id}'.")
    lines.extend(tp_line(tp) for tp in tps)
    lines.append("")
    lines.append(
        "tp-id is the interface name; pass it verbatim to cnc_get_node_interface. IPs come "
        "from the L3 feed, MAC/unnumbered-id/encapsulation from L2 collection."
    )
    return "\n".join(lines)


def _interface_markdown(network_id: str, node_id: str, tp: dict[str, Any]) -> str:
    lines = [f"# Interface {tp_id_of(tp)} on {node_id} (network {network_id})", "", tp_line(tp)]
    attrs = field(tp, TP_ATTRIBUTES)
    if isinstance(attrs, dict) and attrs:
        lines.extend(["", "Attributes as the platform reports them:", to_json(attrs)])
    return "\n".join(lines)


def _links_markdown(
    network_id: str,
    links: list[dict[str, Any]],
    envelope: dict[str, Any],
    link_type: str,
    node: str | None,
    note: str | None = None,
) -> str:
    scope = f"link_type={link_type}" + (f" node={node}" if node else "")
    lines = [
        f"# Topology links in {network_id} ({envelope['count']} shown, matching "
        f"{envelope['total']}, collection {envelope['collection_total']}; page {envelope['page']}; "
        f"{scope})",
        "",
    ]
    if note:
        lines.append(f"No links: {note}")
    elif not envelope["collection_total"]:
        lines.append(
            f"No links: the platform reports none for network '{network_id}'. L3 "
            f"({LINK_TYPE_ISIS}) links need the SR-PCE gRPC feed; L2 ({LINK_TYPE_ETHERNET}) "
            "links need LLDP collection of the devices."
        )
    elif not links:
        lines.append(f"No links matched {scope}.")
    lines.extend(link_line(link) for link in links)
    lines.extend(_paging_note(envelope))
    lines.append("")
    lines.append(
        "Links are listed once per direction (A->B and B->A are two entries). Link ids are "
        "'<src> : <srcIf> : <dst> : <dstIf> : <TYPE>'; cnc_get_topology_link takes them verbatim."
    )
    return "\n".join(lines)


def _link_markdown(network_id: str, link: dict[str, Any]) -> str:
    src, src_tp, dst, dst_tp = link_ends(link)
    lines = [
        f"# Topology link (network {network_id})",
        "",
        link_line(link),
        "",
        f"link-id: {link_id_of(link)}",
        f"source: {src} / {src_tp}",
        f"destination: {dst} / {dst_tp}",
    ]
    l3 = link_l3(link)
    if l3:
        te = as_dict(field(l3, TE_LINK_ATTRIBUTES))
        isis = as_dict(field(l3, ISIS_LINK_ATTRIBUTES))
        sr = as_dict(field(l3, SR_MPLS))
        lines.append(
            f"L3: name={field(l3, 'name', '-')} metric1={field(l3, 'metric1', '-')} "
            f"metric2={field(l3, 'metric2', '-')} domain-id={field(te, 'domain-id', '-')} "
            f"max-bandwidth-kbps={field(te, 'max-bandwidth-kbps', '-')}"
        )
        if isis:
            net = as_dict(field(isis, "net"))
            lines.append(
                f"IS-IS: level={field(isis, 'level', '-')} system-id={field(net, 'system-id', '-')}"
            )
        ospf = as_dict(field(l3, OSPF_LINK_ATTRIBUTES))
        if ospf:
            lines.append(
                f"OSPF: router-id={field(ospf, 'ospf-router-id', '-')} "
                f"area-id={field(ospf, 'area-id', '-')}"
            )
        for _kind, attrs in link_igp_attributes(l3):
            group = field(as_dict(field(attrs, FLEX_ALGO_LINK_ATTRIBUTES)), "flex-algo-admin-group")
            if group is not None:
                lines.append(f"Flex-Algo admin-group: {group}")
        if sr:
            lines.append(
                f"SR-MPLS: advertise-protection={field(sr, 'advertise-protection', '-')} "
                f"information-source={field(sr, 'information-source', '-')}"
            )
        sids = adjacency_sids(l3)
        lines.append(f"Adjacency SIDs ({len(sids)}):")
        if not sids:
            lines.append("- (none)")
        for s in sids:
            lines.append(
                f"- {field(s, 'sid', '?')} backup={field(s, 'is-backup', '?')} "
                f"persistent={field(s, 'is-persistent', '?')} local={field(s, 'is-local', '?')} "
                f"address-family={field(s, 'address-family', '?')} "
                f"value-type={field(s, 'value-type', '?')}"
            )
        lines.extend(_srv6_adjacency_sid_lines(l3))
    l2 = link_l2(link)
    if l2:
        lines.extend(["L2 attributes as the platform reports them:", to_json(l2)])
    if not l3 and not l2:
        lines.append("The platform reports no L2 or L3 attributes for this link.")
    return "\n".join(lines)


def _srv6_locators_markdown(
    network_id: str,
    rows: list[dict[str, Any]],
    srv6_type: bool,
    nodes: int,
    note: str | None = None,
) -> str:
    """The cnc_list_srv6_locators page: stable phrasing for the SRv6 readiness playbook."""
    presence = "present" if srv6_type else "absent"
    lines = [
        f"# SRv6 locators in {network_id} ({len(rows)} locators on "
        f"{len({r['node'] for r in rows})} of {nodes} nodes; network-types srv6: {presence})",
        "",
    ]
    if note:
        lines.append(f"{NO_SRV6_LOCATORS}: {note}")
    elif not rows:
        why = (
            "network-types carries no srv6"
            if not srv6_type
            else "network-types carries srv6, but no node advertises an srv6-node-sid"
        )
        lines.append(
            f"{NO_SRV6_LOCATORS} ({why}): no node carries a srv6-node-sid under its "
            "IS-IS/OSPF instances, so no locator can be derived."
        )
        lines.append(SRV6_UNDERLAY_HINT)
    for row in rows:
        first_sid = field(row["sids"][0], "sid", "?") if row["sids"] else "?"
        locator = row["locator"] or f"? (sid {first_sid})"
        lb = "?" if row["lb_length"] is None else row["lb_length"]
        ln = "?" if row["ln_length"] is None else row["ln_length"]
        lines.append(
            f"- **{row['node']}** {locator} block/node={lb}/{ln} format={row['format']} "
            f"algorithms={','.join(str(a) for a in row['algorithms']) or '-'} "
            f"behaviors={','.join(row['endpoint_behaviors']) or '-'} sids={row['sid_count']} "
            f"igp={'; '.join(row['igp']) or '-'}"
        )
    lines.append("")
    lines.append(
        "Locators are DERIVED: the 7.2 topology model has no locator object, so each row is a "
        "node's srv6-node-sid masked to lb-length + ln-length bits (block/node). "
        f"'{SID_FORMAT_USID_F3216}' = 32-bit block + 16-bit node id + 16-bit function (the XR "
        f"micro-segment format); '{SID_FORMAT_CLASSIC}' = any other structure; "
        f"'{SID_FORMAT_UNKNOWN}' = the "
        "SID carries no srv6-sid-structure (no locator derivable). Algorithm 0 = SPF, 1 = "
        "strict SPF, 128-255 = Flex-Algo (definitions: cnc_get_topology_node). Per-node SIDs "
        "with their IGP instance: cnc_get_topology_node; End.X SIDs per adjacency: "
        "cnc_get_topology_link; per-locator egress rate: the performance SRV6LOCATOR schema."
    )
    return "\n".join(lines)


# --- Registration ----------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def keyed_get(url: str, missing: PlatformError) -> Any:
        """GET one keyed RESTCONF entry (node or termination point — the network and link
        reads go through the collection, whose keyed GETs are shallow).

        ``missing`` is raised for the platform's not-found spelling — 409
        ``data-missing`` (:func:`is_not_found`). A 404 WITHOUT a RESTCONF error
        document raises :func:`plain_404_error`: on this gateway it means the
        URL is malformed or the NBI prefix is not routed, never that the object
        is absent, and the generic 404 hint would say the opposite. Every other
        failure raises :func:`http_error` with its explanation. A 204 / empty
        body answers ``None`` (an empty container).
        """
        response = await client.request("GET", url, headers=YANG_ACCEPT, raise_on_error=False)
        data: Any = None
        if response.content:
            try:
                data = response.json()
            except ValueError:
                data = None
        if is_not_found(response.status_code, data):
            raise missing
        if response.status_code == 404 and not parse_restconf_errors(data):
            raise plain_404_error(url)
        if not response.is_success:
            raise http_error(response)
        if response.content and data is None:
            raise PlatformError(
                "The topology NBI returned a non-JSON response where YANG JSON was expected."
            )
        return data

    def missing_network(network: str) -> PlatformError:
        return PlatformError(
            f"no network '{network}' on the topology NBI (it answered 409 data-missing for the "
            f"key). The default is '{DEFAULT_NETWORK}'."
        )

    async def fetch_network(network: str) -> FetchedNetwork:
        """The one ``network`` entry for ``network``, from the COLLECTION GET.

        Verified live (2026-09-13): the keyed ``network=<id>`` GET answers a
        SHALLOW copy — nodes carry only ``name``/``router-id`` and the
        ``l3-topology-attributes`` are absent — while the unkeyed
        ``networks`` collection GET carries the full node attributes (IS-IS,
        SRGB/MSD, prefix-SIDs, PCEP sessions) and the topology attributes. So
        the collection is fetched and the id selected client-side (the same
        select_by_field the NBI's key-ignoring behaviour needs anyway): "no
        network" is an error only when OTHER networks are present. An empty
        container (``{}`` / 204 — nothing discovered yet) is answered as a
        placeholder entry with :data:`NO_NETWORKS_NOTE`, so the callers report
        zeros / "No nodes" rather than an error.
        """
        key = network.strip()
        data = await keyed_get(NETWORKS_URL, missing_network(key))
        networks = unwrap_list(data, NETWORK_MODULE, "network")
        matches = select_by_field(networks, "network-id", key)
        if matches:
            return FetchedNetwork(matches[0], None)
        present = [network_id_of(n) for n in networks if isinstance(n, dict)]
        if present:
            raise PlatformError(
                f"no network '{key}' on the topology NBI (the platform answers an unknown "
                f"network id with the whole list, so the id was checked client-side). Networks "
                f"present: {', '.join(present)}. The default is '{DEFAULT_NETWORK}'."
            )
        return FetchedNetwork({"network-id": key}, NO_NETWORKS_NOTE)

    def missing_node(node_id: str, network: str) -> PlatformError:
        return PlatformError(
            f"no node '{node_id}' in topology '{network}'. Node ids are the inventory host names, "
            "exact and case-sensitive; list them with cnc_list_topology_nodes."
        )

    async def fetch_node(network: str, node_id: str) -> dict[str, Any]:
        key = node_id.strip()
        data = await keyed_get(node_url(network, key), missing_node(key, network))
        nodes = select_by_field(unwrap_list(data, NETWORK_MODULE, "node"), "node-id", key)
        if not nodes:
            raise missing_node(key, network)
        return nodes[0]

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_topology_summary",
        title="Get Topology Summary",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_topology_summary(
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
    ) -> str:
        """Summarize one topology network: node and link counts by type, SR-MPLS / SRv6 /
        PCEP coverage.

        Read-only. One ``GET /crosswork/nbi/topology/v3/restconf/data/
        ietf-network-state:networks`` (``Accept: application/
        yang-data+json``), the network selected client-side, then counted.
        Use it first to learn whether the topology is populated and WHICH
        feed populated it:

        - ``links.isis_ipv4_l2`` > 0, ``sr_capable_nodes`` > 0, ``prefix_sids``
          > 0: the SR-PCE gRPC feed is up and the L3 view (IS-IS adjacencies,
          SR-MPLS, IGP metrics, PCEP sessions) is available.
        - links are ALL ``ethernet`` (``isis_ipv4_l2`` = 0, ``sr_capable_nodes``
          = 0): only LLDP (L2) collection is feeding the topology — **the
          SR-PCE gRPC feed is not up** (no SR-PCE provider, no GRPC 57400
          connectivity entry / ROBOT_USERPASS_GRPC credential, or the PCE not
          running lslib-server, 'grpc ... service-layer' and 'pce distribute
          link-state'). The answer carries a ``note`` saying so. Check the
          provider with cnc_list_providers.
        - 0 nodes: nothing has been discovered yet — check onboarding and
          collection with cnc_list_devices. When the NBI has no networks at
          all (an empty container: a fresh instance) every count is 0 and the
          ``note`` says so; that is not an error.

        SRv6 readiness (the ``srv6_*`` / ``flex_algos`` / ``node_dataplanes``
        counters, added 2026-09-15): ``srv6_network_type`` is the
        ``network-types`` srv6 presence container — the cheapest "is there
        SRv6 anywhere" flag; ``srv6_capable_nodes`` counts nodes with at
        least one ``srv6-node-sid`` under an IS-IS/OSPF instance,
        ``srv6_adjacency_links`` the links carrying End.X SIDs
        (``srv6-adjacency-sid``), ``ipv6_router_id_nodes`` the nodes with an
        IPv6 TE router-id and ``flex_algos`` the distinct Flex-Algo ids
        advertised. All of them are 0 / false / [] on an SR-MPLS-only
        network (verified live 2026-09-15: the lab's network-types carries
        only sr-mpls and no node or link carries any srv6 member); the
        member names come from the 7.2 topology model and the counting has
        NOT yet been exercised against a live SRv6 feed. Whether an IPv6
        IS-IS adjacency gets a link-id suffix other than ``ISIS_IPV4_L2``
        is unverified — such links would land in ``links.other``. Locators
        themselves: cnc_list_srv6_locators.

        Device reachability / admin / oper state are not part of the topology
        model: read them with cnc_list_devices (node-id = host_name).

        Args:
            network: topology network id (default 'Default-network').

        Returns:
            str: JSON {"network_id": str, "isis_area": str|null,
            "nodes": int, "links": {"total": int, "isis_ipv4_l2": int,
            "ethernet": int, "other": int} (classified by the link-id suffix
            after the last ' : '), "sr_capable_nodes": int (nodes advertising
            ietf-sr-mpls-topology-state:sr-mpls), "pcep_session_nodes": int
            (nodes with node-pcep-sessions), "prefix_sids": int (prefix
            entries carrying SR-MPLS SIDs), "srv6_network_type": bool,
            "srv6_capable_nodes": int, "srv6_node_sids": int (SRv6 node-SID
            entries in total), "srv6_adjacency_links": int, "ipv6_router_id_nodes":
            int, "flex_algos": [int], "node_dataplanes": {"sr-mpls": int,
            "srv6": int, "both": int, "none": int}, "termination_points": int,
            "note"?: str (present when the topology is L2-only, or when the
            NBI reports no networks yet — then every count is 0)}. A network
            without nodes or links answers zeros, not an error. "Error: no
            network '<id>' ..." when the id is unknown but other networks
            exist (the NBI answers the whole list, checked client-side);
            "Error: ..." on an API failure (400 unknown-element -> the data
            path is wrong for this build; a plain 404 -> the NBI prefix is not
            routed or the URL is malformed, never a missing object).
        """
        try:
            fetched = await fetch_network(network)
            summary = summarize_network(fetched.network)
            if fetched.note:
                summary["note"] = fetched.note
            return finalize(to_json(summary), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_topology_nodes",
        title="List Topology Nodes",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_topology_nodes(
        name: Annotated[
            str | None,
            Field(
                description=(
                    "node-id filter (= inventory host_name), applied client-side: exact match, "
                    "case-insensitive, '*' wildcard (e.g. 'PE1' or 'pe*')."
                ),
                max_length=253,
            ),
        ] = None,
        sr_only: Annotated[
            bool,
            Field(
                description=(
                    "true to keep only nodes advertising SR-MPLS (ietf-sr-mpls-topology-state:"
                    "sr-mpls under their L3 node attributes); the same as dataplane='sr-mpls'."
                )
            ),
        ] = False,
        dataplane: Annotated[
            str | None,
            Field(
                description=(
                    f"Keep nodes by the segment-routing dataplane they advertise, one of: "
                    f"{_DATAPLANE_CHOICES} — 'sr-mpls' = nodes with an SR-MPLS SRGB (dataplane "
                    "sr-mpls or both), 'srv6' = nodes advertising SRv6 node SIDs (srv6 or both), "
                    "'both' = exactly both, 'none' = neither (e.g. 'srv6')."
                ),
                max_length=20,
            ),
        ] = None,
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        page_size: Annotated[
            int, Field(description="Nodes per page, client-side (e.g. 50).", ge=1, le=500)
        ] = 50,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the nodes of a topology network with their IS-IS / SR-MPLS / SRv6 essentials
        and the dataplane each advertises.

        Read-only. The ``node`` sub-list cannot be listed on its own (the NBI
        answers 400 missing-attribute), so the whole network is fetched
        (``GET .../ietf-network-state:networks``, the id selected
        client-side) and the nodes are filtered and paged client-side; every
        call re-downloads the network. A node is a router the topology knows:
        ``node-id`` equals the inventory ``host_name``. Nodes reported by the
        SR-PCE feed carry ``ietf-l3-unicast-topology-state:l3-node-attributes``
        (router-id, IS-IS level/system-id, SR-MPLS SRGB/SRLB/MSD, prefix-SIDs,
        PCEP sessions); nodes known from LLDP collection only have termination
        points and no L3 attributes — they are listed all the same, with '-'
        in the L3 columns. For reachability use cnc_list_devices.

        Dataplane (added 2026-09-15): every row carries ``dataplane=`` —
        ``sr-mpls`` (the node advertises an SRGB), ``srv6`` (at least one
        ``srv6-node-sid`` under an IS-IS/OSPF instance), ``both`` or ``none``
        (an L2-only node) — and ``srv6-sids=<n>`` next to ``prefix-sids=``.
        Verified live on the SR-MPLS-only lab: every L3 node reads
        ``srv6-sids=0 dataplane=sr-mpls``; the SRv6 member names come from
        the 7.2 topology model and no node has yet been seen carrying them
        (they need an SRv6 locator on the routers — cnc_list_srv6_locators
        says what). ``router-id=`` lists the IPv4 TE router-ids, then the
        IPv6 ones (``ipv6-router-id``, spec-only today).

        Args:
            name: node-id filter, exact / case-insensitive / '*' wildcard.
            sr_only: keep only SR-MPLS-capable nodes (= dataplane 'sr-mpls').
            dataplane: sr-mpls | srv6 | both | none (inclusive for the first
                two: a dual-stack node matches 'sr-mpls' and 'srv6').
            network: topology network id.
            page_size, page: client-side paging (page is 0-based).
            response_format: markdown (one line per node: "**<node-id>**
                router-id=<ids> isis=<level>/<system-id> srgb=<lower>-<upper>
                msd=<msd> prefix-sids=<n> srv6-sids=<n> dataplane=<sr-mpls|
                srv6|both|none> pcep=<sessions> tps=<n>") or json (the raw
                node objects).

        Returns:
            str: Markdown, or JSON {"network_id": str, "total": int (matches),
            "count": int, "page": int, "page_size": int, "has_more": bool,
            "next_page": int|null, "collection_total": int (nodes in the
            network), "items": [<node as the NBI returns it: {"node-id",
            "ietf-network-topology-state:termination-point": [...],
            "ietf-l3-unicast-topology-state:l3-node-attributes"?: {...}}],
            "note"?: str (the NBI reports no networks yet)}. "No nodes ..."
            (not an error) when the network has none, nothing matches, or
            the NBI has no networks at all. "Error: Unknown dataplane ..."
            before any request for a value outside the four; "Error: no
            network '<id>' ..." for an unknown network when other networks
            exist; "Error: ..." on an API failure.
        """
        try:
            wanted = normalize_dataplane(dataplane) if dataplane and dataplane.strip() else None
            fetched = await fetch_network(network)
            network_obj = fetched.network
            network_id = network_id_of(network_obj)
            all_nodes = network_nodes(network_obj)
            nodes = all_nodes
            if name is not None and name.strip():
                nodes = [n for n in nodes if node_id_matches(name, field(n, "node-id"))]
            if sr_only:
                nodes = [n for n in nodes if sr_mpls_of(node_l3(n)) is not None]
            if wanted:
                nodes = [n for n in nodes if dataplane_matches(wanted, node_dataplane(node_l3(n)))]
            start = page * page_size
            envelope = page_envelope(
                nodes[start : start + page_size],
                result_count=len(nodes),
                total_count=len(all_nodes),
                page_size=page_size,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                payload: dict[str, Any] = {"network_id": network_id, **envelope}
                if fetched.note:
                    payload["note"] = fetched.note
                return finalize(to_json(payload), settings)
            filtered = bool(name and name.strip()) or sr_only or wanted is not None
            srv6_nodes = sum(1 for n in all_nodes if node_srv6_sids(node_l3(n)))
            return finalize(
                _nodes_markdown(
                    network_id,
                    envelope["items"],
                    envelope,
                    filtered,
                    fetched.note,
                    dataplane=wanted,
                    srv6_nodes=srv6_nodes,
                ),
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_topology_node",
        title="Get Topology Node",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_topology_node(
        node_id: Annotated[
            str,
            Field(
                description=(
                    "Topology node id = inventory host_name, exact and case-sensitive "
                    "(e.g. 'PE1'). List them with cnc_list_topology_nodes."
                ),
                min_length=1,
                max_length=253,
            ),
        ],
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one topology node: router-ids, IS-IS, SR-MPLS, SRv6 node SIDs / locators,
        Flex-Algos, prefix-SIDs, PCEP sessions and termination points.

        Read-only. ``GET .../ietf-network-state:networks/network=<id>/node=
        <node-id>`` (the id percent-encoded as one list key) answers a list of
        one node, re-matched on ``node-id`` client-side (this keyed GET is
        full — verified, unlike the keyed network and link GETs). Use it to
        read a router's SR data (SRGB/SRLB, MSD, its prefix-SID per prefix and
        algorithm), whether it holds a PCEP session with the PCE (PCC nodes
        only: pcc/pce address, stateful, SR/update/instantiate capabilities)
        and its interfaces (termination points with IP, MAC, unnumbered-id).
        A node known from LLDP collection only has termination points and no
        L3 attributes — the markdown says so. Interfaces alone:
        cnc_list_node_interfaces; adjacency: cnc_list_topology_links with
        node=<node-id>.

        SRv6 (added 2026-09-15): the markdown prints, symmetrically with the
        SR-MPLS block, ``SRv6 node SIDs (N):`` — one line per
        ``srv6-node-sid`` of each IS-IS / OSPF instance entry: ``<sid>
        behavior=<endpoint-behavior> algorithm=<n> structure=<lb/ln/func/arg>
        (lb/ln/func/arg) locator=<sid masked to lb+ln bits> (uSID F3216 |
        classic | unknown structure) via IS-IS <level>`` — plus ``IPv6 router
        IDs:`` (``ipv6-router-id``), ``OSPF:`` and ``Flex-Algos (N):``
        (``flex-algo-id metric-type priority elected participated include/
        exclude affinities``) when present, and ``transport=`` on the SR-MPLS
        line (``node-capabilities.transport-planes``, live:
        ``segment-routing-transport-mpls``). What is verified live (SR-MPLS
        lab, 2026-09-15): every L3 node prints ``SRv6 node SIDs (0):`` with an
        explicit "(none: ...)" line and no IPv6 / OSPF / Flex-Algo lines,
        because the feed carries none of these members. What is spec-only
        (7.2 topology model ``cisco-crosswork-srv6-topology-state`` /
        ``cisco-crosswork-flex-algo``, exercised on fixtures): the SID lines
        themselves, the ``uSID F3216`` label (lb 32 + ln 16 + func 16, the
        XR micro-segment format; anything else is ``classic``) and the derived
        locator — the model has no locator object. Whether the SR-PCE feed
        populates them, the exact ``endpoint-behavior`` strings (``uN``,
        ``End`` ...) and whether ``transport=`` ever names an SRv6 plane
        await the SRv6 underlay. All locators at once: cnc_list_srv6_locators.

        PCEP sessions: the feed carries no state leaf (verified — each entry
        is pcc/pce address, the SR / update / instantiate capabilities,
        stateful and msd, nothing else); a down or never-established
        session is presumably absent rather than listed as down — NOT
        verified live (only Up sessions have ever been observed; no down
        PCC session has been seen in the feed). So ``PCEP sessions (0 ...)``
        on a router configured as a PCC most likely means it has no session
        with the SR-PCE right now: check on the router (cnc_get_device_backup,
        its ``pce`` config) and against cnc_list_providers rather than
        reading the 0 alone as "PCEP down"; a P router that never speaks
        PCEP shows 0 as well.
        Session addresses (verified live 2026-09-14): ``pcc-address`` is the
        router's TE router-id (loopback); ``pce-address`` is the address the
        SR-PCE feed identifies itself by — the SR-PCE provider's endpoint
        address as shown by cnc_list_providers (typically the PCE's
        management address), NOT necessarily the ``pce address ipv4
        <loopback>`` peer configured on the router (often the PCE's
        loopback). A mismatch between the two is therefore normal and is not
        a misconfigured peer; the router-side peer address is only visible
        in the device configuration / backup (cnc_get_device_backup).

        Args:
            node_id: exact node-id (no wildcards).
            network: topology network id.
            response_format: markdown (summary line, router-ids, IS-IS,
                SR-MPLS, SRv6 node SIDs, Flex-Algos, prefix table, PCEP
                sessions — "N; the feed carries no state leaf" — one line per
                termination point) or json (the raw node object, SRv6 members
                under their verbatim keys).

        Returns:
            str: Markdown, or the JSON node {"node-id": str,
            "ietf-network-topology-state:termination-point": [{"tp-id",
            "cisco-crosswork-topology-state:termination-point-attributes":
            {"l2-termination-point-attributes": {"unnumbered-id": [],
            "mac-address", "encapsulation-type"},
            "l3-termination-point-attributes": {"ip-address": []}, ...}}],
            "ietf-l3-unicast-topology-state:l3-node-attributes"?: {"name",
            "router-id": [], "cisco-crosswork-l3-te-topology:ipv6-router-id"?:
            [], "cisco-crosswork-isis-topology:isis-node-attributes":
            [{"level", "system-id",
            "cisco-crosswork-srv6-topology-state:srv6-node-sid"?: [{"sid",
            "endpoint-behavior", "algorithm", "srv6-sid-structure":
            {"lb-length", "ln-length", "func-length", "arg-length"}}],
            "cisco-crosswork-flex-algo:flex-algo"?: [{"flex-algo-id",
            "metric-type", "priority", "elected", "participated", ...}]}],
            "cisco-crosswork-ospf-topology:ospf-node-attributes"?: [...],
            "ietf-sr-mpls-topology-state:sr-mpls":
            {"srgb": [{"lower-bound", "upper-bound"}], "srlb": [...], "msd",
            "node-capabilities"}, "prefix": [{"prefix",
            "ietf-sr-mpls-topology-state:sr-mpls": [{"algorithm-value",
            "algorithm", "sid", ...}]}],
            "cisco-crosswork-l3-te-topology:node-pcep-sessions": [{"pcc-address",
            "pce-address", "capability-sr", "capability-update", "stateful",
            "msd", "capability-instantiate"}]}} (the "?" members are the
            SRv6 / IPv6 / OSPF / Flex-Algo ones: 7.2 model, absent live).
            "Error: no node '<id>' in topology '<network>' ..." when the NBI
            answers 409 data-missing (or another node came back); "Error: ..."
            on any other API failure — a plain 404 is a malformed / unrouted
            URL, not a missing node.
        """
        try:
            key = node_id.strip()
            node = await fetch_node(network.strip(), key)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(node), settings)
            return finalize(_node_markdown(network.strip(), node), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_node_interfaces",
        title="List Topology Node Interfaces",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_node_interfaces(
        node_id: Annotated[
            str,
            Field(
                description="Topology node id (= host_name), exact and case-sensitive (e.g. 'P1').",
                min_length=1,
                max_length=253,
            ),
        ],
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the interfaces (termination points) of one topology node.

        Read-only. Reads the node (``GET .../network=<id>/node=<node-id>``,
        the same call as cnc_get_topology_node) and reports its
        ``ietf-network-topology-state:termination-point`` entries: ``tp-id``
        (the interface name, e.g. GigabitEthernet0/0/0/0), IP address(es)
        (from the L3 feed), MAC address, unnumbered-id and encapsulation type
        (from L2 collection). Only interfaces that take part in a discovered
        link or carry topology attributes appear here — this is not the
        device's full interface table. Pass a ``tp-id`` verbatim to
        cnc_get_node_interface for its raw attributes.

        Args:
            node_id: exact node-id.
            network: topology network id.
            response_format: markdown (one line per termination point:
                "<tp-id> ip=<a,b> mac=<mac> unnumbered=<ids> encap=<type>") or
                json (the raw termination-point objects).

        Returns:
            str: Markdown, or JSON {"network_id": str, "node_id": str,
            "count": int, "items": [{"tp-id": str,
            "cisco-crosswork-topology-state:termination-point-attributes":
            {"l2-termination-point-attributes": {...},
            "l3-termination-point-attributes": {"ip-address": [str]},
            "ipv4-termination-point-attributes": {...}}}]}. "No termination
            points ..." (not an error) when the node has none. "Error: no
            node '<id>' ..." when the node does not exist; "Error: ..." on an
            API failure.
        """
        try:
            key = node_id.strip()
            net = network.strip()
            node = await fetch_node(net, key)
            tps = node_termination_points(node)
            if response_format is ResponseFormat.JSON:
                payload = {"network_id": net, "node_id": key, "count": len(tps), "items": tps}
                return finalize(to_json(payload), settings)
            return finalize(_interfaces_markdown(net, node_id_of(node), tps), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_node_interface",
        title="Get Topology Node Interface",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_node_interface(
        node_id: Annotated[
            str,
            Field(
                description=(
                    "Topology node id (= host_name), exact and case-sensitive (e.g. 'PE1')."
                ),
                min_length=1,
                max_length=253,
            ),
        ],
        tp_id: Annotated[
            str,
            Field(
                description=(
                    "Termination-point id = interface name, verbatim as cnc_list_node_interfaces "
                    "prints it (e.g. 'GigabitEthernet0/0/0/0'); the tool URL-encodes it."
                ),
                min_length=1,
                max_length=253,
            ),
        ],
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one interface (termination point) of a topology node.

        Read-only. ``GET .../network=<id>/node=<node-id>/ietf-network-topology-
        state:termination-point=<tp-id>`` — the interface name is
        percent-encoded as one list key (``GigabitEthernet0%2F0%2F0%2F0``; an
        unencoded slash would be a plain 404 from the gateway). Answers the
        termination point's ``tp-id`` and its
        ``cisco-crosswork-topology-state:termination-point-attributes``: L2
        (mac-address, unnumbered-id, encapsulation-type) and L3 / IPv4 / IPv6
        (ip-address lists). Use cnc_list_node_interfaces to find the exact
        ``tp-id``.

        Args:
            node_id: exact node-id.
            tp_id: exact termination-point id (interface name).
            network: topology network id.
            response_format: markdown (the summary line plus the attributes
                block) or json (the raw termination-point object).

        Returns:
            str: Markdown, or the JSON termination point {"tp-id": str,
            "cisco-crosswork-topology-state:termination-point-attributes":
            {"l2-termination-point-attributes": {"unnumbered-id": [int],
            "mac-address": str, "encapsulation-type": str},
            "l3-termination-point-attributes": {"ip-address": [str]},
            "ipv4-termination-point-attributes": {"l3-termination-point-
            attributes": {"ip-address": [str]}}}}. "Error: no interface
            '<tp>' on node '<node>' ..." when the NBI answers 409
            data-missing (the node itself may be the missing part — verify
            with cnc_get_topology_node); "Error: ..." on any other API
            failure (a plain 404 is a malformed / unrouted URL).
        """
        try:
            node_key, tp_key, net = node_id.strip(), tp_id.strip(), network.strip()
            missing = PlatformError(
                f"no interface '{tp_key}' on node '{node_key}' in topology '{net}'. Termination-"
                "point ids are interface names, exact and case-sensitive — list them with "
                "cnc_list_node_interfaces (and verify the node with cnc_get_topology_node)."
            )
            data = await keyed_get(termination_point_url(net, node_key, tp_key), missing)
            tps = select_by_field(
                unwrap_list(data, TOPOLOGY_MODULE, "termination-point"), "tp-id", tp_key
            )
            if not tps:
                raise missing
            tp = tps[0]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(tp), settings)
            return finalize(_interface_markdown(net, node_key, tp), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_topology_links",
        title="List Topology Links",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_topology_links(
        link_type: Annotated[
            str,
            Field(
                description=(
                    f"One of: {_LINK_TYPE_CHOICES} — 'isis' = L3 adjacencies (link ids ending "
                    f"{LINK_TYPE_ISIS}), 'ethernet' = L2/LLDP links (ids ending "
                    f"{LINK_TYPE_ETHERNET}), 'other' = any other suffix (e.g. 'isis')."
                ),
                min_length=1,
                max_length=20,
            ),
        ] = "all",
        node: Annotated[
            str | None,
            Field(
                description=(
                    "Keep links with this node-id at either end: exact, case-insensitive, no "
                    "wildcard (e.g. 'PE1')."
                ),
                max_length=253,
            ),
        ] = None,
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        page_size: Annotated[
            int, Field(description="Links per page, client-side (e.g. 50).", ge=1, le=500)
        ] = 50,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the links of a topology network (IS-IS adjacencies and/or L2 Ethernet links).

        Read-only. The ``link`` sub-list cannot be listed on its own (400
        missing-attribute), so the network is fetched whole (``GET .../
        ietf-network-state:networks``, the id selected client-side — the
        keyed ``network=<id>`` GET is shallow) and filtered / paged
        client-side. **Links are directed and listed once per direction**:
        A->B and B->A are two entries, so a ring of 5 routers shows 10 IS-IS
        links plus 10 Ethernet links. The link id is
        ``"<src> : <srcIf> : <dst> : <dstIf> : <TYPE>"`` with ``TYPE``
        ``ISIS_IPV4_L2`` (L3 adjacency from the SR-PCE feed — carries the IGP
        ``metric1``, the adjacency-SIDs and ``max-bandwidth-kbps``) or
        ``ETHERNET`` (L2 link from LLDP collection — L2 attributes only). A
        topology with only ETHERNET links means the SR-PCE gRPC feed is down
        (cnc_get_topology_summary). For one link's full attributes pass its
        id verbatim to cnc_get_topology_link.

        SRv6 (added 2026-09-15): each L3 row carries ``srv6-adj-sid=<End.X
        sids>`` next to the SR-MPLS ``adj-sid=``, read from
        ``cisco-crosswork-srv6-topology-state:srv6-adjacency-sid[]`` under the
        link's IS-IS / OSPF link attributes (7.2 topology model — the End.X
        SIDs live there, NOT in the SR-MPLS ``sids[]`` list). Verified live
        on the SR-MPLS-only lab: every IS-IS row reads ``srv6-adj-sid=-``;
        the populated form is spec-only (fixtures) until the routers
        advertise SRv6 locators. Whether an IPv6-only adjacency gets a
        link-id suffix other than ``ISIS_IPV4_L2`` is unverified (it would be
        ``link_type='other'``).

        Args:
            link_type: all | isis | ethernet | other.
            node: node-id at either end (exact, case-insensitive).
            network: topology network id.
            page_size, page: client-side paging (page is 0-based).
            response_format: markdown (one line per link: "<src>:<srcIf> ->
                <dst>:<dstIf> [<TYPE>] metric=<metric1> adj-sid=<sids>
                srv6-adj-sid=<End.X sids or -> bw=<max-bandwidth-kbps>kbps"
                for L3, "... [ETHERNET] <l2 attributes>" for L2) or json (the
                raw link objects).

        Returns:
            str: Markdown, or JSON {"network_id": str, "link_type": str,
            "node": str|null, "total": int (matches), "count": int, "page":
            int, "page_size": int, "has_more": bool, "next_page": int|null,
            "collection_total": int (links in the network), "items":
            [{"link-id": str, "source": {"source-node", "source-tp"},
            "destination": {"dest-node", "dest-tp"},
            "ietf-l3-unicast-topology-state:l3-link-attributes"?: {"name",
            "metric1", "ietf-sr-mpls-topology-state:sr-mpls": {"sids": [{"sid",
            "is-backup", "is-persistent", "is-local", ...}], ...},
            "cisco-crosswork-l3-te-topology:l3-link-attributes": {"domain-id",
            "max-bandwidth-kbps"}, "cisco-crosswork-isis-topology:isis-link-
            attributes": {"level", "net": {"system-id"},
            "cisco-crosswork-srv6-topology-state:srv6-adjacency-sid"?: [{"sid",
            "endpoint-behavior", "protected", "flags", "algorithm", "weight",
            "srv6-sid-structure"}]}},
            "ietf-l2-topology-state:l2-link-attributes"?: {...}}], "note"?:
            str (the NBI reports no networks yet)}. "No links ..." (not an
            error) when the network has none, nothing matches, or the NBI has
            no networks at all. "Error: Unknown link_type ..." / "Error: no
            network '<id>' ..." (unknown id while other networks exist) /
            "Error: ..." on an API failure.
        """
        try:
            kind = normalize_link_type(link_type)
            fetched = await fetch_network(network)
            network_obj = fetched.network
            network_id = network_id_of(network_obj)
            all_links = network_links(network_obj)
            links = all_links
            if kind != "all":
                links = [ln for ln in links if classify_link(link_id_of(ln)) == kind]
            node_key = node.strip() if node and node.strip() else None
            if node_key:
                links = [ln for ln in links if link_touches(ln, node_key)]
            start = page * page_size
            envelope = page_envelope(
                links[start : start + page_size],
                result_count=len(links),
                total_count=len(all_links),
                page_size=page_size,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                payload: dict[str, Any] = {
                    "network_id": network_id,
                    "link_type": kind,
                    "node": node_key,
                    **envelope,
                }
                if fetched.note:
                    payload["note"] = fetched.note
                return finalize(to_json(payload), settings)
            return finalize(
                _links_markdown(
                    network_id, envelope["items"], envelope, kind, node_key, fetched.note
                ),
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_topology_link",
        title="Get Topology Link",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_topology_link(
        link_id: Annotated[
            str,
            Field(
                description=(
                    "Link id verbatim as cnc_list_topology_links prints it, spaces and colons "
                    "included (e.g. 'P2 : GigabitEthernet0/0/0/0 : PE2 : GigabitEthernet0/0/0/1 "
                    ": ISIS_IPV4_L2'); matched client-side against the networks collection "
                    "(exact, case-sensitive)."
                ),
                min_length=1,
                max_length=600,
            ),
        ],
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one topology link with all its L3 (IGP metric, SR-MPLS adjacency-SIDs, SRv6
        End.X SIDs, bandwidth, IS-IS / OSPF) or L2 attributes.

        Read-only. Reads the ``networks`` COLLECTION (``GET .../ietf-network-
        state:networks``, the same call as cnc_list_topology_links) and
        selects the link by ``link-id`` client-side, exact and case-sensitive
        — pass the id verbatim as listed (spaces and colons included; A->B and
        B->A are different links). It does NOT use the keyed ``link=<id>``
        GET: verified live 2026-09-15, that keyed answer is SHALLOW and omits
        the link's ``ietf-sr-mpls-topology-state:sr-mpls`` container, so the
        earlier keyed read printed ``adj-sid=-`` / ``Adjacency SIDs (0)`` for
        links whose adjacency SIDs the list tool shows (the fix is in the
        same release as the SRv6 rendering; the End.X list sits in the same
        subtree and is assumed dropped by the keyed GET too). An
        ``ISIS_IPV4_L2`` link carries ``ietf-l3-unicast-topology-state:
        l3-link-attributes`` (name, metric1 = IGP metric, the SR-MPLS
        adjacency ``sids`` with their backup/persistent/local flags,
        ``cisco-crosswork-l3-te-topology:l3-link-attributes`` domain-id and
        max-bandwidth-kbps, IS-IS level and neighbour system-id); an
        ``ETHERNET`` link carries ``ietf-l2-topology-state:l2-link-attributes``
        only. Per-link performance metrics (utilisation, delay) are a separate
        keyed read on the same NBI and exist for IGP links only.

        SRv6 (added 2026-09-15): after the SR-MPLS ``Adjacency SIDs (N):``
        block the markdown prints ``SRv6 adjacency SIDs (N):`` — one line
        per End.X entry of ``cisco-crosswork-srv6-topology-state:
        srv6-adjacency-sid[]`` under the IS-IS / OSPF link attributes:
        ``<sid> behavior=<endpoint-behavior> algorithm=<n> structure=<lb/ln/
        func/arg> (lb/ln/func/arg) locator=<derived> (<format>)
        protected=<bool> flags=<n> weight=<n>`` — plus ``OSPF:`` and
        ``Flex-Algo admin-group:`` lines when present. Verified live on the
        SR-MPLS-only lab: every IS-IS link prints ``SRv6 adjacency SIDs
        (0):`` with an explicit "(none: ...)" line; the populated lines are
        spec-only (7.2 model, fixtures) until the routers advertise SRv6
        locators — the ``endpoint-behavior`` strings the feed emits (``uA``,
        ``End.X`` ...) and the ``flags`` encoding await the underlay.

        Args:
            link_id: exact link id (directed: A->B and B->A are different links).
            network: topology network id.
            response_format: markdown (summary line, endpoints, L3 / IS-IS /
                OSPF / SR-MPLS lines, adjacency-SID table, SRv6 adjacency-SID
                table, or the L2 attributes) or json (the raw link object as
                the collection carries it).

        Returns:
            str: Markdown, or the JSON link {"link-id": str, "source":
            {"source-node", "source-tp"}, "destination": {"dest-node",
            "dest-tp"}, "ietf-l3-unicast-topology-state:l3-link-attributes"?:
            {"name", "metric1", "ietf-sr-mpls-topology-state:sr-mpls":
            {"advertise-protection", "sids": [{"sid", "is-backup",
            "is-persistent", "is-on-lan", "value-type", "is-local",
            "address-family", "is-part-of-set"}], "information-source"},
            "cisco-crosswork-l3-te-topology:l3-link-attributes": {"domain-id",
            "max-bandwidth-kbps"}, "cisco-crosswork-isis-topology:isis-link-
            attributes": {"level", "net": {"system-id"},
            "cisco-crosswork-srv6-topology-state:srv6-adjacency-sid"?: [{"sid",
            "endpoint-behavior", "protected", "flags", "algorithm", "weight",
            "srv6-sid-structure": {"lb-length", "ln-length", "func-length",
            "arg-length"}}], "cisco-crosswork-flex-algo:link-attributes"?:
            {"flex-algo-admin-group"}}},
            "ietf-l2-topology-state:l2-link-attributes"?: {...}}.
            "Error: no link '<id>' in topology '<network>' ..." when no link
            of the network carries that id (checked client-side against the
            collection; cnc_list_topology_links shows the exact ids), also
            when the NBI reports no networks yet; "Error: no network '<id>'
            ..." for an unknown network when other networks exist; "Error:
            ..." on any other API failure — a plain 404 means the topology
            NBI is not routed on this instance (the id is never put in a
            URL), not that the link is missing.
        """
        try:
            key = link_id.strip()
            fetched = await fetch_network(network)
            net = network_id_of(fetched.network)
            links = select_by_field(network_links(fetched.network), "link-id", key)
            if not links:
                if fetched.note:
                    raise PlatformError(f"no link '{key}' in topology '{net}': {fetched.note}")
                raise PlatformError(
                    f"no link '{key}' in topology '{net}' (the network's "
                    f"{len(network_links(fetched.network))} links were checked client-side). "
                    "cnc_list_topology_links shows the exact ids — they contain spaces and "
                    "colons ('<src> : <srcIf> : <dst> : <dstIf> : <TYPE>'), are directed (A->B "
                    "and B->A differ) and must be passed verbatim."
                )
            link = links[0]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(link), settings)
            return finalize(_link_markdown(net, link), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_srv6_locators",
        title="List SRv6 Locators",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_srv6_locators(
        network: Annotated[str, _NETWORK_FIELD] = DEFAULT_NETWORK,
        response_format: Annotated[ResponseFormat, _FORMAT_FIELD] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the SRv6 locators advertised in a topology network, one row per node x
        locator, derived from the nodes' SRv6 node SIDs.

        Read-only. One ``GET .../ietf-network-state:networks`` (the network
        selected client-side, as every topology read), then every
        ``cisco-crosswork-srv6-topology-state:srv6-node-sid`` under each
        node's IS-IS / OSPF instance entries is folded into locators. **The
        7.2 topology model has no locator object**: a locator here is the
        SID masked to ``lb-length + ln-length`` bits of its
        ``srv6-sid-structure`` (``fc00:0:1::`` with lb 32 / ln 16 ->
        ``fc00:0:1::/48``), labelled ``uSID F3216`` for lb 32 + ln 16 + func
        16 (the XR micro-segment format: 32-bit block, 16-bit node id,
        16-bit function; a structure without func-length passes on lb/ln)
        and ``classic`` for any other structure; a SID without a structure gets
        its own row with locator ``?`` (``unknown structure``). Each row
        aggregates the SIDs of that node x locator: the algorithms (0 = SPF,
        1 = strict SPF, 128-255 = Flex-Algo), the endpoint behaviours seen
        (``uN``, ``End`` ... as the feed spells them), the IGP instances and
        the SID count. Use it first in an SRv6 readiness check: the
        network-level ``network-types`` srv6 presence flag is in the header,
        and an empty answer says exactly why.

        Verification status: the "no locators" answer is verified live on
        the SR-MPLS-only lab (2026-09-15: ``network-types`` carries only
        ``sr-mpls`` and no node has an ``srv6-node-sid``); the populated rows
        follow the 7.2 topology model (member names, uint32 lengths parsed
        as int or string) and are exercised on fixtures only — which of the
        members the SR-PCE feed populates, and the behaviour strings it
        emits, await the SRv6 underlay (locators on the routers, IS-IS IPv6
        advertising them, the gRPC feed carrying them).

        Args:
            network: topology network id (default 'Default-network').
            response_format: markdown (header "# SRv6 locators in <network>
                (<n> locators on <m> of <k> nodes; network-types srv6:
                present|absent)", one line per row "**<node>** <locator>
                block/node=<lb>/<ln> format=<uSID F3216|classic|unknown
                structure> algorithms=<a,b> behaviors=<x,y> sids=<n>
                igp=<IS-IS level-2; ...>", or the stable sentence "No SRv6
                locators are advertised in the topology (network-types
                carries no srv6): ..." followed by what the underlay needs)
                or json (the rows with the raw SID entries).

        Returns:
            str: Markdown, or JSON {"network_id": str, "srv6_network_type":
            bool (the network-types srv6 presence container), "nodes": int
            (nodes in the network), "count": int (rows), "items": [{"node":
            str, "locator": str|null (CIDR), "lb_length", "ln_length",
            "func_length", "arg_length": int|null, "format": "uSID F3216" |
            "classic" | "unknown structure", "algorithms": [int],
            "endpoint_behaviors": [str], "igp": [str], "sid_count": int,
            "sids": [<srv6-node-sid entries verbatim>]}], "note"?: str (the
            NBI reports no networks yet)}. "No SRv6 locators ..." (not an
            error) when no node advertises an SRv6 node SID — the case on an
            SR-MPLS-only network — or the NBI has no networks at all.
            "Error: no network '<id>' ..." for an unknown network when other
            networks exist; "Error: ..." on an API failure.
        """
        try:
            fetched = await fetch_network(network)
            network_obj = fetched.network
            network_id = network_id_of(network_obj)
            rows = srv6_locator_rows(network_obj)
            srv6_type = srv6_network_type(network_obj)
            nodes = len(network_nodes(network_obj))
            if response_format is ResponseFormat.JSON:
                payload: dict[str, Any] = {
                    "network_id": network_id,
                    "srv6_network_type": srv6_type,
                    "nodes": nodes,
                    "count": len(rows),
                    "items": rows,
                }
                if fetched.note:
                    payload["note"] = fetched.note
                return finalize(to_json(payload), settings)
            return finalize(
                _srv6_locators_markdown(network_id, rows, srv6_type, nodes, fetched.note),
                settings,
            )
        except Exception as e:
            return format_error(e)
