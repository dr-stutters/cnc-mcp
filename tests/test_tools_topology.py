"""Topology tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the shapes verified live on the Crosswork 7.2 topology NBI
(2026-09-13, see the platform notes "Topology NBI"): the ``ietf-network-state``
network with its five lab nodes (PE1, P1, PE2, P2, PCE), IS-IS / SR-MPLS node
attributes, a PCEP session and prefix-SIDs on the PE nodes, termination points
under ``cisco-crosswork-topology-state:termination-point-attributes``, and
links listed once per direction with ids ending ``ISIS_IPV4_L2`` (L3, from
the SR-PCE feed) or ``ETHERNET`` (L2, from LLDP). Error documents use the
bare ``errors`` key the NBI answers with. Attribute VALUES are illustrative;
the member names and nesting are the verified ones.

SRv6 fixtures (2026-09-15) are SPEC-SHAPED: the lab is SR-MPLS only, so the
``cisco-crosswork-srv6-topology-state`` / ``cisco-crosswork-flex-algo`` /
``ipv6-router-id`` members below follow the 7.2 topology OpenAPI (member
names, nesting under the IS-IS / OSPF instance entries, uint32 leaves) in the
RFC 7951 wire spelling the live SR-MPLS members use — none of them has been
seen live yet. The two live link captures (``LIVE_LINK_KEYED`` /
``LIVE_LINK_FULL``) ARE verbatim wire shapes: the keyed ``link=<id>`` GET is
shallow (no ``sr-mpls``), the collection carries the adjacency SID.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

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
from cnc_mcp.tools import topology
from cnc_mcp.tools.topology import (
    NO_NETWORKS_NOTE,
    NO_SRV6_LOCATORS,
    all_router_ids,
    classify_link,
    dataplane_matches,
    field,
    igp_instance_text,
    link_type_of,
    node_dataplane,
    node_id_matches,
    normalize_dataplane,
    normalize_link_type,
    plain_404_error,
    select_by_field,
    sid_format,
    sid_structure,
    srv6_locator,
    srv6_locator_rows,
    structure_text,
    summarize_network,
    tp_summary,
    transport_planes,
)
from tests.conftest import BASE_URL, call_tool_text

YANG_JSON = "application/yang-data+json"
NETWORKS_URL = f"{BASE_URL}/crosswork/nbi/topology/v3/restconf/data/ietf-network-state:networks"
# Every network fetch is the COLLECTION GET: the keyed network=<id> GET answers a shallow
# copy (nodes without IS-IS/SR attributes, no topology attributes) — verified live.
NETWORK_URL = NETWORKS_URL


def node_url(encoded_node: str, network: str = "Default-network") -> str:
    return f"{NETWORKS_URL}/network={network}/node={encoded_node}"


def tp_url(encoded_node: str, encoded_tp: str) -> str:
    return f"{node_url(encoded_node)}/ietf-network-topology-state:termination-point={encoded_tp}"


def link_url(encoded_link: str, network: str = "Default-network") -> str:
    return f"{NETWORKS_URL}/network={network}/ietf-network-topology-state:link={encoded_link}"


# --- Fixtures (verified shapes) --------------------------------------------------

TP_ATTRS = "cisco-crosswork-topology-state:termination-point-attributes"
L3_NODE = "ietf-l3-unicast-topology-state:l3-node-attributes"
SR_MPLS = "ietf-sr-mpls-topology-state:sr-mpls"
SPF_ALGORITHM = "ietf-segment-routing-common:prefix-sid-algorithm-shortest-path"
PCEP = "cisco-crosswork-l3-te-topology:node-pcep-sessions"
L3_LINK = "ietf-l3-unicast-topology-state:l3-link-attributes"
L2_LINK = "ietf-l2-topology-state:l2-link-attributes"
LINK_LIST = "ietf-network-topology-state:link"
TP_LIST = "ietf-network-topology-state:termination-point"


def tp(tp_id: str, ip: str | None, mac: str, unnumbered: int) -> dict[str, Any]:
    """A termination point as the NBI returns it (L2 attrs always, L3/IPv4 when the feed
    reported an address)."""
    attrs: dict[str, Any] = {
        "l2-termination-point-attributes": {
            "unnumbered-id": [unnumbered],
            "mac-address": mac,
            "encapsulation-type": "ethernet",
        }
    }
    if ip:
        attrs["l3-termination-point-attributes"] = {"ip-address": [ip]}
        attrs["ipv4-termination-point-attributes"] = {
            "l3-termination-point-attributes": {"ip-address": [ip]}
        }
    return {"tp-id": tp_id, TP_ATTRS: attrs}


def l3_attributes(node_id: str, index: int, pcep: bool) -> dict[str, Any]:
    router_id = f"10.0.0.{index}"
    attrs: dict[str, Any] = {
        "name": node_id,
        "router-id": [router_id],
        "cisco-crosswork-isis-topology:isis-node-attributes": [
            {"level": "level-2", "system-id": f"0000.0000.000{index}"}
        ],
        SR_MPLS: {
            "srgb": [{"lower-bound": 16000, "upper-bound": 23999}],
            "srlb": [{"lower-bound": 15000, "upper-bound": 15999}],
            "msd": 10,
            "node-capabilities": {"transport-planes": [{"transport-plane": "sr-mpls"}]},
        },
        "prefix": [
            {
                "prefix": f"{router_id}/32",
                SR_MPLS: [
                    {  # verified shape: an SRGB index; the label is lower-bound + start-sid
                        "algorithm-value": 0,
                        "algorithm": SPF_ALGORITHM,
                        "value-type": "index",
                        "is-local": False,
                        "range": 1,
                        "last-hop-behavior": "php",
                        "is-node": True,
                        "start-sid": index,
                    }
                ],
            },
            # A connected prefix without a SID: must not count as a prefix-SID.
            {"prefix": f"10.1.{index}.0/30"},
        ],
    }
    if pcep:
        attrs[PCEP] = [
            {
                "pcc-address": router_id,
                "pce-address": "10.0.0.5",
                "capability-sr": True,
                "capability-update": True,
                "stateful": True,
                "msd": 10,
                "capability-instantiate": True,
            }
        ]
    return attrs


def l3_node(node_id: str, index: int, tps: list[dict[str, Any]], pcep: bool = False) -> dict:
    return {"node-id": node_id, TP_LIST: tps, L3_NODE: l3_attributes(node_id, index, pcep)}


def l2_node(node_id: str, tps: list[dict[str, Any]]) -> dict[str, Any]:
    """A node known from LLDP only (what the lab showed before the gRPC feed was up)."""
    return {"node-id": node_id, TP_LIST: tps}


GI0 = "GigabitEthernet0/0/0/0"
GI1 = "GigabitEthernet0/0/0/1"
PE1_TPS = [tp(GI0, "10.1.1.1", "02:42:0a:01:01:01", 3), tp(GI1, "10.1.4.2", "02:42:0a:01:04:02", 4)]
P1_TPS = [tp(GI0, "10.1.1.2", "02:42:0a:01:01:02", 3), tp(GI1, "10.1.2.1", "02:42:0a:01:02:01", 4)]
PE2_TPS = [tp(GI0, "10.1.2.2", "02:42:0a:01:02:02", 3), tp(GI1, "10.1.3.2", "02:42:0a:01:03:02", 4)]
P2_TPS = [tp(GI0, "10.1.3.1", "02:42:0a:01:03:01", 3), tp(GI1, "10.1.4.1", "02:42:0a:01:04:01", 4)]
PCE_TPS = [tp(GI0, "10.1.5.2", "02:42:0a:01:05:02", 3)]

PE1 = l3_node("PE1", 1, PE1_TPS, pcep=True)
P1 = l3_node("P1", 2, P1_TPS)
PE2 = l3_node("PE2", 3, PE2_TPS, pcep=True)
P2 = l3_node("P2", 4, P2_TPS)
PCE = l3_node("PCE", 5, PCE_TPS)


def link_id(src: str, src_tp: str, dst: str, dst_tp: str, kind: str) -> str:
    return f"{src} : {src_tp} : {dst} : {dst_tp} : {kind}"


def isis_link(
    src: str, src_tp: str, dst: str, dst_tp: str, sid: int, neighbour_sysid: str
) -> dict[str, Any]:
    """An L3 adjacency as the SR-PCE feed reports it (metric1 / max-bandwidth-kbps are
    strings on the wire)."""
    return {
        "link-id": link_id(src, src_tp, dst, dst_tp, "ISIS_IPV4_L2"),
        "source": {"source-node": src, "source-tp": src_tp},
        "destination": {"dest-node": dst, "dest-tp": dst_tp},
        L3_LINK: {
            "name": f"{src}-{dst}",
            "metric1": "10",
            SR_MPLS: {
                "advertise-protection": "unprotected",
                "sids": [
                    {
                        "sid": sid,
                        "is-backup": False,
                        "is-persistent": False,
                        "is-on-lan": False,
                        "value-type": "absolute",
                        "is-local": True,
                        "address-family": "ipv4",
                        "is-part-of-set": False,
                    }
                ],
                "information-source": "isis",
            },
            "cisco-crosswork-l3-te-topology:l3-link-attributes": {
                "domain-id": "0",
                "max-bandwidth-kbps": "1000000",
            },
            "cisco-crosswork-isis-topology:isis-link-attributes": {
                "level": 2,
                "net": {"system-id": neighbour_sysid},
            },
        },
    }


def ethernet_link(src: str, src_tp: str, dst: str, dst_tp: str) -> dict[str, Any]:
    """An L2 link from LLDP collection: L2 attributes only."""
    return {
        "link-id": link_id(src, src_tp, dst, dst_tp, "ETHERNET"),
        "source": {"source-node": src, "source-tp": src_tp},
        "destination": {"dest-node": dst, "dest-tp": dst_tp},
        L2_LINK: {"rate": 1000000, "delay": 0},
    }


# The verified example ids: "PE1 : Gi0/0/0/0 : P1 : Gi0/0/0/0 : ETHERNET" and
# "P2 : Gi0/0/0/0 : PE2 : Gi0/0/0/1 : ISIS_IPV4_L2"; every link once per direction.
LINK_PE1_P1 = isis_link("PE1", GI0, "P1", GI0, 24003, "0000.0000.0002")
LINK_P1_PE1 = isis_link("P1", GI0, "PE1", GI0, 24004, "0000.0000.0001")
LINK_P2_PE2 = isis_link("P2", GI0, "PE2", GI1, 24005, "0000.0000.0003")
LINK_PE2_P2 = isis_link("PE2", GI1, "P2", GI0, 24006, "0000.0000.0004")
ETH_PE1_P1 = ethernet_link("PE1", GI0, "P1", GI0)
ETH_P1_PE1 = ethernet_link("P1", GI0, "PE1", GI0)
ETH_P2_PE2 = ethernet_link("P2", GI0, "PE2", GI1)
LINKS = [LINK_PE1_P1, LINK_P1_PE1, LINK_P2_PE2, LINK_PE2_P2, ETH_PE1_P1, ETH_P1_PE1, ETH_P2_PE2]
P2_PE2_ISIS_ID = LINK_P2_PE2["link-id"]
P2_PE2_ISIS_ENCODED = quote(P2_PE2_ISIS_ID, safe="")

NETWORK = {
    "network-id": "Default-network",
    "network-types": {
        "ietf-l3-unicast-topology-state:l3-unicast-topology": {
            "cisco-crosswork-isis-topology:isis": {},
            SR_MPLS: {},
        },
        "ietf-l2-topology-state:l2-topology": {},
    },
    "ietf-l3-unicast-topology-state:l3-topology-attributes": {
        "cisco-crosswork-isis-topology:isis-topology-attributes": {"area": "49.0001"}
    },
    "node": [PE1, P1, PE2, P2, PCE],
    LINK_LIST: LINKS,
}
# Verified: GET network=<known id> answers a list of one.
NETWORK_COLLECTION = {"ietf-network-state:networks": {"network": [NETWORK]}}
# Verified: GET network=<unknown id> ignores the key and answers the WHOLE container.
# (The tools now always fetch the container and select the id client-side.)
NETWORKS_WHOLE = {"ietf-network-state:networks": {"network": [NETWORK]}}
# The lab before the gRPC feed: nodes from LLDP only, ETHERNET links only.
L2_ONLY_NETWORK = {
    "network-id": "Default-network",
    "node": [l2_node("PE1", PE1_TPS), l2_node("P1", P1_TPS)],
    LINK_LIST: [ETH_PE1_P1, ETH_P1_PE1],
}
L2_ONLY_COLLECTION = {"ietf-network-state:networks": {"network": [L2_ONLY_NETWORK]}}
# A network with neither nodes nor links (fresh instance).
EMPTY_NETWORK_COLLECTION = {
    "ietf-network-state:networks": {"network": [{"network-id": "Default-network"}]}
}
# SYNTHETIC: a link whose type suffix is neither of the two verified ones.
OTHER_LINK = {
    "link-id": link_id("PE1", "Loopback0", "PE2", "Loopback0", "BGP_EPE"),
    "source": {"source-node": "PE1", "source-tp": "Loopback0"},
    "destination": {"dest-node": "PE2", "dest-tp": "Loopback0"},
}
MIXED_NETWORK_COLLECTION = {
    "ietf-network-state:networks": {"network": [{**NETWORK, LINK_LIST: [*LINKS, OTHER_LINK]}]}
}

# --- SRv6 fixtures: SPEC-SHAPED (7.2 topology OpenAPI, wire spelling), never seen live -----

SRV6_MODULE = "cisco-crosswork-srv6-topology-state"
SRV6_NODE_SID = f"{SRV6_MODULE}:srv6-node-sid"
SRV6_ADJ_SID = f"{SRV6_MODULE}:srv6-adjacency-sid"
SRV6_STRUCTURE = f"{SRV6_MODULE}:srv6-sid-structure"
SRV6_TYPE = f"{SRV6_MODULE}:srv6"
ISIS_NODE = "cisco-crosswork-isis-topology:isis-node-attributes"
OSPF_NODE = "cisco-crosswork-ospf-topology:ospf-node-attributes"
FLEX_ALGO = "cisco-crosswork-flex-algo:flex-algo"
FLEX_ALGO_LINK = "cisco-crosswork-flex-algo:link-attributes"
IPV6_ROUTER_ID = "cisco-crosswork-l3-te-topology:ipv6-router-id"
ISIS_LINK = "cisco-crosswork-isis-topology:isis-link-attributes"
OSPF_LINK = "cisco-crosswork-ospf-topology:ospf-link-attributes"

USID_STRUCTURE = {"lb-length": 32, "ln-length": 16, "func-length": 16, "arg-length": 0}


def srv6_node_sid(sid: str, algorithm: int, behavior: str = "uN") -> dict[str, Any]:
    return {
        "sid": sid,
        "endpoint-behavior": behavior,
        "algorithm": algorithm,
        SRV6_STRUCTURE: dict(USID_STRUCTURE),
    }


FLEX_ALGO_128 = {
    "flex-algo-id": 128,
    "metric-type": "cisco-crosswork-flex-algo:te-metric",
    "priority": 100,
    "exclude-any": "0x2",
    "include-any": "",
    "include-all": "",
    "elected": True,
    "participated": True,
}


def srv6_l3_node(node_id: str, index: int, sr_mpls: bool, pcep: bool = False) -> dict[str, Any]:
    """The maintainer's planned uSID underlay: locator fc00:0:<n>::/48 (F3216) on algorithm
    0, a second locator fc00:1:<n>::/48 for Flex-Algo 128, IPv6 loopback 2001:db8::<n>."""
    attrs = l3_attributes(node_id, index, pcep)
    attrs[IPV6_ROUTER_ID] = [f"2001:db8::{index}"]
    attrs[ISIS_NODE] = [
        {
            "level": "level-2",
            "system-id": f"0000.0000.000{index}",
            SRV6_NODE_SID: [
                srv6_node_sid(f"fc00:0:{index}::", 0),
                srv6_node_sid(f"fc00:1:{index}::", 128),
            ],
            FLEX_ALGO: [FLEX_ALGO_128],
        }
    ]
    if not sr_mpls:
        del attrs[SR_MPLS]
        attrs["prefix"] = [{"prefix": f"2001:db8::{index}/128"}]
    return {"node-id": node_id, TP_LIST: PE1_TPS if index == 1 else P1_TPS, L3_NODE: attrs}


# PE1: SR-MPLS + SRv6 (dataplane both); P1: SRv6 only; PE2: SR-MPLS only; SW1: L2 only.
PE1_SRV6 = srv6_l3_node("PE1", 1, sr_mpls=True, pcep=True)
P1_SRV6 = srv6_l3_node("P1", 2, sr_mpls=False)
SW1 = l2_node("SW1", PCE_TPS)
# An OSPF node whose SID has the OpenAPI (fully prefixed) spelling, string-typed lengths
# and a classic (non-F3216) structure: proves field() tolerance and the classic label.
P3_OSPF_CLASSIC = {
    "node-id": "P3",
    TP_LIST: P2_TPS,
    L3_NODE: {
        "name": "P3",
        "router-id": ["10.0.0.6"],
        OSPF_NODE: [
            {
                "ospf-router-id": "10.0.0.6",
                "area-id": ["0.0.0.0"],
                SRV6_NODE_SID: [
                    {
                        f"{SRV6_MODULE}:sid": "2001:db8:6::",
                        f"{SRV6_MODULE}:endpoint-behavior": "End",
                        f"{SRV6_MODULE}:algorithm": "0",
                        SRV6_STRUCTURE: {
                            f"{SRV6_MODULE}:lb-length": "40",
                            f"{SRV6_MODULE}:ln-length": "24",
                            f"{SRV6_MODULE}:func-length": "16",
                            f"{SRV6_MODULE}:arg-length": "0",
                        },
                    }
                ],
            }
        ],
    },
}


def srv6_isis_link(
    src: str, src_tp: str, dst: str, dst_tp: str, sid: int, neighbour_sysid: str, index: int
) -> dict[str, Any]:
    """An IS-IS adjacency carrying both an SR-MPLS adjacency SID and an SRv6 End.X SID
    (the End.X list sits under the IS-IS link attributes, NOT under sr-mpls.sids)."""
    link = isis_link(src, src_tp, dst, dst_tp, sid, neighbour_sysid)
    link[L3_LINK][ISIS_LINK][SRV6_ADJ_SID] = [
        {
            "sid": f"fc00:0:{index}:e000::",
            "endpoint-behavior": "uA",
            "protected": False,
            "flags": 0,
            "algorithm": 0,
            "weight": 0,
            SRV6_STRUCTURE: dict(USID_STRUCTURE),
        }
    ]
    link[L3_LINK][ISIS_LINK][FLEX_ALGO_LINK] = {"flex-algo-admin-group": "0x1"}
    return link


SRV6_LINK_PE1_P1 = srv6_isis_link("PE1", GI0, "P1", GI0, 24003, "0000.0000.0002", 1)
SRV6_LINK_P1_PE1 = srv6_isis_link("P1", GI0, "PE1", GI0, 24004, "0000.0000.0001", 2)


def srv6_ospf_link(src: str, src_tp: str, dst: str, dst_tp: str, index: int) -> dict[str, Any]:
    """An OSPF adjacency in the 7.2 model: ``ospf-link-attributes`` carries ``ospf-router-id``,
    a STRING ``area-id``, the End.X list and the flex-algo link attributes (the OpenAPI has
    all four as siblings there); no ``sr-mpls`` container — an SRv6-only adjacency with a
    classic 40/24 structure. The link-id suffix is SYNTHETIC: what CNC appends to an OSPF
    link id is unverified (the lab is IS-IS only), so the tool classifies it 'other'."""
    return {
        "link-id": link_id(src, src_tp, dst, dst_tp, "OSPF_IPV4"),
        "source": {"source-node": src, "source-tp": src_tp},
        "destination": {"dest-node": dst, "dest-tp": dst_tp},
        L3_LINK: {
            "name": f"{src}-{dst}",
            "metric1": "20",
            "cisco-crosswork-l3-te-topology:l3-link-attributes": {
                "domain-id": "0",
                "max-bandwidth-kbps": "1000000",
            },
            OSPF_LINK: {
                "ospf-router-id": f"10.0.0.{index}",
                "area-id": "0.0.0.0",
                SRV6_ADJ_SID: [
                    {
                        "sid": f"2001:db8:{index}:0:e000::",
                        "endpoint-behavior": "End.X",
                        "protected": True,
                        "flags": 0,
                        "algorithm": 0,
                        "weight": 0,
                        SRV6_STRUCTURE: {
                            "lb-length": 40,
                            "ln-length": 24,
                            "func-length": 16,
                            "arg-length": 0,
                        },
                    }
                ],
                FLEX_ALGO_LINK: {"flex-algo-admin-group": "0x2"},
            },
        },
    }


SRV6_OSPF_LINK_P3_PE2 = srv6_ospf_link("P3", GI1, "PE2", GI1, 6)
SRV6_NETWORK = {
    "network-id": "Default-network",
    "network-types": {
        "ietf-l3-unicast-topology-state:l3-unicast-topology": {
            "cisco-crosswork-isis-topology:isis": {},
            SR_MPLS: {},
            SRV6_TYPE: {},
        },
        "ietf-l2-topology-state:l2-topology": {},
    },
    "ietf-l3-unicast-topology-state:l3-topology-attributes": {
        "cisco-crosswork-isis-topology:isis-topology-attributes": {"area": "49.0001"}
    },
    "node": [PE1_SRV6, P1_SRV6, PE2, SW1, P3_OSPF_CLASSIC],
    LINK_LIST: [
        SRV6_LINK_PE1_P1,
        SRV6_LINK_P1_PE1,
        LINK_P2_PE2,
        ETH_PE1_P1,
        SRV6_OSPF_LINK_P3_PE2,
    ],
}
SRV6_NETWORK_COLLECTION = {"ietf-network-state:networks": {"network": [SRV6_NETWORK]}}

# --- Live captures (verbatim, 2026-09-15): the keyed link GET is shallow -------------------

LIVE_LINK_ID = "PE1 : GigabitEthernet0/0/0/0 : P1 : GigabitEthernet0/0/0/0 : ISIS_IPV4_L2"
# GET .../network=Default-network/ietf-network-topology-state:link=<id>: NO sr-mpls container.
LIVE_LINK_KEYED = {
    "link-id": LIVE_LINK_ID,
    L3_LINK: {
        "name": LIVE_LINK_ID,
        "metric1": "10",
        "cisco-crosswork-l3-te-topology:l3-link-attributes": {
            "domain-id": "0",
            "max-bandwidth-kbps": "1000000",
        },
        ISIS_LINK: {"level": 2, "net": {"system-id": "0000.0000.0001"}},
    },
    "source": {"source-node": "PE1", "source-tp": GI0},
    "destination": {"dest-node": "P1", "dest-tp": GI0},
}
# The same link inside the unkeyed networks collection: sr-mpls with the adjacency SID.
LIVE_LINK_FULL = {
    "link-id": LIVE_LINK_ID,
    L3_LINK: {
        "name": LIVE_LINK_ID,
        "metric1": "10",
        SR_MPLS: {
            "advertise-protection": "single",
            "sids": [
                {
                    "sid": 24001,
                    "is-backup": False,
                    "is-persistent": True,
                    "is-on-lan": False,
                    "value-type": "absolute",
                    "is-local": True,
                    "address-family": "ipv4",
                    "is-part-of-set": False,
                }
            ],
            "information-source": "isis",
        },
        "cisco-crosswork-l3-te-topology:l3-link-attributes": {
            "domain-id": "0",
            "max-bandwidth-kbps": "1000000",
        },
        ISIS_LINK: {"level": 2, "net": {"system-id": "0000.0000.0001"}},
    },
    "source": {"source-node": "PE1", "source-tp": GI0},
    "destination": {"dest-node": "P1", "dest-tp": GI0},
}
LIVE_NETWORK_COLLECTION = {
    "ietf-network-state:networks": {
        "network": [{**NETWORK, LINK_LIST: [LIVE_LINK_FULL, ETH_PE1_P1]}]
    }
}

# Verified: a keyed GET that matches nothing answers 409 with the bare ``errors`` key.
DATA_MISSING_409 = httpx.Response(
    409,
    json={
        "errors": {
            "error": [
                {
                    "error-tag": "data-missing",
                    "error-message": (
                        "Request could not be completed because the relevant data model "
                        "content does not exist"
                    ),
                }
            ]
        }
    },
)
# Verified: a bad module prefix / container name answers 400 unknown-element.
UNKNOWN_ELEMENT_400 = httpx.Response(
    400,
    json={
        "errors": {
            "error": [
                {
                    "error-type": "protocol",
                    "error-tag": "unknown-element",
                    "error-message": "Unknown element: ietf-network:networks",
                }
            ]
        }
    },
)
# Verified: an unencoded '/' in a key breaks the route — a plain 404 with no RESTCONF error
# document. Only that much is verified; the Spring-style {status, error, path} body below is
# SYNTHETIC (the notes do not record what, if anything, the body carries).
PLAIN_404 = httpx.Response(
    404,
    json={
        "status": 404,
        "error": "Not Found",
        "path": "/crosswork/nbi/topology/v3/restconf/data/ietf-network-state:networks",
    },
)
# SYNTHETIC: the same plain 404 with no body at all.
EMPTY_404 = httpx.Response(404)
# What the generic 404 hint of errors.http_error() says — it must never reach the agent
# from this NBI, where a plain 404 is a routing/encoding problem, not a missing object.
GENERIC_404_HINTS = ("Resource not found", "ID or name is correct")
PLAIN_404_EXPLANATION = "the URL is malformed or the NBI prefix is not routed"


def assert_plain_404(text: str, *not_found_phrases: str) -> None:
    """The rendered plain-404 text names the real cause and never claims a missing object."""
    assert text.startswith("Error: API request failed with status 404.")
    assert PLAIN_404_EXPLANATION in text
    assert "NOT that the object is missing" in text
    assert "409 data-missing" in text
    for phrase in (*GENERIC_404_HINTS, *not_found_phrases):
        assert phrase not in text, phrase


# SYNTHETIC: a 409 that is a real conflict, not data-missing.
CONFLICT_409 = httpx.Response(
    409,
    json={"errors": {"error": [{"error-tag": "in-use", "error-message": "locked by admin"}]}},
)


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    topology.register(mcp, ctx)
    return mcp


def ok(body: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json=body)


@pytest.fixture
def mcp(settings: Settings) -> MCPServer:
    return build(settings)


# --- Pure helpers ---------------------------------------------------------------


def test_field_accepts_bare_and_prefixed_spellings():
    node = {"node-id": "PE1", L3_NODE: {"router-id": ["10.0.0.1"]}}
    assert field(node, "node-id") == "PE1"
    assert field(node, "ietf-network-state:node-id") == "PE1"  # documented prefixed form
    assert field(node, L3_NODE)["router-id"] == ["10.0.0.1"]
    assert field(node, "l3-node-attributes")["router-id"] == ["10.0.0.1"]  # bare local name
    prefixed = {"ietf-network-topology-state:tp-id": GI0}
    assert field(prefixed, "tp-id") == GI0  # any-module suffix match
    assert field(node, "missing", "dflt") == "dflt"
    assert field("not a dict", "node-id") is None


def test_select_by_field_matches_bare_and_prefixed_keys_exactly():
    bare = {"node-id": "PE1"}
    prefixed = {"ietf-network-state:node-id": "PE1"}
    other = {"node-id": "pe1"}  # case-sensitive: not a match
    assert select_by_field([bare, prefixed, other, "junk", {"x": 1}], "node-id", "PE1") == [
        bare,
        prefixed,
    ]
    assert select_by_field([{"tunnel-id": 7}], "tunnel-id", "7") == [{"tunnel-id": 7}]
    assert select_by_field([{"node-id": ["PE1"]}], "node-id", "PE1") == []
    assert select_by_field(None, "node-id", "PE1") == []


def test_plain_404_error_explains_routing_not_a_missing_object():
    text = str(plain_404_error("/crosswork/nbi/topology/v3/restconf/data/x"))
    assert text.startswith("API request failed with status 404.")
    assert "GET /crosswork/nbi/topology/v3/restconf/data/x" in text
    assert PLAIN_404_EXPLANATION in text
    assert "/crosswork/nbi/topology/v3/restconf" in text
    for phrase in GENERIC_404_HINTS:
        assert phrase not in text


def test_link_type_of_and_classify_link():
    assert link_type_of(LINK_PE1_P1["link-id"]) == "ISIS_IPV4_L2"
    assert link_type_of(ETH_PE1_P1["link-id"]) == "ETHERNET"
    assert link_type_of("no separator") == ""
    assert link_type_of(None) == ""
    assert classify_link(LINK_PE1_P1["link-id"]) == "isis"
    assert classify_link(ETH_PE1_P1["link-id"]) == "ethernet"
    assert classify_link(OTHER_LINK["link-id"]) == "other"
    assert classify_link("") == "other"


def test_normalize_link_type():
    assert normalize_link_type(" ISIS ") == "isis"
    assert normalize_link_type("all") == "all"
    with pytest.raises(PlatformError, match="Unknown link_type 'l3'"):
        normalize_link_type("l3")


def test_node_id_matches_is_exact_case_insensitive_with_wildcard():
    assert node_id_matches("pe1", "PE1")
    assert node_id_matches("PE*", "PE2")
    assert node_id_matches("*e*", "PCE")
    assert not node_id_matches("PE", "PE1")  # no substring match without '*'
    assert not node_id_matches("PE1", None)


def test_tp_summary_collects_addresses_and_l2_fields():
    assert tp_summary(PE1_TPS[0]) == {
        "tp-id": GI0,
        "ip-address": ["10.1.1.1"],  # the same address in l3 and ipv4 containers, once
        "mac-address": "02:42:0a:01:01:01",
        "unnumbered-id": ["3"],
        "encapsulation": "ethernet",
    }
    bare = tp_summary({"tp-id": "Loopback0"})
    assert bare["ip-address"] == [] and bare["mac-address"] is None


# The SR-MPLS-only summary: what the lab answers today (the srv6 counters all zero/false).
SR_MPLS_SUMMARY = {
    "network_id": "Default-network",
    "isis_area": "49.0001",
    "nodes": 5,
    "links": {"total": 7, "isis_ipv4_l2": 4, "ethernet": 3, "other": 0},
    "sr_capable_nodes": 5,
    "pcep_session_nodes": 2,
    "prefix_sids": 5,
    "srv6_network_type": False,
    "srv6_capable_nodes": 0,
    "srv6_node_sids": 0,
    "srv6_adjacency_links": 0,
    "ipv6_router_id_nodes": 0,
    "flex_algos": [],
    "node_dataplanes": {"sr-mpls": 5, "srv6": 0, "both": 0, "none": 0},
    "termination_points": 9,
}


def test_summarize_network_counts():
    assert summarize_network(NETWORK) == SR_MPLS_SUMMARY
    l2_only = summarize_network(L2_ONLY_NETWORK)
    assert l2_only["links"] == {"total": 2, "isis_ipv4_l2": 0, "ethernet": 2, "other": 0}
    assert l2_only["sr_capable_nodes"] == 0 and l2_only["isis_area"] is None
    assert l2_only["node_dataplanes"] == {"sr-mpls": 0, "srv6": 0, "both": 0, "none": 2}
    assert "SR-PCE gRPC feed is not up" in l2_only["note"]
    assert "note" not in summarize_network({"network-id": "Default-network"})


def test_summarize_network_counts_srv6_members():
    """Spec-shaped SRv6 network: presence flag, per-node SIDs across IS-IS and OSPF instances,
    End.X links, IPv6 router-ids, Flex-Algo ids and the dataplane split."""
    summary = summarize_network(SRV6_NETWORK)
    assert summary["srv6_network_type"] is True
    assert summary["srv6_capable_nodes"] == 3  # PE1 (both), P1 (srv6), P3 (OSPF, srv6)
    assert summary["srv6_node_sids"] == 5  # 2 + 2 + 1
    assert summary["srv6_adjacency_links"] == 3  # two IS-IS End.X links + the OSPF one
    assert summary["links"] == {"total": 5, "isis_ipv4_l2": 3, "ethernet": 1, "other": 1}
    assert summary["ipv6_router_id_nodes"] == 2
    assert summary["flex_algos"] == [128]
    assert summary["node_dataplanes"] == {"sr-mpls": 1, "srv6": 2, "both": 1, "none": 1}
    assert summary["sr_capable_nodes"] == 2 and "note" not in summary
    # An SRv6-only node keeps a network with only ETHERNET links from reading as "L2-only".
    srv6_only = {**SRV6_NETWORK, "node": [P1_SRV6], LINK_LIST: [ETH_PE1_P1]}
    assert "note" not in summarize_network(srv6_only)
    assert "note" in summarize_network({**srv6_only, "node": [SW1]})


def test_srv6_locator_and_format_derivation():
    usid = sid_structure({SRV6_STRUCTURE: USID_STRUCTURE})
    assert usid == {"lb": 32, "ln": 16, "func": 16, "arg": 0}
    assert srv6_locator("fc00:0:1::", usid) == "fc00:0:1::/48"
    assert srv6_locator("fc00:0:1:e000::", usid) == "fc00:0:1::/48"  # an End.X of the locator
    assert sid_format(usid) == "uSID F3216" and structure_text(usid) == "32/16/16/0"
    # F3216 is 32/16/16: a /48 locator with a non-16-bit function is a classic SID, while a
    # structure without func-length still passes on lb/ln; arg-length is not checked.
    assert sid_format({"lb": 32, "ln": 16, "func": 64, "arg": None}) == "classic"
    assert sid_format({"lb": 32, "ln": 16, "func": None, "arg": None}) == "uSID F3216"
    assert sid_format({"lb": 32, "ln": 16, "func": 16, "arg": 32}) == "uSID F3216"
    classic = sid_structure(
        {SRV6_STRUCTURE: {"lb-length": "40", "ln-length": "24", "func-length": "16"}}
    )
    assert classic == {"lb": 40, "ln": 24, "func": 16, "arg": None}  # string-typed leaves
    assert srv6_locator("2001:db8:6::", classic) == "2001:db8:6::/64"
    assert sid_format(classic) == "classic" and structure_text(classic) == "40/24/16/?"
    none = sid_structure({"sid": "fc00:0:1::"})  # no srv6-sid-structure container
    assert none == {"lb": None, "ln": None, "func": None, "arg": None}
    assert srv6_locator("fc00:0:1::", none) is None
    assert sid_format(none) == "unknown structure" and structure_text(none) == "-"
    assert srv6_locator("not-an-address", usid) is None
    assert srv6_locator("fc00::", {"lb": 100, "ln": 100, "func": None, "arg": None}) is None


def test_igp_instance_text_names_the_instance_a_sid_was_learnt_from():
    assert igp_instance_text("isis", {"level": "level-2", "system-id": "x"}) == "IS-IS level-2"
    assert igp_instance_text("isis", {}) == "IS-IS ?"
    assert igp_instance_text("ospf", {"area-id": ["0.0.0.0"]}) == "OSPF area 0.0.0.0"
    assert (
        igp_instance_text("ospf", {"area-id": ["0.0.0.0", "0.0.0.1"]})
        == "OSPF area 0.0.0.0,0.0.0.1"
    )
    assert igp_instance_text("ospf", {"area-id": "0.0.0.1"}) == "OSPF area 0.0.0.1"  # a lone string
    assert igp_instance_text("ospf", {"area-id": []}) == "OSPF area ?"
    assert igp_instance_text("ospf", {}) == "OSPF area ?"  # an OSPF entry without area-id


def test_node_dataplane_and_filter_semantics():
    assert node_dataplane(PE1[L3_NODE]) == "sr-mpls"
    assert node_dataplane(PE1_SRV6[L3_NODE]) == "both"
    assert node_dataplane(P1_SRV6[L3_NODE]) == "srv6"
    assert node_dataplane(P3_OSPF_CLASSIC[L3_NODE]) == "srv6"  # OSPF instance, prefixed keys
    assert node_dataplane({}) == "none"
    assert normalize_dataplane(" SR_MPLS ") == "sr-mpls" and normalize_dataplane("SRv6") == "srv6"
    with pytest.raises(PlatformError, match="Unknown dataplane 'mpls'"):
        normalize_dataplane("mpls")
    # 'sr-mpls' / 'srv6' are inclusive of dual-stack nodes; 'both' / 'none' are exact.
    assert dataplane_matches("sr-mpls", "both") and dataplane_matches("srv6", "both")
    assert dataplane_matches("srv6", "srv6") and not dataplane_matches("srv6", "sr-mpls")
    assert dataplane_matches("both", "both") and not dataplane_matches("both", "srv6")
    assert dataplane_matches("none", "none") and not dataplane_matches("none", "sr-mpls")


def test_all_router_ids_and_transport_planes():
    assert all_router_ids(PE1[L3_NODE]) == ["10.0.0.1"]
    assert all_router_ids(PE1_SRV6[L3_NODE]) == ["10.0.0.1", "2001:db8::1"]  # IPv4 first
    assert all_router_ids({}) == []
    assert transport_planes(PE1[L3_NODE][SR_MPLS]) == ["sr-mpls"]
    live = {
        "node-capabilities": {
            "transport-planes": [
                {"transport-plane": ("ietf-segment-routing-common:segment-routing-transport-mpls")}
            ]
        }
    }
    assert transport_planes(live) == ["segment-routing-transport-mpls"]
    assert transport_planes(None) == [] and transport_planes({}) == []


def test_srv6_locator_rows_fold_sids_per_node_and_locator():
    rows = srv6_locator_rows(SRV6_NETWORK)
    assert [(r["node"], r["locator"]) for r in rows] == [
        ("PE1", "fc00:0:1::/48"),
        ("PE1", "fc00:1:1::/48"),
        ("P1", "fc00:0:2::/48"),
        ("P1", "fc00:1:2::/48"),
        ("P3", "2001:db8:6::/64"),
    ]
    pe1_algo0 = rows[0]
    assert pe1_algo0["format"] == "uSID F3216" and pe1_algo0["algorithms"] == [0]
    assert pe1_algo0["endpoint_behaviors"] == ["uN"] and pe1_algo0["igp"] == ["IS-IS level-2"]
    assert pe1_algo0["sid_count"] == 1 and pe1_algo0["sids"] == [srv6_node_sid("fc00:0:1::", 0)]
    assert pe1_algo0["lb_length"] == 32 and pe1_algo0["ln_length"] == 16
    assert rows[1]["algorithms"] == [128]
    p3 = rows[4]
    assert p3["format"] == "classic" and p3["algorithms"] == [0]
    assert p3["endpoint_behaviors"] == ["End"] and p3["igp"] == ["OSPF area 0.0.0.0"]
    # Two SIDs of one locator on different algorithms fold into one row.
    twin = {
        "node": [
            {
                "node-id": "X",
                L3_NODE: {
                    ISIS_NODE: [
                        {
                            "level": "level-2",
                            SRV6_NODE_SID: [
                                srv6_node_sid("fc00:0:9::", 0),
                                srv6_node_sid("fc00:0:9:1::", 128, "uN"),
                                {"sid": "fc00:0:9:2::", "endpoint-behavior": "uDT4"},
                            ],
                        }
                    ]
                },
            }
        ]
    }
    twin_rows = srv6_locator_rows(twin)
    assert [(r["locator"], r["algorithms"], r["sid_count"]) for r in twin_rows] == [
        ("fc00:0:9::/48", [0, 128], 2),
        (None, [], 1),  # no structure: its own row, no locator derivable
    ]
    assert twin_rows[1]["format"] == "unknown structure"
    assert srv6_locator_rows(NETWORK) == [] and srv6_locator_rows({}) == []


# --- cnc_get_topology_summary -----------------------------------------------------


@respx.mock
async def test_summary_fetches_the_network_with_yang_accept(mcp):
    route = respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_get_topology_summary", {})
    request = route.calls[0].request
    assert request.method == "GET"
    assert str(request.url) == NETWORK_URL
    assert request.headers["Accept"] == YANG_JSON
    assert json.loads(text) == SR_MPLS_SUMMARY


@respx.mock
async def test_summary_srv6_counters_on_a_spec_shaped_srv6_network(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(SRV6_NETWORK_COLLECTION))
    data = json.loads(await call_tool_text(mcp, "cnc_get_topology_summary", {}))
    assert data["srv6_network_type"] is True
    assert data["srv6_capable_nodes"] == 3 and data["srv6_node_sids"] == 5
    assert data["srv6_adjacency_links"] == 3 and data["flex_algos"] == [128]
    assert data["node_dataplanes"] == {"sr-mpls": 1, "srv6": 2, "both": 1, "none": 1}
    assert data["links"] == {"total": 5, "isis_ipv4_l2": 3, "ethernet": 1, "other": 1}


@respx.mock
async def test_summary_selects_the_requested_network_from_the_collection(mcp):
    # The collection GET (not the shallow keyed GET) is fetched and the id chosen client-side.
    other = {**NETWORK, "network-id": "Ops/Prod:net", "node": NETWORK["node"][:2]}
    route = respx.get(NETWORKS_URL).mock(
        return_value=ok({"ietf-network-state:networks": {"network": [NETWORK, other]}})
    )
    text = await call_tool_text(mcp, "cnc_get_topology_summary", {"network": "Ops/Prod:net"})
    assert route.calls[0].request.url.raw_path.decode().endswith("ietf-network-state:networks")
    summary = json.loads(text)
    assert summary["network_id"] == "Ops/Prod:net"
    assert summary["nodes"] == 2


@respx.mock
async def test_summary_accepts_the_prefixed_network_id_spelling(mcp):
    # The 7.2 OpenAPI spells the key ietf-network-state:network-id; live it is bare.
    prefixed = {**NETWORK}
    del prefixed["network-id"]
    prefixed = {"ietf-network-state:network-id": "Default-network", **prefixed}
    respx.get(NETWORK_URL).mock(
        return_value=ok({"ietf-network-state:networks": {"network": [prefixed]}})
    )
    data = json.loads(await call_tool_text(mcp, "cnc_get_topology_summary", {}))
    assert data["network_id"] == "Default-network" and data["nodes"] == 5


@respx.mock
async def test_summary_all_l2_topology_carries_the_feed_note(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(L2_ONLY_COLLECTION))
    data = json.loads(await call_tool_text(mcp, "cnc_get_topology_summary", {}))
    assert data["links"] == {"total": 2, "isis_ipv4_l2": 0, "ethernet": 2, "other": 0}
    assert data["sr_capable_nodes"] == 0 and data["pcep_session_nodes"] == 0
    assert "SR-PCE gRPC feed is not up" in data["note"]


@respx.mock
async def test_summary_empty_network_is_zeros_not_error(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(EMPTY_NETWORK_COLLECTION))
    data = json.loads(await call_tool_text(mcp, "cnc_get_topology_summary", {}))
    assert data["nodes"] == 0 and data["links"]["total"] == 0
    assert data["termination_points"] == 0 and "note" not in data


@respx.mock
async def test_summary_unknown_network_is_checked_client_side(mcp):
    # The NBI ignores an unknown network key and answers the whole list.
    respx.get(NETWORKS_URL).mock(return_value=ok(NETWORKS_WHOLE))
    text = await call_tool_text(mcp, "cnc_get_topology_summary", {"network": "nope"})
    assert text.startswith("Error: no network 'nope'")
    assert "Networks present: Default-network" in text


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(ok({}), id="empty-container"),  # the verified empty-container answer
        pytest.param(httpx.Response(204), id="204-no-content"),  # documented in the 7.2 OpenAPI
    ],
)
@respx.mock
async def test_summary_no_networks_at_all_is_zeros_with_a_note(mcp, response):
    # A fresh instance: the first topology call an agent makes must not be an error.
    respx.get(NETWORK_URL).mock(return_value=response)
    text = await call_tool_text(mcp, "cnc_get_topology_summary", {})
    assert not text.startswith("Error")
    data = json.loads(text)
    assert data["network_id"] == "Default-network"
    assert data["nodes"] == 0 and data["termination_points"] == 0
    assert data["links"] == {"total": 0, "isis_ipv4_l2": 0, "ethernet": 0, "other": 0}
    assert data["sr_capable_nodes"] == 0 and data["prefix_sids"] == 0
    assert data["note"] == NO_NETWORKS_NOTE
    assert "reports no networks yet" in data["note"] and "cnc_list_devices" in data["note"]


@respx.mock
async def test_summary_plain_404_on_the_network_url_is_a_routing_error(mcp):
    respx.get(NETWORK_URL).mock(return_value=PLAIN_404)
    text = await call_tool_text(mcp, "cnc_get_topology_summary", {})
    assert_plain_404(text, "no network")


@respx.mock
async def test_summary_400_unknown_element_is_rendered_from_bare_errors_key(mcp):
    respx.get(NETWORK_URL).mock(return_value=UNKNOWN_ELEMENT_400)
    text = await call_tool_text(mcp, "cnc_get_topology_summary", {})
    assert text.startswith("Error: API request failed with status 400.")
    assert "RESTCONF path or key problem" in text
    assert "Platform said: RESTCONF unknown-element: Unknown element: ietf-network:networks" in text


# --- cnc_list_topology_nodes ----------------------------------------------------


@respx.mock
async def test_list_nodes_markdown_lines(mcp):
    route = respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {})
    assert route.calls[0].request.headers["Accept"] == YANG_JSON
    assert "# Topology nodes in Default-network (5 shown, matching 5, collection 5; page 0)" in text
    # The SR-MPLS-only lab: srv6-sids=0 dataplane=sr-mpls on every L3 row (verified live).
    assert (
        "- **PE1** router-id=10.0.0.1 isis=level-2/0000.0000.0001 srgb=16000-23999 msd=10 "
        "prefix-sids=1 srv6-sids=0 dataplane=sr-mpls pcep=1 tps=2"
    ) in text
    assert (
        "- **P1** router-id=10.0.0.2 isis=level-2/0000.0000.0002 srgb=16000-23999 msd=10 "
        "prefix-sids=1 srv6-sids=0 dataplane=sr-mpls pcep=0 tps=2"
    ) in text
    assert "- **PCE** " in text and "More available" not in text
    assert "cnc_list_devices" in text


@respx.mock
async def test_list_nodes_srv6_rows_show_ipv6_router_id_sid_count_and_dataplane(mcp):
    # Spec-shaped: the IPv6 TE router-id follows the IPv4 one; dataplane both / srv6 / none.
    respx.get(NETWORK_URL).mock(return_value=ok(SRV6_NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {})
    assert (
        "- **PE1** router-id=10.0.0.1,2001:db8::1 isis=level-2/0000.0000.0001 srgb=16000-23999 "
        "msd=10 prefix-sids=1 srv6-sids=2 dataplane=both pcep=1 tps=2"
    ) in text
    assert (
        "- **P1** router-id=10.0.0.2,2001:db8::2 isis=level-2/0000.0000.0002 srgb=- msd=- "
        "prefix-sids=0 srv6-sids=2 dataplane=srv6 pcep=0 tps=2"
    ) in text
    assert "- **PE2** router-id=10.0.0.3 " in text and "srv6-sids=0 dataplane=sr-mpls" in text
    assert (
        "- **SW1** router-id=- isis=- srgb=- msd=- prefix-sids=0 srv6-sids=0 dataplane=none" in text
    )
    assert (
        "- **P3** router-id=10.0.0.6 isis=- srgb=- msd=- prefix-sids=0 srv6-sids=1 dataplane=srv6"
        in text
    )


@respx.mock
async def test_list_nodes_dataplane_filter_is_inclusive_for_dual_stack_nodes(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(SRV6_NETWORK_COLLECTION))

    async def ids(dataplane: str) -> list[str]:
        data = json.loads(
            await call_tool_text(
                mcp,
                "cnc_list_topology_nodes",
                {"dataplane": dataplane, "response_format": "json"},
            )
        )
        assert data["collection_total"] == 5
        return [n["node-id"] for n in data["items"]]

    assert await ids("srv6") == ["PE1", "P1", "P3"]
    assert await ids("SR-MPLS") == ["PE1", "PE2"]
    assert await ids("both") == ["PE1"]
    assert await ids("none") == ["SW1"]
    # Combined with the name filter and sr_only.
    data = json.loads(
        await call_tool_text(
            mcp,
            "cnc_list_topology_nodes",
            {"dataplane": "srv6", "sr_only": True, "response_format": "json"},
        )
    )
    assert [n["node-id"] for n in data["items"]] == ["PE1"]


@respx.mock
async def test_list_nodes_dataplane_srv6_on_the_sr_mpls_lab_matches_nothing(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {"dataplane": "srv6"})
    assert not text.startswith("Error")
    assert "(0 shown, matching 0, collection 5; page 0)" in text
    assert "No nodes matched the filter" in text
    # The SRv6 clause is true to the network: on the SR-MPLS-only lab no node advertises a SID.
    assert (
        "'srv6' matches nothing here: no node of the network advertises an srv6-node-sid yet "
        "(cnc_list_srv6_locators says what the underlay needs)"
    ) in text
    # A name-only miss says nothing about SRv6.
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {"name": "nope"})
    assert "No nodes matched the filter" in text
    assert "srv6-node-sid" not in text and "cnc_list_srv6_locators" not in text


@respx.mock
async def test_list_nodes_dataplane_miss_on_an_srv6_network_says_which_nodes_would_match(mcp):
    # PE2 is SR-MPLS only: the miss is the name, not the network — three nodes DO advertise.
    respx.get(NETWORK_URL).mock(return_value=ok(SRV6_NETWORK_COLLECTION))
    text = await call_tool_text(
        mcp, "cnc_list_topology_nodes", {"dataplane": "srv6", "name": "PE2"}
    )
    assert "(0 shown, matching 0, collection 5; page 0)" in text
    assert (
        "'srv6' matches only nodes advertising srv6-node-sids (3 in this network — "
        "cnc_list_srv6_locators shows which)"
    ) in text
    assert "matches nothing here" not in text
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {"dataplane": "both", "name": "P1"})
    assert "'both' matches only nodes advertising srv6-node-sids (3 in this network" in text
    # 'sr-mpls' / 'none' misses carry no SRv6 clause at all.
    text = await call_tool_text(
        mcp, "cnc_list_topology_nodes", {"dataplane": "sr-mpls", "name": "SW1"}
    )
    assert "No nodes matched the filter" in text and "srv6-node-sid" not in text


@respx.mock
async def test_list_nodes_unknown_dataplane_is_an_error_before_any_request(mcp):
    route = respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {"dataplane": "mpls"})
    assert text.startswith("Error: Unknown dataplane 'mpls'")
    assert "sr-mpls, srv6, both, none" in text
    assert not route.called


@respx.mock
async def test_list_nodes_without_l3_attributes_still_list(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(L2_ONLY_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {})
    assert "(2 shown, matching 2, collection 2; page 0)" in text
    assert (
        "- **PE1** router-id=- isis=- srgb=- msd=- prefix-sids=0 srv6-sids=0 dataplane=none "
        "pcep=0 tps=2"
    ) in text
    assert (
        "- **P1** router-id=- isis=- srgb=- msd=- prefix-sids=0 srv6-sids=0 dataplane=none "
        "pcep=0 tps=2"
    ) in text


@respx.mock
async def test_list_nodes_json_is_raw_nodes_with_envelope(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    data = json.loads(
        await call_tool_text(mcp, "cnc_list_topology_nodes", {"response_format": "json"})
    )
    assert data["network_id"] == "Default-network"
    assert data["total"] == 5 and data["count"] == 5 and data["collection_total"] == 5
    assert data["page"] == 0 and data["page_size"] == 50
    assert data["has_more"] is False and data["next_page"] is None
    assert data["items"] == [PE1, P1, PE2, P2, PCE]


@respx.mock
async def test_list_nodes_name_wildcard_is_case_insensitive(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    data = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_nodes", {"name": "pe*", "response_format": "json"}
        )
    )
    assert [n["node-id"] for n in data["items"]] == ["PE1", "PE2"]
    assert data["total"] == 2 and data["collection_total"] == 5
    data = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_nodes", {"name": "p1", "response_format": "json"}
        )
    )
    assert [n["node-id"] for n in data["items"]] == ["P1"]


@respx.mock
async def test_list_nodes_sr_only_and_no_match(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(L2_ONLY_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {"sr_only": True})
    assert not text.startswith("Error")
    assert "(0 shown, matching 0, collection 2; page 0)" in text
    assert "No nodes matched the filter" in text
    respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    data = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_nodes", {"sr_only": True, "response_format": "json"}
        )
    )
    assert data["total"] == 5  # every lab node advertises SR-MPLS


@respx.mock
async def test_list_nodes_paging(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    page0 = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_nodes", {"page_size": 2, "page": 0, "response_format": "json"}
        )
    )
    assert [n["node-id"] for n in page0["items"]] == ["PE1", "P1"]
    assert page0["has_more"] is True and page0["next_page"] == 1
    page2 = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_nodes", {"page_size": 2, "page": 2, "response_format": "json"}
        )
    )
    assert [n["node-id"] for n in page2["items"]] == ["PCE"]
    assert page2["has_more"] is False and page2["next_page"] is None
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {"page_size": 2, "page": 1})
    assert "(2 shown, matching 5, collection 5; page 1)" in text
    assert "More available: repeat with page=2." in text


@respx.mock
async def test_list_nodes_empty_network_is_not_an_error(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(EMPTY_NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {})
    assert not text.startswith("Error")
    assert "No nodes: the platform reports none for network 'Default-network'" in text


@respx.mock
async def test_list_nodes_no_networks_at_all_is_not_an_error(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok({}))
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {})
    assert not text.startswith("Error")
    assert "(0 shown, matching 0, collection 0; page 0)" in text
    assert f"No nodes: {NO_NETWORKS_NOTE}" in text
    data = json.loads(
        await call_tool_text(mcp, "cnc_list_topology_nodes", {"response_format": "json"})
    )
    assert data["items"] == [] and data["collection_total"] == 0
    assert data["network_id"] == "Default-network" and data["note"] == NO_NETWORKS_NOTE


@respx.mock
async def test_list_nodes_unknown_network(mcp):
    # "no network" is an error only when OTHER networks are present.
    respx.get(NETWORKS_URL).mock(return_value=ok(NETWORKS_WHOLE))
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {"network": "Other"})
    assert text.startswith("Error: no network 'Other'")
    assert "Networks present: Default-network" in text


async def test_list_nodes_schema_rejects_bad_paging(mcp):
    # Flat Annotated parameters: the input schema itself refuses out-of-range values.
    with pytest.raises(ToolError, match="page_size"):
        await call_tool_text(mcp, "cnc_list_topology_nodes", {"page_size": 0})
    with pytest.raises(ToolError, match="page"):
        await call_tool_text(mcp, "cnc_list_topology_links", {"page": -1})


# --- cnc_get_topology_node ------------------------------------------------------


@respx.mock
async def test_get_node_markdown_encodes_key_and_renders_details(mcp):
    route = respx.get(node_url("PE1")).mock(return_value=ok({"ietf-network-state:node": [PE1]}))
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "PE1"})
    request = route.calls[0].request
    assert str(request.url) == node_url("PE1")
    assert request.headers["Accept"] == YANG_JSON
    assert "# Topology node PE1 (network Default-network)" in text
    assert "- **PE1** router-id=10.0.0.1 isis=level-2/0000.0000.0001" in text
    assert "Router IDs: 10.0.0.1" in text
    assert "IPv6 router IDs" not in text  # only when the ipv6-router-id leaf-list is present
    assert "IS-IS: level level-2 system-id 0000.0000.0001" in text
    assert "SR-MPLS: srgb=16000-23999 srlb=15000-15999 msd=10 transport=sr-mpls" in text
    # The SR-MPLS-only lab: the SRv6 block is an explicit, symmetric "none" (verified live).
    assert "SRv6 node SIDs (0):" in text
    assert "- (none: no srv6-node-sid under the node's IS-IS/OSPF instances" in text
    assert "Flex-Algos" not in text and "OSPF:" not in text
    assert "Prefixes (2, 1 with SR-MPLS SIDs):" in text
    # the index (1) is rendered as the absolute label (SRGB 16000 + 1)
    assert "- 10.0.0.1/32 -> sid 16001 (index 1) algorithm 0" in text
    assert "- 10.1.1.0/30 -> no SID" in text
    # Round 3: the feed carries no state leaf (verified); whether a down session is
    # omitted was never observed live, so the header states only the verified fact.
    assert "PCEP sessions (1; the feed carries no state leaf):" in text
    assert " established;" not in text and "omits down sessions" not in text
    assert "no established PCEP session" not in text  # the old, unverified claim
    assert (
        "- pcc 10.0.0.1 -> pce 10.0.0.5 stateful=True sr=True update=True instantiate=True msd=10"
    ) in text
    # Round 2: the pce address is the SR-PCE feed's own (provider endpoint) address and may
    # differ from the peer configured on the router — said right under the sessions.
    assert "(pce = the address the SR-PCE feed identifies itself by" in text
    assert "may differ from the 'pce address ipv4' peer configured on the router" in text
    assert "Termination points (2):" in text
    assert (
        "- GigabitEthernet0/0/0/0 ip=10.1.1.1 mac=02:42:0a:01:01:01 unnumbered=3 encap=ethernet"
    ) in text


@respx.mock
async def test_get_node_renders_srv6_node_sids_locators_flex_algos_and_ipv6_router_id(mcp):
    """Spec-shaped SRv6 node (7.2 model, not seen live): two node SIDs on algorithm 0 and 128,
    each rendered with its derived locator and the uSID F3216 label, the Flex-Algo definition
    and the IPv6 TE router-id — next to the unchanged SR-MPLS block (dataplane both)."""
    respx.get(node_url("PE1")).mock(return_value=ok({"ietf-network-state:node": [PE1_SRV6]}))
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "PE1"})
    assert "- **PE1** router-id=10.0.0.1,2001:db8::1 " in text
    assert "srv6-sids=2 dataplane=both" in text
    assert "Router IDs: 10.0.0.1\nIPv6 router IDs: 2001:db8::1\n" in text
    assert "SR-MPLS: srgb=16000-23999 srlb=15000-15999 msd=10 transport=sr-mpls" in text
    assert "SRv6 node SIDs (2):" in text
    assert (
        "- fc00:0:1:: behavior=uN algorithm=0 structure=32/16/16/0 (lb/ln/func/arg) "
        "locator=fc00:0:1::/48 (uSID F3216) via IS-IS level-2"
    ) in text
    assert (
        "- fc00:1:1:: behavior=uN algorithm=128 structure=32/16/16/0 (lb/ln/func/arg) "
        "locator=fc00:1:1::/48 (uSID F3216) via IS-IS level-2"
    ) in text
    assert "(none: no srv6-node-sid" not in text
    assert "Flex-Algos (1):" in text
    assert (
        "- 128 metric-type=te-metric priority=100 elected=True participated=True "
        "include-any=- include-all=- exclude-any=0x2 via IS-IS level-2"
    ) in text
    assert "Prefixes (2, 1 with SR-MPLS SIDs):" in text  # the SR-MPLS block is untouched


@respx.mock
async def test_get_node_renders_an_ospf_srv6_sid_in_the_openapi_spelling_as_classic(mcp):
    # Fully prefixed member names, string-typed lengths, a 40/24 structure -> 'classic'.
    respx.get(node_url("P3")).mock(return_value=ok({"ietf-network-state:node": [P3_OSPF_CLASSIC]}))
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "P3"})
    assert "OSPF: router-id 10.0.0.6 area 0.0.0.0" in text
    assert "SR-MPLS:" not in text and "srv6-sids=1 dataplane=srv6" in text
    assert "SRv6 node SIDs (1):" in text
    assert (
        "- 2001:db8:6:: behavior=End algorithm=0 structure=40/24/16/0 (lb/ln/func/arg) "
        "locator=2001:db8:6::/64 (classic) via OSPF area 0.0.0.0"
    ) in text
    data = json.loads(
        await call_tool_text(
            mcp, "cnc_get_topology_node", {"node_id": "P3", "response_format": "json"}
        )
    )
    assert data == P3_OSPF_CLASSIC  # json keeps the raw keys


@respx.mock
async def test_get_node_key_with_slash_and_colon_is_percent_encoded(mcp):
    # httpx encodes a raw space itself but leaves '/' and ':' alone, so only these two
    # characters prove the tool's own encode_key() is in the path (live: a raw '/' is a 404).
    route = respx.get(node_url("PE1%2FRSP0%3ACPU0")).mock(
        return_value=ok({"ietf-network-state:node": [{**P1, "node-id": "PE1/RSP0:CPU0"}]})
    )
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "PE1/RSP0:CPU0"})
    assert route.calls[0].request.url.raw_path.decode().endswith("/node=PE1%2FRSP0%3ACPU0")
    assert "# Topology node PE1/RSP0:CPU0" in text


@respx.mock
async def test_get_node_accepts_the_prefixed_node_id_spelling(mcp):
    # The 7.2 OpenAPI spells every member with its module prefix; live the key is bare.
    prefixed = {
        "ietf-network-state:node-id": "PE1",
        **{k: v for k, v in PE1.items() if k != "node-id"},
    }
    respx.get(node_url("PE1")).mock(return_value=ok({"ietf-network-state:node": [prefixed]}))
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "PE1"})
    assert text.startswith("# Topology node PE1 (network Default-network)")
    assert "- **PE1** router-id=10.0.0.1" in text


@respx.mock
async def test_get_node_without_pcep_session_says_none_is_not_down(mcp):
    """An L3 node with no node-pcep-sessions (P1 here) renders an explicit 'none' that
    separates the verified fact (no state leaf in the feed) from the assumption (a down
    session is absent rather than listed — never observed live) and says where to check,
    so an agent does not read 0 as "not a PCC" or as "PCEP down" without checking."""
    respx.get(node_url("P1")).mock(return_value=ok({"ietf-network-state:node": [P1]}))
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "P1"})
    assert "PCEP sessions (0; the feed carries no state leaf):" in text
    assert "- (none: no PCEP session with the SR-PCE in the feed" in text
    assert "presumably absent rather than listed as down (assumed, not verified live)" in text
    assert "cnc_get_device_backup" in text and "cnc_list_providers" in text
    assert " established;" not in text and "omits down sessions" not in text
    assert "no established PCEP session" not in text  # the old, unverified claim
    assert "pce = the address" not in text  # the PCEP note only follows actual sessions


@respx.mock
async def test_get_node_l2_only_says_so(mcp):
    respx.get(node_url("P1")).mock(
        return_value=ok({"ietf-network-state:node": [l2_node("P1", P1_TPS)]})
    )
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "P1"})
    assert "No L3 node attributes" in text and "SR-PCE gRPC feed" in text
    assert "Termination points (2):" in text
    assert "pce = the address" not in text  # the PCEP note only follows actual sessions


@respx.mock
async def test_get_node_json_is_the_raw_node(mcp):
    respx.get(node_url("P2")).mock(return_value=ok({"ietf-network-state:node": [P2]}))
    text = await call_tool_text(
        mcp, "cnc_get_topology_node", {"node_id": "P2", "response_format": "json"}
    )
    assert json.loads(text) == P2


@respx.mock
async def test_get_node_409_data_missing_is_not_found(mcp):
    respx.get(node_url("nope")).mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "nope"})
    assert text.startswith("Error: no node 'nope' in topology 'Default-network'")
    assert "cnc_list_topology_nodes" in text


@pytest.mark.parametrize("response", [PLAIN_404, EMPTY_404], ids=["spring-body", "empty-body"])
@respx.mock
async def test_get_node_plain_404_is_not_reported_as_missing(mcp, response):
    respx.get(node_url("PE1")).mock(return_value=response)
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "PE1"})
    assert_plain_404(text, "no node")
    assert "for GET /crosswork/nbi/topology/v3/restconf/data/ietf-network-state:networks" in text


@respx.mock
async def test_get_node_other_409_is_a_conflict_error(mcp):
    respx.get(node_url("PE1")).mock(return_value=CONFLICT_409)
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "PE1"})
    assert text.startswith("Error: API request failed with status 409.")
    assert "no node" not in text and "locked by admin" in text


@respx.mock
async def test_get_node_reselects_on_node_id_when_the_key_is_ignored(mcp):
    # Belt and braces: a keyed GET answering a different node is not that node.
    respx.get(node_url("pe1")).mock(return_value=ok({"ietf-network-state:node": [PE1]}))
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "pe1"})
    assert text.startswith("Error: no node 'pe1'")  # case-sensitive


@respx.mock
async def test_get_node_400_unknown_element(mcp):
    respx.get(node_url("PE1")).mock(return_value=UNKNOWN_ELEMENT_400)
    text = await call_tool_text(mcp, "cnc_get_topology_node", {"node_id": "PE1"})
    assert text.startswith("Error: API request failed with status 400.")
    assert "RESTCONF unknown-element" in text


# --- cnc_list_node_interfaces ---------------------------------------------------


@respx.mock
async def test_list_node_interfaces_markdown(mcp):
    route = respx.get(node_url("P1")).mock(return_value=ok({"ietf-network-state:node": [P1]}))
    text = await call_tool_text(mcp, "cnc_list_node_interfaces", {"node_id": "P1"})
    assert str(route.calls[0].request.url) == node_url("P1")
    assert route.calls[0].request.headers["Accept"] == YANG_JSON
    assert "# Interfaces of P1 in Default-network (2 termination points)" in text
    assert (
        "- GigabitEthernet0/0/0/0 ip=10.1.1.2 mac=02:42:0a:01:01:02 unnumbered=3 encap=ethernet"
    ) in text
    assert (
        "- GigabitEthernet0/0/0/1 ip=10.1.2.1 mac=02:42:0a:01:02:01 unnumbered=4 encap=ethernet"
    ) in text
    assert "cnc_get_node_interface" in text


@respx.mock
async def test_list_node_interfaces_json_is_raw_termination_points(mcp):
    respx.get(node_url("P1")).mock(return_value=ok({"ietf-network-state:node": [P1]}))
    data = json.loads(
        await call_tool_text(
            mcp, "cnc_list_node_interfaces", {"node_id": "P1", "response_format": "json"}
        )
    )
    assert data == {
        "network_id": "Default-network",
        "node_id": "P1",
        "count": 2,
        "items": P1_TPS,
    }


@respx.mock
async def test_list_node_interfaces_none_is_not_an_error(mcp):
    respx.get(node_url("PCE")).mock(
        return_value=ok({"ietf-network-state:node": [{"node-id": "PCE"}]})
    )
    text = await call_tool_text(mcp, "cnc_list_node_interfaces", {"node_id": "PCE"})
    assert not text.startswith("Error")
    assert "No termination points: the platform reports none for node 'PCE'" in text


@respx.mock
async def test_list_node_interfaces_409_is_no_node(mcp):
    respx.get(node_url("ghost")).mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(mcp, "cnc_list_node_interfaces", {"node_id": "ghost"})
    assert text.startswith("Error: no node 'ghost' in topology 'Default-network'")


@respx.mock
async def test_list_node_interfaces_plain_404_is_a_routing_error(mcp):
    respx.get(node_url("P1")).mock(return_value=PLAIN_404)
    text = await call_tool_text(mcp, "cnc_list_node_interfaces", {"node_id": "P1"})
    assert_plain_404(text, "no node")


@respx.mock
async def test_list_node_interfaces_accepts_the_prefixed_spellings(mcp):
    # node-id and tp-id spelled with their module prefixes (the 7.2 OpenAPI form).
    prefixed_tps = [
        {"ietf-network-topology-state:tp-id": t["tp-id"], TP_ATTRS: t[TP_ATTRS]} for t in P1_TPS
    ]
    prefixed = {"ietf-network-state:node-id": "P1", TP_LIST: prefixed_tps}
    respx.get(node_url("P1")).mock(return_value=ok({"ietf-network-state:node": [prefixed]}))
    text = await call_tool_text(mcp, "cnc_list_node_interfaces", {"node_id": "P1"})
    assert "# Interfaces of P1 in Default-network (2 termination points)" in text
    assert "- GigabitEthernet0/0/0/0 ip=10.1.1.2" in text
    assert "- GigabitEthernet0/0/0/1 ip=10.1.2.1" in text


# --- cnc_get_node_interface -----------------------------------------------------


@respx.mock
async def test_get_node_interface_encodes_slashes_and_renders(mcp):
    route = respx.get(tp_url("PE1", "GigabitEthernet0%2F0%2F0%2F0")).mock(
        return_value=ok({"ietf-network-topology-state:termination-point": [PE1_TPS[0]]})
    )
    text = await call_tool_text(
        mcp, "cnc_get_node_interface", {"node_id": "PE1", "tp_id": "GigabitEthernet0/0/0/0"}
    )
    request = route.calls[0].request
    assert str(request.url) == tp_url("PE1", "GigabitEthernet0%2F0%2F0%2F0")
    assert request.url.raw_path.decode().endswith(
        "/node=PE1/ietf-network-topology-state:termination-point=GigabitEthernet0%2F0%2F0%2F0"
    )
    assert request.headers["Accept"] == YANG_JSON
    assert "# Interface GigabitEthernet0/0/0/0 on PE1 (network Default-network)" in text
    assert (
        "- GigabitEthernet0/0/0/0 ip=10.1.1.1 mac=02:42:0a:01:01:01 unnumbered=3 encap=ethernet"
    ) in text
    assert '"mac-address": "02:42:0a:01:01:01"' in text


@respx.mock
async def test_get_node_interface_json_is_the_raw_termination_point(mcp):
    respx.get(tp_url("PE1", "GigabitEthernet0%2F0%2F0%2F1")).mock(
        return_value=ok({"ietf-network-topology-state:termination-point": [PE1_TPS[1]]})
    )
    text = await call_tool_text(
        mcp,
        "cnc_get_node_interface",
        {"node_id": "PE1", "tp_id": "GigabitEthernet0/0/0/1", "response_format": "json"},
    )
    assert json.loads(text) == PE1_TPS[1]


@respx.mock
async def test_get_node_interface_409_is_no_interface(mcp):
    respx.get(tp_url("PE1", "GigabitEthernet0%2F0%2F0%2F9")).mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(
        mcp, "cnc_get_node_interface", {"node_id": "PE1", "tp_id": "GigabitEthernet0/0/0/9"}
    )
    assert text.startswith(
        "Error: no interface 'GigabitEthernet0/0/0/9' on node 'PE1' in topology 'Default-network'"
    )
    assert "cnc_list_node_interfaces" in text


@respx.mock
async def test_get_node_interface_plain_404_is_not_reported_as_missing(mcp):
    respx.get(tp_url("PE1", "GigabitEthernet0%2F0%2F0%2F0")).mock(return_value=PLAIN_404)
    text = await call_tool_text(
        mcp, "cnc_get_node_interface", {"node_id": "PE1", "tp_id": "GigabitEthernet0/0/0/0"}
    )
    assert_plain_404(text, "no interface")
    assert "termination-point=GigabitEthernet0%2F0%2F0%2F0" in text  # the URL as sent


@respx.mock
async def test_get_node_interface_accepts_the_prefixed_tp_id_spelling(mcp):
    prefixed = {"ietf-network-topology-state:tp-id": GI0, TP_ATTRS: PE1_TPS[0][TP_ATTRS]}
    respx.get(tp_url("PE1", "GigabitEthernet0%2F0%2F0%2F0")).mock(
        return_value=ok({"ietf-network-topology-state:termination-point": [prefixed]})
    )
    text = await call_tool_text(
        mcp, "cnc_get_node_interface", {"node_id": "PE1", "tp_id": "GigabitEthernet0/0/0/0"}
    )
    assert "# Interface GigabitEthernet0/0/0/0 on PE1 (network Default-network)" in text
    assert "- GigabitEthernet0/0/0/0 ip=10.1.1.1 mac=02:42:0a:01:01:01" in text


@respx.mock
async def test_get_node_interface_reselects_on_tp_id(mcp):
    respx.get(tp_url("PE1", "Gi0")).mock(
        return_value=ok({"ietf-network-topology-state:termination-point": [PE1_TPS[0]]})
    )
    text = await call_tool_text(mcp, "cnc_get_node_interface", {"node_id": "PE1", "tp_id": "Gi0"})
    assert text.startswith("Error: no interface 'Gi0' on node 'PE1'")


# --- cnc_list_topology_links ----------------------------------------------------


@respx.mock
async def test_list_links_markdown_lines_l3_and_l2(mcp):
    route = respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_topology_links", {})
    assert route.calls[0].request.headers["Accept"] == YANG_JSON
    assert (
        "# Topology links in Default-network (7 shown, matching 7, collection 7; page 0; "
        "link_type=all)"
    ) in text
    # The SR-MPLS-only lab: srv6-adj-sid=- on every IS-IS row (verified live).
    assert (
        "- PE1:GigabitEthernet0/0/0/0 -> P1:GigabitEthernet0/0/0/0 [ISIS_IPV4_L2] metric=10 "
        "adj-sid=24003 srv6-adj-sid=- bw=1000000kbps"
    ) in text
    assert (
        "- P2:GigabitEthernet0/0/0/0 -> PE2:GigabitEthernet0/0/0/1 [ISIS_IPV4_L2] metric=10 "
        "adj-sid=24005 srv6-adj-sid=- bw=1000000kbps"
    ) in text
    assert (
        "- PE1:GigabitEthernet0/0/0/0 -> P1:GigabitEthernet0/0/0/0 [ETHERNET] rate=1000000 delay=0"
    ) in text
    assert "listed once per direction" in text
    assert "More available" not in text


@respx.mock
async def test_list_links_srv6_rows_show_the_end_x_sid_next_to_the_mpls_adj_sid(mcp):
    # Spec-shaped End.X (srv6-adjacency-sid under the IS-IS link attributes).
    respx.get(NETWORK_URL).mock(return_value=ok(SRV6_NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_topology_links", {"link_type": "isis"})
    assert (
        "- PE1:GigabitEthernet0/0/0/0 -> P1:GigabitEthernet0/0/0/0 [ISIS_IPV4_L2] metric=10 "
        "adj-sid=24003 srv6-adj-sid=fc00:0:1:e000:: bw=1000000kbps"
    ) in text
    assert (
        "- P2:GigabitEthernet0/0/0/0 -> PE2:GigabitEthernet0/0/0/1 [ISIS_IPV4_L2] metric=10 "
        "adj-sid=24005 srv6-adj-sid=- bw=1000000kbps"
    ) in text
    data = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_links", {"link_type": "isis", "response_format": "json"}
        )
    )
    assert data["items"][0] == SRV6_LINK_PE1_P1  # raw keys kept
    # The OSPF End.X SID is read from ospf-link-attributes (synthetic suffix -> 'other').
    text = await call_tool_text(mcp, "cnc_list_topology_links", {"link_type": "other"})
    assert (
        "- P3:GigabitEthernet0/0/0/1 -> PE2:GigabitEthernet0/0/0/1 [OSPF_IPV4] metric=20 "
        "adj-sid=- srv6-adj-sid=2001:db8:6:0:e000:: bw=1000000kbps"
    ) in text


@respx.mock
async def test_list_links_json_is_raw_links_with_envelope(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    data = json.loads(
        await call_tool_text(mcp, "cnc_list_topology_links", {"response_format": "json"})
    )
    assert data["network_id"] == "Default-network"
    assert data["link_type"] == "all" and data["node"] is None
    assert data["total"] == 7 and data["count"] == 7 and data["collection_total"] == 7
    assert data["has_more"] is False and data["next_page"] is None
    assert data["items"] == LINKS


@respx.mock
async def test_list_links_type_filters(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(MIXED_NETWORK_COLLECTION))
    isis = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_links", {"link_type": "ISIS", "response_format": "json"}
        )
    )
    assert isis["total"] == 4 and isis["collection_total"] == 8
    assert {link_type_of(ln["link-id"]) for ln in isis["items"]} == {"ISIS_IPV4_L2"}
    ethernet = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_links", {"link_type": "ethernet", "response_format": "json"}
        )
    )
    assert ethernet["total"] == 3
    assert {link_type_of(ln["link-id"]) for ln in ethernet["items"]} == {"ETHERNET"}
    other = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_links", {"link_type": "other", "response_format": "json"}
        )
    )
    assert other["items"] == [OTHER_LINK]
    text = await call_tool_text(mcp, "cnc_list_topology_links", {"link_type": "other"})
    assert "- PE1:Loopback0 -> PE2:Loopback0 [BGP_EPE] (no attributes)" in text


@respx.mock
async def test_list_links_node_filter_matches_either_end_case_insensitively(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    data = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_links", {"node": "pe1", "response_format": "json"}
        )
    )
    assert [ln["link-id"] for ln in data["items"]] == [
        LINK_PE1_P1["link-id"],
        LINK_P1_PE1["link-id"],
        ETH_PE1_P1["link-id"],
        ETH_P1_PE1["link-id"],
    ]
    assert data["node"] == "pe1" and data["total"] == 4
    data = json.loads(
        await call_tool_text(
            mcp,
            "cnc_list_topology_links",
            {"node": "PE2", "link_type": "isis", "response_format": "json"},
        )
    )
    assert [ln["link-id"] for ln in data["items"]] == [
        LINK_P2_PE2["link-id"],
        LINK_PE2_P2["link-id"],
    ]
    # Exact match only: 'PE' is nobody.
    text = await call_tool_text(mcp, "cnc_list_topology_links", {"node": "PE"})
    assert not text.startswith("Error")
    assert "No links matched link_type=all node=PE." in text


@respx.mock
async def test_list_links_paging(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    page0 = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_links", {"page_size": 3, "page": 0, "response_format": "json"}
        )
    )
    assert [ln["link-id"] for ln in page0["items"]] == [ln["link-id"] for ln in LINKS[:3]]
    assert page0["has_more"] is True and page0["next_page"] == 1
    page2 = json.loads(
        await call_tool_text(
            mcp, "cnc_list_topology_links", {"page_size": 3, "page": 2, "response_format": "json"}
        )
    )
    assert [ln["link-id"] for ln in page2["items"]] == [LINKS[6]["link-id"]]
    assert page2["has_more"] is False and page2["next_page"] is None
    text = await call_tool_text(mcp, "cnc_list_topology_links", {"page_size": 3, "page": 1})
    assert "(3 shown, matching 7, collection 7; page 1; link_type=all)" in text
    assert "More available: repeat with page=2." in text


@respx.mock
async def test_list_links_empty_network_is_not_an_error(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(EMPTY_NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_topology_links", {})
    assert not text.startswith("Error")
    assert "No links: the platform reports none for network 'Default-network'" in text
    assert "SR-PCE gRPC feed" in text


@respx.mock
async def test_list_links_no_networks_at_all_is_not_an_error(mcp):
    respx.get(NETWORK_URL).mock(return_value=httpx.Response(204))
    text = await call_tool_text(mcp, "cnc_list_topology_links", {"link_type": "isis"})
    assert not text.startswith("Error")
    assert "(0 shown, matching 0, collection 0; page 0; link_type=isis)" in text
    assert f"No links: {NO_NETWORKS_NOTE}" in text
    data = json.loads(
        await call_tool_text(mcp, "cnc_list_topology_links", {"response_format": "json"})
    )
    assert data["items"] == [] and data["collection_total"] == 0
    assert data["network_id"] == "Default-network" and data["note"] == NO_NETWORKS_NOTE


@respx.mock
async def test_list_links_unknown_link_type_is_an_error_before_any_request(mcp):
    route = respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_topology_links", {"link_type": "l3"})
    assert text.startswith("Error: Unknown link_type 'l3'")
    assert "all, isis, ethernet, other" in text
    assert not route.called


@respx.mock
async def test_list_links_unknown_network(mcp):
    respx.get(NETWORKS_URL).mock(return_value=ok(NETWORKS_WHOLE))
    text = await call_tool_text(mcp, "cnc_list_topology_links", {"network": "nope"})
    assert text.startswith("Error: no network 'nope'")


@respx.mock
async def test_list_links_400_unknown_element(mcp):
    respx.get(NETWORK_URL).mock(return_value=UNKNOWN_ELEMENT_400)
    text = await call_tool_text(mcp, "cnc_list_topology_links", {})
    assert text.startswith("Error: API request failed with status 400.")
    assert "RESTCONF unknown-element" in text


# --- cnc_get_topology_link ------------------------------------------------------
# The tool reads the networks COLLECTION and selects the link client-side: the keyed
# link=<id> GET is shallow (verified live 2026-09-15 — it omits sr-mpls, see LIVE_LINK_KEYED).


@respx.mock
async def test_get_link_reads_the_collection_and_renders(mcp):
    route = respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    keyed = respx.get(link_url(P2_PE2_ISIS_ENCODED)).mock(
        return_value=ok({"ietf-network-topology-state:link": [LINK_P2_PE2]})
    )
    text = await call_tool_text(mcp, "cnc_get_topology_link", {"link_id": P2_PE2_ISIS_ID})
    request = route.calls[0].request
    assert str(request.url) == NETWORK_URL and request.headers["Accept"] == YANG_JSON
    assert not keyed.called  # the shallow keyed GET is never used
    assert "# Topology link (network Default-network)" in text
    assert (
        "- P2:GigabitEthernet0/0/0/0 -> PE2:GigabitEthernet0/0/0/1 [ISIS_IPV4_L2] metric=10 "
        "adj-sid=24005 srv6-adj-sid=- bw=1000000kbps"
    ) in text
    assert f"link-id: {P2_PE2_ISIS_ID}" in text
    assert "source: P2 / GigabitEthernet0/0/0/0" in text
    assert "destination: PE2 / GigabitEthernet0/0/0/1" in text
    assert "L3: name=P2-PE2 metric1=10 metric2=- domain-id=0 max-bandwidth-kbps=1000000" in text
    assert "IS-IS: level=2 system-id=0000.0000.0003" in text
    assert "SR-MPLS: advertise-protection=unprotected information-source=isis" in text
    assert "Adjacency SIDs (1):" in text
    assert (
        "- 24005 backup=False persistent=False local=True address-family=ipv4 value-type=absolute"
    ) in text
    # The SR-MPLS-only lab: an explicit, symmetric "none" for the End.X block (verified live).
    assert "SRv6 adjacency SIDs (0):" in text
    assert "- (none: no End.X SID (srv6-adjacency-sid) advertised on this adjacency" in text
    assert "OSPF:" not in text and "Flex-Algo admin-group" not in text


@respx.mock
async def test_get_link_live_shapes_the_collection_carries_the_adjacency_sid(mcp):
    """Regression for the shallow keyed GET: with the verbatim live collection shape the tool
    renders adj-sid=24001 — the keyed shape (LIVE_LINK_KEYED) has no sr-mpls at all, which is
    what the old keyed read rendered as adj-sid=- / Adjacency SIDs (0)."""
    assert SR_MPLS not in LIVE_LINK_KEYED[L3_LINK] and SR_MPLS in LIVE_LINK_FULL[L3_LINK]
    assert topology.link_line(LIVE_LINK_KEYED).endswith(
        "metric=10 adj-sid=- srv6-adj-sid=- bw=1000000kbps"
    )
    respx.get(NETWORK_URL).mock(return_value=ok(LIVE_NETWORK_COLLECTION))
    keyed = respx.get(link_url(quote(LIVE_LINK_ID, safe=""))).mock(
        return_value=ok({"ietf-network-topology-state:link": [LIVE_LINK_KEYED]})
    )
    text = await call_tool_text(mcp, "cnc_get_topology_link", {"link_id": LIVE_LINK_ID})
    assert not keyed.called
    assert (
        "- PE1:GigabitEthernet0/0/0/0 -> P1:GigabitEthernet0/0/0/0 [ISIS_IPV4_L2] metric=10 "
        "adj-sid=24001 srv6-adj-sid=- bw=1000000kbps"
    ) in text
    assert "SR-MPLS: advertise-protection=single information-source=isis" in text
    assert "Adjacency SIDs (1):" in text
    assert (
        "- 24001 backup=False persistent=True local=True address-family=ipv4 value-type=absolute"
    ) in text
    data = json.loads(
        await call_tool_text(
            mcp, "cnc_get_topology_link", {"link_id": LIVE_LINK_ID, "response_format": "json"}
        )
    )
    assert data == LIVE_LINK_FULL


@respx.mock
async def test_get_link_renders_srv6_end_x_sids_next_to_the_mpls_adjacency_sids(mcp):
    # Spec-shaped End.X entry (7.2 model): every leaf, the derived locator, the flex-algo group.
    respx.get(NETWORK_URL).mock(return_value=ok(SRV6_NETWORK_COLLECTION))
    text = await call_tool_text(
        mcp, "cnc_get_topology_link", {"link_id": SRV6_LINK_PE1_P1["link-id"]}
    )
    assert "adj-sid=24003 srv6-adj-sid=fc00:0:1:e000:: bw=1000000kbps" in text
    assert "Flex-Algo admin-group: 0x1" in text
    assert "Adjacency SIDs (1):" in text and "- 24003 backup=False" in text
    assert "SRv6 adjacency SIDs (1):" in text
    assert (
        "- fc00:0:1:e000:: behavior=uA algorithm=0 structure=32/16/16/0 (lb/ln/func/arg) "
        "locator=fc00:0:1::/48 (uSID F3216) protected=False flags=0 weight=0"
    ) in text
    assert "(none: no End.X SID" not in text


@respx.mock
async def test_get_link_renders_an_ospf_adjacency_with_its_end_x_sid_and_admin_group(mcp):
    """Spec-shaped OSPF link (7.2 model, never seen live): the OSPF line with the string
    area-id, the End.X SID read from ospf-link-attributes with a classic 40/24 structure and
    the flex-algo admin-group from the same container; no IS-IS or SR-MPLS lines at all."""
    respx.get(NETWORK_URL).mock(return_value=ok(SRV6_NETWORK_COLLECTION))
    text = await call_tool_text(
        mcp, "cnc_get_topology_link", {"link_id": SRV6_OSPF_LINK_P3_PE2["link-id"]}
    )
    assert (
        "- P3:GigabitEthernet0/0/0/1 -> PE2:GigabitEthernet0/0/0/1 [OSPF_IPV4] metric=20 "
        "adj-sid=- srv6-adj-sid=2001:db8:6:0:e000:: bw=1000000kbps"
    ) in text
    assert "L3: name=P3-PE2 metric1=20 metric2=- domain-id=0 max-bandwidth-kbps=1000000" in text
    assert "OSPF: router-id=10.0.0.6 area-id=0.0.0.0" in text
    assert "IS-IS:" not in text and "SR-MPLS:" not in text
    assert "Flex-Algo admin-group: 0x2" in text
    assert "Adjacency SIDs (0):\n- (none)\n" in text
    assert "SRv6 adjacency SIDs (1):" in text
    assert (
        "- 2001:db8:6:0:e000:: behavior=End.X algorithm=0 structure=40/24/16/0 (lb/ln/func/arg) "
        "locator=2001:db8:6::/64 (classic) protected=True flags=0 weight=0"
    ) in text
    data = json.loads(
        await call_tool_text(
            mcp,
            "cnc_get_topology_link",
            {"link_id": SRV6_OSPF_LINK_P3_PE2["link-id"], "response_format": "json"},
        )
    )
    assert data == SRV6_OSPF_LINK_P3_PE2


@respx.mock
async def test_get_link_ethernet_markdown_shows_l2_attributes(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_get_topology_link", {"link_id": ETH_PE1_P1["link-id"]})
    assert "[ETHERNET] rate=1000000 delay=0" in text
    assert "L2 attributes as the platform reports them:" in text
    assert '"rate": 1000000' in text
    assert "Adjacency SIDs" not in text and "SRv6 adjacency SIDs" not in text


@respx.mock
async def test_get_link_json_is_the_raw_link(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    text = await call_tool_text(
        mcp, "cnc_get_topology_link", {"link_id": P2_PE2_ISIS_ID, "response_format": "json"}
    )
    assert json.loads(text) == LINK_P2_PE2


@respx.mock
async def test_get_link_missing_from_the_collection_is_not_found_with_verbatim_hint(mcp):
    missing_id = "does : not : exist : a : b : ISIS_IPV4_L2"
    respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_get_topology_link", {"link_id": missing_id})
    assert text.startswith(f"Error: no link '{missing_id}' in topology 'Default-network'")
    assert "7 links were checked client-side" in text
    assert "cnc_list_topology_links" in text and "verbatim" in text
    # Exact and case-sensitive: the reverse direction and a case variant are other links.
    text = await call_tool_text(mcp, "cnc_get_topology_link", {"link_id": P2_PE2_ISIS_ID.lower()})
    assert text.startswith("Error: no link 'p2 : gigabitethernet0/0/0/0")


@respx.mock
async def test_get_link_no_networks_at_all_is_not_found_with_the_note(mcp):
    respx.get(NETWORK_URL).mock(return_value=ok({}))
    text = await call_tool_text(mcp, "cnc_get_topology_link", {"link_id": P2_PE2_ISIS_ID})
    assert text.startswith(f"Error: no link '{P2_PE2_ISIS_ID}' in topology 'Default-network': ")
    assert NO_NETWORKS_NOTE in text


@respx.mock
async def test_get_link_unknown_network_when_others_exist(mcp):
    respx.get(NETWORKS_URL).mock(return_value=ok(NETWORKS_WHOLE))
    text = await call_tool_text(
        mcp, "cnc_get_topology_link", {"link_id": P2_PE2_ISIS_ID, "network": "nope"}
    )
    assert text.startswith("Error: no network 'nope'")
    assert "Networks present: Default-network" in text


@respx.mock
async def test_get_link_plain_404_is_not_reported_as_missing(mcp):
    respx.get(NETWORK_URL).mock(return_value=PLAIN_404)
    text = await call_tool_text(mcp, "cnc_get_topology_link", {"link_id": P2_PE2_ISIS_ID})
    assert_plain_404(text, "no link")


@respx.mock
async def test_get_link_accepts_the_prefixed_link_id_spelling(mcp):
    prefixed = {
        "ietf-network-topology-state:link-id": P2_PE2_ISIS_ID,
        **{k: v for k, v in LINK_P2_PE2.items() if k != "link-id"},
    }
    respx.get(NETWORK_URL).mock(
        return_value=ok(
            {"ietf-network-state:networks": {"network": [{**NETWORK, LINK_LIST: [prefixed]}]}}
        )
    )
    text = await call_tool_text(mcp, "cnc_get_topology_link", {"link_id": P2_PE2_ISIS_ID})
    assert text.startswith("# Topology link (network Default-network)")
    assert f"link-id: {P2_PE2_ISIS_ID}" in text
    assert "adj-sid=24005" in text


@respx.mock
async def test_get_link_400_unknown_element_from_bare_errors_key(mcp):
    respx.get(NETWORK_URL).mock(return_value=UNKNOWN_ELEMENT_400)
    text = await call_tool_text(mcp, "cnc_get_topology_link", {"link_id": P2_PE2_ISIS_ID})
    assert text.startswith("Error: API request failed with status 400.")
    assert "Platform said: RESTCONF unknown-element: Unknown element: ietf-network:networks" in text


# --- cnc_list_srv6_locators -----------------------------------------------------


@respx.mock
async def test_list_srv6_locators_on_the_sr_mpls_lab_says_none_with_the_underlay_hint(mcp):
    """What the lab answers today (verified live 2026-09-15): the stable sentence the SRv6
    readiness playbook keys on, the network-types verdict and what has to exist first."""
    route = respx.get(NETWORK_URL).mock(return_value=ok(NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_srv6_locators", {})
    assert route.calls[0].request.headers["Accept"] == YANG_JSON
    assert not text.startswith("Error")
    assert text.startswith(
        "# SRv6 locators in Default-network (0 locators on 0 of 5 nodes; network-types srv6: "
        "absent)"
    )
    assert f"{NO_SRV6_LOCATORS} (network-types carries no srv6): no node carries a" in text
    assert "SRv6 state appears in the topology once the routers run an SRv6 locator" in text
    assert "segment-routing srv6 locators locator <name> prefix <block>::/48" in text
    assert "hw-module profile segment-routing srv6 mode micro-segment format f3216" in text
    assert "after a reload" in text
    assert "not been verified against a live SRv6 feed yet" in text
    assert "Locators are DERIVED" in text
    data = json.loads(
        await call_tool_text(mcp, "cnc_list_srv6_locators", {"response_format": "json"})
    )
    assert data == {
        "network_id": "Default-network",
        "srv6_network_type": False,
        "nodes": 5,
        "count": 0,
        "items": [],
    }


@respx.mock
async def test_list_srv6_locators_rows_per_node_and_locator(mcp):
    # Spec-shaped: PE1 with two locators (algorithm 0 and 128), P1 the same, P3 classic.
    respx.get(NETWORK_URL).mock(return_value=ok(SRV6_NETWORK_COLLECTION))
    text = await call_tool_text(mcp, "cnc_list_srv6_locators", {})
    assert text.startswith(
        "# SRv6 locators in Default-network (5 locators on 3 of 5 nodes; network-types srv6: "
        "present)"
    )
    assert NO_SRV6_LOCATORS not in text
    assert (
        "- **PE1** fc00:0:1::/48 block/node=32/16 format=uSID F3216 algorithms=0 behaviors=uN "
        "sids=1 igp=IS-IS level-2"
    ) in text
    assert (
        "- **PE1** fc00:1:1::/48 block/node=32/16 format=uSID F3216 algorithms=128 "
        "behaviors=uN sids=1 igp=IS-IS level-2"
    ) in text
    assert "- **P1** fc00:0:2::/48 " in text
    assert (
        "- **P3** 2001:db8:6::/64 block/node=40/24 format=classic algorithms=0 behaviors=End "
        "sids=1 igp=OSPF area 0.0.0.0"
    ) in text
    assert "'uSID F3216' = 32-bit block + 16-bit node id + 16-bit function" in text
    data = json.loads(
        await call_tool_text(mcp, "cnc_list_srv6_locators", {"response_format": "json"})
    )
    assert data["srv6_network_type"] is True and data["nodes"] == 5 and data["count"] == 5
    assert data["items"][0] == {
        "node": "PE1",
        "locator": "fc00:0:1::/48",
        "lb_length": 32,
        "ln_length": 16,
        "func_length": 16,
        "arg_length": 0,
        "format": "uSID F3216",
        "algorithms": [0],
        "endpoint_behaviors": ["uN"],
        "igp": ["IS-IS level-2"],
        "sid_count": 1,
        "sids": [srv6_node_sid("fc00:0:1::", 0)],
    }


@respx.mock
async def test_list_srv6_locators_srv6_type_without_sids_says_which_half_is_missing(mcp):
    # network-types carries srv6 but no node advertises a SID yet: the sentence says so.
    network = {**SRV6_NETWORK, "node": [PE2, SW1], LINK_LIST: [LINK_P2_PE2]}
    respx.get(NETWORK_URL).mock(
        return_value=ok({"ietf-network-state:networks": {"network": [network]}})
    )
    text = await call_tool_text(mcp, "cnc_list_srv6_locators", {})
    assert "(0 locators on 0 of 2 nodes; network-types srv6: present)" in text
    assert (
        f"{NO_SRV6_LOCATORS} (network-types carries srv6, but no node advertises an srv6-node-sid)"
    ) in text


@respx.mock
async def test_list_srv6_locators_no_networks_at_all_is_not_an_error(mcp):
    respx.get(NETWORK_URL).mock(return_value=httpx.Response(204))
    text = await call_tool_text(mcp, "cnc_list_srv6_locators", {})
    assert not text.startswith("Error")
    assert "(0 locators on 0 of 0 nodes; network-types srv6: absent)" in text
    assert f"{NO_SRV6_LOCATORS}: {NO_NETWORKS_NOTE}" in text
    data = json.loads(
        await call_tool_text(mcp, "cnc_list_srv6_locators", {"response_format": "json"})
    )
    assert data["items"] == [] and data["note"] == NO_NETWORKS_NOTE


@respx.mock
async def test_list_srv6_locators_unknown_network_and_api_failures(mcp):
    respx.get(NETWORKS_URL).mock(return_value=ok(NETWORKS_WHOLE))
    text = await call_tool_text(mcp, "cnc_list_srv6_locators", {"network": "nope"})
    assert text.startswith("Error: no network 'nope'")
    respx.get(NETWORK_URL).mock(return_value=UNKNOWN_ELEMENT_400)
    text = await call_tool_text(mcp, "cnc_list_srv6_locators", {})
    assert text.startswith("Error: API request failed with status 400.")
    assert "RESTCONF unknown-element" in text
    respx.get(NETWORK_URL).mock(return_value=PLAIN_404)
    assert_plain_404(await call_tool_text(mcp, "cnc_list_srv6_locators", {}), "no network")


async def test_list_srv6_locators_schema_rejects_a_blank_network(mcp):
    with pytest.raises(ToolError, match="network"):
        await call_tool_text(mcp, "cnc_list_srv6_locators", {"network": ""})


# --- Registration ---------------------------------------------------------------


async def test_tools_registered_read_only_and_flat(mcp):
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    assert set(tools) == {
        "cnc_get_topology_summary",
        "cnc_list_topology_nodes",
        "cnc_get_topology_node",
        "cnc_list_node_interfaces",
        "cnc_get_node_interface",
        "cnc_list_topology_links",
        "cnc_get_topology_link",
        "cnc_list_srv6_locators",
    }
    for tool in tools.values():
        assert tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.idempotent_hint is True, tool.name
        assert tool.description and len(tool.description) > 40, tool.name
        for prop in tool.input_schema.get("properties", {}).values():
            assert prop.get("type") != "object", tool.name


def test_prefix_sid_label_adds_index_to_srgb_and_passes_absolute_through():
    from cnc_mcp.tools.topology import prefix_sid_label, srgb_lower_bound

    l3 = {SR_MPLS: {"srgb": [{"lower-bound": 16000, "upper-bound": 23999}]}}
    assert srgb_lower_bound(l3) == 16000
    assert srgb_lower_bound({}) is None
    assert prefix_sid_label({"value-type": "index", "start-sid": 4}, 16000) == 16004
    assert prefix_sid_label({"value-type": "absolute", "start-sid": 16004}, 16000) == 16004
    assert prefix_sid_label({"sid": 16004}, None) == 16004  # OpenAPI spelling: a label
    assert prefix_sid_label({"value-type": "index", "start-sid": 4}, None) is None
    assert prefix_sid_label({"start-sid": "x"}, 16000) is None
    assert prefix_sid_label({}, 16000) is None
