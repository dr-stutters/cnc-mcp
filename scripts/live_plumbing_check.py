#!/usr/bin/env python3
"""Live check of the module-0 plumbing against a real Crosswork instance.

Exercises every dialect helper (RESTCONF NBI, EMF RESTCONF, routing probe, the
JSON-over-POST variants) through the real ApiClient, so a platform change that
breaks a verified assumption shows up here before it shows up in a tool.
Read-only. Connection settings come from .env like the server.

    uv run python scripts/live_plumbing_check.py
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any

from cnc_mcp import crosswork, emf, probe, restconf
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError, http_error
from cnc_mcp.server import create_auth, quiet_http_logging

PASS, FAIL = "ok  ", "FAIL"
results: list[tuple[str, str, str]] = []


def _json_or_none(response: Any) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def record(ok: bool, name: str, detail: str = "") -> None:
    results.append((PASS if ok else FAIL, name, detail))
    print(f"{PASS if ok else FAIL} {name}: {detail[:120]}")


async def run() -> int:
    logging.basicConfig(stream=sys.stderr, level="WARNING")
    quiet_http_logging()
    settings = Settings()
    client = ApiClient(settings, create_auth(settings))
    yang = {"Accept": restconf.YANG_JSON}
    try:
        # ---- RESTCONF NBI: collection + keyed shapes, key ignored, 409 not-found, errors, RPC ----
        nets = restconf.unwrap_list(
            await client.request_json(
                "GET", f"{restconf.TOPOLOGY_NBI}/data/ietf-network-state:networks", headers=yang
            ),
            "ietf-network-state",
            "network",
        )
        record(
            bool(nets) and nets[0].get("network-id") == "Default-network",
            "restconf: networks collection unwrap",
            f"{len(nets)} network(s)",
        )
        net = restconf.unwrap_list(
            await client.request_json(
                "GET",
                f"{restconf.TOPOLOGY_NBI}/data/ietf-network-state:networks/network=does-not-exist",
                headers=yang,
            ),
            "ietf-network-state",
            "network",
        )
        kept = restconf.select_key(net, "network-id", "does-not-exist")
        record(
            len(net) >= 1 and kept == [],
            "restconf: top-level key ignored by platform, select_key filters",
            f"raw={len(net)} filtered={len(kept)}",
        )
        r = await client.request(
            "GET",
            f"{restconf.TOPOLOGY_NBI}/data/ietf-network-state:networks/network=Default-network/node=nope",
            headers=yang,
            raise_on_error=False,
        )
        data = r.json()
        record(
            restconf.is_not_found(r.status_code, data),
            "restconf: 409 data-missing is not-found",
            f"{r.status_code} {restconf.restconf_error_message(r.status_code, data)}",
        )
        # keyed reads: encode_key makes slashes/spaces/colons routable; a raw "/" is a
        # plain 404 (malformed URL), an encoded unknown key is 409 (not-found)
        link_id = "P2 : GigabitEthernet0/0/0/0 : PE2 : GigabitEthernet0/0/0/1 : ISIS_IPV4_L2"
        link_url = (
            f"{restconf.TOPOLOGY_NBI}/data/ietf-network-state:networks/network=Default-network"
            "/ietf-network-topology-state:link="
        )
        r = await client.request(
            "GET", link_url + restconf.encode_key(link_id), headers=yang, raise_on_error=False
        )
        links = restconf.unwrap_list(r.json(), "ietf-network-topology-state", "link")
        record(
            r.status_code == 200 and restconf.select_key(links, "link-id", link_id) != [],
            "restconf: encode_key routes a link id with '/', ' ' and ':'",
            f"{r.status_code} {len(links)} link(s)",
        )
        r = await client.request("GET", link_url + link_id, headers=yang, raise_on_error=False)
        record(
            r.status_code == 404 and not restconf.is_not_found(r.status_code, _json_or_none(r)),
            "restconf: unencoded '/' in a key is a plain 404, not not-found",
            f"{r.status_code}",
        )
        r = await client.request(
            "GET",
            link_url + restconf.encode_key("no : such : link : a : b : ISIS_IPV4_L2"),
            headers=yang,
            raise_on_error=False,
        )
        record(
            restconf.is_not_found(r.status_code, r.json()),
            "restconf: encoded unknown link key is 409 data-missing",
            f"{r.status_code}",
        )
        r = await client.request(
            "GET",
            f"{restconf.TOPOLOGY_NBI}/data/cisco-crosswork-performance-metrics"
            ":igp-links-performance-metrics",
            headers=yang,
            raise_on_error=False,
        )
        record(
            restconf.is_not_found(r.status_code, r.json()),
            "restconf: PM container cannot be listed unkeyed (409)",
            f"{r.status_code}",
        )
        r = await client.request(
            "GET",
            f"{restconf.TOPOLOGY_NBI}/data/cisco-crosswork-segment-routing-p2mp-policy"
            ":p2mp-policies",
            headers=yang,
            raise_on_error=False,
        )
        record(
            r.status_code == 200 and r.json() == {},
            "restconf: empty container answers {} (not 409)",
            f"{r.status_code} {r.text[:40]!r}",
        )
        r = await client.request(
            "GET", f"{restconf.TOPOLOGY_NBI}/data/no-such:thing", headers=yang, raise_on_error=False
        )
        errs = restconf.parse_restconf_errors(r.json())
        record(
            r.status_code == 400 and errs and errs[0]["tag"] == restconf.TAG_UNKNOWN_ELEMENT,
            "restconf: bare 'errors' document parsed",
            f"{r.status_code} {errs[0] if errs else None}",
        )
        record(
            "unknown YANG" in str(http_error(r)) or "unknown-element" in str(http_error(r)),
            "errors: RESTCONF hint rendered",
            str(http_error(r))[:110],
        )
        out = restconf.rpc_output(
            await client.request_json(
                "POST",
                restconf.rpc_path(
                    restconf.OPTIMIZATION_NBI,
                    "cisco-crosswork-optimization-engine-operations",
                    "get-plan",
                ),
                json_body=restconf.rpc_body(),
                headers={**yang, "Content-Type": restconf.YANG_JSON},
            ),
            "cisco-crosswork-optimization-engine-operations",
        )
        try:
            restconf.check_rpc_output(out, "get-plan")
            record(False, "restconf: RPC status:error inside 200 raises", "did not raise")
        except PlatformError as e:
            record("failed" in str(e), "restconf: RPC status:error inside 200 raises", str(e)[:110])
        r = await client.request(
            "POST",
            restconf.rpc_path(
                restconf.OPTIMIZATION_NBI,
                "cisco-crosswork-optimization-engine-opm-operations",
                "list-opm-package",
            ),
            json_body=restconf.rpc_body(),
            headers={**yang, "Content-Type": restconf.YANG_JSON},
            raise_on_error=False,
        )
        record(
            bool(restconf.explain_empty_500(r.status_code, r.text)),
            "restconf: empty-body 500 explained",
            f"{r.status_code} {restconf.explain_empty_500(r.status_code, r.text) or ''}",
        )
        # NSO proxy: yang-data+json required; device list
        devs = restconf.unwrap_list(
            await client.request_json(
                "GET", f"{restconf.NSO_PROXY}/data/tailf-ncs:devices/device", headers=yang
            ),
            "tailf-ncs",
            "device",
        )
        record(
            len(devs) >= 1,
            "restconf: NSO proxy device list",
            f"{[d.get('name') for d in devs][:6]}",
        )
        r = await client.request(
            "POST",
            f"{restconf.NSO_PROXY}/data/tailf-ncs:devices/device={devs[0]['name']}/connect",
            json_body={},
            headers=yang,
            raise_on_error=False,
        )
        record(
            r.status_code == 415 and restconf.parse_restconf_errors(r.json()),
            "restconf: NSO proxy rejects application/json with 415 (ietf-restconf:errors parsed)",
            f"{r.status_code}",
        )

        # ---- EMF RESTCONF: JSON only for exact Accept; envelope; empty shape ----
        data = await client.request_json(
            "GET",
            f"{emf.EMF_INVENTORY}/resource-physical:node",
            params=emf.page_params(0, 2),
            headers=emf.EMF_HEADERS,
        )
        items, header = emf.unwrap(data)
        record(
            isinstance(data, dict) and emf.data_key(data) == "nd.node" and len(items) <= 2,
            "emf: inventory node envelope (nd.node) + paging",
            f"{len(items)} item(s), header={header}",
        )
        r = await client.request(
            "GET",
            f"{emf.EMF_INVENTORY}/resource-physical:node",
            params=emf.page_params(0, 1),
            headers={"Accept": restconf.YANG_JSON},
        )
        record(
            emf.looks_like_xml(r.text),
            "emf: any other Accept yields XML (detected)",
            emf.explain_xml(r.text)[:100],
        )
        data = await client.request_json(
            "GET",
            f"{emf.EMF_ALARM}/rtm:alarm",
            params=emf.page_params(0, 5),
            headers=emf.EMF_HEADERS,
        )
        items, header = emf.unwrap(data)
        record(
            header.get("last_index") is not None,
            "emf: rtm:alarm envelope (possibly empty, last_index -1)",
            f"{len(items)} alarm(s), header={header}",
        )

        # ---- probe: real signatures ----
        cases = {
            "/crosswork/aa/v1/x": probe.Routing.UNROUTED,
            "/crosswork/nca/v1/servicestatus": probe.Routing.UNROUTED,
            "/crosswork/probemgr/v1/x": probe.Routing.ROUTED_NO_PATH,
            "/crosswork/swim/v1/x": probe.Routing.ROUTED_NO_PATH,
            "/crosswork/config/v1/x": probe.Routing.ROUTED_NO_PATH,
            "/crosswork/aaa/v1/user": probe.Routing.AVAILABLE,
        }
        for path, expected in cases.items():
            got = await probe.probe_path(client, path)
            record(got == expected, f"probe: {path}", f"{got} (expected {expected})")
        got = await probe.probe_path(client, "/crosswork/inventory/v1/__probe__")
        record(
            got in (probe.Routing.ROUTED_NO_RBAC, probe.Routing.ROUTED_BAD_BODY),
            "probe: inventory unknown path is routed (403 no-RBAC or 500 NATS)",
            str(got),
        )
        got = await probe.probe_path(
            client, "/crosswork/dg-manager/v2/dg/query", method="POST", json_body={"criteria": "x"}
        )
        record(
            got == probe.Routing.ROUTED_BAD_BODY,
            "probe: dg-manager unknown field -> ROUTED_BAD_BODY",
            str(got),
        )

        # ---- JSON-over-POST variants ----
        dgs = await client.request_json(
            "POST",
            "/crosswork/dg-manager/v2/dg/query",
            json_body=crosswork.dg_query_body("gateways"),
        )
        record(
            isinstance(dgs, dict) and dgs.get("data"),
            "crosswork: dg_query_body gateways",
            f"{[d.get('name') for d in dgs.get('data', [])]}",
        )
        pools = await client.request_json(
            "POST",
            "/crosswork/dg-manager/v2/hapool/query",
            json_body=crosswork.dg_query_body("pools"),
        )
        record(
            isinstance(pools, dict) and pools.get("data"),
            "crosswork: dg_query_body pools",
            f"{[p.get('name') for p in pools.get('data', [])]}",
        )
        col = await client.request_json("POST", "/crosswork/collection/v1/jobs/query", json_body={})
        try:
            crosswork.check_collection_result(col, "collection jobs/query")
            record(
                True, "crosswork: collection result ACCEPTED", str(col.get("query_options"))[:90]
            )
        except PlatformError as e:
            record(False, "crosswork: collection result ACCEPTED", str(e))
        bad = await client.request_json("POST", "/crosswork/alarm/v1/query", json_body={})
        try:
            crosswork.check_alarm_v1(bad, "alarm/v1 query {}")
            record(False, "crosswork: alarm/v1 200-error raises", "did not raise")
        except PlatformError as e:
            record(True, "crosswork: alarm/v1 200-error raises", str(e)[:100])
        alarms = await client.request_json(
            "POST",
            "/crosswork/alarms/v1/query",
            json_body={"openAlarmsOnly": True, "criteria": crosswork.alarms_criteria(3, 0)},
        )
        record(
            isinstance(alarms, dict) and alarms.get("state") == "Success",
            "crosswork: alarms_criteria grammar",
            f"{len(alarms.get('alarms', []))} alarm(s)",
        )
        # raw text body + content-type override on the wire: POST a body the platform
        # rejects and confirm the request itself went out with our headers
        r = await client.request(
            "POST",
            "/crosswork/dg-manager/v2/dg/query",
            content="not json",
            headers={"Content-Type": "text/plain"},
            raise_on_error=False,
        )
        record(
            r.status_code in (400, 415, 500)
            and r.request.headers.get("Content-Type") == "text/plain",
            "client: raw content body with caller Content-Type",
            f"{r.status_code} ct={r.request.headers.get('Content-Type')}",
        )
        # the one real raw-text consumer: the EMS job scheduler answers a bare false
        # (HTTP 200) to an unknown job key — verified live 2026-09-13, tools/ems_jobs.py
        r = await client.request(
            "POST",
            "/crosswork/rs/json/jobSchedulerServiceInv/v1/suspendJob",
            content="nope:Inventory",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            retryable=False,
            raise_on_error=False,
        )
        record(
            r.status_code == 200 and r.text.strip() == "false",
            "client: job scheduler raw key body (unknown job -> bare false)",
            f"{r.status_code} body={r.text.strip()[:20]!r}",
        )
    finally:
        await client.aclose()
    failures = sum(1 for s, _, _ in results if s == FAIL)
    print(
        f"\n{len(results) - failures}/{len(results)} checks passed"
        + ("" if not failures else f" — {failures} FAILED")
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
