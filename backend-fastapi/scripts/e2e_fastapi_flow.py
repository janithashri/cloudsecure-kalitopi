"""
End-to-end smoke flow for backend-fastapi only:
register/login -> provider connect/test -> inventory pull -> optional deep scan -> attack/GDS.
"""

from __future__ import annotations

import argparse
import json
import time
from typing import Any

import requests


def _req(method: str, url: str, token: str | None = None, **kwargs) -> requests.Response:
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Token {token}"
    if "json" in kwargs:
        headers["Content-Type"] = "application/json"
    r = requests.request(method, url, headers=headers, timeout=30, **kwargs)
    return r


def _ok(r: requests.Response, ctx: str) -> Any:
    if r.status_code >= 400:
        raise RuntimeError(f"{ctx} failed: {r.status_code} {r.text}")
    if not r.text:
        return {}
    return r.json()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://localhost:8000")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--email", default="")
    p.add_argument("--provider-name", default="aws-e2e")
    p.add_argument("--account-id", required=True)
    p.add_argument("--role-name", default="CloudSecureRole")
    p.add_argument("--run-deep-scan", action="store_true")
    p.add_argument("--source-node-id", default="")
    p.add_argument("--target-node-id", default="")
    args = p.parse_args()

    base = args.base_url.rstrip("/")

    # Register best-effort
    reg = _req(
        "POST",
        f"{base}/api/auth/register/",
        json={"username": args.username, "email": args.email or args.username, "password": args.password},
    )
    if reg.status_code not in (200, 201, 400):
        _ok(reg, "register")

    login = _ok(
        _req("POST", f"{base}/api/auth/login/", json={"username": args.username, "password": args.password}),
        "login",
    )
    token = login["token"]
    print("[ok] login")

    # Upsert-ish provider by create then fallback to existing by name
    prov_resp = _req(
        "POST",
        f"{base}/api/v1/providers/",
        token=token,
        json={
            "name": args.provider_name,
            "aws_account_id": args.account_id,
            "inventory_role_name": args.role_name,
        },
    )
    if prov_resp.status_code in (200, 201):
        provider = prov_resp.json()
    else:
        providers = _ok(_req("GET", f"{base}/api/v1/providers/", token=token), "list providers")
        provider = next((x for x in providers if x.get("name") == args.provider_name), None)
        if provider is None:
            raise RuntimeError(f"provider create failed and fallback lookup not found: {prov_resp.status_code} {prov_resp.text}")
    provider_id = provider["id"]
    print(f"[ok] provider id={provider_id}")

    test_conn = _ok(
        _req("POST", f"{base}/api/v1/providers/{provider_id}/test-connection/", token=token),
        "test connection",
    )
    print(f"[ok] test-connection: {json.dumps(test_conn)}")

    pull = _ok(
        _req("POST", f"{base}/api/v1/providers/{provider_id}/inventory-pull/", token=token),
        "inventory pull",
    )
    print(f"[ok] inventory-pull accepted: {json.dumps(pull)}")

    if args.run_deep_scan:
        ds = _ok(
            _req("POST", f"{base}/api/v1/deep-scan/", token=token, json={"provider_id": provider_id}),
            "deep scan start",
        )
        scan_id = ds["scan_id"]
        print(f"[ok] deep-scan started scan_id={scan_id}")
        for _ in range(40):
            time.sleep(15)
            status = _ok(_req("GET", f"{base}/api/v1/deep-scan/{scan_id}/", token=token), "deep scan status")
            state = status.get("state")
            print(f"[info] deep-scan state={state} progress={status.get('progress')}")
            if state in ("COMPLETED", "FAILED"):
                break

        attacks = _ok(
            _req("POST", f"{base}/api/v1/providers/{provider_id}/attack-engine/run/", token=token, json={"scan_id": scan_id}),
            "attack engine run",
        )
        print(f"[ok] attack-engine results={len(attacks.get('results', []))}")

        if args.source_node_id and args.target_node_id:
            gds = _ok(
                _req(
                    "POST",
                    f"{base}/api/v1/providers/{provider_id}/gds/shortest-path/",
                    token=token,
                    json={
                        "source_node_id": args.source_node_id,
                        "target_node_id": args.target_node_id,
                        "scan_id": scan_id,
                    },
                ),
                "gds shortest path",
            )
            print(f"[ok] gds shortest-path node_count={gds.get('node_count')} total_cost={gds.get('total_cost')}")

    print("[done] e2e flow completed")


if __name__ == "__main__":
    main()
