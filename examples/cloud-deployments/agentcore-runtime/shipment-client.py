#!/usr/bin/env python3
"""Run a deterministic customer-support trajectory through the Box proxy."""
import argparse
import http.client
import json
import os
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True)
    parser.add_argument("--scenario", choices=["shipment", "failed", "unrelated", "refund-first"], required=True)
    args = parser.parse_args()
    proxy = urlsplit(os.environ["HTTP_PROXY"])
    service = urlsplit(args.service)
    steps = []

    def request(label, method, path, key=None):
        connection = http.client.HTTPConnection(proxy.hostname, proxy.port, timeout=15)
        headers = {"Host": service.netloc, "Connection": "close"}
        body = None
        if method == "POST":
            headers["Content-Type"] = "application/json"
            headers["Idempotency-Key"] = key or "shipment-demo"
            body = "{}"
        connection.request(method, args.service + path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read().decode()
        try:
            data = json.loads(raw)
        except ValueError:
            data = raw
        step = {"label": label, "method": method, "path": path,
                "status": response.status,
                "box_refused": response.getheader("x-strands-box-egress") == "refused",
                "body": data}
        steps.append(step)
        connection.close()
        return step

    case = request("read_customer_case", "GET", "/orders/42")
    if args.scenario == "shipment":
        request("premature_dispatch", "POST", "/orders/42/replacement", "replacement-42")
        request("successful_eligibility", "GET", "/orders/42/replacement")
        dispatch = request("dispatch_replacement", "POST", "/orders/42/replacement", "replacement-42")
        request("repeat_dispatch", "POST", "/orders/42/replacement", "replacement-42")
        request("competing_refund", "POST", "/orders/42/refund", "refund-42")
        receipt = dispatch["body"]
        if dispatch["status"] == 201 and isinstance(receipt, dict) and receipt.get("order_id") == 42 and receipt.get("resolution") == "dispatch":
            customer_reply = (
                "I am sorry your " + receipt["item"].lower() + " missed its delivery date. "
                "Your replacement has been dispatched and is expected by " + receipt["estimated_delivery"] + ". "
                "Your confirmation is " + receipt["effect_id"] + "."
            )
        else:
            customer_reply = "I could not confirm a replacement dispatch. Please check the order service before retrying."
    elif args.scenario == "refund-first":
        request("failed_refund", "POST", "/orders/42/refund", "invalid key")
        refund = request("refund_order", "POST", "/orders/42/refund", "refund-42")
        request("repeat_refund", "POST", "/orders/42/refund", "refund-42")
        request("successful_eligibility", "GET", "/orders/42/replacement")
        request("dispatch_after_refund", "POST", "/orders/42/replacement", "replacement-42")
        receipt = refund["body"]
        if refund["status"] == 201 and isinstance(receipt, dict) and receipt.get("order_id") == 42 and receipt.get("resolution") == "refund":
            customer_reply = "Your refund is confirmed. Your confirmation is " + receipt["effect_id"] + "."
        else:
            customer_reply = "I could not confirm a refund. Please check the order service before retrying."
    elif args.scenario == "failed":
        request("failed_eligibility", "GET", "/orders/42/replacement")
        request("dispatch_after_failed_check", "POST", "/orders/42/replacement", "replacement-42")
        customer_reply = "The eligibility check did not pass. No replacement was dispatched."
    else:
        request("other_order_before_check", "POST", "/orders/43/replacement", "replacement-43")
        request("unrelated_eligibility", "GET", "/orders/43/replacement")
        request("dispatch_after_unrelated_check", "POST", "/orders/42/replacement", "replacement-42")
        # Box permits the matching order; the one-order backend still returns 404.
        request("other_order_after_check", "POST", "/orders/43/replacement", "replacement-43")
        customer_reply = "The other order's eligibility does not authorize this replacement."
    print(json.dumps({"mode": "deterministic scripted workload", "scenario": args.scenario,
                      "steps": steps, "customer_reply": customer_reply}))


if __name__ == "__main__":
    main()
