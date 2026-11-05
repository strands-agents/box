"""Test the synthetic deployment fixture and its evidence checks without AWS."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from check_deployment import verify
from deployment_policy import deployment_policy
from deployment_service import DeploymentService
import deployment_tools


class ProxyFixture:
    """Forward local fixture traffic or return one configured proxy response."""

    def __init__(self, status=None, body=b'{}', refused=False, *, upstream_port=None):
        if status is None and (type(upstream_port) is not int or not 1 <= upstream_port <= 65535):
            raise ValueError('a forwarding fixture requires its service port')
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def serve(self):
                owner.requests.append((self.command, self.path, self.headers.get('Host')))
                data = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                code, response = status, body
                if code is None:
                    route = {'POST': '/deployments/checkout', 'GET': '/deployments/checkout/status'}[self.command]
                    expected = 'http://127.0.0.1:' + str(upstream_port) + route
                    if self.path != expected:
                        code, response = 403, b'fixture destination refused'
                    else:
                        connection = http.client.HTTPConnection('127.0.0.1', upstream_port, timeout=3)
                        try:
                            connection.request(self.command, route, body=data)
                            upstream = connection.getresponse()
                            code, response = upstream.status, upstream.read()
                        finally:
                            connection.close()
                self.send_response(code)
                self.send_header('Content-Length', str(len(response)))
                if refused:
                    self.send_header('x-strands-box-egress', 'refused')
                self.end_headers()
                self.wfile.write(response)

            do_GET = do_POST = serve

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': 0.05}, daemon=True)

    @property
    def url(self):
        return 'http://127.0.0.1:' + str(self.server.server_address[1])

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def direct_request(service, method, path):
    connection = http.client.HTTPConnection('127.0.0.1', service.port, timeout=3)
    try:
        connection.request(method, path, body='{}' if method == 'POST' else None)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


class DeploymentServiceTests(unittest.TestCase):
    def test_service_has_no_cooldown_and_records_actual_http_arrivals(self):
        with DeploymentService() as service:
            statuses = [direct_request(service, 'POST', '/deployments/checkout')[0] for _ in range(4)]
            self.assertEqual(statuses, [503, 503, 503, 201])
            self.assertEqual(direct_request(service, 'GET', '/deployments/checkout/status')[0], 200)
            self.assertEqual([row['status'] for row in service.receipts], statuses + [200])
            self.assertTrue(all(row['body_sha256'] for row in service.receipts))
            receipts = service.receipts
            receipts[0]['status'] = 999
            self.assertEqual(service.receipts[0]['status'], 503)

    def test_unknown_operation_does_not_consume_a_deployment_failure(self):
        with DeploymentService() as service:
            self.assertEqual(direct_request(service, 'POST', '/deployments/payments')[0], 404)
            self.assertEqual(direct_request(service, 'GET', '/deployments/checkout')[0], 404)
            self.assertEqual(direct_request(service, 'POST', '/deployments/checkout')[1]['attempt'], 1)


class DeploymentToolsTests(unittest.TestCase):
    def test_no_proxy_never_bypasses_the_explicit_proxy(self):
        with DeploymentService() as service, ProxyFixture(upstream_port=service.port) as proxy:
            with patch.dict(os.environ, {'HTTP_PROXY': proxy.url, 'NO_PROXY': '*', 'no_proxy': '*'}, clear=True):
                result = deployment_tools.request(service.url, 'POST', '/deployments/checkout')
            self.assertEqual(result['status'], 503)
            self.assertFalse(result['box_refused'])
            self.assertEqual(proxy.requests, [('POST', service.url + '/deployments/checkout',
                                               '127.0.0.1:' + str(service.port))])
            self.assertEqual(len(service.receipts), 1)

    def test_proxy_cannot_forward_to_another_fixture_service(self):
        with DeploymentService() as service, DeploymentService() as other:
            with ProxyFixture(upstream_port=service.port) as proxy:
                with patch.dict(os.environ, {'HTTP_PROXY': proxy.url}, clear=True):
                    result = deployment_tools.request(other.url, 'POST', '/deployments/checkout')
                self.assertEqual(result['status'], 403)
                self.assertEqual(service.receipts, [])
                self.assertEqual(other.receipts, [])

    def test_proxy_refusal_never_reaches_the_service(self):
        with DeploymentService() as service, ProxyFixture(403, b'policy denied', True) as proxy:
            with patch.dict(os.environ, {'HTTP_PROXY': proxy.url}, clear=True):
                result = deployment_tools.request(service.url, 'POST', '/deployments/checkout')
            self.assertEqual(result, {'status': 403, 'box_refused': True, 'body': 'policy denied'})
            self.assertEqual(service.receipts, [])

    def test_missing_proxy_refuses_without_direct_fallback(self):
        with DeploymentService() as service, patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'HTTP_PROXY is required'):
                deployment_tools.request(service.url, 'POST', '/deployments/checkout')
            self.assertEqual(service.receipts, [])

    def test_invalid_proxy_refuses_without_direct_fallback(self):
        with DeploymentService() as service:
            for proxy in ['http://example.com:8080', 'https://127.0.0.1:8080', 'http://127.0.0.1',
                          'http://user@127.0.0.1:8080', 'http://127.0.0.1:8080/path']:
                with self.subTest(proxy=proxy), patch.dict(os.environ, {'HTTP_PROXY': proxy}, clear=True):
                    with self.assertRaises(ValueError):
                        deployment_tools.request(service.url, 'POST', '/deployments/checkout')
            self.assertEqual(service.receipts, [])

    def test_response_size_is_bounded(self):
        with ProxyFixture(200, b'x' * (deployment_tools.MAX_RESPONSE_BYTES + 1)) as proxy:
            with patch.dict(os.environ, {'HTTP_PROXY': proxy.url}, clear=True):
                with self.assertRaisesRegex(ValueError, 'response exceeds'):
                    deployment_tools.request('http://127.0.0.1:12345', 'GET', '/deployments/checkout/status')

    def test_mcp_frames_preserve_ids_and_forward_only_declared_tools(self):
        frames = [
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2024-11-05'}},
            {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
            {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'deploy_checkout', 'arguments': {}}},
            {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call', 'params': {'name': 'deployment_status', 'arguments': {}}},
            {'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call', 'params': {'name': 'deploy_checkout', 'arguments': {'path': '/other'}}},
            {'jsonrpc': '2.0', 'id': 6, 'method': 'tools/call', 'params': {'name': 'other', 'arguments': {}}},
        ]
        with DeploymentService() as service, ProxyFixture(upstream_port=service.port) as proxy:
            process = subprocess.run([sys.executable, str(Path(deployment_tools.__file__)), service.url],
                input=''.join(json.dumps(frame) + '\n' for frame in frames), text=True, capture_output=True,
                env={**os.environ, 'HTTP_PROXY': proxy.url, 'NO_PROXY': '*'}, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            replies = [json.loads(line) for line in process.stdout.splitlines()]
            self.assertEqual([row['id'] for row in replies], [1, 2, 3, 4, 5, 6])
            self.assertEqual({tool['name'] for tool in replies[1]['result']['tools']},
                             {'deploy_checkout', 'deployment_status'})
            self.assertTrue(replies[2]['result']['isError'])
            self.assertEqual(json.loads(replies[2]['result']['content'][0]['text'])['status'], 503)
            self.assertFalse(replies[3]['result']['isError'])
            self.assertTrue(replies[4]['result']['isError'])
            self.assertTrue(replies[5]['result']['isError'])
            self.assertEqual(len(proxy.requests), 2)
            self.assertEqual([row['status'] for row in service.receipts], [503, 200])


class DeploymentPolicyTests(unittest.TestCase):
    def test_host_is_escaped_as_one_policy_string(self):
        host = 'example";forbid(principal,action,resource);\\host'
        policy = deployment_policy(host, 8080)
        self.assertEqual(policy.count(json.dumps(host)), 5)
        self.assertNotIn('host == "example";', policy)
        self.assertIn('@id("deployment_cooldown")', policy)

    def test_durations_and_port_require_positive_integers(self):
        for value in [False, True, 0, -1, 1.5, '300', None]:
            for name in ['failure_window', 'cooldown']:
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    deployment_policy('127.0.0.1', 8080, **{name: value})
        for value in [False, 0, 65536, '8080', 1.5]:
            with self.subTest(port=value), self.assertRaises(ValueError):
                deployment_policy('127.0.0.1', value)


def valid_evidence():
    labels = ['initial_diagnostics', 'failure_one', 'diagnostics_between_failures', 'failure_two',
              'unrelated_path', 'failure_three', 'immediate_retry', 'diagnostics_during_cooldown',
              'after_failure_window', 'diagnostics_after_failure_window', 'near_expiry',
              'diagnostics_near_expiry', 'after_cooldown']
    seconds = [7, 8, 8.5, 9, 9.5, 9.9, 10.2, 10.4, 312, 312.2, 608, 608.2, 612]
    statuses = [200, 503, 200, 503, 403, 503, 403, 200, 403, 200, 403, 200, 201]
    steps = [{'label': label, 'status': status, 'box_refused': status == 403,
              'started_ns': int(second * 1_000_000_000),
              'completed_ns': int((second + 0.1) * 1_000_000_000)}
             for label, second, status in zip(labels, seconds, statuses)]
    arrivals = [{'method': 'POST', 'path': '/deployments/checkout', 'status': status}
                for status in [503, 503, 503, 201]]
    audit = [{'action': 'http:request', 'verdict': 'deny', 'rule': 'deployment_cooldown'} for _ in range(3)]
    return steps, arrivals, audit


class DeploymentVerifierTests(unittest.TestCase):
    def test_valid_evidence_passes_all_checks(self):
        checks = verify(*valid_evidence(), 0, 300, 600)
        self.assertTrue(all(checks.values()), checks)

    def test_extra_service_arrival_refuses_a_client_only_claim(self):
        steps, arrivals, audit = valid_evidence()
        arrivals.append({'method': 'POST', 'path': '/deployments/checkout', 'status': 201})
        self.assertFalse(verify(steps, arrivals, audit, 0, 300, 600)['only_permitted_deployments_reached_service'])

    def test_missing_rule_or_refusal_marker_fails(self):
        steps, arrivals, audit = valid_evidence()
        audit[0]['rule'] = 'unrelated_rule'
        self.assertFalse(verify(steps, arrivals, audit, 0, 300, 600)['three_cooldown_refusals'])
        steps, arrivals, audit = valid_evidence()
        steps[6]['box_refused'] = False
        self.assertFalse(verify(steps, arrivals, audit, 0, 300, 600)['three_cooldown_refusals'])

    def test_early_retry_and_short_observation_fail(self):
        steps, arrivals, audit = valid_evidence()
        steps[-1]['started_ns'] = 609_000_000_000
        self.assertFalse(verify(steps, arrivals, audit, 0, 300, 600)['retry_waited_full_cooldown'])
        steps, arrivals, audit = valid_evidence()
        steps[8]['started_ns'] = 300_000_000_000
        self.assertFalse(verify(steps, arrivals, audit, 0, 300, 600)['cooldown_outlasts_failure_window'])

    def test_missing_step_and_malformed_audit_fail(self):
        steps, arrivals, audit = valid_evidence()
        self.assertFalse(verify(steps[:-1], arrivals, audit, 0, 300, 600)['complete_sequence'])
        self.assertFalse(verify(steps, arrivals, audit, 1, 300, 600)['audit_readable'])


if __name__ == '__main__':
    unittest.main()
