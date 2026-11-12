import argparse
import base64
import contextlib
import copy
import http.client
import io
import json
import shutil
import socket
import ssl
import subprocess
import threading
import time
import unittest
from unittest import mock

import jwt
import https_poc as h
import make_lab_certs
import poc
import prepare_https
from test_poc import TempDirectory


class HTTPSIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = TempDirectory()
        from pathlib import Path
        cls.root = Path(cls.temp.name)
        make_lab_certs.generate(cls.root / 'certs', openssl=shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe')
        prepare_https.prepare(cls.root / 'certs', cls.root / 'bundles', 'localhost', 'localhost')
        cls.gateway = h.read_config(cls.root / 'bundles/gateway/config.json')
        cls.agent = h.read_config(cls.root / 'bundles/agent/config.json')
        cls.client = h.read_config(cls.root / 'bundles/client/config.json')
        cls.state = h.State(cls.gateway)
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(h.file(cls.gateway, 'tls_cert'), h.file(cls.gateway, 'tls_key'))
        mtls = poc.tls(h.file(cls.gateway, 'tls_ca'), h.file(cls.gateway, 'tls_cert'), h.file(cls.gateway, 'tls_key'), True)
        cls.api = h.API(('127.0.0.1', 0), cls.state, server_tls)
        cls.clients = h.Clients(('127.0.0.1', 0), cls.state, mtls)
        cls.agent['agent_url'] = 'https://localhost:' + str(cls.api.server_address[1])
        cls.client['client_host'], cls.client['client_port'] = 'localhost', cls.clients.server_address[1]
        cls.lab = poc.http.server.HTTPServer(('127.0.0.1', 18765), poc.Lab)
        cls.echo = poc.socketserver.TCPServer(('127.0.0.1', 18766), poc.Echo)
        cls.output = io.StringIO()
        cls.capture = contextlib.redirect_stdout(cls.output)
        cls.capture.__enter__()
        cls.servers = (cls.api, cls.clients, cls.lab, cls.echo)
        cls.threads = []
        for server in cls.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(10)
        cls.state.replay.db.close()
        cls.capture.__exit__(None, None, None)
        assert 'PRIVATE KEY' not in cls.output.getvalue()
        cls.temp.cleanup()

    def setUp(self):
        self.state.rates.clear()

    def test_signed_check_and_client_mtls(self):
        self.assertEqual({'ready': True}, h.Channel(self.agent).request({'action': 'check', 'service': 'lab-status'}))
        with h.client_socket(self.client, 'lab-status', 'check'):
            pass

    def test_real_targets_disabled_at_agent_and_gateway(self):
        for service in ('gitlab', 'artifactory'):
            self.assertFalse(h.service_allowed(self.agent, service))
            with self.assertRaises(ValueError):
                h.client_socket(self.client, service)
            with self.assertRaises(ValueError):
                h.Channel(self.agent).request({'action': 'poll', 'service': service})

    def test_expired_or_incomplete_approval_denied(self):
        config = copy.deepcopy(self.agent)
        entry = config['services']['gitlab']
        entry['enabled'] = True
        for approval in ({}, {'agent_id': config['agent_id'], 'endpoint_security': 'ticket',
                            'service_owner': 'ticket', 'expires_utc': 'invalid'},
                         {'agent_id': config['agent_id'], 'endpoint_security': 'ticket',
                          'service_owner': 'ticket', 'expires_utc': '2000-01-01T00:00:00Z'}):
            entry['approval'] = approval
            self.assertFalse(h.service_allowed(config, 'gitlab'))

    def test_gateway_signature_and_response_binding_required(self):
        channel = h.Channel(self.agent)
        token = self.state.signer.sign(self.agent['agent_id'], {'ready': True}, 'wrong-request')
        decoded = h.decode(token, h.file(self.agent, 'gateway_public'), self.agent['gateway_id'], self.agent['agent_id'])
        self.assertEqual('wrong-request', decoded['reply_to'])
        fake_response = mock.MagicMock(status=200)
        fake_response.read.return_value = token.encode()
        with mock.patch.object(h.http.client, 'HTTPSConnection') as connection:
            connection.return_value.getresponse.return_value = fake_response
            with self.assertRaisesRegex(ValueError, 'response binding'):
                channel.request({'action': 'check', 'service': 'lab-status'})
        wrong = h.Signer(self.agent['gateway_id'], h.file(self.agent, 'signing_key')).sign(self.agent['agent_id'], {'ready': True})
        with self.assertRaises(jwt.InvalidSignatureError):
            h.decode(wrong, h.file(self.agent, 'gateway_public'), self.agent['gateway_id'], self.agent['agent_id'])

    def test_expired_or_modified_agent_message_rejected(self):
        signer = h.Channel(self.agent).signer
        token = signer.sign(self.agent['gateway_id'], {'action': 'check', 'service': 'lab-status'})
        claims = jwt.decode(token, options={'verify_signature': False})
        claims['iat'], claims['nbf'], claims['exp'] = int(time.time()) - 60, int(time.time()) - 60, int(time.time()) - 30
        expired = jwt.encode(claims, signer.key, algorithm='RS256')
        with self.assertRaises(jwt.ExpiredSignatureError):
            h.decode(expired, h.file(self.gateway, 'agent_public'), self.agent['agent_id'], self.agent['gateway_id'])
        parts = token.split('.')
        claims['body']['service'] = 'gitlab'
        parts[1] = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
        with self.assertRaises(jwt.InvalidSignatureError):
            h.decode('.'.join(parts), h.file(self.gateway, 'agent_public'), self.agent['agent_id'], self.agent['gateway_id'])

    def test_sequence_and_block_limits(self):
        job = {'id': 'fixture', 'service': 'lab-echo', 'assigned': True,
               'done': threading.Event(), 'seq': 0}
        with self.state.lock:
            self.state.job = job
        try:
            body = {'action': 'exchange', 'service': 'lab-echo', 'job': 'fixture',
                    'seq': 1, 'data': '', 'closed': False, 'ready': True}
            with self.assertRaises(ValueError):
                self.state.exchange(body)
            body['seq'] = 0
            body['data'] = base64.b64encode(b'x' * (h.BLOCK + 1)).decode()
            with self.assertRaises(ValueError):
                self.state.exchange(body)
        finally:
            with self.state.lock:
                self.state.job = None

    def test_http_transport_does_not_disable_hostname_validation(self):
        config = copy.deepcopy(self.agent)
        config['agent_url'] = 'https://127.0.0.1:' + str(self.api.server_address[1])
        with self.assertRaises(ssl.SSLCertVerificationError):
            h.Channel(config).request({'action': 'check', 'service': 'lab-status'})

    @unittest.skipUnless(shutil.which('powershell'), 'Windows PowerShell unavailable')
    def test_powershell_launcher_check(self):
        for role, config, script_name in (('agent', self.agent, 'Start-RestrictedLab.ps1'),
                                           ('client', self.client, 'Start-HttpsClient.ps1')):
            config_path = self.root / ('bundles/' + role + '/config.json')
            serializable = {key: value for key, value in config.items() if key != '_root'}
            config_path.write_text(json.dumps(serializable), encoding='utf-8')
            script = self.root.parents[1] / script_name
            result = subprocess.run(['powershell', '-NoProfile', '-File', str(script), '-Mode', 'Check',
                                     '-Config', str(config_path)], capture_output=True, text=True, timeout=30)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn('"ready": true', result.stdout)

    def test_replay_rejected_over_https(self):
        channel = h.Channel(self.agent)
        token = channel.signer.sign(self.agent['gateway_id'], {'action': 'check', 'service': 'lab-status'})
        statuses = []
        for _ in range(2):
            connection = http.client.HTTPSConnection('localhost', self.api.server_address[1], context=channel.context, timeout=5)
            connection.request('POST', '/v1/exchange', token)
            response = connection.getresponse()
            statuses.append(response.status)
            response.read()
            connection.close()
        self.assertEqual([200, 403], statuses)

    def test_replay_survives_database_reopen(self):
        path = self.root / 'replay-test.sqlite'
        first = h.ReplayStore(path)
        message = {'jti': 'a' * 32, 'exp': int(time.time()) + 30}
        first.claim(message)
        first.db.close()
        second = h.ReplayStore(path)
        try:
            with self.assertRaises(ValueError):
                second.claim(message)
        finally:
            second.db.close()

    def run_agent(self, service):
        stop = threading.Event()
        thread = threading.Thread(target=h.agent, args=(self.agent, service, stop), daemon=True)
        thread.start()
        return stop, thread

    def test_http_fixture_roundtrip(self):
        stop, thread = self.run_agent('lab-status')
        try:
            with h.client_socket(self.client, 'lab-status') as sock:
                sock.sendall(b'GET /status HTTP/1.0\r\nHost: localhost\r\n\r\n')
                response = http.client.HTTPResponse(sock)
                response.begin()
                self.assertEqual(200, response.status)
                self.assertEqual(poc.SERVICES['lab-status'][1], json.loads(response.read(4096)))
        finally:
            stop.set()
            thread.join(15)
            self.assertFalse(thread.is_alive())

    def test_binary_echo_roundtrip(self):
        stop, thread = self.run_agent('lab-echo')
        try:
            with h.client_socket(self.client, 'lab-echo') as sock:
                payload = b'\x00\xff synthetic fixture'
                sock.sendall(payload)
                self.assertEqual(payload, poc.exact(sock, len(payload), time.monotonic() + 10))
        finally:
            stop.set()
            thread.join(15)
            self.assertFalse(thread.is_alive())

    def test_bundle_separates_private_keys(self):
        self.assertFalse((self.root / 'bundles/agent/gateway.key').exists())
        self.assertFalse((self.root / 'bundles/client/signing.key').exists())
        self.assertFalse((self.root / 'bundles/gateway/client.key').exists())
        self.assertFalse(any((self.root / 'bundles').rglob('ca.key')))


if __name__ == '__main__':
    unittest.main()
