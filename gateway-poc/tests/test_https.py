import argparse
import base64
import contextlib
import copy
import datetime
import http.client
import io
import json
import os
import hashlib
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time
import unittest
import uuid
from unittest import mock

import jwt
import https_poc as h
import make_lab_certs
import poc
import prepare_https
import homologation
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

    @contextlib.contextmanager
    def token_client(self, services=('lab-status', 'lab-echo')):
        token = secrets.token_urlsafe(32)
        identity = 'test-client-01'
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        policy = {'enabled': True, 'services': list(services), 'expires_utc': expires.strftime('%Y-%m-%dT%H:%M:%SZ'),
                  'token_sha256': hashlib.sha256(token.encode()).hexdigest()}
        old_mode = self.gateway.get('client_auth')
        old_clients = self.gateway.get('token_clients')
        self.gateway['client_auth'], self.gateway['token_clients'] = 'token', {identity: policy}
        server = h.Clients(('127.0.0.1', 0), self.state, h.client_tls_context(self.gateway))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        config = copy.deepcopy(self.client)
        config.update(client_auth='token', client_id=identity, client_token_file='test-client.token',
                      client_port=server.server_address[1], proxy_port=0)
        config.pop('tls_cert', None)
        config.pop('tls_key', None)
        token_path = config['_root'] / 'test-client.token'
        token_path.write_text(token, encoding='ascii')
        try:
            yield config, policy, token
        finally:
            server.shutdown()
            server.server_close()
            thread.join(10)
            token_path.unlink(missing_ok=True)
            if old_mode is None:
                self.gateway.pop('client_auth', None)
            else:
                self.gateway['client_auth'] = old_mode
            if old_clients is None:
                self.gateway.pop('token_clients', None)
            else:
                self.gateway['token_clients'] = old_clients

    def test_client_token_without_client_certificate_and_no_secret_logs(self):
        with self.token_client() as (config, policy, token):
            with h.client_socket(config, 'lab-status', 'check'):
                pass
            self.assertNotIn(token, self.output.getvalue())
            (config['_root'] / 'test-client.token').write_text('wrong-token-' * 4)
            with self.assertRaises(ValueError):
                h.client_socket(config, 'lab-status', 'check')

    def test_token_scope_expiry_revocation_and_missing_token(self):
        with self.token_client(('lab-status',)) as (config, policy, token):
            with self.assertRaises(ValueError):
                h.client_socket(config, 'lab-echo', 'check')
            policy['enabled'] = False
            with self.assertRaises(ValueError):
                h.client_socket(config, 'lab-status', 'check')
            policy['enabled'] = True
            policy['expires_utc'] = '2000-01-01T00:00:00Z'
            with self.assertRaises(ValueError):
                h.client_socket(config, 'lab-status', 'check')
            context = ssl.create_default_context(cafile=h.file(config, 'tls_ca'))
            with socket.create_connection(('127.0.0.1', config['client_port']), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname='localhost') as peer:
                    poc.send(peer, {'op': 'check', 'service': 'lab-status', 'client_id': config['client_id']})
                    self.assertEqual({'error': 'denied'}, poc.receive(peer))

    def test_token_client_still_checks_server_hostname(self):
        with self.token_client() as (config, policy, token):
            config['client_host'] = '127.0.0.1'
            with self.assertRaises(ssl.SSLCertVerificationError):
                h.client_socket(config, 'lab-status', 'check')

    def test_preflight_reports_connectivity_not_application_login(self):
        connection = mock.MagicMock()
        connection.getresponse.return_value.status = 401
        with mock.patch.object(h, 'service_allowed', return_value=True), \
                mock.patch.object(h.Channel, 'request', return_value={'ready': True}), \
                mock.patch.object(h.socket, 'getaddrinfo', return_value=[]), \
                mock.patch.object(h.http.client, 'HTTPSConnection', return_value=connection), \
                mock.patch.object(h.http.client, 'HTTPConnection', return_value=connection):
            result = h.preflight(self.agent, ['gitlab', 'artifactory'])
            self.assertTrue(result['ready'])
            self.assertEqual(2, len(result['checks']))
            self.assertEqual('not_tested_on_agent', result['checks'][0]['application_login'])
            connection.getresponse.return_value.status = 403
            with self.assertRaises(h.ChannelError) as failure:
                h.preflight(self.agent, ['gitlab'])
            self.assertEqual('target_http_not_ready', h.diagnostics(failure.exception)['reason'])

    def test_preflight_failure_never_starts_agent_or_writes_ready_marker(self):
        path = self.root / 'bundles/agent/preflight-config.json'
        path.write_text(json.dumps({key: value for key, value in self.agent.items() if key != '_root'}))
        marker = self.root / 'must-not-exist.json'
        with mock.patch('sys.argv', ['https_poc.py', 'agent', '--config', str(path),
                                     '--service', 'homologation', '--preflight', '--ready-file', str(marker)]), \
                mock.patch.object(h.signal, 'signal'), \
                mock.patch.object(h, 'preflight', side_effect=h.ChannelError('target_http_not_ready', 'target_preflight', 403)), \
                mock.patch.object(h, 'agent_pool') as pool:
            with self.assertRaises(h.ChannelError):
                h.main()
            pool.assert_not_called()
            self.assertFalse(marker.exists())

    @unittest.skipUnless(shutil.which('powershell'), 'Windows PowerShell unavailable')
    def test_background_launcher_status_stop_and_pid_reuse_guard(self):
        path = self.root / 'bundles/agent/background-config.json'
        path.write_text(json.dumps({key: value for key, value in self.agent.items() if key != '_root'}))
        runtime = self.root / 'runtime'
        script = self.root.parents[1] / 'Start-RestrictedLab.ps1'
        def invoke(mode):
            # Windows children may inherit pipe handles even after PowerShell exits.
            # Capture to ordinary files so a correctly detached child cannot hold
            # unittest's communicate() open.
            output = self.root / ('launcher-' + uuid.uuid4().hex + '.out')
            errors = output.with_suffix('.err')
            with output.open('w', encoding='utf-8') as stdout, errors.open('w', encoding='utf-8') as stderr:
                result = subprocess.run(['powershell', '-NoProfile', '-File', str(script), '-Mode', mode,
                                         '-Service', 'lab-status', '-Config', str(path),
                                         '-RuntimeDirectory', str(runtime)], stdout=stdout, stderr=stderr, timeout=60)
            result.stdout = output.read_text(encoding='utf-8-sig', errors='replace')
            result.stderr = errors.read_text(encoding='utf-8-sig', errors='replace')
            return result
        try:
            result = invoke('Agent')
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            record = json.loads((runtime / 'agent.json').read_text(encoding='utf-8-sig'))
            self.assertEqual('agent_running', record['event'])
            self.assertNotEqual(os.getpid(), record['pid'])
            status = invoke('Status')
            self.assertEqual(record['pid'], json.loads(status.stdout)['pid'])
            with h.client_socket(self.client, 'lab-status') as sock:
                sock.sendall(b'GET /status HTTP/1.0\r\nHost: localhost\r\n\r\n')
                response = http.client.HTTPResponse(sock)
                response.begin()
                self.assertEqual(poc.SERVICES['lab-status'][1], json.loads(response.read(4096)))
        finally:
            stopped = invoke('Stop')
            self.assertEqual(0, stopped.returncode, stopped.stdout + stopped.stderr)
        self.assertFalse((runtime / 'agent.json').exists())
        (runtime / 'agent.json').write_text(json.dumps({'pid': os.getpid(), 'start_ticks': '0', 'executable': 'wrong'}))
        refused = invoke('Stop')
        self.assertNotEqual(0, refused.returncode)
        (runtime / 'agent.json').unlink()

    def test_concurrent_sessions_for_two_services(self):
        previous = self.gateway.get('max_sessions')
        previous_idle = self.gateway.get('idle_seconds')
        self.gateway['max_sessions'] = 2
        self.gateway['idle_seconds'] = 30
        with self.token_client() as (config, policy, token):
            stop = threading.Event()
            pool = threading.Thread(target=h.agent_pool, args=(self.agent, ['lab-status', 'lab-echo'], stop), daemon=True)
            pool.start()
            try:
                with h.client_socket(config, 'lab-status') as first, h.client_socket(config, 'lab-echo') as second:
                    with self.state.lock:
                        self.assertEqual(2, len(self.state.jobs))
                    second.sendall(b'two-services')
                    self.assertEqual(b'two-services', poc.exact(second, 12, time.monotonic() + 12))
                    first.sendall(b'GET /status HTTP/1.0\r\nHost: localhost\r\n\r\n')
                    response = http.client.HTTPResponse(first)
                    response.begin()
                    self.assertEqual(poc.SERVICES['lab-status'][1], json.loads(response.read(4096)))
            finally:
                stop.set()
                pool.join(15)
                self.assertFalse(pool.is_alive())
                if previous is None:
                    self.gateway.pop('max_sessions', None)
                else:
                    self.gateway['max_sessions'] = previous
                if previous_idle is None:
                    self.gateway.pop('idle_seconds', None)
                else:
                    self.gateway['idle_seconds'] = previous_idle

    def test_homologation_policies_preserve_tls_and_record_pending_corporate_approval(self):
        with TempDirectory() as directory:
            from pathlib import Path
            directory = Path(directory)
            output = directory / 'policies'
            summary = homologation.prepare(output, requested_by='test-operator')
            another = directory / 'other-client'
            homologation.prepare(another, client_id='other-client', requested_by='test-operator', services=['gitlab'])
            self.assertNotEqual((output / 'client.token').read_text(), (another / 'client.token').read_text())
            token = (output / 'client.token').read_text().strip()
            self.assertNotIn(token, json.dumps(summary))
            for role, original in (('gateway', self.gateway), ('agent', self.agent), ('client', self.client)):
                target = directory / (role + '-config.json')
                original = {key: value for key, value in original.items() if key != '_root'}
                target.write_text(json.dumps(original))
                backup = homologation.apply(target, output / (role + '-policy.json'))
                updated = h.read_config(target)
                self.assertEqual(original, json.loads(Path(backup).read_text()))
                for field in ('tls_cert', 'tls_key', 'tls_ca', 'signing_key', 'replay_db', 'agent_url'):
                    self.assertEqual(original.get(field), updated.get(field))
                self.assertTrue(h.service_allowed(updated, 'gitlab'))
                self.assertTrue(h.service_allowed(updated, 'artifactory'))
                self.assertEqual('pending', updated['services']['gitlab']['test_authorization']['corporate_approval'])
                end = h.utc_expiry(updated['services']['gitlab']['test_authorization']['expires_utc'])
                with mock.patch.object(h.time, 'time', return_value=end + 1):
                    self.assertFalse(h.service_allowed(updated, 'gitlab'))
                if role == 'gateway':
                    self.assertNotIn(token, target.read_text())
                    homologation.revoke(target, summary['client_id'])
                    self.assertFalse(h.read_config(target)['token_clients'][summary['client_id']]['enabled'])
                    homologation.apply(target, another / 'gateway-policy.json')
                    identities = h.read_config(target)['token_clients']
                    self.assertFalse(identities[summary['client_id']]['enabled'])
                    self.assertEqual(['gitlab'], identities['other-client']['services'])

    def test_local_proxy_http_and_connect_with_token(self):
        for service in ('lab-status', 'lab-echo'):
            with self.token_client() as (config, policy, token):
                stop, agent = self.run_agent(service)
                with h.LocalProxy(config) as proxy:
                    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
                    thread.start()
                    try:
                        with socket.create_connection(proxy.server_address, timeout=12) as local:
                            if service == 'lab-status':
                                local.sendall(b'GET http://127.0.0.1:18765/status HTTP/1.1\r\nHost: example.invalid\r\n\r\n')
                                response = http.client.HTTPResponse(local)
                                response.begin()
                                self.assertEqual(200, response.status)
                                self.assertEqual(poc.SERVICES['lab-status'][1], json.loads(response.read(4096)))
                            else:
                                local.sendall(b'CONNECT 127.0.0.1:18766 HTTP/1.1\r\nHost: localhost\r\n\r\n')
                                header = b''
                                while not header.endswith(b'\r\n\r\n'):
                                    header += local.recv(1)
                                self.assertIn(b'200 Connection Established', header)
                                local.sendall(b'proxy-echo-fixture')
                                self.assertEqual(b'proxy-echo-fixture', poc.exact(local, 18, time.monotonic() + 12))
                    finally:
                        proxy.shutdown()
                        thread.join(10)
                        stop.set()
                        agent.join(15)

    def test_local_proxy_denies_unknown_destination_without_gateway_connection(self):
        with self.token_client() as (config, policy, token), h.LocalProxy(config) as proxy:
            thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            thread.start()
            try:
                with mock.patch.object(h, 'client_socket') as gateway:
                    with socket.create_connection(proxy.server_address, timeout=5) as local:
                        local.sendall(b'CONNECT forbidden.invalid:443 HTTP/1.1\r\nHost: forbidden.invalid\r\n\r\n')
                        self.assertIn(b'403 Forbidden', local.recv(4096))
                    gateway.assert_not_called()
            finally:
                proxy.shutdown()
                thread.join(10)

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
        fake_response.getheader.return_value = 'application/jwt'
        with mock.patch.object(h.http.client, 'HTTPSConnection') as connection:
            connection.return_value.getresponse.return_value = fake_response
            with self.assertRaisesRegex(ValueError, 'application_response_binding_invalid'):
                channel.request({'action': 'check', 'service': 'lab-status'})
        wrong = h.Signer(self.agent['gateway_id'], h.file(self.agent, 'signing_key')).sign(self.agent['agent_id'], {'ready': True})
        with self.assertRaises(jwt.InvalidSignatureError):
            h.decode(wrong, h.file(self.agent, 'gateway_public'), self.agent['gateway_id'], self.agent['agent_id'])

    def test_http_error_status_and_html_are_diagnosed_without_content(self):
        channel = h.Channel(self.agent)
        for status in (403, 404, 407, 502, 503):
            response = mock.MagicMock(status=status)
            response.read.return_value = b'sensitive proxy response body'
            with mock.patch.object(h.http.client, 'HTTPSConnection') as connection:
                connection.return_value.getresponse.return_value = response
                with self.assertRaises(h.ChannelError) as failure:
                    channel.request({'action': 'check', 'service': 'lab-status'})
            self.assertEqual({'reason': 'https_http_error', 'stage': 'http_response',
                              'http_status': status}, h.diagnostics(failure.exception))
            response.read.assert_not_called()
        response = mock.MagicMock(status=200)
        response.getheader.return_value = 'text/html; charset=utf-8'
        with mock.patch.object(h.http.client, 'HTTPSConnection') as connection:
            connection.return_value.getresponse.return_value = response
            with self.assertRaises(h.ChannelError) as failure:
                channel.request({'action': 'check', 'service': 'lab-status'})
        self.assertEqual('https_unexpected_content_type', h.diagnostics(failure.exception)['reason'])
        response.read.assert_not_called()

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
            self.state.jobs['fixture'] = job
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
                self.state.jobs.pop('fixture', None)

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
