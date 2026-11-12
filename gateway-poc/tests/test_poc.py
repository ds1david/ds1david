import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import socket
import ssl
import struct
import threading
import time
import unittest
import uuid
from unittest import mock

import make_lab_certs
import poc


class TempDirectory:
    # Windows Python 3.13 mode-700 temp ACLs exclude the managed runner SID.
    def __init__(self):
        self.root = (Path(__file__).resolve().parents[1] / '.test-state').resolve()
        self.path = self.root / uuid.uuid4().hex
        self.path.mkdir(parents=True)
        self.name = str(self.path)

    def cleanup(self):
        assert self.path.resolve().parent == self.root
        shutil.rmtree(self.path)

    def __enter__(self):
        return self.name

    def __exit__(self, *_):
        self.cleanup()


class ProtocolTests(unittest.TestCase):
    def test_oversized_and_non_object(self):
        for payload in (struct.pack('!I', poc.MAX_FRAME + 1), struct.pack('!I', 2) + b'[]'):
            class Reader:
                def __init__(self, data):
                    self.data = data

                def recv(self, count):
                    part, self.data = self.data[:count], self.data[count:]
                    return part

                def settimeout(self, _):
                    pass
            with self.assertRaises(ValueError):
                poc.receive(Reader(payload))

    def test_policy_rejects_real_services(self):
        with TempDirectory() as directory:
            path = Path(directory) / 'policy.json'
            path.write_text(json.dumps({'a' * 64: {'role': 'agent', 'services': ['gitlab']}}))
            with self.assertRaises(ValueError):
                poc.load_policy(path)

    def test_agent_reconnect_backoff_and_recovers(self):
        class Stop:
            stopped = False
            waits = []

            def is_set(self):
                return self.stopped

            def wait(self, duration):
                self.waits.append(duration)
                if duration == 2:
                    self.stopped = True

        stop = Stop()
        args = argparse.Namespace(ca='ca', cert='cert', key='key', service='lab-status')
        good = mock.MagicMock()
        with mock.patch.object(poc, 'tls'), mock.patch.object(poc, 'audit'), \
                mock.patch.object(poc, 'connect', side_effect=[OSError(), OSError(), good]), \
                mock.patch.object(poc, 'send'), mock.patch.object(poc, 'receive', return_value={'idle': True}):
            poc.agent(args, stop)
        self.assertTrue(1 <= stop.waits[0] <= 1.25)
        self.assertTrue(2 <= stop.waits[1] <= 2.5)
        self.assertEqual(2, stop.waits[2])


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = TempDirectory()
        cls.certs = Path(cls.temp.name) / 'certs'
        openssl = shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe'
        make_lab_certs.generate(cls.certs, openssl=openssl)
        cls.output = io.StringIO()
        cls.capture = contextlib.redirect_stdout(cls.output)
        cls.capture.__enter__()
        cls.gateway = poc.Gateway(('127.0.0.1', 0), cls.context('gateway', True),
                                  poc.load_policy(cls.certs / 'policy.json'))
        cls.thread = threading.Thread(target=cls.gateway.serve_forever, daemon=True)
        cls.thread.start()
        cls.lab = poc.http.server.HTTPServer(('127.0.0.1', 18765), poc.Lab)
        cls.lab_thread = threading.Thread(target=cls.lab.serve_forever, daemon=True)
        cls.lab_thread.start()
        cls.echo = poc.socketserver.TCPServer(('127.0.0.1', 18766), poc.Echo)
        cls.echo_thread = threading.Thread(target=cls.echo.serve_forever, daemon=True)
        cls.echo_thread.start()

    @classmethod
    def context(cls, role, server=False):
        return poc.tls(str(cls.certs / 'ca.crt'), str(cls.certs / (role + '.crt')),
                       str(cls.certs / (role + '.key')), server)

    @classmethod
    def tearDownClass(cls):
        cls.gateway.shutdown()
        cls.gateway.server_close()
        cls.lab.shutdown()
        cls.lab.server_close()
        cls.thread.join()
        cls.lab_thread.join()
        cls.echo.shutdown()
        cls.echo.server_close()
        cls.echo_thread.join()
        cls.capture.__exit__(None, None, None)
        logs = cls.output.getvalue()
        assert 'PRIVATE KEY' not in logs and 'demo' not in logs
        for line in logs.splitlines():
            json.loads(line)
        cls.temp.cleanup()

    def setUp(self):
        with self.gateway.lock:
            self.gateway.rates.clear()

    def connect(self, role='client', hostname='localhost'):
        raw = socket.create_connection(self.gateway.server_address, timeout=12)
        try:
            return self.context(role).wrap_socket(raw, server_hostname=hostname)
        except BaseException:
            raw.close()
            raise

    def request(self, data, role='client'):
        with self.connect(role) as sock:
            poc.send(sock, data)
            return poc.receive(sock)

    def test_hostname_validation(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect(hostname='wrong.invalid')

    def test_client_certificate_required(self):
        context = ssl.create_default_context(cafile=str(self.certs / 'ca.crt'))
        with socket.create_connection(self.gateway.server_address, timeout=3) as raw:
            with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
                with context.wrap_socket(raw, server_hostname='localhost') as sock:
                    poc.send(sock, {'op': 'query', 'service': 'lab-status'})
                    poc.receive(sock)

    def test_unknown_identity_and_role_and_destination_denied(self):
        self.assertEqual({'error': 'denied'}, self.request({'op': 'pull', 'service': 'lab-status'}, 'unknown'))
        self.assertEqual({'error': 'denied'}, self.request({'op': 'pull', 'service': 'lab-status'}))
        self.assertEqual({'error': 'denied'}, self.request({'op': 'query', 'service': 'gitlab'}))
        self.assertEqual({'error': 'denied'}, self.request({'op': 'query', 'service': 'lab-status', 'url': 'http://secret'}))

    def test_roundtrip_two_synthetic_services(self):
        for service in poc.SERVICES:
            stop = threading.Event()
            args = argparse.Namespace(host='localhost', port=self.gateway.server_address[1],
                                      ca=str(self.certs / 'ca.crt'), cert=str(self.certs / 'agent.crt'),
                                      key=str(self.certs / 'agent.key'), service=service)
            worker = threading.Thread(target=poc.agent, args=(args, stop), daemon=True)
            worker.start()
            try:
                self.assertEqual({'result': poc.SERVICES[service][1]},
                                 self.request({'op': 'query', 'service': service}))
            finally:
                stop.set()
                worker.join(15)
                self.assertFalse(worker.is_alive())

    def test_tcp_local_port_end_to_end(self):
        stop = threading.Event()
        args = argparse.Namespace(host='localhost', port=self.gateway.server_address[1],
                                  ca=str(self.certs / 'ca.crt'), cert=str(self.certs / 'agent.crt'),
                                  key=str(self.certs / 'agent.key'), service='lab-echo')
        agent = threading.Thread(target=poc.agent, args=(args, stop), daemon=True)
        agent.start()
        client_args = argparse.Namespace(**vars(args))
        client_args.cert = str(self.certs / 'client.crt')
        client_args.key = str(self.certs / 'client.key')
        with poc.Forwarder(0, client_args) as forwarder:
            thread = threading.Thread(target=forwarder.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.create_connection(forwarder.server_address, timeout=12) as client:
                    for payload in (b'synthetic tcp fixture', b'\x00\xff\x10'):
                        client.sendall(payload)
                        self.assertEqual(payload, poc.exact(client, len(payload), time.monotonic() + 12))
            finally:
                forwarder.shutdown()
                thread.join(15)
                stop.set()
                agent.join(15)
                self.assertFalse(agent.is_alive())

    def test_stream_byte_and_duration_limits(self):
        import stream
        left, left_peer = socket.socketpair()
        right, right_peer = socket.socketpair()
        with left, left_peer, right, right_peer:
            left_peer.sendall(b'over limit')
            reason, count = stream.relay(left, right, max_bytes=2, max_seconds=2)
            self.assertEqual('byte_limit', reason)
            self.assertEqual(0, count)
        left, left_peer = socket.socketpair()
        right, right_peer = socket.socketpair()
        with left, left_peer, right, right_peer:
            reason, count = stream.relay(left, right, max_seconds=.1)
            self.assertEqual('timeout', reason)
            self.assertEqual(0, count)

    def test_busy_invalid_result_and_recovery(self):
        result = []
        worker = threading.Thread(target=lambda: result.append(self.request({'op': 'query', 'service': 'lab-status'})))
        worker.start()
        deadline = time.monotonic() + 3
        while self.gateway.job is None and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual({'error': 'busy'}, self.request({'op': 'query', 'service': 'lab-status'}))
        with self.connect('agent') as sock:
            poc.send(sock, {'op': 'pull', 'service': 'lab-status'})
            job = poc.receive(sock)
            poc.send(sock, {'id': job['id'], 'result': {'secret': 'must-never-be-logged'}})
        worker.join(10)
        self.assertEqual([{'error': 'invalid_lab_response'}], result)
        self.assertNotIn('must-never-be-logged', self.output.getvalue())
        self.assertEqual({'idle': True}, self.request({'op': 'pull', 'service': 'lab-status'}, 'agent'))

    def test_rate_limit(self):
        data = {'op': 'query', 'service': 'forbidden'}
        for _ in range(30):
            self.assertEqual({'error': 'denied'}, self.request(data))
        self.assertEqual({'error': 'rate_limit'}, self.request(data))

    def test_per_service_authorization(self):
        der = ssl.PEM_cert_to_DER_cert((self.certs / 'client.crt').read_text())
        identity = self.gateway.policy[hashlib.sha256(der).hexdigest()]
        previous = identity['services']
        try:
            identity['services'] = ['lab-status']
            self.assertEqual({'error': 'denied'}, self.request({'op': 'query', 'service': 'lab-catalog'}))
        finally:
            identity['services'] = previous

    def test_untrusted_server_ca(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with socket.create_connection(self.gateway.server_address, timeout=3) as raw:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(raw, server_hostname='localhost')

    def test_lab_offline_is_bounded(self):
        with mock.patch.object(poc.http.client.HTTPConnection, 'request', side_effect=ConnectionRefusedError):
            with self.assertRaises(ConnectionRefusedError):
                poc.lab_read('lab-status')

    def test_absent_agent_times_out_and_cleans_slot(self):
        self.assertEqual({'error': 'agent_timeout'}, self.request({'op': 'query', 'service': 'lab-status'}))
        self.assertIsNone(self.gateway.job)


if __name__ == '__main__':
    unittest.main()
