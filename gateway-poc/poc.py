"""Controlled synthetic health RPC. Python 3.11+, standard library only."""
import argparse
import collections
import hashlib
import http.client
import http.server
import json
import random
import signal
import socket
import socketserver
import ssl
import struct
import threading
import time
import uuid
from pathlib import Path
from stream import relay

MAX_FRAME = 4096
SERVICES = {
    'lab-status': ('/status', {'service': 'lab-status', 'synthetic': True, 'status': 'ok'}),
    'lab-catalog': ('/catalog', {'service': 'lab-catalog', 'synthetic': True, 'items': ['demo']}),
}
STREAM_SERVICE = 'lab-echo'
ALLOWED_SERVICES = (*SERVICES, STREAM_SERVICE)


def audit(event, **fields):
    # Callers supply only generated IDs, policy fingerprints, enums and counters.
    print(json.dumps({'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                      'event': event, **fields}), flush=True)


def failure_reason(error):
    """Return fixed diagnostic codes, never exception text or peer input."""
    if isinstance(error, ssl.SSLCertVerificationError):
        return {9: 'certificate_not_yet_valid', 10: 'certificate_expired',
                18: 'untrusted_certificate', 19: 'untrusted_ca',
                20: 'untrusted_ca', 21: 'untrusted_ca',
                26: 'certificate_wrong_purpose', 62: 'hostname_mismatch',
                64: 'hostname_mismatch'}.get(error.verify_code, 'certificate_verification_failed')
    if isinstance(error, ssl.SSLError):
        return {'TLSV1_ALERT_UNKNOWN_CA': 'peer_rejected_ca',
                'SSLV3_ALERT_BAD_CERTIFICATE': 'peer_rejected_certificate',
                'SSLV3_ALERT_CERTIFICATE_EXPIRED': 'peer_certificate_expired',
                'TLSV13_ALERT_CERTIFICATE_REQUIRED': 'client_certificate_required',
                'PEER_DID_NOT_RETURN_A_CERTIFICATE': 'client_certificate_required',
                'WRONG_VERSION_NUMBER': 'not_tls',
                'HTTP_REQUEST': 'not_tls'}.get(error.reason, 'tls_error')
    if isinstance(error, TimeoutError):
        return 'timeout'
    if isinstance(error, ConnectionRefusedError):
        return 'connection_refused'
    if isinstance(error, socket.gaierror):
        return 'dns_failed'
    if isinstance(error, ConnectionError):
        return 'connection_closed'
    if isinstance(error, OSError):
        return 'network_error'
    return 'invalid_protocol'


def exact(sock, count, deadline):
    result = bytearray()
    while len(result) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('frame deadline')
        sock.settimeout(remaining)
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise ConnectionError('closed')
        result.extend(chunk)
    return bytes(result)


def receive(sock, timeout=12):
    deadline = time.monotonic() + timeout
    size = struct.unpack('!I', exact(sock, 4, deadline))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError('frame limit')
    obj = json.loads(exact(sock, size, deadline))
    if not isinstance(obj, dict):
        raise ValueError('object required')
    return obj


def send(sock, obj):
    data = json.dumps(obj, separators=(',', ':'), allow_nan=False).encode()
    if len(data) > MAX_FRAME:
        raise ValueError('frame limit')
    sock.sendall(struct.pack('!I', len(data)) + data)


def tls(ca, cert, key, server=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=ca)
    context.load_cert_chain(cert, key)
    return context


def load_policy(path):
    policy = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(policy, dict) or not policy:
        raise ValueError('empty policy')
    for fingerprint, identity in policy.items():
        if len(fingerprint) != 64 or any(c not in '0123456789abcdef' for c in fingerprint):
            raise ValueError('SHA256 fingerprint required')
        if set(identity) != {'role', 'services'} or identity['role'] not in ('agent', 'client'):
            raise ValueError('invalid role')
        services = identity['services']
        if not isinstance(services, list) or not services or any(s not in ALLOWED_SERVICES for s in services):
            raise ValueError('only synthetic services allowed')
    return policy


class Gateway(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, context, policy):
        self.context, self.policy = context, policy
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(8)
        self.rates = collections.defaultdict(collections.deque)
        self.job = None  # One outstanding request in the entire POC.
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            audit('connection_limit')
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            request.close()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def allowed_rate(self, identity, role):
        with self.lock:
            entries = self.rates[identity]
            now = time.monotonic()
            while entries and now - entries[0] >= 60:
                entries.popleft()
            if len(entries) >= (90 if role == 'agent' else 30):
                return False
            entries.append(now)
            return True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        fingerprint = None
        stage = 'tls_handshake'
        try:
            self.request.settimeout(4)
            with self.server.context.wrap_socket(self.request, server_side=True) as sock:
                sock.settimeout(12)
                fingerprint = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
                stage = 'request_frame'
                # Consume the bounded request before denial, avoiding a TCP reset
                # caused by closing with unread application data on Windows.
                request = receive(sock, timeout=4)
                identity = self.server.policy.get(fingerprint)
                if identity is None:
                    audit('identity_denied', fingerprint=fingerprint)
                    send(sock, {'error': 'denied'})
                    return
                if not self.server.allowed_rate(fingerprint, identity['role']):
                    audit('rate_limit', fingerprint=fingerprint)
                    send(sock, {'error': 'rate_limit'})
                    return
                service = request.get('service')
                if request == {'op': 'check', 'service': service} and service in identity['services']:
                    send(sock, {'ready': True})
                    audit('check_succeeded', fingerprint=fingerprint, service=service)
                    return
                operation = 'pull' if identity['role'] == 'agent' else ('open' if service == STREAM_SERVICE else 'query')
                if set(request) != {'op', 'service'} or request['op'] != operation or service not in identity['services']:
                    audit('service_denied', fingerprint=fingerprint)
                    send(sock, {'error': 'denied'})
                    return
                stage = 'service_exchange'
                if operation == 'pull':
                    self.pull(sock, service, fingerprint)
                elif operation == 'open':
                    self.open_stream(sock, fingerprint)
                else:
                    self.query(sock, service, fingerprint)
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
            audit('connection_rejected', fingerprint=fingerprint, stage=stage,
                  reason=failure_reason(error))

    def query(self, sock, service, fingerprint):
        gateway = self.server
        job = {'id': uuid.uuid4().hex, 'service': service, 'done': threading.Event(),
               'assigned': False, 'result': {'error': 'agent_unavailable'}}
        with gateway.lock:
            if gateway.job is not None:
                send(sock, {'error': 'busy'})
                audit('busy', fingerprint=fingerprint)
                return
            gateway.job = job
        audit('request_started', request_id=job['id'], fingerprint=fingerprint, service=service)
        try:
            completed = job['done'].wait(8)
        finally:
            with gateway.lock:
                if gateway.job is job:
                    gateway.job = None
        send(sock, job['result'] if completed else {'error': 'agent_timeout'})
        audit('request_finished', request_id=job['id'], outcome='ok' if completed and 'result' in job['result'] else 'failed')

    def pull(self, sock, service, fingerprint):
        gateway = self.server
        with gateway.lock:
            job = gateway.job
            if job is None or job['service'] != service or job['assigned']:
                send(sock, {'idle': True})
                return
            job['assigned'] = True
        audit('request_assigned', request_id=job['id'], fingerprint=fingerprint, service=service)
        try:
            if service == STREAM_SERVICE:
                send(sock, {'id': job['id'], 'service': service, 'mode': 'stream'})
                ready = receive(sock, timeout=4)
                if ready != {'ready': True}:
                    send(job['socket'], {'error': 'lab_unavailable'})
                    return
                send(job['socket'], {'ready': True})
                reason, count = relay(job['socket'], sock)
                audit('stream_finished', request_id=job['id'], outcome=reason, bytes=count)
                return
            send(sock, {'id': job['id'], 'service': service})
            response = receive(sock, timeout=4)
            if response == {'id': job['id'], 'result': SERVICES[service][1]}:
                job['result'] = {'result': SERVICES[service][1]}
            else:
                job['result'] = {'error': 'invalid_lab_response'}
        finally:
            job['done'].set()

    def open_stream(self, sock, fingerprint):
        gateway = self.server
        job = {'id': uuid.uuid4().hex, 'service': STREAM_SERVICE,
               'assigned': False, 'done': threading.Event(), 'socket': sock}
        with gateway.lock:
            if gateway.job is not None:
                send(sock, {'error': 'busy'})
                return
            gateway.job = job
        audit('stream_started', request_id=job['id'], fingerprint=fingerprint, service=STREAM_SERVICE)
        try:
            # Assignment gets eight seconds; an assigned stream has a fixed 60s lifetime.
            deadline = time.monotonic() + 8
            while not job['done'].wait(.1):
                with gateway.lock:
                    assigned = job['assigned']
                if not assigned and time.monotonic() >= deadline:
                    send(sock, {'error': 'agent_timeout'})
                    break
                if time.monotonic() >= deadline + 65:
                    break
        finally:
            with gateway.lock:
                if gateway.job is job:
                    gateway.job = None


def connect(args, context):
    raw = socket.create_connection((args.host, args.port), timeout=12)
    try:
        return context.wrap_socket(raw, server_hostname=args.host)
    except BaseException:
        raw.close()
        raise


def lab_read(service):
    # No configurable destination, URL, headers, method, request body or redirect.
    connection = http.client.HTTPConnection('127.0.0.1', 18765, timeout=2)
    try:
        connection.request('GET', SERVICES[service][0])
        response = connection.getresponse()
        body = response.read(MAX_FRAME + 1)
        if response.status != 200 or len(body) > MAX_FRAME:
            raise ValueError('invalid lab response')
        result = json.loads(body)
        if result != SERVICES[service][1]:
            raise ValueError('synthetic fixture required')
        return result
    finally:
        connection.close()


def agent(args, stop=None):
    stop = stop or threading.Event()
    context = tls(args.ca, args.cert, args.key)
    delay = 1
    connected = False
    audit('agent_started', service=args.service)
    while not stop.is_set():
        try:
            with connect(args, context) as sock:
                send(sock, {'op': 'pull', 'service': args.service})
                job = receive(sock)
                if 'error' in job:
                    connected = False
                    audit('agent_denied', reason='rate_limit' if job['error'] == 'rate_limit' else 'denied')
                    stop.wait(30)
                    continue
                if not connected:
                    audit('agent_connected', service=args.service)
                    connected = True
                if job != {'idle': True}:
                    if args.service == STREAM_SERVICE:
                        if set(job) != {'id', 'service', 'mode'} or job['service'] != STREAM_SERVICE or job['mode'] != 'stream':
                            raise ValueError('invalid stream job')
                        try:
                            with socket.create_connection(('127.0.0.1', 18766), timeout=2) as local:
                                send(sock, {'ready': True})
                                reason, count = relay(local, sock)
                                audit('agent_stream_finished', outcome=reason, bytes=count)
                        except OSError:
                            send(sock, {'error': 'lab_unavailable'})
                        continue
                    if set(job) != {'id', 'service'} or job['service'] != args.service:
                        raise ValueError('invalid job')
                    try:
                        result = lab_read(args.service)
                        send(sock, {'id': job['id'], 'result': result})
                        audit('lab_completed', service=args.service)
                    except (OSError, ValueError, http.client.HTTPException):
                        send(sock, {'id': job['id'], 'error': 'lab_unavailable'})
                        audit('lab_unavailable', service=args.service)
            delay = 1
            stop.wait(2)
        except (OSError, ValueError, TypeError, KeyError) as error:
            connected = False
            audit('agent_reconnect', retry_seconds=delay, reason=failure_reason(error))
            stop.wait(delay + random.uniform(0, delay / 4))
            delay = min(30, delay * 2)


class Lab(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        for path, payload in SERVICES.values():
            if self.path == path:
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
        self.send_error(404)

    def log_message(self, *_):
        pass


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while data := self.request.recv(16384):
                self.request.sendall(data)
        except OSError:
            pass


class ForwardHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with connect(self.server.args, self.server.context) as sock:
                send(sock, {'op': 'open', 'service': STREAM_SERVICE})
                if receive(sock) != {'ready': True}:
                    audit('forward_denied')
                    return
                reason, count = relay(self.request, sock)
                audit('client_stream_finished', outcome=reason, bytes=count)
        except (OSError, ValueError):
            audit('forward_unavailable')


class Forwarder(socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 1

    def __init__(self, port, args):
        self.args = args
        self.context = tls(args.ca, args.cert, args.key)
        super().__init__(('127.0.0.1', port), ForwardHandler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['gateway', 'agent', 'query', 'check', 'forward', 'lab'])
    parser.add_argument('--host', default='localhost')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--ca', default='certs/ca.crt')
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--policy', default='certs/policy.json')
    parser.add_argument('--service', choices=ALLOWED_SERVICES, default='lab-status')
    parser.add_argument('--local-port', type=int, default=18080)
    args = parser.parse_args()
    if args.mode == 'lab':
        with socketserver.TCPServer(('127.0.0.1', 18766), Echo) as echo, \
                http.server.HTTPServer(('127.0.0.1', 18765), Lab) as server:
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            server.serve_forever()
    elif args.mode == 'gateway':
        with Gateway((args.bind, args.port), tls(args.ca, args.cert, args.key, True), load_policy(args.policy)) as server:
            audit('gateway_started')
            server.serve_forever()
    elif args.mode == 'agent':
        stop = threading.Event()
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        agent(args, stop)
    elif args.mode == 'forward':
        if args.service != STREAM_SERVICE:
            parser.error('forward requires --service lab-echo')
        with Forwarder(args.local_port, args) as server:
            audit('forward_listening', service=STREAM_SERVICE, port=args.local_port)
            server.serve_forever()
    else:
        try:
            with connect(args, tls(args.ca, args.cert, args.key)) as sock:
                send(sock, {'op': 'check' if args.mode == 'check' else 'query', 'service': args.service})
                result = receive(sock)
                print(json.dumps(result))
                return 1 if 'error' in result else 0
        except (OSError, ValueError) as error:
            audit('check_failed' if args.mode == 'check' else 'query_failed', reason=failure_reason(error))
            return 1
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        pass
