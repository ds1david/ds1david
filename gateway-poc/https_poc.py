"""HTTPS agent channel with signed messages and a separate mTLS client channel."""
import argparse
import base64
import collections
import contextlib
import datetime
import hashlib
import http.client
import http.server
import json
import signal
import socket
import socketserver
import sqlite3
import ssl
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import poc
from stream import relay

BLOCK = 4096
MAX_HTTP = 20000
TARGETS = {
    'lab-status': ('127.0.0.1', 18765), 'lab-catalog': ('127.0.0.1', 18765),
    'lab-echo': ('127.0.0.1', 18766),
    'gitlab': ('gitlab.sicredi.net', 443),
    'artifactory': ('artifactory.sicredi.net', 80),
}


def diagnostics(error):
    result = poc.diagnostic_fields(error, 'https_channel')
    if isinstance(error, jwt.InvalidSignatureError):
        result['reason'] = 'application_signature_invalid'
    elif isinstance(error, jwt.ExpiredSignatureError):
        result['reason'] = 'application_message_expired'
    elif isinstance(error, jwt.PyJWTError):
        result['reason'] = 'application_identity_invalid'
    return result


def read_config(path):
    path = Path(path).resolve()
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    config['_root'] = path.parent
    return config


def file(config, name):
    return str((config['_root'] / config[name]).resolve())


def service_allowed(config, service):
    if service not in TARGETS:
        return False
    entry = config['services'].get(service, {})
    if entry.get('enabled') is not True:
        return False
    if service.startswith('lab-'):
        return True
    approval = entry.get('approval', {})
    try:
        expires = datetime.datetime.strptime(approval['expires_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    except (KeyError, TypeError, ValueError):
        return False
    return (approval.get('agent_id') == config['agent_id']
            and all(isinstance(approval.get(k), str) and approval[k].strip()
                    for k in ('endpoint_security', 'service_owner'))
            and expires > datetime.datetime.now(datetime.timezone.utc))


class Signer:
    def __init__(self, identity, key_path):
        self.identity = identity
        self.key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)

    def sign(self, audience, payload, reply_to=''):
        now = int(time.time())
        return jwt.encode({'iss': self.identity, 'aud': audience, 'iat': now, 'nbf': now,
                           'exp': now + 30, 'jti': uuid.uuid4().hex,
                           'scope': 'POST:/v1/exchange', 'reply_to': reply_to, 'body': payload},
                          self.key, algorithm='RS256')


def decode(token, public_key, issuer, audience):
    result = jwt.decode(token, Path(public_key).read_bytes(), algorithms=['RS256'],
                        audience=audience, issuer=issuer,
                        options={'require': ['iss', 'aud', 'iat', 'nbf', 'exp', 'jti', 'scope', 'reply_to', 'body']})
    if (result['scope'] != 'POST:/v1/exchange' or not isinstance(result['body'], dict)
            or type(result['iat']) is not int or type(result['exp']) is not int
            or not 0 < result['exp'] - result['iat'] <= 30
            or not isinstance(result['jti'], str) or len(result['jti']) != 32):
        raise ValueError('invalid claims')
    return result


class ReplayStore:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute('CREATE TABLE IF NOT EXISTS used (jti TEXT PRIMARY KEY, expires INTEGER NOT NULL)')
        self.db.commit()

    def claim(self, message):
        with self.lock, self.db:
            self.db.execute('DELETE FROM used WHERE expires < ?', (int(time.time()),))
            try:
                self.db.execute('INSERT INTO used VALUES (?, ?)', (message['jti'], message['exp']))
            except sqlite3.IntegrityError:
                raise ValueError('replayed message') from None


class State:
    def __init__(self, config):
        self.config = config
        self.lock = threading.RLock()
        self.job = None
        self.rates = collections.defaultdict(collections.deque)
        self.signer = Signer(config['gateway_id'], file(config, 'signing_key'))
        self.replay = ReplayStore(file(config, 'replay_db'))

    def rate(self, identity, maximum):
        with self.lock:
            now = time.monotonic()
            queue = self.rates[identity]
            while queue and now - queue[0] > 60:
                queue.popleft()
            if len(queue) >= maximum:
                raise ValueError('rate limit')
            queue.append(now)

    def exchange(self, body):
        action, service = body.get('action'), body.get('service')
        if not service_allowed(self.config, service):
            raise ValueError('service denied')
        with self.lock:
            if action == 'check' and set(body) == {'action', 'service'}:
                return {'ready': True}
            job = self.job
            if action == 'poll' and set(body) == {'action', 'service'}:
                if not job or job['service'] != service or job['assigned'] or job['done'].is_set():
                    return {'idle': True}
                job['assigned'] = True
                poc.audit('https_request_assigned', request_id=job['id'], service=service)
                return {'job': job['id']}
            if (action != 'exchange' or set(body) != {'action', 'service', 'job', 'seq', 'data', 'closed', 'ready'}
                    or not job or job['done'].is_set() or not job['assigned']
                    or job['id'] != body['job'] or job['service'] != service
                    or type(body['seq']) is not int or job['seq'] != body['seq']
                    or type(body['closed']) is not bool or type(body['ready']) is not bool):
                raise ValueError('invalid exchange')
            data = base64.b64decode(body['data'], validate=True)
            if len(data) > BLOCK:
                raise ValueError('block limit')
            job['seq'] += 1
            if not job['ready']:
                if not body['ready']:
                    job['error'] = 'target_unavailable'
                    job['done'].set()
                    return {'closed': True, 'data': '', 'seq': body['seq']}
                poc.send(job['socket'], {'ready': True})
                job['socket'].settimeout(.1)
                job['ready'] = True
            job['bytes'] += len(data)
            if job['bytes'] > self.config['max_bytes'] or time.monotonic() >= job['deadline']:
                job['done'].set()
                return {'closed': True, 'data': '', 'seq': body['seq']}
            if data:
                job['socket'].sendall(data)
                job['activity'] = time.monotonic()
            outbound = b''
            closed = body['closed']
            if not closed:
                try:
                    outbound = job['socket'].recv(BLOCK)
                    if not outbound:
                        closed = True
                except socket.timeout:
                    pass
            job['bytes'] += len(outbound)
            if outbound:
                job['activity'] = time.monotonic()
            if (job['bytes'] > self.config['max_bytes']
                    or time.monotonic() - job['activity'] > 10):
                closed, outbound = True, b''
            if closed:
                job['done'].set()
            return {'closed': closed, 'data': base64.b64encode(outbound).decode(), 'seq': body['seq']}


class BoundedServer(socketserver.ThreadingMixIn):
    daemon_threads = True

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class TLSAccept:
    def setup(self):
        self.request.settimeout(4)
        self.request = self.server.context.wrap_socket(self.request, server_side=True)
        self.request.settimeout(4)
        self.connection = self.request
        super().setup()

    def finish(self):
        try:
            super().finish()
        finally:
            self.request.close()


class APIHandler(TLSAccept, http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def log_message(self, *_):
        pass

    def do_POST(self):
        state = self.server.state
        try:
            lengths = self.headers.get_all('Content-Length', [])
            if (self.path != '/v1/exchange' or len(lengths) != 1 or 'Transfer-Encoding' in self.headers
                    or not 0 < int(lengths[0]) <= MAX_HTTP):
                raise ValueError('invalid request')
            token = self.rfile.read(int(lengths[0])).decode('ascii')
            message = decode(token, file(state.config, 'agent_public'),
                             state.config['agent_id'], state.config['gateway_id'])
            if message['reply_to'] != '':
                raise ValueError('request binding')
            state.rate(state.config['agent_id'], 1200)
            state.replay.claim(message)
            response = state.exchange(message['body'])
            output = state.signer.sign(state.config['agent_id'], response, message['jti']).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/jwt')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(output)))
            self.end_headers()
            self.wfile.write(output)
        except (OSError, ValueError, TypeError, KeyError, jwt.PyJWTError, RecursionError):
            poc.audit('https_request_rejected')
            self.send_error(403, 'denied')


class API(BoundedServer, http.server.HTTPServer):
    def __init__(self, address, state, context):
        self.state, self.context = state, context
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, APIHandler)

    def handle_error(self, *_):
        poc.audit('https_connection_rejected')


class ClientHandler(TLSAccept, socketserver.BaseRequestHandler):
    def handle(self):
        state = self.server.state
        try:
            identity = hashlib.sha256(self.request.getpeercert(binary_form=True)).hexdigest()
            policy = state.config['clients'].get(identity, {})
            request = poc.receive(self.request, timeout=4)
            service = request.get('service')
            state.rate(identity if identity in state.config['clients'] else 'unknown', 30)
            if (set(request) != {'op', 'service'} or request['op'] not in ('open', 'check')
                    or service not in policy.get('services', []) or not service_allowed(state.config, service)):
                poc.send(self.request, {'error': 'denied'})
                return
            if request['op'] == 'check':
                poc.send(self.request, {'ready': True})
                return
            now = time.monotonic()
            job = {'id': uuid.uuid4().hex, 'socket': self.request, 'service': service,
                   'done': threading.Event(), 'assigned': False, 'ready': False, 'seq': 0,
                   'bytes': 0, 'activity': now, 'deadline': now + state.config['max_seconds'],
                   'error': 'agent_timeout'}
            with state.lock:
                if state.job is not None:
                    poc.send(self.request, {'error': 'busy'})
                    return
                state.job = job
            poc.audit('https_session_started', request_id=job['id'], service=service, fingerprint=identity)
            try:
                while not job['done'].wait(.1):
                    with state.lock:
                        if (time.monotonic() >= job['deadline']
                                or (not job['assigned'] and time.monotonic() - now > 8)):
                            job['done'].set()
                if not job['ready']:
                    poc.send(self.request, {'error': job['error']})
            finally:
                with state.lock:
                    job['done'].set()
                    if state.job is job:
                        state.job = None
                poc.audit('https_session_finished', request_id=job['id'], service=service, bytes=job['bytes'])
        except (OSError, ValueError, KeyError, TypeError):
            poc.audit('https_client_rejected')


class Clients(BoundedServer, socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, address, state, context):
        self.state, self.context = state, context
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, ClientHandler)

    def handle_error(self, *_):
        poc.audit('https_client_tls_rejected')


class Channel:
    def __init__(self, config):
        self.config = config
        self.url = urlsplit(config['agent_url'])
        if self.url.scheme != 'https' or self.url.path not in ('', '/') or self.url.username or self.url.query:
            raise ValueError('HTTPS origin required')
        self.context = ssl.create_default_context()
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_verify_locations(cafile=file(config, 'tls_ca'))
        if config.get('corporate_ca'):
            self.context.load_verify_locations(cafile=file(config, 'corporate_ca'))
        self.signer = Signer(config['agent_id'], file(config, 'signing_key'))

    def request(self, body):
        token = self.signer.sign(self.config['gateway_id'], body)
        claims = jwt.decode(token, options={'verify_signature': False}, algorithms=['RS256'])
        connection = http.client.HTTPSConnection(self.url.hostname, self.url.port or 443,
                                                  timeout=6, context=self.context)
        try:
            connection.request('POST', '/v1/exchange', token, {'Content-Type': 'application/jwt'})
            response = connection.getresponse()
            data = response.read(MAX_HTTP + 1)
            if response.status != 200 or len(data) > MAX_HTTP:
                raise ValueError('endpoint denied request')
            result = decode(data, file(self.config, 'gateway_public'),
                            self.config['gateway_id'], self.config['agent_id'])
            if result['reply_to'] != claims['jti']:
                raise ValueError('response binding')
            return result['body']
        finally:
            connection.close()


def agent(config, service, stop):
    if not service_allowed(config, service):
        raise ValueError('service disabled or approval missing')
    channel = Channel(config)
    delay, connected = 1, False
    while not stop.is_set():
        try:
            result = channel.request({'action': 'poll', 'service': service})
            if not connected:
                poc.audit('https_agent_connected', service=service)
                connected = True
            if 'job' in result:
                local = None
                try:
                    local = socket.create_connection(TARGETS[service], timeout=2)
                    local.settimeout(.1)
                except OSError:
                    pass
                try:
                    seq, closed = 0, local is None
                    deadline = time.monotonic() + config['max_seconds']
                    while not stop.is_set() and time.monotonic() < deadline:
                        data = b''
                        if local:
                            try:
                                data = local.recv(BLOCK)
                                closed = not data
                            except socket.timeout:
                                pass
                        response = channel.request({'action': 'exchange', 'service': service,
                            'job': result['job'], 'seq': seq, 'data': base64.b64encode(data).decode(),
                            'closed': closed, 'ready': local is not None})
                        if response.get('seq') != seq:
                            raise ValueError('invalid sequence')
                        received = base64.b64decode(response['data'], validate=True)
                        if len(received) > BLOCK:
                            raise ValueError('block limit')
                        if received and local:
                            local.sendall(received)
                        if closed or response['closed']:
                            break
                        seq += 1
                finally:
                    if local:
                        local.close()
            delay = 1
            stop.wait(2)
        except (OSError, ValueError, TypeError, KeyError, jwt.PyJWTError) as error:
            connected = False
            poc.audit('https_agent_retry', retry_seconds=delay, **diagnostics(error))
            stop.wait(delay)
            delay = min(30, delay * 2)


def client_socket(config, service, op='open'):
    if not service_allowed(config, service):
        raise ValueError('service disabled or approval missing')
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=file(config, 'tls_ca'))
    context.load_cert_chain(file(config, 'tls_cert'), file(config, 'tls_key'))
    args = argparse.Namespace(host=config['client_host'], port=config['client_port'])
    sock = poc.connect(args, context)
    try:
        poc.send(sock, {'op': op, 'service': service})
        if poc.receive(sock) != {'ready': True}:
            raise ValueError('client denied or agent unavailable')
        return sock
    except BaseException:
        sock.close()
        raise


class LocalHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with client_socket(self.server.config, self.server.service) as remote:
                reason, count = relay(self.request, remote,
                    max_bytes=self.server.config['max_bytes'], max_seconds=self.server.config['max_seconds'])
                poc.audit('https_local_finished', outcome=reason, bytes=count)
        except (OSError, ValueError):
            poc.audit('https_local_failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['gateway', 'agent', 'check', 'query', 'forward'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--service', choices=TARGETS, default='lab-status')
    parser.add_argument('--lab', action='store_true', help='Start the fixed loopback fixtures with the agent')
    args = parser.parse_args()
    config = read_config(args.config)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    if args.mode == 'gateway':
        state = State(config)
        agent_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        agent_tls.minimum_version = ssl.TLSVersion.TLSv1_2
        agent_tls.load_cert_chain(file(config, 'tls_cert'), file(config, 'tls_key'))
        client_tls = poc.tls(file(config, 'tls_ca'), file(config, 'tls_cert'), file(config, 'tls_key'), True)
        with API((config['bind'], config['agent_port']), state, agent_tls) as api, \
                Clients((config['bind'], config['client_port']), state, client_tls) as clients:
            for server in (api, clients):
                threading.Thread(target=server.serve_forever, daemon=True).start()
            poc.audit('https_gateway_started')
            while not stop.wait(.5):
                pass
            api.shutdown()
            clients.shutdown()
        state.replay.db.close()
    elif args.mode == 'agent':
        if args.lab and not args.service.startswith('lab-'):
            raise ValueError('automatic lab only supports synthetic services')
        with contextlib.ExitStack() as stack:
            servers = []
            if args.lab:
                servers = [stack.enter_context(http.server.HTTPServer(('127.0.0.1', 18765), poc.Lab)),
                           stack.enter_context(socketserver.TCPServer(('127.0.0.1', 18766), poc.Echo))]
                for server in servers:
                    threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                agent(config, args.service, stop)
            finally:
                for server in servers:
                    server.shutdown()
                poc.audit('https_agent_stopped', service=args.service)
    elif args.mode == 'check':
        if 'agent_url' in config:
            if not service_allowed(config, args.service):
                raise ValueError('service disabled')
            result = Channel(config).request({'action': 'check', 'service': args.service})
            print(json.dumps(result))
        else:
            with client_socket(config, args.service, 'check'):
                print(json.dumps({'ready': True}))
    elif args.mode == 'query':
        if args.service not in poc.SERVICES:
            raise ValueError('query supports synthetic HTTP only; use forward for TCP')
        with client_socket(config, args.service) as sock:
            path, expected = poc.SERVICES[args.service]
            sock.sendall(f'GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n'.encode())
            response = http.client.HTTPResponse(sock)
            response.begin()
            body = response.read(poc.MAX_FRAME + 1)
            if response.status != 200 or json.loads(body) != expected:
                raise ValueError('invalid fixture')
            print(json.dumps({'result': expected}))
    else:
        if not service_allowed(config, args.service):
            raise ValueError('service disabled or approval missing')
        with socketserver.TCPServer(('127.0.0.1', config['services'][args.service]['local_port']), LocalHandler) as server:
            server.config, server.service = config, args.service
            server.timeout = .5
            poc.audit('https_local_listening', service=args.service)
            while not stop.is_set():
                server.handle_request()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, jwt.PyJWTError) as error:
        poc.audit('https_failed', **diagnostics(error))
        raise SystemExit(1)
