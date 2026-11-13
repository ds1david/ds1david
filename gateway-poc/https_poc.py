"""HTTPS agent channel with signed messages and a separate mTLS client channel."""
import argparse
import base64
import collections
import contextlib
import datetime
import hashlib
import hmac
import http.client
import http.server
import json
import os
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

BLOCK = 32768
MAX_HTTP = 65536
TARGETS = {
    'lab-status': ('127.0.0.1', 18765), 'lab-catalog': ('127.0.0.1', 18765),
    'lab-echo': ('127.0.0.1', 18766),
    'gitlab': ('gitlab.sicredi.net', 443),
    'artifactory': ('artifactory.sicredi.net', 80),
}


class ChannelError(ValueError):
    """Fixed public error code; never include response bodies or headers."""
    def __init__(self, reason, stage, http_status=None):
        super().__init__(reason)
        self.reason, self.poc_stage, self.http_status = reason, stage, http_status


def diagnostics(error):
    result = poc.diagnostic_fields(error, 'https_channel')
    if isinstance(error, ChannelError):
        result['reason'] = error.reason
        if type(error.http_status) is int:
            result['http_status'] = error.http_status
    elif isinstance(error, jwt.InvalidSignatureError):
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


def utc_expiry(value):
    try:
        return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()
    except (TypeError, ValueError):
        return 0


def service_allowed(config, service):
    if service not in TARGETS:
        return False
    entry = config['services'].get(service, {})
    if entry.get('enabled') is not True:
        return False
    if service.startswith('lab-'):
        return True
    test = entry.get('test_authorization', {})
    if config.get('operation_mode') == 'homologation':
        return (test.get('kind') == 'requester_authorized_test'
                and test.get('agent_id') == config['agent_id']
                and isinstance(test.get('requested_by'), str) and bool(test['requested_by'].strip())
                and test.get('corporate_approval') == 'pending'
                and utc_expiry(test.get('expires_utc')) > time.time())
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
        raise ChannelError('application_claims_invalid', 'application_authentication')
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
        self.jobs = {}
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
            if action == 'poll' and set(body) == {'action', 'service'}:
                job = next((j for j in self.jobs.values() if j['service'] == service
                            and not j['assigned'] and not j['done'].is_set()), None)
                if job is None:
                    return {'idle': True}
                job['assigned'] = True
                poc.audit('https_request_assigned', request_id=job['id'], service=service)
                return {'job': job['id']}
            job = self.jobs.get(body.get('job'))
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
                    or time.monotonic() - job['activity'] > self.config.get('idle_seconds', 10)):
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
        stage = 'http_request'
        try:
            lengths = self.headers.get_all('Content-Length', [])
            if (self.path != '/v1/exchange' or len(lengths) != 1 or 'Transfer-Encoding' in self.headers
                    or not 0 < int(lengths[0]) <= MAX_HTTP):
                raise ValueError('invalid request')
            token = self.rfile.read(int(lengths[0])).decode('ascii')
            stage = 'agent_authentication'
            message = decode(token, file(state.config, 'agent_public'),
                             state.config['agent_id'], state.config['gateway_id'])
            if message['reply_to'] != '':
                raise ValueError('request binding')
            state.rate(state.config['agent_id'], 1200)
            state.replay.claim(message)
            stage = 'service_dispatch'
            response = state.exchange(message['body'])
            output = state.signer.sign(state.config['agent_id'], response, message['jti']).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/jwt')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(output)))
            self.end_headers()
            self.wfile.write(output)
        except (OSError, ValueError, TypeError, KeyError, jwt.PyJWTError, RecursionError) as error:
            details = diagnostics(error)
            if details['stage'] == 'https_channel':
                details['stage'] = stage
            poc.audit('https_request_rejected', **details)
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
            request = poc.receive(self.request, timeout=4)
            mode = state.config.get('client_auth', 'mtls')
            if mode == 'token':
                supplied = request.get('token')
                identity = request.get('client_id')
                if not isinstance(identity, str) or len(identity) > 64:
                    identity = 'unknown'
                policy = state.config.get('token_clients', {}).get(identity, {})
                state.rate(identity if policy else 'unknown', min(120, state.config.get('client_requests_per_minute', 30)))
                if (not isinstance(supplied, str) or not 32 <= len(supplied) <= 128
                        or policy.get('enabled') is not True
                        or utc_expiry(policy.get('expires_utc')) <= time.time()
                        or not hmac.compare_digest(hashlib.sha256(supplied.encode()).hexdigest(), policy.get('token_sha256', ''))):
                    poc.send(self.request, {'error': 'denied'})
                    poc.audit('token_client_denied')
                    return
                expected = {'op', 'service', 'client_id', 'token'}
            elif mode == 'mtls':
                identity = hashlib.sha256(self.request.getpeercert(binary_form=True)).hexdigest()
                policy = state.config['clients'].get(identity, {})
                state.rate(identity if identity in state.config['clients'] else 'unknown', 30)
                expected = {'op', 'service'}
            else:
                raise ValueError('unknown client auth mode')
            service = request.get('service')
            if (set(request) != expected or request['op'] not in ('open', 'check')
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
            expiry = utc_expiry(policy.get('expires_utc'))
            test_expiry = utc_expiry(state.config['services'][service].get('test_authorization', {}).get('expires_utc'))
            for limit in (expiry, test_expiry):
                if limit:
                    job['deadline'] = min(job['deadline'], now + max(0, limit - time.time()))
            with state.lock:
                if len(state.jobs) >= min(4, state.config.get('max_sessions', 1)):
                    poc.send(self.request, {'error': 'busy'})
                    return
                state.jobs[job['id']] = job
            poc.audit('https_session_started', request_id=job['id'], service=service, client_id=identity, auth=mode)
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
                    state.jobs.pop(job['id'], None)
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
            if response.status != 200:
                raise ChannelError('https_http_error', 'http_response', response.status)
            if response.getheader('Content-Type', '').split(';')[0].strip().lower() != 'application/jwt':
                raise ChannelError('https_unexpected_content_type', 'http_response', response.status)
            data = response.read(MAX_HTTP + 1)
            if len(data) > MAX_HTTP:
                raise ChannelError('https_response_too_large', 'http_response', response.status)
            try:
                result = decode(data, file(self.config, 'gateway_public'),
                                self.config['gateway_id'], self.config['agent_id'])
            except (jwt.PyJWTError, OSError) as error:
                error.poc_stage = 'gateway_authentication'
                raise
            if result['reply_to'] != claims['jti']:
                raise ChannelError('application_response_binding_invalid', 'gateway_authentication')
            return result['body']
        finally:
            connection.close()


def agent(config, service, stop):
    if not service_allowed(config, service):
        raise ChannelError('service_disabled_or_expired', 'service_authorization')
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
                seq, finished = 0, False
                try:
                    local = socket.create_connection(TARGETS[service], timeout=2)
                    local.settimeout(.1)
                except OSError:
                    pass
                try:
                    closed = local is None
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
                        seq += 1
                        received = base64.b64decode(response['data'], validate=True)
                        if len(received) > BLOCK:
                            raise ValueError('block limit')
                        if received and local:
                            local.sendall(received)
                        if closed or response['closed']:
                            finished = True
                            break
                finally:
                    if not finished:
                        try:
                            channel.request({'action': 'exchange', 'service': service, 'job': result['job'],
                                             'seq': seq, 'data': '', 'closed': True, 'ready': local is not None})
                        except (OSError, ValueError, KeyError, jwt.PyJWTError):
                            poc.audit('session_abort_pending', service=service)
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
        raise ChannelError('service_disabled_or_expired', 'service_authorization')
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=file(config, 'tls_ca'))
    mode = config.get('client_auth', 'mtls')
    if mode == 'mtls':
        context.load_cert_chain(file(config, 'tls_cert'), file(config, 'tls_key'))
    elif mode != 'token':
        raise ValueError('unknown client auth mode')
    args = argparse.Namespace(host=config['client_host'], port=config['client_port'])
    sock = poc.connect(args, context)
    try:
        request = {'op': op, 'service': service}
        if mode == 'token':
            request.update(client_id=config['client_id'], token=Path(file(config, 'client_token_file')).read_text().strip())
        poc.send(sock, request)
        result = poc.receive(sock)
        if result != {'ready': True}:
            reason = {'denied': 'client_or_service_denied', 'busy': 'gateway_busy',
                      'agent_timeout': 'agent_not_available', 'target_unavailable': 'target_unavailable'}.get(
                          result.get('error'), 'client_response_invalid')
            raise ChannelError(reason, 'client_authorization')
        return sock
    except BaseException:
        sock.close()
        raise


def client_tls_context(config):
    mode = config.get('client_auth', 'mtls')
    if mode == 'mtls':
        return poc.tls(file(config, 'tls_ca'), file(config, 'tls_cert'), file(config, 'tls_key'), True)
    if mode != 'token':
        raise ValueError('unknown client auth mode')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(file(config, 'tls_cert'), file(config, 'tls_key'))
    return context


def agent_pool(config, services, stop):
    for service in services:
        if not service_allowed(config, service):
            raise ChannelError('service_disabled_or_expired', 'service_authorization')
    # Four bounded workers allow concurrent browser/Git requests without an open proxy.
    workers = [threading.Thread(target=agent, args=(config, services[i % len(services)], stop), daemon=True)
               for i in range(4)]
    for worker in workers:
        worker.start()
    while not stop.wait(.5):
        if any(not service_allowed(config, service) for service in services):
            poc.audit('homologation_expired')
            stop.set()
    for worker in workers:
        worker.join(10)


def preflight(config, services):
    channel = Channel(config)
    results = []
    target_tls = ssl.create_default_context()
    target_tls.minimum_version = ssl.TLSVersion.TLSv1_2
    if config.get('corporate_ca'):
        target_tls.load_verify_locations(cafile=file(config, 'corporate_ca'))
    for service in services:
        if not service_allowed(config, service):
            raise ChannelError('service_disabled_or_expired', 'service_authorization')
        reply = channel.request({'action': 'check', 'service': service})
        if reply != {'ready': True}:
            raise ChannelError('gateway_preflight_invalid', 'gateway_preflight')
        host, port = TARGETS[service]
        try:
            socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            if service.startswith('lab-'):
                with socket.create_connection((host, port), timeout=5):
                    pass
                results.append({'service': service, 'transport': 'tcp_ready'})
                continue
            path = config.get('readiness_paths', {}).get(service, '/')
            if not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or '\r' in path or '\n' in path:
                raise ChannelError('invalid_readiness_path', 'target_preflight')
            connection = (http.client.HTTPSConnection(host, port, timeout=5, context=target_tls)
                          if service == 'gitlab' else http.client.HTTPConnection(host, port, timeout=5))
            try:
                connection.request('HEAD', path, headers={'Connection': 'close'})
                response = connection.getresponse()
                if not (200 <= response.status < 400 or response.status == 401):
                    raise ChannelError('target_http_not_ready', 'target_preflight', response.status)
                results.append({'service': service, 'http_status': response.status,
                                'application_login': 'not_tested_on_agent'})
            finally:
                connection.close()
        except (OSError, http.client.HTTPException) as error:
            error.poc_stage = 'target_preflight'
            raise
    return {'ready': True, 'checks': results, 'scope': 'agent transport; application credentials remain on client'}


def mark_ready(path):
    if path:
        target = Path(path)
        temporary = target.with_name(target.name + '.' + uuid.uuid4().hex + '.tmp')
        temporary.write_text(json.dumps({'ready': True, 'pid': os.getpid(), 'time': time.time()}), encoding='utf-8')
        temporary.replace(target)


def watch_stop_file(path, stop):
    while not stop.wait(.25):
        if Path(path).is_file():
            stop.set()


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        established = False
        destination_allowed = False
        try:
            header = bytearray()
            deadline = time.monotonic() + 5
            while not header.endswith(b'\r\n\r\n'):
                if len(header) >= 16384 or time.monotonic() >= deadline:
                    raise ValueError('header limit')
                self.request.settimeout(max(.01, deadline - time.monotonic()))
                data = self.request.recv(1)
                if not data:
                    return
                header.extend(data)
            lines = header.decode('iso-8859-1').split('\r\n')
            method, target, version = lines[0].split()
            if version not in ('HTTP/1.0', 'HTTP/1.1'):
                raise ValueError('version denied')
            headers = []
            names = []
            for line in lines[1:-2]:
                name, value = line.split(':', 1)
                if not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in name.lower()):
                    raise ValueError('header denied')
                names.append(name.lower())
                if name.lower() not in ('host', 'connection', 'proxy-connection', 'proxy-authorization'):
                    headers.append((name, value.strip()))
            if names.count('content-length') > 1 or ('content-length' in names and 'transfer-encoding' in names):
                raise ValueError('ambiguous body')
            url = urlsplit('//' + target if method == 'CONNECT' else target)
            port = url.port or (443 if method == 'CONNECT' else 80)
            if url.username or url.password or url.fragment:
                raise ValueError('authority denied')
            if method == 'CONNECT':
                if url.path or url.query:
                    raise ValueError('authority denied')
            elif (url.scheme != 'http' or method not in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')):
                raise ValueError('method denied')
            service = next((name for name, destination in TARGETS.items()
                            if destination == (url.hostname, port)
                            and service_allowed(self.server.config, name)), None)
            if service is None:
                raise ValueError('destination denied')
            destination_allowed = True
            with client_socket(self.server.config, service) as remote:
                if method == 'CONNECT':
                    self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                else:
                    path = url.path or '/'
                    if url.query:
                        path += '?' + url.query
                    host = url.hostname if port == 80 else f'{url.hostname}:{port}'
                    request = f'{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n'
                    request += ''.join(f'{name}: {value}\r\n' for name, value in headers) + '\r\n'
                    remote.sendall(request.encode('iso-8859-1'))
                established = True
                reason, count = relay(self.request, remote, self.server.config['max_bytes'],
                                      self.server.config['max_seconds'], self.server.config.get('idle_seconds', 10))
                poc.audit('local_proxy_finished', service=service, outcome=reason, bytes=count)
        except (OSError, ValueError, TypeError) as error:
            poc.audit('local_proxy_failed' if destination_allowed else 'local_proxy_denied', **diagnostics(error))
            if not established:
                try:
                    status = b'502 Bad Gateway' if destination_allowed else b'403 Forbidden'
                    self.request.sendall(b'HTTP/1.1 ' + status + b'\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                except OSError:
                    pass


class LocalProxy(BoundedServer, socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, config):
        self.config = config
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(('127.0.0.1', config.get('proxy_port', 18080)), ProxyHandler)

    def handle_error(self, *_):
        poc.audit('local_proxy_failed')


class LocalHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with client_socket(self.server.config, self.server.service) as remote:
                reason, count = relay(self.request, remote,
                    max_bytes=self.server.config['max_bytes'], max_seconds=self.server.config['max_seconds'],
                    idle_seconds=self.server.config.get('idle_seconds', 10))
                poc.audit('https_local_finished', outcome=reason, bytes=count)
        except (OSError, ValueError):
            poc.audit('https_local_failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['gateway', 'agent', 'check', 'query', 'forward', 'proxy', 'preflight'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--service', choices=[*TARGETS, 'homologation'], default='lab-status')
    parser.add_argument('--lab', action='store_true', help='Start the fixed loopback fixtures with the agent')
    parser.add_argument('--preflight', action='store_true', help='Require all agent connectivity checks before starting')
    parser.add_argument('--ready-file', help='Local readiness marker for the background launcher')
    parser.add_argument('--stop-file', help='Private local stop marker for the background launcher')
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
        client_tls = client_tls_context(config)
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
        if args.stop_file:
            threading.Thread(target=watch_stop_file, args=(args.stop_file, stop), daemon=True).start()
        if args.service == 'homologation':
            if args.lab:
                raise ValueError('homologation does not start synthetic fixtures')
            if args.preflight:
                poc.audit('agent_preflight_ok', **preflight(config, ['gitlab', 'artifactory']))
            mark_ready(args.ready_file)
            agent_pool(config, ['gitlab', 'artifactory'], stop)
            return
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
                if args.preflight:
                    poc.audit('agent_preflight_ok', **preflight(config, [args.service]))
                mark_ready(args.ready_file)
                agent(config, args.service, stop)
            finally:
                for server in servers:
                    server.shutdown()
                poc.audit('https_agent_stopped', service=args.service)
    elif args.mode == 'preflight':
        print(json.dumps(preflight(config, ['gitlab', 'artifactory'] if args.service == 'homologation' else [args.service])))
    elif args.mode == 'check':
        if args.service == 'homologation':
            results = {}
            for service in ('gitlab', 'artifactory'):
                if 'agent_url' in config:
                    if not service_allowed(config, service):
                        raise ChannelError('service_disabled_or_expired', 'service_authorization')
                    results[service] = Channel(config).request({'action': 'check', 'service': service})
                else:
                    with client_socket(config, service, 'check'):
                        results[service] = {'ready': True}
            print(json.dumps(results))
            return
        if 'agent_url' in config:
            if not service_allowed(config, args.service):
                raise ChannelError('service_disabled_or_expired', 'service_authorization')
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
    elif args.mode == 'proxy':
        with LocalProxy(config) as server:
            server.timeout = .5
            poc.audit('local_proxy_started', port=server.server_address[1])
            while not stop.is_set():
                server.handle_request()
    else:
        if not service_allowed(config, args.service):
            raise ChannelError('service_disabled_or_expired', 'service_authorization')
        with socketserver.TCPServer(('127.0.0.1', config['services'][args.service]['local_port']), LocalHandler) as server:
            server.config, server.service = config, args.service
            server.timeout = .5
            poc.audit('https_local_listening', service=args.service)
            while not stop.is_set():
                server.handle_request()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, jwt.PyJWTError, http.client.HTTPException) as error:
        poc.audit('https_failed', **diagnostics(error))
        raise SystemExit(1)
