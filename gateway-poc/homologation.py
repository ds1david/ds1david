"""Create per-client tokens and apply a time-limited requester-authorized test policy."""
import argparse
import copy
import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import uuid

SERVICES = {'gitlab': 18443, 'artifactory': 18081}
LIMITS = {'max_bytes': 16 * 1024 * 1024, 'max_seconds': 300,
          'max_sessions': 4, 'idle_seconds': 30, 'client_requests_per_minute': 120}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    path.chmod(0o600)


def prepare(out, client_id='intermediario-01', agent_id='windows-lab-01', hours=24,
            requested_by=None, services=('gitlab', 'artifactory')):
    if not all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', value) for value in (client_id, agent_id)):
        raise ValueError('invalid identity')
    if not 1 <= hours <= 24 or not services or any(service not in SERVICES for service in services):
        raise ValueError('test scope must be fixed destinations and 1-24 hours')
    out = Path(out).resolve()
    out.mkdir(parents=True, mode=0o755 if os.name == 'nt' else 0o700, exist_ok=False)
    requested_by = requested_by or getpass.getuser()
    if not isinstance(requested_by, str) or not requested_by.strip():
        raise ValueError('requester required')
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = (now + datetime.timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%SZ')
    authorization = {'kind': 'requester_authorized_test', 'agent_id': agent_id,
        'requested_by': requested_by, 'issued_utc': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'expires_utc': expires, 'corporate_approval': 'pending',
        'purpose': 'Final POC validation requested by operator; not production approval'}
    common = {'operation_mode': 'homologation', 'agent_id': agent_id,
        'services': {name: {'enabled': True, 'local_port': SERVICES[name],
                           'test_authorization': copy.deepcopy(authorization)} for name in services}, **LIMITS}
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    token_path = out / 'client.token'
    token_path.write_text(token + '\n', encoding='ascii')
    token_path.chmod(0o600)
    patches = {
        'gateway': {**copy.deepcopy(common), 'client_auth': 'token',
                    'token_clients': {client_id: {'enabled': True, 'token_sha256': digest,
                                      'expires_utc': expires, 'services': list(services)}}},
        'agent': copy.deepcopy(common),
        'client': {**copy.deepcopy(common), 'client_auth': 'token', 'client_id': client_id,
                   'client_token_file': 'client.token', 'proxy_port': 18080},
    }
    for role, patch in patches.items():
        write_json(out / (role + '-policy.json'), {'format': 1, 'role': role, 'patch': patch,
                    **({'token_sha256': digest} if role == 'client' else {})})
    return {'client_id': client_id, 'agent_id': agent_id, 'services': list(services),
            'expires_utc': expires, 'token_file': str(token_path), 'corporate_approval': 'pending'}


def apply(config_path, policy_path):
    config_path, policy_path = Path(config_path).resolve(), Path(policy_path).resolve()
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    overlay = json.loads(policy_path.read_text(encoding='utf-8-sig'))
    role = overlay.get('role')
    expected_role = 'agent' if 'agent_url' in config else ('gateway' if 'signing_key' in config else 'client')
    if overlay.get('format') != 1 or role != expected_role:
        raise ValueError('policy role does not match configuration')
    patch = overlay['patch']
    allowed = {'operation_mode', 'agent_id', 'services', *LIMITS}
    allowed |= {'gateway': {'client_auth', 'token_clients'}, 'agent': set(),
                'client': {'client_auth', 'client_id', 'client_token_file', 'proxy_port'}}[role]
    if (set(patch) - allowed or patch.get('operation_mode') != 'homologation'
            or patch.get('agent_id') != config['agent_id']):
        raise ValueError('invalid policy fields or agent identity')
    if not patch.get('services') or set(patch['services']) - SERVICES.keys():
        raise ValueError('invalid destinations')
    for entry in patch['services'].values():
        authorization = entry.get('test_authorization', {})
        try:
            end = datetime.datetime.strptime(authorization['expires_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
            start = datetime.datetime.strptime(authorization['issued_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
        except (KeyError, TypeError, ValueError):
            raise ValueError('invalid test authorization') from None
        if (authorization.get('kind') != 'requester_authorized_test'
                or authorization.get('corporate_approval') != 'pending'
                or authorization.get('agent_id') != config['agent_id']
                or not 0 < (end - start).total_seconds() <= 24 * 3600
                or end <= datetime.datetime.now(datetime.timezone.utc)):
            raise ValueError('expired or invalid test authorization')
    token_path = None
    if role == 'client':
        if patch.get('client_token_file') != 'client.token':
            raise ValueError('invalid token file')
        token_path = policy_path.parent / 'client.token'
        token = token_path.read_text(encoding='ascii').strip()
        if not secrets.compare_digest(hashlib.sha256(token.encode()).hexdigest(), overlay['token_sha256']):
            raise ValueError('token and policy differ')
    backup = config_path.with_name(config_path.name + '.before-homologation-' + uuid.uuid4().hex[:10])
    shutil.copy2(config_path, backup)
    backup.chmod(0o600)
    for key, value in patch.items():
        if key in ('services', 'token_clients'):
            for name, entry in value.items():
                config.setdefault(key, {}).setdefault(name, {}).update(entry)
        else:
            config[key] = value
    if token_path:
        target = config_path.parent / 'client.token'
        if target != token_path:
            shutil.copyfile(token_path, target)
        target.chmod(0o600)
    # Do not chmod the existing config: preserve its root:gateway-poc 0640 mode.
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return str(backup)


def issue_client(config_path, out, client_id, hours=24, services=('gitlab', 'artifactory')):
    """Issue on the gateway, bounded by its existing service authorization."""
    config_path = Path(config_path).resolve()
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    if config.get('operation_mode') != 'homologation' or config.get('client_auth') != 'token':
        raise ValueError('gateway must already use homologation tokens')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', client_id):
        raise ValueError('invalid client identity')
    if client_id in config.get('token_clients', {}):
        raise ValueError('client already exists; use a new identity')
    if not 1 <= hours <= 24 or not services or set(services) - SERVICES.keys():
        raise ValueError('invalid scope or lifetime')
    now = datetime.datetime.now(datetime.timezone.utc)
    deadline = now + datetime.timedelta(hours=hours)
    selected = {}
    for name in services:
        entry = config.get('services', {}).get(name, {})
        auth = entry.get('test_authorization', {})
        if (not entry.get('enabled') or auth.get('kind') != 'requester_authorized_test'
                or auth.get('agent_id') != config.get('agent_id')
                or auth.get('corporate_approval') != 'pending'):
            raise ValueError('service not authorized for this agent')
        end = datetime.datetime.strptime(auth['expires_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
        if end <= now:
            raise ValueError('service authorization expired')
        deadline = min(deadline, end)
        selected[name] = copy.deepcopy(entry)
    out = Path(out).resolve()
    out.mkdir(parents=True, mode=0o755 if os.name == 'nt' else 0o700, exist_ok=False)
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    expires = deadline.strftime('%Y-%m-%dT%H:%M:%SZ')
    token_path = out / 'client.token'
    token_path.write_text(token + '\n', encoding='ascii')
    token_path.chmod(0o600)
    patch = {'operation_mode': 'homologation', 'agent_id': config['agent_id'],
             'services': selected, 'client_auth': 'token', 'client_id': client_id,
             'client_token_file': 'client.token', 'proxy_port': 18080}
    for name, default in LIMITS.items():
        patch[name] = config.get(name, default)
    write_json(out / 'client-policy.json', {'format': 1, 'role': 'client',
                                           'patch': patch, 'token_sha256': digest})
    backup = config_path.with_name(config_path.name + '.before-client-' + uuid.uuid4().hex[:10])
    shutil.copy2(config_path, backup)
    backup.chmod(0o600)
    config.setdefault('token_clients', {})[client_id] = {'enabled': True,
        'token_sha256': digest, 'expires_utc': expires, 'services': list(services)}
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return {'client_id': client_id, 'expires_utc': expires, 'bundle': str(out),
            'backup': str(backup), 'action': 'restart gateway'}


def revoke(config_path, client_id):
    config_path = Path(config_path).resolve()
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    if client_id not in config.get('token_clients', {}):
        raise ValueError('unknown token client')
    backup = config_path.with_name(config_path.name + '.before-revocation-' + uuid.uuid4().hex[:10])
    shutil.copy2(config_path, backup)
    backup.chmod(0o600)
    config['token_clients'][client_id]['enabled'] = False
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return str(backup)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('prepare')
    create.add_argument('--out', default='bundles-homologation')
    create.add_argument('--client-id', default='intermediario-01')
    create.add_argument('--agent-id', default='windows-lab-01')
    create.add_argument('--hours', type=int, default=24)
    create.add_argument('--requested-by')
    create.add_argument('--services', nargs='+', choices=SERVICES, default=list(SERVICES))
    update = sub.add_parser('apply')
    update.add_argument('--config', required=True)
    update.add_argument('--policy', required=True)
    issue = sub.add_parser('issue-client')
    issue.add_argument('--config', required=True)
    issue.add_argument('--out', required=True)
    issue.add_argument('--client-id', required=True)
    issue.add_argument('--hours', type=int, default=24)
    issue.add_argument('--services', nargs='+', choices=SERVICES, default=list(SERVICES))
    disable = sub.add_parser('revoke')
    disable.add_argument('--config', required=True)
    disable.add_argument('--client-id', required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        print(json.dumps(prepare(args.out, args.client_id, args.agent_id, args.hours, args.requested_by, args.services)))
    elif args.command == 'apply':
        print(json.dumps({'backup': apply(args.config, args.policy), 'action': 'restart affected processes'}))
    elif args.command == 'issue-client':
        print(json.dumps(issue_client(args.config, args.out, args.client_id, args.hours, args.services)))
    else:
        print(json.dumps({'backup': revoke(args.config, args.client_id), 'action': 'restart gateway to revoke active sessions'}))
