"""Create role-specific HTTPS POC bundles from an existing disposable TLS set."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def prepare(cert_dir, out, host='secure-gateway.sicredi.space', agent_host='agent-gateway.sicredi.space'):
    cert_dir, out = Path(cert_dir).resolve(), Path(out).resolve()
    server = x509.load_pem_x509_certificate((cert_dir / 'gateway.crt').read_bytes())
    names = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    if host not in names or agent_host not in names:
        raise ValueError('Gateway TLS certificate must contain both configured DNS names in its SAN')
    out.mkdir(parents=True, exist_ok=False)
    for role in ('gateway', 'agent', 'client'):
        (out / role).mkdir(mode=0o755 if os.name == 'nt' else 0o700)
    for role in ('gateway', 'agent'):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        (out / role / 'signing.key').write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        peer = 'agent' if role == 'gateway' else 'gateway'
        (out / peer / (role + '-signing.pub')).write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    for role in ('gateway', 'agent', 'client'):
        shutil.copyfile(cert_dir / 'ca.crt', out / role / 'ca.crt')
    for role in ('gateway', 'client'):
        shutil.copyfile(cert_dir / (role + '.crt'), out / role / (role + '.crt'))
        shutil.copyfile(cert_dir / (role + '.key'), out / role / (role + '.key'))
    cert = x509.load_pem_x509_certificate((cert_dir / 'client.crt').read_bytes())
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    services = {
        'lab-status': {'enabled': True, 'local_port': 18080},
        'lab-catalog': {'enabled': True, 'local_port': 18082},
        'lab-echo': {'enabled': True, 'local_port': 18083},
        'gitlab': {'enabled': False, 'local_port': 18443, 'approval': {}},
        'artifactory': {'enabled': False, 'local_port': 18081, 'approval': {}},
    }
    common = {'gateway_id': 'gateway-poc-aws', 'agent_id': 'windows-lab-01',
              'services': services, 'max_bytes': 1048576, 'max_seconds': 60, 'tls_ca': 'ca.crt'}
    configs = {}
    configs['gateway'] = {**copy.deepcopy(common), 'bind': '127.0.0.1', 'agent_port': 9444,
        'client_port': 9443, 'tls_cert': 'gateway.crt', 'tls_key': 'gateway.key',
        'signing_key': 'signing.key', 'agent_public': 'agent-signing.pub',
        'replay_db': 'replay.sqlite', 'clients': {fingerprint: {'services': ['lab-status', 'lab-catalog', 'lab-echo']}}}
    configs['agent'] = {**copy.deepcopy(common), 'agent_url': f'https://{agent_host}',
        'signing_key': 'signing.key', 'gateway_public': 'gateway-signing.pub', 'corporate_ca': None}
    configs['client'] = {**copy.deepcopy(common), 'client_host': host, 'client_port': 443,
                          'tls_cert': 'client.crt', 'tls_key': 'client.key'}
    for role, config in configs.items():
        (out / role / 'config.json').write_text(json.dumps(config, indent=2), encoding='utf-8')
    for role in ('gateway', 'agent', 'client'):
        for path in (out / role).glob('*.key'):
            path.chmod(0o600)
    return out


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cert-dir', default='certs-https')
    parser.add_argument('--out', default='bundles-https')
    parser.add_argument('--host', default='secure-gateway.sicredi.space')
    parser.add_argument('--agent-host', default='agent-gateway.sicredi.space')
    args = parser.parse_args()
    prepare(args.cert_dir, args.out, args.host, args.agent_host)
    print('Role-specific bundles created. Transfer only each recipient role; never commit these files.')
