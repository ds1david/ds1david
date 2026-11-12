"""Disposable lab PKI; never use this CA for production."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess


def verify(out, hostname='localhost', openssl='openssl'):
    """Check public chains, TLS purposes, hostname and policy without reading keys."""
    out = Path(out)
    policy = json.loads((out / 'policy.json').read_text(encoding='utf-8'))
    for role in ('gateway', 'agent', 'client', 'unknown'):
        command = [openssl, 'verify', '-x509_strict', '-CAfile', 'ca.crt',
                   '-purpose', 'sslserver' if role == 'gateway' else 'sslclient']
        if role == 'gateway':
            command += ['-verify_hostname', hostname]
        result = subprocess.run([*command, role + '.crt'], cwd=out,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode:
            raise ValueError(f'Certificate validation failed for {role}: check CA, TLS purpose, validity and hostname')
        if role in ('agent', 'client'):
            der = ssl.PEM_cert_to_DER_cert((out / (role + '.crt')).read_text())
            identity = policy.get(hashlib.sha256(der).hexdigest(), {})
            if identity.get('role') != role:
                raise ValueError(f'Policy does not match {role} certificate')


def generate(out, hostname='localhost', openssl='openssl'):
    if not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', hostname):
        raise ValueError('DNS hostname required')
    out = Path(out)
    out.mkdir(mode=0o755 if os.name == 'nt' else 0o700, parents=True, exist_ok=False)

    def run(*args):
        subprocess.run([openssl, *args], cwd=out, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # An explicit issuance profile prevents an installed openssl.cnf from adding
    # server-only EKU restrictions to this disposable lab CA.
    (out / 'lab.cnf').write_text(
        '[req]\ndistinguished_name=dn\nprompt=no\n'
        '[dn]\nCN=Disposable POC\n'
        '[ca_extensions]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n'
        'keyUsage=critical,keyCertSign,cRLSign\n'
        'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n', encoding='ascii')
    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key',
        '-out', 'ca.crt', '-days', '7', '-subj', '/CN=Disposable POC CA',
        '-config', 'lab.cnf', '-extensions', 'ca_extensions', '-sha256')
    policy = {}
    for role in ('gateway', 'agent', 'client', 'unknown'):
        run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', role + '.key',
            '-out', role + '.csr', '-subj', '/CN=poc-' + role, '-config', 'lab.cnf', '-sha256')
        extension = 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
        extension += 'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n'
        extension += 'extendedKeyUsage=' + ('serverAuth' if role == 'gateway' else 'clientAuth') + '\n'
        if role == 'gateway':
            extension += 'subjectAltName=DNS:' + hostname + '\n'
        (out / 'extensions.cnf').write_text(extension, encoding='ascii')
        run('x509', '-req', '-in', role + '.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
            '-CAcreateserial', '-out', role + '.crt', '-days', '2', '-sha256',
            '-extfile', 'extensions.cnf')
        if role in ('agent', 'client'):
            der = ssl.PEM_cert_to_DER_cert((out / (role + '.crt')).read_text())
            policy[hashlib.sha256(der).hexdigest()] = {'role': role, 'services': ['lab-status', 'lab-catalog', 'lab-echo']}
    (out / 'policy.json').write_text(json.dumps(policy, indent=2), encoding='utf-8')
    (out / 'extensions.cnf').unlink()
    for path in out.glob('*.key'):
        path.chmod(0o600)
    verify(out, hostname, openssl)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', default='certs')
    parser.add_argument('--hostname', default='localhost')
    parser.add_argument('--openssl', default=shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe')
    parser.add_argument('--verify-only', action='store_true', help='Validate existing public certificates and policy; do not generate files')
    args = parser.parse_args()
    if args.verify_only:
        verify(args.out, args.hostname, args.openssl)
        print('Certificate chains, TLS purposes, gateway hostname and policy verified.')
    else:
        generate(args.out, args.hostname, args.openssl)
        print('Disposable certificates created and verified. Protect private keys; do not copy ca.key to endpoints.')
