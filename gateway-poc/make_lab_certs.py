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


def generate(out, hostname='localhost', openssl='openssl'):
    if not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', hostname):
        raise ValueError('DNS hostname required')
    out = Path(out)
    out.mkdir(mode=0o755 if os.name == 'nt' else 0o700, parents=True, exist_ok=False)

    def run(*args):
        subprocess.run([openssl, *args], cwd=out, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key',
        '-out', 'ca.crt', '-days', '7', '-subj', '/CN=Disposable POC CA',
        '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    policy = {}
    for role in ('gateway', 'agent', 'client', 'unknown'):
        run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', role + '.key',
            '-out', role + '.csr', '-subj', '/CN=poc-' + role)
        extension = 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', default='certs')
    parser.add_argument('--hostname', default='localhost')
    parser.add_argument('--openssl', default=shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe')
    args = parser.parse_args()
    generate(args.out, args.hostname, args.openssl)
    print('Disposable certificates created. Protect private keys; do not copy ca.key to endpoints.')
