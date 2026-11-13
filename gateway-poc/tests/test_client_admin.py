import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import homologation


class ClientAdministration(unittest.TestCase):
    def test_issue_preserves_agent_policy_and_caps_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            homologation.prepare(root / 'initial', hours=1)
            config = json.loads((root / 'initial/gateway-policy.json').read_text())['patch']
            config['tls_cert'] = '/existing/server.crt'
            path = root / 'config.json'
            homologation.write_json(path, config)
            result = homologation.issue_client(path, root / 'new', 'cliente-02', services=['gitlab'])
            updated = json.loads(path.read_text())
            self.assertEqual(updated['services'], config['services'])
            self.assertEqual(updated['tls_cert'], config['tls_cert'])
            self.assertEqual(updated['token_clients']['intermediario-01'], config['token_clients']['intermediario-01'])
            client = updated['token_clients']['cliente-02']
            self.assertEqual(client['expires_utc'], config['services']['gitlab']['test_authorization']['expires_utc'])
            self.assertEqual(client['services'], ['gitlab'])
            token = (root / 'new/client.token').read_text().strip()
            self.assertEqual(client['token_sha256'], hashlib.sha256(token.encode()).hexdigest())
            self.assertNotIn(token, path.read_text())
            self.assertNotIn(token, json.dumps(result))
            self.assertFalse((root / 'new/agent-policy.json').exists())
            with self.assertRaises(ValueError):
                homologation.issue_client(path, root / 'duplicate', 'cliente-02')

    def test_expired_service_cannot_issue_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            homologation.prepare(root / 'initial')
            config = json.loads((root / 'initial/gateway-policy.json').read_text())['patch']
            config['services']['gitlab']['test_authorization']['expires_utc'] = '2000-01-01T00:00:00Z'
            path = root / 'config.json'
            homologation.write_json(path, config)
            with self.assertRaises(ValueError):
                homologation.issue_client(path, root / 'new', 'cliente-02', services=['gitlab'])
            self.assertFalse((root / 'new').exists())
            self.assertEqual(json.loads(path.read_text()), config)
