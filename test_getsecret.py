"""Offline tests: no credentials or OCI requests."""
import base64
import contextlib
import io
import json
import sys
from types import SimpleNamespace as NS
import unittest
from unittest.mock import MagicMock, patch
import getsecret


class SecretTests(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()
        self.client.get_secret_bundle.return_value = NS(data=NS(
            version_number=1, secret_bundle_content=NS(
                content_type='BASE64', content=base64.b64encode(b'demo-only').decode())))

    def test_retrieves_current_and_decodes(self):
        _, value = getsecret.retrieve_secret(self.client, 'secret-id')
        self.assertEqual(value, b'demo-only')
        self.client.get_secret_bundle.assert_called_once_with(secret_id='secret-id', stage='CURRENT')

    def test_default_output_does_not_disclose_secret(self):
        out = io.StringIO()
        with patch.object(getsecret, 'create_client', return_value=self.client), contextlib.redirect_stdout(out):
            getsecret.main(['--region', 'us-ashburn-1', '--secret-id', 'secret-id'])
        self.assertNotIn('demo-only', out.getvalue())
        self.assertEqual(json.loads(out.getvalue())['bytes'], 9)

    def test_show_explicitly_displays_demo_text(self):
        out = io.StringIO()
        with patch.object(getsecret, 'create_client', return_value=self.client), contextlib.redirect_stdout(out):
            getsecret.main(['--region', 'us-ashburn-1', '--secret-id', 'secret-id', '--show'])
        self.assertEqual(json.loads(out.getvalue().splitlines()[1])['demo_secret_text'], 'demo-only')

    def test_client_uses_instance_signer_without_profile(self):
        sdk = MagicMock()
        with patch.dict(sys.modules, {'oci': sdk}):
            getsecret.create_client('us-ashburn-1')
        sdk.auth.signers.InstancePrincipalsSecurityTokenSigner.assert_called_once_with()
        sdk.secrets.SecretsClient.assert_called_once_with(
            {'region': 'us-ashburn-1'}, signer=sdk.auth.signers.InstancePrincipalsSecurityTokenSigner.return_value)
        sdk.config.from_file.assert_not_called()


if __name__ == '__main__':
    unittest.main()
