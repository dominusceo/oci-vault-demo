"""Offline behavior tests; fake KMS is not an OCI or HSM emulator."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import MagicMock, patch

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import paramiko
import vault_demo as demo


class FakeKMS:
    def __init__(self):
        self.keys = {mode: AESGCM.generate_key(256) for mode in ('hsm', 'software')}

    def generate_data_encryption_key(self, details):
        dek = AESGCM.generate_key(256)
        nonce = b'\x01' * 12  # Fake wrapping only; fresh DEK per test call
        wrapped = AESGCM(self.keys[details.key_id]).encrypt(nonce, dek, b'fake-kms')
        return NS(data=NS(plaintext=demo.b64(dek), ciphertext=demo.b64(nonce + wrapped)))

    def decrypt(self, details):
        wrapped = demo.unb64(details.ciphertext)
        dek = AESGCM(self.keys[details.key_id]).decrypt(wrapped[:12], wrapped[12:], b'fake-kms')
        return NS(data=NS(plaintext=demo.b64(dek)))


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'input'
        self.source.write_bytes(bytes(range(256)) * 100)
        self.kms = FakeKMS()

    def encrypt(self, mode='hsm'):
        output = self.root / (mode + '.json')
        demo.encrypt_file(self.kms, mode, self.source, output)
        return output

    def test_both_modes_roundtrip(self):
        for mode in ('hsm', 'software'):
            with self.subTest(mode=mode):
                encrypted = self.encrypt(mode)
                restored = self.root / (mode + '.restored')
                demo.decrypt_file(self.kms, set(self.kms.keys), encrypted, restored)
                self.assertEqual(restored.read_bytes(), self.source.read_bytes())

    def test_tampering_creates_no_plaintext(self):
        encrypted = self.encrypt()
        envelope = json.loads(encrypted.read_text())
        ciphertext = bytearray(demo.unb64(envelope['ciphertext']))
        ciphertext[0] ^= 1
        envelope['ciphertext'] = demo.b64(ciphertext)
        encrypted.write_text(json.dumps(envelope))
        output = self.root / 'restored'
        with self.assertRaises(InvalidTag):
            demo.decrypt_file(self.kms, set(self.kms.keys), encrypted, output)
        self.assertFalse(output.exists())

    def test_never_overwrites_source(self):
        original = self.source.read_bytes()
        with self.assertRaises(FileExistsError):
            demo.encrypt_file(self.kms, 'hsm', self.source, self.source)
        self.assertEqual(original, self.source.read_bytes())

    def test_unknown_key_rejected(self):
        with self.assertRaises(ValueError):
            demo.decrypt_file(self.kms, {'unrelated-key'}, self.encrypt(), self.root / 'out')

    def test_ssh_uses_secret_and_checks_host(self):
        key = paramiko.RSAKey.generate(2048)
        private = io.StringIO()
        key.write_private_key(private)
        secrets = MagicMock()
        secrets.get_secret_bundle.return_value = NS(data=NS(
            secret_bundle_content=NS(content=demo.b64(private.getvalue().encode()))))
        with patch.object(demo.paramiko, 'SSHClient') as factory:
            client = factory.return_value.__enter__.return_value
            stdout, stderr = MagicMock(), MagicMock()
            stdout.read.return_value = b'opc\nlab-host\n'
            stderr.read.return_value = b''
            stdout.channel.recv_exit_status.return_value = 0
            client.exec_command.return_value = (None, stdout, stderr)
            with contextlib.redirect_stdout(io.StringIO()):
                demo.ssh_connect(secrets, 'secret-id', 'host', 'opc', 'known_hosts', 22, None)
            secrets.get_secret_bundle.assert_called_once_with('secret-id', stage='CURRENT')
            client.load_host_keys.assert_called_once_with('known_hosts')
            self.assertIsInstance(client.set_missing_host_key_policy.call_args.args[0],
                                  paramiko.RejectPolicy)
            self.assertFalse(client.connect.call_args.kwargs['allow_agent'])
            self.assertFalse(client.connect.call_args.kwargs['look_for_keys'])
            self.assertEqual(client.connect.call_args.kwargs['pkey'].get_fingerprint(),
                             key.get_fingerprint())


if __name__ == '__main__':
    unittest.main()
