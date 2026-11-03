"""Real local cryptography, mocked OCI export API; no network or credentials."""
import base64
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import export_software_key as demo


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.public = self.root / 'public.pem'
        self.private_path = self.root / 'private.pem'
        self.public.write_bytes(self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.private_path.write_bytes(self.private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b'test-password')))
        self.material = bytes(range(32))
        self.envelope = self.root / 'export.json'
        self.output = self.root / 'key.bin'
        self.crypto, self.management = MagicMock(), MagicMock()
        self.management.get_key.return_value = NS(data=NS(
            protection_mode='SOFTWARE', lifecycle_state='ENABLED',
            key_shape=NS(algorithm='AES', length=32), current_key_version='version-1'))
        encrypted = self.private.public_key().encrypt(self.material, demo.oaep())
        self.crypto.export_key.return_value = NS(data=NS(
            algorithm=demo.ALGORITHM, key_id='key-id', key_version_id='version-1',
            encrypted_key=base64.b64encode(encrypted).decode()))
        fake_oci = NS(key_management=NS(models=NS(ExportKeyDetails=lambda **kwargs: NS(**kwargs))))
        self.mock_sdk = patch.dict(sys.modules, {'oci': fake_oci})
        self.mock_sdk.start()
        self.addCleanup(self.mock_sdk.stop)

    def export(self):
        demo.export_key(self.crypto, self.management, 'key-id', self.public, self.envelope)

    def test_export_unwrap_and_local_check(self):
        self.export()
        details = self.crypto.export_key.call_args.args[0]
        self.assertEqual(details.key_version_id, 'version-1')
        self.assertEqual(details.algorithm, 'RSA_OAEP_SHA256')
        demo.unwrap_key(self.envelope, self.private_path, b'test-password', self.output)
        self.assertEqual(self.output.read_bytes(), self.material)
        demo.local_check(self.output)

    def test_hsm_rejected_before_export(self):
        self.management.get_key.return_value.data.protection_mode = 'HSM'
        with self.assertRaises(ValueError):
            self.export()
        self.crypto.export_key.assert_not_called()
        self.assertFalse(self.envelope.exists())

    def test_wrong_password_creates_no_key_file(self):
        self.export()
        with self.assertRaises(ValueError):
            demo.unwrap_key(self.envelope, self.private_path, b'wrong', self.output)
        self.assertFalse(self.output.exists())

    def test_tampered_blob_creates_no_key_file(self):
        self.export()
        data = json.loads(self.envelope.read_text())
        blob = bytearray(base64.b64decode(data['encrypted_key']))
        blob[0] ^= 1
        data['encrypted_key'] = base64.b64encode(blob).decode()
        self.envelope.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            demo.unwrap_key(self.envelope, self.private_path, b'test-password', self.output)
        self.assertFalse(self.output.exists())

    def test_existing_key_file_never_overwritten(self):
        self.export()
        self.output.write_bytes(b'original')
        with self.assertRaises(FileExistsError):
            demo.unwrap_key(self.envelope, self.private_path, b'test-password', self.output)
        self.assertEqual(self.output.read_bytes(), b'original')

    def test_generate_encrypted_wrapping_pair(self):
        private_path, public_path = self.root / 'new-private.pem', self.root / 'new-public.pem'
        demo.generate_wrapping_pair(private_path, public_path, b'new-password')
        private = serialization.load_pem_private_key(private_path.read_bytes(), b'new-password')
        public = serialization.load_pem_public_key(public_path.read_bytes())
        self.assertEqual(private.key_size, 3072)
        self.assertEqual(private.public_key().public_numbers(), public.public_numbers())


if __name__ == '__main__':
    unittest.main()
