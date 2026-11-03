"""Small-file envelope encryption and in-memory SSH credentials with OCI Vault."""
import argparse
import base64
import getpass
import io
import json
import os
from pathlib import Path
import sys

import oci
import paramiko
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

CONTEXT = {"application": "oci-vault-python-demo", "format": "1"}
AAD = b"oci-vault-python-demo:1"
MAX_FILE = 16 * 1024 * 1024  # intentionally a small-file lab, not a streaming format


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def write_new(path, data):
    # Never replace the source or an existing output. Linux output mode is 600;
    # keep the project directory private (mode 700).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def encrypt_file(crypto, key_id, source, output):
    if Path(source).stat().st_size > MAX_FILE:
        raise ValueError("Lab file limit is 16 MiB")
    plaintext = Path(source).read_bytes()
    generated = crypto.generate_data_encryption_key(
        oci.key_management.models.GenerateKeyDetails(
            key_id=key_id, include_plaintext_key=True,
            key_shape=oci.key_management.models.KeyShape(algorithm="AES", length=32),
            associated_data=CONTEXT)).data
    dek = unb64(generated.plaintext)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, AAD)
    envelope = {"format": 1, "key_id": key_id,
                "wrapped_dek": generated.ciphertext,
                "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
    write_new(output, json.dumps(envelope, indent=2).encode())
    # CPython cannot guarantee zeroization of immutable key/plaintext copies.
    del dek, generated, plaintext
    print("Encrypted; saved ciphertext and wrapped DEK only.")


def decrypt_file(crypto, allowed_keys, source, output):
    if Path(source).stat().st_size > MAX_FILE * 2:
        raise ValueError("Envelope exceeds lab limit")
    envelope = json.loads(Path(source).read_text())
    if envelope["format"] != 1 or envelope["key_id"] not in allowed_keys:
        raise ValueError("Unsupported format or key not allowed by config")
    response = crypto.decrypt(oci.key_management.models.DecryptDataDetails(
        key_id=envelope["key_id"], ciphertext=envelope["wrapped_dek"],
        associated_data=CONTEXT)).data
    dek = unb64(response.plaintext)
    plaintext = AESGCM(dek).decrypt(unb64(envelope["nonce"]),
                                  unb64(envelope["ciphertext"]), AAD)
    write_new(output, plaintext)  # write only after authentication succeeds
    del dek, response, plaintext
    print("Decrypted; authentication tag verified.")


def ssh_connect(secrets, secret_id, host, user, known_hosts, port, passphrase):
    bundle = secrets.get_secret_bundle(secret_id, stage="CURRENT").data
    private_text = unb64(bundle.secret_bundle_content.content).decode("utf-8")
    # Accept the lab's Ed25519 key or an existing RSA/EC PEM key.
    key = None
    for key_type in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            key = key_type.from_private_key(io.StringIO(private_text), password=passphrase)
            break
        except paramiko.PasswordRequiredException:
            raise ValueError("Encrypted SSH key: rerun with --prompt-passphrase") from None
        except (paramiko.SSHException, ValueError):
            continue
    if key is None:
        raise ValueError("Unsupported private key or incorrect passphrase")
    del private_text, bundle
    with paramiko.SSHClient() as client:
        client.load_host_keys(known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(hostname=host, port=port, username=user, pkey=key,
                       allow_agent=False, look_for_keys=False,
                       timeout=15, auth_timeout=15, banner_timeout=15)
        _, stdout, stderr = client.exec_command("whoami && hostname", timeout=20)
        print(stdout.read().decode(), end="")
        error = stderr.read().decode()
        if error:
            print(error, file=sys.stderr, end="")
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError("Remote demonstration command failed")


def clients(settings):
    kwargs = {}
    if settings.get("auth", "config") == "instance_principal":
        kwargs["signer"] = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        config = {"region": settings["region"]}
    else:
        config = oci.config.from_file(profile_name=settings.get("profile", "DEFAULT"))
    return (
        oci.key_management.KmsCryptoClient(config, settings["crypto_endpoint"], **kwargs),
        oci.key_management.KmsManagementClient(config, settings["management_endpoint"], **kwargs),
        oci.secrets.SecretsClient(config, **kwargs))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.json")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("inspect", help="Show authoritative key protection metadata")
    enc = sub.add_parser("encrypt")
    enc.add_argument("--mode", choices=["hsm", "software"], required=True)
    enc.add_argument("source")
    enc.add_argument("output")
    dec = sub.add_parser("decrypt")
    dec.add_argument("source")
    dec.add_argument("output")
    ssh = sub.add_parser("ssh")
    ssh.add_argument("--host", required=True)
    ssh.add_argument("--user", default="opc")
    ssh.add_argument("--port", type=int, default=22)
    ssh.add_argument("--known-hosts", required=True)
    ssh.add_argument("--prompt-passphrase", action="store_true")
    args = parser.parse_args()
    settings = json.loads(Path(args.config).read_text())
    crypto, management, secrets = clients(settings)
    if args.command == "inspect":
        for label, key_id in settings["keys"].items():
            key = management.get_key(key_id).data
            print(f"{label}: {key.display_name}, protection={key.protection_mode}, "
                  f"algorithm={key.key_shape.algorithm}, bytes={key.key_shape.length}, "
                  f"state={key.lifecycle_state}, version={key.current_key_version}")
    elif args.command == "encrypt":
        key_id = settings["keys"][args.mode]
        metadata = management.get_key(key_id).data
        if (metadata.protection_mode != args.mode.upper() or
                metadata.key_shape.algorithm != "AES" or metadata.key_shape.length != 32):
            raise ValueError("Configured key must be AES-256 and match the selected mode")
        encrypt_file(crypto, key_id, args.source, args.output)
    elif args.command == "decrypt":
        decrypt_file(crypto, set(settings["keys"].values()), args.source, args.output)
    else:
        passphrase = getpass.getpass("SSH private-key passphrase: ") if args.prompt_passphrase else None
        ssh_connect(secrets, settings["ssh_secret_id"], args.host, args.user,
                    args.known_hosts, args.port, passphrase)


if __name__ == "__main__":
    try:
        main()
    except oci.exceptions.ServiceError as error:
        print(f"OCI request failed: status={error.status}, code={error.code}, "
              f"request_id={error.request_id}", file=sys.stderr)
        sys.exit(1)
    except InvalidTag:
        print("Authentication failed: file was altered or key/nonce is wrong.", file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, KeyError, RuntimeError, paramiko.SSHException) as error:
        print(f"Demo failed: {error}", file=sys.stderr)
        sys.exit(1)
