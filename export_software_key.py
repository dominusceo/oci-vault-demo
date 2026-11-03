"""Export an OCI SOFTWARE AES-256 key using RSA-OAEP/SHA-256 wrapping."""
import argparse
import base64
import getpass
import json
import os
from pathlib import Path
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHM = "RSA_OAEP_SHA256"


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)


def generate_wrapping_pair(private_path, public_path, password):
    if not password:
        raise ValueError("La frase de paso no puede estar vacia")
    if Path(private_path).exists() or Path(public_path).exists():
        raise FileExistsError("Usa rutas nuevas para ambas llaves RSA")
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    write_new(private_path, private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password)))
    write_new(public_path, private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def export_key(crypto, management, key_id, public_path, output, version=None):
    import oci  # Offline commands do not need the OCI SDK or credentials.
    if Path(output).exists():
        raise FileExistsError("El archivo de salida ya existe")
    key = management.get_key(key_id).data
    if key.protection_mode != "SOFTWARE":
        raise ValueError("Solo se permite exportar SOFTWARE; HSM no es exportable")
    if key.key_shape.algorithm != "AES" or key.key_shape.length != 32:
        raise ValueError("Este ejemplo requiere una llave AES-256 (32 bytes)")
    if key.lifecycle_state != "ENABLED":
        raise ValueError("La llave debe estar ENABLED")
    public_pem = Path(public_path).read_bytes()
    public = serialization.load_pem_public_key(public_pem)
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size not in (2048, 3072, 4096):
        raise ValueError("La llave de envoltura debe ser RSA 2048, 3072 o 4096")
    # Pin the version to avoid ambiguity if rotation occurs during the demo.
    selected_version = version or key.current_key_version
    exported = crypto.export_key(oci.key_management.models.ExportKeyDetails(
        key_id=key_id, key_version_id=selected_version,
        algorithm=ALGORITHM, public_key=public_pem.decode("ascii"))).data
    if (exported.algorithm != ALGORITHM or exported.key_id != key_id or
            exported.key_version_id != selected_version):
        raise ValueError("La respuesta de exportacion no coincide con la solicitud")
    envelope = {"format": 1, "algorithm": exported.algorithm,
                "key_id": exported.key_id, "key_version_id": exported.key_version_id,
                "encrypted_key": exported.encrypted_key}
    write_new(output, json.dumps(envelope, indent=2).encode("utf-8"))
    print(f"Exportacion envuelta guardada. Version: {selected_version}")


def unwrap_key(source, private_path, password, output):
    if Path(output).exists():
        raise FileExistsError("El archivo de salida ya existe")
    envelope = json.loads(Path(source).read_text(encoding="utf-8"))
    if envelope["format"] != 1 or envelope["algorithm"] != ALGORITHM:
        raise ValueError("Formato o algoritmo no soportado por este ejemplo")
    private = serialization.load_pem_private_key(Path(private_path).read_bytes(), password)
    if not isinstance(private, rsa.RSAPrivateKey):
        raise ValueError("Se requiere la llave RSA privada de envoltura")
    material = private.decrypt(base64.b64decode(envelope["encrypted_key"], validate=True), oaep())
    if len(material) != 32:
        raise ValueError("El material exportado no es una llave AES-256 de 32 bytes")
    write_new(output, material)
    print("Llave AES-256 desenvuelta: 32 bytes binarios; no se imprime el material.")
    del material, private


def local_check(key_path):
    material = Path(key_path).read_bytes()
    if len(material) != 32:
        raise ValueError("Se esperan 32 bytes binarios AES-256")
    cipher = AESGCM(material)
    nonce = os.urandom(12)
    message = b"OCI SOFTWARE export demo"
    ciphertext = cipher.encrypt(nonce, message, b"local-demo")
    if cipher.decrypt(nonce, ciphertext, b"local-demo") != message:
        raise ValueError("La verificacion local fallo")
    print("OK: cifrado y descifrado AES-256-GCM local, sin llamadas a OCI.")
    del material, cipher


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate-wrapping")
    gen.add_argument("--private", required=True)
    gen.add_argument("--public", required=True)
    exp = sub.add_parser("export")
    exp.add_argument("--config", default="config.json")
    exp.add_argument("--public", required=True)
    exp.add_argument("--output", required=True)
    exp.add_argument("--key-version-id")
    unwrap = sub.add_parser("unwrap")
    unwrap.add_argument("source")
    unwrap.add_argument("--private", required=True)
    unwrap.add_argument("--output", required=True)
    check = sub.add_parser("local-check")
    check.add_argument("--key", required=True)
    args = parser.parse_args()
    if args.command == "generate-wrapping":
        password = getpass.getpass("Frase de paso para proteger la RSA privada: ")
        if password != getpass.getpass("Repite la frase de paso: "):
            raise ValueError("Las frases no coinciden")
        generate_wrapping_pair(args.private, args.public, password.encode("utf-8"))
        print("Par RSA-3072 creado; privada PKCS8 cifrada con frase de paso.")
    elif args.command == "export":
        import oci
        settings = json.loads(Path(args.config).read_text(encoding="utf-8"))
        kwargs = {}
        if settings.get("auth", "config") == "instance_principal":
            kwargs["signer"] = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config = {"region": settings["region"]}
        else:
            config = oci.config.from_file(profile_name=settings.get("profile", "DEFAULT"))
        crypto = oci.key_management.KmsCryptoClient(config, settings["crypto_endpoint"], **kwargs)
        management = oci.key_management.KmsManagementClient(config, settings["management_endpoint"], **kwargs)
        export_key(crypto, management, settings["keys"]["software"], args.public,
                   args.output, args.key_version_id)
    elif args.command == "unwrap":
        password = getpass.getpass("Frase de paso de la RSA privada: ").encode("utf-8")
        unwrap_key(args.source, args.private, password, args.output)
    else:
        local_check(args.key)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Avoid printing SDK response payloads or secret material.
        if hasattr(error, "status"):
            print(f"OCI: status={error.status}, code={error.code}, "
                  f"request_id={getattr(error, 'request_id', '')}", file=sys.stderr)
        else:
            print(f"Error ({type(error).__name__}): {error}", file=sys.stderr)
        sys.exit(1)
