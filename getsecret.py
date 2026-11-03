"""Retrieve a CURRENT secret bundle from OCI Compute using Instance Principal."""
import argparse
import base64
import json
import sys


def retrieve_secret(client, secret_id):
    bundle = client.get_secret_bundle(secret_id=secret_id, stage="CURRENT").data
    content = bundle.secret_bundle_content
    if content.content_type != "BASE64":
        raise ValueError("El ejemplo requiere contenido BASE64 en el secret bundle")
    return bundle, base64.b64decode(content.content, validate=True)


def create_client(region):
    import oci
    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    return oci.secrets.SecretsClient({"region": region}, signer=signer)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-id", required=True, help="OCID del secreto, no de la llave")
    parser.add_argument("--region", required=True, help="Region del secreto, ej. us-ashburn-1")
    parser.add_argument("--show", action="store_true", help="Mostrar texto: usar solo con secreto ficticio")
    args = parser.parse_args(argv)
    client = create_client(args.region)
    bundle, value = retrieve_secret(client, args.secret_id)
    print(json.dumps({"auth": "instance_principal", "secret_id": args.secret_id,
                      "version_number": bundle.version_number, "stage": "CURRENT",
                      "bytes": len(value), "retrieved": True}, ensure_ascii=False))
    if args.show:
        # JSON escaping prevents secret text from emitting terminal control sequences.
        print(json.dumps({"demo_secret_text": value.decode("utf-8")}, ensure_ascii=False))
    del value, bundle


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        if hasattr(error, "status"):
            print(f"OCI: status={error.status}, code={error.code}, "
                  f"request_id={getattr(error, 'request_id', '')}", file=sys.stderr)
        else:
            print(f"Error: {type(error).__name__}. Revisa dependencias, metadata, red y argumentos.",
                  file=sys.stderr)
        sys.exit(1)
