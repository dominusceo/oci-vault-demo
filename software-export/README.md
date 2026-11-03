# Exportar una llave SOFTWARE de OCI Vault con Python

Este laboratorio amplía la [demo principal](../README.md). Exportarás una **versión de la llave maestra AES-256 SOFTWARE**, cifrada bajo una RSA pública tuya. Después la desenvolverás localmente y comprobarás que sirve para cifrar y descifrar sin conexión con OCI.

El ejemplo usa `RSA_OAEP_SHA256` con OAEP SHA-256 y MGF1 SHA-256. Una llave AES-256 de 32 bytes cabe en esta envoltura RSA directa. No usa el mecanismo híbrido `RSA_OAEP_AES_SHA256`, que requiere separar y desenvolver una AES temporal. La RSA de envoltura es independiente de las llaves SSH y de la API signing key de OCI.

## 1. Preparar Python y el directorio

Abre una terminal Bash de Linux en la carpeta `oci-vault-demo`, **un nivel arriba de este README**. Todos los comandos siguientes se ejecutan desde esa carpeta.

Si todavía no preparaste la demo:

```bash
umask 077
chmod 700 .
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp -n config.instance-principal.example.json config.json
chmod 600 config.json
```

Si `config.json` ya existe, consérvalo y edítalo; no lo reemplaces. Requiere Python 3.10+. No necesitas ejecutar OpenSSL por separado para estos comandos: la biblioteca `cryptography` realiza las operaciones locales.

## 2. Preparar la llave SOFTWARE y la autenticación

En OCI, usa un compartimento de laboratorio y un Vault regular. Crea una llave con:

| Campo | Valor |
|---|---|
| Nombre | `lab-software` |
| Algoritmo | AES |
| Longitud | 256 bits / 32 bytes |
| Protection mode | SOFTWARE |
| Estado antes de exportar | ENABLED |

No se puede convertir una llave HSM existente a SOFTWARE. El ejemplo rechaza HSM antes de solicitar la exportación. Dedicated KMS no sirve para esta comparación porque admite HSM únicamente.

Ejecuta en la instancia Linux OCI del escenario [Instance Principal](../instance-principal/README.md). No necesitas ejecutar `oci setup config` ni instalar una API signing key de usuario. Edita `config.json` con los endpoints reales del Vault y la OCID de la llave:

```json
{
  "auth": "instance_principal",
  "region": "us-ashburn-1",
  "management_endpoint": "https://REEMPLAZAR-management.kms.us-ashburn-1.oraclecloud.com",
  "crypto_endpoint": "https://REEMPLAZAR-crypto.kms.us-ashburn-1.oraclecloud.com",
  "keys": {
    "software": "ocid1.key.REEMPLAZAR"
  }
}
```

Este script solo necesita `keys.software`; puedes conservar también el resto de la configuración de la demo principal. Usa la región de los recursos y las políticas de Dynamic Group del escenario. Si ejecutas desde otro Linux fuera de OCI, puedes usar opcionalmente `auth: "config"` y un perfil OCI de usuario válido, como se explica en la guía principal.

## 3. Dar permiso de lectura y exportación

Un administrador puede asignar estos permisos mínimos al Dynamic Group de la instancia que ejecutará **este script**, sustituyendo los nombres y la OCID:

```text
Allow dynamic-group VaultLabRunner to read keys in compartment VaultLab where target.key.id = '<SOFTWARE_KEY_OCID>'
Allow dynamic-group VaultLabRunner to {KEY_EXPORT} in compartment VaultLab where target.key.id = '<SOFTWARE_KEY_OCID>'
```

`read keys` permite consultar y fijar la versión; `KEY_EXPORT` permite exportarla. Para identity domains, usa la sintaxis de dominio/Dynamic Group que corresponda a tu tenancy. Espera la propagación de IAM. En el modo opcional con perfil de usuario, reemplaza el principal por el grupo IAM del usuario autorizado.

**Si ya tienes `use keys`, ese permiso incluye `KEY_EXPORT`.** No necesitas agregarlo otra vez. Para una identidad que solo deba cifrar/descifrar sin exportar, usa permisos explícitos como `KEY_READ`, `KEY_ENCRYPT` y `KEY_DECRYPT`, en vez de conceder `use keys`. Las políticas son acumulativas: agregar una política más estrecha no quita permisos otorgados por otras políticas.

## 4. Generar la RSA de envoltura

```bash
.venv/bin/python export_software_key.py generate-wrapping --private wrapping-private.pem --public wrapping-public.pem
```

Introduce y confirma una frase de paso. No se pasa por argumentos ni se imprime. Se crean:

| Archivo | Contenido | Uso |
|---|---|---|
| `wrapping-private.pem` | RSA-3072 privada PKCS8, cifrada con frase de paso | Desenvolver localmente; no se envía a OCI |
| `wrapping-public.pem` | RSA pública PEM | Se envía a OCI para envolver la AES |

Salida esperada: `Par RSA-3072 creado; privada PKCS8 cifrada con frase de paso.` Los archivos existentes no se sobrescriben; para repetir usa nombres nuevos en todos los pasos.

## 5. Exportar la versión SOFTWARE desde OCI

```bash
.venv/bin/python export_software_key.py export --config config.json --public wrapping-public.pem --output software-export.json
```

El script consulta el estado, tipo y modo de protección de la llave. Fija `current_key_version` y llama a `KmsCryptoClient.export_key()` con `ExportKeyDetails`. Solo envía la RSA **pública**. OCI devuelve el material exportado cifrado bajo esa RSA y codificado en Base64; se guarda en `software-export.json`.

Salida esperada: `Exportacion envuelta guardada. Version: <OCID_VERSION>`.

Para exportar una versión específica, usa la OCID real de una versión de esa misma llave:

```bash
.venv/bin/python export_software_key.py export --config config.json --public wrapping-public.pem --key-version-id '<OCID_VERSION>' --output software-export-version.json
```

El JSON contiene `algorithm`, `key_id`, `key_version_id` y `encrypted_key`, además del formato de la demo. **Base64 no aporta protección**; la protección del material exportado es RSA-OAEP. OCI no elimina ni modifica la llave original al exportarla.

## 6. Desenvolver la AES localmente

```bash
.venv/bin/python export_software_key.py unwrap software-export.json --private wrapping-private.pem --output software-key.bin
```

Introduce la misma frase de paso de la RSA privada. No requiere credenciales ni conectividad OCI. Python decodifica Base64, descifra con RSA-OAEP SHA-256 y comprueba que el resultado tenga 32 bytes.

Salida esperada: `Llave AES-256 desenvuelta: 32 bytes binarios; no se imprime el material.`

Comprueba solo el tamaño, sin mostrar el contenido:

```bash
wc -c < software-key.bin
```

Resultado esperado: `32`. `software-key.bin` es la **llave maestra AES en claro**, en formato binario; no es PEM, texto hexadecimal ni una DEK. Este paso escribe material sensible en disco de manera explícita para demostrar la exportación. Guarda los archivos en un directorio Linux privado con modo 700 y usa únicamente una llave de laboratorio. Ejecuta `umask 077`; el script crea archivos con modo 600. Comprueba los permisos con `stat -c "%a %n" software-key.bin wrapping-private.pem`.

## 7. Comprobar el uso local sin OCI

```bash
.venv/bin/python export_software_key.py local-check --key software-key.bin
```

Salida esperada: `OK: cifrado y descifrado AES-256-GCM local, sin llamadas a OCI.`

Este comando cifra un mensaje de prueba con nonce aleatorio y verifica su descifrado en memoria. Demuestra que el material recuperado es utilizable como AES-256. No compara el formato de ciphertext de OCI con AES-GCM local, ni descifra los archivos de envelope encryption de la demo principal: esos archivos usan DEKs independientes envueltas por KMS.

Para explicar la diferencia con HSM, muestra ambos modos con `vault_demo.py inspect` usando la configuración completa de la demo principal. HSM no permite exportar su material privado/maestro mediante `ExportKey`; la posibilidad de descargar una llave pública asimétrica es un caso diferente.

## 8. Mostrar qué ocurre después de exportar

Opcionalmente, deshabilita **solo la llave SOFTWARE de laboratorio** en OCI. Espera DISABLED y vuelve a ejecutar `local-check`: seguirá funcionando porque ya posees una copia local. Una nueva exportación mediante el script fallará por estado. Reactiva la llave al terminar.

Esta es una diferencia operativa esencial: deshabilitar, rotar o eliminar la llave en OCI no revoca copias exportadas. IAM y Audit controlan/registran la exportación desde OCI; las operaciones hechas posteriormente en tu equipo no pasan por KMS. Una rotación crea una versión nueva, pero el archivo exportado sigue siendo la versión anterior.

## 9. Errores esperables

| Error o situación | Acción |
|---|---|
| `ModuleNotFoundError: oci` | Instala `requirements.txt` con el mismo Python de `.venv` |
| OCI 404 / `NotAuthorizedOrNotFound` | Revisa OCID, región, endpoints, perfil y políticas |
| Rechazo de SOFTWARE/HSM | Usa una llave SOFTWARE AES-256; no cambies etiquetas para simular el modo |
| Estado distinto de ENABLED | Espera la transición o habilita la llave de laboratorio |
| Frase incorrecta, RSA distinta o blob alterado | La desenvoltura debe fallar; usa el par y archivo correctos |
| Archivo de salida existente | Usa un nombre nuevo; el script no lo sobrescribe |

El JSON exportado es un formato de demostración, no un contenedor firmado. Mantén su procedencia confiable; la validación de longitud y la prueba AES local no autentican por sí solas que provenga de una llave OCI determinada.

## 10. Validar y cerrar la demostración

Pruebas locales sin credenciales OCI:

```bash
.venv/bin/python -m unittest -v test_export_software_key.py
```

Las pruebas usan criptografía RSA-OAEP y AES-GCM real, con la llamada OCI simulada. No prueban IAM ni el servicio real. La aceptación contra tu tenancy consiste en completar los pasos 5, 6 y 7 con una llave de laboratorio.

Al cerrar, retira los permisos temporales y elimina las copias locales según tu política de retención. No incluyas la llave binaria ni la RSA privada en repositorios o paquetes compartidos. Están excluidas por `.gitignore` con los nombres de este tutorial, pero nombres alternativos también requieren cuidado. El script no garantiza borrado de memoria y la eliminación normal de archivos no garantiza borrado físico en SSD o backups. Programa la eliminación de los recursos OCI de laboratorio que ya no necesites; no elimines versiones necesarias para descifrar datos retenidos.

## Referencias oficiales

- [API Python ExportKeyDetails: algoritmos y parámetros](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/key_management/models/oci.key_management.models.ExportKeyDetails.html)
- [KmsCryptoClient.export_key](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/key_management/client/oci.key_management.KmsCryptoClient.html)
- [Exportación CLI: RSA pública admitida y restricciones HSM](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/kms/crypto/key/export.html)
- [IAM: KEY_EXPORT y permisos de use keys](https://docs.oracle.com/en-us/iaas/Content/Identity/policyreference/keypolicyreference.htm)

Referencias verificadas el 2 de noviembre de 2026. Se usa la definición del SDK/API para seleccionar explícitamente RSA-OAEP directo; algunos ejemplos narrativos de exportación incluyen el algoritmo híbrido bajo títulos que pueden resultar confusos.
