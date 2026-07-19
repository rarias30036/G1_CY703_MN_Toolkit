# auditoria basica de ssl/tls
#
# se conecta al puerto seguro del sitio para revisar el certificado (validez y
# vencimiento) y para detectar si el servidor todavia acepta versiones
# obsoletas del protocolo tls.

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from common import findings as F
from common import logger

# versiones de tls que vamos a probar contra el servidor
VERSIONES = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

# fragmentos que identifican suites de cifrado debiles u obsoletas
CIFRADORES_DEBILES = ["RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "ANON"]


def _host_puerto(url):
    # extrae el host y el puerto de la url
    p = urlparse(url if "://" in url else "https://" + url)
    return p.hostname, (p.port or 443)


def obtener_certificado(host, puerto, timeout=10):
    # intenta obtener el certificado validando la cadena.
    # devuelve (certificado, version_tls, cifrador, error) donde error puede ser
    # el texto de la falla de verificacion o "sin_conexion". el cifrador es la
    # tupla (nombre, protocolo, bits) negociada o none.
    contexto = ssl.create_default_context()
    try:
        with socket.create_connection((host, puerto), timeout=timeout) as sock:
            with contexto.wrap_socket(sock, server_hostname=host) as seguro:
                return seguro.getpeercert(), seguro.version(), seguro.cipher(), None
    except ssl.SSLCertVerificationError as error:
        return None, None, None, str(error)
    except (socket.timeout, socket.gaierror, ConnectionError, OSError):
        return None, None, None, "sin_conexion"


def probar_version(host, puerto, version, timeout=8):
    # intenta un handshake forzando una version especifica de tls.
    # devuelve true si el servidor la acepta.
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE
    try:
        contexto.minimum_version = version
        contexto.maximum_version = version
    except (ValueError, AttributeError):
        return False
    try:
        with socket.create_connection((host, puerto), timeout=timeout) as sock:
            with contexto.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def analizar(url):
    # revisa el certificado y los protocolos, devuelve una lista de hallazgos
    hallazgos = []

    host, puerto = _host_puerto(url)
    if not host:
        return hallazgos

    # si el sitio se sirve por http no hay cifrado que auditar
    if url.startswith("http://"):
        hallazgos.append(F.crear_hallazgo(
            "web",
            "el sitio se sirve sobre http sin cifrado",
            "ALTA",
            "la url usa http sin tls, la informacion viaja en texto plano y puede ser interceptada",
            "migrar el sitio a https con un certificado valido (por ejemplo let's encrypt)",
            identificador="WEB-SSL",
        ))
        return hallazgos

    print("  [i] revisando certificado y protocolos tls...")
    cert, version, cifrador, error = obtener_certificado(host, puerto)

    if error == "sin_conexion":
        print("  [-] no se pudo establecer conexion tls con %s" % host)
        logger.registrar("ADVERTENCIA", "fallo la conexion tls con %s" % host)
        return hallazgos

    if error:
        hallazgos.append(F.crear_hallazgo(
            "web",
            "certificado ssl invalido o no confiable",
            "ALTA",
            "la verificacion del certificado fallo: %s" % error,
            "renovar el certificado con una autoridad certificadora confiable",
            identificador="WEB-SSL",
            evidencia={"error": error},
        ))

    # revision del vencimiento del certificado
    if cert and "notAfter" in cert:
        try:
            vence = datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            dias = (vence - datetime.now(timezone.utc)).days
            if dias < 0:
                hallazgos.append(F.crear_hallazgo(
                    "web",
                    "certificado ssl expirado",
                    "ALTA",
                    "el certificado vencio hace %d dias" % abs(dias),
                    "renovar el certificado de inmediato",
                    identificador="WEB-SSL",
                ))
            elif dias < 30:
                hallazgos.append(F.crear_hallazgo(
                    "web",
                    "certificado ssl proximo a expirar",
                    "MEDIA",
                    "el certificado expira en %d dias" % dias,
                    "programar la renovacion del certificado",
                    identificador="WEB-SSL",
                ))
        except (ValueError, KeyError):
            pass

    # deteccion de protocolos obsoletos
    for nombre in ("TLSv1.0", "TLSv1.1"):
        if probar_version(host, puerto, VERSIONES[nombre]):
            print("      [!] el servidor acepta %s" % nombre)
            hallazgos.append(F.crear_hallazgo(
                "web",
                "el servidor acepta un protocolo obsoleto (%s)" % nombre,
                "ALTA",
                "%s esta deprecado y no deberia aceptarse en un sitio actual" % nombre,
                "deshabilitar %s y aceptar solo tls 1.2 y tls 1.3" % nombre,
                identificador="WEB-SSL",
            ))

    # analisis de la fuerza del cifrador negociado
    if cifrador:
        nombre_suite = cifrador[0]
        bits = cifrador[2]
        if any(debil in nombre_suite.upper() for debil in CIFRADORES_DEBILES) or (
            isinstance(bits, int) and bits < 128
        ):
            print("      [!] cifrador debil negociado: %s" % nombre_suite)
            hallazgos.append(F.crear_hallazgo(
                "web",
                "el servidor negocia un cifrador debil (%s)" % nombre_suite,
                "ALTA",
                "la suite de cifrado %s (%s bits) es debil u obsoleta" % (nombre_suite, bits),
                "configurar el servidor para usar solo suites de cifrado fuertes (aead, >=128 bits)",
                identificador="WEB-SSL",
                evidencia={"cifrador": nombre_suite, "bits": bits},
            ))

    return hallazgos
