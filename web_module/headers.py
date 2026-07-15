# analisis de headers de seguridad http
#
# hace una peticion a la pagina y revisa si estan presentes los headers de
# seguridad mas importantes. genera un hallazgo por cada header ausente y
# tambien detecta la divulgacion de tecnologia del servidor.

import requests

from common import findings as F
from common import logger

# se identifica la herramienta en el user-agent de las peticiones
CABECERAS = {"User-Agent": "G1-CY703-Toolkit"}

# headers de seguridad esperados con su severidad, motivo y recomendacion
HEADERS_ESPERADOS = [
    {
        "nombre": "strict-transport-security",
        "sev": "ALTA",
        "motivo": "obliga a usar https y evita el downgrade a http",
        "reco": "configurar strict-transport-security con un max-age de al menos 31536000 segundos",
    },
    {
        "nombre": "content-security-policy",
        "sev": "ALTA",
        "motivo": "mitiga ataques de inyeccion de scripts (xss)",
        "reco": "definir una politica csp restrictiva, por ejemplo default-src 'self'",
    },
    {
        "nombre": "x-frame-options",
        "sev": "MEDIA",
        "motivo": "evita que la pagina se cargue dentro de un iframe (clickjacking)",
        "reco": "configurar x-frame-options en DENY o SAMEORIGIN",
    },
    {
        "nombre": "x-content-type-options",
        "sev": "MEDIA",
        "motivo": "evita que el navegador adivine el tipo de contenido (mime sniffing)",
        "reco": "configurar x-content-type-options en nosniff",
    },
    {
        "nombre": "referrer-policy",
        "sev": "BAJA",
        "motivo": "controla que informacion de origen se comparte con otros sitios",
        "reco": "configurar referrer-policy en strict-origin-when-cross-origin",
    },
    {
        "nombre": "permissions-policy",
        "sev": "BAJA",
        "motivo": "restringe el uso de funciones del navegador como camara o microfono",
        "reco": "definir una permissions-policy restrictiva",
    },
]


def obtener_headers(url, timeout=10):
    # hace una peticion get y devuelve los headers en minuscula y el codigo http.
    # el timeout evita que la peticion se quede bloqueada (rs-8).
    try:
        respuesta = requests.get(
            url, timeout=timeout, allow_redirects=True, headers=CABECERAS, verify=True
        )
        headers = {k.lower(): v for k, v in respuesta.headers.items()}
        return headers, respuesta.status_code
    except requests.exceptions.SSLError:
        # si falla la verificacion del certificado se reintenta sin verificar
        # para no frenar la revision de headers (el problema de tls lo reporta
        # el modulo ssl_tls por separado)
        try:
            requests.packages.urllib3.disable_warnings()
            respuesta = requests.get(
                url, timeout=timeout, allow_redirects=True, headers=CABECERAS, verify=False
            )
            headers = {k.lower(): v for k, v in respuesta.headers.items()}
            return headers, respuesta.status_code
        except requests.exceptions.RequestException:
            return None, None
    except requests.exceptions.RequestException:
        return None, None


def analizar(url):
    # revisa los headers de seguridad y devuelve una lista de hallazgos
    hallazgos = []

    headers, estado = obtener_headers(url)
    if headers is None:
        print("  [-] no se pudo conectar a %s" % url)
        logger.registrar("ADVERTENCIA", "fallo la conexion web con %s" % url)
        return hallazgos

    print("  [i] respuesta http %s, revisando headers de seguridad..." % estado)

    for esperado in HEADERS_ESPERADOS:
        nombre = esperado["nombre"]
        if nombre in headers:
            print("      [ok] %s presente" % nombre)
        else:
            print("      [!] falta %s" % nombre)
            hallazgos.append(F.crear_hallazgo(
                "web",
                "header de seguridad ausente: %s" % nombre,
                esperado["sev"],
                "la respuesta no incluye el header %s. %s" % (nombre, esperado["motivo"]),
                esperado["reco"],
                identificador="WEB-HDR",
            ))

    # divulgacion de la tecnologia del servidor
    if "x-powered-by" in headers:
        hallazgos.append(F.crear_hallazgo(
            "web",
            "el servidor divulga su tecnologia (x-powered-by)",
            "INFO",
            "el header x-powered-by expone la tecnologia del servidor: %s" % headers["x-powered-by"],
            "eliminar el header x-powered-by en la configuracion del servidor",
            identificador="WEB-HDR",
            evidencia={"x-powered-by": headers["x-powered-by"]},
        ))

    # TODO: falta analizar el valor de los headers (por ejemplo si el csp usa
    # unsafe-inline o si el max-age del hsts es demasiado corto)
    return hallazgos
