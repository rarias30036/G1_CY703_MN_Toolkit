"""
modulo web

revisa los headers de seguridad de una pagina usando urllib de la libreria
estandar: comprueba si estan presentes algunos headers basicos y genera un
hallazgo por cada uno que falte.
"""

import urllib.request

from toolkitPreeliminar.common import findings as F

# headers de seguridad que esperamos encontrar y por que importan
HEADERS_ESPERADOS = {
    "Strict-Transport-Security": "Obliga a usar HTTPS y evita downgrade a HTTP.",
    "Content-Security-Policy": "Mitiga ataques de inyeccion de scripts (XSS).",
    "X-Frame-Options": "Evita que la pagina se cargue dentro de un iframe (clickjacking).",
    "X-Content-Type-Options": "Evita que el navegador adivine el tipo de contenido.",
}


def obtener_headers(url):
    """hace una peticion get y devuelve los headers de la respuesta"""
    if not url.startswith("http"):
        url = "https://" + url
    peticion = urllib.request.Request(url, headers={"User-Agent": "toolkitPreeliminar"})
    respuesta = urllib.request.urlopen(peticion, timeout=5)
    return dict(respuesta.headers)


def analizar(url):
    """revisa los headers de seguridad y devuelve una lista de hallazgos"""
    hallazgos = []

    try:
        headers = obtener_headers(url)
    except Exception as error:
        print(f"  [-] no se pudo conectar a {url}: {error}")
        return hallazgos

    print(f"  [i] respuesta recibida, revisando headers de seguridad...")

    for header, motivo in HEADERS_ESPERADOS.items():
        if header in headers:
            print(f"      [ok] {header} presente")
        else:
            print(f"      [!] falta {header}")
            hallazgos.append(F.crear_hallazgo(
                "web",
                f"Header de seguridad ausente: {header}",
                "MEDIA",
                f"La respuesta no incluye el header {header}. {motivo}",
                f"Configurar el header {header} en el servidor web.",
            ))

    return hallazgos
