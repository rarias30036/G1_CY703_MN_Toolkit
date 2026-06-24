"""
modulo de red

hace dos cosas usando la libreria estandar de python:
  - resuelve un dominio a su ip (analisis dns directo)
  - prueba unos cuantos puertos tcp comunes para ver cuales estan abiertos
"""

import socket

from toolkitPreeliminar.common import findings as F

# puertos comunes que vamos a probar en el prototipo
PUERTOS_COMUNES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    443: "https",
    3306: "mysql",
    3389: "rdp",
}

# servicios que normalmente NO deberian estar expuestos
PUERTOS_RIESGOSOS = {21, 23, 3306, 3389}


def resolver_dominio(objetivo):
    """devuelve la ip de un dominio, o el mismo objetivo si ya es una ip"""
    try:
        ip = socket.gethostbyname(objetivo)
        return ip
    except socket.gaierror:
        return None


def escanear_puerto(ip, puerto):
    """intenta conectar a un puerto, devuelve true si esta abierto"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    abierto = s.connect_ex((ip, puerto)) == 0
    s.close()
    return abierto


def analizar(objetivo):
    """escanea el objetivo y devuelve una lista de hallazgos"""
    hallazgos = []

    ip = resolver_dominio(objetivo)
    if ip is None:
        print(f"  [-] no se pudo resolver {objetivo}")
        return hallazgos

    print(f"  [i] {objetivo} -> {ip}")
    print("  [i] probando puertos comunes...")

    for puerto, servicio in PUERTOS_COMUNES.items():
        if escanear_puerto(ip, puerto):
            print(f"      puerto {puerto} ({servicio}) ABIERTO")
            if puerto in PUERTOS_RIESGOSOS:
                hallazgos.append(F.crear_hallazgo(
                    "red",
                    f"Puerto riesgoso {puerto}/{servicio} expuesto",
                    "ALTA",
                    f"El servicio {servicio} esta accesible en el puerto {puerto}.",
                    "Cerrar el puerto o restringirlo con un firewall si no es necesario.",
                ))
            else:
                hallazgos.append(F.crear_hallazgo(
                    "red",
                    f"Puerto {puerto}/{servicio} abierto",
                    "INFO",
                    f"El puerto {puerto} ({servicio}) responde a conexiones.",
                ))

    return hallazgos
