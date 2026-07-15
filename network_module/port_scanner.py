# escaneo de puertos tcp
#
# prueba una lista de puertos tcp comunes sobre la ip objetivo, intenta leer
# el banner del servicio y marca como riesgosos los puertos que normalmente
# no deberian estar expuestos a internet.

import socket

from common import findings as F

# puertos comunes que vamos a probar con su servicio asociado
PUERTOS_COMUNES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http-alt",
}

# servicios que normalmente no deberian estar expuestos a internet
PUERTOS_RIESGOSOS = {21, 23, 445, 3306, 3389, 5432}


def escanear_puerto(ip, puerto, timeout=0.8):
    # intenta conectar a un puerto y leer su banner.
    # devuelve (abierto, banner). el timeout evita bloqueos (rs-8).
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = ""
    try:
        if s.connect_ex((ip, puerto)) != 0:
            return False, ""
        try:
            datos = s.recv(120)
            banner = datos.decode("utf-8", "ignore").strip()
        except OSError:
            banner = ""
    finally:
        s.close()
    return True, banner


def analizar(ip):
    # escanea los puertos comunes y devuelve una lista de hallazgos
    hallazgos = []
    print("  [i] escaneando puertos comunes en %s..." % ip)

    for puerto, servicio in PUERTOS_COMUNES.items():
        abierto, banner = escanear_puerto(ip, puerto)
        if not abierto:
            continue

        detalle = " banner: %s" % banner if banner else ""
        print("      puerto %d (%s) abierto%s" % (puerto, servicio, detalle))

        if puerto in PUERTOS_RIESGOSOS:
            hallazgos.append(F.crear_hallazgo(
                "red",
                "puerto riesgoso %d/%s expuesto" % (puerto, servicio),
                "ALTA",
                "el servicio %s esta accesible en el puerto %d y no deberia estar expuesto" % (servicio, puerto),
                "cerrar el puerto o restringirlo con un firewall si no es necesario",
                identificador="RED-PTO",
                evidencia={"puerto": puerto, "servicio": servicio, "banner": banner},
            ))
        else:
            hallazgos.append(F.crear_hallazgo(
                "red",
                "puerto %d/%s abierto" % (puerto, servicio),
                "INFO",
                "el puerto %d (%s) responde a conexiones" % (puerto, servicio),
                identificador="RED-PTO",
                evidencia={"puerto": puerto, "banner": banner},
            ))

    # TODO: falta el escaneo de puertos udp, queda pendiente para una version posterior
    return hallazgos


def escanear_udp(ip, puerto):
    # pendiente: el escaneo udp requiere un manejo distinto porque no hay
    # una confirmacion de conexion como en tcp. queda como trabajo futuro.
    raise NotImplementedError("escaneo udp aun no implementado")
