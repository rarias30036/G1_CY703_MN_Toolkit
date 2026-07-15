# analisis dns
#
# resuelve un dominio a su ip (resolucion directa) o una ip a su nombre
# (resolucion inversa) usando la libreria estandar, y revisa si el dominio
# presenta caracteristicas tipicas de sitios sospechosos.

import socket

from common import findings as F

# tld usados con frecuencia en dominios maliciosos o de baja reputacion
TLDS_SOSPECHOSOS = [".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf"]


def resolver_directo(dominio):
    # devuelve la ip de un dominio, o None si no se puede resolver
    try:
        return socket.gethostbyname(dominio)
    except socket.gaierror:
        return None


def resolver_inverso(ip):
    # devuelve el nombre asociado a una ip, o None si no hay registro
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def analizar_dominio_sospechoso(dominio):
    # revisa senales simples de un dominio sospechoso y devuelve las razones
    razones = []
    d = dominio.lower()
    if any(d.endswith(tld) for tld in TLDS_SOSPECHOSOS):
        razones.append("tld sospechoso")
    if len(d) > 30:
        razones.append("dominio largo")
    if sum(c.isdigit() for c in d) >= 5:
        razones.append("muchos numeros")
    return razones


def analizar(objetivo, es_ip):
    # ejecuta la resolucion dns y devuelve (hallazgos, ip_a_escanear).
    # si el objetivo es una ip se hace resolucion inversa y se escanea esa ip.
    hallazgos = []

    if es_ip:
        nombre = resolver_inverso(objetivo)
        if nombre:
            print("  [i] dns inverso: %s -> %s" % (objetivo, nombre))
        else:
            print("  [i] dns inverso: sin registro ptr para %s" % objetivo)
        return hallazgos, objetivo

    ip = resolver_directo(objetivo)
    if ip is None:
        print("  [-] no se pudo resolver %s" % objetivo)
        return hallazgos, None

    print("  [i] dns directo: %s -> %s" % (objetivo, ip))

    razones = analizar_dominio_sospechoso(objetivo)
    if razones:
        hallazgos.append(F.crear_hallazgo(
            "red",
            "el dominio presenta caracteristicas sospechosas",
            "BAJA",
            "el dominio %s coincide con: %s" % (objetivo, ", ".join(razones)),
            "verificar la legitimidad del dominio antes de confiar en el",
            identificador="RED-DNS",
            evidencia={"razones": razones},
        ))

    # TODO: falta la deteccion de ips maliciosas contra un servicio de
    # reputacion (por ejemplo virustotal), que requiere una api key
    return hallazgos, ip
