# analisis dns
#
# resuelve un dominio a su ip (resolucion directa) o una ip a su nombre
# (resolucion inversa) usando la libreria estandar, y revisa si el dominio
# presenta caracteristicas tipicas de sitios sospechosos.

import ipaddress
import socket

from common import findings as F

# tld usados con frecuencia en dominios maliciosos o de baja reputacion
TLDS_SOSPECHOSOS = [".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf"]


def ip_no_publica(ip):
    # indica si la ip pertenece a un rango privado, reservado o de loopback.
    # que un dominio publico resuelva a una de estas ips es una senal de mala
    # configuracion o de un posible ataque de dns rebinding.
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        direccion.is_private
        or direccion.is_loopback
        or direccion.is_reserved
        or direccion.is_link_local
    )


def resolver_directo(dominio):
    # devuelve la ip de un dominio, o none si no se puede resolver
    try:
        return socket.gethostbyname(dominio)
    except socket.gaierror:
        return None


def resolver_inverso(ip):
    # devuelve el nombre asociado a una ip, o none si no hay registro
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

    # deteccion de ips no publicas: un dominio publico no deberia resolver a una
    # ip privada, reservada o de loopback
    if ip_no_publica(ip):
        hallazgos.append(F.crear_hallazgo(
            "red",
            "el dominio resuelve a una ip no publica",
            "MEDIA",
            "el dominio %s resuelve a la ip %s, que pertenece a un rango privado "
            "o reservado (posible mala configuracion o dns rebinding)" % (objetivo, ip),
            "verificar la configuracion dns del dominio y descartar un ataque de rebinding",
            identificador="RED-DNS",
            evidencia={"dominio": objetivo, "ip": ip},
        ))

    return hallazgos, ip
