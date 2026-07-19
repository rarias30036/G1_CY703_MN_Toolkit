# validacion de entradas (rs-6)
#
# valida y normaliza las entradas del usuario antes de procesarlas, para
# evitar errores de ejecucion y entradas maliciosas en los modulos de analisis.

import ipaddress
import re

# expresion regular basica para validar un nombre de dominio
_RE_DOMINIO = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$"
)


def limpiar_objetivo(valor):
    # quita el esquema y la ruta para quedarse solo con el host
    valor = valor.strip().lower()
    valor = valor.replace("https://", "").replace("http://", "")
    valor = valor.split("/")[0]
    valor = valor.split(":")[0]
    return valor


def es_ip(valor):
    # indica si el valor es una direccion ip valida (v4 o v6)
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False


def es_dominio(valor):
    # indica si el valor tiene forma de nombre de dominio
    return bool(_RE_DOMINIO.match(valor))


def es_ip_privada(valor):
    # indica si la ip pertenece a un rango privado
    try:
        return ipaddress.ip_address(valor).is_private
    except ValueError:
        return False


def normalizar_url(url):
    # valida y normaliza una url para el modulo web.
    # si no trae esquema se asume https. devuelve none si no es valida.
    url = url.strip()
    if not url:
        return None
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    host = limpiar_objetivo(url)
    if not es_ip(host) and not es_dominio(host):
        return None
    return url


def validar_objetivo_red(valor):
    # valida la entrada del modulo de red: debe ser una ip o un dominio.
    # devuelve el host limpio o none si no es valido.
    host = limpiar_objetivo(valor)
    if es_ip(host) or es_dominio(host):
        return host
    return None
