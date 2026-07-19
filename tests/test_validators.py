# pruebas de la validacion y normalizacion de entradas (rs-6)

from common import validators


def test_es_ip_valida():
    assert validators.es_ip("8.8.8.8") is True
    assert validators.es_ip("::1") is True


def test_es_ip_invalida():
    assert validators.es_ip("999.999.999.999") is False
    assert validators.es_ip("ejemplo.org") is False


def test_es_dominio_valido():
    assert validators.es_dominio("ejemplo.org") is True
    assert validators.es_dominio("sub.dominio.co.uk") is True


def test_es_dominio_invalido():
    assert validators.es_dominio("no valido !!") is False
    assert validators.es_dominio("") is False


def test_es_ip_privada():
    assert validators.es_ip_privada("192.168.1.1") is True
    assert validators.es_ip_privada("8.8.8.8") is False


def test_limpiar_objetivo_canonicaliza():
    # rs-6: quita esquema, ruta y puerto, y pasa a minusculas
    assert validators.limpiar_objetivo("HTTPS://Ejemplo.org/ruta") == "ejemplo.org"
    assert validators.limpiar_objetivo("http://ejemplo.org:8080/x") == "ejemplo.org"


def test_normalizar_url_agrega_esquema():
    assert validators.normalizar_url("ejemplo.org") == "https://ejemplo.org"


def test_normalizar_url_invalida():
    assert validators.normalizar_url("no valido !!") is None
    assert validators.normalizar_url("") is None


def test_validar_objetivo_red_acepta_ip_y_dominio():
    assert validators.validar_objetivo_red("8.8.8.8") == "8.8.8.8"
    assert validators.validar_objetivo_red("https://ejemplo.org/x") == "ejemplo.org"


def test_validar_objetivo_red_rechaza_invalido():
    # rs-6: enfoque de lista blanca, rechaza lo que no es ip ni dominio
    assert validators.validar_objetivo_red("<script>") is None
