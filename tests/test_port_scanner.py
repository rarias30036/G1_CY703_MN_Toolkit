# pruebas del escaneo de puertos tcp y udp (rs-8)

from network_module import port_scanner as ps


def test_escanear_puerto_cerrado_retorna_falso():
    # rs-8: un puerto cerrado en loopback responde rapido y no bloquea
    abierto, banner = ps.escanear_puerto("127.0.0.1", 65500, timeout=0.5)
    assert abierto is False
    assert banner == ""


def test_escanear_udp_retorna_estado_valido():
    # rs-8: el escaneo udp devuelve un estado conocido sin lanzar excepciones
    estado = ps.escanear_udp("127.0.0.1", 65500, timeout=0.5)
    assert estado in ("abierto", "cerrado", "abierto|filtrado")


def test_puertos_riesgosos_definidos():
    # los servicios sensibles estan marcados como riesgosos
    assert 23 in ps.PUERTOS_RIESGOSOS
    assert 3389 in ps.PUERTOS_RIESGOSOS
    assert 161 in ps.PUERTOS_UDP_RIESGOSOS


def test_analizar_udp_no_falla_en_loopback():
    # el escaneo udp completo no debe lanzar excepciones
    hallazgos = ps.analizar_udp("127.0.0.1")
    assert isinstance(hallazgos, list)
