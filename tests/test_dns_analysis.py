# pruebas del analisis dns (deteccion de dominios e ips sospechosas)

from network_module import dns_analysis as dns


def test_ip_no_publica_detecta_rangos_reservados():
    assert dns.ip_no_publica("127.0.0.1") is True
    assert dns.ip_no_publica("192.168.0.10") is True
    assert dns.ip_no_publica("10.0.0.1") is True


def test_ip_no_publica_permite_ip_publica():
    assert dns.ip_no_publica("8.8.8.8") is False


def test_ip_no_publica_valor_invalido():
    assert dns.ip_no_publica("no-es-ip") is False


def test_dominio_sospechoso_por_tld():
    razones = dns.analizar_dominio_sospechoso("malicioso.tk")
    assert "tld sospechoso" in razones


def test_dominio_sin_senales():
    assert dns.analizar_dominio_sospechoso("ejemplo.org") == []
