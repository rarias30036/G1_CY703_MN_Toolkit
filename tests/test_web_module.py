# pruebas del modulo web (headers, ssl/tls y archivos expuestos)

from web_module import headers
from web_module import ssl_tls


def test_headers_hsts_max_age_corto():
    # se detecta un hsts con max-age menor al minimo recomendado
    valores = {"strict-transport-security": "max-age=100"}
    hallazgos = headers._analizar_valores(valores)
    titulos = [h["titulo"] for h in hallazgos]
    assert "hsts con max-age demasiado corto" in titulos


def test_headers_hsts_max_age_correcto():
    # un hsts con max-age suficiente no genera hallazgo
    valores = {"strict-transport-security": "max-age=31536000"}
    assert headers._analizar_valores(valores) == []


def test_headers_csp_permisiva():
    # csp con unsafe-inline se marca como permisiva
    valores = {"content-security-policy": "default-src 'self' 'unsafe-inline'"}
    hallazgos = headers._analizar_valores(valores)
    titulos = [h["titulo"] for h in hallazgos]
    assert "content-security-policy permisiva" in titulos


def test_ssl_host_puerto_por_defecto():
    host, puerto = ssl_tls._host_puerto("https://ejemplo.org")
    assert host == "ejemplo.org"
    assert puerto == 443


def test_ssl_host_puerto_explicito():
    host, puerto = ssl_tls._host_puerto("https://ejemplo.org:8443/ruta")
    assert host == "ejemplo.org"
    assert puerto == 8443


def test_ssl_http_sin_cifrado_genera_hallazgo():
    # una url http (sin tls) genera un hallazgo de severidad alta
    hallazgos = ssl_tls.analizar("http://ejemplo.org")
    assert any(h["severidad"] == "ALTA" for h in hallazgos)


def test_cifradores_debiles_definidos():
    assert "RC4" in ssl_tls.CIFRADORES_DEBILES
    assert "3DES" in ssl_tls.CIFRADORES_DEBILES
