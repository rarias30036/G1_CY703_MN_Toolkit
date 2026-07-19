# pruebas del registro de eventos de seguridad (rs-5, rs-7)

import importlib

from common import logger


def test_registrar_escribe_linea(tmp_path, monkeypatch):
    # rs-5: cada evento se escribe con fecha, nivel y mensaje
    archivo = tmp_path / "toolkit.log"
    monkeypatch.setattr(logger, "DIR_LOGS", str(tmp_path))
    monkeypatch.setattr(logger, "ARCHIVO_LOG", str(archivo))

    logger.registrar("INFO", "evento de prueba")

    contenido = archivo.read_text(encoding="utf-8")
    assert "INFO" in contenido
    assert "evento de prueba" in contenido


def test_registrar_no_lanza_error_si_falla_escritura(monkeypatch):
    # rs-7: si no se puede escribir el log no se interrumpe la ejecucion
    def falla(*args, **kwargs):
        raise OSError("disco lleno")

    monkeypatch.setattr("builtins.open", falla)
    # no debe propagar la excepcion
    logger.registrar("ERROR", "mensaje")
