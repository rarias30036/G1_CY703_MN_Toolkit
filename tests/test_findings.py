# pruebas del esquema comun de hallazgos y su puntuacion

from common import findings as F


def test_crear_hallazgo_estructura():
    h = F.crear_hallazgo("web", "titulo", "ALTA", "descripcion", "reco", "WEB-X")
    assert h["modulo"] == "web"
    assert h["severidad"] == "ALTA"
    assert h["id"] == "WEB-X"
    assert h["evidencia"] == {}


def test_calcular_puntaje_sin_hallazgos():
    assert F.calcular_puntaje([]) == 100


def test_calcular_puntaje_resta_pesos():
    hallazgos = [
        F.crear_hallazgo("web", "a", "ALTA", "d"),
        F.crear_hallazgo("red", "b", "MEDIA", "d"),
    ]
    assert F.calcular_puntaje(hallazgos) == 100 - 15 - 8


def test_calcular_puntaje_no_baja_de_cero():
    hallazgos = [F.crear_hallazgo("web", "a", "CRITICA", "d") for _ in range(10)]
    assert F.calcular_puntaje(hallazgos) == 0


def test_ordenar_por_severidad():
    hallazgos = [
        F.crear_hallazgo("web", "info", "INFO", "d"),
        F.crear_hallazgo("web", "critica", "CRITICA", "d"),
        F.crear_hallazgo("web", "media", "MEDIA", "d"),
    ]
    orden = [h["severidad"] for h in F.ordenar_por_severidad(hallazgos)]
    assert orden == ["CRITICA", "MEDIA", "INFO"]


def test_resumen_por_severidad():
    hallazgos = [
        F.crear_hallazgo("web", "a", "ALTA", "d"),
        F.crear_hallazgo("web", "b", "ALTA", "d"),
        F.crear_hallazgo("red", "c", "BAJA", "d"),
    ]
    conteo = F.resumen_por_severidad(hallazgos)
    assert conteo["ALTA"] == 2
    assert conteo["BAJA"] == 1
    assert conteo["CRITICA"] == 0
