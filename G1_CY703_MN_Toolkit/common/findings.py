"""
esquema comun de hallazgos

define el formato unico que usan los modulos web y red para reportar sus
hallazgos, de modo que se puedan consolidar y puntuar en un mismo reporte.
"""

# severidades que vamos a usar (de mayor a menor impacto)
SEVERIDADES = ["CRITICA", "ALTA", "MEDIA", "BAJA", "INFO"]

# peso para un puntaje muy simple de 0 a 100
PESOS = {
    "CRITICA": 25,
    "ALTA": 15,
    "MEDIA": 8,
    "BAJA": 3,
    "INFO": 0,
}


def crear_hallazgo(modulo, titulo, severidad, descripcion, recomendacion=""):
    """arma un hallazgo como un diccionario simple"""
    return {
        "modulo": modulo,
        "titulo": titulo,
        "severidad": severidad,
        "descripcion": descripcion,
        "recomendacion": recomendacion,
    }


def calcular_puntaje(hallazgos):
    """puntaje 0-100: empieza en 100 y resta el peso de cada hallazgo"""
    puntaje = 100
    for h in hallazgos:
        puntaje -= PESOS.get(h["severidad"], 0)
    if puntaje < 0:
        puntaje = 0
    return puntaje


def ordenar_por_severidad(hallazgos):
    """ordena los hallazgos de mas grave a menos grave"""
    orden = {sev: i for i, sev in enumerate(SEVERIDADES)}
    return sorted(hallazgos, key=lambda h: orden.get(h["severidad"], 99))
