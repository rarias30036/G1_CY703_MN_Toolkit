# esquema comun de hallazgos
#
# define el formato unico que usan los modulos web y de red para reportar sus
# hallazgos, de modo que se puedan consolidar y puntuar en un mismo reporte.

# severidades que vamos a usar (de mayor a menor impacto)
SEVERIDADES = ["CRITICA", "ALTA", "MEDIA", "BAJA", "INFO"]

# peso para un puntaje simple de 0 a 100
PESOS = {
    "CRITICA": 25,
    "ALTA": 15,
    "MEDIA": 8,
    "BAJA": 3,
    "INFO": 0,
}


def crear_hallazgo(modulo, titulo, severidad, descripcion, recomendacion="",
                   identificador="", evidencia=None):
    # arma un hallazgo como un diccionario simple.
    # identificador y evidencia son opcionales para no romper el codigo previo.
    return {
        "id": identificador,
        "modulo": modulo,
        "titulo": titulo,
        "severidad": severidad,
        "descripcion": descripcion,
        "recomendacion": recomendacion,
        "evidencia": evidencia if evidencia is not None else {},
    }


def calcular_puntaje(hallazgos):
    # puntaje 0-100: empieza en 100 y resta el peso de cada hallazgo
    puntaje = 100
    for h in hallazgos:
        puntaje -= PESOS.get(h["severidad"], 0)
    if puntaje < 0:
        puntaje = 0
    return puntaje


def ordenar_por_severidad(hallazgos):
    # ordena los hallazgos de mas grave a menos grave
    orden = {sev: i for i, sev in enumerate(SEVERIDADES)}
    return sorted(hallazgos, key=lambda h: orden.get(h["severidad"], 99))


def resumen_por_severidad(hallazgos):
    # devuelve un conteo de cuantos hallazgos hay por cada severidad
    conteo = {sev: 0 for sev in SEVERIDADES}
    for h in hallazgos:
        sev = h["severidad"]
        if sev in conteo:
            conteo[sev] += 1
    return conteo
