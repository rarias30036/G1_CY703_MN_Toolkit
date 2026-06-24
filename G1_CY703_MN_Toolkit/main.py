"""
punto de entrada del toolkit

pide autenticacion al iniciar, muestra un menu para elegir entre el analisis
web o el de red, y arma un reporte consolidado en pantalla con los hallazgos
encontrados durante la sesion.

ejecucion:
    python run.py
"""

from toolkitPreeliminar.common import auth
from toolkitPreeliminar.common import findings as F
from toolkitPreeliminar.network_module import scanner as red
from toolkitPreeliminar.web_module import scanner as web

# aqui se van guardando todos los hallazgos de la sesion
hallazgos_sesion = []


def banner():
    print("""
============================================================
        TOOLKIT PRELIMINAR - SEGURIDAD PARA ONGs
                Web  |  Red   (prototipo)
============================================================
""")


def menu():
    print("\n------------------------------------------------------------")
    print(" MENU PRINCIPAL")
    print("------------------------------------------------------------")
    print(" 1. Analisis Web       revisa headers de seguridad de un sitio")
    print(" 2. Analisis de Red    resuelve dns y escanea puertos comunes")
    print(" 3. Reporte            muestra los hallazgos de esta sesion")
    print(" 0. Salir")


def correr_web():
    url = input("\nURL a analizar (ej. https://ejemplo.org): ").strip()
    if url:
        nuevos = web.analizar(url)
        hallazgos_sesion.extend(nuevos)
        print(f"\n  [+] {len(nuevos)} hallazgo(s) agregado(s).")


def correr_red():
    objetivo = input("\nIP o dominio a analizar (ej. ejemplo.org): ").strip()
    if objetivo:
        nuevos = red.analizar(objetivo)
        hallazgos_sesion.extend(nuevos)
        print(f"\n  [+] {len(nuevos)} hallazgo(s) agregado(s).")


def reporte():
    print("\n============================================================")
    print(" REPORTE DE LA SESION")
    print("============================================================")

    if not hallazgos_sesion:
        print(" No hay hallazgos todavia. Ejecute un analisis primero.")
        return

    puntaje = F.calcular_puntaje(hallazgos_sesion)
    print(f" Puntaje de seguridad : {puntaje}/100")
    print(f" Total de hallazgos   : {len(hallazgos_sesion)}")
    print("------------------------------------------------------------")

    for h in F.ordenar_por_severidad(hallazgos_sesion):
        print(f"\n [{h['severidad']}] ({h['modulo']}) {h['titulo']}")
        print(f"   {h['descripcion']}")
        if h["recomendacion"]:
            print(f"   -> {h['recomendacion']}")


def main():
    banner()
    # control de acceso: sin login valido no se entra al menu
    if not auth.login():
        return
    while True:
        menu()
        opcion = input("\nSeleccione una opcion: ").strip()
        if opcion == "1":
            correr_web()
        elif opcion == "2":
            correr_red()
        elif opcion == "3":
            reporte()
        elif opcion == "0":
            print("\nSaliendo del toolkit preliminar. Hasta luego.")
            break
        else:
            print("\n[-] Opcion invalida, intente de nuevo.")


if __name__ == "__main__":
    main()
