# punto de entrada del toolkit
#
# muestra el aviso legal, pide autenticacion, presenta el menu para elegir
# entre el analisis web o el de red, arma un reporte en pantalla y permite
# exportar los hallazgos de la sesion a un archivo pdf.
#
# ejecucion:
#   python run.py

from common import auth
from common import findings as F
from common import logger
from common import report
from network_module import scanner as red
from web_module import scanner as web

# aqui se van guardando todos los hallazgos de la sesion
hallazgos_sesion = []

# objetivos que se han analizado durante la sesion (para el reporte)
objetivos_sesion = []


def banner():
    print("""
============================================================
        TOOLKIT PRELIMINAR - SEGURIDAD PARA ONGs
                Web  |  Red   (prototipo)
============================================================
""")


def aviso_legal():
    # aviso legal: solo se debe analizar sistemas con autorizacion (rs-10)
    print("------------------------------------------------------------")
    print(" AVISO LEGAL")
    print("------------------------------------------------------------")
    print(" Esta herramienta debe usarse unicamente sobre sistemas en los")
    print(" que se cuenta con autorizacion expresa. El uso sobre sistemas")
    print(" de terceros sin permiso puede constituir un delito.")
    respuesta = input("\n Escriba 'acepto' para continuar: ").strip().lower()
    if respuesta != "acepto":
        print("\n [!] No se acepto el aviso legal. Saliendo.")
        return False
    return True


def menu():
    print("\n------------------------------------------------------------")
    print(" MENU PRINCIPAL")
    print("------------------------------------------------------------")
    print(" 1. Analisis Web       headers, ssl/tls y archivos expuestos")
    print(" 2. Analisis de Red    resuelve dns y escanea puertos comunes")
    print(" 3. Reporte            muestra los hallazgos de esta sesion")
    print(" 4. Exportar PDF       guarda el reporte en la carpeta reportes")
    print(" 0. Salir")


def correr_web():
    url = input("\nURL a analizar (ej. https://ejemplo.org): ").strip()
    if not url:
        return
    nuevos = web.analizar(url)
    hallazgos_sesion.extend(nuevos)
    objetivos_sesion.append(url)
    print("\n  [+] %d hallazgo(s) agregado(s)." % len(nuevos))


def correr_red():
    objetivo = input("\nIP o dominio a analizar (ej. ejemplo.org): ").strip()
    if not objetivo:
        return
    nuevos = red.analizar(objetivo)
    hallazgos_sesion.extend(nuevos)
    objetivos_sesion.append(objetivo)
    print("\n  [+] %d hallazgo(s) agregado(s)." % len(nuevos))


def reporte():
    print("\n============================================================")
    print(" REPORTE DE LA SESION")
    print("============================================================")

    if not hallazgos_sesion:
        print(" No hay hallazgos todavia. Ejecute un analisis primero.")
        return

    puntaje = F.calcular_puntaje(hallazgos_sesion)
    print(" Puntaje de seguridad : %d/100" % puntaje)
    print(" Total de hallazgos   : %d" % len(hallazgos_sesion))
    print("------------------------------------------------------------")

    for h in F.ordenar_por_severidad(hallazgos_sesion):
        print("\n [%s] (%s) %s" % (h["severidad"], h["modulo"], h["titulo"]))
        print("   %s" % h["descripcion"])
        if h["recomendacion"]:
            print("   -> %s" % h["recomendacion"])


def exportar_pdf(usuario):
    if not hallazgos_sesion:
        print("\n No hay hallazgos todavia. Ejecute un analisis primero.")
        return
    ruta = report.generar_reporte_pdf(hallazgos_sesion, objetivos_sesion, usuario)
    if ruta:
        print("\n  [+] Reporte guardado en: %s" % ruta)
        logger.registrar("INFO", "reporte pdf generado en %s" % ruta)


def main():
    banner()
    # aviso legal antes de todo (rs-10)
    if not aviso_legal():
        return
    # control de acceso: sin login valido no se entra al menu (rs-1)
    usuario = auth.login()
    if not usuario:
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
        elif opcion == "4":
            exportar_pdf(usuario)
        elif opcion == "0":
            print("\nSaliendo del toolkit preliminar. Hasta luego.")
            logger.registrar("INFO", "cierre de sesion del usuario %s" % usuario)
            break
        else:
            print("\n[-] Opcion invalida, intente de nuevo.")


if __name__ == "__main__":
    main()
