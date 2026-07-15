# instalador de dependencias del toolkit
#
# instala automaticamente las librerias de python que necesita el proyecto
# a partir del archivo requirements.txt.
#
# uso:
#   python install.py

import os
import subprocess
import sys

DIR_BASE = os.path.dirname(os.path.abspath(__file__))
REQUISITOS = os.path.join(DIR_BASE, "requirements.txt")


def titulo(texto):
    print("\n" + "=" * 60)
    print(texto)
    print("=" * 60)


def instalar_dependencias():
    # instala las dependencias de python usando pip
    titulo("instalando dependencias de python")
    if not os.path.exists(REQUISITOS):
        print("[-] no se encontro el archivo de requisitos en %s" % REQUISITOS)
        return False
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-r", REQUISITOS]
        )
        print("\n[+] dependencias instaladas correctamente")
        return True
    except subprocess.CalledProcessError as error:
        print("\n[-] fallo la instalacion de dependencias: %s" % error)
        return False


def main():
    titulo("instalador del toolkit g1 - cy703")
    print("interprete de python : %s" % sys.executable)
    print("version              : %s" % sys.version.split()[0])

    ok = instalar_dependencias()

    titulo("resultado de la instalacion")
    if ok:
        print("[+] todo listo. puede ejecutar el toolkit con:")
    else:
        print("[!] instalacion completada con advertencias. revise los mensajes anteriores.")
        print("    una vez resueltas, ejecute el toolkit con:")
    print("\n    python run.py\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
