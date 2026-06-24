"""
control de acceso

pide usuario y clave al iniciar el toolkit y los compara con un par fijo.
permite un numero limitado de intentos antes de cerrar la aplicacion.
"""

import getpass

# credenciales fijas del prototipo
USUARIO = "admin"
CLAVE = "password"

# cantidad de intentos permitidos antes de cerrar el toolkit
MAX_INTENTOS = 3


def login():
    """pide credenciales y devuelve true si son correctas"""
    print("------------------------------------------------------------")
    print(" INICIO DE SESION")
    print("------------------------------------------------------------")

    for intento in range(1, MAX_INTENTOS + 1):
        usuario = input(" Usuario: ").strip()
        clave = getpass.getpass(" Clave: ")

        if usuario == USUARIO and clave == CLAVE:
            print(f"\n [+] Bienvenido, {usuario}.")
            return True

        restantes = MAX_INTENTOS - intento
        print(f" [-] Credenciales incorrectas. Intentos restantes: {restantes}\n")

    print("\n [!] Demasiados intentos fallidos. Saliendo.")
    return False
