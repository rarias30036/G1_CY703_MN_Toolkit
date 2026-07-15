# control de acceso (rs-1, rs-2, rs-4)
#
# pide usuario y clave al iniciar el toolkit y los compara contra un usuario
# fijo. la clave no se guarda en texto plano sino como un hash sha256.
# permite un numero limitado de intentos antes de cerrar la aplicacion.

import getpass
import hashlib

from common import logger

# usuario fijo del prototipo
USUARIO = "admin"

# hash sha256 de la clave del prototipo (la clave es "password").
# de esta forma no se almacena la clave en texto plano dentro del codigo.
# nota: por ahora el hash no utiliza salt, es un punto por mejorar.
CLAVE_HASH = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

# cantidad de intentos permitidos antes de cerrar el toolkit
MAX_INTENTOS = 3


def hash_clave(clave):
    # devuelve el hash sha256 de la clave ingresada
    return hashlib.sha256(clave.encode("utf-8")).hexdigest()


def login():
    # pide credenciales y devuelve el nombre de usuario si son correctas,
    # o None si se agotan los intentos.
    print("------------------------------------------------------------")
    print(" INICIO DE SESION")
    print("------------------------------------------------------------")

    for intento in range(1, MAX_INTENTOS + 1):
        usuario = input(" Usuario: ").strip()
        clave = getpass.getpass(" Clave: ")

        if usuario == USUARIO and hash_clave(clave) == CLAVE_HASH:
            print("\n [+] Bienvenido, %s." % usuario)
            logger.registrar("INFO", "login exitoso para el usuario %s" % usuario)
            return usuario

        # no se registra la clave ingresada, solo el intento fallido
        logger.registrar("ADVERTENCIA", "intento de login fallido")
        restantes = MAX_INTENTOS - intento
        print(" [-] Credenciales incorrectas. Intentos restantes: %d\n" % restantes)

    print("\n [!] Demasiados intentos fallidos. Saliendo.")
    logger.registrar("ADVERTENCIA", "acceso bloqueado por demasiados intentos fallidos")
    return None
