# control de acceso y autorizacion (rs-1, rs-2, rs-3, rs-4)
#
# pide usuario y clave al iniciar el toolkit y los compara contra el almacen de
# usuarios. la clave nunca se guarda ni se compara en texto plano: se guarda un
# salt y el hash pbkdf2-hmac-sha256 de la clave, y la verificacion se hace en
# tiempo constante. cada usuario tiene un rol que define sus permisos y se
# permite un numero limitado de intentos antes de cerrar la aplicacion.

import getpass
import hashlib
import hmac

from common import logger

# parametros del hashing de contrasenas (rs-4).
# pbkdf2 con salt e iteraciones protege las credenciales frente a ataques de
# diccionario y rainbow tables en caso de exposicion del almacen.
_ALGORITMO = "sha256"
_ITERACIONES = 200000

# almacen de usuarios del prototipo (rs-1, rs-3, rs-4).
# la clave no se almacena en texto plano: se guarda el salt y el hash pbkdf2.
#   admin    -> clave "password"     (rol administrador)
#   analista -> clave "analista123"  (rol analista)
USUARIOS = {
    "admin": {
        "rol": "admin",
        "salt": "2a47e8dda5dab7e3bf8e786d472d357a",
        "hash": "1a6b90b4bdc8330745c974fdcd54daef4a58bbe473f2608044a133ae3dd1e340",
    },
    "analista": {
        "rol": "analista",
        "salt": "a3197e371cdf2305ca071313016d6d9e",
        "hash": "d5d61f3ebea7fa19505bbca9b9782a16fcf2df1d512a1089b7999ad204f7b865",
    },
}

# permisos por rol (rs-3, principio de minimo privilegio).
# el administrador tiene acceso total; el analista puede ejecutar los analisis
# y ver el reporte, pero no exportar el pdf ni administrar la herramienta.
PERMISOS = {
    "admin": {"web", "red", "reporte", "exportar"},
    "analista": {"web", "red", "reporte"},
}

# cantidad de intentos permitidos antes de cerrar el toolkit (rs-2)
MAX_INTENTOS = 3


def _hash_clave(clave, salt_bytes):
    # devuelve el hash pbkdf2-hmac de la clave con el salt indicado
    return hashlib.pbkdf2_hmac(
        _ALGORITMO, clave.encode("utf-8"), salt_bytes, _ITERACIONES
    )


def _verificar_clave(clave, registro):
    # compara en tiempo constante la clave ingresada contra el hash almacenado
    try:
        salt = bytes.fromhex(registro["salt"])
        esperado = bytes.fromhex(registro["hash"])
    except (KeyError, ValueError):
        return False
    calculado = _hash_clave(clave, salt)
    return hmac.compare_digest(calculado, esperado)


def tiene_permiso(rol, accion):
    # indica si el rol tiene permiso para ejecutar la accion (rs-3)
    return accion in PERMISOS.get(rol, set())


def login():
    # pide credenciales y devuelve (usuario, rol) si son correctas,
    # o (none, none) si se agotan los intentos.
    print("------------------------------------------------------------")
    print(" INICIO DE SESION")
    print("------------------------------------------------------------")

    for intento in range(1, MAX_INTENTOS + 1):
        usuario = input(" Usuario: ").strip()
        clave = getpass.getpass(" Clave: ")

        registro = USUARIOS.get(usuario)
        if registro is not None and _verificar_clave(clave, registro):
            rol = registro["rol"]
            print("\n [+] Bienvenido, %s (rol: %s)." % (usuario, rol))
            logger.registrar(
                "INFO", "login exitoso para el usuario %s con rol %s" % (usuario, rol)
            )
            return usuario, rol

        # no se registra la clave ingresada, solo el intento fallido (rs-5)
        logger.registrar("ADVERTENCIA", "intento de login fallido")
        restantes = MAX_INTENTOS - intento
        print(" [-] Credenciales incorrectas. Intentos restantes: %d\n" % restantes)

    print("\n [!] Demasiados intentos fallidos. Saliendo.")
    logger.registrar("ADVERTENCIA", "acceso bloqueado por demasiados intentos fallidos")
    return None, None
