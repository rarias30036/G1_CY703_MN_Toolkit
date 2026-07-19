# pruebas del control de acceso y autorizacion (rs-1, rs-2, rs-3, rs-4)

from common import auth


def test_clave_no_se_guarda_en_texto_plano():
    # rs-4: el almacen no debe contener la clave en texto plano
    for datos in auth.USUARIOS.values():
        assert "password" not in datos.values()
        assert "salt" in datos and "hash" in datos


def test_verificar_clave_correcta():
    # rs-4: la clave correcta valida contra el hash salteado
    assert auth._verificar_clave("password", auth.USUARIOS["admin"]) is True
    assert auth._verificar_clave("analista123", auth.USUARIOS["analista"]) is True


def test_verificar_clave_incorrecta():
    # rs-4: una clave incorrecta no valida
    assert auth._verificar_clave("otra", auth.USUARIOS["admin"]) is False
    assert auth._verificar_clave("", auth.USUARIOS["admin"]) is False


def test_hash_usa_salt_distinto_por_usuario():
    # rs-4: cada usuario tiene su propio salt
    assert auth.USUARIOS["admin"]["salt"] != auth.USUARIOS["analista"]["salt"]


def test_permisos_por_rol():
    # rs-3: el admin tiene acceso total y el analista no puede exportar
    assert auth.tiene_permiso("admin", "exportar") is True
    assert auth.tiene_permiso("admin", "web") is True
    assert auth.tiene_permiso("analista", "web") is True
    assert auth.tiene_permiso("analista", "reporte") is True
    assert auth.tiene_permiso("analista", "exportar") is False


def test_permiso_rol_desconocido():
    # rs-3: un rol inexistente no tiene ningun permiso
    assert auth.tiene_permiso("invitado", "web") is False


def test_login_exitoso(monkeypatch):
    # rs-1: credenciales validas devuelven usuario y rol
    monkeypatch.setattr("builtins.input", lambda _="": "admin")
    monkeypatch.setattr(auth.getpass, "getpass", lambda _="": "password")
    usuario, rol = auth.login()
    assert usuario == "admin"
    assert rol == "admin"


def test_login_fallido_agota_intentos(monkeypatch):
    # rs-2: tras max_intentos credenciales invalidas se cierra el acceso
    monkeypatch.setattr("builtins.input", lambda _="": "admin")
    monkeypatch.setattr(auth.getpass, "getpass", lambda _="": "incorrecta")
    usuario, rol = auth.login()
    assert usuario is None
    assert rol is None
