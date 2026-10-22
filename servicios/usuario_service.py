# servicios/usuario_service.py
import secrets
import hmac
from werkzeug.security import generate_password_hash

# Simulador de Base de Datos MySQL temporal
db_usuarios = {}

class UsuarioService:
    @staticmethod
    def crear_usuario(datos):
        user_id = len(db_usuarios) + 1
        codigo_generado = f"{secrets.randbelow(900000) + 100000:06d}"
        nuevo_usuario = {
            "id": user_id,
            "nombre": datos.nombre,
            "correo": datos.correo,
            "password": generate_password_hash(datos.password),
            "rol": "CLIENTE",
            "estado": "INACTIVO", # Requiere validación
            "codigo_validacion": codigo_generado,
            "fecha_registro": "2026-10-01T07:31:00Z"
        }
        db_usuarios[user_id] = nuevo_usuario
        return nuevo_usuario

    @staticmethod
    def obtener_por_correo(correo: str):
        for user in db_usuarios.values():
            if user["correo"] == correo:
                return user
        return None

    @staticmethod
    def obtener_perfil(user_id: int):
        return db_usuarios.get(user_id)

    @staticmethod
    def activar_cuenta(correo: str, codigo: str):
        # Lógica de validación con código dinámico por usuario
        usuario = UsuarioService.obtener_por_correo(correo)
        codigo_guardado = usuario.get("codigo_validacion") if usuario else None
        if usuario and codigo_guardado and hmac.compare_digest(codigo_guardado, codigo.strip()):
            usuario["estado"] = "ACTIVO"
            usuario["codigo_validacion"] = None
            return True
        return False
