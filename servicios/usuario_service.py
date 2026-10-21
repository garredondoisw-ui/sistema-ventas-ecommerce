# servicios/usuario_service.py

# Simulador de Base de Datos MySQL temporal
db_usuarios = {}

class UsuarioService:
    @staticmethod
    def crear_usuario(datos):
        user_id = len(db_usuarios) + 1
        nuevo_usuario = {
            "id": user_id,
            "nombre": datos.nombre,
            "correo": datos.correo,
            "password": datos.password, # En un entorno real, esto se guarda con Hash (ej. bcrypt)
            "rol": "CLIENTE",
            "estado": "INACTIVO", # Requiere validación
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
        # Lógica de validación
        usuario = UsuarioService.obtener_por_correo(correo)
        if usuario and codigo == "123456": # Código quemado por ahora para pruebas
            usuario["estado"] = "ACTIVO"
            return True
        return False