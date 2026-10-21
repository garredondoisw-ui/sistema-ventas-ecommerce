# servicios/auth_service.py
import jwt
from datetime import datetime, timedelta
from servicios.usuario_service import UsuarioService

SECRET_KEY = "mi_clave_super_secreta_para_ventas"
ALGORITHM = "HS256"

class AuthService:
    @staticmethod
    def validar_credenciales(correo: str, password: str):
        usuario = UsuarioService.obtener_por_correo(correo)
        # Validación de contraseña plana (en producción usar passlib/bcrypt)
        if usuario and usuario["password"] == password:
            return usuario
        return None

    @staticmethod
    def generar_token_jwt(user_id: int, rol: str):
        # El token expira en 1 hora
        expiracion = datetime.utcnow() + timedelta(hours=1)
        payload = {
            "sub": str(user_id),
            "rol": rol,
            "exp": expiracion
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        return token

    @staticmethod
    def decodificar_token(token: str):
        try:
            # Quitamos la palabra "Bearer " si viene en el header
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None # El token expiró
        except jwt.InvalidTokenError:
            return None # El token es inválido