# servicios/auth_service.py
import os
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
from servicios.usuario_service import UsuarioService

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Falta la variable de entorno crítica JWT_SECRET_KEY en el archivo .env")

ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

class AuthService:
    @staticmethod
    def validar_credenciales(correo: str, password: str):
        usuario = UsuarioService.obtener_por_correo(correo)
        # Validación de contraseña mediante hash seguro (pbkdf2 / scrypt)
        if usuario and check_password_hash(usuario["password"], password):
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
