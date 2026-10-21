from fastapi import FastAPI, HTTPException, Header, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from sqlalchemy import create_engine, Column, Integer, String, Float, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import jwt
from datetime import datetime, timedelta

# ==========================================
# 1. CONFIGURACIÓN DE BASE DE DATOS (MySQL en XAMPP)
# ==========================================
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://root:@localhost:3306/sistema_ventas"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==========================================
# 2. MODELOS SQL (Tablas del Documento)
# ==========================================
class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(100))
    correo = Column(String(100), unique=True, index=True)
    password = Column(String(255))
    rol = Column(String(50), default="CLIENTE")
    estado = Column(String(50), default="INACTIVO")

class ProductoDB(Base):
    __tablename__ = "productos"
    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(150))
    descripcion = Column(String(500))
    precio = Column(Float)
    categoria = Column(String(100))
    stock = Column(Integer)

class CarritoItemDB(Base):
    __tablename__ = "carritos"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, index=True)
    producto_id = Column(Integer)
    cantidad = Column(Integer)

class OrdenDB(Base):
    __tablename__ = "ordenes"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, index=True)
    direccion_envio = Column(String(255))
    metodo_pago = Column(String(50))
    subtotal = Column(Float)
    costo_envio = Column(Float)
    total = Column(Float)
    estado = Column(String(50), default="PENDIENTE_PAGO")
    fecha_creacion = Column(String(50))

class DetalleOrdenDB(Base):
    __tablename__ = "detalle_orden"
    id = Column(Integer, primary_key=True, index=True)
    orden_id = Column(Integer, index=True)
    producto_id = Column(Integer)
    nombre_producto = Column(String(150))
    cantidad = Column(Integer)
    precio_unitario = Column(Float)
    subtotal = Column(Float)

class PagoDB(Base):
    __tablename__ = "pagos"
    id = Column(Integer, primary_key=True, index=True)
    orden_id = Column(Integer, index=True)
    id_evento = Column(String(100))
    monto = Column(Float)
    estado = Column(String(50))
    fecha_pago = Column(String(50))

class NotificacionDB(Base):
    __tablename__ = "notificaciones"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, index=True)
    tipo = Column(String(100))
    mensaje = Column(String(500))
    fecha = Column(String(50))

class EnvioDB(Base):
    __tablename__ = "envios"
    id = Column(Integer, primary_key=True, index=True)
    orden_id = Column(Integer, unique=True, index=True)
    guia_rastreo = Column(String(100), unique=True, index=True)
    estado_logistico = Column(String(50), default="EN_PREPARACION")
    fecha_actualizacion = Column(String(50))

# Crear todas las tablas en MySQL
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# 3. INICIALIZACIÓN DE FASTAPI Y CORS (Habilitado para LAN)
# ==========================================
app = FastAPI(title="Sistema de Ventas API Monolítica")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "mi_clave_super_secreta_para_ventas"
ALGORITHM = "HS256"

# ==========================================
# 4. MODELOS PYDANTIC (Validación de Entradas)
# ==========================================
class RegistroUsuario(BaseModel):
    nombre: str
    correo: str
    password: str
    rol: Optional[str] = "CLIENTE"

class LoginUsuario(BaseModel):
    correo: str
    password: str

class ValidacionUsuario(BaseModel):
    correo: str
    codigo_validacion: str

class ProductoCrear(BaseModel):
    nombre: str
    descripcion: str
    precio: float
    categoria: str
    stock: int

class ProductoActualizar(BaseModel):
    precio: Optional[float] = None
    stock: Optional[int] = None
    descripcion: Optional[str] = None

class ItemCarrito(BaseModel):
    product_id: int
    quantity: int

class OrdenCrear(BaseModel):
    direccion_envio: str
    metodo_pago: str

class WebhookData(BaseModel):
    order_id: int
    monto: float
    status: str

class WebhookPago(BaseModel):
    id_evento: str
    tipo: str
    data: WebhookData

class EnvioActualizarEstado(BaseModel):
    estado_logistico: Optional[str] = None

# ==========================================
# 5. CAPA DE SERVICIOS DE NEGOCIO
# ==========================================

class AuthService:
    @staticmethod
    def iniciar_sesion(db: Session, credenciales: LoginUsuario):
        user = db.query(UsuarioDB).filter(
            UsuarioDB.correo == credenciales.correo,
            UsuarioDB.password == credenciales.password
        ).first()
        if not user:
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")
        if user.estado != "ACTIVO":
            raise HTTPException(status_code=403, detail="Cuenta inactiva. Valide su cuenta.")

        expiracion = datetime.utcnow() + timedelta(hours=1)
        token = jwt.encode(
            {"sub": str(user.id), "rol": user.rol, "exp": expiracion},
            SECRET_KEY,
            algorithm=ALGORITHM
        )
        return {"token": token, "tipo": "Bearer", "expira_en": 3600}

    @staticmethod
    def decodificar_payload(authorization: Optional[str]) -> dict:
        if not authorization:
            raise HTTPException(status_code=401, detail="Token requerido. Inicia sesión.")
        try:
            token = authorization.split(" ")[1] if authorization.startswith("Bearer ") else authorization
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except Exception:
            raise HTTPException(status_code=401, detail="Token inválido o expirado")

    @staticmethod
    def decodificar_token(authorization: Optional[str]) -> int:
        payload = AuthService.decodificar_payload(authorization)
        return int(payload.get("sub"))

    @staticmethod
    def verificar_admin(authorization: Optional[str]) -> int:
        payload = AuthService.decodificar_payload(authorization)
        if payload.get("rol") != "ADMIN":
            raise HTTPException(
                status_code=403,
                detail="Acceso denegado: Se requieren permisos de ADMINISTRADOR"
            )
        return int(payload.get("sub"))


def obtener_usuario_actual_id(authorization: Optional[str]) -> int:
    return AuthService.decodificar_token(authorization)


class UsuarioService:
    @staticmethod
    def registrar_usuario(db: Session, datos: RegistroUsuario):
        if db.query(UsuarioDB).filter(UsuarioDB.correo == datos.correo).first():
            raise HTTPException(status_code=400, detail="El correo ya está registrado")

        rol_asignado = datos.rol.upper() if datos.rol else "CLIENTE"
        nuevo_user = UsuarioDB(
            nombre=datos.nombre,
            correo=datos.correo,
            password=datos.password,
            rol=rol_asignado
        )
        db.add(nuevo_user)
        db.commit()
        db.refresh(nuevo_user)
        return {"id": nuevo_user.id, "rol": nuevo_user.rol, "mensaje": "Usuario registrado exitosamente"}

    @staticmethod
    def validar_cuenta(db: Session, datos: ValidacionUsuario):
        user = db.query(UsuarioDB).filter(UsuarioDB.correo == datos.correo).first()
        if not user or datos.codigo_validacion != "123456":
            raise HTTPException(status_code=400, detail="Código incorrecto o usuario no encontrado")

        user.estado = "ACTIVO"
        db.commit()
        return {"mensaje": "Cuenta validada y activada exitosamente", "estado": "ACTIVO"}

    @staticmethod
    def obtener_perfil(db: Session, usuario_id: int):
        user = db.query(UsuarioDB).filter(UsuarioDB.id == usuario_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        return {
            "id": user.id,
            "nombre": user.nombre,
            "correo": user.correo,
            "rol": user.rol,
            "estado": user.estado
        }


class InventarioService:
    @staticmethod
    def consultar_stock(db: Session, producto_id: int) -> int:
        prod = db.query(ProductoDB).filter(ProductoDB.id == producto_id).first()
        if not prod:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        return prod.stock

    @staticmethod
    def actualizar_stock(db: Session, producto_id: int, nuevo_stock: int):
        prod = db.query(ProductoDB).filter(ProductoDB.id == producto_id).first()
        if not prod:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        prod.stock = nuevo_stock
        db.commit()
        return {"producto_id": producto_id, "stock": prod.stock, "mensaje": "Stock actualizado correctamente"}


class ProductoService:
    @staticmethod
    def listar_productos(db: Session, category: Optional[str] = None):
        query = db.query(ProductoDB)
        if category:
            query = query.filter(ProductoDB.categoria == category)
        return query.all()

    @staticmethod
    def obtener_producto(db: Session, producto_id: int):
        prod = db.query(ProductoDB).filter(ProductoDB.id == producto_id).first()
        if not prod:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        return prod

    @staticmethod
    def crear_producto(db: Session, producto: ProductoCrear):
        nuevo_prod = ProductoDB(**producto.dict())
        db.add(nuevo_prod)
        db.commit()
        db.refresh(nuevo_prod)
        return {"id": nuevo_prod.id, "mensaje": "Producto creado exitosamente"}

    @staticmethod
    def actualizar_producto(db: Session, producto_id: int, datos: ProductoActualizar):
        prod = ProductoService.obtener_producto(db, producto_id)
        if datos.precio is not None:
            prod.precio = datos.precio
        if datos.descripcion is not None:
            prod.descripcion = datos.descripcion
        if datos.stock is not None:
            InventarioService.actualizar_stock(db, producto_id, datos.stock)
        db.commit()
        return {"id": producto_id, "mensaje": "Producto actualizado correctamente"}


class NotificacionService:
    @staticmethod
    def enviar_correo(db: Session, usuario_id: int, asunto: str, mensaje: str):
        fecha_actual = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        usuario = db.query(UsuarioDB).filter(UsuarioDB.id == usuario_id).first()
        destinatario = f"{usuario.nombre} <{usuario.correo}>" if usuario else f"Usuario ID #{usuario_id}"

        nueva_notificacion = NotificacionDB(
            usuario_id=usuario_id,
            tipo=asunto,
            mensaje=mensaje,
            fecha=fecha_actual
        )
        db.add(nueva_notificacion)
        db.commit()
        db.refresh(nueva_notificacion)

        # Impresión formateada en la consola del servidor
        borde = "=" * 65
        print(f"\n{borde}")
        print("📧 [NOTIFICACIÓN POR CORREO SIMULADA - SISTEMA DE VENTAS]")
        print(borde)
        print(f"  ID Notificación : #{nueva_notificacion.id}")
        print(f"  Fecha (UTC)     : {fecha_actual}")
        print(f"  Para            : {destinatario}")
        print(f"  Asunto (Tipo)   : {asunto}")
        print("-" * 65)
        print(f"  Mensaje:\n  {mensaje}")
        print(f"{borde}\n")

        return nueva_notificacion


class EnvioService:
    ESTADOS_FLUJO = ["EN_PREPARACION", "EN_CAMINO", "ENTREGADO"]

    @staticmethod
    def generar_envio(db: Session, orden_id: int):
        envio_existente = db.query(EnvioDB).filter(EnvioDB.orden_id == orden_id).first()
        if envio_existente:
            return envio_existente

        fecha_actual = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        guia = f"GUIA-MX-2026-{orden_id}"

        nuevo_envio = EnvioDB(
            orden_id=orden_id,
            guia_rastreo=guia,
            estado_logistico="EN_PREPARACION",
            fecha_actualizacion=fecha_actual
        )
        db.add(nuevo_envio)
        db.commit()
        db.refresh(nuevo_envio)
        return nuevo_envio

    @staticmethod
    def consultar_envio(db: Session, orden_id: int):
        envio = db.query(EnvioDB).filter(EnvioDB.orden_id == orden_id).first()
        if not envio:
            raise HTTPException(
                status_code=404,
                detail=f"No existe información de envío para la orden #{orden_id} (verifique que esté pagada)"
            )
        return {
            "id": envio.id,
            "orden_id": envio.orden_id,
            "guia_rastreo": envio.guia_rastreo,
            "estado_logistico": envio.estado_logistico,
            "fecha_actualizacion": envio.fecha_actualizacion
        }

    @staticmethod
    def actualizar_estado_envio(db: Session, orden_id: int, datos: Optional[EnvioActualizarEstado] = None):
        envio = db.query(EnvioDB).filter(EnvioDB.orden_id == orden_id).first()
        if not envio:
            raise HTTPException(
                status_code=404,
                detail=f"Envío no encontrado para la orden #{orden_id}"
            )

        estado_anterior = envio.estado_logistico

        # Si el cliente envía un estado específico válido, se usa; de lo contrario, avanza automáticamente al siguiente
        if datos and datos.estado_logistico:
            nuevo_estado = datos.estado_logistico.upper()
            if nuevo_estado not in EnvioService.ESTADOS_FLUJO:
                raise HTTPException(
                    status_code=400,
                    detail=f"Estado inválido. Estados permitidos: {EnvioService.ESTADOS_FLUJO}"
                )
        else:
            idx_actual = EnvioService.ESTADOS_FLUJO.index(estado_anterior) if estado_anterior in EnvioService.ESTADOS_FLUJO else 0
            if idx_actual >= len(EnvioService.ESTADOS_FLUJO) - 1:
                raise HTTPException(
                    status_code=400,
                    detail="El paquete ya se encuentra en estado ENTREGADO"
                )
            nuevo_estado = EnvioService.ESTADOS_FLUJO[idx_actual + 1]

        envio.estado_logistico = nuevo_estado
        envio.fecha_actualizacion = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Sincronizar estado de la orden si se entrega
        orden = db.query(OrdenDB).filter(OrdenDB.id == orden_id).first()
        if orden:
            if nuevo_estado == "EN_CAMINO":
                orden.estado = "EN_CAMINO"
            elif nuevo_estado == "ENTREGADO":
                orden.estado = "ENTREGADA"

        db.commit()
        db.refresh(envio)

        # Notificar al cliente sobre el avance logístico
        if orden:
            NotificacionService.enviar_correo(
                db=db,
                usuario_id=orden.usuario_id,
                asunto="Actualización de Envío",
                mensaje=(
                    f"Tu paquete de la orden #{orden.id} con guía {envio.guia_rastreo} "
                    f"cambió de estado: {estado_anterior} -> {nuevo_estado}."
                )
            )

        return {
            "mensaje": "Estado logístico actualizado correctamente",
            "orden_id": envio.orden_id,
            "guia_rastreo": envio.guia_rastreo,
            "estado_anterior": estado_anterior,
            "estado_actual": envio.estado_logistico,
            "fecha_actualizacion": envio.fecha_actualizacion
        }


class ReporteService:
    ESTADOS_PAGADOS = ["PAGADA", "PAGADA_EN_PREPARACION", "EN_CAMINO", "ENTREGADA"]

    @staticmethod
    def obtener_ingresos_totales(db: Session):
        ingresos = db.query(func.sum(OrdenDB.total)).filter(
            OrdenDB.estado.in_(ReporteService.ESTADOS_PAGADOS)
        ).scalar()
        cantidad_pagadas = db.query(func.count(OrdenDB.id)).filter(
            OrdenDB.estado.in_(ReporteService.ESTADOS_PAGADOS)
        ).scalar()
        return {
            "total_ingresos": round(float(ingresos or 0.0), 2),
            "ordenes_pagadas_contabilizadas": cantidad_pagadas or 0
        }

    @staticmethod
    def obtener_ordenes_por_estado(db: Session):
        resultados = db.query(
            OrdenDB.estado,
            func.count(OrdenDB.id).label("cantidad")
        ).group_by(OrdenDB.estado).all()

        desglose = {estado: cantidad for estado, cantidad in resultados}
        return {
            "total_ordenes": sum(desglose.values()),
            "ordenes_por_estado": desglose
        }

    @staticmethod
    def obtener_productos_bajo_stock(db: Session, limite: int = 5):
        productos = db.query(ProductoDB).filter(ProductoDB.stock < limite).order_by(ProductoDB.stock.asc()).all()
        return {
            "umbral_stock": limite,
            "cantidad_productos_criticos": len(productos),
            "productos": [
                {
                    "id": p.id,
                    "nombre": p.nombre,
                    "categoria": p.categoria,
                    "precio": p.precio,
                    "stock_actual": p.stock
                } for p in productos
            ]
        }

    @staticmethod
    def obtener_dashboard_completo(db: Session, limite_stock: int = 5):
        ingresos = ReporteService.obtener_ingresos_totales(db)
        ordenes_estado = ReporteService.obtener_ordenes_por_estado(db)
        bajo_stock = ReporteService.obtener_productos_bajo_stock(db, limite_stock)

        return {
            "fecha_generacion": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ingresos": ingresos,
            "resumen_ordenes": ordenes_estado,
            "alertas_inventario": bajo_stock
        }


class CarritoService:
    @staticmethod
    def obtener_carrito(db: Session, usuario_id: int):
        items_db = db.query(CarritoItemDB).filter(CarritoItemDB.usuario_id == usuario_id).all()
        items_respuesta = []
        subtotal_carrito = 0.0

        for item in items_db:
            prod = db.query(ProductoDB).filter(ProductoDB.id == item.producto_id).first()
            if prod:
                sub = round(prod.precio * item.cantidad, 2)
                subtotal_carrito += sub
                items_respuesta.append({
                    "product_id": prod.id,
                    "nombre": prod.nombre,
                    "cantidad": item.cantidad,
                    "precio_unitario": prod.precio,
                    "subtotal_item": sub
                })
        return {"items": items_respuesta, "subtotal_carrito": round(subtotal_carrito, 2)}

    @staticmethod
    def agregar_item(db: Session, usuario_id: int, product_id: int, quantity: int):
        prod = db.query(ProductoDB).filter(ProductoDB.id == product_id).first()
        if not prod:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        if prod.stock < quantity:
            raise HTTPException(status_code=400, detail=f"Stock insuficiente. Disponible: {prod.stock}")

        item_existente = db.query(CarritoItemDB).filter(
            CarritoItemDB.usuario_id == usuario_id,
            CarritoItemDB.producto_id == product_id
        ).first()

        if item_existente:
            if prod.stock < (item_existente.cantidad + quantity):
                raise HTTPException(status_code=400, detail=f"Stock insuficiente para sumar. Disponible: {prod.stock}")
            item_existente.cantidad += quantity
        else:
            nuevo_item = CarritoItemDB(usuario_id=usuario_id, producto_id=product_id, cantidad=quantity)
            db.add(nuevo_item)

        db.commit()
        carrito_actual = CarritoService.obtener_carrito(db, usuario_id)
        return {"mensaje": "Producto agregado al carrito", "subtotal_carrito": carrito_actual["subtotal_carrito"]}

    @staticmethod
    def eliminar_item(db: Session, usuario_id: int, product_id: int):
        item = db.query(CarritoItemDB).filter(
            CarritoItemDB.usuario_id == usuario_id,
            CarritoItemDB.producto_id == product_id
        ).first()
        if not item:
            raise HTTPException(status_code=404, detail="El producto no está en el carrito")
        db.delete(item)
        db.commit()
        return {"mensaje": "Producto eliminado del carrito"}


class OrdenService:
    @staticmethod
    def crear_orden(db: Session, usuario_id: int, datos: OrdenCrear):
        items_db = db.query(CarritoItemDB).filter(CarritoItemDB.usuario_id == usuario_id).all()
        if not items_db:
            raise HTTPException(status_code=400, detail="Tu carrito está vacío")

        subtotal = 0.0
        detalles_para_guardar = []

        # Validar stock y calcular subtotales congelando el precio
        for item in items_db:
            prod = db.query(ProductoDB).filter(ProductoDB.id == item.producto_id).first()
            if not prod or prod.stock < item.cantidad:
                nombre_p = prod.nombre if prod else f"ID {item.producto_id}"
                raise HTTPException(status_code=400, detail=f"Stock insuficiente para {nombre_p}")
            
            sub_item = round(prod.precio * item.cantidad, 2)
            subtotal += sub_item
            detalles_para_guardar.append((prod, item.cantidad, sub_item))

        costo_envio = 100.00
        total = round(subtotal + costo_envio, 2)

        nueva_orden = OrdenDB(
            usuario_id=usuario_id,
            direccion_envio=datos.direccion_envio,
            metodo_pago=datos.metodo_pago,
            subtotal=round(subtotal, 2),
            costo_envio=costo_envio,
            total=total,
            estado="PENDIENTE_PAGO",
            fecha_creacion=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        db.add(nueva_orden)
        db.commit()
        db.refresh(nueva_orden)

        # Descontar stock definitivo y registrar detalle de orden
        for prod, cantidad, sub_item in detalles_para_guardar:
            prod.stock -= cantidad
            detalle = DetalleOrdenDB(
                orden_id=nueva_orden.id,
                producto_id=prod.id,
                nombre_producto=prod.nombre,
                cantidad=cantidad,
                precio_unitario=prod.precio,
                subtotal=sub_item
            )
            db.add(detalle)

        # Vaciar el carrito del usuario
        db.query(CarritoItemDB).filter(CarritoItemDB.usuario_id == usuario_id).delete()
        db.commit()

        return {
            "order_id": nueva_orden.id,
            "estado": nueva_orden.estado,
            "subtotal": nueva_orden.subtotal,
            "costo_envio": nueva_orden.costo_envio,
            "total": nueva_orden.total,
            "url_pago": "url_de_pago_generada"
        }

    @staticmethod
    def consultar_orden(db: Session, orden_id: int, usuario_id: int):
        orden = db.query(OrdenDB).filter(OrdenDB.id == orden_id, OrdenDB.usuario_id == usuario_id).first()
        if not orden:
            raise HTTPException(status_code=404, detail="Orden no encontrada")
        detalles = db.query(DetalleOrdenDB).filter(DetalleOrdenDB.orden_id == orden.id).all()
        envio = db.query(EnvioDB).filter(EnvioDB.orden_id == orden.id).first()
        guia = envio.guia_rastreo if envio else (f"GUIA-MX-2026-{orden.id}" if orden.estado != "PENDIENTE_PAGO" else None)

        return {
            "order_id": orden.id,
            "estado": orden.estado,
            "subtotal": orden.subtotal,
            "costo_envio": orden.costo_envio,
            "total": orden.total,
            "direccion_envio": orden.direccion_envio,
            "metodo_pago": orden.metodo_pago,
            "fecha_creacion": orden.fecha_creacion,
            "guia_rastreo": guia,
            "estado_logistico": envio.estado_logistico if envio else None,
            "productos": [
                {
                    "nombre": d.nombre_producto,
                    "cantidad": d.cantidad,
                    "precio_unitario": d.precio_unitario,
                    "subtotal": d.subtotal
                } for d in detalles
            ]
        }

    @staticmethod
    def listar_ordenes_usuario(db: Session, usuario_id: int):
        ordenes = db.query(OrdenDB).filter(OrdenDB.usuario_id == usuario_id).order_by(OrdenDB.id.desc()).all()
        respuesta = []
        for o in ordenes:
            envio = db.query(EnvioDB).filter(EnvioDB.orden_id == o.id).first()
            guia = envio.guia_rastreo if envio else (f"GUIA-MX-2026-{o.id}" if o.estado != "PENDIENTE_PAGO" else None)
            respuesta.append({
                "order_id": o.id,
                "estado": o.estado,
                "total": o.total,
                "direccion_envio": o.direccion_envio,
                "fecha_creacion": o.fecha_creacion,
                "guia_rastreo": guia,
                "estado_logistico": envio.estado_logistico if envio else None
            })
        return respuesta


class PagoService:
    @staticmethod
    def procesar_webhook(db: Session, payload: WebhookPago):
        orden = db.query(OrdenDB).filter(OrdenDB.id == payload.data.order_id).first()
        if not orden:
            raise HTTPException(status_code=404, detail="Orden no encontrada para aplicar el pago")

        pago_exitoso = payload.data.status.lower() == "paid" or payload.tipo == "charge.succeeded"

        if pago_exitoso:
            orden.estado = "PAGADA_EN_PREPARACION"
            estado_Texto = "PAGADA"
        else:
            orden.estado = "PAGO_RECHAZADO"
            estado_Texto = "RECHAZADA"

        nuevo_pago = PagoDB(
            orden_id=orden.id,
            id_evento=payload.id_evento,
            monto=payload.data.monto,
            estado=estado_Texto,
            fecha_pago=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        db.add(nuevo_pago)
        db.commit()

        guia_generada = None
        if pago_exitoso:
            # 1. Generar envío automáticamente con guía de rastreo
            envio = EnvioService.generar_envio(db, orden.id)
            guia_generada = envio.guia_rastreo

            # 2. Inyectar NotificacionService para alertar al cliente en BD y consola
            NotificacionService.enviar_correo(
                db=db,
                usuario_id=orden.usuario_id,
                asunto="Confirmación de Pago",
                mensaje=(
                    f"¡Hola! Tu pago por ${orden.total:.2f} MXN para la orden #{orden.id} "
                    f"fue aprobado exitosamente. Guía de envío asignada: {guia_generada}."
                )
            )

        return {
            "recibido": True,
            "guia_rastreo": guia_generada,
            "mensaje": f"Webhook procesado. Orden {orden.id} actualizada a {estado_Texto}."
        }


# ==========================================
# 6. ENDPOINTS: AUTH Y USUARIOS
# ==========================================
@app.post("/api/v1/auth/register", status_code=201, tags=["Auth"])
async def registrar_cliente(usuario: RegistroUsuario, db: Session = Depends(get_db)):
    return UsuarioService.registrar_usuario(db, usuario)

@app.post("/api/v1/auth/validate", tags=["Auth"])
async def validar_cuenta(datos: ValidacionUsuario, db: Session = Depends(get_db)):
    return UsuarioService.validar_cuenta(db, datos)

@app.post("/api/v1/auth/login", tags=["Auth"])
async def iniciar_sesion(usuario: LoginUsuario, db: Session = Depends(get_db)):
    return AuthService.iniciar_sesion(db, usuario)

@app.get("/api/v1/users/me", tags=["Auth"])
async def obtener_perfil(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user_id = AuthService.decodificar_token(authorization)
    return UsuarioService.obtener_perfil(db, user_id)

# ==========================================
# 7. ENDPOINTS: CATÁLOGO, PRODUCTOS E INVENTARIO
# ==========================================
@app.get("/api/v1/products", tags=["Catálogo"])
async def listar_productos(category: Optional[str] = None, db: Session = Depends(get_db)):
    return ProductoService.listar_productos(db, category)

@app.get("/api/v1/products/{id}", tags=["Catálogo"])
async def obtener_producto(id: int, db: Session = Depends(get_db)):
    return ProductoService.obtener_producto(db, id)

@app.post("/api/v1/products", status_code=201, tags=["Catálogo"])
async def crear_producto(producto: ProductoCrear, db: Session = Depends(get_db)):
    return ProductoService.crear_producto(db, producto)

@app.put("/api/v1/products/{id}", tags=["Catálogo"])
async def actualizar_producto(id: int, datos: ProductoActualizar, db: Session = Depends(get_db)):
    return ProductoService.actualizar_producto(db, id, datos)

# ==========================================
# 8. ENDPOINTS: CARRITO (CarritoService)
# ==========================================
@app.get("/api/v1/cart", tags=["Carrito"])
async def obtener_carrito(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user_id = obtener_usuario_actual_id(authorization)
    return CarritoService.obtener_carrito(db, user_id)

@app.post("/api/v1/cart/items", tags=["Carrito"])
async def agregar_al_carrito(item: ItemCarrito, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user_id = obtener_usuario_actual_id(authorization)
    return CarritoService.agregar_item(db, user_id, item.product_id, item.quantity)

@app.delete("/api/v1/cart/items/{product_id}", tags=["Carrito"])
async def eliminar_del_carrito(product_id: int, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user_id = obtener_usuario_actual_id(authorization)
    return CarritoService.eliminar_item(db, user_id, product_id)

# ==========================================
# 9. ENDPOINTS: ÓRDENES Y PAGOS (OrdenService y PagoService)
# ==========================================
@app.post("/api/v1/orders", status_code=201, tags=["Órdenes y Pagos"])
async def crear_orden(orden: OrdenCrear, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user_id = obtener_usuario_actual_id(authorization)
    return OrdenService.crear_orden(db, user_id, orden)

@app.get("/api/v1/orders", tags=["Órdenes y Pagos"])
async def listar_mis_ordenes(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user_id = obtener_usuario_actual_id(authorization)
    return OrdenService.listar_ordenes_usuario(db, user_id)

@app.get("/api/v1/orders/{id}", tags=["Órdenes y Pagos"])
async def consultar_orden(id: int, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user_id = obtener_usuario_actual_id(authorization)
    return OrdenService.consultar_orden(db, id, user_id)

@app.post("/api/v1/payments/webhook", tags=["Órdenes y Pagos"])
async def webhook_pagos(payload: WebhookPago, webhook_signature: Optional[str] = Header(None), db: Session = Depends(get_db)):
    return PagoService.procesar_webhook(db, payload)

# ==========================================
# 10. ENDPOINTS: ENVÍOS Y LOGÍSTICA (EnvioService)
# ==========================================
@app.get("/api/v1/shipping/{orden_id}", tags=["Logística y Envíos"])
async def consultar_envio(orden_id: int, db: Session = Depends(get_db)):
    return EnvioService.consultar_envio(db, orden_id)

@app.put("/api/v1/shipping/{orden_id}/status", tags=["Logística y Envíos"])
async def actualizar_estado_envio(
    orden_id: int,
    datos: Optional[EnvioActualizarEstado] = Body(default=None),
    db: Session = Depends(get_db)
):
    return EnvioService.actualizar_estado_envio(db, orden_id, datos)

# ==========================================
# 11. ENDPOINTS: REPORTES DE ADMINISTRADOR (ReporteService)
# ==========================================
@app.get("/api/v1/admin/reports", tags=["Admin - Reportes"])
async def obtener_reporte_general(
    low_stock_threshold: int = 5,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    AuthService.verificar_admin(authorization)
    return ReporteService.obtener_dashboard_completo(db, low_stock_threshold)

@app.get("/api/v1/admin/reports/income", tags=["Admin - Reportes"])
async def obtener_reporte_ingresos(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    AuthService.verificar_admin(authorization)
    return ReporteService.obtener_ingresos_totales(db)

@app.get("/api/v1/admin/reports/orders-by-status", tags=["Admin - Reportes"])
async def obtener_reporte_ordenes_estado(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    AuthService.verificar_admin(authorization)
    return ReporteService.obtener_ordenes_por_estado(db)

@app.get("/api/v1/admin/reports/low-stock", tags=["Admin - Reportes"])
async def obtener_reporte_bajo_stock(
    threshold: int = 5,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    AuthService.verificar_admin(authorization)
    return ReporteService.obtener_productos_bajo_stock(db, threshold)
