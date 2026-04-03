from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator

# ==========================================
# 1. NÚCLEO DEL ANÁLISIS (EL "BAG" O BOLSA)
# ==========================================Para implementar esta relación muchos a muchos de forma profesional, vamos a crear el modelo Subida. Este actuará como una "tabla intermedia" que conecta a los usuarios con los análisis globales.
class Analisis(models.Model):
    """
    Representa el análisis global de un binario (único por hash).
    """
    # ELIMINAMOS la línea de usuario de aquí
    nombre_fichero = models.CharField(max_length=255)
    hash_sha256 = models.CharField(max_length=64, unique=True, db_index=True)
    tamano_bytes = models.BigIntegerField(null=True, blank=True)
    
    resultado_clase = models.CharField(max_length=50)
    confianza_global = models.FloatField(
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)]
    )
    probabilidades_json = models.JSONField(help_text="Distribución de probabilidad")
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    call_graph_json = models.JSONField(null=True, blank=True, help_text="Estructura de nodos y aristas")

    class Meta:
        verbose_name_plural = "Análisis"
        ordering = ['-fecha_creacion']

# NUEVO MODELO PARA GESTIONAR LAS SUBIDAS
class Subida(models.Model):
    """
    Relaciona a un usuario con un análisis específico. 
    Permite que varios usuarios 'posean' el mismo resultado de análisis.
    """
    usuario = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mis_subidas')
    analisis = models.ForeignKey(Analisis, on_delete=models.CASCADE, related_name='subidas_relacionadas')
    
    # Guardamos el nombre con el que el usuario subió el archivo (puede variar)
    nombre_fichero_personalizado = models.CharField(max_length=255)
    fecha_subida = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Subidas"
        # Un usuario no puede 'subir' el mismo hash dos veces al historial
        unique_together = ('usuario', 'analisis') 
        ordering = ['-fecha_subida']

# ==========================================
# 2. DETALLE DE INSTANCIAS (LAS FUNCIONES)
# ==========================================
class DetalleFuncion(models.Model):
    """
    Almacena las funciones con mayor peso de atención del modelo MIL.
    Incluye las características (features) que alimentaron al modelo.
    """
    analisis = models.ForeignKey(Analisis, on_delete=models.CASCADE, related_name='detalles_funciones')
    direccion_memoria = models.CharField(max_length=50) # func_addr
    codigo_desensamblado = models.TextField(blank=True, null=True)

    # --- DATOS DEL MODELO MIL ---

    # El valor 'A' (Softmax de atención) que devuelve forward()
    atencion_score = models.FloatField()

    # Corresponde a 'probs_instancias': la predicción individual de esa función
    prediccion_especifica = models.JSONField(
        null=True,
        blank=True,
        help_text="Probabilidades individuales (softmax) de la función"
    )

    # --- CARACTERÍSTICAS DE ENTRADA (FEATURES) ---

    # Aquí guardamos el vector 'x' que entra al modelo MIL
    features_vector = models.JSONField(
        null=True,
        blank=True,
        help_text="Valores numéricos de entrada pasados al modelo (input_dim)"
    )

    # Métricas calculadas para visualización rápida en UI
    num_instrucciones = models.IntegerField(default=0)
    num_llamadas_sistema = models.IntegerField(default=0) # Nueva útil para malware
    entropia = models.FloatField(default=0.0)
    complejidad_ciclomatica = models.IntegerField(default=1)

    class Meta:
        verbose_name_plural = "Detalles de Funciones"
        ordering = ['-atencion_score'] # Prioridad a las funciones que la IA marcó como clave

    def __str__(self):
        return f"Función {self.direccion_memoria} - Score: {self.atencion_score:.4f}"

# ==========================================
# 3. SEGURIDAD Y AUDITORÍA (REQUISITO TFG)
# ==========================================
class LogActividad(models.Model):
    """
    Registra cada acción crítica en el sistema para auditoría forense.
    """
    ACCIONES = [
        ('LOGIN', 'Inicio de Sesión'),
        ('UPLOAD', 'Subida de Binario'),
        ('DELETE', 'Borrado de Historial'),
        ('REPORT', 'Reporte de Falso Positivo'),
    ]
    
    usuario = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    accion = models.CharField(max_length=20, choices=ACCIONES)
    ip_origen = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    detalles = models.TextField(blank=True)

    class Meta:
        verbose_name_plural = "Logs de Actividad"

# ==========================================
# 4. MEJORA CONTINUA (REPETICIÓN Y FEEDBACK)
# ==========================================
class ReporteFalsoPositivo(models.Model):
    """
    Permite que el usuario corrija al modelo. 
    Datos valiosos para el futuro re-entrenamiento.
    """
    analisis = models.OneToOneField(Analisis, on_delete=models.CASCADE)
    clase_sugerida = models.CharField(max_length=50)
    comentario = models.TextField()
    revisado_por_admin = models.BooleanField(default=False)
    fecha_reporte = models.DateTimeField(auto_now_add=True)

class TelemetriaSistema(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    cpu_usage = models.FloatField()
    gpu_usage = models.FloatField()

    class Meta:
        ordering = ['-timestamp']

class MetricasModelo(models.Model):
    clase = models.CharField(max_length=50)
    precision = models.FloatField()
    recall = models.FloatField()
    f1_score = models.FloatField()
    support = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Métricas del Modelo"

    def __str__(self):
        return f"{self.clase} - {self.timestamp.strftime('%Y-%m-%d')}"