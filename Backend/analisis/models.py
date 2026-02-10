from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator

# ==========================================
# 1. NÚCLEO DEL ANÁLISIS (EL "BAG" O BOLSA)
# ==========================================
class Analisis(models.Model):
    """
    Representa el análisis global de un binario. 
    Cumple con el objetivo de Trazabilidad y Persistencia.
    """
    usuario = models.ForeignKey(User, on_delete=models.CASCADE, related_name='analisis_realizados')
    nombre_fichero = models.CharField(max_length=255)
    hash_sha256 = models.CharField(max_length=64, unique=True, db_index=True)
    tamano_bytes = models.BigIntegerField(null=True, blank=True)
    
    # Resultados del modelo
    resultado_clase = models.CharField(max_length=50) # Benigno, Financiero, etc.
    confianza_global = models.FloatField(
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)]
    )
    
    # Guardamos el array completo de probabilidades de las 5 clases en JSONB
    # Ejemplo: {"Benigno": 0.05, "Financiero": 0.80, ...}
    probabilidades_json = models.JSONField(help_text="Distribución de probabilidad de todas las clases")
    
    fecha_creacion = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Análisis"
        ordering = ['-fecha_creacion']

    def __str__(self):
        return f"{self.nombre_fichero} ({self.resultado_clase})"

# ==========================================
# 2. DETALLE DE INSTANCIAS (LAS FUNCIONES)
# ==========================================
class DetalleFuncion(models.Model):
    """
    Almacena las funciones con mayor peso de atención del modelo MIL.
    Esencial para la "Explicabilidad" de la IA.
    """
    analisis = models.ForeignKey(Analisis, on_delete=models.CASCADE, related_name='detalles_funciones')
    direccion_memoria = models.CharField(max_length=50) # func_addr
    
    # El valor 'A' (Atención) que devuelve tu modelo para esta función
    atencion_score = models.FloatField()
    
    prediccion_especifica = models.JSONField(null=True, blank=True)

    # Resumen de características para el frontend
    num_instrucciones = models.IntegerField(default=0)
    entropia = models.FloatField(default=0.0)
    
    class Meta:
        verbose_name_plural = "Detalles de Funciones"
        ordering = ['-atencion_score'] # Las más sospechosas primero

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
    timestamp = models.DateTimeField(auto_now_add=True)
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