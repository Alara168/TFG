from django.db import models
from django.contrib.auth.models import User

class AnalisisBinario(models.Model):
    usuario = models.ForeignKey(User, on_delete=models.CASCADE)
    nombre_fichero = models.CharField(max_length=255)
    hash_sha256 = models.CharField(max_length=64, unique=True)
    resultado = models.CharField(max_length=50) # Benigno, Financiero...
    puntuacion_atencion = models.JSONField() # Aquí guardas los scores de las funciones
    fecha_creacion = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.nombre_fichero} - {self.resultado}"