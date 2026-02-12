from rest_framework import serializers
from .models import Analisis, DetalleFuncion, LogActividad, Subida
from django.contrib.auth.models import User

class DetalleFuncionSerializer(serializers.ModelSerializer):
    """
    Serializador para las funciones específicas identificadas por el modelo MIL
    y su correspondiente score de atención (XAI).
    """
    class Meta:
        model = DetalleFuncion
        fields = ['direccion_memoria', 'atencion_score', 'prediccion_especifica']

class AnalisisSerializer(serializers.ModelSerializer):
    """
    Serializador principal para los resultados del análisis de malware.
    Incluye la relación anidada de los detalles de las funciones sospechosas.
    """
    # Relación Reverse ForeignKey: permite ver los detalles de funciones dentro del análisis
    detalles_funciones = DetalleFuncionSerializer(many=True, read_only=True)
    
    # Formateamos la fecha para que sea más legible en el Frontend (Opcional)
    fecha_creacion = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S", read_only=True)

    class Meta:
        model = Analisis
        fields = [
            'id',  
            'nombre_fichero', 
            'hash_sha256', 
            'tamano_bytes', 
            'resultado_clase', 
            'confianza_global', 
            'probabilidades_json', 
            'fecha_creacion', 
            'detalles_funciones'
        ]
        read_only_fields = ['id', 'fecha_creacion', 'detalles_funciones']

class LogActividadSerializer(serializers.ModelSerializer):
    """
    Serializador para el historial de acciones realizadas en la plataforma.
    """
    class Meta:
        model = LogActividad
        fields = ['id', 'usuario', 'accion', 'fecha', 'detalles']

class RegistroSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'first_name', 'last_name']

    def create(self, validated_data):
        # Usamos create_user para que la contraseña se guarde con hash y no en texto plano
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        return user

class HistorialSubidasSerializer(serializers.ModelSerializer):
    # Incluimos los datos del análisis anidados
    detalles_analisis = AnalisisSerializer(source='analisis', read_only=True)
    
    class Meta:
        model = Subida
        fields = ['id', 'nombre_fichero_personalizado', 'fecha_subida', 'detalles_analisis']

class HistorialSimplificadoSerializer(serializers.ModelSerializer):
    # Traemos campos específicos del objeto Analisis relacionado
    resultado_clase = serializers.CharField(source='analisis.resultado_clase', read_only=True)
    confianza_global = serializers.FloatField(source='analisis.confianza_global', read_only=True)
    hash_sha256 = serializers.CharField(source='analisis.hash_sha256', read_only=True)
    tamano_bytes = serializers.IntegerField(source='analisis.tamano_bytes', read_only=True)
    
    # Formateamos la fecha de subida del usuario
    fecha_subida = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S", read_only=True)

    class Meta:
        model = Subida
        fields = [
            'id', 
            'nombre_fichero_personalizado', 
            'hash_sha256', 
            'resultado_clase', 
            'confianza_global', 
            'tamano_bytes',
            'fecha_subida'
        ]