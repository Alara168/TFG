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
        fields = ['id', 'usuario', 'accion', 'fecha', 'detalles', 'ip_origen']

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

class HistorialSimplificadoSerializer(serializers.ModelSerializer):
    # Traemos campos específicos del objeto Analisis relacionado
    resultado_clase = serializers.CharField(source='analisis.resultado_clase', read_only=True)
    confianza_global = serializers.FloatField(source='analisis.confianza_global', read_only=True)
    hash_sha256 = serializers.CharField(source='analisis.hash_sha256', read_only=True)
    tamano_bytes = serializers.IntegerField(source='analisis.tamano_bytes', read_only=True)
    id_analisis = serializers.IntegerField(source='analisis.id', read_only=True)
    
    # Formateamos la fecha de subida del usuario
    fecha_subida = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S", read_only=True)

    class Meta:
        model = Subida
        fields = [
            'id_analisis',
            'nombre_fichero_personalizado', 
            'hash_sha256', 
            'resultado_clase', 
            'confianza_global', 
            'tamano_bytes',
            'fecha_subida'
        ]

#SERIALIZERS FANTASMAS PARA LA DOCUMENTACIÓN
class AnalizarBinarioInputSerializer(serializers.Serializer):
    archivo = serializers.FileField(help_text="Archivo ejecutable de Windows (PE)")
    enable_pseudo_label = serializers.BooleanField(default=False, help_text="Activar etiquetado pseudo-label")

from rest_framework import serializers

class KPIISerializer(serializers.Serializer):
    gpu_load = serializers.IntegerField()
    cpu_load = serializers.FloatField()
    active_users = serializers.IntegerField()
    dataset_size = serializers.CharField()

class ResourceUsageSerializer(serializers.Serializer):
    time = serializers.CharField()
    cpu = serializers.FloatField()
    gpu = serializers.FloatField()

class ModelPerformanceSerializer(serializers.Serializer):
    name = serializers.CharField()
    precision = serializers.FloatField()
    recall = serializers.FloatField()
    f1 = serializers.FloatField()

class AdminDashboardResponseSerializer(serializers.Serializer):
    kpis = KPIISerializer()
    active_users_list = serializers.ListField(child=serializers.CharField())
    charts = serializers.JSONField(help_text="Contiene resource_usage y model_performance")
    pseudo_labels = serializers.ListField(child=serializers.JSONField())
    user_logs = serializers.ListField(child=serializers.JSONField())
    user_reputation = serializers.ListField(child=serializers.JSONField())

class FunciónFiltradaSerializer(serializers.Serializer):
    direccion_memoria = serializers.CharField()
    atencion_score = serializers.FloatField()
    num_instrucciones = serializers.IntegerField()
    entropia = serializers.FloatField()
    complejidad = serializers.IntegerField()

class DatasetExplorerResponseSerializer(serializers.Serializer):
    nombre_fichero = serializers.CharField()
    resultado_clase = serializers.CharField()
    confianza_global = serializers.FloatField()
    hash_sha256 = serializers.CharField()
    detalles_funciones = FunciónFiltradaSerializer(many=True)

class CallGraphNodeSerializer(serializers.Serializer):
    id = serializers.CharField(help_text="ID único del nodo (dirección de memoria)")
    label = serializers.CharField(help_text="Etiqueta corta para visualización")
    atencion_score = serializers.FloatField(help_text="Puntuación de atención de la IA")
    is_critical = serializers.BooleanField(default=True)

class CallGraphEdgeSerializer(serializers.Serializer):
    source = serializers.CharField(help_text="ID del nodo origen")
    target = serializers.CharField(help_text="ID del nodo destino")
    label = serializers.CharField(default="bypass")

class CallGraphResponseSerializer(serializers.Serializer):
    nodes = CallGraphNodeSerializer(many=True)
    edges = CallGraphEdgeSerializer(many=True)
    metodo = serializers.CharField(default="bypass")
    procesado = serializers.BooleanField(default=True)