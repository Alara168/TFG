from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .utils import calcular_sha256, extract_features, get_resources
from .models import Analisis, DetalleFuncion, LogActividad, Subida
from .serializers import AnalisisSerializer, HistorialSimplificadoSerializer
import torch, pandas as pd
from rest_framework import generics
#TODO: no usar Allow Any
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.models import User
from .serializers import RegistroSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class AnalizarBinarioView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file_obj = request.FILES.get('archivo')
        if not file_obj: 
            return Response({"error": "No se proporcionó ningún archivo."}, status=400)

        user_actual = request.user 
        h = calcular_sha256(file_obj)

        # 1. BUSQUEDA GLOBAL: ¿Alguien ha analizado este archivo ya?
        analisis_obj = Analisis.objects.filter(hash_sha256=h).first()

        if not analisis_obj:
            # --- PROCESAMIENTO DE IA (Solo si el hash es nuevo) ---
            model, pipeline = get_resources()
            raw_feats, addrs = extract_features(file_obj)
            
            if raw_feats is None or len(raw_feats) == 0:
                return Response({"error": "Error al procesar el binario o extraer funciones."}, status=422)

            # Inferencia con Pandas y Torch
            df = pd.DataFrame(raw_feats)
            for col in pipeline['feature_cols']:
                if col not in df.columns: df[col] = 0
            df = df[pipeline['feature_cols']]
            
            scaled_feats = pipeline['scaler'].transform(df.astype(float))
            bag_tensor = torch.tensor(scaled_feats, dtype=torch.float32)

            with torch.no_grad():
                # El forward devuelve: logits_global, pesos_atencion, probs_instancias
                logits_global, A, probs_instancias_tensor = model(bag_tensor)
                
                probs_global = torch.sigmoid(logits_global).cpu().numpy()[0]
                probs_instancias = probs_instancias_tensor.cpu().numpy()
                attn = A.cpu().numpy()[0]

            # Guardar el Análisis Global
            idx_max = probs_global.argmax()
            clases_nombres = pipeline['nombres']
            
            analisis_obj = Analisis.objects.create(
                nombre_fichero=file_obj.name, 
                hash_sha256=h, 
                tamano_bytes=file_obj.size,
                resultado_clase=clases_nombres[idx_max], 
                confianza_global=float(probs_global[idx_max]),
                probabilidades_json={n: float(p) for n, p in zip(clases_nombres, probs_global)}
            )

            # Guardar el TOP 5 de funciones por atención (Explicabilidad)
            top_i = attn.argsort()[-5:][::-1]
            for i in top_i:
                set_probs = {clases_nombres[j]: float(probs_instancias[i][j]) for j in range(len(clases_nombres))}
                DetalleFuncion.objects.create(
                    analisis=analisis_obj, 
                    direccion_memoria=addrs[i], 
                    atencion_score=float(attn[i]), 
                    prediccion_especifica=set_probs
                )
        
        # 2. VINCULACIÓN: Crear la relación entre el usuario actual y el análisis
        # Usamos update_or_create por si el usuario re-sube el mismo archivo, 
        # así actualizamos la fecha de su historial personal.
        subida_rel, created = Subida.objects.update_or_create(
            usuario=user_actual,
            analisis=analisis_obj,
            defaults={'nombre_fichero_personalizado': file_obj.name}
        )

        # 3. AUDITORÍA Y RESPUESTA
        log_msg = f"Subida exitosa: {file_obj.name}" if created else f"Re-subida (caché): {file_obj.name}"
        LogActividad.objects.create(
            usuario=user_actual, 
            accion='UPLOAD', 
            detalles=log_msg
        )

        return Response(AnalisisSerializer(analisis_obj).data)

class HistorialAnalisisView(generics.ListAPIView):
    """
    Devuelve el historial de archivos que el usuario actual ha subido,
    incluyendo los resultados del análisis de cada uno.
    """
    serializer_class = HistorialSimplificadoSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Filtramos por el usuario del JWT y ordenamos por lo más reciente
        return Subida.objects.filter(usuario=self.request.user).order_by('-fecha_subida')

class DetalleAnalisisView(generics.RetrieveAPIView):
    serializer_class = AnalisisSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Si el análisis con ese ID no es del usuario, devolverá 404 automáticamente
        return Analisis.objects.filter(usuario=self.request.user)

class RegistroUsuarioView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegistroSerializer

class CustomJWTSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        
        # Añadimos información extra a la respuesta
        data['user_id'] = self.user.id
        data['username'] = self.user.username
        data['email'] = self.user.email
        return data

class CustomLoginView(TokenObtainPairView):
    serializer_class = CustomJWTSerializer