from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .utils import calcular_sha256, extract_features, get_resources
from .models import Analisis, DetalleFuncion, LogActividad
from .serializers import AnalisisSerializer
import torch, pandas as pd
from rest_framework import generics
#TODO: no usar Allow Any
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.models import User


class AnalizarBinarioView(APIView):
    def post(self, request):
        file_obj = request.FILES.get('archivo')
        if not file_obj: 
            return Response({"error": "No se proporcionó ningún archivo."}, status=400)

        # TODO: hacer que sea siempre request.user
        # 1. Gestión de Usuario (Fingir admin si es anónimo para evitar errores)
        user_final = request.user if request.user.is_authenticated else User.objects.filter(is_superuser=True).first()

        # 2. Verificación de caché por Hash
        h = calcular_sha256(file_obj)
        cached = Analisis.objects.filter(hash_sha256=h).first()
        if cached: 
            return Response(AnalisisSerializer(cached).data)

        file_size = file_obj.size
        model, pipeline = get_resources()

        # 3. Extracción de características (SMDA)
        print(f"DEBUG: Procesando archivo: {file_obj.name} ({file_size} bytes)")
        raw_feats, addrs = extract_features(file_obj)
        
        if raw_feats is None:
            return Response({"error": "Fallo crítico en el desensamblado estático."}, status=500)

        if len(raw_feats) == 0:
            return Response({"error": "No se encontraron funciones analizables en el binario."}, status=422)

        # 4. Preparación de datos para el modelo
        df = pd.DataFrame(raw_feats)
        for col in pipeline['feature_cols']:
            if col not in df.columns:
                df[col] = 0
        
        df = df[pipeline['feature_cols']]
        
        # Escalado y conversión a tensor
        scaled_feats = pipeline['scaler'].transform(df.astype(float))
        bag_tensor = torch.tensor(scaled_feats, dtype=torch.float32)

        # 5. Inferencia con lógica Multifamilia
        with torch.no_grad():
            # El modelo ya devuelve: logits_global, atención, y probabilidades por instancia
            logits_global, A, probs_instancias_tensor = model(bag_tensor)
            
            # Probabilidades globales (sigmoid para multifamilia)
            probs_global = torch.sigmoid(logits_global).cpu().numpy()[0]
            
            # Probabilidades por función (ya vienen calculadas del forward del modelo)
            # Solo las pasamos a numpy
            probs_instancias = probs_instancias_tensor.cpu().numpy()
            
            attn = A.cpu().numpy()[0]

        # 6. Guardar el Análisis Principal
        # En multifamilia, el resultado_clase suele ser el de mayor probabilidad
        idx_max = probs_global.argmax()
        clases_nombres = pipeline['nombres']
        
        res = Analisis.objects.create(
            usuario=user_final, 
            nombre_fichero=file_obj.name, 
            hash_sha256=h, 
            tamano_bytes=file_size,
            resultado_clase=clases_nombres[idx_max], 
            confianza_global=float(probs_global[idx_max]),
            probabilidades_json={n: float(p) for n, p in zip(clases_nombres, probs_global)}
        )

        # 7. Guardar Detalles de Funciones con probabilidades específicas (XAI Local)
        top_i = attn.argsort()[-5:][::-1]
        for i in top_i:
            # Creamos el set de probabilidades para esta función concreta
            set_probabilidades_func = {
                clases_nombres[j]: float(probs_instancias[i][j]) 
                for j in range(len(clases_nombres))
            }
            
            DetalleFuncion.objects.create(
                analisis=res, 
                direccion_memoria=addrs[i], 
                atencion_score=float(attn[i]),
                # Asegúrate de haber añadido este campo JSONField en tu modelo DetalleFuncion
                prediccion_especifica=set_probabilidades_func 
            )

        # 8. Registro de actividad y respuesta
        LogActividad.objects.create(
            usuario=user_final, 
            accion='UPLOAD', 
            detalles=f"Analizado {file_obj.name} - Detectado como {clases_nombres[idx_max]}"
        )
        
        return Response(AnalisisSerializer(res).data)

class HistorialAnalisisView(generics.ListAPIView):
    serializer_class = AnalisisSerializer
    # Solo usuarios logueados pueden ver su historial
    # (Para pruebas en Postman, si no mandas Token, usaremos el admin por defecto)
    permission_classes = [IsAuthenticated] 
    permission_classes = [AllowAny]

    def get_queryset(self):
        user = self.request.user
        if user.is_anonymous:
            from django.contrib.auth.models import User
            user = User.objects.filter(is_superuser=True).first()
            
        return Analisis.objects.filter(usuario=user).order_by('-fecha_creacion')