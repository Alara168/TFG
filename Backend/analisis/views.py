from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .utils import calcular_sha256, extract_features, get_resources, registrar_log, desensamblar_funcion
from .models import Analisis, DetalleFuncion, LogActividad, Subida, TelemetriaSistema, MetricasModelo
from .serializers import AnalisisSerializer, HistorialSimplificadoSerializer
import torch, pandas as pd
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.models import User
from .serializers import RegistroSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
import networkx as nx
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
import psutil
from django.db.models import Count, Max, Sum, F, Case, When, FloatField
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from datetime import timedelta
import GPUtil

RECURSOS_IA = None

def obtener_recursos_cache():
    global RECURSOS_IA
    if RECURSOS_IA is None:
        RECURSOS_IA = get_resources()
    return RECURSOS_IA

class AnalizarBinarioView(APIView):
    permission_classes = [IsAuthenticated]
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def validate_pe(self, file_obj):
        """
        Verifica si el archivo es un ejecutable de Windows (PE) 
        leyendo los 'Magic Bytes'.
        """
        # Los archivos PE siempre empiezan con 'MZ' (0x4D 0x5A)
        file_obj.seek(0)
        header = file_obj.read(2)
        file_obj.seek(0) # Resetear el puntero para que el resto del código pueda leerlo
        
        if header != b'MZ':
            return False
        return True

    def post(self, request):
        file_obj = request.FILES.get('archivo')
        if not file_obj: 
            return Response({"error": "No se proporcionó ningún archivo."}, status=400)

        if file_obj.size > self.MAX_FILE_SIZE:
            return Response({"error": "El archivo es demasiado grande (máx 10MB)."}, status=413)

        if not self.validate_pe(file_obj):
            registrar_log(request.user, 'UPLOAD', "Intento de subida de archivo no PE", request)
            return Response({
                "error": "Tipo de archivo no soportado.",
                "detalle": "El modelo solo acepta ejecutables de Windows (PE) válidos."
            }, status=415)

        user_actual = request.user 
        h = calcular_sha256(file_obj)

        # 1. BUSQUEDA GLOBAL: Caché de base de datos por Hash
        analisis_obj = Analisis.objects.filter(hash_sha256=h).first()

        if not analisis_obj:
            # --- PROCESAMIENTO DE IA OPTIMIZADO ---
            # Carga perezosa del modelo (solo la primera vez)
            model, pipeline = obtener_recursos_ia()
            
            # Extracción de características
            raw_feats, addrs = extract_features(file_obj)
            
            if raw_feats is None or len(raw_feats) == 0:
                return Response({"error": "Error al procesar el binario o extraer funciones."}, status=422)

            # Grafo inicial (Nodes/Edges)
            nodes = [{"id": addr, "label": f"{addr[:8]}"} for addr in addrs]
            edges = [{"source": nodes[i]["id"], "target": nodes[i+1]["id"]} for i in range(len(nodes) - 1)] if len(nodes) > 1 else []
            grafo_inicial = {"nodes": nodes, "edges": edges}

            # Inferencia con Torch (eval mode para velocidad)
            df = pd.DataFrame(raw_feats)
            for col in pipeline['feature_cols']:
                if col not in df.columns: df[col] = 0
            df = df[pipeline['feature_cols']]
            
            scaled_feats = pipeline['scaler'].transform(df.astype(float))
            bag_tensor = torch.tensor(scaled_feats, dtype=torch.float32)

            model.eval() # IMPORTANTE: Modo evaluación
            with torch.no_grad():
                logits_global, A, probs_instancias_tensor = model(bag_tensor)
                
                probs_global = torch.sigmoid(logits_global).cpu().numpy()[0]
                probs_instancias = probs_instancias_tensor.cpu().numpy()
                attn = A.cpu().numpy()[0]

            # Lógica de clasificación
            clases_nombres = pipeline['nombres']
            probs_dict = {n: float(p) for n, p in zip(clases_nombres, probs_global)}
            idx_max = probs_global.argmax()
            confianza_max = float(probs_global[idx_max])
            suma_otras = sum(v for k, v in probs_dict.items() if k != "Benigno")

            if confianza_max < 0.4 and suma_otras < 0.5:
                resultado_final = "Benigno"
                probs_dict["Benigno"] = 1.0 - suma_otras
                confianza_final = float(probs_dict["Benigno"])
            else:
                resultado_final = clases_nombres[idx_max]
                confianza_final = confianza_max
            
            # Guardar el Análisis Global (Una sola transacción)
            analisis_obj = Analisis.objects.create(
                nombre_fichero=file_obj.name, 
                hash_sha256=h, 
                tamano_bytes=file_obj.size,
                resultado_clase=resultado_final,
                confianza_global=confianza_final,
                probabilidades_json=probs_dict,
                call_graph_json = grafo_inicial
            )

            # --- OPTIMIZACIÓN DE DETALLES (Bulk Create) ---
            detalles_batch = []
            top_i = attn.argsort()[-20:][::-1]
            
            # Leemos el archivo una sola vez a memoria para desensamblar más rápido
            file_obj.seek(0)
            file_data = file_obj.read()

            for i in top_i:
                # La función ahora recibe los bytes directamente para no reabrir el archivo
                asm_code = desensamblar_funcion(file_data, addrs[i]) 
                
                set_probs = {clases_nombres[j]: float(probs_instancias[i][j]) for j in range(len(clases_nombres))}
                
                detalles_batch.append(DetalleFuncion(
                    analisis=analisis_obj, 
                    direccion_memoria=addrs[i], 
                    atencion_score=float(attn[i]), 
                    prediccion_especifica=set_probs,
                    codigo_desensamblado=asm_code
                ))
            
            # Inserción masiva en BD (1 sola query en lugar de 20)
            DetalleFuncion.objects.bulk_create(detalles_batch)
        
        # 2. VINCULACIÓN Y AUDITORÍA
        subida_rel, created = Subida.objects.update_or_create(
            usuario=user_actual,
            analisis=analisis_obj,
            defaults={'nombre_fichero_personalizado': file_obj.name}
        )

        log_msg = f"Subida exitosa: {file_obj.name}" if created else f"Re-subida (caché): {file_obj.name}"
        LogActividad.objects.create(
            usuario=user_actual, 
            accion='UPLOAD', 
            detalles=log_msg,
            ip_origen=self.request.META.get('REMOTE_ADDR')
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
        return Analisis.objects.filter(subidas_relacionadas__usuario=self.request.user)

class RegistroUsuarioView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegistroSerializer

class CustomJWTSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        request = self.context.get('request')
        
        registrar_log(self.user, 'LOGIN', "Inicio de sesión exitoso", request)
        
        # Añadimos información extra a la respuesta
        data['user_id'] = self.user.id
        data['username'] = self.user.username
        data['email'] = self.user.email
        data['isAdmin'] = self.user.is_staff
        return data

class CustomLoginView(TokenObtainPairView):
    serializer_class = CustomJWTSerializer


class CallGraphView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        subida = Subida.objects.filter(analisis_id=pk, usuario=request.user).first()
        if not subida: 
            return Response({"error": "No autorizado"}, status=403)
        
        analisis = subida.analisis

        if analisis.call_graph_json and analisis.call_graph_json.get('metodo') == 'bypass':
            return Response(analisis.call_graph_json)

        # 2. OBTENER DATOS BASE
        top_20_objs = analisis.detalles_funciones.all().order_by('-atencion_score')[:20]
        direcciones_top = {f.direccion_memoria for f in top_20_objs}
        scores_map = {f.direccion_memoria: f.atencion_score for f in top_20_objs}
        
        base_grafo = analisis.call_graph_json or {"nodes": [], "edges": []}
        
        # 3. CONSTRUCCIÓN DEL GRAFO
        G = nx.DiGraph()
        for edge in base_grafo.get("edges", []):
            G.add_edge(edge["source"], edge["target"])

        # Aseguramos que los nodos críticos existan en el grafo de NetworkX 
        # aunque no tengan aristas registradas aún
        for dir_mem in direcciones_top:
            if dir_mem not in G:
                G.add_node(dir_mem)

        # 4. LÓGICA DE BYPASS
        aristas_bypass = []
        nodos_criticos = [n for n in G.nodes if n in direcciones_top]

        for origen in nodos_criticos:
            descendientes = nx.descendants(G, origen)
            for destino in descendientes:
                if destino in direcciones_top:
                    try:
                        path = nx.shortest_path(G, origen, destino)
                        if all(nodo not in direcciones_top for nodo in path[1:-1]):
                            aristas_bypass.append({
                                "source": origen,
                                "target": destino,
                                "label": "bypass"
                            })
                    except nx.NetworkXNoPath:
                        continue

        # 5. GENERACIÓN DE NODOS FINALES (CORREGIDO)
        # Eliminamos el filtro de 'nodos_conectados' para permitir grafos de un solo nodo
        nodos_finales = [
            {
                "id": node_id,
                "label": f"{node_id[-6:]}" if "0x" in node_id else node_id,
                "atencion_score": scores_map.get(node_id, 0),
                "is_critical": True,
            }
            for node_id in nodos_criticos
        ]

        # 6. ESTRUCTURA FINAL Y PERSISTENCIA
        resultado_bypass = {
            "nodes": nodos_finales,
            "edges": aristas_bypass,
            "metodo": "bypass",
            "procesado": True,
        }

        analisis.call_graph_json = resultado_bypass
        analisis.save()

        return Response(resultado_bypass)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()  # Esto lo mete en la BD de tokens invalidados
            return Response({"detalle": "Sesión cerrada exitosamente."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": "Token inválido o no proporcionado."}, status=status.HTTP_400_BAD_REQUEST)

class AdminDashboardView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        # --- 1. LÓGICA DE ACTUALIZACIÓN LAZY (EAGER COMPUTATION) ---
        ahora = timezone.now()
        ultimo_registro = TelemetriaSistema.objects.order_by('-timestamp').first()

        # Si no hay registros o el último fue hace > 15 minutos, calculamos y guardamos
        if not ultimo_registro or (ahora - ultimo_registro.timestamp) > timedelta(minutes=15):
            cpu = psutil.cpu_percent(interval=1)
            gpu = round(GPUtil.getGPUs()[0].load * 100) if GPUtil.getGPUs() else 0
            TelemetriaSistema.objects.create(cpu_usage=cpu, gpu_usage=gpu)
            

        dataset_size = round((45000 + Analisis.objects.count()) / 1000)

        # --- 2. RESTO DE KPIs Y LOGS ---
        
        
        # 1. Obtener el umbral de tiempo
        umbral_tiempo = ahora - timedelta(minutes=30)

        # 2. Obtener usuarios únicos que han hecho LOGIN en los últimos 30 min
        # Usamos values('usuario_id') para obtener solo los IDs y luego distinct() para evitar duplicados
        active_users_count = LogActividad.objects.filter(
            accion='LOGIN', 
            timestamp__gte=umbral_tiempo
        ).values('usuario_id').distinct().count()

        # 3. Logs de actividad para la tabla (los 5 más recientes)
        logs_data = LogActividad.objects.order_by('-timestamp')[:5]
        formatted_logs = [
            {
                "id": log.id,
                "user": log.usuario.username if log.usuario else "Desconocido",
                "action": log.accion,
                "timestamp": log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "ip": log.ip_origen
            } for log in logs_data
        ]

        active_users = len(LogActividad.objects.filter(accion='LOGIN').values('usuario').annotate(max_time=Max('timestamp')))

        
        # 4. Obtención de datos históricos para la gráfica
        hace_24h = ahora - timedelta(hours=24)
        telemetria = TelemetriaSistema.objects.filter(timestamp__gte=hace_24h).order_by('timestamp')
        resource_usage = [
            {"time": t.timestamp.strftime('%H:%M'), "cpu": t.cpu_usage, "gpu": t.gpu_usage} 
            for t in telemetria
        ]

        # 5. Datos actuales del modelo
        metricas = MetricasModelo.objects.order_by('-timestamp')[:5]
        
        model_performance = [
                {
                    "name": m.clase,
                    "precision": m.precision,
                    "recall": m.recall,
                    "f1": m.f1_score
                } for m in metricas
            ]

        # 6. Datos actuales del sistema
        gpu_usage = round(GPUtil.getGPUs()[0].load * 100) if GPUtil.getGPUs() else 0
        cpu_usage = psutil.cpu_percent(interval=1)

        # 7. Datos actuales de reputación
        # Consulta para obtener reputación: limitamos a [:3]
        top_users_risk = Subida.objects.values('usuario__username') \
            .annotate(risk_score=Sum(F('analisis__confianza_global'))) \
            .order_by('-risk_score')[:3]

        # 8. Construcción de la respuesta
        data = {
            "kpis": {
                "gpu_load": gpu_usage,
                "cpu_load": cpu_usage,
                "active_users": active_users,
                "dataset_size": f"{dataset_size}K"
            },
            
            "charts": {
                "resource_usage": resource_usage,
                "model_performance": model_performance
            },
            "pseudo_labels": [
                {"id": a.id, "filename": a.nombre_fichero, "confidence": float(a.confianza_global), 
                 "prediction": a.resultado_clase, "status": "pendiente"} 
                for a in Analisis.objects.all().order_by('-fecha_creacion')[:5]
            ],
            "user_logs": formatted_logs,
            "user_reputation": list(top_users_risk),
        }
        
        return Response(data)

class DetalleCodigoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, analisis_pk, direccion):
        # 1. Verificar que el usuario tenga acceso al análisis
        subida = Subida.objects.filter(analisis_id=analisis_pk, usuario=request.user).first()
        if not subida:
            return Response({"error": "No autorizado"}, status=403)
        
        # 2. Buscar el detalle de la función
        detalle = DetalleFuncion.objects.filter(
            analisis_id=analisis_pk, 
            direccion_memoria=direccion
        ).first()
        
        if not detalle or not detalle.codigo_desensamblado:
            return Response({"error": "Código no disponible"}, status=404)
        
        return Response({
            "direccion": detalle.direccion_memoria,
            "codigo": detalle.codigo_desensamblado
        })