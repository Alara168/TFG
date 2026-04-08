from django.urls import path
from .views import (
    AnalizarBinarioView, 
    HistorialAnalisisView, 
    DetalleAnalisisView, 
    RegistroUsuarioView,
    CustomLoginView,
    CallGraphView,
    LogoutView,
    AdminDashboardView,
    DetalleCodigoView,
    DatasetExplorerListView,
    UpdatePseudoLabelView
)
from drf_spectacular.views import (
    SpectacularAPIView, 
    SpectacularRedocView, 
    SpectacularSwaggerView
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('analizar/', AnalizarBinarioView.as_view(), name='analizar'),
    path('historial/', HistorialAnalisisView.as_view(), name='historial'),
    path('analisis/<int:pk>/', DetalleAnalisisView.as_view(), name='detalle-analisis'),
    path('registro/', RegistroUsuarioView.as_view(), name='registro'),
    path('login/', CustomLoginView.as_view(), name='token_obtain_pair'),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('analisis/<int:pk>/grafo/', CallGraphView.as_view(), name='analisis-grafo'),
    path('logout/', LogoutView.as_view(), name='auth_logout'),
    path('admin/dashboard-stats/', AdminDashboardView.as_view(), name='admin-stats'),
    path('analisis/<int:analisis_pk>/codigo/<str:direccion>/', DetalleCodigoView.as_view(), name='analisis-codigo'),
    path('admin/full-dataset-explorer/', DatasetExplorerListView.as_view(), name='dataset-explorer'),
    path('admin/<int:pk>/toggle-pseudo-label/', UpdatePseudoLabelView.as_view(), name='toggle-pseudo-label'),

    # --- DOCUMENTACIÓN API ---
    # Genera el archivo schema.yml internamente
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    # Interfaz Swagger (la más visual y profesional para empresas)
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    # Interfaz Redoc (alternativa más limpia)
    path('redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]