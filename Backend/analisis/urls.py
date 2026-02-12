from django.urls import path
from .views import AnalizarBinarioView, HistorialAnalisisView, DetalleAnalisisView, RegistroUsuarioView, CustomLoginView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('analizar/', AnalizarBinarioView.as_view(), name='analizar'),
    path('historial/', HistorialAnalisisView.as_view(), name='historial'),
    path('analisis/<int:pk>/', DetalleAnalisisView.as_view(), name='detalle-analisis'),
    path('registro/', RegistroUsuarioView.as_view(), name='registro'),
    path('login/', CustomLoginView.as_view(), name='token_obtain_pair'),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]