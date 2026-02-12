from django.urls import path
from .views import AnalizarBinarioView, HistorialAnalisisView, DetalleAnalisisView, RegistroUsuarioView

urlpatterns = [
    path('analizar/', AnalizarBinarioView.as_view(), name='analizar'),
    path('historial/', HistorialAnalisisView.as_view(), name='historial'),
    path('analisis/<int:pk>/', DetalleAnalisisView.as_view(), name='detalle-analisis'),
    path('registro/', RegistroUsuarioView.as_view(), name='registro'),
]