from django.urls import path
from .views import AnalizarBinarioView, HistorialAnalisisView

urlpatterns = [
    path('analizar/', AnalizarBinarioView.as_view(), name='analizar'),
    path('historial/', HistorialAnalisisView.as_view(), name='historial'),
]