import torch
import torch.nn as nn
import torch.nn.functional as F

class GatedAttentionMIL(nn.Module):
    def __init__(self, input_dim, num_classes, num_heads=4):
        super(GatedAttentionMIL, self).__init__()
        self.L = 256
        self.D = 128
        self.K = num_heads  # Mejora 1: Número de cabezas

        # --- Mejora 2: Extractor con LayerNorm ---
        self.feature_extractor = nn.Sequential(
            nn.Linear(input_dim, self.L),
            nn.LayerNorm(self.L), 
            nn.ReLU(),
            nn.Dropout(0.35),
            nn.Linear(self.L, self.L),
            nn.LayerNorm(self.L),
            nn.ReLU()
        )

        # --- Mejora 1: Multi-Head Gated Attention ---
        # Proyectamos a D * K para que cada cabeza tenga su propio espacio
        self.attention_V = nn.Linear(self.L, self.D * self.K)
        self.attention_U = nn.Linear(self.L, self.D * self.K)
        self.attention_w = nn.Linear(self.D * self.K, self.K)

        # --- Mejora 3: Clasificador para Agregación Concatenada ---
        # El tamaño de entrada es (L * K) [Atención] + L [Mean] + L [Max]
        input_classifier = (self.L * self.K) + self.L + self.L
        
        self.classifier = nn.Sequential(
            nn.Linear(input_classifier, self.L),
            nn.ReLU(),
            nn.Dropout(0.25),
            nn.Linear(self.L, num_classes)
        )

    def forward(self, x):
        if x.dim() > 2: x = x.squeeze(0)
        
        # Extracción de características de las funciones (Instancias)
        h_raw = self.feature_extractor(x) 
        
        # Mejora 2: Conexión Residual simple (sumar entrada al feature extractor si dimensiones coinciden)
        # Aquí h ya tiene la representación aprendida
        h = h_raw 

        # --- Mecanismo de Atención Multicabeza ---
        a_v = torch.tanh(self.attention_V(h))
        a_u = torch.sigmoid(self.attention_U(h))
        gated_attention = a_v * a_u
        
        # weights: [N_funciones, K_cabezas]
        weights = self.attention_w(gated_attention)
        A = F.softmax(weights, dim=0) 

        # M_attention: [K, L] -> Representación por cada cabeza
        M_attn = torch.matmul(A.t(), h) 
        M_attn_flat = M_attn.view(1, -1) # [1, K * L]

        # --- Mejora 3: Agregación de Instancias (Mean y Max) ---
        # Esto ayuda a detectar instaladores (promedio) vs Ransomware (picos de sospecha)
        M_mean = torch.mean(h, dim=0, keepdim=True) # [1, L]
        M_max, _ = torch.max(h, dim=0, keepdim=True)  # [1, L]

        # Concatenamos todo: [1, (K*L) + L + L]
        M_final = torch.cat([M_attn_flat, M_mean, M_max], dim=1)

        logits = self.classifier(M_final)
        
        # Retornamos A[:, 0] para que tu script de video siga funcionando con la primera cabeza
        return logits, A[:, 0].unsqueeze(0), h