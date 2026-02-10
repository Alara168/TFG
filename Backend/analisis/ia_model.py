import torch
import torch.nn as nn
import torch.nn.functional as F

class GatedAttentionMIL(nn.Module):
    def __init__(self, input_dim, num_classes):
        super(GatedAttentionMIL, self).__init__()
        self.L = 256
        self.D = 128
        
        self.feature_extractor = nn.Sequential(
            nn.Linear(input_dim, self.L),
            nn.ReLU(),
            nn.Dropout(0.35),
            nn.Linear(self.L, self.L),
            nn.ReLU()
        )

        self.attention_V = nn.Sequential(nn.Linear(self.L, self.D), nn.Tanh())
        self.attention_U = nn.Sequential(nn.Linear(self.L, self.D), nn.Sigmoid())
        self.attention_w = nn.Linear(self.D, 1)
        self.classifier = nn.Linear(self.L, num_classes)

    def forward(self, x):
        if x.dim() > 2: 
            x = x.squeeze(0)
        
        # h tiene forma [num_funciones, 128] (o el tamaño de tu capa oculta)
        h = self.feature_extractor(x) 
        
        # 1. Cálculo de atención (como ya lo tenías)
        a_v = self.attention_V(h)
        a_u = self.attention_U(h)
        a = self.attention_w(a_v * a_u).t() 
        A = F.softmax(a, dim=1) 
        
        # 2. Predicción GLOBAL (el binario completo)
        M = torch.matmul(A, h) 
        logits_global = self.classifier(M)
        
        # 3. Predicción INDIVIDUAL (cada función por separado)
        # Aplicamos el mismo clasificador a cada fila de h
        logits_instancias = self.classifier(h)
        probs_instancias = F.softmax(logits_instancias, dim=1)
        
        return logits_global, A, probs_instancias