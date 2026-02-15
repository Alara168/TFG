import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset
from torch.optim.lr_scheduler import ReduceLROnPlateau
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import seaborn as sns
import joblib
import os

# Nombres ajustados a la nueva unificación (0 a 4)
NOMBRES_CLASES = ['Benigno', 'Financiero', 'Intrusion', 'Herramientas/Sistema', 'Otros/Ransom']

# ==========================================
# 1. DATASET CON BALANCEO DE INSTANCIAS 1:1
# ==========================================
class MalwareMILDataset(Dataset):
    def __init__(self, csv_path, scaler=None):
        self.csv_path = csv_path
        print(f"[1/4] Cargando CSV: {csv_path}")
        df = pd.read_csv(csv_path)
        
        # --- LÓGICA DE DOWNSAMPLING POR INSTANCIAS (BENIGNO VS RESTO) ---
        hashes_finales = []
        benigno_id = 0
        
        # 1. Calculamos cuántas funciones hay en TOTAL en las clases de malware (1, 2, 3, 4)
        # Esto nos dará el objetivo exacto para la clase Benigno
        df_malware_solo = df[df['malware'] != benigno_id]
        # Aplicamos primero el límite a las clases de malware para saber el total real final
        total_instancias_malware_objetivo = 0
        
        print(f"[*] Calculando presupuesto de instancias para balanceo...")
        
        # Calculamos cuántas funciones aportará cada clase de malware tras su propio límite
        for clase_id in sorted(df['malware'].unique()):
            if clase_id == benigno_id: continue
            
            df_clase = df[df['malware'] == clase_id]
            counts_per_hash = df_clase.groupby('binary_hash').size().reset_index(name='count')
            counts_per_hash = counts_per_hash.sample(frac=1, random_state=42)
            counts_per_hash['cum_sum'] = counts_per_hash['count'].cumsum()
            
            # Límite estándar de 500k para cada clase de malware
            LIMITE_MALWARE = 500000
            seleccion_malware = counts_per_hash[counts_per_hash['cum_sum'] <= LIMITE_MALWARE]
            
            # Sumamos lo que esta clase aportará al total
            total_instancias_malware_objetivo += seleccion_malware['count'].sum()
            hashes_finales.extend(seleccion_malware['binary_hash'].tolist())

        print(f"[*] Objetivo de instancias Benignas: {total_instancias_malware_objetivo}")

        # 2. Ahora aplicamos ese objetivo como límite estricto para la clase Benigno
        df_benigno = df[df['malware'] == benigno_id]
        counts_benigno = df_benigno.groupby('binary_hash').size().reset_index(name='count')
        counts_benigno = counts_benigno.sample(frac=1, random_state=42)
        counts_benigno['cum_sum'] = counts_benigno['count'].cumsum()
        
        seleccion_benigno = counts_benigno[counts_benigno['cum_sum'] <= total_instancias_malware_objetivo]['binary_hash'].tolist()
        if not seleccion_benigno and not counts_benigno.empty:
            seleccion_benigno = [counts_benigno.iloc[0]['binary_hash']]
        
        hashes_finales.extend(seleccion_benigno)
        
        # Filtrado final del dataframe
        df = df[df['binary_hash'].isin(hashes_finales)].copy()

        # --- LÓGICA DE OVERSAMPLING (EQUILIBRADO DE BOLSAS) ---
        groups = df.groupby('binary_hash')
        self.bag_indices = groups.indices
        temp_bag_names = list(self.bag_indices.keys())
        temp_labels = groups['malware'].first().values

        clases, conteos = np.unique(temp_labels, return_counts=True)
        max_muestras = max(conteos)
        
        self.bag_names = []
        self.labels = []
        
        print(f"[*] Aplicando Oversampling para equilibrar a {max_muestras} bolsas por clase...")
        for clase_id in clases:
            idx_clase = np.where(temp_labels == clase_id)[0]
            muestras_actuales = [temp_bag_names[i] for i in idx_clase]
            
            replicas = (max_muestras // len(muestras_actuales))
            sobrante = max_muestras % len(muestras_actuales)
            
            muestras_equilibradas = muestras_actuales * replicas + muestras_actuales[:sobrante]
            self.bag_names.extend(muestras_equilibradas)
            self.labels.extend([clase_id] * len(muestras_equilibradas))
        
        self.labels = np.array(self.labels)

        # --- RESUMEN DEL BALANCEO FINAL ---
        print("-" * 65)
        print(f"{'ID':<4} | {'CLASE':<20} | {'FUNCIONES':<12} | {'HASHES (FINAL)':<8}")
        print("-" * 65)
        for cid in clases:
            nombre = NOMBRES_CLASES[int(cid)]
            n_func = len(df[df['malware'] == cid])
            n_hash = (self.labels == cid).sum()
            print(f"{int(cid):<4} | {nombre:<20} | {n_func:<12} | {n_hash:<8}")
        print("-" * 65 + "\n")

        self.feature_cols = [col for col in df.columns if col not in ['binary_hash', 'func_addr', 'malware']]
        
        print(f"[3/4] Escalando características...")
        if scaler is None:
            self.scaler = StandardScaler()
            df[self.feature_cols] = self.scaler.fit_transform(df[self.feature_cols].astype(np.float32))
        else:
            self.scaler = scaler
            df[self.feature_cols] = self.scaler.transform(df[self.feature_cols].astype(np.float32))
        
        print(f"[4/4] Agrupando funciones en 'Bags'...")
        self.all_data = df 

    def __len__(self): return len(self.bag_names)
    def __getitem__(self, idx):
        indices = self.bag_indices[self.bag_names[idx]]
        bag_data = self.all_data.iloc[indices]
        addrs = bag_data['func_addr'].values
        feats = torch.tensor(bag_data[self.feature_cols].values, dtype=torch.float32)
        
        label_idx = self.labels[idx]
        label_onehot = np.zeros(len(NOMBRES_CLASES), dtype=np.float32)
        label_onehot[label_idx] = 1.0
        
        return feats, torch.tensor(label_onehot), addrs

# ==========================================
# 2. MODELO: GATED ATTENTION MIL
# ==========================================
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
        if x.dim() > 2: x = x.squeeze(0)
        h = self.feature_extractor(x) 
        a_v = self.attention_V(h)
        a_u = self.attention_U(h)
        a = self.attention_w(a_v * a_u).t() 
        A = F.softmax(a, dim=1) 
        M = torch.matmul(A, h) 
        logits = self.classifier(M)
        return logits, A, h 

# ==========================================
# 3. UTILIDADES DE VISUALIZACIÓN
# ==========================================
def plot_architecture(input_dim):
    plt.figure(figsize=(10, 6))
    layers = [f'Input\n({input_dim})', 'FC 256\n+ReLU', 'FC 256\n+ReLU', 'Gated\nAttention', 'FC 128\n(Pool)', f'Output\n({len(NOMBRES_CLASES)})']
    x = range(len(layers))
    y = [1] * len(layers)
    plt.plot(x, y, 'ko-', markersize=40, markerfacecolor='skyblue')
    for i, txt in enumerate(layers):
        plt.annotate(txt, (x[i], y[i]), textcoords="offset points", xytext=(0,10), ha='center', fontweight='bold')
    plt.title("Arquitectura Gated Attention MIL (Oversampled)")
    plt.axis('off')
    plt.savefig('arquitectura_neuronal.png')
    plt.close()

def create_activation_video(model, feats, addrs, filename='activacion_neuronal.gif'):
    model.eval()
    with torch.no_grad():
        logits, A, h = model(feats)
        importance = A.cpu().numpy()[0]
        activations = h.cpu().numpy()

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
    
    def update(frame):
        ax1.clear()
        ax2.clear()
        ax1.bar(range(len(importance[:20])), importance[:20], color='orange')
        ax1.set_title(f"Atención en Funciones (Frame {frame})")
        ax1.set_ylabel("Importancia")
        
        ax2.imshow(activations[frame:frame+1, :64], aspect='auto', cmap='viridis')
        ax2.set_title(f"Activación - Función: {hex(int(addrs[frame])) if isinstance(addrs[frame], (int, float, np.integer)) else addrs[frame]}")
        ax2.axis('off')

    ani = animation.FuncAnimation(fig, update, frames=min(20, len(importance)), interval=500)
    ani.save(filename, writer='pillow')
    print(f"(*) Video de activación guardado en {filename}")

# ==========================================
# 4. ENTRENAMIENTO MEJORADO CON CV
# ==========================================
def entrenar(csv_path, k_folds=5):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Usando dispositivo: {device}")
    
    dataset = MalwareMILDataset(csv_path)
    
    pipeline_data = {'scaler': dataset.scaler, 'feature_cols': dataset.feature_cols, 'nombres': NOMBRES_CLASES}
    joblib.dump(pipeline_data, 'mil_pipeline.pkl')

    plot_architecture(len(dataset.feature_cols))

    skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=42)
    best_model_path = 'best_model_gated_mil.pth'
    global_best_val_loss = float('inf')

    pbar_folds = tqdm(total=k_folds, desc="Cross-Validation Progress", unit="fold")

    for fold, (train_val_idx, test_idx) in enumerate(skf.split(dataset.bag_names, dataset.labels)):
        train_idx, val_idx = train_test_split(train_val_idx, test_size=0.1, stratify=dataset.labels[train_val_idx], random_state=42)
        model = GatedAttentionMIL(len(dataset.feature_cols), len(NOMBRES_CLASES)).to(device)
        optimizer = torch.optim.Adam(model.parameters(), lr=0.0005)
        
        criterion = nn.BCEWithLogitsLoss()
        scheduler = ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=3)
        
        fold_best_loss = float('inf')
        early_stop_patience, counter = 8, 0

        pbar_epochs = tqdm(range(50), desc=f"Fold {fold+1}/{k_folds} Training", leave=False)
        for epoch in pbar_epochs:
            model.train()
            train_loss = 0
            for idx in train_idx:
                feats, labels, _ = dataset[idx]
                optimizer.zero_grad()
                logits, _, _ = model(feats.to(device))
                loss = criterion(logits, labels.unsqueeze(0).to(device))
                loss.backward()
                optimizer.step()
                train_loss += loss.item()

            model.eval()
            val_loss = 0
            with torch.no_grad():
                for idx in val_idx:
                    f, l, _ = dataset[idx]
                    log, _, _ = model(f.to(device))
                    val_loss += criterion(log, l.unsqueeze(0).to(device)).item()
            val_loss /= len(val_idx)
            
            scheduler.step(val_loss)
            pbar_epochs.set_postfix(val_loss=f"{val_loss:.4f}", best=f"{fold_best_loss:.4f}")

            if val_loss < fold_best_loss:
                fold_best_loss = val_loss
                counter = 0
                if val_loss < global_best_val_loss:
                    global_best_val_loss = val_loss
                    torch.save(model.state_dict(), best_model_path)
            else:
                counter += 1
                if counter >= early_stop_patience: break
        
        pbar_folds.update(1)
    
    pbar_folds.close()

    print("\n[+] Evaluando mejor modelo...")
    model.load_state_dict(torch.load(best_model_path))
    model.eval()
    
    y_true, y_pred = [], []
    with torch.no_grad():
        for idx in tqdm(test_idx, desc="Evaluando Test"):
            f, l, _ = dataset[idx]
            log, _, _ = model(f.to(device))
            y_true.append(l.numpy().argmax())
            y_pred.append(torch.sigmoid(log).detach().cpu().numpy()[0].argmax())

    report = classification_report(y_true, y_pred, target_names=NOMBRES_CLASES)
    with open('estadisticas_modelo.txt', 'w') as f:
        f.write(report)
    print(f"\n{report}")

    # Inferencia de ejemplo con video
    for i in range(min(2, len(test_idx))):
        ex_idx = test_idx[i]
        feats, label, addrs = dataset[ex_idx]
        if i == 0: create_activation_video(model, feats.to(device), addrs)

if __name__ == "__main__":
    csv_file = "../../Scrap/dataset_tfg_etiquetado_completo.csv"
    if os.path.exists(csv_file):
        entrenar(csv_file)