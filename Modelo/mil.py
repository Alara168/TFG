import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset
from torch.optim.lr_scheduler import ReduceLROnPlateau
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Nombres de tus clases
NOMBRES_CLASES = ['Benigno', 'Financiero', 'Intrusion', 'Herramientas', 'Tecnico', 'Otros/Ransom']


# DATASET

class MalwareMILDataset(Dataset):
    def __init__(self, csv_path, scaler=None):
        self.csv_path = csv_path
        print(f"--- Paso 1/3: Cargando CSV ---")
        df = pd.read_csv(csv_path)
        self.feature_cols = [col for col in df.columns if col not in ['binary_hash', 'func_addr', 'malware']]
        
        if scaler is None:
            self.scaler = StandardScaler()
            df[self.feature_cols] = self.scaler.fit_transform(df[self.feature_cols].astype(np.float32))
        else:
            self.scaler = scaler
            df[self.feature_cols] = self.scaler.transform(df[self.feature_cols].astype(np.float32))
        
        groups = df.groupby('binary_hash')
        self.bag_indices = groups.indices
        self.bag_names = list(self.bag_indices.keys())
        self.labels = groups['malware'].first().values
        self.all_data = df 

    def __len__(self): return len(self.bag_names)
    def __getitem__(self, idx):
        indices = self.bag_indices[self.bag_names[idx]]
        bag_data = self.all_data.iloc[indices]
        addrs = bag_data['func_addr'].values
        feats = torch.tensor(bag_data[self.feature_cols].values, dtype=torch.float32)
        label = torch.tensor(self.labels[idx], dtype=torch.long)
        return feats, label, addrs


# MODELO: GATED ATTENTION MIL

class GatedAttentionMIL(nn.Module):
    def __init__(self, input_dim, num_classes):
        super(GatedAttentionMIL, self).__init__()
        self.L = 256
        self.D = 128
        
        self.feature_extractor = nn.Sequential(
            nn.Linear(input_dim, self.L),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(self.L, self.L),
            nn.ReLU()
        )

        self.attention_V = nn.Sequential(nn.Linear(self.L, self.D), nn.Tanh())
        self.attention_U = nn.Sequential(nn.Linear(self.L, self.D), nn.Sigmoid())
        self.attention_w = nn.Linear(self.D, 1)

        self.classifier = nn.Sequential(
            nn.Linear(self.L, num_classes)
        )

    def forward(self, x):
        if x.dim() > 2: x = x.squeeze(0)
        h = self.feature_extractor(x)
        
        a_v = self.attention_V(h)
        a_u = self.attention_U(h)
        a = self.attention_w(a_v * a_u).t() 
        
        A = F.softmax(a, dim=1)
        M = torch.matmul(A, h) 
        logits = self.classifier(M)
        return logits, A


# PIPELINE DE EJECUCIÓN

def entrenar(csv_path, k_folds=5):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    dataset = MalwareMILDataset(csv_path)
    skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=42)
    
    all_y_true, all_y_pred = [], []
    global_best_val_loss = float('inf')
    best_model_path = 'best_model_gated_mil.pth'
    
    print(f"\nEntrenando Gated-MIL en {device}...")

    for fold, (train_val_idx, test_idx) in enumerate(skf.split(dataset.bag_names, dataset.labels)):
        print(f"\n" + "="*40 + f"\n FOLD {fold+1}/{k_folds} \n" + "="*40)
        
        train_idx, val_idx = train_test_split(
            train_val_idx, test_size=0.1, stratify=dataset.labels[train_val_idx], random_state=42
        )

        counts = np.bincount(dataset.labels[train_idx])
        weights = (1. / torch.tensor(np.where(counts==0, 1, counts), dtype=torch.float32)).to(device)
        weights = weights / weights.sum() * len(counts)

        model = GatedAttentionMIL(len(dataset.feature_cols), len(NOMBRES_CLASES)).to(device)
        optimizer = torch.optim.Adam(model.parameters(), lr=0.0005)
        scheduler = ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=3)
        criterion = nn.CrossEntropyLoss(weight=weights)
        
        fold_best_loss = float('inf')
        early_stop_patience, counter = 8, 0

        for epoch in range(50):
            model.train()
            train_loss = 0
            pbar = tqdm(train_idx, desc=f"F{fold+1} E{epoch+1}", unit="bag", leave=False)
            for idx in pbar:
                feats, label, _ = dataset[idx]
                optimizer.zero_grad()
                logits, _ = model(feats.to(device))
                loss = criterion(logits, label.unsqueeze(0).to(device))
                loss.backward()
                optimizer.step()
                train_loss += loss.item()
                pbar.set_postfix({'loss': f"{loss.item():.4f}"})

            model.eval()
            val_loss = 0
            with torch.no_grad():
                for idx in val_idx:
                    f, l, _ = dataset[idx]
                    log, _ = model(f.to(device))
                    val_loss += criterion(log, l.unsqueeze(0).to(device)).item()
            val_loss /= len(val_idx)
            
            scheduler.step(val_loss) 

            if val_loss < fold_best_loss:
                fold_best_loss = val_loss
                counter = 0
                if val_loss < global_best_val_loss:
                    global_best_val_loss = val_loss
                    torch.save(model.state_dict(), best_model_path)
                    print(f"  (*) Nuevo récord global de Loss: {val_loss:.4f}")
            else:
                counter += 1
                if counter >= early_stop_patience: break

        # Evaluar Fold con el mejor guardado
        model.load_state_dict(torch.load(best_model_path))
        model.eval()
        with torch.no_grad():
            for idx in tqdm(test_idx, desc=f"Eval F{fold+1}", leave=False):
                f, l, _ = dataset[idx]
                logits, _ = model(f.to(device))
                pred = torch.argmax(logits, dim=1).item()
                all_y_true.append(l.item())
                all_y_pred.append(pred)

    print("\n" + "X"*40 + "\n REPORTE FINAL GATED-MIL \n" + "X"*40)
    print(classification_report(all_y_true, all_y_pred, target_names=NOMBRES_CLASES, zero_division=0))

    # Matriz de Confusión
    cm = confusion_matrix(all_y_true, all_y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Purples', xticklabels=NOMBRES_CLASES, yticklabels=NOMBRES_CLASES)
    plt.title('Matriz de Confusión: Gated Attention MIL')
    plt.savefig('confusion_gated_mil.png')

    # Análisis Forense
    model.load_state_dict(torch.load(best_model_path))
    model.eval()
    with torch.no_grad():
        example_idx = test_idx[0]
        feats_ex, label_ex, addrs_ex = dataset[example_idx]
        logits_ex, A_ex = model(feats_ex.to(device))
        importancia = A_ex.cpu().numpy()[0]

    print("\n" + "*"*65 + "\n ANÁLISIS FORENSE (GATED ATTENTION) \n" + "*"*65)
    print(f"HASH: {dataset.bag_names[example_idx]}\nPREDICCIÓN: {NOMBRES_CLASES[torch.argmax(logits_ex).item()]}")
    indices_top = importancia.argsort()[-12:][::-1]
    for i in indices_top:
        relevancia = importancia[i]
        barra = "*" * int(relevancia * 50 / importancia.max())
        try:
            # Si es un número, lo pasamos a hex
            addr_str = hex(int(addrs_ex[i]))
        except:
            # Si ya es un string (como '0x40093b'), lo dejamos como está
            addr_str = str(addrs_ex[i])
        print(f"{addr_str:<18} | {relevancia:.4f} | {barra}")

if __name__ == "__main__":
    csv_file = "../Scrap/dataset_tfg_balanceado_bags.csv"
    if os.path.exists(csv_file):
        entrenar(csv_file)