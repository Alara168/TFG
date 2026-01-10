import pandas as pd
import re
import numpy as np

# Cargar el archivo
try:
    df = pd.read_csv('hashes_exe.csv', sep=';')
except FileNotFoundError:
    df = pd.read_csv('hashes.csv', sep=';')

# Función de limpieza
def limpiar_tags(texto):
    t = str(texto)
    t = re.sub(r'[0-9]', '', t)
    t = re.sub(r'[#<>]', '', t)
    t = re.sub(r'exe', '', t, flags=re.I)
    t = re.sub(r'\.,', ',', t)
    t = re.sub(r',\.', ',', t)
    t = re.sub(r'\.{2,}', '.', t)
    t = re.sub(r',{2,}', ',', t)
    t = t.strip().lstrip('.,- ').rstrip('.,- ')
    t = re.sub(r'\s+', ' ', t)
    return t.strip()

df['tags_limpio'] = df['tags'].apply(limpiar_tags)
lista_unicos = sorted(df[df['tags_limpio'] != ""]['tags_limpio'].unique())

# --- LÓGICA DE CATEGORÍAS ---

categorias = {
    # Ransomware, Wipers Virus y Worms
    "RANSOMWARE, WIPERS Y DESTRUCTIVOS": [
        "ransomware", "lockbit", "avos", "chaos", "phobos", "wannacry", "teslacrypt", "revil", 
        "blackbasta", "blackcat", "conti", "magniber", "medusa", "stop", "djvu", "petya", 
        "cryptolocker", "zeppelin", "locky", "gandcrab", "hive", "babuk", "blackmatter", 
        "sodinokibi", "astralocker", "darkpower", "lockergoga", "knightcrypt", "onyxlocker", "helloxd", "JobCrypter", "wiper",
        "caddywiper", "hermeticwiper", "whispergate", "ruransom", "killwin", 
        "diskwriter", "killmbr", "azov", "hitlercrypt", "mbr", "efilock", "breakwin", "iran", "Azov", "WhisperGate", "GlobeImposter",
        "LegionLocker", "Filecoder", "LockFile", "Ransom.Satan", "Troldesh", "BlackOut", "LockFile", "Encryption",
        "Endurance", "BURNTCIGAR", "Osiris", "Karma", "rapid", "berndware", "virus", "sality", "ramnit", "virut",
        "neshta", "virlock", "brontok", "worm", "vjwrm", "mydoom", "warezov", "floxif", "expiro", "simda"
    ],

    # Bankers, Rats & Stealers
    "CRIMEN_FINANCIERO_Y_ROBO": [
        "banker", "bancos", "caixa", "bbva", "hsbc", "santander", "commerzbank", "deutschebank", 
        "casbaneiro", "coyote", "tinba", "carbanak", "swift", "banload", "bancteian", "coringa", 
        "fabookie", "shifu", "zeus", "zbot", "vmzeus", "rat", "stealer", "key", "agenttesla", "asyncrat", "remcos", "quasarrat", "njrat", "netwire", 
        "formbook", "azorult", "redline", "loki", "snakekeylogger", "amadey", "vidar", "stealc", 
        "lumma", "darkcloud", "darkcomet", "pony", "purelogs", "rhadamanthys", "risepro", 
        "blackshades", "bluebot", "bandook", "recordbreaker", "arkei", "ffdroider", "stormkitty", 
        "loda", "meduza", "blackguard", "blackmoon", "blacknet", "nanocore", "Nanocore", "HawkEye", "MassLogger", "Matiex", "DarkGate", "DarkVNC",
        "DarkWatchman", "ArechClient", "Loda", "Remcos", "aLogger", "Keylogger", "LunaLogger", "Phoenix", "Phonk", "Stealc", "Vidar", "Logger",
        "Luminosity", "Icarus", "RemoteManipulator", "DarkOxide", "DiamondFox", "Mercurial", "Bobik", "IISpy", "FlawedAmmyy",
        "Bayrob", "Exbyte", "GrandaMisha", "Graphiron", "LUDER_MAL", "PSWmarket", "MailPassView",
        "MnDv", "Rad", "Shaifmia",  "Adhubllka", "Creepy", "Healer", "Kutaki",  "Levis",
        "metla", "yellowcockatoo", "younglotus", "zyklon", "echelon", "reconyc", "resur", "shafmia", "zatoxp",
        "itroublve", "qqpass", "spyware", "pwsx"," clipper", "grabber", "allcome", "clipbanker", "cryptbot",
        "laplas", "coinminer", "xmrig", "miner", "cryptone", "babadeda"
    ],
    
    #APT, Backdoors & Loaders
    "INTRUSION_Y_PERSISTENCIA": [
        "guloader", "bumblebee", "icedid", "bokbot", "bazaloader", "smokeloader", "qakbot", 
        "emotet", "heodo", "trickbot", "zloader", "dbatloader", "wikiloader", "latrodectus", 
        "dridex", "gozi", "ursnif", "purecrypter", "pikabot", "colibri", "modiloader", 
        "buerloader", "idat", "diceloader", "customerloader", "netsupport", "privateloader", 
        "anchor", "andromeda", "bazarcall", "loader", "bot", "Bot", "Glupteba", "Quakbot", "Upatre", "Cutwail", "Empyrean",
        "Mirai", "Nitol", "Phorpiex", "Tofsee", "GuLoader", "Gofot", "Nymaim", "GhostSocks", "SocksSystemz", "Kovter",
        "Ostap", "MirrorBlast", "DarkTortilla", "DarkTortilla,HUN", "FruitMiX", "GCleaner",
        "Matanbuchus", "Nivdort", "Nabucur", "Neurevt", "Poullight", "Bdaejec", "Koceg",
        "tinynuke", "topinambour", "urelas", "wapomi", "redosdru","neconyd", "neojit", "roopy", "comfoo",
        "lmir", "rilo", "toitoin", "apt", "lazarus", "konni", "bitter", "fancybear", "cicada", "sandworm", "turla", 
        "blindeagle", "equationgroup", "industroyer", "sidewalk", "decoydog", "knotweed", 
        "kimsuky", "sharppanda", "earthkrahang", "manuscrypt", "bisonal", "biopass",
        "Androm", "SystemBC", "Void", "Rabisu", "RomCom", "ServHelper", "CyberGate", "PoshC",
        "BADNEWS", "PlugX", "Sandman", "Purple Fox", "Berbew", "OfflRouter", "Backdoor.TeamViewer", "GhstCringe",
        "NoName", "DDosia", "LeprechaunHvnc", "OpenCTI.BR", "Prometei", "N-Wrm", "Lucifer",
        "EvilPlayout", "Macoute", "backdoor", "socelars", "telemiris", "tempedreve",
        "korplug", "hvnc", "silentnight", "triusor"
    ],
    
    #RedTeam, Social Eng & Adware
    "HERRAMIENTAS_Y_VECTORES": [
        "mimikatz", "hacktool", "metasploit", "meterpreter", "rubeus", "juicypotato", "cve", 
        "rootkit", "webshell", "cobaltstrike", "cobalt strike", "beacon", "sliver", "havoc", "mythic", 
        "printspoofer", "antiav", "killav", "ncat", "sharps", "Cobalt", "RaspberryRobin", "FRP", "PrintSpoofer", "Mimic",
        "Kernel Driver Utility", "Prometheus", "StealthWorker", "CMSBrute", "CLFS", "RandomStub",
        "bomber", "forkbomb", "tunnussched", "adware", "installcore", "eorezo", "extenbro", "opencandy", "dealply", "softpulse", "pua", "riskware",
        "cheat", "cracked", "gaming", "ce_malware", "porn", "COVID", "COVID-", "DHL", "Fedex", "Invoice", "geo", "HUN", "Maersk", "Shipping",
        "ShipUP", "Shyape", "Payment", "RFQ", "SendGrid", "MailChannels", "HN",  "Joke",
        "telegram", "outlook", "yahoo", "ukr", "netmail"
    ],
    
    #Sistema y Ruido
    "TECNICOS_Y_SISTEMA": [
        "signed", "msil", "python", "golang", "pyinstaller", "discord", "upx", "electron", 
        "dll", "msi", "bat", "packer", "dropped", "extracted", "pif", "scr", "base-decoded", 
        "overdriven", "win", "generic", "unknown", "Cosmu", "Dropper", "Go", "Renamer",
        "ABB", "Akeo", "Hangzhou", "Foresee", "Happytuk", "Hiltd", "Hostgator", "Analize", 
        "FGHTING", "Growtopia", "LolKek", "bitbucket", "backblaze", "boxer-trc", "mapping", "zaanx",
        "test", "study_", "boxer", "opendir", "zip", "xll", "com", "bin", "gz", "prg", "reg", "sfx",
        "online", "team", "boxer", "dkuug", "mod-bussines", "payload", "boxer", "sfx"
    ]
}

def clasificar_multiopcion(tags_limpios):
    linea_lower = str(tags_limpios).lower()
    categorias_encontradas = []
    for cat, keywords in categorias.items():
        if any(key.lower() in linea_lower for key in keywords):
            categorias_encontradas.append(cat)
    if not categorias_encontradas:
        return "OTROS_NO_ENCAJAN"
    return ", ".join(categorias_encontradas)

df['categorias_mapeadas'] = df['tags_limpio'].apply(clasificar_multiopcion)

# --- MAPEO NUMÉRICO ---
# Ransomware (ID 5) se agrupa con OTROS para evitar clases vacías
mapping_ids = {
    "CRIMEN_FINANCIERO_Y_ROBO": 1,
    "INTRUSION_Y_PERSISTENCIA": 2,
    "HERRAMIENTAS_Y_VECTORES": 3,
    "TECNICOS_Y_SISTEMA": 4,
    "RANSOMWARE, WIPERS Y DESTRUCTIVOS": 5,
    "OTROS_NO_ENCAJAN": 5
}

nombres_clases = {1: "CRIMEN_FINANCIERO", 2: "INTRUSION", 3: "HERRAMIENTAS", 4: "TECNICO", 5: "OTROS/RANSOM", 0: "BENIGNO"}

def asignar_id(cat_string):
    primera_cat = cat_string.split(',')[0].strip()
    return mapping_ids.get(primera_cat, 5)

dict_lookup = pd.Series(df['categorias_mapeadas'].apply(asignar_id).values, index=df['hash']).to_dict()

# --- PROCESAMIENTO DEL DATASET DE FEATURES ---
dataset_path = '../dataset_mil_features_pure.csv'
dataset_balanceado_path = '../dataset_tfg_balanceado_bags.csv'
LIMITE_FUNCIONES_POR_CLASE = 500000 

try:
    print(f"Leyendo dataset: {dataset_path}...")
    ds = pd.read_csv(dataset_path)

    print("Asignando nuevas etiquetas...")
    ds['malware'] = ds['binary_hash'].map(dict_lookup).fillna(ds['malware']).astype(int)

    # --- BALANCEO POR BAGS (HASH COMPLETO) ---
    print(f"Iniciando balanceo por Bags (Límite: {LIMITE_FUNCIONES_POR_CLASE} funciones/clase)...")
    hashes_finales = []

    for clase_id in ds['malware'].unique():
        df_clase = ds[ds['malware'] == clase_id]
        
        # Agrupar por hash y contar funciones
        counts_per_hash = df_clase.groupby('binary_hash').size().reset_index(name='count')
        # Mezclar hashes
        counts_per_hash = counts_per_hash.sample(frac=1, random_state=42)
        # Suma acumulada
        counts_per_hash['cum_sum'] = counts_per_hash['count'].cumsum()
        
        # Seleccionar hashes hasta el límite
        seleccionados = counts_per_hash[counts_per_hash['cum_sum'] <= LIMITE_FUNCIONES_POR_CLASE]['binary_hash'].tolist()
        
        if not seleccionados and not counts_per_hash.empty:
            seleccionados = [counts_per_hash.iloc[0]['binary_hash']]
            
        hashes_finales.extend(seleccionados)
        print(f"  > Clase {clase_id} ({nombres_clases.get(clase_id)}): {len(seleccionados)} hashes seleccionados.")

    # Filtrar dataset final
    ds_final = ds[ds['binary_hash'].isin(hashes_finales)]
    
    # Guardar en un archivo NUEVO para seguridad, luego puedes borrar el viejo
    ds_final.to_csv(dataset_balanceado_path, index=False)

    print("\n" + "="*60)
    print("RESUMEN FINAL DEL DATASET BALANCEADO POR BAGS:")
    print("="*60)
    resumen = ds_final['malware'].value_counts().sort_index()
    for id_clase, total_f in resumen.items():
        n_h = ds_final[ds_final['malware'] == id_clase]['binary_hash'].nunique()
        print(f"ID {id_clase} | Funciones: {total_f:<10} | Hashes: {n_h:<6} | {nombres_clases.get(id_clase)}")
    print("="*60)
    print(f"Archivo guardado en: {dataset_balanceado_path}")

except Exception as e:
    print(f"Error: {e}")