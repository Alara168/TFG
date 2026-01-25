import pandas as pd
import re
import numpy as np

# 1. CARGAR ARCHIVOS DE ETIQUETAS
try:
    df_tags = pd.read_csv('hashes_exe.csv', sep=';')
except FileNotFoundError:
    df_tags = pd.read_csv('hashes.csv', sep=';')

# 2. FUNCIÓN DE LIMPIEZA DE TAGS
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

df_tags['tags_limpio'] = df_tags['tags'].apply(limpiar_tags)

# 3. DICCIONARIO DE CATEGORÍAS
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
    return ", ".join(categorias_encontradas) if categorias_encontradas else "OTROS_NO_ENCAJAN"

df_tags['categorias_mapeadas'] = df_tags['tags_limpio'].apply(clasificar_multiopcion)

# 4. MAPEO A IDs NUMÉRICOS (Unificado)
# 0: Benigno (asumiendo que viene en el dataset original)
# 1: Financiero
# 2: Intrusion
# 3: Herramientas y Sistema (clases 3 y 4 unificadas)
# 4: Ransomware y Otros
mapping_ids = {
    "CRIMEN_FINANCIERO_Y_ROBO": 1,
    "INTRUSION_Y_PERSISTENCIA": 2,
    "HERRAMIENTAS_Y_SISTEMA": 3,
    "RANSOMWARE, WIPERS Y DESTRUCTIVOS": 4,
    "OTROS_NO_ENCAJAN": 4
}

def asignar_id(cat_string):
    # Cogemos la primera categoría detectada
    primera_cat = cat_string.split(',')[0].strip()
    # Si es Herramientas o Tecnicos, ambos devuelven 3
    if primera_cat in ["HERRAMIENTAS_Y_VECTORES", "TECNICOS_Y_SISTEMA", "HERRAMIENTAS_Y_SISTEMA"]:
        return 3
    return mapping_ids.get(primera_cat, 4)

# Diccionario de búsqueda rápido
dict_lookup = pd.Series(df_tags['categorias_mapeadas'].apply(asignar_id).values, index=df_tags['hash']).to_dict()

# 5. PROCESAMIENTO DEL DATASET
dataset_path = '../dataset_mil_features_pure.csv'
dataset_output_path = '../dataset_tfg_etiquetado_completo.csv'

try:
    print(f"Leyendo dataset original: {dataset_path}...")
    ds = pd.read_csv(dataset_path)

    print("Asignando nuevas etiquetas unificadas...")
    ds['malware'] = ds['binary_hash'].map(dict_lookup).fillna(ds['malware']).astype(int)

    # Guardar
    ds.to_csv(dataset_output_path, index=False)
    
    print(f"¡Hecho! Dataset unificado guardado en: {dataset_output_path}")
    print("\nNueva distribución de clases:")
    resumen = ds['malware'].value_counts().sort_index()
    print(resumen)

except Exception as e:
    print(f"Error: {e}")