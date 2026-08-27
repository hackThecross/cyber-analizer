import os
import json
import sys

def get_base_data_dir():
    """
    Retorna el directorio de datos adecuado para guardar configuración, logs y cuarentena.
    Si el directorio de la aplicación tiene permisos de escritura (portable o desarrollo), se usa ese.
    Si está en 'Program Files' o modo sólo lectura, usa %LOCALAPPDATA%\\CyberAnalyzer.
    """
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Verificar si base_dir es escribible
    try:
        test_file = os.path.join(base_dir, ".perm_test")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("ok")
        if os.path.exists(test_file):
            os.remove(test_file)
        return base_dir
    except (PermissionError, OSError):
        appdata = os.environ.get("LOCALAPPDATA", os.environ.get("APPDATA", base_dir))
        target_dir = os.path.join(appdata, "CyberAnalyzer")
        os.makedirs(target_dir, exist_ok=True)
        return target_dir


def get_writable_path(subpath):
    base_dir = get_base_data_dir()
    full_path = os.path.join(base_dir, subpath)
    return full_path


CONFIG_FILE = get_writable_path("settings.json")
CONFIG_PY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.py")

DEFAULT_CONFIG = {
    "vt_api_key": "85d99e45f5361ed99cd2eddbf31e35dbf249d80a3600cdeac876cc0b584a17c4",
    "quarantine_dir": "cuarentena",
    "auto_refresh_procesos": 3,
    "nivel_sensibilidad": "Normal",
    "notificaciones_alertas": True,
    "tema": "Oscuro (Cyber)",
    "github_repo": "hackThecross/cyber-analizer",
    "check_updates_startup": True
}

def cargar_configuracion():
    cfg = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                guardado = json.load(f)
                cfg.update(guardado)
        except Exception:
            pass
    elif os.path.exists(CONFIG_PY_FILE):
        try:
            from config import VT_API_KEY
            cfg["vt_api_key"] = VT_API_KEY
        except Exception:
            pass

    return cfg


def guardar_configuracion(nueva_config):
    cfg = cargar_configuracion()
    cfg.update(nueva_config)

    # 1. Guardar settings.json
    try:
        config_path = get_writable_path("settings.json")
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4, ensure_ascii=False)
    except Exception:
        pass

    # 2. Sincronizar config.py para retrocompatibilidad si es posible
    try:
        if not getattr(sys, 'frozen', False) and os.path.exists(CONFIG_PY_FILE):
            with open(CONFIG_PY_FILE, "w", encoding="utf-8") as f:
                f.write(f'VT_API_KEY = "{cfg.get("vt_api_key", "")}"\n')
    except Exception:
        pass

    return True


def probar_conexion_vt(api_key):
    """
    Verifica si la API Key de VirusTotal es válida realizando una petición de prueba.
    """
    if not api_key:
        return False, "La API Key no puede estar vacía"

    import requests
    try:
        headers = {"x-apikey": api_key.strip()}
        # Test con un hash conocido (calc.exe sha256 o similar)
        test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{test_hash}", headers=headers, timeout=10)
        if r.status_code == 200:
            return True, "✅ Conexión con VirusTotal API exitosa. Clave válida."
        elif r.status_code == 401:
            return False, "❌ Clave de API no autorizada o inválida (Error 401)."
        elif r.status_code == 429:
            return True, "⚠️ Cuota excedida temporalmente en VirusTotal, pero la clave es válida (Error 429)."
        else:
            return False, f"Respuesta inesperada del servidor VirusTotal: Código {r.status_code}"
    except Exception as e:
        return False, f"Error de conexión de red: {e}"
