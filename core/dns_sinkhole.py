import os
import subprocess
import json
from core.settings_manager import get_writable_path
from core.security_logs import registrar_accion_edr
from core.audio_alerts import reproducir_bloqueo_exitoso, reproducir_sonido_exito

SINKHOLE_CONFIG_FILE = get_writable_path("dns_sinkhole.json")
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"

DOMINIOS_MALICIOSOS_DEFAULT = [
    "coinhive.com", "crypto-loot.com", "webminerpool.com",
    "c2-rat-payload.biz", "dark-payload-handler.net", "botnet-beacon.xyz",
    "secure-login-apple-support.xyz", "update-microsoft-security.net",
    "paypal-verification-account.top", "bank-login-secure-auth.club",
    "ransomware-decryption-key.cc", "cobaltstrike-listener.org"
]

def cargar_config_sinkhole():
    cfg = {
        "activo": False,
        "dominios_bloqueados": list(DOMINIOS_MALICIOSOS_DEFAULT)
    }
    if os.path.exists(SINKHOLE_CONFIG_FILE):
        try:
            with open(SINKHOLE_CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                cfg.update(saved)
        except Exception:
            pass
    return cfg


def guardar_config_sinkhole(nueva_config):
    cfg = cargar_config_sinkhole()
    cfg.update(nueva_config)
    try:
        with open(SINKHOLE_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def aplicar_escudo_sinkhole(habilitar=True):
    """
    Aplica o retira el bloqueo a nivel de resolución DNS de dominios maliciosos en el archivo hosts de Windows.
    """
    cfg = cargar_config_sinkhole()
    cfg["activo"] = habilitar
    guardar_config_sinkhole(cfg)

    dominios = cfg.get("dominios_bloqueados", DOMINIOS_MALICIOSOS_DEFAULT)

    try:
        # 1. Leer hosts actual y remover entradas anteriores de CyberAnalyzer
        subprocess.run(["attrib", "-r", "-s", "-h", HOSTS_FILE], shell=True)

        lineas_existentes = []
        if os.path.exists(HOSTS_FILE):
            with open(HOSTS_FILE, "r", encoding="utf-8", errors="ignore") as f:
                lineas_existentes = f.readlines()

        lineas_limpias = [l for l in lineas_existentes if "# CYBER_ANALYZER_SINKHOLE" not in l]

        if habilitar:
            # 2. Agregar bloqueos DNS hacia 0.0.0.0
            lineas_limpias.append("\n# CYBER_ANALYZER_SINKHOLE_START\n")
            for d in dominios:
                d_clean = d.strip()
                if d_clean:
                    lineas_limpias.append(f"0.0.0.0    {d_clean}    # CYBER_ANALYZER_SINKHOLE\n")
            lineas_limpias.append("# CYBER_ANALYZER_SINKHOLE_END\n")

        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            f.writelines(lineas_limpias)

        # 3. Purgar caché DNS de Windows
        subprocess.run(["ipconfig", "/flushdns"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if habilitar:
            registrar_accion_edr("DNS_SINKHOLE_ENABLED", f"Escudo Anti-Phishing activado ({len(dominios)} dominios bloqueados).", nivel="ALTO", exito=True)
            reproducir_bloqueo_exitoso()
            return True, f"🛡️ ESCUDO SINKHOLE ACTIVADO: Se han bloqueado {len(dominios)} dominios maliciosos y de phishing a nivel de sistema."
        else:
            registrar_accion_edr("DNS_SINKHOLE_DISABLED", "Escudo Anti-Phishing desactivado.", nivel="INFO", exito=True)
            reproducir_sonido_exito()
            return True, "🟢 ESCUDO SINKHOLE DESACTIVADO: Dominios restaurados."

    except Exception as e:
        return False, f"Error al modificar resolución DNS (¿Requiere permisos de Administrador?): {e}"


def agregar_dominio_sinkhole(dominio):
    cfg = cargar_config_sinkhole()
    doms = cfg.get("dominios_bloqueados", [])
    d_clean = dominio.strip().lower()
    if d_clean and d_clean not in doms:
        doms.append(d_clean)
        cfg["dominios_bloqueados"] = doms
        guardar_config_sinkhole(cfg)
        if cfg.get("activo", False):
            aplicar_escudo_sinkhole(True)
        return True, f"Dominio '{d_clean}' añadido al escudo de bloqueo."
    return False, "El dominio ya existe o no es válido."
