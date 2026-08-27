import os
import subprocess
import json
from datetime import datetime
from core.settings_manager import get_writable_path
from core.security_logs import registrar_accion_edr
from core.audio_alerts import reproducir_alerta_panico, reproducir_sonido_exito

PANIC_STATE_FILE = get_writable_path("panic_state.json")

def estado_modo_panico():
    """Retorna True si el equipo se encuentra actualmente en aislamiento total de emergencia."""
    if os.path.exists(PANIC_STATE_FILE):
        try:
            with open(PANIC_STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("panico_activo", False)
        except Exception:
            return False
    return False


def activar_modo_panico():
    """
    AISLAMIENTO TOTAL DE EMERGENCIA:
    Corta instantáneamente todas las conexiones de red entrantes y salientes mediante Windows Firewall
    para frenar ataques activos, exfiltración de datos o propagación de malware.
    """
    try:
        # 1. Bloquear todo el tráfico entrante y saliente
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"], shell=True, check=True)
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], shell=True, check=True)

        # 2. Agregar regla maestra de corte total CyberEDR_LOCKDOWN
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=CyberEDR_EMERGENCY_LOCKDOWN_OUT",
            "dir=out", "action=block", "protocol=any"
        ], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=CyberEDR_EMERGENCY_LOCKDOWN_IN",
            "dir=in", "action=block", "protocol=any"
        ], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 3. Guardar estado
        with open(PANIC_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"panico_activo": True, "fecha_activacion": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, f, indent=2)

        registrar_accion_edr("MODO_PANICO_ACTIVADO", "Aislamiento total de red activado. Todo el tráfico entrante y saliente ha sido cortado.", nivel="CRÍTICO", exito=True)
        reproducir_alerta_panico()

        return True, "🚨 MODO PÁNICO ACTIVADO: El equipo ha sido completamente aislado de la red. Ningún atacante o malware puede comunicarse."

    except Exception as e:
        registrar_accion_edr("MODO_PANICO_FALLIDO", f"Error al aislar equipo: {e}", nivel="CRÍTICO", exito=False)
        return False, f"No se pudo activar el aislamiento total (¿Requiere privilegios de Administrador?): {e}"


def desactivar_modo_panico():
    """
    Restaura la conectividad normal de red del equipo eliminando las reglas de aislamiento de emergencia.
    """
    try:
        # 1. Eliminar reglas de corte de emergencia
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=CyberEDR_EMERGENCY_LOCKDOWN_OUT"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=CyberEDR_EMERGENCY_LOCKDOWN_IN"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 2. Restaurar política normal (bloquear entrante no solicitado, permitir saliente normal)
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"], shell=True, check=True)

        # 3. Actualizar estado
        with open(PANIC_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"panico_activo": False, "fecha_desactivacion": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, f, indent=2)

        registrar_accion_edr("MODO_PANICO_DESACTIVADO", "Conectividad de red normal restaurada con éxito.", nivel="INFO", exito=True)
        reproducir_sonido_exito()

        return True, "🟢 CONECTIVIDAD RESTAURADA: Las reglas de aislamiento han sido removidas. El tráfico de red opera normalmente."

    except Exception as e:
        return False, f"Error al restaurar conectividad: {e}"
