import os
import subprocess
import json
import csv
import io
from datetime import datetime
from core.settings_manager import get_writable_path

LOGS_DIR = get_writable_path("logs")
EDR_LOG_FILE = os.path.join(LOGS_DIR, "cyber_edr_audit.log")

EVENTOS_INTERES = {
    "4624": {"nombre": "Inicio de Sesión Exitoso", "nivel": "INFO", "categoria": "Autenticación"},
    "4625": {"nombre": "Intento Fallido de Inicio de Sesión", "nivel": "CRÍTICO", "categoria": "Fuerza Bruta / Acceso"},
    "4688": {"nombre": "Nuevo Proceso Creado", "nivel": "INFO", "categoria": "Ejecución"},
    "7045": {"nombre": "Nuevo Servicio Instalado en Windows", "nivel": "CRÍTICO", "categoria": "Persistencia"},
    "1102": {"nombre": "Registro de Auditoría Borrado", "nivel": "CRÍTICO", "categoria": "Evasión de Defensa"},
    "4720": {"nombre": "Nueva Cuenta de Usuario Creada", "nivel": "CRÍTICO", "categoria": "Persistencia"},
}

def registrar_accion_edr(accion, detalle, nivel="INFO", exito=True):
    os.makedirs(LOGS_DIR, exist_ok=True)
    registro = {
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "accion": accion,
        "detalle": detalle,
        "nivel": nivel,
        "resultado": "ÉXITO" if exito else "ERROR"
    }

    try:
        with open(EDR_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(registro, ensure_ascii=False) + "\n")
    except Exception:
        pass


def obtener_historial_edr():
    if not os.path.exists(EDR_LOG_FILE):
        return []

    registros = []
    try:
        with open(EDR_LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line_clean = line.strip()
                if line_clean:
                    try:
                        registros.append(json.loads(line_clean))
                    except Exception:
                        pass
    except Exception:
        pass

    return list(reversed(registros))


def limpiar_historial_edr():
    if os.path.exists(EDR_LOG_FILE):
        try:
            with open(EDR_LOG_FILE, "w", encoding="utf-8") as f:
                f.write("")
            return True, "Historial de auditoría EDR limpiado con éxito"
        except Exception as e:
            return False, str(e)
    return True, "Historial limpio"


def obtener_logs_seguridad_windows(max_eventos=40):
    """
    Obtiene eventos recientes del registro de seguridad o sistema de Windows utilizando wevtutil.
    """
    eventos = []

    # 1. Intentar Security log
    try:
        cmd = ["wevtutil", "qe", "Security", f"/c:{max_eventos}", "/rd:true", "/f:text"]
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
        if proc.returncode == 0 and proc.stdout:
            bloques = proc.stdout.split("Event[")
            for b in bloques:
                if not b.strip():
                    continue
                # Extraer Event ID, Date, User
                event_id = None
                fecha = None
                user = "N/A"
                for line in b.splitlines():
                    line_s = line.strip()
                    if "Event ID:" in line_s:
                        event_id = line_s.split(":")[-1].strip()
                    elif "Date:" in line_s:
                        fecha = line_s.replace("Date:", "").strip()
                    elif "Account Name:" in line_s or "Nombre de cuenta:" in line_s:
                        user = line_s.split(":")[-1].strip()

                if event_id:
                    info_meta = EVENTOS_INTERES.get(event_id, {
                        "nombre": f"Evento de Seguridad ID {event_id}",
                        "nivel": "INFO",
                        "categoria": "Sistema / Seguridad"
                    })
                    eventos.append({
                        "id": event_id,
                        "nombre": info_meta["nombre"],
                        "nivel": info_meta["nivel"],
                        "categoria": info_meta["categoria"],
                        "fecha": fecha or "Reciente",
                        "usuario": user,
                        "origen": "Windows Security Log"
                    })
    except Exception:
        pass

    # 2. Si no hay permisos para Security log (requiere Admin), consultar System log
    if len(eventos) < 5:
        try:
            cmd = ["wevtutil", "qe", "System", f"/c:{max_eventos}", "/rd:true", "/f:text"]
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
            if proc.returncode == 0 and proc.stdout:
                bloques = proc.stdout.split("Event[")
                for b in bloques:
                    if not b.strip():
                        continue
                    event_id = None
                    fecha = None
                    for line in b.splitlines():
                        line_s = line.strip()
                        if "Event ID:" in line_s:
                            event_id = line_s.split(":")[-1].strip()
                        elif "Date:" in line_s:
                            fecha = line_s.replace("Date:", "").strip()

                    if event_id:
                        info_meta = EVENTOS_INTERES.get(event_id, {
                            "nombre": f"Evento de Sistema ID {event_id}",
                            "nivel": "INFO" if event_id not in ["7045", "1000", "1001"] else "CRÍTICO",
                            "categoria": "Sistema Windows"
                        })
                        eventos.append({
                            "id": event_id,
                            "nombre": info_meta["nombre"],
                            "nivel": info_meta["nivel"],
                            "categoria": info_meta["categoria"],
                            "fecha": fecha or "Reciente",
                            "usuario": "SYSTEM",
                            "origen": "Windows System Log"
                        })
        except Exception:
            pass

    return eventos[:max_eventos]
