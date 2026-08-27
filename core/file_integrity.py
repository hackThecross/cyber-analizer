import os
import json
import hashlib
from datetime import datetime
from core.settings_manager import get_writable_path
from core.security_logs import registrar_accion_edr

FIM_BASELINE_FILE = get_writable_path("fim_baseline.json")

ARCHIVOS_CRITICOS = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\taskmgr.exe"
]

def _calcular_sha256(ruta):
    if not os.path.exists(ruta):
        return None
    try:
        h = hashlib.sha256()
        with open(ruta, "rb") as f:
            for chunk in iter(lambda: f.read(16384), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def crear_linea_base_fim():
    """Genera y guarda la línea base criptográfica de archivos del sistema."""
    baseline = {}
    for ruta in ARCHIVOS_CRITICOS:
        if os.path.exists(ruta):
            h = _calcular_sha256(ruta)
            if h:
                baseline[ruta] = {
                    "sha256": h,
                    "tamano": os.path.getsize(ruta),
                    "fecha_base": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

    try:
        with open(FIM_BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2)
        return True, f"Línea base FIM creada con éxito ({len(baseline)} archivos auditados)."
    except Exception as e:
        return False, str(e)


def auditar_integridad_archivos():
    """Compara el estado actual de los archivos contra la línea base registrada."""
    if not os.path.exists(FIM_BASELINE_FILE):
        crear_linea_base_fim()

    baseline = {}
    try:
        with open(FIM_BASELINE_FILE, "r", encoding="utf-8") as f:
            baseline = json.load(f)
    except Exception:
        pass

    resultados = []
    for ruta in ARCHIVOS_CRITICOS:
        if not os.path.exists(ruta):
            resultados.append({
                "archivo": os.path.basename(ruta),
                "ruta": ruta,
                "estado": "ELIMINADO / INACCESIBLE",
                "nivel": "CRÍTICO",
                "detalle": "El archivo del sistema no fue encontrado."
            })
            continue

        h_actual = _calcular_sha256(ruta)
        base_info = baseline.get(ruta)

        if not base_info:
            resultados.append({
                "archivo": os.path.basename(ruta),
                "ruta": ruta,
                "estado": "NUEVO / SIN LÍNEA BASE",
                "nivel": "INFO",
                "detalle": "Archivo presente sin firma previa registrada."
            })
        elif h_actual != base_info["sha256"]:
            # Detección especial en archivo hosts
            is_hosts = "hosts" in ruta.lower()
            resultados.append({
                "archivo": os.path.basename(ruta),
                "ruta": ruta,
                "estado": "MODIFICADO / POSIBLE HIJACKING" if is_hosts else "MODIFICADO",
                "nivel": "CRÍTICO",
                "detalle": "La firma criptográfica no coincide con la línea base original."
            })
        else:
            resultados.append({
                "archivo": os.path.basename(ruta),
                "ruta": ruta,
                "estado": "INTEGRO (VERIFICADO)",
                "nivel": "SEGURO",
                "detalle": "Firma SHA-256 coincide exactamente con la línea base."
            })

    return resultados


def restaurar_archivo_hosts_limpio():
    """Restaura el archivo hosts de Windows a su configuración predeterminada de fábrica."""
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    default_hosts = (
        "# Copyright (c) 1993-2009 Microsoft Corp.\n"
        "# Default Windows Hosts File\n"
        "127.0.0.1       localhost\n"
        "::1             localhost\n"
    )
    try:
        subprocess.run(["attrib", "-r", "-s", "-h", hosts_path], shell=True)
        with open(hosts_path, "w", encoding="utf-8") as f:
            f.write(default_hosts)
        registrar_accion_edr("RESTORE_HOSTS", "Archivo hosts de Windows restaurado a valores por defecto limpios.", nivel="ALTO", exito=True)
        return True, "✅ Archivo hosts restaurado a la configuración original de Microsoft."
    except Exception as e:
        return False, f"Error al restaurar archivo hosts: {e}"
