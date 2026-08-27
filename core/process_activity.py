import psutil
import os

RUTAS_SOSPECHOSAS = [
    "appdata",
    "temp",
    "downloads",
    "\\users\\public"
]

def calcular_riesgo_proceso(proc):
    ruta = (proc.get("ruta") or "").lower()

    for r in RUTAS_SOSPECHOSAS:
        if r in ruta:
            return "ALTO"

    cpu_val = proc.get("cpu") or 0
    ram_val = proc.get("ram") or 0
    if cpu_val > 50 or ram_val > 500:
        return "MEDIO"

    return "BAJO"


def obtener_procesos_activos():
    procesos = []

    for p in psutil.process_iter(
        ["pid", "name", "username", "cpu_percent", "memory_info", "exe"]
    ):
        try:
            info = p.info
            mem = info.get("memory_info")
            ram_mb = round(mem.rss / (1024 * 1024), 2) if mem else 0.0

            procesos.append({
                "pid": info.get("pid"),
                "nombre": info.get("name") or "Desconocido",
                "usuario": info.get("username") or "",
                "cpu": info.get("cpu_percent") or 0,
                "ram": ram_mb,
                "ruta": info.get("exe") or "",
            })

        except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
            continue

    return procesos
