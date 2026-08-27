# core/redr.py

import psutil
from core.utils_red import ip_externa

def evaluar_proceso(p, conexiones):
    score = 0
    motivos = []

    for c in conexiones:
        if c.get("pid") == p.pid and ip_externa(c.get("ip")):
            score += 30
            motivos.append("Conexión a IP externa")

    if p.name().lower() in ("powershell.exe", "cmd.exe"):
        score += 20
        motivos.append("Proceso sensible")

    return score, motivos


def generar_eventos_edr(conexiones):
    eventos = []

    for p in psutil.process_iter(["pid", "name"]):
        try:
            score, motivos = evaluar_proceso(p, conexiones)

            if score >= 30:
                eventos.append({
                    "tipo": "Actividad sospechosa de red",
                    "nivel": "CRÍTICO" if score >= 60 else "MEDIO",
                    "pid": p.pid,
                    "nombre": p.name(),
                    "riesgo": score,
                    "motivos": motivos
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return eventos
