import os
import winreg
import subprocess
import csv
import io
import psutil

RUTAS_SOSPECHOSAS = [
    "appdata",
    "temp",
    "downloads",
    "public",
    "users"
]

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
]

STARTUP_DIRS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
]


def detectar_persistencia():
    alertas = []

    # ───── REGISTRY RUN ─────
    for root, path in RUN_KEYS:
        try:
            key = winreg.OpenKey(root, path)
            i = 0
            while True:
                nombre, valor, _ = winreg.EnumValue(key, i)
                i += 1

                ruta = valor.lower()
                sospechoso = any(r in ruta for r in RUTAS_SOSPECHOSAS)

                if sospechoso:
                    alertas.append({
                        "tipo": "Persistencia (Registry Run)",
                        "nivel": "CRÍTICO",
                        "mensaje": f"{nombre} → {valor}",
                        "ruta": valor
                    })
        except OSError:
            pass

    # ───── STARTUP FOLDERS ─────
    for folder in STARTUP_DIRS:
        if not os.path.isdir(folder):
            continue

        for f in os.listdir(folder):
            ruta = os.path.join(folder, f)
            low = ruta.lower()

            if any(r in low for r in RUTAS_SOSPECHOSAS):
                alertas.append({
                    "tipo": "Persistencia (Startup Folder)",
                    "nivel": "CRÍTICO",
                    "mensaje": ruta,
                    "ruta": ruta
                })

    return alertas

PALABRAS_PELIGROSAS = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "base64",
    "-enc",
]

RUTAS_PELIGROSAS = [
    "appdata",
    "temp",
    "public",
    "users"
]


def detectar_scheduled_tasks():
    alertas = []

    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            capture_output=True,
            text=True,
            errors="ignore"
        )

        reader = csv.DictReader(io.StringIO(proc.stdout))

        for row in reader:
            comando = (row.get("Task To Run") or "").lower()
            nombre = row.get("TaskName")

            if not comando:
                continue

            sospechoso = (
                any(p in comando for p in PALABRAS_PELIGROSAS) or
                any(r in comando for r in RUTAS_PELIGROSAS)
            )

            if sospechoso:
                alertas.append({
                    "tipo": "Persistencia (Scheduled Task)",
                    "nivel": "CRÍTICO",
                    "mensaje": f"{nombre} → {comando}",
                    "comando": comando
                })

    except Exception:
        pass

    return alertas


def detectar_servicios_sospechosos():
    alertas = []

    for s in psutil.win_service_iter():
        try:
            info = s.as_dict()
            path = (info.get("binpath") or "").lower()

            if not path:
                continue

            sospechoso = (
                info.get("start_type") == "auto" and
                any(r in path for r in RUTAS_PELIGROSAS) and
                "system32" not in path
            )

            if sospechoso:
                alertas.append({
                    "tipo": "Persistencia (Servicio)",
                    "nivel": "CRÍTICO",
                    "mensaje": f"{info['name']} → {path}",
                    "servicio": info["name"],
                    "ruta": path
                })

        except Exception:
            pass

    return alertas