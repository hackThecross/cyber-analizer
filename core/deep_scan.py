import os
import psutil
import socket
import subprocess
import winreg
import time
from collections import Counter
from core.hash_utils import calcular_sha256
from core.edr.persistencia import detectar_persistencia, detectar_scheduled_tasks, detectar_servicios_sospechosos

PUERTOS_PELIGROSOS = {
    21: "FTP no cifrado",
    23: "Telnet inseguro",
    1337: "Backdoor / C2",
    3389: "RDP expuesto",
    4444: "Metasploit / Payload Handler",
    5555: "Android ADB / RAT",
    6666: "IRC Botnet",
    7777: "C2 Server",
    9001: "Tor Relay / Proxy",
    31337: "Back Orifice"
}

def auditar_hosts_file():
    hallazgos = []
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    if os.path.exists(hosts_path):
        try:
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lineas = f.readlines()
            
            redirecciones_sospechosas = []
            for line in lineas:
                line_clean = line.strip()
                if line_clean and not line_clean.startswith("#"):
                    partes = line_clean.split()
                    if len(partes) >= 2:
                        ip, dom = partes[0], partes[1]
                        # Buscar si secuestran antivirus o dominios de seguridad
                        dom_low = dom.lower()
                        if any(sec in dom_low for sec in ["virustotal", "microsoft", "kaspersky", "symantec", "mcafee", "avast", "bitdefender", "malwarebytes"]):
                            redirecciones_sospechosas.append(f"{ip} -> {dom}")

            if redirecciones_sospechosas:
                hallazgos.append({
                    "fase": "Red y Comunicaciones",
                    "tipo": "Secuestro de Archivo Hosts (DNS Hijacking)",
                    "nivel": "CRÍTICO",
                    "mensaje": f"Se detectaron redirecciones maliciosas a dominios de seguridad en el archivo hosts: {', '.join(redirecciones_sospechosas)}",
                    "ruta": hosts_path
                })
        except Exception:
            pass
    return hallazgos


def auditar_procesos_activos():
    hallazgos = []
    rutas_riesgo = ["appdata", "temp", "downloads", "public"]
    nombres_legitimos = {"svchost.exe", "explorer.exe", "lsass.exe", "services.exe", "csrss.exe", "smss.exe"}

    for p in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_info']):
        try:
            info = p.info
            exe = info['exe'] or ""
            exe_low = exe.lower()
            name = (info['name'] or "").lower()

            if not exe:
                continue

            # 1. Suplantación de procesos de sistema
            if name in nombres_legitimos:
                # Deben estar en system32 o Windows
                if "windows\\system32" not in exe_low and "windows\\explorer.exe" not in exe_low and "windows\\syswow64" not in exe_low:
                    hallazgos.append({
                        "fase": "Memoria y Procesos",
                        "tipo": "Suplantación de Proceso Legítimo",
                        "nivel": "CRÍTICO",
                        "mensaje": f"Proceso '{info['name']}' ejecutándose fuera de System32: {exe}",
                        "pid": info['pid'],
                        "ruta": exe,
                        "sha256": calcular_sha256(exe)
                    })

            # 2. Ejecutable en ruta temporal o sospechosa
            elif any(r in exe_low for r in rutas_riesgo):
                hallazgos.append({
                    "fase": "Memoria y Procesos",
                    "tipo": "Ejecutable en Carpeta Sospechosa",
                    "nivel": "CRÍTICO" if info['cpu_percent'] > 20 else "MEDIO",
                    "mensaje": f"Proceso activo desde ruta inusual: {exe} (PID {info['pid']})",
                    "pid": info['pid'],
                    "ruta": exe,
                    "sha256": calcular_sha256(exe)
                })

            # 3. Uso excesivo de CPU (posible Cryptominer)
            if info['cpu_percent'] > 85:
                hallazgos.append({
                    "fase": "Memoria y Procesos",
                    "tipo": "Alto Consumo / Posible Minero",
                    "nivel": "MEDIO",
                    "mensaje": f"Proceso '{info['name']}' consumiendo {info['cpu_percent']}% de CPU",
                    "pid": info['pid'],
                    "ruta": exe
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return hallazgos

def auditar_zonas_criticas():
    hallazgos = []
    zonas = [
        os.environ.get("TEMP", ""),
        os.path.expandvars(r"%APPDATA%"),
        os.path.expandvars(r"%LOCALAPPDATA%"),
        os.path.expandvars(r"C:\Users\Public"),
        os.path.expandvars(r"%USERPROFILE%\Downloads")
    ]
    exts_script = {".vbs", ".bat", ".cmd", ".ps1", ".hta", ".wsf", ".js"}
    exts_bin = {".exe", ".dll", ".scr"}

    for zona in zonas:
        if not zona or not os.path.exists(zona):
            continue

        archivos_vistos = 0
        for root, dirs, files in os.walk(zona):
            # No profundizar más de 2 niveles en carpetas gigantes
            rel = os.path.relpath(root, zona)
            if rel.count(os.sep) > 2:
                continue

            for f in files:
                archivos_vistos += 1
                if archivos_vistos > 400:
                    break

                fp = os.path.join(root, f)
                f_low = f.lower()
                _, ext = os.path.splitext(f_low)

                # Script peligroso suelto
                if ext in exts_script and any(x in f_low for x in ["install", "update", "payload", "crack", "patch", "run", "start"]):
                    hallazgos.append({
                        "fase": "Zonas Críticas de Disco",
                        "tipo": "Script Sospechoso Detectado",
                        "nivel": "MEDIO",
                        "mensaje": f"Script encontrado en zona volátil: {fp}",
                        "ruta": fp,
                        "sha256": calcular_sha256(fp)
                    })

                # Doble extensión
                partes = f_low.split(".")
                if len(partes) >= 3 and f".{partes[-1]}" in (exts_bin | exts_script):
                    hallazgos.append({
                        "fase": "Zonas Críticas de Disco",
                        "tipo": "Doble Extensión Engañosa",
                        "nivel": "CRÍTICO",
                        "mensaje": f"Archivo con extensión oculta/doble: {fp}",
                        "ruta": fp,
                        "sha256": calcular_sha256(fp)
                    })

    return hallazgos


def auditar_red_puertos():
    hallazgos = []
    try:
        conns = psutil.net_connections(kind="inet")
        for c in conns:
            if c.status == "LISTEN" and c.laddr:
                port = c.laddr.port
                if port in PUERTOS_PELIGROSOS:
                    hallazgos.append({
                        "fase": "Red y Comunicaciones",
                        "tipo": "Puerto Sensible / Peligroso Abierto",
                        "nivel": "CRÍTICO" if port in [1337, 4444, 5555, 6666, 31337] else "MEDIO",
                        "mensaje": f"Puerto {port} ({PUERTOS_PELIGROSOS[port]}) escuchando en {c.laddr.ip} (PID {c.pid})",
                        "pid": c.pid
                    })
    except Exception:
        pass

    hallazgos.extend(auditar_hosts_file())
    return hallazgos


def auditar_postura_seguridad():
    hallazgos = []
    # 1. Comprobar UAC (User Account Control)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            enable_lua, _ = winreg.QueryValueEx(key, "EnableLUA")
            if enable_lua == 0:
                hallazgos.append({
                    "fase": "Postura de Seguridad",
                    "tipo": "UAC Deshabilitado",
                    "nivel": "CRÍTICO",
                    "mensaje": "El Control de Cuentas de Usuario (UAC) está completamente desactivado, facilitando la ejecución de malware sin confirmación."
                })
    except Exception:
        pass

    # 2. Comprobar Firewall
    try:
        res = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True, errors="ignore")
        if "OFF" in res.stdout or "DESACTIVADO" in res.stdout.upper():
            hallazgos.append({
                "fase": "Postura de Seguridad",
                "tipo": "Firewall de Windows Desactivado",
                "nivel": "CRÍTICO",
                "mensaje": "Al menos un perfil del Firewall de Windows se encuentra desactivado."
            })
    except Exception:
        pass

    return hallazgos


def ejecutar_analisis_profundo(callback_fase=None):
    """
    Ejecuta el análisis profundo completo del sistema.
    """
    hallazgos = []

    # Fase 1: Procesos
    if callback_fase:
        callback_fase("Auditando Memoria y Procesos Activos...", 20)
    time.sleep(0.3)
    hallazgos.extend(auditar_procesos_activos())

    # Fase 2: Persistencia
    if callback_fase:
        callback_fase("Revisando Registro, Tareas y Servicios de Persistencia...", 40)
    time.sleep(0.3)
    for a in detectar_persistencia():
        a["fase"] = "Persistencia y Auto-Inicio"
        hallazgos.append(a)
    for a in detectar_scheduled_tasks():
        a["fase"] = "Persistencia y Auto-Inicio"
        hallazgos.append(a)
    for a in detectar_servicios_sospechosos():
        a["fase"] = "Persistencia y Auto-Inicio"
        hallazgos.append(a)

    # Fase 3: Red y Puertos
    if callback_fase:
        callback_fase("Inspeccionando Puertos, Conexiones y Archivo Hosts...", 60)
    time.sleep(0.3)
    hallazgos.extend(auditar_red_puertos())

    # Fase 4: Archivos y Zonas Críticas
    if callback_fase:
        callback_fase("Escaneando Zonas Críticas del Sistema (%TEMP%, AppData, etc.)...", 80)
    time.sleep(0.3)
    hallazgos.extend(auditar_zonas_criticas())

    # Fase 5: Postura de Seguridad
    if callback_fase:
        callback_fase("Evaluando Postura de Seguridad y Configuración de Windows...", 95)
    time.sleep(0.3)
    hallazgos.extend(auditar_postura_seguridad())

    if callback_fase:
        callback_fase("Generando Reporte de Amenazas...", 100)

    # Calcular puntaje de seguridad (Health Score) de 0 a 100
    criticos = sum(1 for h in hallazgos if h.get("nivel") == "CRÍTICO")
    medios = sum(1 for h in hallazgos if h.get("nivel") == "MEDIO" or h.get("nivel") == "ALTO")

    score = 100 - (criticos * 25 + medios * 10)
    if score < 10:
        score = 10 if (criticos or medios) else 100

    if score >= 85:
        estado_global = "SEGURO"
        color_estado = "#00ff9c"
    elif score >= 60:
        estado_global = "PRECAUCIÓN"
        color_estado = "#ffcc00"
    else:
        estado_global = "VULNERABLE / EN RIESGO"
        color_estado = "#ff4c4c"

    return {
        "score": score,
        "estado_global": estado_global,
        "color_estado": color_estado,
        "total_hallazgos": len(hallazgos),
        "criticos": criticos,
        "medios": medios,
        "hallazgos": hallazgos,
        "fecha": time.strftime("%Y-%m-%d %H:%M:%S")
    }
