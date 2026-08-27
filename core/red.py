import psutil
import socket
import subprocess
import platform
from collections import Counter
from core.edr.persistencia import (
    detectar_persistencia,
    detectar_scheduled_tasks,
    detectar_servicios_sospechosos
)
from collections import defaultdict
import time
import re
import math
from core.redr import generar_eventos_edr
from core.utils_red import ip_externa
from core.software_inventory import obtener_programas_instalados

#botnet y rutas sopechosas
# ─────────────────────────────────────────────
# INDICADORES DE C2 / BOTNET
# ─────────────────────────────────────────────

PUERTOS_C2 = {
    1337, 4444, 5555, 6666, 7777,
    9001,    # Tor
    23,      # Telnet (Mirai)
    2323,    # Telnet alternativo
    1080,    # SOCKS proxy
    3389,    # RATs por RDP
    53       # DNS tunneling
}

RUTAS_SOSPECHOSAS = [
    "appdata",
    "temp",
    "roaming",
    "downloads",
    "programdata"
]


# ─────────────────────────────────────────────
# INDICADORES DE AMENAZA
# ─────────────────────────────────────────────

PUERTOS_C2 = {1337, 4444, 5555, 6666, 7777, 9001, 1080, 53}
PUERTOS_RAT = {3389, 5900, 22, 23, 2323}
PUERTOS_BACKDOOR = {4444, 5555, 31337}

DOMINIOS_DINAMICOS = [
    ".duckdns.org", ".no-ip.org", ".ddns.net",
    ".dyndns.org", ".servehttp.com"
]

RUTAS_SOSPECHOSAS = [
    "appdata", "temp", "roaming", "programdata"
]



# ─────────────────────────────────────────
# IP PÚBLICA (opcional y segura)
# ─────────────────────────────────────────
def obtener_ip_publica():
    try:
        import urllib.request
        return urllib.request.urlopen("https://api.ipify.org").read().decode()
    except:
        return "No disponible"

# ─────────────────────────────────────────
# INTERFACES DE RED
# ─────────────────────────────────────────
def interfaces_red():
    data = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface, addr_list in addrs.items():
        ip = mac = None
        for a in addr_list:
            if a.family == socket.AF_INET:
                ip = a.address
            elif a.family == psutil.AF_LINK:
                mac = a.address

        estado = "UP" if stats.get(iface) and stats[iface].isup else "DOWN"

        data.append({
            "interfaz": iface,
            "ip": ip,
            "mac": mac,
            "estado": estado
        })
    return data

# ─────────────────────────────────────────
# DNS Y GATEWAY
# ─────────────────────────────────────────
def dns_gateway():
    dns = []
    gateway = "No detectado"

    try:
        if platform.system() == "Windows":
            salida = subprocess.check_output("ipconfig /all", shell=True, text=True)
            for line in salida.splitlines():
                if "DNS Servers" in line:
                    dns.append(line.split(":")[-1].strip())
                if "Default Gateway" in line:
                    gateway = line.split(":")[-1].strip()
        else:
            salida = subprocess.check_output("nmcli dev show", shell=True, text=True)
    except:
        pass

    return {
        "dns": dns,
        "gateway": gateway
    }

# ─────────────────────────────────────────
# PUERTOS Y CONEXIONES
# ─────────────────────────────────────────
def conexiones_red():
    conexiones = []
    puertos_abiertos = []

    for c in psutil.net_connections(kind="inet"):
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None

        item = {
            "local": laddr,
            "remoto": raddr,
            "estado": c.status,
            "pid": c.pid
        }

        conexiones.append(item)

        if c.status == "LISTEN":
            puertos_abiertos.append(item)

    return conexiones, puertos_abiertos

def procesos_conectados():
    procesos = {}

    for c in psutil.net_connections(kind="inet"):
        if not c.raddr or not c.pid:
            continue

        try:
            p = psutil.Process(c.pid)
            exe = p.exe()
            nombre = p.name()
        except:
            continue

        key = (c.pid, exe)
        if key not in procesos:
            procesos[key] = {
                "pid": c.pid,
                "nombre": nombre,
                "ruta": exe,
                "conexiones": []
            }

        procesos[key]["conexiones"].append({
            "remoto": f"{c.raddr.ip}:{c.raddr.port}",
            "estado": c.status
        })

    return list(procesos.values())

def dispositivos_red_local():
    dispositivos = []

    try:
        salida = subprocess.check_output("arp -a", shell=True, text=True)
        for line in salida.splitlines():
            if "." in line and "-" in line:
                partes = line.split()
                dispositivos.append({
                    "ip": partes[0],
                    "mac": partes[1],
                    "tipo": "local"
                })
    except:
        pass

    return dispositivos

def ejecutables_sospechosos(procesos):
    alertas = []

    rutas_riesgo = ["AppData", "Temp", "Downloads"]
    puertos_riesgo = {22, 3389, 4444, 6666}

    for p in procesos:
        ruta = p.get("ruta", "")
        nombre = p.get("nombre", "Desconocido")
        pid = p.get("pid")

        for c in p.get("conexiones", []):
            remoto = c.get("remoto", "")

            try:
                ip_remota = remoto.split(":")[0]
                port = int(remoto.split(":")[-1])
            except:
                ip_remota = None
                port = None

            # ─── EJECUTABLE EN RUTA SOSPECHOSA ───
            if any(r in ruta for r in rutas_riesgo):
                alertas.append({
                    "tipo": "EJECUTABLE SOSPECHOSO",
                    "nivel": "CRÍTICO",
                    "mensaje": f"{nombre} ejecutándose desde {ruta}",
                    "ip": ip_remota,
                    "pid": pid
                })

            # ─── PUERTO REMOTO PELIGROSO ───
            if port in puertos_riesgo:
                alertas.append({
                    "tipo": "PUERTO REMOTO PELIGROSO",
                    "nivel": "ALTO",
                    "mensaje": f"{nombre} conectado al puerto remoto {port}",
                    "ip": ip_remota,
                    "pid": pid
                })

    return alertas


def servicios_expuestos(puertos):
    servicios = []
    mapa = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        80: "HTTP",
        3389: "RDP"
    }

    for p in puertos:
        try:
            port = int(p["local"].split(":")[-1])
            if port in mapa:
                servicios.append(mapa[port])
        except:
            pass

    return list(set(servicios))

def estado_red_completo():
    conexiones, puertos = conexiones_red()
    procesos = procesos_conectados()
    eventos_edr = generar_eventos_edr(conexiones)


    alertas = []
    alertas.extend(alertas_red(conexiones, puertos))
    alertas.extend(ejecutables_sospechosos(procesos))
    alertas.extend(detectar_c2_botnet(conexiones))
    alertas.extend(detectar_c2_rat_backdoor(conexiones))
    alertas.extend(detectar_persistencia())
    alertas.extend(detectar_scheduled_tasks())
    alertas.extend(detectar_servicios_sospechosos())
    alertas.extend(detectar_beaconing(conexiones))
    alertas.extend(detectar_dns_tunneling())
    alertas.extend(detectar_exfiltracion_datos())




    return  {
        "interfaces": interfaces_red(),
        "ip_publica": obtener_ip_publica(),
        "dns_gateway": dns_gateway(),
        "conexiones": conexiones,
        "puertos_abiertos": puertos,
        "procesos_remotos": procesos,
        "equipos_red": dispositivos_red_local(),
        "servicios": servicios_expuestos(puertos),
        "edr": eventos_edr,
        "alertas": alertas + eventos_edr



    }



# ─────────────────────────────────────────
# ALERTAS DE SEGURIDAD
# ─────────────────────────────────────────
def alertas_red(conexiones, puertos):
    alertas = []

    for c in conexiones:
        remoto = c.get("remoto")
        estado = c.get("estado")

        if not remoto or remoto.startswith("127.") or remoto.startswith("0.0.0.0"):
            continue

        try:
            ip, puerto = remoto.split(":")
        except ValueError:
            continue

        # Solo conexiones externas activas
        if estado == "ESTABLISHED":
            alerta = {
                "nivel": "MEDIO",
                "tipo": "Conexión externa",
                "mensaje": f"{ip}:{puerto} conexión activa",
                "ip": ip,
                "puerto": int(puerto),
                "estado": estado,
                "pid": c.get("pid"),
                "proceso": c.get("proceso"),
                "ruta": c.get("ruta")
            }

            alertas.append(alerta)

    return alertas

def detectar_c2_botnet(conexiones):
    alertas = []
    contador_ip = {}

    for c in conexiones:
        remoto = c.get("remoto")
        estado = c.get("estado")

        if not remoto or estado != "ESTABLISHED":
            continue

        try:
            ip, puerto = remoto.split(":")
            puerto = int(puerto)
        except:
            continue

        # ignorar LAN
        if ip.startswith(("192.168.", "10.", "127.")):
            continue

        contador_ip[ip] = contador_ip.get(ip, 0) + 1

        proceso = c.get("proceso", "desconocido")
        ruta = c.get("ruta", "")

        riesgo = 0
        motivos = []

        # 🔥 Puerto C2
        if puerto in PUERTOS_C2:
            riesgo += 3
            motivos.append(f"Puerto C2 ({puerto})")

        # 🔥 Ruta sospechosa
        if any(r.lower() in ruta.lower() for r in RUTAS_SOSPECHOSAS):
            riesgo += 3
            motivos.append("Ruta sospechosa")

        # 🔥 Proceso extraño
        if proceso.lower() not in ["chrome.exe", "firefox.exe", "svchost.exe"]:
            riesgo += 2
            motivos.append("Proceso no estándar")

        if riesgo >= 4:
            alertas.append({
                "nivel": "CRÍTICO",
                "tipo": "POSIBLE C2 / BOTNET",
                "mensaje": f"{ip}:{puerto} → {' | '.join(motivos)}",
                "ip": ip,
                "puerto": puerto,
                "pid": c.get("pid"),
                "proceso": proceso,
                "ruta": ruta
            })

    # 🔁 Beaconing (misma IP muchas veces)
    for ip, veces in contador_ip.items():
        if veces >= 5:
            alertas.append({
                "nivel": "CRÍTICO",
                "tipo": "BEACONING C2",
                "mensaje": f"{ip} contactado {veces} veces",
                "ip": ip
            })

    return alertas


def clasificar_amenaza(con):
    """
    Determina si una conexión es C2, RAT o BACKDOOR
    """
    remoto = con.get("remoto") or ""
    puerto = con.get("puerto_remoto")
    proceso = (con.get("proceso") or "").lower()
    ruta = (con.get("ruta") or "").lower()

    # ───── C2 ─────
    if puerto in PUERTOS_C2:
        return "C2"

    if remoto and any(d in remoto for d in DOMINIOS_DINAMICOS):
        return "C2"

    # ───── RAT ─────
    if puerto in PUERTOS_RAT:
        return "RAT"

    if any(x in proceso for x in ("teamviewer", "anydesk", "ultravnc", "remmina")):
        return "RAT"

    # ───── BACKDOOR ─────
    if puerto in PUERTOS_BACKDOOR:
        return "BACKDOOR"

    if any(r in ruta for r in RUTAS_SOSPECHOSAS):
        return "BACKDOOR"

    return None


def detectar_c2_rat_backdoor(conexiones):
    alertas = []

    for c in conexiones:
        tipo = clasificar_amenaza(c)

        if not tipo:
            continue

        nivel = "CRÍTICO" if tipo == "C2" else "MEDIO"

        alertas.append({
            "nivel": nivel,
            "tipo": tipo,
            "mensaje": f"Conexión {tipo} detectada → {c['local']} → {c['remoto']}",
            "ip": c.get("ip_remota"),
            "pid": c.get("pid"),
            "proceso": c.get("proceso"),
            "ruta": c.get("ruta"),
            "conexion": c
        })

    return alertas


def detectar_beaconing(conexiones):
    alertas = []

    grupos = defaultdict(list)

    # Agrupar por (PID + remoto)
    for c in conexiones:
        remoto = c.get("remoto")
        pid = c.get("pid")

        if not remoto or not pid:
            continue

        grupos[(pid, remoto)].append(c)

    for (pid, remoto), eventos in grupos.items():
        if len(eventos) < 6:
            continue  # muy pocas conexiones

        # ordenar por tiempo
        eventos.sort(key=lambda x: x.get("timestamp", 0))

        intervalos = []
        for i in range(1, len(eventos)):
            t1 = eventos[i-1].get("timestamp")
            t2 = eventos[i].get("timestamp")
            if t1 and t2:
                intervalos.append(t2 - t1)

        if len(intervalos) < 4:
            continue

        promedio = sum(intervalos) / len(intervalos)

        # beaconing suele ser regular (ej: cada 30s, 60s)
        if all(abs(i - promedio) < 5 for i in intervalos):
            alertas.append({
                "tipo": "Beaconing / C2 detectado",
                "nivel": "CRÍTICO",
                "mensaje": f"Comunicación periódica con {remoto}",
                "ip": remoto.split(":")[0],
                "pid": pid,
                "proceso": eventos[0].get("proceso"),
                "intervalo": int(promedio),
                "conteo": len(eventos)
            })

    return alertas

def obtener_consultas_dns():
    consultas = []

    try:
        salida = subprocess.check_output(
            ["ipconfig", "/displaydns"],
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        dominios = re.findall(r"Nombre de registro\s+:\s+(.+)", salida)

        for d in dominios:
            consultas.append(d.strip())

    except Exception:
        pass

    return consultas



def entropia(s):
    probs = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)

def detectar_dns_tunneling():
    alertas = []

    dominios = obtener_consultas_dns()

    sospechosos = []

    for d in dominios:
        partes = d.split(".")

        if len(partes) < 3:
            continue

        subdominio = partes[0]

        # subdominios muy largos
        if len(subdominio) > 30:
            sospechosos.append(d)
            continue

        # entropía alta (base64 / datos)
        if entropia(subdominio) > 4.2:
            sospechosos.append(d)

    if len(sospechosos) >= 5:
        alertas.append({
            "tipo": "DNS Tunneling",
            "nivel": "CRÍTICO",
            "mensaje": f"{len(sospechosos)} consultas DNS sospechosas",
            "dominios": sospechosos[:10]
        })

    return alertas


def procesos_con_trafico():
    resultados = []

    for p in psutil.process_iter(attrs=["pid", "name"]):
        try:
            try:
                conns = p.net_connections(kind="inet")
            except Exception:
                conns = p.connections(kind="inet") if hasattr(p, "connections") else []

            if not conns:
                continue

            io = p.io_counters() if hasattr(p, "io_counters") else None
            if not io:
                continue

            enviados = io.write_bytes
            recibidos = io.read_bytes

            if enviados < 1024 * 500:  # menos de 500 KB
                continue

            for c in conns:
                if c.raddr and ip_externa(c.raddr.ip):
                    resultados.append({
                        "pid": p.pid,
                        "proceso": p.info.get("name") or "Desconocido",
                        "ip": c.raddr.ip,
                        "puerto": c.raddr.port,
                        "bytes_enviados": enviados,
                        "bytes_recibidos": recibidos,
                        "estado": c.status
                    })

        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            continue

    return resultados

def detectar_exfiltracion_datos():
    alertas = []

    sospechosos = procesos_con_trafico()

    for s in sospechosos:
        ratio = (
            s["bytes_enviados"] / max(s["bytes_recibidos"], 1)
        )

        # Mucho más upload que download
        if ratio > 5 and s["bytes_enviados"] > 1024 * 1024:
            alertas.append({
                "tipo": "Exfiltración de datos",
                "nivel": "CRÍTICO",
                "mensaje": (
                    f"{s['proceso']} envió "
                    f"{s['bytes_enviados'] // 1024} KB a {s['ip']}"
                ),
                "pid": s["pid"],
                "proceso": s["proceso"],
                "ip": s["ip"],
                "puerto": s["puerto"],
                "bytes": s["bytes_enviados"]
            })

    return alertas
