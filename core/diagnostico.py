# core/diagnostico.py

import platform
import socket
import psutil
import getpass
import time


def diagnostico_general():
    data = {}

    # ───── SISTEMA ─────
    data["sistema"] = {
        "os": f"{platform.system()} {platform.release()}",
        "version": platform.version(),
        "arquitectura": platform.architecture()[0],
        "usuario": getpass.getuser(),
        "hostname": socket.gethostname(),
        "uptime_horas": int((time.time() - psutil.boot_time()) // 3600)
    }

    # ───── CPU ─────
    data["cpu"] = {
        "nucleos_fisicos": psutil.cpu_count(logical=False),
        "nucleos_logicos": psutil.cpu_count(logical=True),
        "frecuencia_mhz": int(psutil.cpu_freq().current) if psutil.cpu_freq() else "N/A",
        "uso": psutil.cpu_percent(interval=1)
    }

    # ───── RAM ─────
    mem = psutil.virtual_memory()
    data["ram"] = {
        "total_gb": round(mem.total / 1024**3, 2),
        "usada_gb": round(mem.used / 1024**3, 2),
        "libre_gb": round(mem.available / 1024**3, 2),
        "uso": mem.percent
    }

    # ───── DISCO (TODAS LAS PARTICIONES) ─────
    discos = []
    for part in psutil.disk_partitions():
        try:
            uso = psutil.disk_usage(part.mountpoint)
            discos.append({
                "dispositivo": part.device,
                "montaje": part.mountpoint,
                "tipo": part.fstype,
                "total_gb": round(uso.total / 1024**3, 2),
                "uso": uso.percent
            })
        except:
            pass

    data["discos"] = discos

    # ───── RED ─────
    red = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                red.append({
                    "interfaz": iface,
                    "ip": addr.address
                })

    data["red"] = red

    # ───── BATERÍA ─────
    bat = psutil.sensors_battery()
    data["bateria"] = None if not bat else {
        "porcentaje": bat.percent,
        "conectada": bat.power_plugged
    }

    # ───── PROCESOS ─────
    data["procesos"] = {
        "total": len(psutil.pids()),
        "top_cpu": sorted(
            psutil.process_iter(['name', 'cpu_percent']),
            key=lambda p: (p.info.get('cpu_percent') or 0),
            reverse=True
        )[:5]
    }

    return data
def evaluar_alertas(data):
    alertas = []

    # CPU
    cpu = data["cpu"]["uso"]
    if cpu > 90:
        alertas.append(("CPU", "CRÍTICO", f"Uso de CPU muy alto: {cpu} %"))
    elif cpu > 70:
        alertas.append(("CPU", "ADVERTENCIA", f"Uso de CPU elevado: {cpu} %"))

    # RAM
    ram = data["ram"]["uso"]
    if ram > 90:
        alertas.append(("RAM", "CRÍTICO", f"Memoria casi llena: {ram} %"))
    elif ram > 75:
        alertas.append(("RAM", "ADVERTENCIA", f"Uso de RAM alto: {ram} %"))

    # DISCO
    for d in data["discos"]:
        uso = d["uso"]
        if uso > 95:
            alertas.append(("DISCO", "CRÍTICO", f"{d['dispositivo']} al {uso} %"))
        elif uso > 80:
            alertas.append(("DISCO", "ADVERTENCIA", f"{d['dispositivo']} al {uso} %"))

    # BATERÍA
    bat = data["bateria"]
    if bat and not bat["conectada"]:
        if bat["porcentaje"] < 15:
            alertas.append(("BATERÍA", "CRÍTICO", f"{bat['porcentaje']} % restante"))
        elif bat["porcentaje"] < 30:
            alertas.append(("BATERÍA", "ADVERTENCIA", f"{bat['porcentaje']} % restante"))

    return alertas
