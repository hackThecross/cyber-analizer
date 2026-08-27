import subprocess
import shutil
import os
import psutil
import ctypes
import json
import time
import winreg
from datetime import datetime
from core.settings_manager import get_writable_path

QUARANTINE_DIR = get_writable_path("cuarentena")
QUARANTINE_META_FILE = os.path.join(QUARANTINE_DIR, "cuarentena_index.json")


# ─────────────────────────
# COMPROBAR ADMINISTRADOR
# ─────────────────────────
def es_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ─────────────────────────
# 1. FINALIZAR PROCESO
# ─────────────────────────
def matar_proceso(pid):
    if not pid:
        return False, "PID inválido"

    try:
        pid = int(pid)
        p = psutil.Process(pid)
        p.kill()
        return True, f"Proceso {pid} ({p.name()}) finalizado correctamente"
    except psutil.NoSuchProcess:
        return True, f"El proceso {pid} ya no se encuentra activo"
    except Exception as e:
        # Fallback to taskkill
        try:
            res = subprocess.run(
                ["taskkill", "/PID", str(pid), "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=True
            )
            if res.returncode == 0:
                return True, f"Proceso PID {pid} finalizado vía taskkill"
            return False, f"No se pudo finalizar: {e}"
        except Exception as e2:
            return False, str(e2)


# ─────────────────────────
# 2. SUSPENDER Y REANUDAR PROCESO
# ─────────────────────────
def suspender_proceso(pid):
    if not pid:
        return False, "PID inválido"
    try:
        p = psutil.Process(int(pid))
        p.suspend()
        return True, f"Proceso {p.name()} (PID {pid}) suspendido / pausado"
    except Exception as e:
        return False, f"Error al suspender proceso: {e}"


def reanudar_proceso(pid):
    if not pid:
        return False, "PID inválido"
    try:
        p = psutil.Process(int(pid))
        p.resume()
        return True, f"Proceso {p.name()} (PID {pid}) reanudado"
    except Exception as e:
        return False, f"Error al reanudar proceso: {e}"


# ─────────────────────────
# 3. BLOQUEAR IP (FIREWALL)
# ─────────────────────────
def bloquear_ip(ip):
    import ipaddress

    if not ip:
        return False, "IP inválida"

    ip = ip.split(":")[0].strip()

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"IP no válida: {ip}"

    if ip_obj.is_loopback:
        return False, "No se puede bloquear localhost"

    ip_str = f'"{ip}"'

    try:
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=CyberEDR_Block_IN_{ip}",
                "dir=in",
                "action=block",
                f"remoteip={ip_str}",
                "protocol=any"
            ],
            check=True,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=CyberEDR_Block_OUT_{ip}",
                "dir=out",
                "action=block",
                f"remoteip={ip_str}",
                "protocol=any"
            ],
            check=True,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return True, f"IP {ip} bloqueada en Windows Firewall"
    except subprocess.CalledProcessError as e:
        return False, f"Error firewall (¿requiere Administrador?): {e}"
    except Exception as e:
        return False, str(e)


def desbloquear_ip(ip):
    if not ip:
        return False, "IP inválida"
    ip = ip.split(":")[0].strip()
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=CyberEDR_Block_IN_{ip}"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=CyberEDR_Block_OUT_{ip}"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True, f"Reglas de bloqueo para IP {ip} eliminadas"
    except Exception as e:
        return False, str(e)


# ─────────────────────────
# 4. AISLAR PROCESO (CORTAR RED)
# ─────────────────────────
def aislar_proceso(pid):
    if not pid:
        return False, "PID inválido"

    try:
        proc = psutil.Process(int(pid))
        exe = proc.exe()
        if not exe:
            return False, "No se pudo determinar el ejecutable del proceso"

        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=CyberEDR_Isolate_{pid}",
                "dir=out",
                "action=block",
                f"program={exe}"
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )
        return True, f"Proceso {proc.name()} (PID {pid}) aislado de la red"
    except Exception as e:
        return False, f"Error al aislar proceso: {e}"


def desaislar_proceso(pid):
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=CyberEDR_Isolate_{pid}"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True, f"Aislamiento de red para PID {pid} removido"
    except Exception as e:
        return False, str(e)


# ─────────────────────────
# 5. CUARENTENA DE ARCHIVO CON METADATA
# ─────────────────────────
def _cargar_quarantine_index():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    if os.path.exists(QUARANTINE_META_FILE):
        try:
            with open(QUARANTINE_META_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def _guardar_quarantine_index(data):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    try:
        with open(QUARANTINE_META_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def cuarentena(ruta):
    if not ruta or not os.path.exists(ruta):
        raise Exception(f"Ruta inválida o archivo inexistente: {ruta}")

    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

        base = os.path.basename(ruta)
        timestamp = int(time.time())
        nombre_guardado = f"{timestamp}_{base}.locked"
        destino = os.path.join(QUARANTINE_DIR, nombre_guardado)

        # Calcular hash previo si es posible
        from core.hash_utils import calcular_sha256
        sha256 = calcular_sha256(ruta) or "N/A"

        # Mover archivo
        shutil.move(ruta, destino)

        # Registrar en índice
        index = _cargar_quarantine_index()
        registro = {
            "id": f"Q_{timestamp}",
            "nombre_original": base,
            "ruta_original": ruta,
            "archivo_cuarentena": nombre_guardado,
            "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sha256": sha256,
            "tamano_bytes": os.path.getsize(destino) if os.path.exists(destino) else 0
        }
        index.append(registro)
        _guardar_quarantine_index(index)

        return True, f"Archivo puesto en cuarentena con éxito en {destino}"
    except Exception as e:
        return False, str(e)


def obtener_archivos_cuarentena():
    index = _cargar_quarantine_index()
    # Filtrar solo los que realmente existen en disco
    validos = []
    modificado = False
    for item in index:
        archivo_path = os.path.join(QUARANTINE_DIR, item.get("archivo_cuarentena", ""))
        if os.path.exists(archivo_path):
            validos.append(item)
        else:
            modificado = True

    if modificado:
        _guardar_quarantine_index(validos)
    return validos


def restaurar_cuarentena(item_id, destino_personalizado=None):
    index = _cargar_quarantine_index()
    for item in index:
        if item.get("id") == item_id or item.get("archivo_cuarentena") == item_id:
            origen = os.path.join(QUARANTINE_DIR, item["archivo_cuarentena"])
            destino = destino_personalizado or item["ruta_original"]

            if not os.path.exists(origen):
                return False, "El archivo en cuarentena no existe"

            os.makedirs(os.path.dirname(os.path.abspath(destino)), exist_ok=True)
            shutil.move(origen, destino)

            index.remove(item)
            _guardar_quarantine_index(index)
            return True, f"Archivo restaurado a: {destino}"

    return False, "Elemento no encontrado en cuarentena"


def eliminar_definitivo_cuarentena(item_id):
    index = _cargar_quarantine_index()
    for item in index:
        if item.get("id") == item_id or item.get("archivo_cuarentena") == item_id:
            origen = os.path.join(QUARANTINE_DIR, item["archivo_cuarentena"])
            if os.path.exists(origen):
                os.remove(origen)
            index.remove(item)
            _guardar_quarantine_index(index)
            return True, "Archivo eliminado permanentemente de la cuarentena"

    return False, "Elemento no encontrado en cuarentena"


# ─────────────────────────
# 6. ELIMINAR PERSISTENCIA REAL
# ─────────────────────────
def eliminar_persistencia(alerta):
    """
    Elimina mecanismos de persistencia:
    - Registro (Run / RunOnce)
    - Archivos en carpetas Startup
    - Tareas programadas (schtasks)
    - Servicios de Windows
    """
    try:
        tipo = alerta.get("tipo", "").lower()
        ruta = alerta.get("ruta") or alerta.get("path") or ""
        mensaje = alerta.get("mensaje", "")
        servicio = alerta.get("servicio")
        tarea = alerta.get("tarea")

        # 1. Registro Run
        if "registry" in tipo or "run" in tipo:
            eliminado_reg = False
            claves = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]
            for root, key_path in claves:
                try:
                    with winreg.OpenKey(root, key_path, 0, winreg.KEY_ALL_ACCESS) as k:
                        i = 0
                        while True:
                            try:
                                val_name, val_data, _ = winreg.EnumValue(k, i)
                                if (ruta and ruta.lower() in val_data.lower()) or (val_name in mensaje):
                                    winreg.DeleteValue(k, val_name)
                                    eliminado_reg = True
                                    break
                                i += 1
                            except OSError:
                                break
                except Exception:
                    pass

            if eliminado_reg:
                return True, "Entrada de persistencia eliminada del Registro de Windows"

        # 2. Startup Folder
        if "startup" in tipo or "inicio" in tipo:
            if ruta and os.path.isfile(ruta):
                try:
                    os.remove(ruta)
                    return True, f"Acceso directo / archivo de inicio eliminado: {ruta}"
                except Exception as e:
                    return False, f"No se pudo eliminar el archivo de inicio: {e}"

        # 3. Tarea programada
        if "scheduled" in tipo or "tarea" in tipo or tarea:
            nombre_tarea = tarea
            if not nombre_tarea and "→" in mensaje:
                nombre_tarea = mensaje.split("→")[0].strip()

            if nombre_tarea:
                res = subprocess.run(
                    ["schtasks", "/Delete", "/TN", nombre_tarea, "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=True
                )
                if res.returncode == 0:
                    return True, f"Tarea programada '{nombre_tarea}' eliminada correctamente"

        # 4. Servicio sospechoso
        if "servicio" in tipo or servicio:
            nombre_serv = servicio or (mensaje.split("→")[0].strip() if "→" in mensaje else None)
            if nombre_serv:
                # Detener y deshabilitar servicio
                subprocess.run(["sc", "stop", nombre_serv], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
                res = subprocess.run(["sc", "config", nombre_serv, "start=disabled"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
                if res.returncode == 0:
                    return True, f"Servicio '{nombre_serv}' deshabilitado correctamente"

        # Fallback genérico: si hay ruta, intentar eliminarla o cuarentenarla
        if ruta and os.path.isfile(ruta):
            cuarentena(ruta)
            return True, f"Elemento persistente enviado a cuarentena: {ruta}"

        return False, "No se identificó el método exacto para eliminar esta persistencia automáticamente"

    except Exception as e:
        return False, str(e)
