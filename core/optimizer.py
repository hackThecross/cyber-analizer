import os
import shutil
import ctypes
import subprocess
import psutil
import winreg
from datetime import datetime

# Rutas estándar de limpieza
CARPETAS_LIMPIEZA = [
    {"nombre": "Archivos Temporales de Usuario (%TEMP%)", "id": "temp_user", "ruta": os.environ.get("TEMP", "")},
    {"nombre": "Archivos Temporales de Windows (C:\\Windows\\Temp)", "id": "temp_win", "ruta": r"C:\Windows\Temp"},
    {"nombre": "Caché de Prefetch de Windows", "id": "prefetch", "ruta": r"C:\Windows\Prefetch"},
    {"nombre": "Reportes de Errores (Crash Dumps)", "id": "crashdumps", "ruta": os.path.expandvars(r"%LOCALAPPDATA%\CrashDumps")},
    {"nombre": "Caché de Google Chrome", "id": "chrome_cache", "ruta": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache")},
    {"nombre": "Caché de Microsoft Edge", "id": "edge_cache", "ruta": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache")},
    {"nombre": "Caché de Miniaturas de Windows", "id": "thumb_cache", "ruta": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer")},
]

def _calcular_tamano_carpeta(ruta, filtro_thumb=False):
    total_bytes = 0
    total_archivos = 0
    if not os.path.exists(ruta):
        return 0, 0

    try:
        if os.path.isfile(ruta):
            return os.path.getsize(ruta), 1

        for root, dirs, files in os.walk(ruta):
            for f in files:
                if filtro_thumb and not f.startswith("thumbcache_"):
                    continue
                fp = os.path.join(root, f)
                try:
                    total_bytes += os.path.getsize(fp)
                    total_archivos += 1
                except Exception:
                    continue
    except Exception:
        pass

    return total_bytes, total_archivos


def analizar_espacio_limpieza():
    resultados = []
    total_general_bytes = 0
    total_general_archivos = 0

    for item in CARPETAS_LIMPIEZA:
        ruta = item["ruta"]
        filtro_thumb = (item["id"] == "thumb_cache")
        tam_bytes, cant = _calcular_tamano_carpeta(ruta, filtro_thumb=filtro_thumb)
        total_general_bytes += tam_bytes
        total_general_archivos += cant

        resultados.append({
            "id": item["id"],
            "nombre": item["nombre"],
            "ruta": ruta,
            "bytes": tam_bytes,
            "mb": round(tam_bytes / (1024 * 1024), 2),
            "archivos": cant,
            "existe": os.path.exists(ruta)
        })

    return {
        "categorias": resultados,
        "total_bytes": total_general_bytes,
        "total_mb": round(total_general_bytes / (1024 * 1024), 2),
        "total_gb": round(total_general_bytes / (1024**3), 2),
        "total_archivos": total_general_archivos
    }


def ejecutar_limpieza(ids_seleccionados=None):
    bytes_liberados = 0
    archivos_eliminados = 0
    errores = 0

    for item in CARPETAS_LIMPIEZA:
        if ids_seleccionados is not None and item["id"] not in ids_seleccionados:
            continue

        ruta = item["ruta"]
        if not os.path.exists(ruta):
            continue

        filtro_thumb = (item["id"] == "thumb_cache")

        if os.path.isfile(ruta):
            try:
                tam = os.path.getsize(ruta)
                os.remove(ruta)
                bytes_liberados += tam
                archivos_eliminados += 1
            except Exception:
                errores += 1
            continue

        for root, dirs, files in os.walk(ruta, topdown=False):
            for f in files:
                if filtro_thumb and not f.startswith("thumbcache_"):
                    continue
                fp = os.path.join(root, f)
                try:
                    tam = os.path.getsize(fp)
                    os.remove(fp)
                    bytes_liberados += tam
                    archivos_eliminados += 1
                except Exception:
                    errores += 1

            # Intentar borrar subdirectorios vacíos
            for d in dirs:
                dp = os.path.join(root, d)
                try:
                    os.rmdir(dp)
                except Exception:
                    pass

    return {
        "bytes_liberados": bytes_liberados,
        "mb_liberados": round(bytes_liberados / (1024 * 1024), 2),
        "archivos_eliminados": archivos_eliminados,
        "errores": errores
    }

def vaciar_papelera():
    try:
        # Usar la API nativa de Windows SHEmptyRecycleBinW
        # FLAGS: SHERB_NOCONFIRMATION = 0x00000001, SHERB_NOPROGRESSUI = 0x00000002, SHERB_NOSOUND = 0x00000004
        resultado = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 7)
        if resultado == 0 or resultado == -2147418113: # S_OK o ya vacía
            return True, "Papelera de reciclaje vaciada correctamente"
        else:
            # Fallback vía PowerShell
            subprocess.run(["powershell", "-Command", "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"], shell=True)
            return True, "Papelera de reciclaje vaciada con éxito"
    except Exception as e:
        return False, f"Error al vaciar papelera: {e}"


def optimizar_ram():
    """
    Realiza una limpieza de páginas inactivas en memoria de los procesos (Working Set Trim).
    """
    mem_antes = psutil.virtual_memory()
    procesos_optimizados = 0

    try:
        psapi = ctypes.windll.psapi
        kernel32 = ctypes.windll.kernel32
        PROCESS_ALL_ACCESS = 0x1F0FFF

        for p in psutil.process_iter(['pid', 'name']):
            try:
                # Evitar tocar procesos de sistema esenciales o PID <= 4
                if p.info['pid'] <= 4 or p.info['name'].lower() in ['system', 'registry', 'smss.exe', 'csrss.exe']:
                    continue

                h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, p.info['pid'])
                if h_process:
                    psapi.EmptyWorkingSet(h_process)
                    kernel32.CloseHandle(h_process)
                    procesos_optimizados += 1
            except Exception:
                continue
    except Exception:
        pass

    # Forzar recolección de basura de Python
    import gc
    gc.collect()

    import time
    time.sleep(0.5)
    mem_despues = psutil.virtual_memory()

    mb_liberados = round((mem_antes.used - mem_despues.used) / (1024 * 1024), 2)
    if mb_liberados < 0:
        mb_liberados = 0

    return {
        "procesos_optimizados": procesos_optimizados,
        "mb_liberados": mb_liberados,
        "ram_antes_porc": mem_antes.percent,
        "ram_despues_porc": mem_despues.percent,
        "ram_libre_gb": round(mem_despues.available / (1024**3), 2)
    }


def obtener_inicio_sistema():
    """
    Obtiene los programas que se ejecutan automáticamente al iniciar Windows y su impacto estimado.
    """
    items = []
    claves = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Usuario Actual"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "Todo el Sistema (HKLM)"),
    ]

    for root, path, origen in claves:
        try:
            with winreg.OpenKey(root, path) as key:
                i = 0
                while True:
                    try:
                        nombre, valor, _ = winreg.EnumValue(key, i)
                        i += 1

                        # Heurística de impacto
                        val_low = valor.lower()
                        if any(x in val_low for x in ["onedrive", "teams", "discord", "spotify", "steam", "epic"]):
                            impacto = "ALTO"
                        elif any(x in val_low for x in ["updater", "helper", "agent", "service", "sync"]):
                            impacto = "MEDIO"
                        else:
                            impacto = "BAJO"

                        items.append({
                            "nombre": nombre,
                            "comando": valor,
                            "origen": origen,
                            "impacto": impacto,
                            "estado": "Habilitado"
                        })
                    except OSError:
                        break
        except Exception:
            pass

    return items
