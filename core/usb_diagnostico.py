import os
import subprocess
import shutil
import psutil
import ctypes
from datetime import datetime
from core.hash_utils import calcular_sha256

EXTS_PELIGROSAS = {".exe", ".vbs", ".bat", ".cmd", ".ps1", ".scr", ".dll", ".com", ".pif", ".hta", ".wsf", ".vbe", ".jse"}

def detectar_unidades_usb():
    unidades = []
    # 1. Usar psutil disk_partitions
    try:
        particiones = psutil.disk_partitions(all=False)
        for p in particiones:
            letra = p.mountpoint.rstrip("\\")
            if not letra.endswith(":"):
                letra += ":"

            # Comprobar si es removable (DriveType == 2 en Windows)
            tipo = ctypes.windll.kernel32.GetDriveTypeW(f"{letra}\\")
            # 2 = DRIVE_REMOVABLE, 3 = DRIVE_FIXED, 5 = DRIVE_CDROM, 4 = DRIVE_REMOTE
            es_removible = (tipo == 2) or ("removable" in p.opts.lower())

            # Información de tamaño si está disponible
            tam_total = 0
            tam_libre = 0
            tam_usado = 0
            porc_uso = 0
            try:
                uso = psutil.disk_usage(p.mountpoint)
                tam_total = round(uso.total / (1024**3), 2)
                tam_libre = round(uso.free / (1024**3), 2)
                tam_usado = round(uso.used / (1024**3), 2)
                porc_uso = uso.percent
            except Exception:
                pass

            if es_removible or (p.device and "removable" in p.device.lower()):
                unidades.append({
                    "letra": letra,
                    "montaje": p.mountpoint,
                    "sistema_archivos": p.fstype,
                    "total_gb": tam_total,
                    "libre_gb": tam_libre,
                    "usado_gb": tam_usado,
                    "porcentaje": porc_uso,
                    "tipo": "USB / Extraíble"
                })
    except Exception:
        pass

    # Si psutil no encontró tipos específicos, buscar vía PowerShell Get-Volume
    if not unidades:
        try:
            cmd = 'powershell "Get-Volume | Where-Object {$_.DriveType -eq \'Removable\'} | Select-Object DriveLetter,FileSystemLabel,FileSystem,Size,SizeRemaining | ConvertTo-Json"'
            salida = subprocess.check_output(cmd, shell=True, text=True, errors="ignore").strip()
            if salida:
                import json
                datos = json.loads(salida)
                if isinstance(datos, dict):
                    datos = [datos]
                for item in datos:
                    dl = item.get("DriveLetter")
                    if dl:
                        letra = f"{dl}:"
                        size = round((item.get("Size") or 0) / (1024**3), 2)
                        free = round((item.get("SizeRemaining") or 0) / (1024**3), 2)
                        used = round(size - free, 2)
                        porc = round((used / size * 100), 1) if size > 0 else 0
                        unidades.append({
                            "letra": letra,
                            "montaje": f"{letra}\\",
                            "sistema_archivos": item.get("FileSystem", "FAT32"),
                            "total_gb": size,
                            "libre_gb": free,
                            "usado_gb": used,
                            "porcentaje": porc,
                            "tipo": "USB / Extraíble"
                        })
        except Exception:
            pass

    return unidades

def es_archivo_oculto(ruta):
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(ruta)
        if attrs == -1:
            return False
        # FILE_ATTRIBUTE_HIDDEN = 0x2, FILE_ATTRIBUTE_SYSTEM = 0x4
        return bool(attrs & (0x2 | 0x4))
    except Exception:
        return False


def analizar_unidad_usb(letra):
    ruta_base = f"{letra}\\" if not letra.endswith("\\") else letra
    if not os.path.exists(ruta_base):
        return {"error": f"La unidad {letra} no está disponible"}

    archivos_sospechosos = []
    total_archivos = 0
    total_directorios = 0
    autorun_detectado = False
    autorun_contenido = ""
    ataques_lnk = 0
    archivos_ocultos_peligrosos = 0

    # 1. Comprobar AUTORUN.INF
    autorun_path = os.path.join(ruta_base, "autorun.inf")
    if os.path.exists(autorun_path):
        autorun_detectado = True
        if os.path.isfile(autorun_path):
            try:
                with open(autorun_path, "r", encoding="utf-8", errors="ignore") as f:
                    autorun_contenido = f.read(1000)
                archivos_sospechosos.append({
                    "tipo": "Autorun.inf Sospechoso",
                    "nivel": "CRÍTICO",
                    "archivo": autorun_path,
                    "tamano": os.path.getsize(autorun_path),
                    "detalle": "Archivo autorun.inf encontrado en la raíz. Puede ejecutar malware al conectar el dispositivo.",
                    "sha256": calcular_sha256(autorun_path)
                })
            except Exception:
                pass

    # 2. Recorrer árbol de archivos (máx 1500 archivos para rapidez)
    for root, dirs, files in os.walk(ruta_base):
        total_directorios += len(dirs)

        # Ignorar System Volume Information o RECYCLER si no hay cosas raras
        nombre_dir = os.path.basename(root).lower()
        if "system volume information" in nombre_dir:
            continue

        for f in files:
            total_archivos += 1
            if total_archivos > 3000:
                break

            archivo_path = os.path.join(root, f)
            nombre_low = f.lower()
            _, ext = os.path.splitext(nombre_low)

            es_oculto = es_archivo_oculto(archivo_path)
            tamano = 0
            try:
                tamano = os.path.getsize(archivo_path)
            except Exception:
                pass

            # Detectar doble extensión (.jpg.exe, .pdf.vbs, etc.)
            partes = nombre_low.split(".")
            es_doble_ext = len(partes) >= 3 and f".{partes[-1]}" in EXTS_PELIGROSAS

            # Acceso directo malicioso (.lnk)
            if ext == ".lnk":
                try:
                    # Heurística rápida para LNKs
                    if es_oculto or len(f) <= 2 or f.startswith("~"):
                        ataques_lnk += 1
                        archivos_sospechosos.append({
                            "tipo": "Acceso Directo Malicioso (LNK)",
                            "nivel": "CRÍTICO",
                            "archivo": archivo_path,
                            "tamano": tamano,
                            "detalle": "Acceso directo posiblemente creado por gusano de acceso directo (Shortcut Malware)",
                            "sha256": calcular_sha256(archivo_path)
                        })
                except Exception:
                    pass

            # Ejecutable en raíz de USB o carpeta sospechosa
            elif ext in EXTS_PELIGROSAS:
                nivel = "CRÍTICO" if (es_oculto or es_doble_ext or root == ruta_base) else "MEDIO"
                if es_oculto:
                    archivos_ocultos_peligrosos += 1

                archivos_sospechosos.append({
                    "tipo": "Binario / Script Sospechoso" if not es_doble_ext else "Doble Extensión Engañosa",
                    "nivel": nivel,
                    "archivo": archivo_path,
                    "tamano": tamano,
                    "detalle": f"Archivo ejecutable/script ({ext}) {'oculto' if es_oculto else ''} encontrado en USB",
                    "sha256": calcular_sha256(archivo_path)
                })

            # Archivo oculto con nombres sospechosos
            elif es_oculto and (f.startswith("$") or f.startswith("~") or "temp" in nombre_low):
                archivos_sospechosos.append({
                    "tipo": "Archivo Oculto Anómalo",
                    "nivel": "MEDIO",
                    "archivo": archivo_path,
                    "tamano": tamano,
                    "detalle": "Archivo oculto anómalo en el almacenamiento extraíble",
                    "sha256": calcular_sha256(archivo_path)
                })

    # Calcular nivel de riesgo general del dispositivo USB
    criticos = sum(1 for a in archivos_sospechosos if a["nivel"] == "CRÍTICO")
    medios = sum(1 for a in archivos_sospechosos if a["nivel"] == "MEDIO")
    if criticos > 0:
        riesgo_general = "CRÍTICO / INFECTADO"
    elif medios > 0:
        riesgo_general = "ADVERTENCIA / SOSPECHOSO"
    else:
        riesgo_general = "LIMPIO / SEGURO"

    return {
        "unidad": letra,
        "total_archivos": total_archivos,
        "total_directorios": total_directorios,
        "autorun_detectado": autorun_detectado,
        "autorun_contenido": autorun_contenido,
        "sospechosos": archivos_sospechosos,
        "riesgo_general": riesgo_general,
        "criticos": criticos,
        "medios": medios
    }

def vacunar_usb(letra):
    """
    Inmuniza la unidad creando una carpeta especial 'AUTORUN.INF' con permisos de sólo lectura y atributos del sistema,
    impidiendo que virus de propagación por autorun creen su propio archivo.
    """
    ruta_base = f"{letra}\\" if not letra.endswith("\\") else letra
    autorun_target = os.path.join(ruta_base, "autorun.inf")

    try:
        # Si ya existe como archivo, eliminarlo
        if os.path.isfile(autorun_target):
            subprocess.run(["attrib", "-r", "-a", "-s", "-h", autorun_target], shell=True)
            os.remove(autorun_target)

        if not os.path.exists(autorun_target):
            os.makedirs(autorun_target, exist_ok=True)
            # Crear subcarpeta interna protegida
            sub_dummy = os.path.join(autorun_target, "immunized.lck")
            with open(sub_dummy, "w") as f:
                f.write("CyberAnalyzer USB Immunization Protection File - DO NOT DELETE\n")

            # Asignar atributos Read-Only + System + Hidden a la carpeta autorun.inf
            subprocess.run(["attrib", "+r", "+s", "+h", autorun_target], shell=True)
            subprocess.run(["attrib", "+r", "+s", "+h", sub_dummy], shell=True)

        return True, f"Unidad {letra} inmunizada con éxito contra virus autorun."
    except Exception as e:
        return False, f"Error al vacunar unidad: {e}"


def desocultar_archivos_usb(letra):
    r"""
    Restaura visibilidad de archivos ocultados por gusanos tipo Shortcut/Acceso directo.
    Ejecuta: attrib -h -r -s /s /d X:\*.*
    """
    ruta_base = f"{letra}\\" if not letra.endswith("\\") else letra
    try:
        cmd = f'attrib -h -r -s /s /d "{ruta_base}*.*"'
        subprocess.run(cmd, shell=True, timeout=15)
        return True, f"Archivos y carpetas en {letra} restaurados y desocultados."
    except Exception as e:
        return False, f"Error al desocultar archivos: {e}"


def limpiar_amenazas_usb(archivos_lista):
    """
    Mueve los archivos sospechosos a la cuarentena de CyberAnalyzer.
    """
    from core.edr_actions import cuarentena
    exitos = 0
    fallos = 0
    for item in archivos_lista:
        ruta = item if isinstance(item, str) else item.get("archivo")
        if ruta and os.path.exists(ruta):
            ok, _ = cuarentena(ruta)
            if ok:
                exitos += 1
            else:
                fallos += 1
    return exitos, fallos


def expulsar_usb(letra):
    """
    Expulsa la unidad USB de manera segura.
    """
    letra_clean = letra.rstrip(":\\").upper()
    try:
        cmd = f'powershell "$driveEject = New-Object -comObject Shell.Application; $driveEject.Namespace(17).ParseName(\'{letra_clean}:\').InvokeVerb(\'Eject\')"'
        subprocess.run(cmd, shell=True, timeout=5)
        return True, f"Unidad {letra_clean}: preparada para desconexión segura."
    except Exception as e:
        return False, f"No se pudo expulsar la unidad: {e}"
