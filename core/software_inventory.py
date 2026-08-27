import winreg
import os
import hashlib
from datetime import datetime

UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def _parse_date(value):
    try:
        return datetime.strptime(value, "%Y%m%d").strftime("%Y-%m-%d")
    except Exception:
        return "Desconocida"


def obtener_programas_instalados():
    programas = []

    for root, path in UNINSTALL_KEYS:
        try:
            with winreg.OpenKey(root, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            nombre = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0] if _existe(subkey, "DisplayVersion") else ""
                            editor = winreg.QueryValueEx(subkey, "Publisher")[0] if _existe(subkey, "Publisher") else ""
                            install_date = _parse_date(winreg.QueryValueEx(subkey, "InstallDate")[0]) if _existe(subkey, "InstallDate") else "Desconocida"
                            uninstall = winreg.QueryValueEx(subkey, "UninstallString")[0] if _existe(subkey, "UninstallString") else ""
                            location = winreg.QueryValueEx(subkey, "InstallLocation")[0] if _existe(subkey, "InstallLocation") else ""

                            programas.append({
                                "nombre": nombre,
                                "version": version,
                                "editor": editor,
                                "fecha_instalacion": install_date,
                                "ruta": location,
                                "uninstall": uninstall,
                                "tipo": "MSI" if "msiexec" in uninstall.lower() else "EXE",
                            })
                    except Exception:
                        continue
        except Exception:
            continue

    return programas


def _existe(key, value):
    try:
        winreg.QueryValueEx(key, value)
        return True
    except FileNotFoundError:
        return False
