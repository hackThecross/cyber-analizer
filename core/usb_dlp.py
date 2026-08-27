import winreg
import subprocess
from core.security_logs import registrar_accion_edr
from core.audio_alerts import reproducir_bloqueo_exitoso, reproducir_sonido_exito

def obtener_politica_usb():
    """
    Retorna la política USB actual: 'permitido', 'solo_lectura', 'bloqueado'.
    """
    # 1. Comprobar bloqueo total en USBSTOR
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR") as key:
            val, _ = winreg.QueryValueEx(key, "Start")
            if val == 4:
                return "bloqueado"
    except Exception:
        pass

    # 2. Comprobar Modo Solo Lectura (WriteProtect)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies") as key:
            val, _ = winreg.QueryValueEx(key, "WriteProtect")
            if val == 1:
                return "solo_lectura"
    except Exception:
        pass

    return "permitido"


def establecer_politica_usb(modo):
    """
    Aplica políticas DLP a nivel de kernel de Windows para almacenamiento USB:
    - 'permitido': Lectura y escritura estándar
    - 'solo_lectura': Bloquea escritura/copiado de datos del PC a la USB (Anti-Fuga de Datos)
    - 'bloqueado': Deshabilita el montaje de dispositivos de almacenamiento USB
    """
    try:
        if modo == "solo_lectura":
            # 1. Habilitar WriteProtect en StorageDevicePolicies
            key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
            try:
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            except Exception:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS)

            winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)

            # Habilitar servicio USBSTOR si estaba bloqueado
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 3)

            registrar_accion_edr("USB_DLP_READONLY", "Política USB establecida en MODO SOLO LECTURA (Anti-Fuga de Datos).", nivel="ALTO", exito=True)
            reproducir_bloqueo_exitoso()
            return True, "🔒 MODO SOLO LECTURA ACTIVADO: Las memorias USB no podrán recibir datos de este equipo (Protección DLP activa)."

        elif modo == "bloqueado":
            # 2. Deshabilitar servicio USBSTOR
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 4)

            registrar_accion_edr("USB_DLP_BLOCKED", "Almacenamiento USB BLOQUEADO TOTALMENTE.", nivel="CRÍTICO", exito=True)
            reproducir_bloqueo_exitoso()
            return True, "⛔ BLOQUEO TOTAL USB ACTIVADO: El sistema no montará unidades de almacenamiento extraíbles."

        else:
            # 3. Permitido normal
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies", 0, winreg.KEY_ALL_ACCESS) as key:
                    winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 0)
            except Exception:
                pass

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 3)

            registrar_accion_edr("USB_DLP_ALLOWED", "Políticas USB restauradas a modo PERMITIDO estándar.", nivel="INFO", exito=True)
            reproducir_sonido_exito()
            return True, "🟢 MODO USB PERMITIDO: Lectura y escritura estándar habilitadas."

    except Exception as e:
        return False, f"Error al modificar políticas USB (¿Requiere permisos de Administrador?): {e}"
