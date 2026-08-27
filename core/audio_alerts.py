import sys
import threading
from core.settings_manager import cargar_configuracion

_sonido_habilitado = True

def _reproducir_tono(frecuencias_y_duraciones):
    if not _sonido_habilitado:
        return
    cfg = cargar_configuracion()
    if not cfg.get("sonidos_cyber", True):
        return

    if sys.platform == "win32":
        try:
            import winsound
            for freq, dur in frecuencias_y_duraciones:
                winsound.Beep(freq, dur)
        except Exception:
            pass


def reproducir_alerta_amenaza():
    """Sonido táctico cuando se intercepta una amenaza o ataque."""
    threading.Thread(target=_reproducir_tono, args=([(1200, 70), (1600, 100)],), daemon=True).start()


def reproducir_bloqueo_exitoso():
    """Sonido de confirmación cuando se bloquea una IP o se manda a cuarentena."""
    threading.Thread(target=_reproducir_tono, args=([(900, 50), (1400, 80)],), daemon=True).start()


def reproducir_alerta_panico():
    """Sonido de alarma para el Modo Pánico / Aislamiento Total."""
    threading.Thread(target=_reproducir_tono, args=([(1800, 100), (1400, 100), (1800, 120)],), daemon=True).start()


def reproducir_alerta_ransomware():
    """Alarma crítica cuando un archivo canario anti-ransomware es tocado."""
    threading.Thread(target=_reproducir_tono, args=([(2000, 150), (1200, 150), (2000, 200)],), daemon=True).start()


def reproducir_sonido_exito():
    """Sonido afirmativo para optimización o escaneo finalizado."""
    threading.Thread(target=_reproducir_tono, args=([(1000, 40), (1500, 60)],), daemon=True).start()
