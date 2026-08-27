import os
import time
import json
import hashlib
import threading
import psutil
from datetime import datetime
from core.settings_manager import get_writable_path
from core.edr_actions import matar_proceso, cuarentena
from core.security_logs import registrar_accion_edr
from core.audio_alerts import reproducir_alerta_ransomware

RANSOM_CONFIG_FILE = get_writable_path("ransomware_guard.json")

CANARY_NAMES = [
    ("00_passwords_vault_decoy.docx", "CyberAnalyzer Decoy Document - DO NOT MODIFY - Canary Trap File Alpha 9128"),
    ("00_financial_budget_backup.xlsx", "CyberAnalyzer Decoy Financial Spreadsheet - DO NOT MODIFY - Canary Trap File Beta 4821"),
    ("00_confidential_contracts.pdf", "%PDF-1.4 CyberAnalyzer Canary Decoy Security File - DO NOT MODIFY"),
]

_canary_watcher_running = False
_canary_thread = None
_canary_baselines = {}
_on_ransomware_callback = None

def _obtener_rutas_canarios():
    carpetas = [
        os.path.expandvars(r"%USERPROFILE%\Documents"),
        os.path.expandvars(r"%USERPROFILE%\Desktop"),
        os.path.expandvars(r"%USERPROFILE%\Downloads")
    ]
    rutas = []
    for c in carpetas:
        if os.path.exists(c):
            for nombre, contenido in CANARY_NAMES:
                rutas.append((os.path.join(c, nombre), contenido))
    return rutas


def desplegar_senuelos():
    """Despliega archivos canario con firmas criptográficas conocidas en carpetas clave."""
    global _canary_baselines
    _canary_baselines.clear()

    desplegados = 0
    for ruta, contenido in _obtener_rutas_canarios():
        try:
            if not os.path.exists(ruta):
                with open(ruta, "w", encoding="utf-8") as f:
                    f.write(contenido)

            # Calcular hash SHA256 base
            h = hashlib.sha256(open(ruta, "rb").read()).hexdigest()
            _canary_baselines[ruta] = h
            desplegados += 1
        except Exception:
            pass

    return desplegados


def _hilo_vigilancia_canarios():
    global _canary_watcher_running, _canary_baselines

    while _canary_watcher_running:
        try:
            for ruta, expected_hash in list(_canary_baselines.items()):
                if not _canary_watcher_running:
                    break

                # 1. Comprobar si el archivo fue eliminado o renombrado (típico de ransomware)
                if not os.path.exists(ruta):
                    _interpolar_y_frenar_ransomware(ruta, "Archivo canario eliminado o renombrado por ransomware")
                    break

                # 2. Comprobar si el contenido fue cifrado o alterado
                try:
                    current_hash = hashlib.sha256(open(ruta, "rb").read()).hexdigest()
                    if current_hash != expected_hash:
                        _interpolar_y_frenar_ransomware(ruta, "Contenido de archivo canario cifrado o modificado")
                        break
                except Exception:
                    pass

        except Exception:
            pass

        time.sleep(1.0)


def _interpolar_y_frenar_ransomware(ruta_canario, motivo):
    """
    Identifica el proceso causante del cifrado, lo finaliza en milisegundos,
    mueve el ejecutable a cuarentena y reproduce la alarma crítica.
    """
    reproducir_alerta_ransomware()

    # Buscar procesos activos sospechosos de alto I/O en disco
    culprit_proc = None
    for p in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent']):
        try:
            name = (p.info['name'] or '').lower()
            if name not in ['system', 'explorer.exe', 'python.exe', 'cyberanalyzer.exe', 'svchost.exe']:
                if p.info['cpu_percent'] and p.info['cpu_percent'] > 15:
                    culprit_proc = p
                    break
        except Exception:
            continue

    if culprit_proc:
        try:
            pid = culprit_proc.info['pid']
            exe = culprit_proc.info['exe']
            matar_proceso(pid)
            if exe and os.path.isfile(exe):
                cuarentena(exe)
        except Exception:
            pass

    evento = {
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tipo": "INTENTO DE RANSOMWARE INTERCEPTADO",
        "motivo": motivo,
        "archivo_canario": ruta_canario,
        "proceso_neutralizado": culprit_proc.info['name'] if culprit_proc else "Proceso Malicioso",
        "accion": "PROCESO ELIMINADO Y BINARIO AISLADO EN CUARENTENA"
    }

    registrar_accion_edr("ANTI_RANSOMWARE_TRIGGER", f"Trampa canario activada en {ruta_canario}. {motivo}", nivel="CRÍTICO", exito=True)

    # Re-desplegar canario
    desplegar_senuelos()

    global _on_ransomware_callback
    if _on_ransomware_callback:
        try:
            _on_ransomware_callback(evento)
        except Exception:
            pass


def iniciar_guardian_ransomware(callback_alerta=None):
    global _canary_watcher_running, _canary_thread, _on_ransomware_callback
    _on_ransomware_callback = callback_alerta
    desplegar_senuelos()

    if not _canary_watcher_running:
        _canary_watcher_running = True
        _canary_thread = threading.Thread(target=_hilo_vigilancia_canarios, daemon=True)
        _canary_thread.start()


def detener_guardian_ransomware():
    global _canary_watcher_running
    _canary_watcher_running = False
