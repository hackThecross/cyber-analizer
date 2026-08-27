"""
Módulo de Verificación y Descarga de Actualizaciones desde GitHub Releases para CyberAnalyzer Suite.
Permite comprobar si existe una nueva versión en el repositorio de GitHub, descargar el instalador
y notificar al usuario en tiempo real.
"""

import os
import sys
import re
import time
import json
import tempfile
import threading
import subprocess
import webbrowser
import requests
from packaging import version as pkg_version

APP_VERSION = "1.0.2"
DEFAULT_GITHUB_REPO = "hackThecross/cyber-analizer"

def obtener_version_actual():
    return APP_VERSION

def parsear_version(cadena_version):
    """
    Limpia y parsea una cadena de versión (ej: 'v1.0.3', '1.0.4-beta', 'v1.0.2.0').
    Retorna un objeto Version de packaging si es posible, o una tupla de enteros.
    """
    if not cadena_version:
        cadena_version = "0.0.0"
    limpia = re.sub(r'^[vV]', '', str(cadena_version).strip())
    try:
        return pkg_version.parse(limpia)
    except Exception:
        nums = [int(n) for n in re.findall(r'\d+', limpia)]
        if not nums:
            nums = [0, 0, 0]
        return nums

def es_version_superior(v_remota, v_local=None):
    """
    Compara si v_remota es estrictamente más nueva que v_local.
    """
    if v_local is None:
        v_local = APP_VERSION
    try:
        pv_remota = parsear_version(v_remota)
        pv_local = parsear_version(v_local)
        return pv_remota > pv_local
    except Exception:
        nums_remota = [int(n) for n in re.findall(r'\d+', str(v_remota))]
        nums_local = [int(n) for n in re.findall(r'\d+', str(v_local))]
        return nums_remota > nums_local


def verificar_actualizacion_github(repo=None, version_local=None, timeout=8):
    """
    Consulta la API pública de GitHub para obtener el último Release del repositorio especificado.
    Retorna un diccionario con los datos del release y si hay actualización disponible.
    """
    if not repo:
        repo = DEFAULT_GITHUB_REPO
    if not version_local:
        version_local = APP_VERSION

    # Limpiar formato de repo (quitar URLs si el usuario pegó la URL completa)
    repo_clean = repo.strip()
    if "github.com/" in repo_clean:
        repo_clean = repo_clean.split("github.com/")[-1].strip("/")
    repo_clean = repo_clean.strip("/")

    api_url = f"https://api.github.com/repos/{repo_clean}/releases/latest"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": f"CyberAnalyzer-Updater/{version_local}"
    }

    resultado = {
        "disponible": False,
        "repo": repo_clean,
        "version_actual": version_local,
        "version_remota": "",
        "tag_name": "",
        "nombre_release": "",
        "notas_cambios": "",
        "url_release": f"https://github.com/{repo_clean}/releases",
        "fecha_publicacion": "",
        "instalador": None,
        "assets": [],
        "error": None
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=timeout)

        if response.status_code == 200:
            data = response.json()
            tag = data.get("tag_name", "")
            nombre = data.get("name") or tag
            body = data.get("body") or "No se incluyeron notas de la versión."
            html_url = data.get("html_url") or f"https://github.com/{repo_clean}/releases"
            published_at = data.get("published_at", "")
            if published_at:
                try:
                    fecha_fmt = published_at.replace("T", " ").replace("Z", "")[:19]
                except Exception:
                    fecha_fmt = published_at
            else:
                fecha_fmt = "Reciente"

            assets_list = []
            exe_asset = None
            for a in data.get("assets", []):
                a_name = a.get("name", "")
                a_url = a.get("browser_download_url", "")
                a_size = a.get("size", 0)
                a_count = a.get("download_count", 0)
                item = {
                    "nombre": a_name,
                    "url": a_url,
                    "tamano_bytes": a_size,
                    "tamano_mb": round(a_size / (1024 * 1024), 2) if a_size else 0,
                    "descargas": a_count
                }
                assets_list.append(item)
                # Priorizar ejecutables de instalación o binarios
                if not exe_asset and (a_name.lower().endswith(".exe") or a_name.lower().endswith(".msi") or a_name.lower().endswith(".zip")):
                    exe_asset = item

            # Limpiar versión remota
            v_remota_limpia = re.sub(r'^[vV]', '', tag.strip())
            hay_nueva = es_version_superior(v_remota_limpia, version_local)

            resultado.update({
                "disponible": hay_nueva,
                "version_remota": v_remota_limpia or tag,
                "tag_name": tag,
                "nombre_release": nombre,
                "notas_cambios": body,
                "url_release": html_url,
                "fecha_publicacion": fecha_fmt,
                "instalador": exe_asset,
                "assets": assets_list,
                "error": None
            })
            return resultado

        elif response.status_code == 404:
            # Quizás no hay release marcado como "latest", buscar lista general
            list_url = f"https://api.github.com/repos/{repo_clean}/releases"
            list_resp = requests.get(list_url, headers=headers, timeout=timeout)
            if list_resp.status_code == 200:
                releases = list_resp.json()
                if not releases:
                    resultado["error"] = f"El repositorio '{repo_clean}' no tiene Releases publicados todavía en GitHub."
                    return resultado
                # Tomar el primer release
                data = releases[0]
                tag = data.get("tag_name", "")
                nombre = data.get("name") or tag
                body = data.get("body") or "No se incluyeron notas de la versión."
                html_url = data.get("html_url") or f"https://github.com/{repo_clean}/releases"
                published_at = data.get("published_at", "")[:10] if data.get("published_at") else "Reciente"

                v_remota_limpia = re.sub(r'^[vV]', '', tag.strip())
                hay_nueva = es_version_superior(v_remota_limpia, version_local)
                resultado.update({
                    "disponible": hay_nueva,
                    "version_remota": v_remota_limpia or tag,
                    "tag_name": tag,
                    "nombre_release": nombre,
                    "notas_cambios": body,
                    "url_release": html_url,
                    "fecha_publicacion": published_at,
                    "error": None
                })
                return resultado
            else:
                resultado["error"] = f"Repositorio '{repo_clean}' no encontrado o no accesible (HTTP 404). Verifica el nombre en Configuración."
                return resultado

        elif response.status_code in (403, 429):
            resultado["error"] = "Límite de peticiones a la API de GitHub alcanzado temporalmente. Intenta más tarde."
            return resultado
        else:
            resultado["error"] = f"GitHub respondió con código de estado {response.status_code}."
            return resultado

    except requests.exceptions.ConnectionError:
        resultado["error"] = "No hay conexión a internet o no se pudo contactar con GitHub."
        return resultado
    except requests.exceptions.Timeout:
        resultado["error"] = "Tiempo de espera agotado al consultar GitHub."
        return resultado
    except Exception as e:
        resultado["error"] = f"Error al verificar actualizaciones: {str(e)}"
        return resultado


def descargar_instalador(url_descarga, ruta_destino, callback_progreso=None, cancelar_evento=None):
    """
    Descarga el archivo del instalador por chunks, reportando progreso mediante callback.
    callback_progreso(bytes_descargados, total_bytes, porcentaje_int, velocidad_str)
    """
    try:
        headers = {"User-Agent": f"CyberAnalyzer-Updater/{APP_VERSION}"}
        resp = requests.get(url_descarga, headers=headers, stream=True, timeout=15)
        resp.raise_for_status()

        total_length = resp.headers.get('content-length')
        if total_length is None:
            total_bytes = 0
        else:
            total_bytes = int(total_length)

        descargados = 0
        inicio_t = time.time()
        temp_dest = ruta_destino + ".part"

        with open(temp_dest, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=65536):
                if cancelar_evento and cancelar_evento.is_set():
                    f.close()
                    try:
                        if os.path.exists(temp_dest):
                            os.remove(temp_dest)
                    except Exception:
                        pass
                    return False, "Descarga cancelada por el usuario"

                if chunk:
                    f.write(chunk)
                    descargados += len(chunk)
                    tiempo_trans = max(0.001, time.time() - inicio_t)
                    velocidad = (descargados / 1024 / 1024) / tiempo_trans  # MB/s
                    vel_str = f"{velocidad:.1f} MB/s"

                    porcentaje = int((descargados / total_bytes) * 100) if total_bytes > 0 else 0
                    if callback_progreso:
                        callback_progreso(descargados, total_bytes, porcentaje, vel_str)

        # Renombrar archivo final
        if os.path.exists(ruta_destino):
            try:
                os.remove(ruta_destino)
            except Exception:
                pass
        os.rename(temp_dest, ruta_destino)
        return True, ruta_destino

    except Exception as e:
        if os.path.exists(ruta_destino + ".part"):
            try:
                os.remove(ruta_destino + ".part")
            except Exception:
                pass
        return False, f"Error durante la descarga: {str(e)}"


def ejecutar_instalador_y_cerrar(ruta_instalador):
    """
    Ejecuta el nuevo instalador de CyberAnalyzer en un proceso independiente.
    """
    try:
        if not os.path.exists(ruta_instalador):
            return False, "El archivo de instalación no existe."

        subprocess.Popen([ruta_instalador], shell=False, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0)
        return True, "Instalador iniciado."
    except Exception as e:
        return False, f"Error al ejecutar instalador: {str(e)}"


def verificar_en_segundo_plano(repo, callback_final, version_local=None):
    """
    Ejecuta la verificación en un hilo en segundo plano para no congelar la interfaz.
    Llama a callback_final(resultado_dict) al terminar.
    """
    def _worker():
        res = verificar_actualizacion_github(repo=repo, version_local=version_local)
        if callback_final:
            try:
                callback_final(res)
            except Exception:
                pass

    t = threading.Thread(target=_worker, daemon=True, name="GitHubUpdateWorker")
    t.start()
    return t
