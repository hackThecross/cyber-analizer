import hashlib
import os


def calcular_sha256(ruta):
    if not ruta or not os.path.exists(ruta):
        return None

    sha256 = hashlib.sha256()

    try:
        with open(ruta, "rb") as f:
            for bloque in iter(lambda: f.read(8192), b""):
                sha256.update(bloque)
        return sha256.hexdigest()
    except Exception:
        return None


def comparar_hash(ruta, hash_esperado):
    if not hash_esperado:
        return False, "Hash esperado vacío"

    hash_esperado = hash_esperado.lower().strip()
    hash_actual = calcular_sha256(ruta)

    if not hash_actual:
        return False, "No se pudo calcular el hash del archivo"

    if hash_actual == hash_esperado:
        return True, "Hash coincide (archivo original)"

    return False, "Hash NO coincide (archivo modificado)"


def obtener_ejecutable_principal(ruta):
    if not ruta or not os.path.exists(ruta):
        return None

    # Si ya es un .exe
    if os.path.isfile(ruta) and ruta.lower().endswith(".exe"):
        return ruta

    # Si es carpeta, buscar exe
    if os.path.isdir(ruta):
        for archivo in os.listdir(ruta):
            if archivo.lower().endswith(".exe"):
                return os.path.join(ruta, archivo)

    return None