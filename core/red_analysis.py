PUERTOS_SOSPECHOSOS = {4444, 1337, 666, 5555}

def evaluar_conexion(con):
    score = 0

    ip_remota = con.get("ip")
    puerto = con.get("puerto")
    proceso = con.get("proceso", "").lower()
    ruta = con.get("ruta", "").lower()

    if ip_remota and not ip_remota.startswith(("10.", "192.168.", "172.")):
        score += 2

    if puerto in PUERTOS_SOSPECHOSOS:
        score += 3

    if any(x in ruta for x in ["appdata", "temp", "public"]):
        score += 3

    if proceso in ["python.exe", "powershell.exe", "cmd.exe"]:
        score += 2

    if score >= 6:
        nivel = "CRÍTICO"
    elif score >= 3:
        nivel = "MEDIO"
    else:
        nivel = "NORMAL"

    return nivel, score
