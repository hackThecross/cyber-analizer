import requests

VT_URL = "https://www.virustotal.com/api/v3/files/{}"

def consultar_hash_vt(hash_sha256, api_key):
    headers = {
        "x-apikey": api_key
    }

    r = requests.get(VT_URL.format(hash_sha256), headers=headers)

    if r.status_code == 404:
        return {
            "estado": "no_encontrado"
        }

    if r.status_code != 200:
        raise Exception(f"Error VirusTotal: {r.status_code}")

    data = r.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]

    return {
        "estado": "ok",
        "malicioso": stats.get("malicious", 0),
        "sospechoso": stats.get("suspicious", 0),
        "total": sum(stats.values()),
        "link": f"https://www.virustotal.com/gui/file/{hash_sha256}"
    }


def obtener_analisis_completo(hash_sha256, api_key):
    headers = {"x-apikey": api_key}
    r = requests.get(
        f"https://www.virustotal.com/api/v3/files/{hash_sha256}",
        headers=headers
    )

    if r.status_code != 200:
        raise Exception("Error VT")

    attr = r.json()["data"]["attributes"]

    return {
        "motores": attr["last_analysis_results"],
        "tags": attr.get("tags", []),
        "mitre": attr.get("crowdsourced_yara_results", []),
        "stats": attr["last_analysis_stats"],
        
    }

