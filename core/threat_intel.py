# core/threat_intel.py

BASE_CONOCIMIENTO = {
    "trojan": {
        "tipo": "Troyano (Trojan Horse)",
        "descripcion": "Malware que se disfraza de software legítimo para engañar al usuario y ejecutarse. Permite al atacante tomar control del endpoint.",
        "comportamiento": [
            "Ejecuta código arbitrario y payloads secundarios",
            "Abre puertas traseras (backdoors) y canales de C2",
            "Descarga módulos maliciosos adicionales en AppData/Temp",
            "Desactiva herramientas de seguridad o defensas"
        ],
        "impacto": [
            "Compromiso total del sistema operativo",
            "Robo de credenciales bancarias y contraseñas",
            "Acceso no autorizado persistente"
        ],
        "mitre": ["T1059", "T1105", "T1071", "T1547"],
        "recomendacion": "Finalizar procesos sospechosos inmediatamente, aislar de la red y mover binarios a cuarentena."
    },
    "ransom": {
        "tipo": "Ransomware / Secuestrador de Archivos",
        "descripcion": "Malware de alto impacto que cifra los documentos y archivos del usuario para exigir un pago de rescate en criptomonedas.",
        "comportamiento": [
            "Cifra archivos de usuario (.docx, .pdf, .jpg, .db, etc.) con algoritmos AES/RSA",
            "Elimina copias de seguridad de volumen sombra (vssadmin delete shadows)",
            "Genera notas de rescate (HOW_TO_DECRYPT)",
            "Intenta propagarse a través de recursos compartidos de red (SMB)"
        ],
        "impacto": [
            "Pérdida irreversible de información sensible",
            "Interrupción operativa total",
            "Extorsión y filtración de datos confidenciales"
        ],
        "mitre": ["T1486", "T1490", "T1070", "T1021"],
        "recomendacion": "Aislar la máquina de la red de inmediato. No pagar el rescate. Restaurar desde backups no infectados."
    },
    "backdoor": {
        "tipo": "Puerta Trasera (Backdoor)",
        "descripcion": "Mecanismo que otorga acceso remoto persistente e inadvertido al sistema, eludiendo los mecanismos normales de autenticación.",
        "comportamiento": [
            "Escucha en puertos TCP/UDP no estándar o realiza beaconing inverso",
            "Permite ejecución de comandos en shell remota",
            "Transfiere archivos y herramientas de explotación"
        ],
        "impacto": [
            "Control remoto ilimitado por parte del adversario",
            "Uso del equipo como pivote en la red local"
        ],
        "mitre": ["T1133", "T1059", "T1095", "T1571"],
        "recomendacion": "Bloquear la IP remota en firewall, matar el proceso y eliminar claves de inicio en el registro."
    },
    "spyware": {
        "tipo": "Software Espía (Spyware / Keylogger)",
        "descripcion": "Software diseñado para recolectar información privada del usuario sin su conocimiento ni consentimiento.",
        "comportamiento": [
            "Captura pulsaciones de teclado (Keylogging)",
            "Toma capturas de pantalla periódicas",
            "Monitorea el portapapeles y credenciales almacenadas en navegadores"
        ],
        "impacto": [
            "Robo de credenciales de acceso, correos y billeteras cripto",
            "Vulneración de la privacidad personal y corporativa"
        ],
        "mitre": ["T1056", "T1113", "T1555", "T1041"],
        "recomendacion": "Cambiar todas las contraseñas desde un dispositivo seguro y eliminar el malware."
    },
    "miner": {
        "tipo": "Minero No Autorizado (Cryptojacker)",
        "descripcion": "Software malicioso que utiliza los recursos de CPU y GPU de la víctima para minar criptomonedas sin permiso.",
        "comportamiento": [
            "Consumo del 90-100% de CPU y calentamiento excesivo",
            "Inyección en procesos legítimos o ejecución en segundo plano",
            "Conexión continua a pools de minería conocidos (puertos 3333, 4444, 8080)"
        ],
        "impacto": [
            "Degradación severa del rendimiento del equipo",
            "Desgaste físico acelerado del hardware"
        ],
        "mitre": ["T1496", "T1059"],
        "recomendacion": "Terminar el proceso consumidor de CPU y revisar tareas programadas."
    },
    "injector": {
        "tipo": "Inyector de Código (Process Injector)",
        "descripcion": "Técnica donde el código malicioso se inserta dentro de la memoria de un proceso legítimo (Process Hollowing / DLL Injection).",
        "comportamiento": [
            "Utiliza llamadas API como VirtualAllocEx, WriteProcessMemory y CreateRemoteThread",
            "Evade la detección tradicional de antivirus basada en archivos",
            "Oculta la actividad del adversario tras un proceso del sistema"
        ],
        "impacto": [
            "Evasión de defensas y persistencia oculta",
            "Robo de tokens y privilegios de sistema"
        ],
        "mitre": ["T1055", "T1055.012", "T1036"],
        "recomendacion": "Terminar el proceso host infectado y analizar el binario de origen."
    },
    "worm": {
        "tipo": "Gusano Informático (Worm / Shortcut Malware)",
        "descripcion": "Malware autorreplicable que se propaga por memorias USB, carpetas compartidas y vulnerabilidades de red.",
        "comportamiento": [
            "Oculta las carpetas del usuario en dispositivos USB y crea accesos directos (.lnk) maliciosos",
            "Modifica autorun.inf y claves de inicio del registro",
            "Escanea redes locales en busca de vulnerabilidades (SMB/EternalBlue)"
        ],
        "impacto": [
            "Infección masiva de unidades extraíbles y equipos de la red",
            "Ocultación y corrupción de archivos de usuario"
        ],
        "mitre": ["T1091", "T1059", "T1204"],
        "recomendacion": "Desinfectar y vacunar memorias USB, y desocultar archivos mediante 'attrib'."
    }
}


def explicar_amenaza(nombre):
    nombre_low = (nombre or "").lower()

    for clave, info in BASE_CONOCIMIENTO.items():
        if clave in nombre_low:
            return (
                f"🚨 {info['tipo']}\n\n"
                f"{info['descripcion']}\n\n"
                f"⚙️ Comportamiento:\n" + "\n".join(f"• {c}" for c in info["comportamiento"]) + "\n\n"
                f"💥 Impacto:\n" + "\n".join(f"• {i}" for i in info["impacto"]) + "\n\n"
                f"🛡️ Técnicas MITRE: {', '.join(info['mitre'])}\n\n"
                f"💡 Recomendación: {info['recomendacion']}"
            )

    return (
        "🚨 Amenaza Detectada\n\n"
        "Comportamiento anómalo o firma maliciosa identificada por los motores de seguridad.\n\n"
        "• Comportamiento sospechoso para la seguridad del endpoint\n"
        "• Riesgo potencial de persistencia y comunicación no autorizada\n\n"
        "💡 Recomendación: Aislar el proceso o mover el binario a cuarentena inmediatamente."
    )


def obtener_info_amenaza(nombre):
    nombre_low = (nombre or "").lower()
    for clave, info in BASE_CONOCIMIENTO.items():
        if clave in nombre_low:
            return info
    return {
        "tipo": "Amenaza Genérica",
        "descripcion": "Amenaza sospechosa detectada por heurística o firmas de seguridad.",
        "comportamiento": ["Actividad potencialmente dañina", "Posible evasión de seguridad"],
        "impacto": ["Riesgo de seguridad para el sistema"],
        "mitre": ["T1059"],
        "recomendacion": "Revisar y aislar el artefacto sospechoso."
    }

