# 🛡️ CyberAnalyzer - EDR & Threat Intelligence Suite

[![Version](https://img.shields.io/badge/version-1.0.2-blue.svg)](https://github.com/hackThecross/cyber-analizer/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-green.svg)](https://github.com/hackThecross/cyber-analizer)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)

**CyberAnalyzer** es una suite de seguridad integral para Windows diseñada para la detección proactiva, análisis forense, respuesta ante incidentes (EDR) e inteligencia de amenazas en tiempo real.

---

## 🚀 Características Principales

- **🛡️ Firewall EDR & Radar en Tiempo Real:** Monitor interactivo de tráfico malicioso, geolocalización de IPs, mapa global de amenazas, detección de escaneos y bloqueo automático.
- **🍯 Anti-Ransomware con Trampas Canario:** Monitoreo activo de archivos cebo y suspensión inmediata de procesos de cifrado no autorizados.
- **💾 Diagnóstico & DLP USB:** Forense de almacenamiento extraíble, vacuna contra autorun, desocultado de payloads y control de políticas USB (Solo Lectura / Bloqueo).
- **🧬 Integridad de Archivos (FIM):** Monitor continuo de firmas SHA-256 en binarios críticos del sistema operativo y protección de `hosts`.
- **🌐 Detección de C2 & Botnets:** Identificación de conexiones a servidores de comando y control (C2), beaconing sospechoso y sinkhole DNS anti-phishing.
- **⚡ Gestor de Procesos Live:** Análisis heurístico de riesgo en memoria RAM, capacidades de pausa, aislamiento y neutralización de procesos maliciosos.
- **📦 Inventario de Software & VirusTotal API:** Análisis multimodelo con VirusTotal v3, clasificación MITRE ATT&CK y extracción de firmas.
- **🚨 Modo Pánico EDR:** Aislamiento total instantáneo de la red ante incidentes críticos.
- **🔄 Auto-Actualización GitHub Releases:** Detector y descargador integrado de actualizaciones directamente desde GitHub.

---

## 📥 Instalación

Descarga el último instalador compilado desde la sección de **[Releases](https://github.com/hackThecross/cyber-analizer/releases)**:

```text
CyberAnalyzer_Setup_v1.0.2.exe
```

---

## 🛠️ Requisitos de Desarrollo

- **Python 3.10+** (Windows 10 / 11 x64)
- Dependencias:
  ```bash
  pip install -r requirements.txt
  ```

### Ejecutar en Desarrollo:
```bash
python main.py
```

---

## 📜 Autor y Créditos

Desarrollado por **hackThecross**.  
*CyberAnalyzer Suite - Threat Intelligence & EDR Protection.*
