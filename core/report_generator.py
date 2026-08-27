import os
import time
import json
import webbrowser
from datetime import datetime
from core.settings_manager import get_writable_path
from core.diagnostico import diagnostico_general
from core.deep_scan import ejecutar_analisis_profundo
from core.firewall_guard import cargar_ataques, cargar_config_firewall
from core.software_inventory import obtener_programas_instalados
from core.security_logs import obtener_historial_edr

REPORTS_DIR = get_writable_path("reportes")

def generar_reporte_seguridad_html():
    """
    Genera un informe forense y técnico de auditoría EDR en formato HTML
    con diseño dark cyber profesional, estadísticas completas y recomendaciones MITRE ATT&CK.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"CyberAnalyzer_Reporte_{timestamp}.html"
    report_path = os.path.join(REPORTS_DIR, report_filename)

    # Recolectar telemetría
    data_diag = diagnostico_general()
    data_deep = ejecutar_analisis_profundo()
    ataques_list = cargar_ataques()
    fw_cfg = cargar_config_firewall()
    software_list = obtener_programas_instalados()[:30]
    edr_logs = obtener_historial_edr()[:25]

    score = data_deep.get("score", 100)
    estado_global = data_deep.get("estado_global", "SEGURO")
    color_score = "#00ff9c" if score >= 85 else ("#ffcc00" if score >= 60 else "#ff4c4c")

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>CyberAnalyzer - Informe Técnico de Seguridad EDR</title>
    <style>
        body {{ font-family: 'Segoe UI', Consolas, monospace; background: #080c10; color: #cfd8dc; margin: 0; padding: 25px; }}
        .header {{ background: #101720; border: 1px solid #1c2b3a; border-radius: 8px; padding: 20px; display: flex; justify-content: space-between; align-items: center; }}
        .title {{ color: #00ff9c; font-size: 24px; font-weight: bold; margin: 0; }}
        .subtitle {{ color: #8899a6; font-size: 13px; margin-top: 5px; }}
        .score-box {{ text-align: right; }}
        .score {{ font-size: 38px; font-weight: bold; color: {color_score}; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .card {{ background: #101720; border: 1px solid #1c2b3a; border-radius: 8px; padding: 15px; }}
        .card-title {{ color: #8899a6; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
        .card-val {{ color: #00d2ff; font-size: 20px; font-weight: bold; margin: 6px 0; }}
        .section {{ background: #101720; border: 1px solid #1c2b3a; border-radius: 8px; padding: 18px; margin-bottom: 20px; }}
        .section-title {{ color: #00ff9c; font-size: 16px; font-weight: bold; margin-bottom: 12px; border-bottom: 1px solid #1c2b3a; padding-bottom: 6px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
        th {{ background: #152230; color: #00ff9c; text-align: left; padding: 10px; border-bottom: 1px solid #1c2b3a; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #141c26; }}
        tr:hover {{ background: #151d28; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 10px; }}
        .badge-crit {{ background: #3a1616; color: #ff4c4c; border: 1px solid #ff4c4c; }}
        .badge-med {{ background: #3a3216; color: #ffcc00; border: 1px solid #ffcc00; }}
        .badge-ok {{ background: #163a24; color: #00ff9c; border: 1px solid #00ff9c; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">🛡️ CYBER_ANALYZER - INFORME TÉCNICO DE AUDITORÍA EDR</div>
            <div class="subtitle">Endpoint: {data_diag['sistema']['hostname']} | SO: {data_diag['sistema']['os']} | Usuario: {data_diag['sistema']['usuario']} | Fecha: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
        </div>
        <div class="score-box">
            <div class="subtitle">PUNTAJE DE SALUD EDR</div>
            <div class="score">{score} / 100</div>
            <div style="color: {color_score}; font-weight: bold; font-size: 12px;">{estado_global}</div>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-title">Ataques Interceptados</div>
            <div class="card-val" style="color: #ff4c4c;">{len(ataques_list)}</div>
            <div class="subtitle">Bloqueados en Firewall</div>
        </div>
        <div class="card">
            <div class="card-title">IPs Baneadas</div>
            <div class="card-val" style="color: #ffcc00;">{len(fw_cfg.get('ips_bloqueadas', []))}</div>
            <div class="subtitle">Reglas Activas netsh</div>
        </div>
        <div class="card">
            <div class="card-title">Vulnerabilidades EDR</div>
            <div class="card-val" style="color: #00d2ff;">{data_deep.get('total_hallazgos', 0)}</div>
            <div class="subtitle">Críticos: {data_deep.get('criticos', 0)}</div>
        </div>
        <div class="card">
            <div class="card-title">Software Auditado</div>
            <div class="card-val" style="color: #00ff9c;">{len(software_list)}</div>
            <div class="subtitle">Firmas e Integridad</div>
        </div>
    </div>

    <div class="section">
        <div class="section-title">🚨 Registro de Ciberataques e Intrusiones Interceptadas (Firewall EDR)</div>
        <table>
            <thead>
                <tr>
                    <th>Fecha / Hora</th>
                    <th>IP Origen</th>
                    <th>País</th>
                    <th>Tipo / VPN</th>
                    <th>¿Qué Quería Hacer? (Intención)</th>
                    <th>Ruta / Puerto Objetivo</th>
                    <th>Acción EDR</th>
                </tr>
            </thead>
            <tbody>
"""

    for a in ataques_list[:15]:
        sev_badge = "badge-crit" if a.get("severidad") == "CRÍTICO" else "badge-med"
        html_content += f"""
                <tr>
                    <td>{a.get('fecha')}</td>
                    <td><strong>{a.get('ip')}</strong></td>
                    <td>{a.get('codigo_pais', '')} - {a.get('pais', '')}</td>
                    <td>{'🛡️ VPN: ' + a.get('proveedor_vpn', '') if a.get('es_vpn') else '🌐 Directa (ISP)'}</td>
                    <td><span class="badge {sev_badge}">{a.get('intencion')}</span></td>
                    <td><code>{a.get('ruta_objetivo')}</code></td>
                    <td><span class="badge badge-ok">{a.get('accion', 'BLOQUEADO')}</span></td>
                </tr>
"""

    html_content += """
            </tbody>
        </table>
    </div>

    <div class="section">
        <div class="section-title">🔍 Hallazgos de Seguridad en Memoria, Persistencia y Zonas Críticas</div>
        <table>
            <thead>
                <tr>
                    <th>Fase de Auditoría</th>
                    <th>Nivel</th>
                    <th>Categoría</th>
                    <th>Descripción del Hallazgo</th>
                </tr>
            </thead>
            <tbody>
"""

    for h in data_deep.get("hallazgos", [])[:12]:
        badge_cls = "badge-crit" if h.get("nivel") == "CRÍTICO" else "badge-med"
        html_content += f"""
                <tr>
                    <td>{h.get('fase', 'Sistema')}</td>
                    <td><span class="badge {badge_cls}">{h.get('nivel', 'INFO')}</span></td>
                    <td><strong>{h.get('tipo', 'Hallazgo')}</strong></td>
                    <td>{h.get('mensaje', '')}</td>
                </tr>
"""

    html_content += f"""
            </tbody>
        </table>
    </div>

    <div class="section">
        <div class="section-title">📋 Registro de Acciones de Remediación y Respuesta EDR</div>
        <table>
            <thead>
                <tr>
                    <th>Fecha / Hora</th>
                    <th>Acción Ejecutada</th>
                    <th>Severidad</th>
                    <th>Resultado</th>
                    <th>Detalle de Operación</th>
                </tr>
            </thead>
            <tbody>
"""

    for log in edr_logs[:12]:
        html_content += f"""
                <tr>
                    <td>{log.get('fecha')}</td>
                    <td><strong>{log.get('accion')}</strong></td>
                    <td>{log.get('nivel', 'INFO')}</td>
                    <td><span class="badge badge-ok">{log.get('resultado', 'OK')}</span></td>
                    <td>{log.get('detalle', '')}</td>
                </tr>
"""

    html_content += """
            </tbody>
        </table>
    </div>

    <div style="text-align: center; color: #8899a6; font-size: 11px; margin-top: 30px;">
        Informe generado automáticamente por CyberAnalyzer Suite EDR v1.0.1 • Cumplimiento MITRE ATT&CK
    </div>
</body>
</html>
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    try:
        webbrowser.open(report_path)
    except Exception:
        pass

    return True, report_path
