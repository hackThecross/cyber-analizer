import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import subprocess
import os
import sys
import threading
import time
import webbrowser
import psutil
from PIL import Image, ImageTk

# ───── MÓDULOS CORE ─────
from core.diagnostico import diagnostico_general, evaluar_alertas
from core.red import estado_red_completo
from core.edr_actions import (
    bloquear_ip, desbloquear_ip, matar_proceso, aislar_proceso, desaislar_proceso,
    cuarentena, eliminar_persistencia, suspender_proceso, reanudar_proceso,
    obtener_archivos_cuarentena, restaurar_cuarentena, eliminar_definitivo_cuarentena, es_admin
)
from core.vt_client import consultar_hash_vt, obtener_analisis_completo
from core.software_inventory import obtener_programas_instalados
from core.hash_utils import calcular_sha256, obtener_ejecutable_principal, comparar_hash
from core.threat_intel import explicar_amenaza, obtener_info_amenaza
from core.process_activity import obtener_procesos_activos, calcular_riesgo_proceso
from core.usb_diagnostico import (
    detectar_unidades_usb, analizar_unidad_usb, vacunar_usb,
    desocultar_archivos_usb, limpiar_amenazas_usb, expulsar_usb
)
from core.optimizer import (
    analizar_espacio_limpieza, ejecutar_limpieza, vaciar_papelera,
    optimizar_ram, obtener_inicio_sistema
)
from core.deep_scan import ejecutar_analisis_profundo
from core.security_logs import (
    obtener_logs_seguridad_windows, registrar_accion_edr,
    obtener_historial_edr, limpiar_historial_edr
)
from core.settings_manager import cargar_configuracion, guardar_configuracion, probar_conexion_vt
from core.firewall_guard import (
    cargar_config_firewall, guardar_config_firewall, cargar_ataques, guardar_ataques,
    bloquear_ip_firewall, desbloquear_ip_firewall, iniciar_monitor_firewall,
    detener_monitor_firewall, simular_ataque_prueba, configurar_persistencia_segundo_plano,
    suscribir_evento_ataque, desuscribir_evento_ataque
)
from core.firewall_globe import ThreatGlobeCanvas
from core.toast_notifier import mostrar_notificacion_antivirus, mostrar_notificacion_actualizacion
from core.panic_mode import activar_modo_panico, desactivar_modo_panico, estado_modo_panico
from core.report_generator import generar_reporte_seguridad_html
from core.anti_ransomware import (
    desplegar_senuelos, iniciar_guardian_ransomware, detener_guardian_ransomware
)
from core.usb_dlp import obtener_politica_usb, establecer_politica_usb
from core.file_integrity import auditar_integridad_archivos, crear_linea_base_fim, restaurar_archivo_hosts_limpio
from core.dns_sinkhole import (
    cargar_config_sinkhole, guardar_config_sinkhole, aplicar_escudo_sinkhole, agregar_dominio_sinkhole
)
from core.audio_alerts import (
    reproducir_alerta_amenaza, reproducir_bloqueo_exitoso, reproducir_alerta_panico, reproducir_sonido_exito
)
from core.updater import (
    verificar_actualizacion_github, verificar_en_segundo_plano,
    descargar_instalador, ejecutar_instalador_y_cerrar, DEFAULT_GITHUB_REPO
)

# ───── PALETA DE COLORES CYBER ─────
BG = "#0b0f14"
PANEL = "#11161d"
PANEL_LIGHT = "#171e27"
BTN = "#151b23"
BTN_HOVER = "#212a36"
GREEN = "#00ff9c"
CYAN = "#00d2ff"
RED = "#ff4c4c"
YELLOW = "#ffcc00"
TEXT = "#cfd8dc"
TEXT_MUTED = "#8899a6"
BORDER = "#1f2933"

APP_VERSION = "1.0.2"


def resource_path(relative_path):
    """
    Obtiene la ruta absoluta para recursos (imágenes, iconos, etc.),
    compatible con PyInstaller (_MEIPASS) y ejecución normal en desarrollo.
    """
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(os.path.dirname(__file__))

    full_path = os.path.join(base_path, relative_path)
    if os.path.exists(full_path):
        return full_path

    fallback_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), relative_path)
    if os.path.exists(fallback_path):
        return fallback_path

    return full_path


class CyberAnalyzerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"CyberAnalyzer - Security & EDR Inspector Suite v{APP_VERSION}")
        self.geometry("1200x720")
        self.minsize(1050, 650)
        self.configure(bg=BG)

        # Configuración de icono de la aplicación (ICO + PhotoImage)
        ico_path = resource_path("imagenes/icono.ico")

        if os.path.exists(ico_path):
            try:
                self.iconbitmap(ico_path)
            except Exception:
                pass


        self.animacion_activa = True
        self.historial_vistas = []
        self.vista_actual = None
        self.live_running = False
        self.config_app = cargar_configuracion()
        self.info_actualizacion = None
        self.btn_update = None

        # Iniciar monitor de firewall en segundo plano y enganchar notificaciones toast
        def _despachar_notificacion_firewall(ev):
            # Si el usuario ya está dentro de la pantalla del firewall, no mostrar notificación emergente
            if hasattr(self, "vista_actual") and self.vista_actual == self.modulo_firewall:
                return
            # En cualquier otra pantalla, minimizado o cerrado en segundo plano, mostrar notificación
            mostrar_notificacion_antivirus(
                self, ev, callback_abrir_firewall=lambda: self.cambiar_vista(self.modulo_firewall)
            )

        try:
            iniciar_monitor_firewall(
                callback_notif=lambda ev: self.after(0, lambda: _despachar_notificacion_firewall(ev))
            )
        except Exception:
            pass

        # Iniciar guardián anti-ransomware en segundo plano
        try:
            iniciar_guardian_ransomware(
                callback_alerta=lambda ev: self.after(0, lambda: messagebox.showwarning(
                    "Anti-Ransomware EDR",
                    f"🚨 ¡ALERTA CRÍTICA DE RANSOMWARE!\n\n"
                    f"{ev['motivo']}\n"
                    f"Archivo canario afectado: {ev['archivo_canario']}\n"
                    f"Proceso neutralizado: {ev['proceso_neutralizado']}\n"
                    f"Acción: {ev['accion']}"
                ))
            )
        except Exception:
            pass

        self.configurar_estilos()
        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.al_cerrar)
        self.inicio()

        # Comprobación de actualizaciones en segundo plano al iniciar
        if self.config_app.get("check_updates_startup", True):
            self.after(2500, self.verificar_actualizacion_silenciosa)

    def configurar_estilos(self):
        style = ttk.Style()
        style.theme_use("default")

        style.configure(
            "Treeview",
            background=PANEL,
            foreground=TEXT,
            fieldbackground=PANEL,
            rowheight=28,
            font=("Consolas", 10),
            borderwidth=0
        )
        style.configure(
            "Treeview.Heading",
            background=PANEL_LIGHT,
            foreground=GREEN,
            font=("Consolas", 10, "bold"),
            borderwidth=1,
            relief="flat"
        )
        style.map(
            "Treeview",
            background=[("selected", "#1e3a5f")],
            foreground=[("selected", GREEN)]
        )

        style.configure(
            "TProgressbar",
            thickness=16,
            troughcolor=PANEL,
            background=GREEN
        )

    def build_ui(self):
        # ───── 1. TOP BAR FIJO (LOGO + TÍTULO DE LA SUITE) ─────
        self.top_bar = tk.Frame(self, bg=PANEL, height=55, bd=1, relief="solid")
        self.top_bar.pack(fill="x", side="top")

        logo_path = resource_path("imagenes/logo.png")
        if os.path.exists(logo_path):
            try:
                img = Image.open(logo_path).resize((40, 40), Image.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(img)
                lbl_logo = tk.Label(self.top_bar, image=self.logo_img, bg=PANEL)
                lbl_logo.pack(side="left", padx=(15, 10), pady=6)
            except Exception:
                pass

        titulo_frame = tk.Frame(self.top_bar, bg=PANEL)
        titulo_frame.pack(side="left", padx=5)
        tk.Label(titulo_frame, text="CYBER_ANALYZER", fg=GREEN, bg=PANEL, font=("Consolas", 14, "bold")).pack(anchor="w")
        tk.Label(titulo_frame, text="EDR & Threat Intelligence Suite", fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 9)).pack(anchor="w")

        # Botones de Acción Rápida en Top Bar (Modo Pánico & Reporte EDR)
        top_actions = tk.Frame(self.top_bar, bg=PANEL)
        top_actions.pack(side="right", padx=15, pady=8)

        is_panic = estado_modo_panico()

        def toggle_panico():
            if estado_modo_panico():
                ok, msg = desactivar_modo_panico()
                if ok:
                    messagebox.showinfo("Modo Pánico", msg)
                    self.btn_panic.config(text="🚨 AISLAR (PÁNICO)", bg="#3a1616", fg=RED)
                else:
                    messagebox.showerror("Error", msg)
            else:
                if messagebox.askyesno("Confirmar Aislamiento Total", "⚠️ ¿Deseas activar el MODO PÁNICO?\n\nSe cortará INMEDIATAMENTE todo el tráfico de red para frenar ataques activos o ransomware."):
                    ok, msg = activar_modo_panico()
                    if ok:
                        messagebox.showwarning("Modo Pánico Activo", msg)
                        self.btn_panic.config(text="🟢 RESTAURAR RED", bg="#163a20", fg=GREEN)
                    else:
                        messagebox.showerror("Error", msg)

        def exportar_reporte():
            ok, path = generar_reporte_seguridad_html()
            if ok:
                messagebox.showinfo("Reporte EDR", f"✅ Informe de auditoría forense generado con éxito:\n\n{path}")
            else:
                messagebox.showerror("Error", "No se pudo generar el informe.")

        self.btn_panic = tk.Button(
            top_actions,
            text="🟢 RESTAURAR RED" if is_panic else "🚨 AISLAR (PÁNICO)",
            bg="#163a20" if is_panic else "#3a1616",
            fg=GREEN if is_panic else RED,
            activebackground=RED,
            activeforeground="#000000",
            font=("Consolas", 9, "bold"),
            relief="solid",
            bd=1,
            padx=10,
            pady=4,
            cursor="hand2",
            command=toggle_panico
        )
        self.btn_panic.pack(side="right", padx=(8, 0))

        tk.Button(
            top_actions,
            text="📑 REPORTE EDR",
            bg=BTN,
            fg=CYAN,
            activebackground=CYAN,
            activeforeground="#000000",
            font=("Consolas", 9, "bold"),
            relief="solid",
            bd=1,
            padx=10,
            pady=4,
            cursor="hand2",
            command=exportar_reporte
        ).pack(side="right", padx=(8, 0))

        self.btn_update = tk.Button(
            top_actions,
            text="🔄 ACTUALIZAR",
            bg=BTN,
            fg=GREEN,
            activebackground=GREEN,
            activeforeground="#000000",
            font=("Consolas", 9, "bold"),
            relief="solid",
            bd=1,
            padx=10,
            pady=4,
            cursor="hand2",
            command=self.comprobar_actualizaciones_manual
        )
        self.btn_update.pack(side="right")

        # ───── 2. BARRA SUB-HEADER FIJA (FUERA DEL SCROLL) ─────
        # Aquí se alojan de forma FIJA y PERMANENTE el botón Volver y el Título de cada pantalla
        self.sub_header = tk.Frame(self, bg=PANEL_LIGHT, height=50, bd=1, relief="solid")

        # ───── 3. ÁREA PRINCIPAL DINÁMICA (SIN SCROLL GLOBAL) ─────
        self.main_container = tk.Frame(self, bg=BG)
        self.main_container.pack(fill="both", expand=True)

    def establecer_cabecera_fija(self, titulo, color=GREEN, boton_extra=None, callback_volver=None):
        """
        Configura la cabecera fija que permanece visible en la parte superior.
        """
        for w in self.sub_header.winfo_children():
            w.destroy()

        # Empacar sub_header justo debajo de top_bar si no está empacado
        self.sub_header.pack(fill="x", side="top", before=self.main_container)

        # Botón Volver fijo a la izquierda
        fn_volver = callback_volver if callback_volver else self.volver
        btn_volver = tk.Button(
            self.sub_header,
            text="⬅ Volver al Menú",
            bg=BTN,
            fg=GREEN,
            activebackground=PANEL,
            activeforeground=GREEN,
            font=("Consolas", 10, "bold"),
            relief="solid",
            bd=1,
            padx=14,
            pady=4,
            cursor="hand2",
            command=fn_volver
        )
        btn_volver.pack(side="left", padx=(20, 15), pady=8)

        # Título de la pantalla fijo
        lbl_tit = tk.Label(
            self.sub_header,
            text=titulo,
            fg=color,
            bg=PANEL_LIGHT,
            font=("Consolas", 13, "bold")
        )
        lbl_tit.pack(side="left", pady=8)

        # Botón o widget extra opcional a la derecha
        if boton_extra:
            txt_b, cmd_b, col_b = boton_extra
            tk.Button(
                self.sub_header,
                text=txt_b,
                bg=BTN,
                fg=col_b,
                font=("Consolas", 10, "bold"),
                relief="solid",
                bd=1,
                padx=12,
                pady=4,
                cursor="hand2",
                command=cmd_b
            ).pack(side="right", padx=20, pady=8)

    def ocultar_cabecera_fija(self):
        self.sub_header.pack_forget()

    def limpiar_contenido(self):
        self.live_running = False
        self.unbind_all("<MouseWheel>")
        for widget in self.main_container.winfo_children():
            widget.destroy()

    def cambiar_vista(self, funcion_vista):
        if hasattr(self, "vista_actual") and self.vista_actual and self.vista_actual != funcion_vista:
            self.historial_vistas.append(self.vista_actual)
        self.vista_actual = funcion_vista
        self.limpiar_contenido()
        funcion_vista()

    def volver(self):
        self.cambiar_vista(self.inicio)

    def al_cerrar(self):
        cfg_fw = cargar_config_firewall()
        if cfg_fw.get("mantener_segundo_plano", True):
            self.withdraw()
            return

        self.salir_completo()

    def salir_completo(self):
        self.live_running = False
        try:
            detener_monitor_firewall()
        except Exception:
            pass
        try:
            detener_guardian_ransomware()
        except Exception:
            pass
        self.destroy()

    # ═════════════════════════════════════════════════════════════
    # VISTA: INICIO / HOME LAUNCHER PRINCIPAL
    # ═════════════════════════════════════════════════════════════
    def inicio(self):
        self.limpiar_contenido()
        self.ocultar_cabecera_fija()

        # ── 1. PANEL PRINCIPAL CON TELEMETRÍA (FIJO EN LA PARTE SUPERIOR) ──
        fixed_top = tk.Frame(self.main_container, bg=BG)
        fixed_top.pack(fill="x", padx=30, pady=(12, 4))

        # Header Hero
        hero = tk.Frame(fixed_top, bg=PANEL, bd=1, relief="solid")
        hero.pack(fill="x", pady=(0, 10))

        hero_left = tk.Frame(hero, bg=PANEL)
        hero_left.pack(side="left", padx=20, pady=10)

        tk.Label(hero_left, text="🛡️ PANEL DE CONTROL PRINCIPAL", fg=GREEN, bg=PANEL, font=("Consolas", 16, "bold")).pack(anchor="w")
        es_admin_str = "ADMINISTRADOR (ELEVADO)" if es_admin() else "USUARIO ESTÁNDAR"
        tk.Label(hero_left, text=f"Selecciona el módulo que deseas ejecutar | Privilegios: {es_admin_str}", fg=CYAN, bg=PANEL, font=("Consolas", 10)).pack(anchor="w", pady=(2, 0))

        # Tarjetas de Telemetría
        cards_frame = tk.Frame(fixed_top, bg=BG)
        cards_frame.pack(fill="x", pady=(0, 8))

        try:
            cpu_val = psutil.cpu_percent()
            mem_info = psutil.virtual_memory()
            mem_val = mem_info.percent
            proc_count = len(psutil.pids())
            conns_count = len(psutil.net_connections(kind="inet"))
        except Exception:
            cpu_val, mem_val, proc_count, conns_count = 0, 0, 0, 0

        def crear_tarjeta(parent, icon, titulo, valor, subtitulo, color):
            c = tk.Frame(parent, bg=PANEL, bd=1, relief="solid")
            c.pack(side="left", fill="both", expand=True, padx=4)
            tk.Label(c, text=icon, fg=color, bg=PANEL, font=("Segoe UI Emoji", 16)).pack(anchor="w", padx=12, pady=(6, 1))
            tk.Label(c, text=titulo, fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 8, "bold")).pack(anchor="w", padx=12)
            tk.Label(c, text=str(valor), fg=color, bg=PANEL, font=("Consolas", 14, "bold")).pack(anchor="w", padx=12, pady=1)
            tk.Label(c, text=subtitulo, fg=TEXT, bg=PANEL, font=("Consolas", 8)).pack(anchor="w", padx=12, pady=(0, 6))

        crear_tarjeta(cards_frame, "⚙️", "USO DE CPU", f"{cpu_val} %", f"{psutil.cpu_count(logical=True)} núcleos", GREEN if cpu_val < 70 else RED)
        crear_tarjeta(cards_frame, "🧠", "MEMORIA RAM", f"{mem_val} %", f"{round(mem_info.used/(1024**3),1)} / {round(mem_info.total/(1024**3),1)} GB", GREEN if mem_val < 80 else YELLOW)
        crear_tarjeta(cards_frame, "📊", "PROCESOS", f"{proc_count}", "En ejecución", CYAN)
        crear_tarjeta(cards_frame, "🌐", "CONEXIONES", f"{conns_count}", "Sockets activos", GREEN)

        # Título de Módulos (Fijo)
        tk.Label(fixed_top, text="🚀 MÓDULOS DISPONIBLES (SELECCIONA UNA OPCIÓN)", fg=GREEN, bg=BG, font=("Consolas", 11, "bold")).pack(anchor="w", pady=(2, 2))

        # ── 2. CONTENEDOR CON SCROLL SÓLO PARA LOS MÓDULOS DISPONIBLES ──
        mod_scroll_container = tk.Frame(self.main_container, bg=BG)
        mod_scroll_container.pack(fill="both", expand=True, padx=30, pady=(0, 10))

        canvas_mod = tk.Canvas(mod_scroll_container, bg=BG, highlightthickness=0)
        scroll_mod = ttk.Scrollbar(mod_scroll_container, orient="vertical", command=canvas_mod.yview)
        scroll_mod.pack(side="right", fill="y")
        canvas_mod.pack(side="left", fill="both", expand=True)

        grid_frame = tk.Frame(canvas_mod, bg=BG)
        canvas_window = canvas_mod.create_window((0, 0), window=grid_frame, anchor="nw")
        canvas_mod.configure(yscrollcommand=scroll_mod.set)

        grid_frame.bind("<Configure>", lambda e: canvas_mod.configure(scrollregion=canvas_mod.bbox("all")))
        canvas_mod.bind("<Configure>", lambda e: canvas_mod.itemconfig(canvas_window, width=e.width))

        def _on_wheel_mod(event):
            if canvas_mod.winfo_exists():
                canvas_mod.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas_mod.bind_all("<MouseWheel>", _on_wheel_mod)

        modulos = [
            ("🛡️ Firewall & Radar EDR", "Escudo activo en tiempo real, bloqueo automático de ataques, mapa global de amenazas y notificaciones.", lambda: self.cambiar_vista(self.modulo_firewall), RED),
            ("🍯 Anti-Ransomware & Canarios", "Trampa con archivos canario y detección inmediata de procesos de cifrado malicioso.", lambda: self.cambiar_vista(self.modulo_anti_ransomware), RED),
            ("💾 Diagnóstico & Control USB (DLP)", "Forense de unidades, vacuna autorun, desocultar archivos y control DLP (Solo Lectura/Bloqueo).", lambda: self.cambiar_vista(self.diagnostico_usb), YELLOW),
            ("🧬 Integridad de Archivos (FIM)", "Monitor de firmas SHA-256 de archivos clave de Windows y protección de archivo hosts.", lambda: self.cambiar_vista(self.modulo_fim), CYAN),
            ("🖥️ Diagnóstico General", "Análisis completo de hardware, SO, procesador, memoria, discos y alertas del sistema.", lambda: self.cambiar_vista(self.mostrar_diagnostico_general), GREEN),
            ("🌐 Estado de Red & C2", "Detección de tráfico malicioso, C2, botnets, beaconing, puertos abiertos y conexiones.", lambda: self.cambiar_vista(self.estado_red), CYAN),
            ("📦 Programas Instalados", "Inventario de software, hashes SHA256, comparación de firmas y análisis en VirusTotal.", lambda: self.cambiar_vista(self.programas_instalados), GREEN),
            ("⚡ Actividad del PC", "Gestor de procesos, análisis heurístico de riesgo, finalización y aislamiento EDR.", lambda: self.cambiar_vista(self.actividad_pc), CYAN),
            ("🛡️ Análisis Profundo", "Auditoría exhaustiva de 5 fases (memoria, persistencia, red, zonas críticas y posture).", lambda: self.cambiar_vista(self.analisis_profundo), RED),
            ("🧹 Optimizar PC", "Liberación de memoria RAM inactiva, vaciado de papelera y limpieza de temporales.", lambda: self.cambiar_vista(self.optimizar_pc), GREEN),
            ("📋 Seguridad, Logs & Anti-Phishing", "Auditoría EDR, eventos Windows, baúl de cuarentena y escudo anti-phishing DNS.", lambda: self.cambiar_vista(self.seguridad_logs), CYAN),
            ("⚡ Procesos Live", "Supervisión de procesos en tiempo real con medidores de carga, pausar y reanudar.", lambda: self.cambiar_vista(self.procesos_live), YELLOW),
            ("⚙️ Configuración & Actualizaciones", "Configuración de VirusTotal API, detector de actualizaciones en GitHub y opciones de la suite.", lambda: self.cambiar_vista(self.setting), TEXT),
        ]

        for idx, (titulo, desc, comando, color_accent) in enumerate(modulos):
            r = idx // 2
            c = idx % 2

            tile = tk.Frame(grid_frame, bg=PANEL, bd=1, relief="solid")
            tile.grid(row=r, column=c, padx=6, pady=5, sticky="nsew")
            grid_frame.grid_columnconfigure(c, weight=1)

            t_top = tk.Frame(tile, bg=PANEL)
            t_top.pack(fill="x", padx=14, pady=(10, 2))
            tk.Label(t_top, text=titulo, fg=color_accent, bg=PANEL, font=("Consolas", 11, "bold")).pack(side="left")

            tk.Label(tile, text=desc, fg=TEXT, bg=PANEL, font=("Consolas", 9), wraplength=460, justify="left").pack(anchor="w", padx=14, pady=(0, 8))

            btn = tk.Button(
                tile,
                text="Abrir Módulo ➔",
                bg=BTN,
                fg=color_accent,
                activebackground=color_accent,
                activeforeground="black",
                font=("Consolas", 9, "bold"),
                relief="flat",
                bd=1,
                padx=10,
                pady=3,
                cursor="hand2",
                command=comando
            )
            btn.pack(anchor="w", padx=14, pady=(0, 10))

    # ═════════════════════════════════════════════════════════════
    # MÓDULO: FIREWALL EDR, RADAR DE AMENAZAS & BLOQUEO
    # ═════════════════════════════════════════════════════════════
    def modulo_firewall(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("🛡️ FIREWALL EDR & RADAR DE AMENAZAS EN TIEMPO REAL", color=RED)

        cfg_fw = cargar_config_firewall()
        ataques_list = cargar_ataques()

        log_panel = tk.Frame(self.main_container, bg=BG)
        log_panel.pack(side="bottom", fill="x", padx=30, pady=(0, 10))

        # El panel expansible se empaqueta después del registro fijo, para que
        # Tk reserve correctamente el espacio de ambos al redimensionar.
        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=10)

        # ── 1. PANEL DE CONTROL Y CONFIGURACIÓN DEL FIREWALL (FIJO) ──
        ctrl_card = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        ctrl_card.pack(fill="x", pady=(0, 8))

        ctrl_top = tk.Frame(ctrl_card, bg=PANEL)
        ctrl_top.pack(fill="x", padx=15, pady=(8, 4))

        # Estado Toggle Activo/Inactivo
        var_activo = tk.BooleanVar(value=cfg_fw.get("activo", True))
        lbl_status_badge = tk.Label(
            ctrl_top,
            text="🟢 ESCUDO FIREWALL: ACTIVO Y BLOQUEANDO" if var_activo.get() else "🔴 ESCUDO FIREWALL: INACTIVO / PAUSADO",
            fg=GREEN if var_activo.get() else RED,
            bg="#162520" if var_activo.get() else "#2b1414",
            font=("Consolas", 10, "bold"),
            padx=10,
            pady=3,
            bd=1,
            relief="solid"
        )
        lbl_status_badge.pack(side="left")

        def toggle_firewall():
            estado = var_activo.get()
            cfg_fw["activo"] = estado
            guardar_config_firewall(cfg_fw)
            if estado:
                lbl_status_badge.config(
                    text="🟢 ESCUDO FIREWALL: ACTIVO Y BLOQUEANDO",
                    fg=GREEN,
                    bg="#162520"
                )
                chk_switch.config(text="✓ Firewall Activo", fg="#000000", bg=GREEN, selectcolor=GREEN)
                lbl_m_esc.config(text="PROTEGIDO", fg=GREEN)
            else:
                lbl_status_badge.config(
                    text="🔴 ESCUDO FIREWALL: INACTIVO / PAUSADO",
                    fg=RED,
                    bg="#2b1414"
                )
                chk_switch.config(text="✕ Firewall Inactivo", fg=TEXT_MUTED, bg=BTN, selectcolor=BG)
                lbl_m_esc.config(text="DESACTIVADO", fg=RED)

        chk_switch = tk.Checkbutton(
            ctrl_top,
            text="✓ Firewall Activo" if var_activo.get() else "✕ Firewall Inactivo",
            variable=var_activo,
            bg=GREEN if var_activo.get() else BTN,
            fg="#000000" if var_activo.get() else TEXT_MUTED,
            selectcolor=GREEN if var_activo.get() else BG,
            font=("Consolas", 9, "bold"),
            bd=1,
            relief="solid",
            padx=8,
            pady=2,
            cursor="hand2",
            command=toggle_firewall
        )
        chk_switch.pack(side="left", padx=15)

        # Botón de Prueba de Simulación de Ataque
        def accion_simular():
            simular_ataque_prueba()
            # El evento se agrega automáticamente en tiempo real a la tabla y mapa sin mostrar toast porque el usuario está en la pantalla del firewall

        tk.Button(
            ctrl_top,
            text="🧪 Simular Intento de Ataque",
            bg=BTN,
            fg=YELLOW,
            font=("Consolas", 9, "bold"),
            padx=10,
            pady=3,
            cursor="hand2",
            command=accion_simular
        ).pack(side="right")

        # Opciones secundarias de persistencia y notificaciones
        opts_frame = tk.Frame(ctrl_card, bg=PANEL)
        opts_frame.pack(fill="x", padx=15, pady=(0, 8))

        var_bg = tk.BooleanVar(value=cfg_fw.get("mantener_segundo_plano", True))
        var_block = tk.BooleanVar(value=cfg_fw.get("bloqueo_automatico", True))
        var_toast = tk.BooleanVar(value=cfg_fw.get("notificaciones_toast", True))

        def actualizar_opciones():
            cfg_fw["mantener_segundo_plano"] = var_bg.get()
            cfg_fw["bloqueo_automatico"] = var_block.get()
            cfg_fw["notificaciones_toast"] = var_toast.get()
            guardar_config_firewall(cfg_fw)
            configurar_persistencia_segundo_plano(var_bg.get())

        tk.Checkbutton(
            opts_frame,
            text="🛡️ Mantener activo al cerrar el programa",
            variable=var_bg,
            bg=PANEL,
            fg=TEXT,
            selectcolor=BG,
            activebackground=PANEL,
            activeforeground=GREEN,
            font=("Consolas", 9),
            command=actualizar_opciones
        ).pack(side="left", padx=(0, 10))

        tk.Checkbutton(
            opts_frame,
            text="🚫 Auto-bloquear atacantes en Firewall",
            variable=var_block,
            bg=PANEL,
            fg=TEXT,
            selectcolor=BG,
            activebackground=PANEL,
            activeforeground=GREEN,
            font=("Consolas", 9),
            command=actualizar_opciones
        ).pack(side="left", padx=10)

        tk.Checkbutton(
            opts_frame,
            text="🔔 Notificaciones tipo antivirus",
            variable=var_toast,
            bg=PANEL,
            fg=TEXT,
            selectcolor=BG,
            activebackground=PANEL,
            activeforeground=GREEN,
            font=("Consolas", 9),
            command=actualizar_opciones
        ).pack(side="left", padx=10)

        # ── 2. TARJETAS DE MÉTRICAS (FIJAS) ──
        metrics_bar = tk.Frame(cont, bg=BG)
        metrics_bar.pack(fill="x", pady=(0, 8))

        def crear_metric_fw(p, icon, tit, val, col):
            f = tk.Frame(p, bg=PANEL, bd=1, relief="solid")
            f.pack(side="left", fill="both", expand=True, padx=3)
            tk.Label(f, text=icon, fg=col, bg=PANEL, font=("Segoe UI Emoji", 13)).pack(anchor="w", padx=10, pady=(4, 0))
            tk.Label(f, text=tit, fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 8, "bold")).pack(anchor="w", padx=10)
            lbl = tk.Label(f, text=str(val), fg=col, bg=PANEL, font=("Consolas", 11, "bold"))
            lbl.pack(anchor="w", padx=10, pady=(0, 4))
            return lbl

        total_bloq = len(cfg_fw.get("ips_bloqueadas", []))
        lbl_m_tot = crear_metric_fw(metrics_bar, "🚨", "ATAQUES INTERCEPTADOS", len(ataques_list), RED if ataques_list else GREEN)
        lbl_m_ips = crear_metric_fw(metrics_bar, "🚫", "IPS BANEADAS", total_bloq, YELLOW)
        lbl_m_pts = crear_metric_fw(metrics_bar, "🔒", "PUERTOS PROTEGIDOS", "11 Sensores Activos", CYAN)
        lbl_m_esc = crear_metric_fw(metrics_bar, "🛡️", "ESTADO DEL ESCUDO", "PROTEGIDO" if var_activo.get() else "DESACTIVADO", GREEN if var_activo.get() else RED)

        # ── 3. RADAR WORLD MAP CANVAS (FIJO ARRIBA) ──
        map_container = tk.Frame(cont, bg=BG)
        map_container.pack(fill="both", expand=True, pady=(0, 8))

        threat_globe = ThreatGlobeCanvas(map_container, height=560, bg=BG)
        threat_globe.pack(fill="both", expand=True)
        threat_globe.actualizar_ataques(ataques_list)

        # ── 4. TABLA DE REGISTRO DE ATAQUES INTERCEPTADOS (SCROLL DEDICADO) ──
        tk.Label(log_panel, text="📋 REGISTRO DE ATAQUES, INTENCIONES Y RUTAS OBJETIVO INTERCEPTADAS:", fg=GREEN, bg=BG, font=("Consolas", 10, "bold")).pack(anchor="w", pady=(0, 3))

        tree_fw_frame = tk.Frame(log_panel, bg=PANEL, bd=1, relief="solid", height=175)
        tree_fw_frame.pack(fill="x")
        tree_fw_frame.pack_propagate(False)

        cols_fw = ("fecha", "ip", "pais", "vpn", "intencion", "ruta", "accion")
        scroll_fw_y = ttk.Scrollbar(tree_fw_frame, orient="vertical")
        scroll_fw_x = ttk.Scrollbar(tree_fw_frame, orient="horizontal")

        tabla_fw = ttk.Treeview(
            tree_fw_frame,
            columns=cols_fw,
            show="headings",
            yscrollcommand=scroll_fw_y.set,
            xscrollcommand=scroll_fw_x.set
        )
        scroll_fw_y.config(command=tabla_fw.yview)
        scroll_fw_x.config(command=tabla_fw.xview)

        scroll_fw_y.pack(side="right", fill="y")
        scroll_fw_x.pack(side="bottom", fill="x")
        tabla_fw.pack(side="left", fill="both", expand=True)

        tabla_fw.heading("fecha", text="Fecha / Hora")
        tabla_fw.heading("ip", text="IP Atacante")
        tabla_fw.heading("pais", text="País / Origen")
        tabla_fw.heading("vpn", text="Detección VPN / Origen")
        tabla_fw.heading("intencion", text="¿Qué Quería Hacer? (Intención)")
        tabla_fw.heading("ruta", text="Ruta / Puerto Objetivo")
        tabla_fw.heading("accion", text="Acción EDR")

        tabla_fw.column("fecha", width=135, anchor="center")
        tabla_fw.column("ip", width=125, anchor="center")
        tabla_fw.column("pais", width=130)
        tabla_fw.column("vpn", width=175)
        tabla_fw.column("intencion", width=300)
        tabla_fw.column("ruta", width=220)
        tabla_fw.column("accion", width=105, anchor="center")

        tabla_fw.tag_configure("CRÍTICO", foreground=RED)
        tabla_fw.tag_configure("ALTO", foreground=YELLOW)
        tabla_fw.tag_configure("MEDIO", foreground=TEXT)

        def recargar_datos_firewall():
            nonlocal ataques_list
            ataques_list = cargar_ataques()
            for item in tabla_fw.get_children():
                tabla_fw.delete(item)

            for a in ataques_list:
                sev = a.get("severidad", "MEDIO")
                vpn_desc = f"🛡️ {a.get('tipo_nodo', 'VPN/Proxy')}" if a.get("es_vpn") else "🌐 Directa (ISP)"
                tabla_fw.insert("", "end", values=(
                    a.get("fecha", ""),
                    a.get("ip", ""),
                    f"{a.get('codigo_pais', '')} - {a.get('pais', '')}",
                    vpn_desc,
                    a.get("intencion", ""),
                    a.get("ruta_objetivo", ""),
                    a.get("accion", "BLOQUEADO")
                ), tags=(sev,))

            threat_globe.actualizar_ataques(ataques_list)
            lbl_m_tot.config(text=str(len(ataques_list)))
            cfg_act = cargar_config_firewall()
            lbl_m_ips.config(text=str(len(cfg_act.get("ips_bloqueadas", []))))

        recargar_datos_firewall()

        # ── AUTO-ACTUALIZACIÓN EN TIEMPO REAL DESDE EL MOTOR DE DETECCIÓN ──
        def _agregar_evento_live(evento):
            if not tabla_fw.winfo_exists():
                return
            sev = evento.get("severidad", "MEDIO")
            vpn_desc = f"🛡️ {evento.get('tipo_nodo', 'VPN/Proxy')}" if evento.get("es_vpn") else "🌐 Directa (ISP)"
            tabla_fw.insert("", 0, values=(
                evento.get("fecha", ""),
                evento.get("ip", ""),
                f"{evento.get('codigo_pais', '')} - {evento.get('pais', '')}",
                vpn_desc,
                evento.get("intencion", ""),
                evento.get("ruta_objetivo", ""),
                evento.get("accion", "BLOQUEADO")
            ), tags=(sev,))

            children = tabla_fw.get_children()
            if len(children) > 200:
                tabla_fw.delete(children[-1])

            threat_globe.actualizar_ataques(cargar_ataques())
            lbl_m_tot.config(text=str(len(cargar_ataques())))
            lbl_m_ips.config(text=str(len(cargar_config_firewall().get("ips_bloqueadas", []))))

        def on_live_threat_event(evento):
            if self.winfo_exists() and tabla_fw.winfo_exists():
                self.after(0, lambda: _agregar_evento_live(evento))

        # Suscribir callback en vivo
        suscribir_evento_ataque(on_live_threat_event)

        # Bucle de sincronización periódica automática (polling en vivo cada 1.2 seg)
        ultimo_conteo = len(ataques_list)

        def auto_sync_firewall_live():
            nonlocal ultimo_conteo
            if not self.winfo_exists() or self.vista_actual != self.modulo_firewall or not tabla_fw.winfo_exists():
                desuscribir_evento_ataque(on_live_threat_event)
                return

            actuales = cargar_ataques()
            if len(actuales) != ultimo_conteo:
                ultimo_conteo = len(actuales)
                recargar_datos_firewall()

            self.after(1200, auto_sync_firewall_live)

        auto_sync_firewall_live()

        def on_attack_double_click(e):
            sel = tabla_fw.selection()
            if not sel:
                return
            vals = tabla_fw.item(sel[0])["values"]
            ip_sel = vals[1]
            atq_obj = None
            for at in cargar_ataques():
                if at.get("ip") == ip_sel:
                    atq_obj = at
                    break

            if atq_obj:
                msg_txt = f"{atq_obj.get('intencion')}\nObjetivo: {atq_obj.get('ruta_objetivo')}\n\n{atq_obj.get('rastreo_forense', '')}"
                self.mostrar_detalle_amenaza({
                    "tipo": f"Intrusión ({atq_obj.get('tipo_nodo', 'Red')})",
                    "nivel": atq_obj.get("severidad", "CRÍTICO"),
                    "mensaje": msg_txt,
                    "ip": ip_sel,
                    "ruta": atq_obj.get("ruta_objetivo")
                }, volver_a=self.modulo_firewall)

        def on_table_select(e):
            sel = tabla_fw.selection()
            if not sel:
                return
            vals = tabla_fw.item(sel[0])["values"]
            if len(vals) > 1:
                ip_sel = vals[1]
                threat_globe.seleccionar_ataque_por_ip(ip_sel)

        tabla_fw.bind("<<TreeviewSelect>>", on_table_select)
        tabla_fw.bind("<Double-1>", on_attack_double_click)

        # ── 5. BARRA DE ACCIONES INFERIOR (FIJA) ──
        act_fw = tk.Frame(log_panel, bg=BG)
        act_fw.pack(fill="x", pady=(8, 0))

        def accion_abrir_maps_sel():
            sel = tabla_fw.selection()
            if not sel:
                messagebox.showwarning("Selección", "Selecciona una fila de la tabla para ver su ubicación en Google Maps.")
                return
            ip_sel = tabla_fw.item(sel[0])["values"][1]
            for at in cargar_ataques():
                if at.get("ip") == ip_sel:
                    lat = at.get("lat", 40.4168)
                    lon = at.get("lon", -3.7038)
                    webbrowser.open(f"https://www.google.com/maps/search/?api=1&query={lat},{lon}")
                    return
            webbrowser.open(f"https://www.google.com/maps/search/?api=1&query={ip_sel}")

        def accion_abrir_streetview_sel():
            sel = tabla_fw.selection()
            if not sel:
                messagebox.showwarning("Selección", "Selecciona una fila de la tabla para abrir Street View.")
                return
            ip_sel = tabla_fw.item(sel[0])["values"][1]
            for at in cargar_ataques():
                if at.get("ip") == ip_sel:
                    lat = at.get("lat", 40.4168)
                    lon = at.get("lon", -3.7038)
                    webbrowser.open(f"https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat},{lon}")
                    return
            webbrowser.open(f"https://www.google.com/maps/search/?api=1&query={ip_sel}")

        def accion_desbloquear_sel():
            sel = tabla_fw.selection()
            if not sel:
                messagebox.showwarning("Selección", "Selecciona una fila de la tabla para desbloquear su IP.")
                return
            ip_sel = tabla_fw.item(sel[0])["values"][1]
            if messagebox.askyesno("Desbloquear IP", f"¿Deseas desbloquear la IP {ip_sel} del Firewall de Windows?"):
                ok, msg = desbloquear_ip_firewall(ip_sel)
                if ok:
                    messagebox.showinfo("Firewall", msg)
                    recargar_datos_firewall()
                else:
                    messagebox.showerror("Error", msg)

        def accion_limpiar_historial():
            if messagebox.askyesno("Limpiar Historial", "¿Deseas borrar el registro de ataques del Firewall?"):
                guardar_ataques([])
                recargar_datos_firewall()

        tk.Button(act_fw, text="🗺️ Abrir en Google Maps", bg=BTN, fg=CYAN, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_abrir_maps_sel).pack(side="left", padx=(0, 6))
        tk.Button(act_fw, text="👁️ Street View 360°", bg=BTN, fg="#ff00d4", font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_abrir_streetview_sel).pack(side="left", padx=6)
        tk.Button(act_fw, text="🚫 Desbloquear IP", bg=BTN, fg=YELLOW, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_desbloquear_sel).pack(side="left", padx=6)
        tk.Button(act_fw, text="🧹 Limpiar Historial", bg=BTN, fg=RED, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_limpiar_historial).pack(side="left", padx=6)
        tk.Button(act_fw, text="🔄 Actualizar", bg=BTN, fg=GREEN, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=recargar_datos_firewall).pack(side="right")

    # ═════════════════════════════════════════════════════════════
    # MÓDULO: TRAMPA ANTI-RANSOMWARE & ARCHIVOS CANARIO
    # ═════════════════════════════════════════════════════════════
    def modulo_anti_ransomware(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("🍯 TRAMPA ANTI-RANSOMWARE & ARCHIVOS CANARIO", color=RED)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=12)

        info_card = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        info_card.pack(fill="x", pady=(0, 10))

        tk.Label(info_card, text="🛡️ PROTECCIÓN ACTIVA CONTRA RANSOMWARE (HONEYPOT TRAPS)", fg=RED, bg=PANEL, font=("Consolas", 12, "bold")).pack(anchor="w", padx=15, pady=(10, 3))
        tk.Label(info_card, text="Despliega archivos señuelo con firmas criptográficas conocidas en Documentos, Escritorio y Descargas. Si un malware o ransomware intenta cifrar o alterar estos archivos, el EDR liquida el proceso en milisegundos y aísla el binario.", fg=TEXT, bg=PANEL, font=("Consolas", 9), wraplength=850, justify="left").pack(anchor="w", padx=15, pady=(0, 10))

        # Barra de métricas
        m_frame = tk.Frame(cont, bg=BG)
        m_frame.pack(fill="x", pady=(0, 10))

        def metric_box(p, icon, tit, val, col):
            f = tk.Frame(p, bg=PANEL, bd=1, relief="solid")
            f.pack(side="left", fill="both", expand=True, padx=3)
            tk.Label(f, text=icon, fg=col, bg=PANEL, font=("Segoe UI Emoji", 13)).pack(anchor="w", padx=10, pady=(4, 0))
            tk.Label(f, text=tit, fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 8, "bold")).pack(anchor="w", padx=10)
            lbl = tk.Label(f, text=str(val), fg=col, bg=PANEL, font=("Consolas", 11, "bold"))
            lbl.pack(anchor="w", padx=10, pady=(0, 4))
            return lbl

        metric_box(m_frame, "🟢", "ESTADO DEL GUARDIÁN", "VIGILANDO EN TIEMPO REAL", GREEN)
        metric_box(m_frame, "📁", "ZONAS PROTEGIDAS", "Documentos, Desktop, Downloads", CYAN)
        metric_box(m_frame, "⚡", "TIEMPO DE REACCIÓN", "< 800 ms (Instantáneo)", YELLOW)

        # Tabla de archivos canario
        tk.Label(cont, text="📋 ARCHIVOS SEÑUELO ACTIVOS EN EL ENDPOINT:", fg=GREEN, bg=BG, font=("Consolas", 10, "bold")).pack(anchor="w", pady=(0, 4))

        tree_f = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        tree_f.pack(fill="both", expand=True)

        cols = ("archivo", "tipo", "ubicacion", "estado")
        scroll_y = ttk.Scrollbar(tree_f, orient="vertical")
        tabla_can = ttk.Treeview(tree_f, columns=cols, show="headings", yscrollcommand=scroll_y.set)
        scroll_y.config(command=tabla_can.yview)
        scroll_y.pack(side="right", fill="y")
        tabla_can.pack(side="left", fill="both", expand=True)

        tabla_can.heading("archivo", text="Archivo Canario")
        tabla_can.heading("tipo", text="Tipo / Extensión")
        tabla_can.heading("ubicacion", text="Ruta de Protección")
        tabla_can.heading("estado", text="Integridad")

        tabla_can.column("archivo", width=220)
        tabla_can.column("tipo", width=120, anchor="center")
        tabla_can.column("ubicacion", width=420)
        tabla_can.column("estado", width=120, anchor="center")

        def recargar_canarios():
            for item in tabla_can.get_children():
                tabla_can.delete(item)

            carpetas = [
                ("Documentos", os.path.expandvars(r"%USERPROFILE%\Documents")),
                ("Escritorio", os.path.expandvars(r"%USERPROFILE%\Desktop")),
                ("Descargas", os.path.expandvars(r"%USERPROFILE%\Downloads"))
            ]
            for nombre_carp, carp in carpetas:
                if os.path.exists(carp):
                    for fname in ["00_passwords_vault_decoy.docx", "00_financial_budget_backup.xlsx", "00_confidential_contracts.pdf"]:
                        full_p = os.path.join(carp, fname)
                        existe = os.path.exists(full_p)
                        ext = os.path.splitext(fname)[1].upper()
                        tabla_can.insert("", "end", values=(
                            fname,
                            ext,
                            full_p,
                            "🟢 ACTIVO / ÍNTEGRO" if existe else "🟡 PENDIENTE"
                        ))

        recargar_canarios()

        # Barra de acciones
        act_bar = tk.Frame(cont, bg=BG)
        act_bar.pack(fill="x", pady=(10, 0))

        def accion_desplegar():
            n = desplegar_senuelos()
            reproducir_bloqueo_exitoso()
            messagebox.showinfo("Trampas Anti-Ransomware", f"✅ Se han desplegado y verificado {n} archivos canario con éxito.")
            recargar_canarios()

        def accion_simular_ransom():
            if messagebox.askyesno("Prueba Anti-Ransomware", "⚠️ ¿Deseas simular una alteración en un archivo canario para probar la reacción del guardián EDR?"):
                rutas = [os.path.join(os.path.expandvars(r"%USERPROFILE%\Documents"), "00_passwords_vault_decoy.docx")]
                for r in rutas:
                    if os.path.exists(r):
                        with open(r, "a") as f:
                            f.write("\nENCRYPTED_SIMULATION_FLAG")
                messagebox.showinfo("Simulación Ejecutada", "Se modificó un archivo canario. El guardián EDR debería detectar la anomalía y re-desplegar la protección.")
                recargar_canarios()

        tk.Button(act_bar, text="🍯 Desplegar / Refrescar Trampas", bg=BTN, fg=GREEN, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_desplegar).pack(side="left", padx=(0, 6))
        tk.Button(act_bar, text="🧪 Probar Reacción EDR (Simulación)", bg=BTN, fg=YELLOW, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_simular_ransom).pack(side="left", padx=6)
        tk.Button(act_bar, text="🔄 Actualizar Estado", bg=BTN, fg=CYAN, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=recargar_canarios).pack(side="right")

    # ═════════════════════════════════════════════════════════════
    # MÓDULO: MONITOR DE INTEGRIDAD DE ARCHIVOS (FIM)
    # ═════════════════════════════════════════════════════════════
    def modulo_fim(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("🧬 MONITOR DE INTEGRIDAD DE ARCHIVOS (FIM)", color=CYAN)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=12)

        info_card = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        info_card.pack(fill="x", pady=(0, 10))

        tk.Label(info_card, text="🛡️ AUDITORÍA DE FIRMAS SHA-256 DE BINARIOS Y ARCHIVOS DEL SISTEMA", fg=CYAN, bg=PANEL, font=("Consolas", 12, "bold")).pack(anchor="w", padx=15, pady=(10, 3))
        tk.Label(info_card, text="Supervisa continuamente la integridad criptográfica de componentes vitales de Windows (hosts, DLLs de sistema, cmd, powershell) para detectar manipulaciones, secuestro de DNS o inyecciones de código.", fg=TEXT, bg=PANEL, font=("Consolas", 9), wraplength=850, justify="left").pack(anchor="w", padx=15, pady=(0, 10))

        tree_f = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        tree_f.pack(fill="both", expand=True)

        cols = ("archivo", "estado", "nivel", "ruta", "detalle")
        scroll_y = ttk.Scrollbar(tree_f, orient="vertical")
        tabla_fim = ttk.Treeview(tree_f, columns=cols, show="headings", yscrollcommand=scroll_y.set)
        scroll_y.config(command=tabla_fim.yview)
        scroll_y.pack(side="right", fill="y")
        tabla_fim.pack(side="left", fill="both", expand=True)

        tabla_fim.heading("archivo", text="Archivo")
        tabla_fim.heading("estado", text="Estado de Integridad")
        tabla_fim.heading("nivel", text="Nivel")
        tabla_fim.heading("ruta", text="Ruta en Disco")
        tabla_fim.heading("detalle", text="Diagnóstico")

        tabla_fim.column("archivo", width=160)
        tabla_fim.column("estado", width=170, anchor="center")
        tabla_fim.column("nivel", width=90, anchor="center")
        tabla_fim.column("ruta", width=340)
        tabla_fim.column("detalle", width=260)

        tabla_fim.tag_configure("CRÍTICO", foreground=RED)
        tabla_fim.tag_configure("SEGURO", foreground=GREEN)
        tabla_fim.tag_configure("INFO", foreground=TEXT)

        def recargar_fim():
            for item in tabla_fim.get_children():
                tabla_fim.delete(item)

            res = auditar_integridad_archivos()
            for r in res:
                tabla_fim.insert("", "end", values=(
                    r["archivo"],
                    r["estado"],
                    r["nivel"],
                    r["ruta"],
                    r["detalle"]
                ), tags=(r["nivel"],))

        recargar_fim()

        act_bar = tk.Frame(cont, bg=BG)
        act_bar.pack(fill="x", pady=(10, 0))

        def accion_crear_base():
            ok, msg = crear_linea_base_fim()
            if ok:
                reproducir_bloqueo_exitoso()
                messagebox.showinfo("Línea Base FIM", msg)
                recargar_fim()
            else:
                messagebox.showerror("Error", msg)

        def accion_restaurar_hosts():
            if messagebox.askyesno("Restaurar Hosts", "¿Deseas restaurar el archivo hosts de Windows a su configuración limpia original?"):
                ok, msg = restaurar_archivo_hosts_limpio()
                if ok:
                    reproducir_sonido_exito()
                    messagebox.showinfo("Archivo Hosts", msg)
                    recargar_fim()
                else:
                    messagebox.showerror("Error", msg)

        tk.Button(act_bar, text="💾 Crear / Actualizar Línea Base", bg=BTN, fg=GREEN, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_crear_base).pack(side="left", padx=(0, 6))
        tk.Button(act_bar, text="♻️ Restaurar Archivo Hosts Limpio", bg=BTN, fg=YELLOW, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_restaurar_hosts).pack(side="left", padx=6)
        tk.Button(act_bar, text="🔍 Re-Auditar Integridad", bg=BTN, fg=CYAN, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=recargar_fim).pack(side="right")

    # ═════════════════════════════════════════════════════════════
    # MÓDULO 1: DIAGNÓSTICO GENERAL DEL SISTEMA
    # ═════════════════════════════════════════════════════════════
    def mostrar_diagnostico_general(self):
        self.establecer_cabecera_fija("🖥️ DIAGNÓSTICO GENERAL DEL SISTEMA", color=GREEN)
        self.escaneo_diagnostico(self._mostrar_resultado_diagnostico)

    def escaneo_diagnostico(self, callback_final):
        self.limpiar_contenido()

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(expand=True, pady=40)

        tk.Label(cont, text="🔍 EJECUTANDO DIAGNÓSTICO...", fg=GREEN, bg=BG, font=("Consolas", 16, "bold")).pack(pady=20)

        estado = tk.Label(cont, text="Inicializando sensores...", fg=TEXT, bg=BG, font=("Consolas", 12))
        estado.pack(pady=10)

        scan_canvas = tk.Canvas(cont, width=500, height=60, bg=BG, highlightthickness=0)
        scan_canvas.pack(pady=15)

        binario = scan_canvas.create_text(250, 30, text="010101010101001010101010101010101010", fill=GREEN, font=("Consolas", 15))
        lupa = scan_canvas.create_oval(0, 15, 30, 45, outline=CYAN, width=2)
        mango = scan_canvas.create_line(25, 40, 40, 55, fill=CYAN, width=3)

        fases = [
            ("Recolectando información del SO...", 15),
            ("Analizando métricas de CPU y núcleos...", 35),
            ("Evaluando uso de memoria RAM y Swap...", 55),
            ("Examinando particiones de almacenamiento...", 75),
            ("Auditando interfaces de red y socket...", 90),
            ("Finalizando diagnóstico...", 100)
        ]

        def animar_lupa(x=0, direccion=1):
            if not scan_canvas.winfo_exists():
                return
            if x >= 460:
                direccion = -1
            elif x <= 0:
                direccion = 1

            dx = 6 * direccion
            scan_canvas.move(lupa, dx, 0)
            scan_canvas.move(mango, dx, 0)

            nuevo = "".join("1" if i % 2 == (x // 20) % 2 else "0" for i in range(36))
            scan_canvas.itemconfig(binario, text=nuevo)
            self.after(35, animar_lupa, x + dx, direccion)

        def avanzar(i=0):
            if not estado.winfo_exists():
                return
            if i < len(fases):
                estado.config(text=fases[i][0])
                self.after(350, avanzar, i + 1)
            else:
                callback_final()

        animar_lupa()
        avanzar()

    def _mostrar_resultado_diagnostico(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("🖥️ DIAGNÓSTICO GENERAL DEL SISTEMA", color=GREEN)

        data = diagnostico_general()
        alertas = evaluar_alertas(data)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=15)

        if alertas:
            box = tk.Frame(cont, bg="#201010", bd=1, relief="solid")
            box.pack(fill="x", pady=(0, 12))
            tk.Label(box, text="⚠ ALERTAS DEL SISTEMA", fg=RED, bg="#201010", font=("Consolas", 12, "bold")).pack(anchor="w", padx=15, pady=5)
            for tipo, nivel, msg in alertas:
                color = RED if nivel == "CRÍTICO" else YELLOW
                icon = "🔴" if nivel == "CRÍTICO" else "🟡"
                tk.Label(box, text=f"{icon} [{nivel}] {tipo}: {msg}", fg=color, bg="#201010", font=("Consolas", 9)).pack(anchor="w", padx=25, pady=2)
        else:
            ok = tk.Frame(cont, bg="#0d1f15", bd=1, relief="solid")
            ok.pack(fill="x", pady=(0, 12))
            tk.Label(ok, text="🟢 Sistema estable — Sin anomalías de hardware o recursos detectadas", fg=GREEN, bg="#0d1f15", font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=6)

        # Cuadro de resultados con scroll interno si fuera necesario
        scroll_res_frame = tk.Frame(cont, bg=BG)
        scroll_res_frame.pack(fill="both", expand=True)

        canvas_diag = tk.Canvas(scroll_res_frame, bg=BG, highlightthickness=0)
        scroll_diag = ttk.Scrollbar(scroll_res_frame, orient="vertical", command=canvas_diag.yview)
        scroll_diag.pack(side="right", fill="y")
        canvas_diag.pack(side="left", fill="both", expand=True)

        libro = tk.Frame(canvas_diag, bg=BG)
        canvas_win = canvas_diag.create_window((0, 0), window=libro, anchor="nw")
        canvas_diag.configure(yscrollcommand=scroll_diag.set)

        libro.bind("<Configure>", lambda e: canvas_diag.configure(scrollregion=canvas_diag.bbox("all")))
        canvas_diag.bind("<Configure>", lambda e: canvas_diag.itemconfig(canvas_win, width=e.width))

        def _on_wheel_diag(event):
            if canvas_diag.winfo_exists():
                canvas_diag.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas_diag.bind_all("<MouseWheel>", _on_wheel_diag)

        izq = tk.Frame(libro, bg=PANEL, bd=1, relief="solid")
        der = tk.Frame(libro, bg=PANEL, bd=1, relief="solid")
        izq.pack(side="left", fill="both", expand=True, padx=(0, 6))
        der.pack(side="right", fill="both", expand=True, padx=(6, 0))

        def seccion_titulo(p, t):
            tk.Label(p, text=t, fg=GREEN, bg=PANEL, font=("Consolas", 12, "bold")).pack(anchor="w", padx=15, pady=(10, 4))

        def linea_dato(p, label, val):
            f = tk.Frame(p, bg=PANEL)
            f.pack(fill="x", padx=15, pady=2)
            tk.Label(f, text=f"{label}:", fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 9, "bold"), width=16, anchor="w").pack(side="left")
            tk.Label(f, text=str(val), fg=TEXT, bg=PANEL, font=("Consolas", 9), anchor="w").pack(side="left")

        seccion_titulo(izq, "🖥️ Sistema Operativo")
        s = data["sistema"]
        linea_dato(izq, "Sistema", s['os'])
        linea_dato(izq, "Versión", s['version'])
        linea_dato(izq, "Arquitectura", s['arquitectura'])
        linea_dato(izq, "Usuario Activo", s['usuario'])
        linea_dato(izq, "Hostname", s['hostname'])
        linea_dato(izq, "Tiempo Activo", f"{s['uptime_horas']} horas")

        seccion_titulo(izq, "⚙️ Procesador (CPU)")
        cpu = data["cpu"]
        linea_dato(izq, "Núcleos Físicos", cpu['nucleos_fisicos'])
        linea_dato(izq, "Núcleos Lógicos", cpu['nucleos_logicos'])
        linea_dato(izq, "Frecuencia", f"{cpu['frecuencia_mhz']} MHz")
        linea_dato(izq, "Carga de Trabajo", f"{cpu['uso']} %")

        seccion_titulo(izq, "🧠 Memoria RAM")
        ram = data["ram"]
        linea_dato(izq, "Total", f"{ram['total_gb']} GB")
        linea_dato(izq, "En Uso", f"{ram['usada_gb']} GB ({ram['uso']} %)")
        linea_dato(izq, "Disponible", f"{ram['libre_gb']} GB")

        seccion_titulo(der, "💾 Unidades de Disco")
        for d in data["discos"]:
            linea_dato(der, f"Unidad {d['dispositivo']}", f"{d['total_gb']} GB ({d['uso']}% usado)")

        seccion_titulo(der, "🌐 Interfaces de Red")
        for r in data["red"][:4]:
            linea_dato(der, r['interfaz'], r['ip'])

        seccion_titulo(der, "📊 Top Procesos por CPU")
        for proc in data["procesos"]["top_cpu"]:
            try:
                linea_dato(der, proc.info['name'][:20], f"{proc.info['cpu_percent']}% CPU")
            except Exception:
                pass

    # ═════════════════════════════════════════════════════════════
    # MÓDULO 2: ESTADO DE RED, C2 Y COMUNICACIONES
    # ═════════════════════════════════════════════════════════════
    def estado_red(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("🌐 ESTADO DE RED, C2 Y CONEXIONES EXTERNAS", color=GREEN)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=15)

        lbl_cargando = tk.Label(cont, text="Analizando tráfico, sockets y anomalías de red...", fg=YELLOW, bg=BG, font=("Consolas", 11))
        lbl_cargando.pack(pady=20)
        self.update_idletasks()

        data = estado_red_completo()
        lbl_cargando.destroy()

        alertas = data.get("alertas", [])
        if alertas:
            box_alertas = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
            box_alertas.pack(fill="x", pady=(0, 12))

            criticos = [a for a in alertas if a.get("nivel") == "CRÍTICO"]
            medios = [a for a in alertas if a.get("nivel") != "CRÍTICO"]

            tk.Label(box_alertas, text=f"🚨 ALERTAS DE RED DETECTADAS ({len(alertas)})", fg=RED if criticos else YELLOW, bg=PANEL, font=("Consolas", 12, "bold")).pack(anchor="w", padx=15, pady=(8, 4))

            alert_btns = tk.Frame(box_alertas, bg=PANEL)
            alert_btns.pack(anchor="w", padx=15, pady=(0, 8))

            if criticos:
                tk.Button(
                    alert_btns,
                    text=f"🔴 {len(criticos)} Amenazas Críticas / C2",
                    bg=BTN,
                    fg=RED,
                    font=("Consolas", 9, "bold"),
                    cursor="hand2",
                    command=lambda: self.mostrar_alertas_por_nivel(criticos, "CRÍTICO")
                ).pack(side="left", padx=(0, 8))

            if medios:
                tk.Button(
                    alert_btns,
                    text=f"🟡 {len(medios)} Conexiones Externas / Advertencias",
                    bg=BTN,
                    fg=YELLOW,
                    font=("Consolas", 9, "bold"),
                    cursor="hand2",
                    command=lambda: self.mostrar_alertas_por_nivel(medios, "MEDIO")
                ).pack(side="left")

        # Contenedor de telemetría de red con scroll interno
        scroll_telemetria = tk.Frame(cont, bg=BG)
        scroll_telemetria.pack(fill="both", expand=True)

        canvas_net = tk.Canvas(scroll_telemetria, bg=BG, highlightthickness=0)
        scroll_net = ttk.Scrollbar(scroll_telemetria, orient="vertical", command=canvas_net.yview)
        scroll_net.pack(side="right", fill="y")
        canvas_net.pack(side="left", fill="both", expand=True)

        telemetria = tk.Frame(canvas_net, bg=BG)
        canvas_net_win = canvas_net.create_window((0, 0), window=telemetria, anchor="nw")
        canvas_net.configure(yscrollcommand=scroll_net.set)

        telemetria.bind("<Configure>", lambda e: canvas_net.configure(scrollregion=canvas_net.bbox("all")))
        canvas_net.bind("<Configure>", lambda e: canvas_net.itemconfig(canvas_net_win, width=e.width))

        def _on_wheel_net(event):
            if canvas_net.winfo_exists():
                canvas_net.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas_net.bind_all("<MouseWheel>", _on_wheel_net)

        col_izq = tk.Frame(telemetria, bg=PANEL, bd=1, relief="solid")
        col_der = tk.Frame(telemetria, bg=PANEL, bd=1, relief="solid")
        col_izq.pack(side="left", fill="both", expand=True, padx=(0, 6))
        col_der.pack(side="right", fill="both", expand=True, padx=(6, 0))

        tk.Label(col_izq, text="🧩 Interfaces de Red", fg=GREEN, bg=PANEL, font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(10, 4))
        for i in data.get("interfaces", []):
            color_if = GREEN if i.get("estado") == "UP" else TEXT_MUTED
            tk.Label(col_izq, text=f"• {i['interfaz']}: {i['ip'] or 'Sin IP'} [{i['estado']}]", fg=color_if, bg=PANEL, font=("Consolas", 9)).pack(anchor="w", padx=20, pady=1)

        tk.Label(col_izq, text="🌍 IP Pública & Puerta de Enlace", fg=GREEN, bg=PANEL, font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(12, 4))
        tk.Label(col_izq, text=f"• IP Pública: {data.get('ip_publica', 'N/A')}", fg=CYAN, bg=PANEL, font=("Consolas", 9)).pack(anchor="w", padx=20, pady=1)
        tk.Label(col_izq, text=f"• Gateway: {data.get('dns_gateway', {}).get('gateway', 'N/A')}", fg=TEXT, bg=PANEL, font=("Consolas", 9)).pack(anchor="w", padx=20, pady=1)

        tk.Label(col_der, text="🔓 Puertos Escuchando (Listen)", fg=GREEN, bg=PANEL, font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(10, 4))
        for p in data.get("puertos_abiertos", [])[:8]:
            tk.Label(col_der, text=f"• {p['local']} | PID: {p['pid'] or 'N/A'}", fg=TEXT, bg=PANEL, font=("Consolas", 9)).pack(anchor="w", padx=20, pady=1)

        tk.Label(col_der, text="🔗 Conexiones Activas (Top Remotas)", fg=GREEN, bg=PANEL, font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(12, 4))
        for c in data.get("conexiones", [])[:8]:
            if c.get("remoto"):
                tk.Label(col_der, text=f"• {c['local']} ➔ {c['remoto']} ({c['estado']})", fg=CYAN, bg=PANEL, font=("Consolas", 9)).pack(anchor="w", padx=20, pady=1)

    def mostrar_alertas_por_nivel(self, alertas, nivel):
        self.limpiar_contenido()
        color_h = RED if nivel == "CRÍTICO" else YELLOW
        self.establecer_cabecera_fija(f"🚨 LISTADO DE ALERTAS - {nivel}", color=color_h, callback_volver=self.estado_red)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=15)

        # Cuadro de alertas con scroll interno
        scroll_alertas_frame = tk.Frame(cont, bg=BG)
        scroll_alertas_frame.pack(fill="both", expand=True)

        canvas_alt = tk.Canvas(scroll_alertas_frame, bg=BG, highlightthickness=0)
        scroll_alt = ttk.Scrollbar(scroll_alertas_frame, orient="vertical", command=canvas_alt.yview)
        scroll_alt.pack(side="right", fill="y")
        canvas_alt.pack(side="left", fill="both", expand=True)

        lista_frame = tk.Frame(canvas_alt, bg=BG)
        canvas_alt_win = canvas_alt.create_window((0, 0), window=lista_frame, anchor="nw")
        canvas_alt.configure(yscrollcommand=scroll_alt.set)

        lista_frame.bind("<Configure>", lambda e: canvas_alt.configure(scrollregion=canvas_alt.bbox("all")))
        canvas_alt.bind("<Configure>", lambda e: canvas_alt.itemconfig(canvas_alt_win, width=e.width))

        def _on_wheel_alt(event):
            if canvas_alt.winfo_exists():
                canvas_alt.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas_alt.bind_all("<MouseWheel>", _on_wheel_alt)

        for alerta in alertas:
            fila = tk.Frame(lista_frame, bg=PANEL, bd=1, relief="solid")
            fila.pack(fill="x", pady=4)

            tipo = alerta.get("tipo", "Alerta")
            msg = alerta.get("mensaje", "")
            pid = alerta.get("pid")
            ip = alerta.get("ip")

            info_text = f"[{tipo}] {msg}"
            if pid:
                info_text += f" | PID: {pid}"
            if ip:
                info_text += f" | IP: {ip}"

            tk.Label(fila, text=info_text, fg=TEXT, bg=PANEL, font=("Consolas", 10), wraplength=750, justify="left").pack(side="left", padx=15, pady=8)

            tk.Button(
                fila,
                text="🛡️ Acciones EDR",
                bg=BTN,
                fg=GREEN,
                font=("Consolas", 9, "bold"),
                cursor="hand2",
                command=lambda a=alerta: self.mostrar_detalle_amenaza(a, volver_a=lambda: self.mostrar_alertas_por_nivel(alertas, nivel))
            ).pack(side="right", padx=15, pady=8)

    # ═════════════════════════════════════════════════════════════
    # MÓDULO 3: PROGRAMAS INSTALADOS
    # ═════════════════════════════════════════════════════════════
    def programas_instalados(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("📦 INVENTARIO DE SOFTWARE INSTALADO", color=GREEN)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=15)

        header = tk.Frame(cont, bg=BG)
        header.pack(fill="x", pady=(0, 10))

        tk.Label(header, text="Software detectado en el Registro de Windows:", fg=TEXT, bg=BG, font=("Consolas", 11)).pack(side="left")

        search_frame = tk.Frame(header, bg=BG)
        search_frame.pack(side="right")
        tk.Label(search_frame, text="Buscar:", fg=TEXT_MUTED, bg=BG, font=("Consolas", 10)).pack(side="left", padx=4)
        var_search = tk.StringVar()
        ent_search = tk.Entry(search_frame, textvariable=var_search, bg=PANEL, fg=TEXT, insertbackground=GREEN, font=("Consolas", 10), width=25)
        ent_search.pack(side="left", padx=4)

        # Contenedor de la tabla con scrollbar dedicado (SOLO la tabla se desplaza)
        tree_container = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        tree_container.pack(fill="both", expand=True)

        cols = ("nombre", "version", "editor", "tipo", "riesgo")
        scroll_y = ttk.Scrollbar(tree_container, orient="vertical")
        scroll_x = ttk.Scrollbar(tree_container, orient="horizontal")

        tabla = ttk.Treeview(
            tree_container,
            columns=cols,
            show="headings",
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set
        )
        scroll_y.config(command=tabla.yview)
        scroll_x.config(command=tabla.xview)

        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        tabla.pack(side="left", fill="both", expand=True)

        tabla.heading("nombre", text="Nombre del Programa")
        tabla.heading("version", text="Versión")
        tabla.heading("editor", text="Editor / Desarrollador")
        tabla.heading("tipo", text="Tipo")
        tabla.heading("riesgo", text="Nivel de Riesgo")

        tabla.column("nombre", width=380)
        tabla.column("version", width=120, anchor="center")
        tabla.column("editor", width=220)
        tabla.column("tipo", width=80, anchor="center")
        tabla.column("riesgo", width=120, anchor="center")

        software_list = obtener_programas_instalados()

        def poblar_tabla(filtro=""):
            for item in tabla.get_children():
                tabla.delete(item)

            filtro = filtro.lower()
            for sw in software_list:
                nombre = sw.get("nombre", "")
                editor = sw.get("editor", "")
                if filtro and (filtro not in nombre.lower() and filtro not in editor.lower()):
                    continue

                riesgo = self.calcular_riesgo_software(sw)
                tag = "alto" if riesgo == "ALTO" else ("medio" if riesgo == "MEDIO" else "bajo")

                tabla.insert("", "end", values=(
                    nombre,
                    sw.get("version", "N/A"),
                    editor or "Desconocido",
                    sw.get("tipo", "EXE"),
                    riesgo
                ), tags=(tag,))

        tabla.tag_configure("alto", foreground=RED)
        tabla.tag_configure("medio", foreground=YELLOW)
        tabla.tag_configure("bajo", foreground=TEXT)

        var_search.trace_add("write", lambda *args: poblar_tabla(var_search.get()))
        poblar_tabla()

        def on_select(event):
            sel = tabla.selection()
            if not sel:
                return
            nombre_sel = tabla.item(sel[0])["values"][0]
            for sw in software_list:
                if sw.get("nombre") == nombre_sel:
                    self.mostrar_detalle_software(sw)
                    break

        tabla.bind("<Double-1>", on_select)
        tk.Label(cont, text="💡 Haz doble clic sobre cualquier software para inspeccionar hash, analizar en VirusTotal o desinstalar.", fg=TEXT_MUTED, bg=BG, font=("Consolas", 9)).pack(anchor="w", pady=(8, 0))

    def calcular_riesgo_software(self, software):
        nombre = software.get("nombre", "").lower()
        editor = software.get("editor", "").lower()
        ruta = software.get("ruta", "").lower()

        palabras_riesgo = ["crack", "patch", "keygen", "hack", "activator", "loader", "cheat", "spoofer"]
        if any(p in nombre or p in ruta or p in editor for p in palabras_riesgo):
            return "ALTO"
        if not editor or editor == "desconocido":
            return "MEDIO"
        return "BAJO"

    # ═════════════════════════════════════════════════════════════
    # MÓDULO 4: ACTIVIDAD DEL PC / GESTOR DE PROCESOS
    # ═════════════════════════════════════════════════════════════
    def actividad_pc(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("⚡ ACTIVIDAD DE PROCESOS EN EJECUCIÓN", color=GREEN)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=15)

        header = tk.Frame(cont, bg=BG)
        header.pack(fill="x", pady=(0, 10))

        tk.Label(header, text="Procesos activos del sistema:", fg=TEXT, bg=BG, font=("Consolas", 11)).pack(side="left")

        search_frame = tk.Frame(header, bg=BG)
        search_frame.pack(side="right")
        tk.Label(search_frame, text="Filtrar:", fg=TEXT_MUTED, bg=BG, font=("Consolas", 10)).pack(side="left", padx=4)
        var_proc_search = tk.StringVar()
        ent_proc = tk.Entry(search_frame, textvariable=var_proc_search, bg=PANEL, fg=TEXT, insertbackground=GREEN, font=("Consolas", 10), width=22)
        ent_proc.pack(side="left", padx=4)

        # Cuadro de resultados de actividad (donde SOLO funciona el scroll)
        tree_container = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        tree_container.pack(fill="both", expand=True)

        cols = ("pid", "nombre", "usuario", "cpu", "ram", "riesgo", "ruta")
        scroll_y = ttk.Scrollbar(tree_container, orient="vertical")
        scroll_x = ttk.Scrollbar(tree_container, orient="horizontal")

        tabla = ttk.Treeview(
            tree_container,
            columns=cols,
            show="headings",
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set
        )
        scroll_y.config(command=tabla.yview)
        scroll_x.config(command=tabla.xview)

        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        tabla.pack(side="left", fill="both", expand=True)

        tabla.heading("pid", text="PID")
        tabla.heading("nombre", text="Proceso")
        tabla.heading("usuario", text="Usuario")
        tabla.heading("cpu", text="CPU %")
        tabla.heading("ram", text="RAM (MB)")
        tabla.heading("riesgo", text="Riesgo")
        tabla.heading("ruta", text="Ruta del Ejecutable")

        tabla.column("pid", width=70, anchor="center")
        tabla.column("nombre", width=190)
        tabla.column("usuario", width=120)
        tabla.column("cpu", width=75, anchor="center")
        tabla.column("ram", width=95, anchor="center")
        tabla.column("riesgo", width=85, anchor="center")
        tabla.column("ruta", width=420)

        tabla.tag_configure("ALTO", foreground=RED)
        tabla.tag_configure("MEDIO", foreground=YELLOW)
        tabla.tag_configure("BAJO", foreground=TEXT)

        lista_procesos = []

        def cargar_procesos(filtro=""):
            nonlocal lista_procesos
            for item in tabla.get_children():
                tabla.delete(item)

            lista_procesos = obtener_procesos_activos()
            filtro = filtro.lower()

            for p in lista_procesos:
                nombre = p.get("nombre", "")
                pid = str(p.get("pid", ""))
                if filtro and (filtro not in nombre.lower() and filtro not in pid):
                    continue

                riesgo = calcular_riesgo_proceso(p)
                tabla.insert("", "end", values=(
                    p["pid"],
                    nombre,
                    p["usuario"] or "SYSTEM",
                    f"{p['cpu']}%",
                    f"{p['ram']:.1f}",
                    riesgo,
                    p["ruta"] or "N/A"
                ), tags=(riesgo,))

        var_proc_search.trace_add("write", lambda *args: cargar_procesos(var_proc_search.get()))
        cargar_procesos()

        actions_bar = tk.Frame(cont, bg=BG)
        actions_bar.pack(fill="x", pady=(12, 0))

        def get_selected_proc():
            sel = tabla.selection()
            if not sel:
                messagebox.showwarning("Selección", "Selecciona primero un proceso de la tabla.")
                return None
            vals = tabla.item(sel[0])["values"]
            return {"pid": vals[0], "nombre": vals[1], "ruta": vals[6]}

        def accion_matar():
            sp = get_selected_proc()
            if sp:
                if messagebox.askyesno("Confirmar", f"¿Deseas finalizar el proceso {sp['nombre']} (PID {sp['pid']})?"):
                    ok, msg = matar_proceso(sp['pid'])
                    registrar_accion_edr("FINALIZAR_PROCESO", f"PID: {sp['pid']}, Proceso: {sp['nombre']}", nivel="ALTO", exito=ok)
                    if ok:
                        messagebox.showinfo("EDR", msg)
                        cargar_procesos(var_proc_search.get())
                    else:
                        messagebox.showerror("Error", msg)

        def accion_aislar():
            sp = get_selected_proc()
            if sp:
                ok, msg = aislar_proceso(sp['pid'])
                registrar_accion_edr("AISLAR_PROCESO", f"PID: {sp['pid']}, Proceso: {sp['nombre']}", nivel="ALTO", exito=ok)
                if ok:
                    messagebox.showinfo("EDR", msg)
                else:
                    messagebox.showerror("Error", msg)

        def accion_vt():
            sp = get_selected_proc()
            if sp and sp['ruta'] and os.path.isfile(sp['ruta']):
                self.analizar_vt_software({"nombre": sp["nombre"], "ruta": sp["ruta"]})
            else:
                messagebox.showwarning("VirusTotal", "No se puede analizar: la ruta del archivo no es accesible.")

        tk.Button(actions_bar, text="⛔ Finalizar Proceso", bg=BTN, fg=RED, font=("Consolas", 10, "bold"), padx=10, pady=5, cursor="hand2", command=accion_matar).pack(side="left", padx=(0, 6))
        tk.Button(actions_bar, text="🧊 Aislar de Red", bg=BTN, fg=YELLOW, font=("Consolas", 10, "bold"), padx=10, pady=5, cursor="hand2", command=accion_aislar).pack(side="left", padx=6)
        tk.Button(actions_bar, text="🌐 Analizar en VirusTotal", bg=BTN, fg=CYAN, font=("Consolas", 10, "bold"), padx=10, pady=5, cursor="hand2", command=accion_vt).pack(side="left", padx=6)
        tk.Button(actions_bar, text="🔄 Actualizar Lista", bg=BTN, fg=GREEN, font=("Consolas", 10, "bold"), padx=10, pady=5, cursor="hand2", command=lambda: cargar_procesos(var_proc_search.get())).pack(side="right")

    # ═════════════════════════════════════════════════════════════
    # MÓDULO: DIAGNÓSTICO & CONTROL DE SEGURIDAD USB (DLP)
    # ═════════════════════════════════════════════════════════════
    def diagnostico_usb(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("💾 DIAGNÓSTICO & CONTROL DE SEGURIDAD USB (DLP)", color=YELLOW)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=12)

        # ── 1. PANEL DE CONTROL DE POLÍTICAS DLP DE SEGURIDAD USB ──
        dlp_card = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        dlp_card.pack(fill="x", pady=(0, 10))

        dlp_top = tk.Frame(dlp_card, bg=PANEL)
        dlp_top.pack(fill="x", padx=15, pady=(8, 4))
        tk.Label(dlp_top, text="🔒 CONTROL DE PUERTOS & POLÍTICAS DLP (PREVENCIÓN DE FUGA DE DATOS):", fg=YELLOW, bg=PANEL, font=("Consolas", 10, "bold")).pack(side="left")

        pol_actual = obtener_politica_usb()
        var_modo_usb = tk.StringVar(value=pol_actual)

        f_radios = tk.Frame(dlp_card, bg=PANEL)
        f_radios.pack(fill="x", padx=15, pady=(0, 8))

        opciones_dlp = [
            ("permitido", "🟢 Permitido Estándar"),
            ("solo_lectura", "🔒 Solo Lectura (Anti-Fuga DLP)"),
            ("bloqueado", "⛔ Bloqueo Total USB")
        ]

        for val, tit in opciones_dlp:
            tk.Radiobutton(
                f_radios,
                text=tit,
                variable=var_modo_usb,
                value=val,
                bg=PANEL,
                fg=TEXT,
                selectcolor=BG,
                activebackground=PANEL,
                activeforeground=GREEN,
                font=("Consolas", 9, "bold")
            ).pack(side="left", padx=(0, 15))

        def accion_aplicar_dlp():
            modo_sel = var_modo_usb.get()
            ok, msg = establecer_politica_usb(modo_sel)
            if ok:
                messagebox.showinfo("Política USB DLP", msg)
            else:
                messagebox.showerror("Error", msg)

        tk.Button(
            f_radios,
            text="💾 Aplicar Política DLP",
            bg=BTN,
            fg=GREEN,
            font=("Consolas", 9, "bold"),
            padx=10,
            pady=2,
            cursor="hand2",
            command=accion_aplicar_dlp
        ).pack(side="right")

        # ── 2. ANÁLISIS FORENSE DE DISPOSITIVOS EXTRAÍBLES ──
        unidades = detectar_unidades_usb()

        if not unidades:
            no_usb = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
            no_usb.pack(fill="x", pady=10)
            tk.Label(no_usb, text="🔌 NO SE DETECTARON DISPOSITIVOS USB CONECTADOS", fg=YELLOW, bg=PANEL, font=("Consolas", 12, "bold")).pack(anchor="w", padx=15, pady=(12, 3))
            tk.Label(no_usb, text="Conecta una memoria USB o disco extraíble y presiona 'Escanear Unidades' para realizar el análisis forense.", fg=TEXT, bg=PANEL, font=("Consolas", 10)).pack(anchor="w", padx=15, pady=(0, 10))
            tk.Button(no_usb, text="🔄 Volver a Escanear Unidades", bg=BTN, fg=GREEN, font=("Consolas", 10, "bold"), padx=12, pady=5, cursor="hand2", command=self.diagnostico_usb).pack(anchor="w", padx=15, pady=(0, 12))
            return

        sel_frame = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        sel_frame.pack(fill="x", pady=(0, 10))

        tk.Label(sel_frame, text="Dispositivos Extraíbles Detectados para Análisis Forense:", fg=GREEN, bg=PANEL, font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(8, 4))

        var_unidad = tk.StringVar(value=unidades[0]["letra"])
        for u in unidades:
            r = tk.Radiobutton(
                sel_frame,
                text=f"Unidad {u['letra']} ({u['sistema_archivos']}) - {u['total_gb']} GB ({u['libre_gb']} GB Libres)",
                variable=var_unidad,
                value=u["letra"],
                bg=PANEL,
                fg=TEXT,
                selectcolor=BG,
                activebackground=PANEL,
                activeforeground=GREEN,
                font=("Consolas", 10)
            )
            r.pack(anchor="w", padx=20, pady=2)

        res_frame = tk.Frame(cont, bg=BG)
        res_frame.pack(fill="both", expand=True)

        def ejecutar_analisis():
            for w in res_frame.winfo_children():
                w.destroy()

            letra = var_unidad.get()
            lbl_wait = tk.Label(res_frame, text=f"Escaneando unidad {letra} en busca de autorun, accesos directos maliciosos y binarios ocultos...", fg=YELLOW, bg=BG, font=("Consolas", 11))
            lbl_wait.pack(pady=12)
            self.update_idletasks()

            analisis = analizar_unidad_usb(letra)
            lbl_wait.destroy()

            if "error" in analisis:
                messagebox.showerror("Error", analisis["error"])
                return

            status_box = tk.Frame(res_frame, bg=PANEL, bd=1, relief="solid")
            status_box.pack(fill="x", pady=(0, 8))

            color_riesgo = GREEN if analisis["criticos"] == 0 and analisis["medios"] == 0 else (RED if analisis["criticos"] > 0 else YELLOW)
            tk.Label(status_box, text=f"ESTADO DE LA UNIDAD: {analisis['riesgo_general']}", fg=color_riesgo, bg=PANEL, font=("Consolas", 12, "bold")).pack(anchor="w", padx=15, pady=(8, 2))
            tk.Label(status_box, text=f"Total Archivos Analizados: {analisis['total_archivos']} | Amenazas Críticas: {analisis['criticos']} | Advertencias: {analisis['medios']}", fg=TEXT, bg=PANEL, font=("Consolas", 9)).pack(anchor="w", padx=15, pady=(0, 8))

            if analisis["sospechosos"]:
                tk.Label(res_frame, text="🚨 ARTEFACTOS SOSPECHOSOS DETECTADOS EN USB:", fg=RED, bg=BG, font=("Consolas", 11, "bold")).pack(anchor="w", pady=(4, 4))

                tree_usb_frame = tk.Frame(res_frame, bg=PANEL, bd=1, relief="solid")
                tree_usb_frame.pack(fill="both", expand=True)

                cols_usb = ("tipo", "nivel", "archivo", "tamano")
                scroll_usb = ttk.Scrollbar(tree_usb_frame, orient="vertical")
                tabla_usb = ttk.Treeview(tree_usb_frame, columns=cols_usb, show="headings", yscrollcommand=scroll_usb.set)
                scroll_usb.config(command=tabla_usb.yview)
                scroll_usb.pack(side="right", fill="y")
                tabla_usb.pack(side="left", fill="both", expand=True)

                tabla_usb.heading("tipo", text="Tipo de Amenaza")
                tabla_usb.heading("nivel", text="Nivel")
                tabla_usb.heading("archivo", text="Ruta en USB")
                tabla_usb.heading("tamano", text="Tamaño (Bytes)")

                tabla_usb.column("tipo", width=220)
                tabla_usb.column("nivel", width=90, anchor="center")
                tabla_usb.column("archivo", width=480)
                tabla_usb.column("tamano", width=120, anchor="center")

                tabla_usb.tag_configure("CRÍTICO", foreground=RED)
                tabla_usb.tag_configure("MEDIO", foreground=YELLOW)

                for item in analisis["sospechosos"]:
                    tabla_usb.insert("", "end", values=(
                        item["tipo"],
                        item["nivel"],
                        item["archivo"],
                        item["tamano"]
                    ), tags=(item["nivel"],))

            usb_actions = tk.Frame(res_frame, bg=BG)
            usb_actions.pack(fill="x", pady=(10, 0))

            def accion_vacunar():
                ok, msg = vacunar_usb(letra)
                registrar_accion_edr("VACUNAR_USB", f"Unidad: {letra}", nivel="INFO", exito=ok)
                if ok:
                    messagebox.showinfo("Inmunización USB", msg)
                else:
                    messagebox.showerror("Error", msg)

            def accion_desocultar():
                ok, msg = desocultar_archivos_usb(letra)
                registrar_accion_edr("DESOCULTAR_USB", f"Unidad: {letra}", nivel="INFO", exito=ok)
                if ok:
                    messagebox.showinfo("Desocultar Archivos", msg)
                    ejecutar_analisis()
                else:
                    messagebox.showerror("Error", msg)

            def accion_limpiar():
                if not analisis["sospechosos"]:
                    messagebox.showinfo("Limpieza", "No hay amenazas pendientes de limpiar en esta unidad.")
                    return
                if messagebox.askyesno("Confirmar Cuarentena", f"¿Deseas enviar los {len(analisis['sospechosos'])} archivos sospechosos a la cuarentena de CyberAnalyzer?"):
                    exitos, fallos = limpiar_amenazas_usb(analisis["sospechosos"])
                    registrar_accion_edr("CUARENTENA_USB", f"Unidad: {letra}, {exitos} aislados, {fallos} fallidos", nivel="ALTO", exito=True)
                    messagebox.showinfo("Limpieza Completada", f"{exitos} artefactos movidos a cuarentena.")
                    ejecutar_analisis()

            def accion_expulsar():
                ok, msg = expulsar_usb(letra)
                if ok:
                    messagebox.showinfo("Expulsar", msg)
                    self.diagnostico_usb()
                else:
                    messagebox.showerror("Error", msg)

            tk.Button(usb_actions, text="💉 Inmunizar / Vacunar USB", bg=BTN, fg=GREEN, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_vacunar).pack(side="left", padx=(0, 6))
            tk.Button(usb_actions, text="👁️ Desocultar Archivos", bg=BTN, fg=CYAN, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_desocultar).pack(side="left", padx=6)
            tk.Button(usb_actions, text="🧹 Enviar Amenazas a Cuarentena", bg=BTN, fg=RED, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_limpiar).pack(side="left", padx=6)
            tk.Button(usb_actions, text="⏏️ Expulsar de Forma Segura", bg=BTN, fg=TEXT, font=("Consolas", 9, "bold"), padx=10, pady=4, cursor="hand2", command=accion_expulsar).pack(side="right")

        tk.Button(sel_frame, text="🔍 Analizar Unidad Seleccionada", bg=BTN, fg=GREEN, font=("Consolas", 10, "bold"), padx=14, pady=5, cursor="hand2", command=ejecutar_analisis).pack(anchor="w", padx=15, pady=(8, 12))

    # ═════════════════════════════════════════════════════════════
    # MÓDULO 6: ANÁLISIS PROFUNDO EDR (FULL THREAT SCAN)
    # ═════════════════════════════════════════════════════════════
    def analisis_profundo(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("🛡️ ANÁLISIS PROFUNDO DE AMENAZAS (EDR)", color=RED)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=15)

        scan_box = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        scan_box.pack(fill="x", pady=(0, 10))

        tk.Label(scan_box, text="Auditoría Integral de 5 Fases del Endpoint:", fg=CYAN, bg=PANEL, font=("Consolas", 11, "bold")).pack(anchor="w", padx=20, pady=(10, 4))
        fases_desc = (
            "1. Memoria RAM y Procesos Activos (suplantaciones y anomalías)\n"
            "2. Persistencia y Registro de Windows (Run keys, tareas programadas y servicios)\n"
            "3. Red, Puertos y Archivo Hosts (C2, sockets sospechosos y DNS hijacking)\n"
            "4. Zonas Críticas del Sistema (AppData, Temp, scripts y dobles extensiones)\n"
            "5. Postura de Seguridad de Windows (Firewall y control de cuentas UAC)"
        )
        tk.Label(scan_box, text=fases_desc, fg=TEXT, bg=PANEL, font=("Consolas", 9), justify="left").pack(anchor="w", padx=20, pady=(0, 8))

        prog_frame = tk.Frame(scan_box, bg=PANEL)
        prog_frame.pack(fill="x", padx=20, pady=(0, 12))

        lbl_fase = tk.Label(prog_frame, text="Listo para iniciar análisis...", fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 9))
        lbl_fase.pack(anchor="w", pady=(0, 4))

        prog_bar = ttk.Progressbar(prog_frame, mode="determinate", length=500)
        prog_bar.pack(fill="x", pady=(0, 8))

        btn_iniciar = tk.Button(prog_frame, text="🚀 Iniciar Análisis Profundo", bg=BTN, fg=GREEN, font=("Consolas", 10, "bold"), padx=12, pady=5, cursor="hand2")
        btn_iniciar.pack(anchor="w")

        res_cont = tk.Frame(cont, bg=BG)
        res_cont.pack(fill="both", expand=True)

        def ejecutar_scan_hilo():
            btn_iniciar.config(state="disabled")

            def callback_progreso(texto, valor):
                self.after(0, lambda: (lbl_fase.config(text=texto), prog_bar.config(value=valor)))

            def run():
                resultado = ejecutar_analisis_profundo(callback_fase=callback_progreso)
                self.after(0, lambda: mostrar_reporte_profundo(resultado))

            threading.Thread(target=run, daemon=True).start()

        btn_iniciar.config(command=ejecutar_scan_hilo)

        def mostrar_reporte_profundo(res):
            btn_iniciar.config(state="normal")
            for w in res_cont.winfo_children():
                w.destroy()

            score_card = tk.Frame(res_cont, bg=PANEL, bd=1, relief="solid")
            score_card.pack(fill="x", pady=(0, 10))

            sc_left = tk.Frame(score_card, bg=PANEL)
            sc_left.pack(side="left", padx=20, pady=10)
            tk.Label(sc_left, text="PUNTAJE DE SALUD Y SEGURIDAD", fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 9, "bold")).pack(anchor="w")
            tk.Label(sc_left, text=f"{res['score']} / 100", fg=res['color_estado'], bg=PANEL, font=("Consolas", 22, "bold")).pack(anchor="w")
            tk.Label(sc_left, text=f"Estado del Endpoint: {res['estado_global']}", fg=res['color_estado'], bg=PANEL, font=("Consolas", 10, "bold")).pack(anchor="w")

            sc_right = tk.Frame(score_card, bg=PANEL)
            sc_right.pack(side="right", padx=20, pady=10)
            tk.Label(sc_right, text=f"🔴 Hallazgos Críticos: {res['criticos']}", fg=RED, bg=PANEL, font=("Consolas", 10, "bold")).pack(anchor="e")
            tk.Label(sc_right, text=f"🟡 Advertencias / Medios: {res['medios']}", fg=YELLOW, bg=PANEL, font=("Consolas", 10, "bold")).pack(anchor="e")
            tk.Label(sc_right, text=f"Total Hallazgos: {res['total_hallazgos']}", fg=TEXT, bg=PANEL, font=("Consolas", 9)).pack(anchor="e")

            if res['hallazgos']:
                tk.Label(res_cont, text="📋 DETALLE DE VULNERABILIDADES Y AMENAZAS ENCONTRADAS:", fg=GREEN, bg=BG, font=("Consolas", 11, "bold")).pack(anchor="w", pady=(0, 4))

                tree_deep_frame = tk.Frame(res_cont, bg=PANEL, bd=1, relief="solid")
                tree_deep_frame.pack(fill="both", expand=True)

                cols = ("fase", "nivel", "tipo", "mensaje")
                scroll_deep = ttk.Scrollbar(tree_deep_frame, orient="vertical")
                tabla_res = ttk.Treeview(tree_deep_frame, columns=cols, show="headings", yscrollcommand=scroll_deep.set)
                scroll_deep.config(command=tabla_res.yview)
                scroll_deep.pack(side="right", fill="y")
                tabla_res.pack(side="left", fill="both", expand=True)

                tabla_res.heading("fase", text="Fase")
                tabla_res.heading("nivel", text="Nivel")
                tabla_res.heading("tipo", text="Categoría")
                tabla_res.heading("mensaje", text="Descripción del Hallazgo")

                tabla_res.column("fase", width=180)
                tabla_res.column("nivel", width=90, anchor="center")
                tabla_res.column("tipo", width=220)
                tabla_res.column("mensaje", width=500)

                tabla_res.tag_configure("CRÍTICO", foreground=RED)
                tabla_res.tag_configure("MEDIO", foreground=YELLOW)

                for h in res['hallazgos']:
                    tabla_res.insert("", "end", values=(
                        h.get("fase", "Sistema"),
                        h.get("nivel", "INFO"),
                        h.get("tipo", "Hallazgo"),
                        h.get("mensaje", "")
                    ), tags=(h.get("nivel", "INFO"),))

                def on_hallazgo_click(e):
                    sel = tabla_res.selection()
                    if not sel:
                        return
                    idx = tabla_res.index(sel[0])
                    if idx < len(res['hallazgos']):
                        self.mostrar_detalle_amenaza(res['hallazgos'][idx], volver_a=None)

                tabla_res.bind("<Double-1>", on_hallazgo_click)
                tk.Label(res_cont, text="💡 Haz doble clic en cualquier fila para abrir el panel de remediación y acciones EDR.", fg=TEXT_MUTED, bg=BG, font=("Consolas", 9)).pack(anchor="w", pady=(4, 0))
            else:
                ok_box = tk.Frame(res_cont, bg="#0d1f15", bd=1, relief="solid")
                ok_box.pack(fill="x", pady=8)
                tk.Label(ok_box, text="🟢 ¡Excelente! No se detectaron amenazas, persistencias ni puertos peligrosos en el sistema.", fg=GREEN, bg="#0d1f15", font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=10)

    # ═════════════════════════════════════════════════════════════
    # MÓDULO 7: OPTIMIZACIÓN Y LIMPIEZA DE RENDIMIENTO
    # ═════════════════════════════════════════════════════════════
    def optimizar_pc(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("🧹 OPTIMIZACIÓN DEL SISTEMA Y RENDIMIENTO", color=GREEN)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=15)

        top_cards = tk.Frame(cont, bg=BG)
        top_cards.pack(fill="x", pady=(0, 12))

        c_ram = tk.Frame(top_cards, bg=PANEL, bd=1, relief="solid")
        c_ram.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(c_ram, text="🧠 Optimizar Memoria RAM", fg=GREEN, bg=PANEL, font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(10, 2))
        tk.Label(c_ram, text="Limpia páginas inactivas y working sets en memoria para acelerar el sistema.", fg=TEXT, bg=PANEL, font=("Consolas", 9), wraplength=260, justify="left").pack(anchor="w", padx=15, pady=(0, 8))

        def ejecutar_opt_ram():
            res = optimizar_ram()
            registrar_accion_edr("OPTIMIZAR_RAM", f"Liberados {res['mb_liberados']} MB en {res['procesos_optimizados']} procesos", nivel="INFO", exito=True)
            messagebox.showinfo(
                "Memoria Optimizada",
                f"✅ Se optimizaron {res['procesos_optimizados']} procesos.\n"
                f"Memoria liberada: {res['mb_liberados']} MB\n"
                f"Uso de RAM actual: {res['ram_despues_porc']}% ({res['ram_libre_gb']} GB Libres)"
            )

        tk.Button(c_ram, text="⚡ Liberar RAM Ahora", bg=BTN, fg=CYAN, font=("Consolas", 9, "bold"), cursor="hand2", command=ejecutar_opt_ram).pack(anchor="w", padx=15, pady=(0, 10))

        c_trash = tk.Frame(top_cards, bg=PANEL, bd=1, relief="solid")
        c_trash.pack(side="left", fill="both", expand=True, padx=4)
        tk.Label(c_trash, text="🗑️ Papelera de Reciclaje", fg=YELLOW, bg=PANEL, font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(10, 2))
        tk.Label(c_trash, text="Vacía de forma permanente los archivos eliminados en todas las unidades.", fg=TEXT, bg=PANEL, font=("Consolas", 9), wraplength=260, justify="left").pack(anchor="w", padx=15, pady=(0, 8))

        def ejecutar_vaciar_pap():
            if messagebox.askyesno("Confirmar", "¿Deseas vaciar la papelera de reciclaje?"):
                ok, msg = vaciar_papelera()
                if ok:
                    messagebox.showinfo("Papelera", msg)
                else:
                    messagebox.showerror("Error", msg)

        tk.Button(c_trash, text="🗑️ Vaciar Papelera", bg=BTN, fg=YELLOW, font=("Consolas", 9, "bold"), cursor="hand2", command=ejecutar_vaciar_pap).pack(anchor="w", padx=15, pady=(0, 10))

        analisis_limp = analizar_espacio_limpieza()

        limp_box = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        limp_box.pack(fill="both", expand=True)

        tk.Label(limp_box, text=f"📂 Limpieza de Archivos Temporales y Caché (Recuperable: {analisis_limp['total_mb']} MB)", fg=GREEN, bg=PANEL, font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(10, 4))

        # Botones de Selección Rápida
        sel_btns_frame = tk.Frame(limp_box, bg=PANEL)
        sel_btns_frame.pack(fill="x", padx=15, pady=(0, 8))

        vars_check = {}
        chk_widgets = {}

        def actualizar_color_chk(cat_id):
            chk = chk_widgets.get(cat_id)
            if not chk or not chk.winfo_exists():
                return
            if vars_check[cat_id].get():
                chk.config(
                    bg=GREEN,
                    fg="#000000",
                    selectcolor=GREEN,
                    activebackground=GREEN,
                    activeforeground="#000000"
                )
            else:
                chk.config(
                    bg=BTN,
                    fg=TEXT,
                    selectcolor=BG,
                    activebackground=BTN_HOVER,
                    activeforeground=TEXT
                )

        def toggle_todos(estado=True):
            for cat_id, var in vars_check.items():
                var.set(estado)
                actualizar_color_chk(cat_id)

        tk.Button(sel_btns_frame, text="✓ Seleccionar Todos", bg=BTN, fg=GREEN, font=("Consolas", 9, "bold"), padx=8, pady=2, cursor="hand2", command=lambda: toggle_todos(True)).pack(side="left", padx=(0, 8))
        tk.Button(sel_btns_frame, text="✗ Deseleccionar Todos", bg=BTN, fg=TEXT_MUTED, font=("Consolas", 9), padx=8, pady=2, cursor="hand2", command=lambda: toggle_todos(False)).pack(side="left")

        # Contenedor con scroll para categorías (SOLO las categorías se desplazan si son muchas)
        cat_scroll_frame = tk.Frame(limp_box, bg=PANEL)
        cat_scroll_frame.pack(fill="both", expand=True, padx=15, pady=(0, 6))

        canvas_limp = tk.Canvas(cat_scroll_frame, bg=PANEL, highlightthickness=0)
        scroll_limp = ttk.Scrollbar(cat_scroll_frame, orient="vertical", command=canvas_limp.yview)
        scroll_limp.pack(side="right", fill="y")
        canvas_limp.pack(side="left", fill="both", expand=True)

        chk_container = tk.Frame(canvas_limp, bg=PANEL)
        canvas_limp_win = canvas_limp.create_window((0, 0), window=chk_container, anchor="nw")
        canvas_limp.configure(yscrollcommand=scroll_limp.set)

        chk_container.bind("<Configure>", lambda e: canvas_limp.configure(scrollregion=canvas_limp.bbox("all")))
        canvas_limp.bind("<Configure>", lambda e: canvas_limp.itemconfig(canvas_limp_win, width=e.width))

        def _on_wheel_limp(event):
            if canvas_limp.winfo_exists():
                canvas_limp.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas_limp.bind_all("<MouseWheel>", _on_wheel_limp)

        for cat in analisis_limp["categorias"]:
            if cat["existe"]:
                cid = cat["id"]
                f_chk = tk.Frame(chk_container, bg=PANEL)
                f_chk.pack(fill="x", pady=2)
                v = tk.BooleanVar(value=True)
                vars_check[cid] = v

                chk = tk.Checkbutton(
                    f_chk,
                    text=f" {cat['nombre']}",
                    variable=v,
                    bg=GREEN,
                    fg="#000000",
                    selectcolor=GREEN,
                    activebackground=GREEN,
                    activeforeground="#000000",
                    font=("Consolas", 9, "bold"),
                    padx=6,
                    pady=2,
                    bd=1,
                    relief="solid",
                    cursor="hand2",
                    command=lambda c=cid: actualizar_color_chk(c)
                )
                chk.pack(side="left")
                chk_widgets[cid] = chk

                tk.Label(f_chk, text=f"{cat['mb']} MB ({cat['archivos']} archivos)", fg=CYAN, bg=PANEL, font=("Consolas", 9, "bold")).pack(side="right", padx=10)

        def accion_limpiar_temporales():
            ids_sel = [cid for cid, v in vars_check.items() if v.get()]
            if not ids_sel:
                messagebox.showwarning("Selección", "Selecciona al menos una categoría para limpiar.")
                return

            res = ejecutar_limpieza(ids_sel)
            registrar_accion_edr("LIMPIEZA_DISCO", f"Liberados {res['mb_liberados']} MB, {res['archivos_eliminados']} archivos borrados", nivel="INFO", exito=True)
            messagebox.showinfo(
                "Limpieza Finalizada",
                f"✅ Se liberaron {res['mb_liberados']} MB.\n"
                f"Archivos eliminados: {res['archivos_eliminados']}\n"
                f"Errores (archivos en uso): {res['errores']}"
            )
            self.optimizar_pc()

        tk.Button(
            limp_box,
            text="🧹 Limpiar Archivos Seleccionados",
            bg=BTN,
            fg=GREEN,
            font=("Consolas", 10, "bold"),
            padx=14,
            pady=5,
            cursor="hand2",
            command=accion_limpiar_temporales
        ).pack(anchor="w", padx=15, pady=(6, 12))

    # ═════════════════════════════════════════════════════════════
    # MÓDULO 8: SEGURIDAD, AUDITORÍA Y BAÚL DE CUARENTENA
    # ═════════════════════════════════════════════════════════════
    def seguridad_logs(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("📋 AUDITORÍA EDR, EVENTOS DE WINDOWS Y CUARENTENA", color=CYAN)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=15)

        tab_container = tk.Frame(cont, bg=BG)
        tab_container.pack(fill="both", expand=True)

        notebook = ttk.Notebook(tab_container)
        notebook.pack(fill="both", expand=True)

        # Tab 1: EDR
        tab_edr = tk.Frame(notebook, bg=PANEL)
        notebook.add(tab_edr, text="🛡️ Auditoría EDR Interna")

        t_frame_edr = tk.Frame(tab_edr, bg=PANEL)
        t_frame_edr.pack(fill="both", expand=True, padx=8, pady=8)

        cols_edr = ("fecha", "accion", "nivel", "resultado", "detalle")
        scroll_edr = ttk.Scrollbar(t_frame_edr, orient="vertical")
        tabla_edr = ttk.Treeview(t_frame_edr, columns=cols_edr, show="headings", yscrollcommand=scroll_edr.set)
        scroll_edr.config(command=tabla_edr.yview)

        scroll_edr.pack(side="right", fill="y")
        tabla_edr.pack(side="left", fill="both", expand=True)

        tabla_edr.heading("fecha", text="Fecha / Hora")
        tabla_edr.heading("accion", text="Acción Ejecutada")
        tabla_edr.heading("nivel", text="Severidad")
        tabla_edr.heading("resultado", text="Resultado")
        tabla_edr.heading("detalle", text="Detalle de Operación")

        tabla_edr.column("fecha", width=160)
        tabla_edr.column("accion", width=180)
        tabla_edr.column("nivel", width=90, anchor="center")
        tabla_edr.column("resultado", width=100, anchor="center")
        tabla_edr.column("detalle", width=420)

        for reg in obtener_historial_edr():
            tabla_edr.insert("", "end", values=(
                reg.get("fecha", ""),
                reg.get("accion", ""),
                reg.get("nivel", "INFO"),
                reg.get("resultado", "OK"),
                reg.get("detalle", "")
            ))

        # Tab 2: Windows
        tab_win = tk.Frame(notebook, bg=PANEL)
        notebook.add(tab_win, text="🪟 Logs de Seguridad de Windows")

        t_frame_win = tk.Frame(tab_win, bg=PANEL)
        t_frame_win.pack(fill="both", expand=True, padx=8, pady=8)

        cols_win = ("id", "nombre", "categoria", "nivel", "fecha", "usuario")
        scroll_win = ttk.Scrollbar(t_frame_win, orient="vertical")
        tabla_win = ttk.Treeview(t_frame_win, columns=cols_win, show="headings", yscrollcommand=scroll_win.set)
        scroll_win.config(command=tabla_win.yview)

        scroll_win.pack(side="right", fill="y")
        tabla_win.pack(side="left", fill="both", expand=True)

        tabla_win.heading("id", text="Event ID")
        tabla_win.heading("nombre", text="Descripción del Evento")
        tabla_win.heading("categoria", text="Categoría")
        tabla_win.heading("nivel", text="Nivel")
        tabla_win.heading("fecha", text="Fecha")
        tabla_win.heading("usuario", text="Usuario")

        tabla_win.column("id", width=80, anchor="center")
        tabla_win.column("nombre", width=280)
        tabla_win.column("categoria", width=160)
        tabla_win.column("nivel", width=80, anchor="center")
        tabla_win.column("fecha", width=180)
        tabla_win.column("usuario", width=140)

        for ev in obtener_logs_seguridad_windows(max_eventos=50):
            tabla_win.insert("", "end", values=(
                ev.get("id", ""),
                ev.get("nombre", ""),
                ev.get("categoria", ""),
                ev.get("nivel", "INFO"),
                ev.get("fecha", ""),
                ev.get("usuario", "")
            ))

        # Tab 3: Cuarentena
        tab_quar = tk.Frame(notebook, bg=PANEL)
        notebook.add(tab_quar, text="📦 Baúl de Cuarentena")

        t_frame_quar = tk.Frame(tab_quar, bg=PANEL)
        t_frame_quar.pack(fill="both", expand=True, padx=8, pady=(8, 4))

        cols_quar = ("id", "nombre", "fecha", "sha256", "ruta")
        scroll_quar = ttk.Scrollbar(t_frame_quar, orient="vertical")
        tabla_quar = ttk.Treeview(t_frame_quar, columns=cols_quar, show="headings", yscrollcommand=scroll_quar.set)
        scroll_quar.config(command=tabla_quar.yview)

        scroll_quar.pack(side="right", fill="y")
        tabla_quar.pack(side="left", fill="both", expand=True)

        tabla_quar.heading("id", text="ID Cuarentena")
        tabla_quar.heading("nombre", text="Archivo")
        tabla_quar.heading("fecha", text="Fecha de Aislamiento")
        tabla_quar.heading("sha256", text="Hash SHA256")
        tabla_quar.heading("ruta", text="Ruta Original")

        tabla_quar.column("id", width=100, anchor="center")
        tabla_quar.column("nombre", width=180)
        tabla_quar.column("fecha", width=160)
        tabla_quar.column("sha256", width=240)
        tabla_quar.column("ruta", width=340)

        def recargar_cuarentena():
            for item in tabla_quar.get_children():
                tabla_quar.delete(item)
            for item in obtener_archivos_cuarentena():
                tabla_quar.insert("", "end", values=(
                    item.get("id", ""),
                    item.get("nombre_original", ""),
                    item.get("fecha", ""),
                    item.get("sha256", "")[:24] + "...",
                    item.get("ruta_original", "")
                ))

        recargar_cuarentena()

        quar_btns = tk.Frame(tab_quar, bg=PANEL)
        quar_btns.pack(fill="x", padx=8, pady=(0, 8))

        def accion_restaurar():
            sel = tabla_quar.selection()
            if not sel:
                messagebox.showwarning("Selección", "Selecciona un archivo de la lista de cuarentena.")
                return
            item_id = tabla_quar.item(sel[0])["values"][0]
            if messagebox.askyesno("Restaurar", f"¿Deseas restaurar el archivo {item_id} a su ubicación original?"):
                ok, msg = restaurar_cuarentena(item_id)
                if ok:
                    messagebox.showinfo("Restaurado", msg)
                    recargar_cuarentena()
                else:
                    messagebox.showerror("Error", msg)

        def accion_eliminar_definitivo():
            sel = tabla_quar.selection()
            if not sel:
                messagebox.showwarning("Selección", "Selecciona un archivo de la lista de cuarentena.")
                return
            item_id = tabla_quar.item(sel[0])["values"][0]
            if messagebox.askyesno("Eliminar", f"¿Deseas borrar permanentemente el archivo {item_id}? Esta acción no se puede deshacer."):
                ok, msg = eliminar_definitivo_cuarentena(item_id)
                if ok:
                    messagebox.showinfo("Eliminado", msg)
                    recargar_cuarentena()
                else:
                    messagebox.showerror("Error", msg)

        tk.Button(quar_btns, text="♻️ Restaurar Archivo", bg=BTN, fg=GREEN, font=("Consolas", 9, "bold"), cursor="hand2", command=accion_restaurar).pack(side="left", padx=(0, 8))
        tk.Button(quar_btns, text="🗑️ Eliminar Definitivamente", bg=BTN, fg=RED, font=("Consolas", 9, "bold"), cursor="hand2", command=accion_eliminar_definitivo).pack(side="left")

        # Tab 4: Escudo Anti-Phishing (DNS Sinkhole)
        tab_snk = tk.Frame(notebook, bg=PANEL)
        notebook.add(tab_snk, text="🛡️ Escudo Anti-Phishing & DNS")

        snk_cont = tk.Frame(tab_snk, bg=PANEL)
        snk_cont.pack(fill="both", expand=True, padx=10, pady=8)

        cfg_snk = cargar_config_sinkhole()
        var_snk_activo = tk.BooleanVar(value=cfg_snk.get("activo", False))

        ctrl_snk_top = tk.Frame(snk_cont, bg=PANEL)
        ctrl_snk_top.pack(fill="x", pady=(0, 8))

        lbl_snk_badge = tk.Label(
            ctrl_snk_top,
            text="🟢 ESCUDO SINKHOLE: ACTIVO (DOMINIOS BLOQUEADOS)" if var_snk_activo.get() else "🔴 ESCUDO SINKHOLE: INACTIVO",
            fg=GREEN if var_snk_activo.get() else RED,
            bg="#162520" if var_snk_activo.get() else "#2b1414",
            font=("Consolas", 10, "bold"),
            padx=10,
            pady=3,
            bd=1,
            relief="solid"
        )
        lbl_snk_badge.pack(side="left")

        def toggle_sinkhole():
            estado = var_snk_activo.get()
            ok, msg = aplicar_escudo_sinkhole(estado)
            if ok:
                if estado:
                    lbl_snk_badge.config(text="🟢 ESCUDO SINKHOLE: ACTIVO (DOMINIOS BLOQUEADOS)", fg=GREEN, bg="#162520")
                    chk_snk.config(text="✓ Escudo Activo", fg="#000000", bg=GREEN, selectcolor=GREEN)
                else:
                    lbl_snk_badge.config(text="🔴 ESCUDO SINKHOLE: INACTIVO", fg=RED, bg="#2b1414")
                    chk_snk.config(text="✕ Escudo Inactivo", fg=TEXT_MUTED, bg=BTN, selectcolor=BG)
                messagebox.showinfo("Escudo Sinkhole DNS", msg)
                recargar_tabla_doms()
            else:
                var_snk_activo.set(not estado)
                messagebox.showerror("Error", msg)

        chk_snk = tk.Checkbutton(
            ctrl_snk_top,
            text="✓ Escudo Activo" if var_snk_activo.get() else "✕ Escudo Inactivo",
            variable=var_snk_activo,
            bg=GREEN if var_snk_activo.get() else BTN,
            fg="#000000" if var_snk_activo.get() else TEXT_MUTED,
            selectcolor=GREEN if var_snk_activo.get() else BG,
            font=("Consolas", 9, "bold"),
            bd=1,
            relief="solid",
            padx=8,
            pady=2,
            cursor="hand2",
            command=toggle_sinkhole
        )
        chk_snk.pack(side="left", padx=15)

        # Entrada para añadir nuevo dominio
        add_frame = tk.Frame(snk_cont, bg=PANEL)
        add_frame.pack(fill="x", pady=(0, 6))

        tk.Label(add_frame, text="Bloquear Dominio:", fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 9, "bold")).pack(side="left", padx=(0, 6))
        var_dom = tk.StringVar()
        ent_dom = tk.Entry(add_frame, textvariable=var_dom, bg=BG, fg=TEXT, insertbackground=GREEN, font=("Consolas", 9), width=35)
        ent_dom.pack(side="left", padx=4)

        def accion_agregar_dom():
            d = var_dom.get().strip()
            if not d:
                return
            ok, msg = agregar_dominio_sinkhole(d)
            if ok:
                messagebox.showinfo("Sinkhole", msg)
                var_dom.set("")
                recargar_tabla_doms()
            else:
                messagebox.showwarning("Sinkhole", msg)

        tk.Button(add_frame, text="➕ Añadir a Lista Negra", bg=BTN, fg=YELLOW, font=("Consolas", 8, "bold"), padx=8, pady=2, cursor="hand2", command=accion_agregar_dom).pack(side="left", padx=6)

        # Tabla de dominios bloqueados
        t_frame_doms = tk.Frame(snk_cont, bg=PANEL)
        t_frame_doms.pack(fill="both", expand=True)

        cols_doms = ("dominio", "categoria", "destino", "estado")
        scroll_doms = ttk.Scrollbar(t_frame_doms, orient="vertical")
        tabla_doms = ttk.Treeview(t_frame_doms, columns=cols_doms, show="headings", yscrollcommand=scroll_doms.set)
        scroll_doms.config(command=tabla_doms.yview)
        scroll_doms.pack(side="right", fill="y")
        tabla_doms.pack(side="left", fill="both", expand=True)

        tabla_doms.heading("dominio", text="Dominio Bloqueado")
        tabla_doms.heading("categoria", text="Categoría de Amenaza")
        tabla_doms.heading("destino", text="Redirección Sinkhole")
        tabla_doms.heading("estado", text="Estado de Bloqueo")

        tabla_doms.column("dominio", width=300)
        tabla_doms.column("categoria", width=200)
        tabla_doms.column("destino", width=150, anchor="center")
        tabla_doms.column("estado", width=130, anchor="center")

        def recargar_tabla_doms():
            for item in tabla_doms.get_children():
                tabla_doms.delete(item)

            cfg = cargar_config_sinkhole()
            activo = cfg.get("activo", False)
            for d in cfg.get("dominios_bloqueados", []):
                cat = "Minería / Cryptojacking" if ("coin" in d or "miner" in d) else ("C2 / Botnet Server" if ("c2" in d or "payload" in d) else "Phishing / Fake Auth")
                tabla_doms.insert("", "end", values=(
                    d,
                    cat,
                    "0.0.0.0 (Sinkhole)",
                    "🟢 BLOQUEADO" if activo else "⚪ INACTIVO"
                ))

        recargar_tabla_doms()

    # ═════════════════════════════════════════════════════════════
    # MÓDULO 9: PROCESOS EN VIVO (REAL-TIME LIVE MONITOR)
    # ═════════════════════════════════════════════════════════════
    def procesos_live(self):
        self.limpiar_contenido()
        self.live_running = True

        self.establecer_cabecera_fija("⚡ MONITOR DE PROCESOS EN TIEMPO REAL", color=YELLOW)

        # En la barra fija colocamos los medidores de carga CPU/RAM a la derecha
        gauge_container = tk.Frame(self.sub_header, bg=PANEL_LIGHT)
        gauge_container.pack(side="right", padx=15, pady=8)

        lbl_cpu_live = tk.Label(gauge_container, text="CPU: --%", fg=CYAN, bg=PANEL_LIGHT, font=("Consolas", 10, "bold"))
        lbl_cpu_live.pack(side="left", padx=10)
        lbl_ram_live = tk.Label(gauge_container, text="RAM: --%", fg=GREEN, bg=PANEL_LIGHT, font=("Consolas", 10, "bold"))
        lbl_ram_live.pack(side="left", padx=10)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=15)

        # Cuadro de resultados de procesos en vivo con scrollbar dedicado
        tree_live_frame = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        tree_live_frame.pack(fill="both", expand=True)

        cols = ("pid", "nombre", "cpu", "ram", "estado")
        scroll_live = ttk.Scrollbar(tree_live_frame, orient="vertical")
        tabla_live = ttk.Treeview(tree_live_frame, columns=cols, show="headings", yscrollcommand=scroll_live.set)
        scroll_live.config(command=tabla_live.yview)

        scroll_live.pack(side="right", fill="y")
        tabla_live.pack(side="left", fill="both", expand=True)

        tabla_live.heading("pid", text="PID")
        tabla_live.heading("nombre", text="Nombre del Proceso")
        tabla_live.heading("cpu", text="CPU %")
        tabla_live.heading("ram", text="RAM (MB)")
        tabla_live.heading("estado", text="Estado")

        tabla_live.column("pid", width=80, anchor="center")
        tabla_live.column("nombre", width=340)
        tabla_live.column("cpu", width=100, anchor="center")
        tabla_live.column("ram", width=120, anchor="center")
        tabla_live.column("estado", width=120, anchor="center")

        def actualizar_bucle():
            if not self.live_running or not self.winfo_exists():
                return

            try:
                cpu_p = psutil.cpu_percent()
                ram_p = psutil.virtual_memory().percent
                if lbl_cpu_live.winfo_exists():
                    lbl_cpu_live.config(text=f"CPU: {cpu_p}%")
                if lbl_ram_live.winfo_exists():
                    lbl_ram_live.config(text=f"RAM: {ram_p}%")

                procs = []
                for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status']):
                    try:
                        ram_mb = p.info['memory_info'].rss / (1024 * 1024) if p.info['memory_info'] else 0
                        procs.append({
                            "pid": p.info['pid'],
                            "nombre": p.info['name'],
                            "cpu": p.info['cpu_percent'] or 0,
                            "ram": ram_mb,
                            "estado": p.info['status'] or "running"
                        })
                    except Exception:
                        continue

                procs.sort(key=lambda x: (x['cpu'], x['ram']), reverse=True)

                sel = tabla_live.selection()
                sel_pid = tabla_live.item(sel[0])["values"][0] if sel else None

                for item in tabla_live.get_children():
                    tabla_live.delete(item)

                for p in procs[:40]:
                    item_id = tabla_live.insert("", "end", values=(
                        p["pid"],
                        p["nombre"],
                        f"{p['cpu']}%",
                        f"{p['ram']:.1f}",
                        p["estado"]
                    ))
                    if sel_pid and p["pid"] == sel_pid:
                        tabla_live.selection_set(item_id)

            except Exception:
                pass

            if self.live_running:
                self.after(2000, actualizar_bucle)

        actualizar_bucle()

        live_actions = tk.Frame(cont, bg=BG)
        live_actions.pack(fill="x", pady=(12, 0))

        def matar_live():
            sel = tabla_live.selection()
            if not sel:
                messagebox.showwarning("Selección", "Selecciona un proceso de la lista.")
                return
            pid = tabla_live.item(sel[0])["values"][0]
            nombre = tabla_live.item(sel[0])["values"][1]
            if messagebox.askyesno("Finalizar Proceso", f"¿Finalizar {nombre} (PID {pid})?"):
                ok, msg = matar_proceso(pid)
                registrar_accion_edr("FINALIZAR_PROCESO_LIVE", f"PID {pid} ({nombre})", nivel="ALTO", exito=ok)
                if ok:
                    messagebox.showinfo("EDR", msg)
                else:
                    messagebox.showerror("Error", msg)

        def suspender_live():
            sel = tabla_live.selection()
            if not sel:
                return
            pid = tabla_live.item(sel[0])["values"][0]
            ok, msg = suspender_proceso(pid)
            if ok:
                messagebox.showinfo("Pausar Proceso", msg)
            else:
                messagebox.showerror("Error", msg)

        def reanudar_live():
            sel = tabla_live.selection()
            if not sel:
                return
            pid = tabla_live.item(sel[0])["values"][0]
            ok, msg = reanudar_proceso(pid)
            if ok:
                messagebox.showinfo("Reanudar Proceso", msg)
            else:
                messagebox.showerror("Error", msg)

        tk.Button(live_actions, text="⛔ Finalizar Proceso", bg=BTN, fg=RED, font=("Consolas", 10, "bold"), cursor="hand2", command=matar_live).pack(side="left", padx=(0, 6))
        tk.Button(live_actions, text="⏸️ Pausar Proceso", bg=BTN, fg=YELLOW, font=("Consolas", 10, "bold"), cursor="hand2", command=suspender_live).pack(side="left", padx=6)
        tk.Button(live_actions, text="▶️ Reanudar Proceso", bg=BTN, fg=GREEN, font=("Consolas", 10, "bold"), cursor="hand2", command=reanudar_live).pack(side="left", padx=6)

    # ═════════════════════════════════════════════════════════════
    # MÓDULO 10: CONFIGURACIÓN Y AJUSTES
    # ═════════════════════════════════════════════════════════════
    def setting(self):
        self.limpiar_contenido()
        self.establecer_cabecera_fija("⚙️ CONFIGURACIÓN Y AJUSTES DE CYBER_ANALYZER", color=GREEN)

        cont = tk.Frame(self.main_container, bg=BG)
        cont.pack(fill="both", expand=True, padx=30, pady=15)

        cfg_box = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        cfg_box.pack(fill="both", expand=True, pady=(0, 12))

        tk.Label(cfg_box, text="🌐 Integración con VirusTotal v3 API", fg=CYAN, bg=PANEL, font=("Consolas", 12, "bold")).pack(anchor="w", padx=20, pady=(15, 6))
        tk.Label(cfg_box, text="Ingresa tu clave de API de VirusTotal para habilitar el análisis de hashes y motores antivirus:", fg=TEXT, bg=PANEL, font=("Consolas", 10)).pack(anchor="w", padx=20, pady=(0, 4))

        f_api = tk.Frame(cfg_box, bg=PANEL)
        f_api.pack(fill="x", padx=20, pady=(0, 10))

        var_api = tk.StringVar(value=self.config_app.get("vt_api_key", ""))
        ent_api = tk.Entry(f_api, textvariable=var_api, bg=BG, fg=TEXT, insertbackground=GREEN, font=("Consolas", 10), width=65)
        ent_api.pack(side="left", padx=(0, 10))

        def accion_probar_api():
            key = var_api.get().strip()
            ok, msg = probar_conexion_vt(key)
            if ok:
                messagebox.showinfo("VirusTotal API", msg)
            else:
                messagebox.showerror("VirusTotal API", msg)

        tk.Button(f_api, text="🧪 Probar Conexión", bg=BTN, fg=YELLOW, font=("Consolas", 10, "bold"), cursor="hand2", command=accion_probar_api).pack(side="left")

        tk.Label(cfg_box, text="📦 Ubicación del Baúl de Cuarentena", fg=CYAN, bg=PANEL, font=("Consolas", 12, "bold")).pack(anchor="w", padx=20, pady=(15, 6))
        f_quar = tk.Frame(cfg_box, bg=PANEL)
        f_quar.pack(fill="x", padx=20, pady=(0, 10))

        var_quar_path = tk.StringVar(value=self.config_app.get("quarantine_dir", "cuarentena"))
        tk.Entry(f_quar, textvariable=var_quar_path, bg=BG, fg=TEXT, font=("Consolas", 10), width=50, state="readonly").pack(side="left", padx=(0, 10))

        # 🚀 Actualizaciones desde GitHub Releases
        tk.Label(cfg_box, text="🚀 Actualizaciones desde GitHub Releases", fg=CYAN, bg=PANEL, font=("Consolas", 12, "bold")).pack(anchor="w", padx=20, pady=(15, 6))
        tk.Label(cfg_box, text="Configura el repositorio de GitHub desde donde CyberAnalyzer detectará nuevas versiones y mejoras:", fg=TEXT, bg=PANEL, font=("Consolas", 10)).pack(anchor="w", padx=20, pady=(0, 4))

        f_gh = tk.Frame(cfg_box, bg=PANEL)
        f_gh.pack(fill="x", padx=20, pady=(0, 6))

        tk.Label(f_gh, text="Repositorio (usuario/repo):", fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 9)).pack(side="left", padx=(0, 8))
        var_repo = tk.StringVar(value=self.config_app.get("github_repo", DEFAULT_GITHUB_REPO))
        ent_repo = tk.Entry(f_gh, textvariable=var_repo, bg=BG, fg=TEXT, insertbackground=GREEN, font=("Consolas", 10), width=35)
        ent_repo.pack(side="left", padx=(0, 10))

        lbl_estado_upd = tk.Label(cfg_box, text=f"• Versión instalada actualmente: v{APP_VERSION}", fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 9))

        def accion_check_manual_setting():
            repo_val = var_repo.get().strip()
            self.config_app["github_repo"] = repo_val
            lbl_estado_upd.config(text="• ⏳ Consultando API de GitHub...", fg=YELLOW)
            btn_check_gh.config(state="disabled")

            def _on_finish(res):
                btn_check_gh.config(state="normal")
                if res.get("disponible"):
                    lbl_estado_upd.config(text=f"• 🚀 ¡Nueva versión v{res['version_remota']} disponible en GitHub!", fg=YELLOW)
                elif res.get("error"):
                    lbl_estado_upd.config(text=f"• ⚠️ Error: {res['error']}", fg=RED)
                else:
                    lbl_estado_upd.config(text=f"• ✅ CyberAnalyzer está actualizado (v{APP_VERSION})", fg=GREEN)

            self.comprobar_actualizaciones_manual(callback_resultado_ui=_on_finish)

        btn_check_gh = tk.Button(f_gh, text="🔍 Comprobar Actualizaciones Ahora", bg=BTN, fg=GREEN, font=("Consolas", 9, "bold"), cursor="hand2", command=accion_check_manual_setting)
        btn_check_gh.pack(side="left")

        var_auto_upd = tk.BooleanVar(value=self.config_app.get("check_updates_startup", True))
        chk_upd = tk.Checkbutton(
            cfg_box,
            text="Comprobar actualizaciones automáticamente al iniciar CyberAnalyzer",
            variable=var_auto_upd,
            bg=PANEL,
            fg=TEXT,
            selectcolor=BG,
            activebackground=PANEL,
            activeforeground=GREEN,
            font=("Consolas", 9)
        )
        chk_upd.pack(anchor="w", padx=20, pady=(4, 4))
        lbl_estado_upd.pack(anchor="w", padx=20, pady=(0, 10))

        def accion_guardar():
            self.config_app["vt_api_key"] = var_api.get().strip()
            self.config_app["github_repo"] = var_repo.get().strip()
            self.config_app["check_updates_startup"] = var_auto_upd.get()
            guardar_configuracion(self.config_app)
            messagebox.showinfo("Configuración", "✅ Ajustes guardados correctamente.")

        tk.Button(cfg_box, text="💾 Guardar Cambios", bg=BTN, fg=GREEN, font=("Consolas", 11, "bold"), padx=15, pady=6, cursor="hand2", command=accion_guardar).pack(anchor="w", padx=20, pady=(15, 15))

        info_card = tk.Frame(cont, bg=PANEL, bd=1, relief="solid")
        info_card.pack(fill="x")
        tk.Label(info_card, text=f"CyberAnalyzer EDR Suite - Versión {APP_VERSION} | Arquitectura x64 Windows", fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 9)).pack(padx=15, pady=10)

    # ═════════════════════════════════════════════════════════════
    # VENTANAS MODALES Y ACCIONES EDR
    # ═════════════════════════════════════════════════════════════
    def mostrar_detalle_amenaza(self, alerta, volver_a=None):
        pid = alerta.get("pid") or alerta.get("process_id")
        ip = alerta.get("ip") or alerta.get("remoto") or alerta.get("ip_remota")

        alerta_norm = {
            "tipo": alerta.get("tipo", "Actividad Sospechosa"),
            "nivel": alerta.get("nivel", "MEDIO"),
            "mensaje": alerta.get("mensaje") or alerta.get("riesgo") or alerta.get("detalle") or "Comportamiento anómalo detectado",
            "proceso": alerta.get("proceso") or alerta.get("nombre") or alerta.get("exe") or "N/A",
            "pid": int(pid) if pid else None,
            "ip": ip,
            "ruta": alerta.get("ruta") or alerta.get("path")
        }
        es_persistencia = "persistencia" in alerta_norm["tipo"].lower()

        if alerta_norm["pid"] and not alerta_norm["ruta"]:
            try:
                p = psutil.Process(alerta_norm["pid"])
                alerta_norm["ruta"] = p.exe()
            except Exception:
                pass

        win = tk.Toplevel(self)
        win.title("🚨 Detalle de Amenaza y Acciones EDR")
        win.geometry("560x650")
        win.configure(bg=BG)
        win.resizable(False, False)

        def fila(txt, color=TEXT):
            tk.Label(win, text=txt, fg=color, bg=BG, font=("Consolas", 10), wraplength=520, justify="left").pack(anchor="w", padx=20, pady=3)

        tk.Label(win, text="⚠ GESTIÓN DE INCIDENTE DE SEGURIDAD", fg=RED, bg=BG, font=("Consolas", 14, "bold")).pack(pady=(15, 10))

        fila(f"Tipo: {alerta_norm['tipo']}", CYAN)
        fila(f"Severidad: {alerta_norm['nivel']}", RED if alerta_norm["nivel"] == "CRÍTICO" else YELLOW)
        fila(f"Detalle: {alerta_norm['mensaje']}")
        fila(f"Proceso: {alerta_norm['proceso']}")
        fila(f"PID: {alerta_norm['pid'] or 'N/A'}")
        fila(f"Ruta: {alerta_norm['ruta'] or 'N/A'}")
        fila(f"IP Remota: {alerta_norm['ip'] or 'N/A'}")

        tk.Label(win, text="─" * 60, fg=BORDER, bg=BG).pack(pady=10)
        tk.Label(win, text="🛠️ ACCIONES DE RESPUESTA EDR DISPONIBLES:", fg=GREEN, bg=BG, font=("Consolas", 11, "bold")).pack(anchor="w", padx=20, pady=(0, 8))

        if alerta_norm["pid"]:
            def run_kill():
                ok, msg = matar_proceso(alerta_norm["pid"])
                registrar_accion_edr("FINALIZAR_PROCESO", f"PID: {alerta_norm['pid']}, Proceso: {alerta_norm['proceso']}", nivel="ALTO", exito=ok)
                if ok:
                    messagebox.showinfo("EDR", msg)
                    win.destroy()
                else:
                    messagebox.showerror("Error", msg)

            def run_isolate():
                ok, msg = aislar_proceso(alerta_norm["pid"])
                registrar_accion_edr("AISLAR_PROCESO", f"PID: {alerta_norm['pid']}", nivel="ALTO", exito=ok)
                if ok:
                    messagebox.showinfo("EDR", msg)
                else:
                    messagebox.showerror("Error", msg)

            tk.Button(win, text="⛔ Finalizar Proceso Inmediatamente", bg=BTN, fg=RED, font=("Consolas", 11, "bold"), command=run_kill).pack(fill="x", padx=40, pady=4)
            tk.Button(win, text="🧊 Aislar Proceso de la Red", bg=BTN, fg=YELLOW, font=("Consolas", 11, "bold"), command=run_isolate).pack(fill="x", padx=40, pady=4)

        if alerta_norm["ip"]:
            def run_block_ip():
                ok, msg = bloquear_ip(alerta_norm["ip"])
                registrar_accion_edr("BLOQUEAR_IP", f"IP: {alerta_norm['ip']}", nivel="ALTO", exito=ok)
                if ok:
                    messagebox.showinfo("Firewall", msg)
                else:
                    messagebox.showerror("Error", msg)

            def run_open_maps():
                from core.firewall_guard import resolver_geoip
                geo = resolver_geoip(alerta_norm["ip"])
                lat = geo.get("lat", 40.4168)
                lon = geo.get("lon", -3.7038)
                webbrowser.open(f"https://www.google.com/maps/search/?api=1&query={lat},{lon}")

            def run_open_streetview():
                from core.firewall_guard import resolver_geoip
                geo = resolver_geoip(alerta_norm["ip"])
                lat = geo.get("lat", 40.4168)
                lon = geo.get("lon", -3.7038)
                webbrowser.open(f"https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat},{lon}")

            tk.Button(win, text=f"🔒 Bloquear IP Remota ({alerta_norm['ip']})", bg=BTN, fg=GREEN, font=("Consolas", 10, "bold"), command=run_block_ip).pack(fill="x", padx=40, pady=3)
            tk.Button(win, text=f"🗺️ Ver Ubicación en Google Maps ({alerta_norm['ip']})", bg=BTN, fg=CYAN, font=("Consolas", 10, "bold"), command=run_open_maps).pack(fill="x", padx=40, pady=3)
            tk.Button(win, text=f"👁️ Abrir Street View 360° ({alerta_norm['ip']})", bg=BTN, fg="#ff00d4", font=("Consolas", 10, "bold"), command=run_open_streetview).pack(fill="x", padx=40, pady=3)

        if alerta_norm["ruta"] and os.path.isfile(alerta_norm["ruta"]):
            def run_quarantine():
                if alerta_norm["pid"]:
                    matar_proceso(alerta_norm["pid"])
                ok, msg = cuarentena(alerta_norm["ruta"])
                registrar_accion_edr("CUARENTENA_ARCHIVO", f"Ruta: {alerta_norm['ruta']}", nivel="CRÍTICO", exito=ok)
                if ok:
                    messagebox.showinfo("Cuarentena", msg)
                    win.destroy()
                else:
                    messagebox.showerror("Error", msg)

            tk.Button(win, text="📦 Mover Binario a Cuarentena", bg=BTN, fg=GREEN, font=("Consolas", 11, "bold"), command=run_quarantine).pack(fill="x", padx=40, pady=4)

        if es_persistencia:
            def run_del_pers():
                ok, msg = eliminar_persistencia(alerta)
                registrar_accion_edr("ELIMINAR_PERSISTENCIA", f"Detalle: {alerta_norm['mensaje']}", nivel="CRÍTICO", exito=ok)
                if ok:
                    messagebox.showinfo("Persistencia", msg)
                    win.destroy()
                else:
                    messagebox.showerror("Error", msg)

            tk.Button(win, text="🧹 Eliminar Mecanismo de Persistencia", bg=BTN, fg=RED, font=("Consolas", 11, "bold"), command=run_del_pers).pack(fill="x", padx=40, pady=4)

        tk.Button(win, text="Cerrar", bg=BTN, fg=TEXT_MUTED, font=("Consolas", 10), command=win.destroy).pack(fill="x", padx=40, pady=(15, 10))

    def mostrar_detalle_software(self, software):
        win = tk.Toplevel(self)
        win.title("📦 Inspección de Software y Archivo")
        win.geometry("640x580")
        win.configure(bg=BG)
        win.resizable(False, False)

        info = tk.Frame(win, bg=BG)
        info.pack(fill="x", padx=20, pady=15)

        def campo(label, valor):
            f = tk.Frame(info, bg=BG)
            f.pack(fill="x", pady=2)
            tk.Label(f, text=f"{label}:", fg=GREEN, bg=BG, font=("Consolas", 10, "bold"), width=18, anchor="w").pack(side="left")
            tk.Label(f, text=str(valor or "Desconocido"), fg=TEXT, bg=BG, font=("Consolas", 10), wraplength=420, justify="left").pack(side="left")

        campo("Nombre", software.get("nombre"))
        campo("Versión", software.get("version"))
        campo("Editor", software.get("editor"))
        campo("Ruta", software.get("ruta"))
        campo("Fecha Instalación", software.get("fecha_instalacion"))
        campo("Tipo", software.get("tipo"))
        campo("Nivel de Riesgo", self.calcular_riesgo_software(software))

        ttk.Separator(win, orient="horizontal").pack(fill="x", padx=20, pady=10)

        acciones = tk.Frame(win, bg=BG)
        acciones.pack(fill="x", padx=20, pady=5)

        tk.Label(acciones, text="🛠️ Acciones y Verificación Criptográfica:", fg=CYAN, bg=BG, font=("Consolas", 11, "bold")).pack(anchor="w", pady=(0, 8))

        tk.Button(acciones, text="🔑 Calcular Hash SHA256", bg=BTN, fg=TEXT, font=("Consolas", 10), command=lambda: self.ver_hash_software(software)).pack(fill="x", pady=3)
        tk.Button(acciones, text="🧬 Comparar Hash con Firma Oficial", bg=BTN, fg=TEXT, font=("Consolas", 10), command=lambda: self.comparar_hash_software(software)).pack(fill="x", pady=3)
        tk.Button(acciones, text="🌐 Analizar en VirusTotal", bg=BTN, fg=CYAN, font=("Consolas", 10, "bold"), command=lambda: self.analizar_vt_software(software)).pack(fill="x", pady=3)

        if software.get("uninstall"):
            tk.Button(acciones, text="🗑️ Desinstalar Software", bg=BTN, fg=RED, font=("Consolas", 10, "bold"), command=lambda: self.desinstalar_software(software)).pack(fill="x", pady=6)

        if software.get("ruta") and os.path.exists(software["ruta"]):
            tk.Button(acciones, text="📂 Abrir Carpeta de Instalación", bg=BTN, fg=TEXT, font=("Consolas", 10), command=lambda: os.startfile(software["ruta"])).pack(fill="x", pady=3)

        tk.Button(acciones, text="Cerrar", bg=BTN, fg=TEXT_MUTED, font=("Consolas", 10), command=win.destroy).pack(fill="x", pady=(10, 5))

    def ver_hash_software(self, software):
        ruta = software.get("ruta")
        exe = obtener_ejecutable_principal(ruta)
        if not exe:
            messagebox.showwarning("Hash", "No se encontró un ejecutable principal para este programa.")
            return

        h = calcular_sha256(exe)
        messagebox.showinfo("Hash SHA256", f"Archivo:\n{exe}\n\nSHA256:\n{h}")

    def comparar_hash_software(self, software):
        ruta = software.get("ruta")
        exe = obtener_ejecutable_principal(ruta)
        if not exe:
            messagebox.showwarning("Hash", "No se encontró un archivo ejecutable para verificar.")
            return

        hash_calculado = calcular_sha256(exe)
        if not hash_calculado:
            messagebox.showerror("Error", "No se pudo calcular el hash del archivo.")
            return

        hash_usuario = simpledialog.askstring("Comparar Hash", "Ingresa el hash SHA256 original proporcionado por el desarrollador:")
        if not hash_usuario:
            return

        if hash_calculado.lower() == hash_usuario.strip().lower():
            messagebox.showinfo("Verificación Exitosa", "✅ El hash COINCIDE exactamente. El archivo es auténtico y no fue alterado.")
        else:
            messagebox.showwarning("Firma Alterada", "❌ El hash NO coincide.\nEl archivo pudo haber sido modificado o infectado.")

    def analizar_vt_software(self, software):
        ruta = software.get("ruta")
        exe = obtener_ejecutable_principal(ruta) if (ruta and os.path.isdir(ruta)) else (ruta if (ruta and os.path.isfile(ruta)) else None)

        if not exe or not os.path.isfile(exe):
            messagebox.showwarning("VirusTotal", "No se encontró un ejecutable accesible para calcular el hash.")
            return

        sha256 = calcular_sha256(exe)
        if not sha256:
            messagebox.showerror("VirusTotal", "No se pudo calcular el hash del binario.")
            return

        api_key = self.config_app.get("vt_api_key")

        try:
            analisis = obtener_analisis_completo(sha256, api_key)
        except Exception as e:
            messagebox.showerror("VirusTotal", f"Error al consultar VirusTotal:\n{e}")
            return

        if not analisis:
            messagebox.showinfo("VirusTotal", "ℹ️ Este archivo no ha sido analizado previamente en VirusTotal.")
            return

        stats = analisis["stats"]
        motores = analisis["motores"]
        detecciones = stats.get("malicious", 0)

        riesgo = "BAJO"
        if detecciones > 3:
            riesgo = "CRÍTICO"
        elif detecciones > 0:
            riesgo = "MEDIO"

        mitre = self.extraer_mitre_desde_motores(motores)

        data = {
            "hash": sha256,
            "motores": motores,
            "stats": stats,
            "detecciones": detecciones,
            "riesgo": riesgo,
            "mitre": mitre
        }

        self.mostrar_resultado_vt(data, software)

    def extraer_mitre_desde_motores(self, motores):
        mitre = set()
        for motor, info in motores.items():
            res = str(info.get("result", ""))
            for p in res.split():
                if p.startswith("T") and p[1:].isdigit():
                    mitre.add(p)
        return sorted(mitre)

    def mostrar_resultado_vt(self, data, software):
        win = tk.Toplevel(self)
        win.title("🧪 Resultado de Análisis en VirusTotal")
        win.geometry("720x680")
        win.configure(bg=BG)

        tk.Label(win, text="🧪 REPORTE DE MOTORES ANTIVIRUS (VIRUSTOTAL)", fg=GREEN, bg=BG, font=("Consolas", 14, "bold")).pack(pady=12)

        res_box = tk.Frame(win, bg=PANEL, bd=1, relief="solid")
        res_box.pack(fill="x", padx=20, pady=(0, 10))

        tk.Label(res_box, text=f"Archivo: {software.get('nombre', 'Desconocido')}", fg=TEXT, bg=PANEL, font=("Consolas", 10)).pack(anchor="w", padx=15, pady=(8, 2))
        tk.Label(res_box, text=f"Detecciones Maliciosas: {data['detecciones']} motores", fg=RED if data['detecciones'] > 0 else GREEN, bg=PANEL, font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=2)
        tk.Label(res_box, text=f"Nivel de Amenaza Evaluado: {data['riesgo']}", fg=RED if data['riesgo'] != "BAJO" else GREEN, bg=PANEL, font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(2, 8))

        cols = ("motor", "estado", "resultado")
        vt_table_frame = tk.Frame(win, bg=PANEL, bd=1, relief="solid")
        vt_table_frame.pack(fill="both", expand=True, padx=20, pady=5)

        scroll_vt = ttk.Scrollbar(vt_table_frame, orient="vertical")
        tabla_vt = ttk.Treeview(vt_table_frame, columns=cols, show="headings", yscrollcommand=scroll_vt.set)
        scroll_vt.config(command=tabla_vt.yview)

        scroll_vt.pack(side="right", fill="y")
        tabla_vt.pack(side="left", fill="both", expand=True)

        tabla_vt.heading("motor", text="Motor Antivirus")
        tabla_vt.heading("estado", text="Categoría")
        tabla_vt.heading("resultado", text="Firma Detectada")

        tabla_vt.column("motor", width=200)
        tabla_vt.column("estado", width=120, anchor="center")
        tabla_vt.column("resultado", width=340)

        tabla_vt.tag_configure("malicious", foreground=RED)
        tabla_vt.tag_configure("suspicious", foreground=YELLOW)
        tabla_vt.tag_configure("undetected", foreground=TEXT_MUTED)

        for motor, info in data["motores"].items():
            cat = info.get("category", "undetected")
            res = info.get("result") or "Limpio / No detectado"
            tabla_vt.insert("", "end", values=(motor, cat.upper(), res), tags=(cat,))

        tabla_vt.bind("<Double-1>", lambda e: self.mostrar_resumen_amenaza(tabla_vt))

        tk.Button(win, text="Cerrar", bg=BTN, fg=TEXT, font=("Consolas", 10), command=win.destroy).pack(fill="x", padx=40, pady=10)

    def mostrar_resumen_amenaza(self, tabla):
        sel = tabla.focus()
        if not sel:
            return
        vals = tabla.item(sel, "values")
        motor, cat, firma = vals
        if firma.lower() in ("limpio / no detectado", "undetected", "limpio", ""):
            return

        info = obtener_info_amenaza(firma)

        win = tk.Toplevel(self)
        win.title("🧠 Inteligencia de Amenazas")
        win.geometry("540x520")
        win.configure(bg=BG)

        tk.Label(win, text=f"🚨 {info['tipo']}", fg=RED, bg=BG, font=("Consolas", 14, "bold")).pack(pady=12)
        tk.Label(win, text=f"Firma: {firma} ({motor})", fg=CYAN, bg=BG, font=("Consolas", 10)).pack(anchor="w", padx=20)

        tk.Label(win, text="Descripción:", fg=GREEN, bg=BG, font=("Consolas", 11, "bold")).pack(anchor="w", padx=20, pady=(12, 4))
        tk.Label(win, text=info["descripcion"], fg=TEXT, bg=BG, font=("Consolas", 10), wraplength=480, justify="left").pack(anchor="w", padx=20)

        tk.Label(win, text="Comportamiento Habitual:", fg=GREEN, bg=BG, font=("Consolas", 11, "bold")).pack(anchor="w", padx=20, pady=(12, 4))
        for c in info["comportamiento"]:
            tk.Label(win, text=f"• {c}", fg=TEXT, bg=BG, font=("Consolas", 9), wraplength=480, justify="left").pack(anchor="w", padx=30, pady=1)

        tk.Label(win, text="Recomendación:", fg=GREEN, bg=BG, font=("Consolas", 11, "bold")).pack(anchor="w", padx=20, pady=(12, 4))
        tk.Label(win, text=info["recomendacion"], fg=YELLOW, bg=BG, font=("Consolas", 10), wraplength=480, justify="left").pack(anchor="w", padx=20)

        tk.Button(win, text="Cerrar", bg=BTN, fg=TEXT, font=("Consolas", 10), command=win.destroy).pack(fill="x", padx=40, pady=15)

    def desinstalar_software(self, software):
        cmd = software.get("uninstall")
        if not cmd:
            messagebox.showerror("Error", "Este programa no dispone de un comando de desinstalación registrado.")
            return

        if messagebox.askyesno("Confirmar Desinstalación", f"¿Deseas ejecutar el desinstalador de '{software.get('nombre')}'?"):
            try:
                subprocess.Popen(cmd, shell=True)
                messagebox.showinfo("Desinstalación", "Se inició el proceso de desinstalación.")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo ejecutar el desinstalador:\n{e}")

    # ═════════════════════════════════════════════════════════════
    # MÓDULO DE ACTUALIZACIONES (GITHUB RELEASES)
    # ═════════════════════════════════════════════════════════════
    def verificar_actualizacion_silenciosa(self):
        """
        Consulta silenciosa en segundo plano al iniciar la app.
        """
        repo = self.config_app.get("github_repo", DEFAULT_GITHUB_REPO)
        def _callback(res):
            self.after(0, lambda: self._procesar_resultado_update_silencioso(res))
        verificar_en_segundo_plano(repo, _callback)

    def _procesar_resultado_update_silencioso(self, res):
        if not self.winfo_exists():
            return
        if res.get("disponible"):
            self.info_actualizacion = res
            if hasattr(self, "btn_update") and self.btn_update:
                self.btn_update.config(
                    text=f"🚀 v{res['version_remota']} DISPONIBLE",
                    bg=YELLOW,
                    fg="#000000",
                    activebackground=GREEN
                )
            mostrar_notificacion_actualizacion(
                self,
                res,
                callback_abrir_update=lambda: self.mostrar_modal_actualizacion(res)
            )

    def comprobar_actualizaciones_manual(self, callback_resultado_ui=None):
        """
        Comprobación manual invocada desde el botón de la barra superior o ajustes.
        """
        if self.info_actualizacion and self.info_actualizacion.get("disponible"):
            self.mostrar_modal_actualizacion(self.info_actualizacion)
            return

        if hasattr(self, "btn_update") and self.btn_update:
            self.btn_update.config(text="⏳ Buscando...", state="disabled")

        repo = self.config_app.get("github_repo", DEFAULT_GITHUB_REPO)
        def _callback(res):
            self.after(0, lambda: self._procesar_resultado_update_manual(res, callback_resultado_ui))
        verificar_en_segundo_plano(repo, _callback)

    def _procesar_resultado_update_manual(self, res, callback_resultado_ui=None):
        if not self.winfo_exists():
            return
        if hasattr(self, "btn_update") and self.btn_update:
            self.btn_update.config(state="normal")
            if res.get("disponible"):
                self.btn_update.config(
                    text=f"🚀 v{res['version_remota']} DISPONIBLE",
                    bg=YELLOW,
                    fg="#000000",
                    activebackground=GREEN
                )
            else:
                self.btn_update.config(
                    text="🔄 ACTUALIZAR",
                    bg=BTN,
                    fg=GREEN
                )

        if callback_resultado_ui:
            try:
                callback_resultado_ui(res)
            except Exception:
                pass

        if res.get("disponible"):
            self.info_actualizacion = res
            self.mostrar_modal_actualizacion(res)
        elif res.get("error"):
            messagebox.showwarning(
                "Actualizaciones",
                f"⚠️ No se pudo comprobar actualizaciones en GitHub:\n\n{res['error']}\n\n"
                f"Repositorio configurado: {res.get('repo', '')}"
            )
        else:
            messagebox.showinfo(
                "Actualizaciones",
                f"✅ CyberAnalyzer Suite está al día.\n\n"
                f"• Versión instalada: v{APP_VERSION}\n"
                f"• Último release en GitHub: v{res.get('version_remota') or APP_VERSION}\n"
                f"• Repositorio: {res.get('repo', '')}"
            )

    def mostrar_modal_actualizacion(self, info_release):
        """
        Ventana modal estilo Cyber para presentar la actualización de GitHub,
        notas de versión (changelog), descarga directa del instalador con barra de progreso e instalación.
        """
        win = tk.Toplevel(self)
        win.title("🚀 Actualización de CyberAnalyzer Suite")
        win.geometry("700x560")
        win.minsize(620, 500)
        win.configure(bg=BG)
        win.transient(self)
        win.grab_set()

        ico_path = resource_path("imagenes/icono.ico")
        if os.path.exists(ico_path):
            try:
                win.iconbitmap(ico_path)
            except Exception:
                pass

        try:
            x = self.winfo_x() + (self.winfo_width() // 2) - 350
            y = self.winfo_y() + (self.winfo_height() // 2) - 280
            win.geometry(f"+{max(0, x)}+{max(0, y)}")
        except Exception:
            pass

        # Encabezado
        h_frame = tk.Frame(win, bg=PANEL_LIGHT, bd=1, relief="solid")
        h_frame.pack(fill="x", padx=20, pady=(15, 10))

        v_nueva = info_release.get("version_remota", "N/A")
        v_actual = info_release.get("version_actual", APP_VERSION)
        nom_rel = info_release.get("nombre_release", f"CyberAnalyzer v{v_nueva}")
        fecha_rel = info_release.get("fecha_publicacion", "Reciente")

        tk.Label(h_frame, text="🚀 ¡NUEVA ACTUALIZACIÓN DETECTADA EN GITHUB!", fg=GREEN, bg=PANEL_LIGHT, font=("Consolas", 13, "bold")).pack(anchor="w", padx=15, pady=(10, 2))

        v_box = tk.Frame(h_frame, bg=PANEL_LIGHT)
        v_box.pack(fill="x", padx=15, pady=(2, 10))
        tk.Label(v_box, text=f"Versión actual: v{v_actual}", fg=TEXT_MUTED, bg=PANEL_LIGHT, font=("Consolas", 10)).pack(side="left")
        tk.Label(v_box, text="  ➔  ", fg=CYAN, bg=PANEL_LIGHT, font=("Consolas", 11, "bold")).pack(side="left")
        tk.Label(v_box, text=f"Nueva versión: v{v_nueva}", fg=YELLOW, bg=PANEL_LIGHT, font=("Consolas", 10, "bold")).pack(side="left")
        tk.Label(v_box, text=f"• Publicado: {fecha_rel}", fg=TEXT_MUTED, bg=PANEL_LIGHT, font=("Consolas", 9)).pack(side="right")

        # Notas de la versión (Changelog)
        notes_frame = tk.Frame(win, bg=PANEL, bd=1, relief="solid")
        notes_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        tk.Label(notes_frame, text=f"📋 Notas de la Versión — {nom_rel}", fg=CYAN, bg=PANEL, font=("Consolas", 10, "bold")).pack(anchor="w", padx=12, pady=(8, 4))

        txt_box = tk.Text(notes_frame, bg=BG, fg=TEXT, font=("Consolas", 9), wrap="word", bd=0, padx=8, pady=8)
        scroll_txt = ttk.Scrollbar(notes_frame, orient="vertical", command=txt_box.yview)
        txt_box.configure(yscrollcommand=scroll_txt.set)
        scroll_txt.pack(side="right", fill="y", padx=(0, 4), pady=(0, 8))
        txt_box.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=(0, 8))

        notas = info_release.get("notas_cambios", "No se proporcionaron notas detalladas.")
        txt_box.insert("1.0", notas)
        txt_box.config(state="disabled")

        # Panel de Descarga & Instalador
        prog_frame = tk.Frame(win, bg=PANEL, bd=1, relief="solid")
        prog_frame.pack(fill="x", padx=20, pady=(0, 10))

        instalador = info_release.get("instalador")
        if instalador:
            info_asset_str = f"Instalador: {instalador['nombre']} ({instalador['tamano_mb']} MB)"
        else:
            info_asset_str = "Paquete disponible en GitHub Releases"

        lbl_asset = tk.Label(prog_frame, text=f"📦 {info_asset_str}", fg=TEXT, bg=PANEL, font=("Consolas", 9))
        lbl_asset.pack(anchor="w", padx=12, pady=(8, 2))

        lbl_status = tk.Label(prog_frame, text="Listo para actualizar", fg=TEXT_MUTED, bg=PANEL, font=("Consolas", 9))
        lbl_status.pack(anchor="w", padx=12, pady=(0, 4))

        pbar = ttk.Progressbar(prog_frame, mode="determinate", length=400)
        pbar.pack(fill="x", padx=12, pady=(0, 8))

        # Botonera
        btn_bar = tk.Frame(win, bg=BG)
        btn_bar.pack(fill="x", padx=20, pady=(0, 15))

        cancel_ev = threading.Event()

        def accion_descargar_e_instalar():
            if not instalador or not instalador.get("url"):
                webbrowser.open(info_release.get("url_release", f"https://github.com/{info_release.get('repo', DEFAULT_GITHUB_REPO)}/releases"))
                return

            btn_descargar.config(state="disabled")
            lbl_status.config(text="⏳ Iniciando descarga del paquete...", fg=YELLOW)
            pbar["value"] = 0

            nombre_archivo = instalador["nombre"]
            import tempfile
            dest_dir = tempfile.gettempdir()
            ruta_local = os.path.join(dest_dir, nombre_archivo)

            def _progreso(descargados, total, porcentaje, vel_str):
                if win.winfo_exists():
                    win.after(0, lambda: _actualizar_ui(descargados, total, porcentaje, vel_str))

            def _actualizar_ui(desc, tot, pct, vel):
                pbar["value"] = pct
                mb_desc = round(desc / (1024 * 1024), 1)
                mb_tot = round(tot / (1024 * 1024), 1) if tot else "?"
                lbl_status.config(
                    text=f"📥 Descargando: {pct}% ({mb_desc} / {mb_tot} MB) • Velocidad: {vel}",
                    fg=CYAN
                )

            def _worker_descarga():
                ok, res_desc = descargar_instalador(
                    instalador["url"],
                    ruta_local,
                    callback_progreso=_progreso,
                    cancelar_evento=cancel_ev
                )
                if win.winfo_exists():
                    win.after(0, lambda: _finalizar_descarga(ok, res_desc))

            def _finalizar_descarga(ok, res_desc):
                btn_descargar.config(state="normal")
                if ok:
                    lbl_status.config(text="✅ ¡Descarga completada con éxito!", fg=GREEN)
                    pbar["value"] = 100
                    if messagebox.askyesno(
                        "Actualización Descargada",
                        f"El instalador de CyberAnalyzer v{v_nueva} se ha descargado correctamente.\n\n"
                        f"¿Deseas cerrar CyberAnalyzer e iniciar la instalación ahora?"
                    ):
                        ejecutar_instalador_y_cerrar(res_desc)
                        self.salir_completo()
                else:
                    lbl_status.config(text=f"❌ Error: {res_desc}", fg=RED)
                    messagebox.showerror("Error en Descarga", f"No se pudo descargar la actualización:\n{res_desc}")

            threading.Thread(target=_worker_descarga, daemon=True).start()

        def accion_abrir_github():
            webbrowser.open(info_release.get("url_release", f"https://github.com/{info_release.get('repo', DEFAULT_GITHUB_REPO)}/releases"))

        def accion_cerrar():
            cancel_ev.set()
            win.destroy()

        btn_descargar = tk.Button(
            btn_bar,
            text="📥 Descargar e Instalar Actualización" if instalador else "📥 Descargar desde GitHub",
            bg=GREEN,
            fg="#000000",
            activebackground="#00cc7a",
            activeforeground="#000000",
            font=("Consolas", 10, "bold"),
            padx=14,
            pady=6,
            relief="solid",
            bd=1,
            cursor="hand2",
            command=accion_descargar_e_instalar
        )
        btn_descargar.pack(side="left", padx=(0, 10))

        tk.Button(
            btn_bar,
            text="🌐 Ver en GitHub",
            bg=BTN,
            fg=CYAN,
            activebackground=BTN_HOVER,
            activeforeground=CYAN,
            font=("Consolas", 10, "bold"),
            padx=12,
            pady=6,
            relief="solid",
            bd=1,
            cursor="hand2",
            command=accion_abrir_github
        ).pack(side="left")

        tk.Button(
            btn_bar,
            text="Cerrar",
            bg=BTN,
            fg=TEXT_MUTED,
            activebackground=BTN_HOVER,
            activeforeground=TEXT,
            font=("Consolas", 10),
            padx=12,
            pady=6,
            relief="solid",
            bd=1,
            cursor="hand2",
            command=accion_cerrar
        ).pack(side="right")


def ejecutar_firewall_en_segundo_plano():
    cfg_fw = cargar_config_firewall()
    if not cfg_fw.get("mantener_segundo_plano", True):
        return

    try:
        iniciar_monitor_firewall()
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            detener_monitor_firewall()
        except Exception:
            pass


if __name__ == "__main__":
    if "--firewall-bg" in sys.argv:
        ejecutar_firewall_en_segundo_plano()
    else:
        app = CyberAnalyzerGUI()
        app.mainloop()
