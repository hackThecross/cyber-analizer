import tkinter as tk
import webbrowser

def mostrar_notificacion_antivirus(root_tk, evento_ataque, callback_abrir_firewall=None):
    """
    Muestra una notificación flotante interactiva estilo antivirus / EDR en la esquina inferior derecha.
    Al hacer clic en la notificación o en el botón de acción, abre directamente la pantalla del Firewall.
    """
    if not root_tk or not root_tk.winfo_exists():
        return

    try:
        toast = tk.Toplevel(root_tk)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)

        ancho = 400
        alto = 165
        screen_w = root_tk.winfo_screenwidth()
        screen_h = root_tk.winfo_screenheight()
        pos_x = screen_w - ancho - 25
        pos_y = screen_h - alto - 60

        toast.geometry(f"{ancho}x{alto}+{pos_x}+{pos_y}")
        toast.configure(bg="#11161d", highlightbackground="#ff4c4c", highlightthickness=2, cursor="hand2")

        def accion_abrir_firewall(event=None):
            if toast.winfo_exists():
                toast.destroy()
            try:
                root_tk.deiconify()
                root_tk.lift()
                root_tk.focus_force()
            except Exception:
                pass
            if callback_abrir_firewall:
                try:
                    callback_abrir_firewall()
                except Exception:
                    pass

        # Header de alerta
        header = tk.Frame(toast, bg="#201010", height=32, cursor="hand2")
        header.pack(fill="x", side="top")
        header.bind("<Button-1>", accion_abrir_firewall)

        lbl_tit = tk.Label(header, text="🛡️ FIREWALL EDR: ATAQUE BLOQUEADO", fg="#ff4c4c", bg="#201010", font=("Consolas", 10, "bold"), cursor="hand2")
        lbl_tit.pack(side="left", padx=10, pady=4)
        lbl_tit.bind("<Button-1>", accion_abrir_firewall)

        btn_close = tk.Button(
            header,
            text="✕",
            fg="#cfd8dc",
            bg="#201010",
            activebackground="#ff4c4c",
            activeforeground="#000000",
            bd=0,
            font=("Consolas", 10, "bold"),
            cursor="hand2",
            command=toast.destroy
        )
        btn_close.pack(side="right", padx=8, pady=2)

        # Cuerpo con información del atacante
        body = tk.Frame(toast, bg="#11161d", cursor="hand2")
        body.pack(fill="both", expand=True, padx=12, pady=4)
        body.bind("<Button-1>", accion_abrir_firewall)

        ip = evento_ataque.get("ip", "Desconocida")
        pais = evento_ataque.get("pais", "Exterior")
        intencion = evento_ataque.get("intencion", "Intrusión de red")
        ruta = evento_ataque.get("ruta_objetivo", "Puerto / Socket")
        es_vpn = evento_ataque.get("es_vpn", False)
        tipo_nodo = evento_ataque.get("tipo_nodo", "Directa")

        badge_vpn = f" [🛡️ {tipo_nodo}]" if es_vpn else " [🌐 Directa]"

        lbl_orig = tk.Label(body, text=f"🔴 Origen: {ip} ({pais}){badge_vpn}", fg="#ffcc00", bg="#11161d", font=("Consolas", 9, "bold"), cursor="hand2")
        lbl_orig.pack(anchor="w")
        lbl_orig.bind("<Button-1>", accion_abrir_firewall)

        lbl_dest = tk.Label(body, text=f"🎯 Objetivo: {ruta}", fg="#00d2ff", bg="#11161d", font=("Consolas", 8), cursor="hand2")
        lbl_dest.pack(anchor="w")
        lbl_dest.bind("<Button-1>", accion_abrir_firewall)

        lbl_int = tk.Label(body, text=f"⚠️ {intencion}", fg="#cfd8dc", bg="#11161d", font=("Consolas", 8), wraplength=370, justify="left", cursor="hand2")
        lbl_int.pack(anchor="w", pady=(1, 0))
        lbl_int.bind("<Button-1>", accion_abrir_firewall)

        # Barra de acciones en la parte inferior del toast
        act_bar = tk.Frame(body, bg="#11161d")
        act_bar.pack(fill="x", pady=(4, 0))

        btn_ver = tk.Button(
            act_bar,
            text="🛡️ Abrir Firewall & Radar ➔",
            bg="#1b2838",
            fg="#00ff9c",
            activebackground="#00ff9c",
            activeforeground="#000000",
            font=("Consolas", 8, "bold"),
            bd=1,
            relief="solid",
            padx=8,
            pady=2,
            cursor="hand2",
            command=accion_abrir_firewall
        )
        btn_ver.pack(side="left")

        tk.Label(act_bar, text="[IP BANEADA EN FIREWALL]", fg="#ff4c4c", bg="#11161d", font=("Consolas", 7, "bold")).pack(side="right", padx=4)

        # Vincular clic en la ventana principal del toast
        toast.bind("<Button-1>", accion_abrir_firewall)

        # Auto cerrar después de 7 segundos
        def auto_destruir():
            if toast.winfo_exists():
                toast.destroy()

        root_tk.after(7000, auto_destruir)

    except Exception:
        pass



def mostrar_notificacion_actualizacion(root_tk, info_update, callback_abrir_update=None):
    """
    Muestra una notificación flotante estilo Cyber anunciando la disponibilidad de una nueva versión en GitHub.
    """
    if not root_tk or not root_tk.winfo_exists():
        return

    try:
        toast = tk.Toplevel(root_tk)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)

        ancho = 420
        alto = 165
        screen_w = root_tk.winfo_screenwidth()
        screen_h = root_tk.winfo_screenheight()
        pos_x = screen_w - ancho - 25
        pos_y = screen_h - alto - 60

        toast.geometry(f"{ancho}x{alto}+{pos_x}+{pos_y}")
        toast.configure(bg="#11161d", highlightbackground="#00ff9c", highlightthickness=2, cursor="hand2")

        def accion_abrir(event=None):
            if toast.winfo_exists():
                toast.destroy()
            try:
                root_tk.deiconify()
                root_tk.lift()
                root_tk.focus_force()
            except Exception:
                pass
            if callback_abrir_update:
                try:
                    callback_abrir_update()
                except Exception:
                    pass

        # Header
        header = tk.Frame(toast, bg="#0d2818", height=32, cursor="hand2")
        header.pack(fill="x", side="top")
        header.bind("<Button-1>", accion_abrir)

        lbl_tit = tk.Label(header, text="🚀 CYBER_ANALYZER: NUEVA VERSIÓN", fg="#00ff9c", bg="#0d2818", font=("Consolas", 10, "bold"), cursor="hand2")
        lbl_tit.pack(side="left", padx=10, pady=4)
        lbl_tit.bind("<Button-1>", accion_abrir)

        btn_close = tk.Button(
            header,
            text="✕",
            fg="#cfd8dc",
            bg="#0d2818",
            activebackground="#00ff9c",
            activeforeground="#000000",
            bd=0,
            font=("Consolas", 10, "bold"),
            cursor="hand2",
            command=toast.destroy
        )
        btn_close.pack(side="right", padx=8, pady=2)

        # Body
        body = tk.Frame(toast, bg="#11161d", cursor="hand2")
        body.pack(fill="both", expand=True, padx=12, pady=6)
        body.bind("<Button-1>", accion_abrir)

        v_nueva = info_update.get("version_remota", "Nueva")
        v_act = info_update.get("version_actual", "1.0.2")
        lbl_ver = tk.Label(body, text=f"🎉 ¡Versión v{v_nueva} disponible en GitHub! (Actual: v{v_act})", fg="#ffcc00", bg="#11161d", font=("Consolas", 9, "bold"), cursor="hand2")
        lbl_ver.pack(anchor="w")
        lbl_ver.bind("<Button-1>", accion_abrir)

        nombre_rel = info_update.get("nombre_release", "")
        if nombre_rel:
            lbl_nom = tk.Label(body, text=f"📌 {nombre_rel}", fg="#00d2ff", bg="#11161d", font=("Consolas", 8), cursor="hand2")
            lbl_nom.pack(anchor="w", pady=(1, 0))
            lbl_nom.bind("<Button-1>", accion_abrir)

        lbl_desc = tk.Label(body, text="Haz clic para ver los cambios y descargar la actualización.", fg="#cfd8dc", bg="#11161d", font=("Consolas", 8), cursor="hand2")
        lbl_desc.pack(anchor="w", pady=(2, 0))
        lbl_desc.bind("<Button-1>", accion_abrir)

        # Botón de acción
        act_bar = tk.Frame(body, bg="#11161d")
        act_bar.pack(fill="x", pady=(6, 0))

        btn_actualizar = tk.Button(
            act_bar,
            text="📥 Ver y Actualizar Ahora ➔",
            bg="#1b2838",
            fg="#00ff9c",
            activebackground="#00ff9c",
            activeforeground="#000000",
            font=("Consolas", 8, "bold"),
            bd=1,
            relief="solid",
            padx=8,
            pady=2,
            cursor="hand2",
            command=accion_abrir
        )
        btn_actualizar.pack(side="left")

        toast.bind("<Button-1>", accion_abrir)

        # Auto cerrar tras 10 segundos
        def auto_destruir():
            if toast.winfo_exists():
                toast.destroy()

        root_tk.after(10000, auto_destruir)

    except Exception:
        pass
