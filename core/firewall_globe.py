import tkinter as tk
import math
import time
import json
import os
import webbrowser

WORLD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "world.geojson")

CYAN = "#00f6ff"
GREEN = "#00ff9c"
RED_BRIGHT = "#ff1744"
WHITE = "#ffffff"


YELLOW_SEL = "#ffcc00"


class ThreatGlobeCanvas(tk.Frame):
    """
    GLOBO TERRÁQUEO 3D DE AMENAZAS (proyección ortográfica).

    API compatible con ThreatMapCanvas:
        - actualizar_ataques(lista)
        - seleccionar_ataque_por_ip(ip)
    """

    def __init__(self, parent, width=1000, height=600, bg="#01080a", **kwargs):
        super().__init__(parent, bg=bg, **kwargs)

        self.bg = bg
        self.width = width
        self.height = height
        self.ataques = []
        self.selected_ip = None
        self.hovered_ip = None
        self.hovered_local = False
        self.attack_positions = []
        self.local_position = None
        self.world_data = None
        self.zoom = 1.0
        self.min_zoom = 0.65
        self.max_zoom = 4.5

        # Rotación del globo
        self.rot_y = 0.0        # giro longitudinal (radianes)
        self.tilt_x = math.radians(20)  # inclinación
        self.auto_spin = True
        self.dragging = False
        self.last_mouse_x = 0
        self.last_mouse_y = 0

        self._cargar_mapa()

        # ─ HUD ─
        self.hud_bar = tk.Frame(self, bg="#020c0f", height=32)
        self.hud_bar.pack(fill="x", side="top")

        tk.Label(self.hud_bar, text="🌐 CYBER THREAT GLOBE",
                 fg=CYAN, bg="#020c0f",
                 font=("Consolas", 11, "bold")).pack(side="left", padx=12, pady=4)

        tk.Label(self.hud_bar, text="LIVE GLOBAL ATTACKS · ARRASTRA PARA GIRAR",
                 fg="#007d83", bg="#020c0f",
                 font=("Consolas", 8, "bold")).pack(side="left", padx=4)

        tk.Button(self.hud_bar, text="⏸ PAUSA GIRO", command=self._toggle_spin,
                  bg="#06171a", fg=CYAN, activebackground="#0b2529",
                  activeforeground=WHITE, bd=1, relief="solid",
                  font=("Consolas", 8, "bold"), cursor="hand2").pack(side="right", padx=5, pady=3)

        tk.Button(self.hud_bar, text="🗺 MAPS", command=self.abrir_google_maps_web,
                  bg="#06171a", fg=CYAN, activebackground="#0b2529",
                  activeforeground=WHITE, bd=1, relief="solid",
                  font=("Consolas", 8, "bold"), cursor="hand2").pack(side="right", padx=3, pady=3)

        tk.Button(self.hud_bar, text="👁 STREET VIEW", command=self.abrir_street_view_seleccion,
                  bg="#06171a", fg="#ff00d4", activebackground="#281126",
                  activeforeground=WHITE, bd=1, relief="solid",
                  font=("Consolas", 8, "bold"), cursor="hand2").pack(side="right", padx=3, pady=3)

        # ─ CANVAS ─
        self.canvas = tk.Canvas(self, bg=self.bg,
                                highlightthickness=1,
                                highlightbackground="#06383d")
        self.canvas.pack(fill="both", expand=True)

        self.canvas.bind("<Configure>", self._on_resize)
        self.canvas.bind("<Motion>", self._on_motion)
        self.canvas.bind("<ButtonPress-1>", self._on_press)
        self.canvas.bind("<B1-Motion>", self._on_drag_motion)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self.canvas.bind("<Double-Button-1>", self._on_double_click)
        self.canvas.bind("<MouseWheel>", self._on_mouse_wheel)
        self.canvas.bind("<Button-4>", lambda event: self._aplicar_zoom(1.12))
        self.canvas.bind("<Button-5>", lambda event: self._aplicar_zoom(0.89))

        self.after(60, self._animar)

    # ============================================================
    # DATOS
    # ============================================================

    def actualizar_ataques(self, ataques):
        self.ataques = ataques or []

    def seleccionar_ataque_por_ip(self, ip):
        self.selected_ip = ip

    def _cargar_mapa(self):
        if not os.path.exists(WORLD_FILE):
            self.world_data = None
            return
        try:
            with open(WORLD_FILE, "r", encoding="utf-8") as f:
                self.world_data = json.load(f)
        except Exception:
            self.world_data = None

    def abrir_google_maps_web(self):
        a = self._ataque_seleccionado() or self._primer_ataque()
        if a:
            webbrowser.open(f"https://www.google.com/maps/search/?api=1&query={a.get('lat')},{a.get('lon')}")

    def abrir_street_view_seleccion(self):
        a = self._ataque_seleccionado() or self._primer_ataque()
        if a:
            webbrowser.open(f"https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={a.get('lat')},{a.get('lon')}")

    def _primer_ataque(self):
        return self.ataques[0] if self.ataques else None

    def _ataque_seleccionado(self):
        for a in self.ataques:
            if a.get("ip") == self.selected_ip:
                return a
        return None

    # ============================================================
    # MATEMÁTICA DEL GLOBO
    # ============================================================

    @staticmethod
    def _latlon_xyz(lon, lat):
        la = math.radians(lat)
        lo = math.radians(lon)
        return (
            math.cos(la) * math.cos(lo),
            math.sin(la),
            math.cos(la) * math.sin(lo),
        )

    def _proyectar(self, lon, lat):
        """Devuelve (x, y, visible) proyectado ortográficamente."""
        x, y, z = self._latlon_xyz(lon, lat)

        # Rotación alrededor del eje Y (giro)
        ry = self.rot_y
        x1 = x * math.cos(ry) + z * math.sin(ry)
        z1 = -x * math.sin(ry) + z * math.cos(ry)
        y1 = y

        # Inclinación alrededor del eje X
        tx = self.tilt_x
        y2 = y1 * math.cos(tx) - z1 * math.sin(tx)
        z2 = y1 * math.sin(tx) + z1 * math.cos(tx)

        cx = self.width / 2
        cy = self.height / 2 + 14
        r = (min(self.width, self.height) / 2 - 30) * self.zoom

        return cx + r * x1, cy - r * y2, z2 > 0

    # ============================================================
    # DIBUJO
    # ============================================================

    def _on_resize(self, event):
        self.width = max(event.width, 400)
        self.height = max(event.height, 300)

    def _animar(self):
        if not self.winfo_exists():
            return
        if self.auto_spin and not self.dragging:
            self.rot_y += 0.004
        try:
            self.redibujar()
        except tk.TclError:
            return
        self.after(60, self._animar)

    def redibujar(self):
        c = self.canvas
        c.delete("all")

        cx = self.width / 2
        cy = self.height / 2 + 14
        r = (min(self.width, self.height) / 2 - 30) * self.zoom
        self.attack_positions = []
        self.local_position = None

        # ─ Halo exterior / atmósfera ─
        for glow in range(6, 0, -1):
            rr = r + glow * 3
            c.create_oval(cx - rr, cy - rr, cx + rr, cy + rr,
                          outline="#03333b", width=1)

        # ─ Esfera base ─
        c.create_oval(cx - r, cy - r, cx + r, cy + r,
                      fill="#02141a", outline=CYAN, width=2)

        # ─ Graticule (meridianos y paralelos) ─
        for lon in range(-180, 180, 30):
            pts = []
            vis = False
            for lat in range(-90, 91, 6):
                x, y, v = self._proyectar(lon, lat)
                vis = vis or v
                pts.extend([x, y])
            if vis:
                c.create_line(pts, fill="#07424a", width=1)

        for lat in range(-60, 61, 30):
            pts = []
            vis = False
            for lon in range(-180, 181, 6):
                x, y, v = self._proyectar(lon, lat)
                vis = vis or v
                pts.extend([x, y])
            if vis:
                c.create_line(pts, fill="#07424a", width=1)

        # ─ Continentes (líneas de frontera) ─
        if self.world_data:
            for feature in self.world_data.get("features", []):
                geom = feature.get("geometry")
                if not geom:
                    continue
                polys = []
                if geom.get("type") == "Polygon":
                    polys = [geom["coordinates"][0]]
                elif geom.get("type") == "MultiPolygon":
                    polys = [p[0] for p in geom["coordinates"]]

                for poly in polys:
                    prev = None
                    for coord in poly:
                        if len(coord) < 2:
                            continue
                        x, y, v = self._proyectar(coord[0], coord[1])
                        if prev is not None and v:
                            c.create_line(prev[0], prev[1], x, y,
                                          fill="#00c8cf", width=1)
                        prev = (x, y, v)

        # ─ Nodo local (EDR Shield) ─
        lx, ly, lv = self._proyectar(-3.7038, 40.4168)
        if lv:
            pulse = (math.sin(time.monotonic() * 1000 * 0.02) + 1) / 2
            rr = 8 + pulse * 5
            c.create_oval(lx - rr * 2, ly - rr * 2, lx + rr * 2, ly + rr * 2,
                          outline="#008f72", width=1)
            c.create_oval(lx - 5, ly - 5, lx + 5, ly + 5,
                          fill=GREEN, outline=WHITE, width=1)
            self.local_position = {"x": lx, "y": ly}
            c.create_text(lx, ly + 22, text="◆ EDR SHIELD // MY PC",
                          fill=GREEN, font=("Consolas", 8, "bold"))

        # ─ Ataques ─
        for idx, atk in enumerate(self.ataques[:40]):
            try:
                lat = float(atk.get("lat", 0))
                lon = float(atk.get("lon", 0))
            except (TypeError, ValueError):
                continue

            if atk.get("es_vpn"):
                color = "#ff00d4"
            elif atk.get("severidad") == "CRÍTICO":
                color = RED_BRIGHT
            else:
                color = "#ff3030"

            ax, ay, av = self._proyectar(lon, lat)
            if av:
                pulse = (math.sin(idx + 1) + 1) / 2
                rad = 4 + pulse * 3
                es_sel = (atk.get("ip") == self.selected_ip)
                if es_sel:
                    c.create_oval(ax - rad * 3, ay - rad * 3,
                                  ax + rad * 3, ay + rad * 3,
                                  outline=YELLOW_SEL, width=2)
                c.create_oval(ax - rad, ay - rad, ax + rad, ay + rad,
                              fill=color, outline=WHITE if es_sel else "",
                              width=2 if es_sel else 1)
                codigo_pais = str(atk.get("codigo_pais") or atk.get("pais", "??")[:2]).upper()
                ip = atk.get("ip", "IP desconocida")
                c.create_text(ax + 10, ay - 10, anchor="sw",
                              text=f"{ip} · {codigo_pais}", fill=WHITE,
                              font=("Consolas", 7, "bold"))
                self.attack_positions.append({"x": ax, "y": ay, "data": atk})

                # Ráfaga animada hacia el nodo local, no una ruta estática.
                if lv and idx < 12:
                    self._dibujar_ataque_animado(
                        lon, lat, -3.7038, 40.4168, color, idx
                    )

        if self.hovered_ip:
            ataque_hover = next(
                (a for a in self.ataques if a.get("ip") == self.hovered_ip), None
            )
            if ataque_hover:
                self._dibujar_info_hover(ataque_hover)
        elif self.hovered_local:
            self._dibujar_info_equipo()

        # ─ Etiqueta de estado ─
        c.create_text(14, self.height - 12, anchor="w",
                      text=f"◈ ATAQUES EN PANTALLA: {len(self.ataques)}   |   ROTACIÓN: {math.degrees(self.rot_y) % 360:.0f}°",
                      fill="#007d83", font=("Consolas", 8))

    def _dibujar_info_hover(self, ataque):
        """Panel informativo para el punto que está bajo el cursor."""
        posicion = next(
            (p for p in self.attack_positions if p["data"].get("ip") == ataque.get("ip")), None
        )
        if not posicion:
            return
        x = min(posicion["x"] + 16, self.width - 285)
        y = max(36, posicion["y"] - 105)
        self.canvas.create_rectangle(x, y, x + 270, y + 92,
                                     fill="#020c0f", outline=CYAN, width=1)
        self.canvas.create_text(x + 9, y + 12, anchor="w",
                                text=f"IP: {ataque.get('ip', 'DESCONOCIDA')}",
                                fill=RED_BRIGHT, font=("Consolas", 9, "bold"))
        self.canvas.create_text(x + 9, y + 31, anchor="w",
                                text=f"ORIGEN: {ataque.get('pais', 'Desconocido')} ({ataque.get('codigo_pais', '??')})",
                                fill=WHITE, font=("Consolas", 8))
        self.canvas.create_text(x + 9, y + 49, anchor="w",
                                text=f"INTENTO: {ataque.get('intencion', 'No identificado')}",
                                fill="#ffcc00", font=("Consolas", 8))
        self.canvas.create_text(x + 9, y + 67, anchor="w",
                                text=f"OBJETIVO: {ataque.get('ruta_objetivo', 'EDR local')}",
                                fill=CYAN, font=("Consolas", 8))
        self.canvas.create_text(x + 9, y + 83, anchor="w",
                                text="DOBLE CLIC → ABRIR UBICACIÓN EN GOOGLE MAPS",
                                fill="#6e989c", font=("Consolas", 7, "bold"))

    def _dibujar_info_equipo(self):
        """Ficha del equipo local con la misma interacción que un atacante."""
        if not self.local_position:
            return
        x = min(self.local_position["x"] + 16, self.width - 270)
        y = max(36, self.local_position["y"] - 82)
        self.canvas.create_rectangle(x, y, x + 255, y + 68,
                                     fill="#020c0f", outline=GREEN, width=1)
        self.canvas.create_text(x + 9, y + 13, anchor="w",
                                text="TU EQUIPO · EDR SHIELD", fill=GREEN,
                                font=("Consolas", 9, "bold"))
        self.canvas.create_text(x + 9, y + 32, anchor="w",
                                text="ESTADO: PROTEGIDO Y MONITOREANDO", fill=WHITE,
                                font=("Consolas", 8))
        self.canvas.create_text(x + 9, y + 50, anchor="w",
                                text="DOBLE CLIC → ABRIR UBICACIÓN EN GOOGLE MAPS", fill="#6e989c",
                                font=("Consolas", 7, "bold"))

    def _punto_arco(self, lon1, lat1, lon2, lat2, t):
        """Devuelve un punto de la ruta de gran círculo ya proyectado."""
        x1, y1, z1 = self._latlon_xyz(lon1, lat1)
        x2, y2, z2 = self._latlon_xyz(lon2, lat2)
        dot = max(-1, min(1, x1 * x2 + y1 * y2 + z1 * z2))
        omega = math.acos(dot)
        if omega < 1e-6:
            sx, sy, sz = x1, y1, z1
        else:
            seno = math.sin(omega)
            a = math.sin((1 - t) * omega) / seno
            b = math.sin(t * omega) / seno
            sx, sy, sz = a * x1 + b * x2, a * y1 + b * y2, a * z1 + b * z2

        lon_p = math.degrees(math.atan2(sz, sx))
        lat_p = math.degrees(math.asin(max(-1, min(1, sy))))
        return self._proyectar(lon_p, lat_p)

    def _dibujar_ataque_animado(self, lon1, lat1, lon2, lat2, color, idx):
        """Ráfaga con rastro y punta que recorre la ruta hasta el EDR."""
        progreso = (time.monotonic() * 0.32 + idx * 0.173) % 1.0
        rastro = []
        for paso in range(7, -1, -1):
            t = progreso - paso * 0.025
            if t < 0:
                continue
            px, py, visible = self._punto_arco(lon1, lat1, lon2, lat2, t)
            if visible:
                rastro.append((px, py))

        for inicio, fin in zip(rastro, rastro[1:]):
            self.canvas.create_line(*inicio, *fin, fill=color, width=2)

        hx, hy, visible = self._punto_arco(lon1, lat1, lon2, lat2, progreso)
        bx, by, _ = self._punto_arco(lon1, lat1, lon2, lat2, max(0, progreso - 0.035))
        if not visible:
            return

        self.canvas.create_oval(hx - 7, hy - 7, hx + 7, hy + 7,
                                outline=color, width=1)
        self.canvas.create_oval(hx - 3, hy - 3, hx + 3, hy + 3,
                                fill=WHITE, outline=color, width=1)
        dx, dy = hx - bx, hy - by
        longitud = math.hypot(dx, dy) or 1
        ux, uy = dx / longitud, dy / longitud
        nx, ny = -uy, ux
        punta = (hx + ux * 8, hy + uy * 8)
        ala_1 = (hx - ux * 4 + nx * 4, hy - uy * 4 + ny * 4)
        ala_2 = (hx - ux * 4 - nx * 4, hy - uy * 4 - ny * 4)
        self.canvas.create_polygon(*punta, *ala_1, *ala_2,
                                   fill=color, outline=WHITE)

    # ============================================================
    # INTERACCIÓN
    # ============================================================

    def _on_press(self, event):
        self.dragging = True
        self.last_mouse_x = event.x
        self.last_mouse_y = event.y
        ataque = self._ataque_en_posicion(event.x, event.y)
        if ataque:
            self.selected_ip = ataque.get("ip")

    def _on_motion(self, event):
        ataque = self._ataque_en_posicion(event.x, event.y)
        nueva_ip = ataque.get("ip") if ataque else None
        nuevo_local = not ataque and self._nodo_local_en_posicion(event.x, event.y)
        if nueva_ip != self.hovered_ip or nuevo_local != self.hovered_local:
            self.hovered_ip = nueva_ip
            self.hovered_local = nuevo_local
            self.canvas.configure(cursor="hand2" if ataque or nuevo_local else "")
            self.redibujar()

    def _on_drag_motion(self, event):
        if not self.dragging:
            return
        dx = event.x - self.last_mouse_x
        dy = event.y - self.last_mouse_y
        self.rot_y += dx * 0.008
        self.tilt_x = max(-1.2, min(1.2, self.tilt_x + dy * 0.006))
        self.last_mouse_x = event.x
        self.last_mouse_y = event.y

    def _on_release(self, event):
        self.dragging = False

    def _ataque_en_posicion(self, x, y):
        """Encuentra el marcador atacado sin hacer clic sobre su etiqueta."""
        for posicion in self.attack_positions:
            if math.hypot(x - posicion["x"], y - posicion["y"]) <= 15:
                return posicion["data"]
        return None

    def _nodo_local_en_posicion(self, x, y):
        if not self.local_position:
            return False
        return math.hypot(
            x - self.local_position["x"], y - self.local_position["y"]
        ) <= 17

    def _on_double_click(self, event):
        ataque = self._ataque_en_posicion(event.x, event.y)
        if ataque:
            self.selected_ip = ataque.get("ip")
            lat, lon = ataque.get("lat"), ataque.get("lon")
        elif self._nodo_local_en_posicion(event.x, event.y):
            lat, lon = 40.4168, -3.7038
        else:
            return
        webbrowser.open(
            "https://www.google.com/maps/search/?api=1"
            f"&query={lat},{lon}"
        )

    def _on_mouse_wheel(self, event):
        self._aplicar_zoom(1.12 if event.delta > 0 else 0.89)

    def _aplicar_zoom(self, factor):
        self.zoom = max(self.min_zoom, min(self.max_zoom, self.zoom * factor))
        self.redibujar()

    def _toggle_spin(self):
        self.auto_spin = not self.auto_spin
