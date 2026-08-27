import tkinter as tk
import math
import json
import os
import random
import webbrowser
import time


# ================================================================
# CONFIGURACIÓN
# ================================================================

WORLD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "world.geojson")

BG = "#01080a"

CYAN = "#00f6ff"
CYAN_DARK = "#007d83"
CYAN_DIM = "#063d43"

GREEN = "#00ff9c"
GREEN_DARK = "#006b55"

RED = "#ff304f"
RED_BRIGHT = "#ff1744"

YELLOW = "#ffcc00"

WHITE = "#d9ffff"

PANEL_BG = "#031214"
PANEL_BORDER = "#075b60"


# ================================================================
# CLASE
# ================================================================

class ThreatMapCanvas(tk.Frame):

    """
    MAPA MUNDIAL CYBER THREAT

    Características:

        - Mapa mundial plano
        - Fronteras reales
        - Grid cyber
        - Ataques animados
        - Proyectiles viajando
        - Estelas
        - Nodos pulsantes
        - HUD
        - Paneles
        - Zoom
        - Pan
        - Hover
        - Selección
        - Google Maps
    """

    def __init__(
        self,
        parent,
        width=1000,
        height=600,
        bg=BG,
        **kwargs
    ):

        super().__init__(
            parent,
            bg=bg,
            **kwargs
        )

        self.bg = bg

        self.width = width
        self.height = height

        # ========================================================
        # DATOS
        # ========================================================

        self.ataques = []

        self.node_positions = []

        self.hovered_attack = None

        # ========================================================
        # MAPA
        # ========================================================

        self.world_data = None

        self.map_margin_x = 30
        self.map_margin_y = 40

        self.map_width = 0
        self.map_height = 0

        # ========================================================
        # ZOOM / PAN
        # ========================================================

        self.zoom = 1.0

        self.min_zoom = 0.70
        self.max_zoom = 3.0

        self.pan_x = 0
        self.pan_y = 0

        # ========================================================
        # MOUSE
        # ========================================================

        self.dragging_left = False
        self.dragging_right = False

        self.last_mouse_x = 0
        self.last_mouse_y = 0

        # ========================================================
        # ANIMACIÓN
        # ========================================================

        self.animating = True

        self.animation_tick = 0

        # ========================================================
        # PARTÍCULAS
        # ========================================================

        self.background_particles = []

        self._crear_particulas()

        # ========================================================
        # ATAQUES ANIMADOS
        # ========================================================

        self.attack_particles = {}

        # ========================================================
        # HUD
        # ========================================================

        self.hud_bar = tk.Frame(
            self,
            bg="#020c0f",
            height=32,
            bd=0
        )

        self.hud_bar.pack(
            fill="x",
            side="top"
        )

        tk.Label(
            self.hud_bar,
            text="◈ CYBER THREAT MAP",
            fg=CYAN,
            bg="#020c0f",
            font=("Consolas", 11, "bold")
        ).pack(
            side="left",
            padx=12,
            pady=4
        )

        tk.Label(
            self.hud_bar,
            text="LIVE GLOBAL ATTACKS",
            fg=CYAN_DARK,
            bg="#020c0f",
            font=("Consolas", 8, "bold")
        ).pack(
            side="left",
            padx=4
        )

        tk.Button(
            self.hud_bar,
            text="🗺 MAPS",
            command=self.abrir_google_maps_web,
            bg="#06171a",
            fg=CYAN,
            activebackground="#0b2529",
            activeforeground=WHITE,
            bd=1,
            relief="solid",
            font=("Consolas", 8, "bold"),
            cursor="hand2"
        ).pack(
            side="right",
            padx=5,
            pady=3
        )

        tk.Button(
            self.hud_bar,
            text="👁 STREET VIEW",
            command=self.abrir_street_view_seleccion,
            bg="#06171a",
            fg="#ff00d4",
            activebackground="#281126",
            activeforeground=WHITE,
            bd=1,
            relief="solid",
            font=("Consolas", 8, "bold"),
            cursor="hand2"
        ).pack(
            side="right",
            padx=3,
            pady=3
        )

        # ========================================================
        # CANVAS
        # ========================================================

        self.canvas = tk.Canvas(
            self,
            bg=self.bg,
            highlightthickness=1,
            highlightbackground="#06383d"
        )

        self.canvas.pack(
            fill="both",
            expand=True
        )

        # ========================================================
        # EVENTOS
        # ========================================================

        self.canvas.bind(
            "<Configure>",
            self._on_resize
        )

        self.canvas.bind(
            "<Motion>",
            self._on_hover
        )

        self.canvas.bind(
            "<ButtonPress-1>",
            self._mouse_left_down
        )

        self.canvas.bind(
            "<B1-Motion>",
            self._mouse_left_drag
        )

        self.canvas.bind(
            "<ButtonRelease-1>",
            self._mouse_left_up
        )

        self.canvas.bind(
            "<ButtonPress-3>",
            self._mouse_right_down
        )

        self.canvas.bind(
            "<B3-Motion>",
            self._mouse_right_drag
        )

        self.canvas.bind(
            "<ButtonRelease-3>",
            self._mouse_right_up
        )

        self.canvas.bind(
            "<MouseWheel>",
            self._mouse_wheel
        )

        self.canvas.bind(
            "<Button-4>",
            self._mouse_wheel_linux
        )

        self.canvas.bind(
            "<Button-5>",
            self._mouse_wheel_linux
        )

        self.canvas.bind(
            "<Double-Button-1>",
            self._on_double_click_map
        )

        # ========================================================
        # CARGAR MAPA
        # ========================================================

        self._cargar_mapa()

        # ========================================================
        # ANIMACIÓN
        # ========================================================

        self.after(
            80,
            self._animar
        )

    # ============================================================
    # PARTÍCULAS
    # ============================================================

    def _crear_particulas(self):

        random.seed(91237)

        self.background_particles = []

        for _ in range(220):

            self.background_particles.append(
                {
                    "x": random.random(),
                    "y": random.random(),
                    "size": random.choice(
                        [1, 1, 1, 2]
                    ),
                    "alpha": random.random(),
                    "speed": random.uniform(
                        0.0003,
                        0.0015
                    )
                }
            )

    # ============================================================
    # CARGAR GEOJSON
    # ============================================================

    def _cargar_mapa(self):

        if not os.path.exists(WORLD_FILE):

            self.canvas.delete("all")

            self.canvas.create_text(
                self.width / 2,
                self.height / 2,
                text=(
                    "WORLD MAP DATA NOT FOUND\n\n"
                    "Coloca el archivo:\n"
                    "world.geojson\n\n"
                    "en la misma carpeta del programa."
                ),
                fill=RED,
                font=(
                    "Consolas",
                    12,
                    "bold"
                ),
                justify="center"
            )

            return

        try:

            with open(
                WORLD_FILE,
                "r",
                encoding="utf-8"
            ) as f:

                self.world_data = json.load(f)

        except Exception as e:

            self.world_data = None

            self.canvas.create_text(
                self.width / 2,
                self.height / 2,
                text=f"ERROR MAP DATA\n{e}",
                fill=RED,
                font=("Consolas", 10)
            )

    # ============================================================
    # RESIZE
    # ============================================================

    def _on_resize(
        self,
        event
    ):

        self.width = max(
            event.width,
            400
        )

        self.height = max(
            event.height,
            300
        )

        self.redibujar_mapa()

    # ============================================================
    # PROYECCIÓN MAPA
    # ============================================================

    def geo_a_canvas(
        self,
        lon,
        lat
    ):

        # --------------------------------------------------------
        # MAPA EQUIRECTANGULAR
        # --------------------------------------------------------

        left = self.map_margin_x
        top = self.map_margin_y

        w = (
            self.width
            - self.map_margin_x * 2
        )

        h = (
            self.height
            - self.map_margin_y * 2
        )

        # mantener proporción mundial

        x = (
            (lon + 180)
            / 360
        )

        y = (
            (90 - lat)
            / 180
        )

        px = (
            left
            + x * w
        )

        py = (
            top
            + y * h
        )

        # zoom alrededor del centro

        cx = self.width / 2
        cy = self.height / 2

        px = (
            cx
            + (px - cx)
            * self.zoom
            + self.pan_x
        )

        py = (
            cy
            + (py - cy)
            * self.zoom
            + self.pan_y
        )

        return (
            px,
            py
        )

    # ============================================================
    # DIBUJAR FONDO
    # ============================================================

    def dibujar_fondo(self):

        self.canvas.create_rectangle(
            0,
            0,
            self.width,
            self.height,
            fill="#01080a",
            outline=""
        )

        # --------------------------------------------------------
        # GRID PRINCIPAL
        # --------------------------------------------------------

        grid = 25

        offset_x = (
            self.pan_x
            % grid
        )

        offset_y = (
            self.pan_y
            % grid
        )

        for x in range(
            -grid,
            self.width + grid,
            grid
        ):

            xx = x + offset_x

            self.canvas.create_line(
                xx,
                0,
                xx,
                self.height,
                fill="#06272b",
                width=1
            )

        for y in range(
            -grid,
            self.height + grid,
            grid
        ):

            yy = y + offset_y

            self.canvas.create_line(
                0,
                yy,
                self.width,
                yy,
                fill="#06272b",
                width=1
            )

        # --------------------------------------------------------
        # GRID FINO
        # --------------------------------------------------------

        fine = 8

        for x in range(
            0,
            self.width,
            fine
        ):

            self.canvas.create_line(
                x,
                0,
                x,
                self.height,
                fill="#03191c",
                width=1
            )

        for y in range(
            0,
            self.height,
            fine
        ):

            self.canvas.create_line(
                0,
                y,
                self.width,
                y,
                fill="#03191c",
                width=1
            )

        # --------------------------------------------------------
        # PARTICULAS
        # --------------------------------------------------------

        for p in self.background_particles:

            x = (
                p["x"]
                * self.width
            )

            y = (
                p["y"]
                * self.height
            )

            size = p["size"]

            self.canvas.create_rectangle(
                x,
                y,
                x + size,
                y + size,
                fill="#08777a",
                outline=""
            )

    # ============================================================
    # DIBUJAR MAPA
    # ============================================================

    def dibujar_mapa(self):

        if not self.world_data:

            return

        for feature in self.world_data.get(
            "features",
            []
        ):

            geometry = feature.get(
                "geometry"
            )

            if not geometry:
                continue

            geo_type = geometry.get(
                "type"
            )

            coordinates = geometry.get(
                "coordinates"
            )

            if geo_type == "Polygon":

                self._dibujar_polygon(
                    coordinates
                )

            elif geo_type == "MultiPolygon":

                for polygon in coordinates:

                    self._dibujar_polygon(
                        polygon
                    )

    # ============================================================
    # POLYGON
    # ============================================================

    def _dibujar_polygon(
        self,
        polygon
    ):

        if not polygon:
            return

        # --------------------------------------------------------
        # PRIMER ANILLO = FRONTERA
        # --------------------------------------------------------

        exterior = polygon[0]

        puntos = []

        for coord in exterior:

            if len(coord) < 2:
                continue

            lon = coord[0]
            lat = coord[1]

            x, y = self.geo_a_canvas(
                lon,
                lat
            )

            puntos.extend(
                [
                    x,
                    y
                ]
            )

        if len(puntos) < 6:
            return

        # --------------------------------------------------------
        # RELLENO
        # --------------------------------------------------------

        self.canvas.create_polygon(
            puntos,
            fill="#021719",
            outline="#00aeb5",
            width=1
        )

        # --------------------------------------------------------
        # BORDE BRILLANTE
        # --------------------------------------------------------

        self.canvas.create_line(
            puntos,
            fill="#00e6eb",
            width=1,
            smooth=True
        )

        # --------------------------------------------------------
        # ISLAS / HUECOS
        # --------------------------------------------------------

        for interior in polygon[1:]:

            pts = []

            for coord in interior:

                if len(coord) < 2:
                    continue

                x, y = self.geo_a_canvas(
                    coord[0],
                    coord[1]
                )

                pts.extend(
                    [
                        x,
                        y
                    ]
                )

            if len(pts) >= 6:

                self.canvas.create_polygon(
                    pts,
                    fill="#01080a",
                    outline="#006e73",
                    width=1
                )

    # ============================================================
    # DOT MATRIX SOBRE MAPA
    # ============================================================

    def dibujar_puntos_mapa(self):

        if not self.world_data:
            return

        # puntos distribuidos sobre el mapa
        # para darle aspecto tecnológico

        random.seed(7744)

        for _ in range(900):

            lon = random.uniform(
                -180,
                180
            )

            lat = random.uniform(
                -60,
                75
            )

            x, y = self.geo_a_canvas(
                lon,
                lat
            )

            if (
                x < 0
                or x > self.width
                or y < 0
                or y > self.height
            ):
                continue

            self.canvas.create_rectangle(
                x,
                y,
                x + 1,
                y + 1,
                fill="#08777b",
                outline=""
            )

    # ============================================================
    # COORDENADAS
    # ============================================================

    def _coord_valida(
        self,
        ataque
    ):

        try:

            lat = float(
                ataque.get(
                    "lat",
                    0
                )
            )

            lon = float(
                ataque.get(
                    "lon",
                    0
                )
            )

            return (
                -90 <= lat <= 90
                and
                -180 <= lon <= 180
            )

        except:

            return False

    # ============================================================
    # NODO LOCAL
    # ============================================================

    def dibujar_nodo_local(self):

        # --------------------------------------------------------
        # TU PC
        # --------------------------------------------------------

        lon = -3.7038
        lat = 40.4168

        x, y = self.geo_a_canvas(
            lon,
            lat
        )

        # --------------------------------------------------------
        # PULSO
        # --------------------------------------------------------

        pulse = (
            math.sin(
                self.animation_tick
                * 0.08
            )
            + 1
        ) / 2

        radius = (
            10
            + pulse * 8
        )

        # --------------------------------------------------------
        # HALO
        # --------------------------------------------------------

        self.canvas.create_oval(
            x - radius * 2,
            y - radius * 2,
            x + radius * 2,
            y + radius * 2,
            outline="#008f72",
            width=1
        )

        self.canvas.create_oval(
            x - radius,
            y - radius,
            x + radius,
            y + radius,
            outline=GREEN,
            width=2
        )

        # --------------------------------------------------------
        # NODO
        # --------------------------------------------------------

        self.canvas.create_oval(
            x - 5,
            y - 5,
            x + 5,
            y + 5,
            fill=RED_BRIGHT,
            outline="#ffffff",
            width=1
        )

        # --------------------------------------------------------
        # TEXTO
        # --------------------------------------------------------

        self.canvas.create_text(
            x,
            y + 25,
            text="◆ EDR SHIELD // MY PC",
            fill=GREEN,
            font=(
                "Consolas",
                8,
                "bold"
            )
        )

        return (
            x,
            y
        )

    # ============================================================
    # ATAQUES
    # ============================================================

    def dibujar_ataques(
        self,
        destino
    ):

        self.node_positions = []

        if destino is None:
            return

        target_x, target_y = destino

        # --------------------------------------------------------
        # MAX 30 ATAQUES
        # --------------------------------------------------------

        ataques = self.ataques[:30]

        for index, ataque in enumerate(
            ataques
        ):

            if not self._coord_valida(
                ataque
            ):
                continue

            lat = float(
                ataque.get(
                    "lat",
                    0
                )
            )

            lon = float(
                ataque.get(
                    "lon",
                    0
                )
            )

            source_x, source_y = (
                self.geo_a_canvas(
                    lon,
                    lat
                )
            )

            # ----------------------------------------------------
            # COLOR
            # ----------------------------------------------------

            if ataque.get(
                "es_vpn",
                False
            ):

                color = "#ff00d4"

            elif ataque.get(
                "severidad"
            ) == "CRÍTICO":

                color = "#ff1744"

            else:

                color = "#ff3030"

            # ----------------------------------------------------
            # CONTROL POINT
            # ----------------------------------------------------

            mid_x = (
                source_x
                + target_x
            ) / 2

            mid_y = (
                source_y
                + target_y
            ) / 2

            distancia = math.hypot(
                target_x - source_x,
                target_y - source_y
            )

            curva = max(
                25,
                min(
                    180,
                    distancia * 0.18
                )
            )

            ctrl_x = mid_x
            ctrl_y = mid_y - curva

            # ----------------------------------------------------
            # TRAYECTORIA
            # ----------------------------------------------------

            self._dibujar_curva(
                source_x,
                source_y,
                ctrl_x,
                ctrl_y,
                target_x,
                target_y,
                color
            )

            # ----------------------------------------------------
            # ANIMACIÓN DEL ATAQUE
            # ----------------------------------------------------

            key = ataque.get(
                "ip",
                str(index)
            )

            if key not in self.attack_particles:

                self.attack_particles[key] = (
                    index
                    * 0.073
                ) % 1.0

            progress = (
                self.attack_particles[key]
            )

            # ----------------------------------------------------
            # PUNTO VIAJANDO
            # ----------------------------------------------------

            px, py = (
                self._bezier(
                    source_x,
                    source_y,
                    ctrl_x,
                    ctrl_y,
                    target_x,
                    target_y,
                    progress
                )
            )

            # ----------------------------------------------------
            # ESTELA
            # ----------------------------------------------------

            for trail in range(
                1,
                8
            ):

                t = progress - (
                    trail * 0.018
                )

                if t < 0:
                    continue

                tx, ty = (
                    self._bezier(
                        source_x,
                        source_y,
                        ctrl_x,
                        ctrl_y,
                        target_x,
                        target_y,
                        t
                    )
                )

                size = max(
                    1,
                    4 - trail * 0.4
                )

                self.canvas.create_oval(
                    tx - size,
                    ty - size,
                    tx + size,
                    ty + size,
                    fill=color,
                    outline=""
                )

            # ----------------------------------------------------
            # GLOW DEL PROYECTIL
            # ----------------------------------------------------

            for glow in range(
                4,
                0,
                -1
            ):

                r = (
                    glow
                    * 3
                )

                self.canvas.create_oval(
                    px - r,
                    py - r,
                    px + r,
                    py + r,
                    outline=color,
                    width=1
                )

            # ----------------------------------------------------
            # PROYECTIL
            # ----------------------------------------------------

            self.canvas.create_oval(
                px - 3,
                py - 3,
                px + 3,
                py + 3,
                fill="#ffffff",
                outline=color,
                width=2
            )

            # ----------------------------------------------------
            # NODO ORIGEN
            # ----------------------------------------------------

            pulse = (
                math.sin(
                    self.animation_tick
                    * 0.12
                    + index
                )
                + 1
            ) / 2

            r = (
                4
                + pulse * 3
            )

            self.canvas.create_oval(
                source_x - r,
                source_y - r,
                source_x + r,
                source_y + r,
                fill=color,
                outline="#ffffff",
                width=1
            )

            # ----------------------------------------------------
            # HALO
            # ----------------------------------------------------

            self.canvas.create_oval(
                source_x - 11,
                source_y - 11,
                source_x + 11,
                source_y + 11,
                outline="#8a1425",
                width=1
            )

            # ----------------------------------------------------
            # ETIQUETA
            # ----------------------------------------------------

            ip = ataque.get(
                "ip",
                "UNKNOWN"
            )

            pais = ataque.get(
                "codigo_pais",
                ataque.get(
                    "pais",
                    "?"
                )
            )

            self.canvas.create_text(
                source_x,
                source_y - 15,
                text=f"{pais} {ip}",
                fill="#eaffff",
                font=(
                    "Consolas",
                    7,
                    "bold"
                )
            )

            # ----------------------------------------------------
            # POSICIÓN PARA HOVER
            # ----------------------------------------------------

            self.node_positions.append(
                {
                    "x": source_x,
                    "y": source_y,
                    "data": ataque
                }
            )

    # ============================================================
    # BEZIER
    # ============================================================

    def _bezier(
        self,
        x1,
        y1,
        cx,
        cy,
        x2,
        y2,
        t
    ):

        u = 1 - t

        x = (
            u * u * x1
            +
            2 * u * t * cx
            +
            t * t * x2
        )

        y = (
            u * u * y1
            +
            2 * u * t * cy
            +
            t * t * y2
        )

        return (
            x,
            y
        )

    # ============================================================
    # CURVA
    # ============================================================

    def _dibujar_curva(
        self,
        x1,
        y1,
        cx,
        cy,
        x2,
        y2,
        color
    ):

        puntos = []

        for i in range(
            31
        ):

            t = i / 30

            x, y = (
                self._bezier(
                    x1,
                    y1,
                    cx,
                    cy,
                    x2,
                    y2,
                    t
                )
            )

            puntos.extend(
                [
                    x,
                    y
                ]
            )

        self.canvas.create_line(
            puntos,
            fill="#42151d",
            width=3,
            smooth=True
        )

        self.canvas.create_line(
            puntos,
            fill=color,
            width=1,
            dash=(3, 6),
            smooth=True
        )

    # ============================================================
    # PANEL
    # ============================================================

    def _panel(
        self,
        x1,
        y1,
        x2,
        y2
    ):

        self.canvas.create_rectangle(
            x1,
            y1,
            x2,
            y2,
            fill=PANEL_BG,
            outline=PANEL_BORDER,
            width=1
        )

        # esquinas cyber

        size = 8

        self.canvas.create_line(
            x1,
            y1 + size,
            x1,
            y1,
            x1 + size,
            y1,
            fill=CYAN,
            width=1
        )

        self.canvas.create_line(
            x2 - size,
            y1,
            x2,
            y1,
            x2,
            y1 + size,
            fill=CYAN,
            width=1
        )

        self.canvas.create_line(
            x1,
            y2 - size,
            x1,
            y2,
            x1 + size,
            y2,
            fill=CYAN,
            width=1
        )

        self.canvas.create_line(
            x2 - size,
            y2,
            x2,
            y2,
            x2,
            y2 - size,
            fill=CYAN,
            width=1
        )

    # ============================================================
    # HUD
    # ============================================================

    def dibujar_hud(
        self
    ):

        # Paneles superpuestos (HUD, países, feed y estado) desactivados:
        # el usuario pidió un mapa limpio, sin cuadros encima.
        return
    def _dibujar_hud_original(
        self
    ):

        # --------------------------------------------------------
        # TITULO
        # --------------------------------------------------------

        self.canvas.create_text(
            20,
            18,
            anchor="w",
            text="CYBER THREAT MAP",
            fill=CYAN,
            font=(
                "Consolas",
                15,
                "bold"
            )
        )

        self.canvas.create_text(
            20,
            38,
            anchor="w",
            text="LIVE GLOBAL ATTACKS",
            fill="#00aeb5",
            font=(
                "Consolas",
                8,
                "bold"
            )
        )

        # --------------------------------------------------------
        # STATUS
        # --------------------------------------------------------

        panel_w = 190
        panel_h = 145

        x2 = (
            self.width
            - 20
        )

        x1 = (
            x2
            - panel_w
        )

        y1 = 18
        y2 = y1 + panel_h

        self._panel(
            x1,
            y1,
            x2,
            y2
        )

        self.canvas.create_text(
            x1 + 12,
            y1 + 15,
            anchor="w",
            text="ATTACK STATUS",
            fill=CYAN,
            font=(
                "Consolas",
                9,
                "bold"
            )
        )

        total = len(
            self.ataques
        )

        live = min(
            total,
            20
        )

        critical = sum(
            1
            for a in self.ataques
            if a.get(
                "severidad"
            ) == "CRÍTICO"
        )

        vpn = sum(
            1
            for a in self.ataques
            if a.get(
                "es_vpn",
                False
            )
        )

        rows = [
            (
                "TOTAL ATTACKS",
                total,
                CYAN
            ),
            (
                "LIVE ATTACKS",
                live,
                YELLOW
            ),
            (
                "HIGH RISK",
                critical,
                RED
            ),
            (
                "VPN SOURCES",
                vpn,
                "#ff00d4"
            ),
            (
                "EDR STATUS",
                "ACTIVE",
                GREEN
            )
        ]

        yy = y1 + 38

        for name, value, color in rows:

            self.canvas.create_text(
                x1 + 12,
                yy,
                anchor="w",
                text=name,
                fill="#779397",
                font=(
                    "Consolas",
                    7
                )
            )

            self.canvas.create_text(
                x2 - 12,
                yy,
                anchor="e",
                text=str(value),
                fill=color,
                font=(
                    "Consolas",
                    8,
                    "bold"
                )
            )

            self.canvas.create_line(
                x1 + 10,
                yy + 10,
                x2 - 10,
                yy + 10,
                fill="#082a2d"
            )

            yy += 21

        # --------------------------------------------------------
        # TARGET COUNTRIES
        # --------------------------------------------------------

        self.dibujar_panel_paises()

        # --------------------------------------------------------
        # ATTACK FEED
        # --------------------------------------------------------

        self.dibujar_feed()

        # --------------------------------------------------------
        # SYSTEM STATUS
        # --------------------------------------------------------

        self.dibujar_system_status()

        # --------------------------------------------------------
        # FOOTER
        # --------------------------------------------------------

        self.canvas.create_text(
            20,
            self.height - 14,
            anchor="w",
            text=(
                f"EVENTS:{total:04d}   "
                f"ZOOM:{self.zoom:.2f}x   "
                f"EDR:ACTIVE   "
                f"NETWORK:MONITORED"
            ),
            fill="#006b70",
            font=(
                "Consolas",
                7
            )
        )

        self.canvas.create_text(
            self.width - 20,
            self.height - 14,
            anchor="e",
            text=(
                "LMB SELECT / RMB PAN / WHEEL ZOOM"
            ),
            fill="#006b70",
            font=(
                "Consolas",
                7
            )
        )

    # ============================================================
    # PAISES
    # ============================================================

    def dibujar_panel_paises(
        self
    ):

        x1 = 20
        y1 = self.height - 270
        x2 = 270
        y2 = self.height - 100

        if y1 < 150:
            return

        self._panel(
            x1,
            y1,
            x2,
            y2
        )

        self.canvas.create_text(
            x1 + 10,
            y1 + 15,
            anchor="w",
            text="TOP TARGETED COUNTRIES",
            fill=CYAN,
            font=(
                "Consolas",
                8,
                "bold"
            )
        )

        paises = {}

        for ataque in self.ataques:

            pais = ataque.get(
                "pais",
                ataque.get(
                    "codigo_pais",
                    "UNKNOWN"
                )
            )

            paises[pais] = (
                paises.get(
                    pais,
                    0
                )
                + 1
            )

        ranking = sorted(
            paises.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        yy = y1 + 40

        for index, (
            pais,
            cantidad
        ) in enumerate(
            ranking,
            1
        ):

            self.canvas.create_text(
                x1 + 10,
                yy,
                anchor="w",
                text=f"{index}",
                fill="#617b7e",
                font=(
                    "Consolas",
                    7
                )
            )

            self.canvas.create_text(
                x1 + 30,
                yy,
                anchor="w",
                text=str(pais)[:20],
                fill=WHITE,
                font=(
                    "Consolas",
                    7
                )
            )

            self.canvas.create_text(
                x2 - 10,
                yy,
                anchor="e",
                text=str(cantidad),
                fill=CYAN,
                font=(
                    "Consolas",
                    8,
                    "bold"
                )
            )

            yy += 22

    # ============================================================
    # FEED
    # ============================================================

    def dibujar_feed(
        self
    ):

        x1 = 20
        y1 = self.height - 95
        x2 = 500
        y2 = self.height - 20

        if y1 < 100:
            return

        self._panel(
            x1,
            y1,
            x2,
            y2
        )

        self.canvas.create_text(
            x1 + 10,
            y1 + 13,
            anchor="w",
            text="LIVE ATTACK FEED",
            fill=CYAN,
            font=(
                "Consolas",
                8,
                "bold"
            )
        )

        self.canvas.create_text(
            x1 + 10,
            y1 + 32,
            anchor="w",
            text="TIME",
            fill="#008f95",
            font=("Consolas", 6)
        )

        self.canvas.create_text(
            x1 + 80,
            y1 + 32,
            anchor="w",
            text="SOURCE",
            fill="#008f95",
            font=("Consolas", 6)
        )

        self.canvas.create_text(
            x1 + 220,
            y1 + 32,
            anchor="w",
            text="TARGET",
            fill="#008f95",
            font=("Consolas", 6)
        )

        self.canvas.create_text(
            x1 + 370,
            y1 + 32,
            anchor="w",
            text="TYPE",
            fill="#008f95",
            font=("Consolas", 6)
        )

        ataques = self.ataques[:3]

        yy = y1 + 48

        for ataque in ataques:

            ip = ataque.get(
                "ip",
                "UNKNOWN"
            )

            pais = ataque.get(
                "pais",
                ataque.get(
                    "codigo_pais",
                    "UNKNOWN"
                )
            )

            tipo = ataque.get(
                "intencion",
                ataque.get(
                    "tipo",
                    "THREAT"
                )
            )

            hora = time.strftime(
                "%H:%M:%S"
            )

            self.canvas.create_text(
                x1 + 10,
                yy,
                anchor="w",
                text=hora,
                fill="#8da9aa",
                font=("Consolas", 6)
            )

            self.canvas.create_text(
                x1 + 80,
                yy,
                anchor="w",
                text=ip[:20],
                fill=RED,
                font=("Consolas", 6)
            )

            self.canvas.create_text(
                x1 + 220,
                yy,
                anchor="w",
                text="MY PC",
                fill=GREEN,
                font=("Consolas", 6)
            )

            self.canvas.create_text(
                x1 + 370,
                yy,
                anchor="w",
                text=str(tipo)[:18],
                fill=YELLOW,
                font=("Consolas", 6)
            )

            yy += 16

    # ============================================================
    # SYSTEM STATUS
    # ============================================================

    def dibujar_system_status(
        self
    ):

        x2 = self.width - 20
        x1 = x2 - 270

        y2 = self.height - 20
        y1 = y2 - 170

        self._panel(
            x1,
            y1,
            x2,
            y2
        )

        self.canvas.create_text(
            x1 + 12,
            y1 + 15,
            anchor="w",
            text="SYSTEM STATUS",
            fill=CYAN,
            font=(
                "Consolas",
                9,
                "bold"
            )
        )

        servicios = [
            "FIREWALL",
            "INTRUSION DETECTION",
            "REAL-TIME MONITOR",
            "GEOIP DATABASE",
            "THREAT INTELLIGENCE"
        ]

        yy = y1 + 40

        for servicio in servicios:

            self.canvas.create_text(
                x1 + 12,
                yy,
                anchor="w",
                text=servicio,
                fill="#8aa2a4",
                font=(
                    "Consolas",
                    6
                )
            )

            self.canvas.create_oval(
                x2 - 55,
                yy - 3,
                x2 - 49,
                yy + 3,
                fill=GREEN,
                outline=""
            )

            self.canvas.create_text(
                x2 - 12,
                yy,
                anchor="e",
                text="ACTIVE",
                fill=GREEN,
                font=(
                    "Consolas",
                    6,
                    "bold"
                )
            )

            yy += 23

    # ============================================================
    # REDIBUJAR
    # ============================================================

    def redibujar_mapa(
        self
    ):

        if not self.canvas.winfo_exists():
            return

        self.canvas.delete(
            "all"
        )

        # --------------------------------------------------------
        # FONDO
        # --------------------------------------------------------

        self.dibujar_fondo()

        # --------------------------------------------------------
        # MAPA REAL
        # --------------------------------------------------------

        self.dibujar_mapa()

        # --------------------------------------------------------
        # DOT MATRIX
        # --------------------------------------------------------

        self.dibujar_puntos_mapa()

        # --------------------------------------------------------
        # NODO LOCAL
        # --------------------------------------------------------

        destino = (
            self.dibujar_nodo_local()
        )

        # --------------------------------------------------------
        # ATAQUES
        # --------------------------------------------------------

        self.dibujar_ataques(
            destino
        )

        # --------------------------------------------------------
        # HUD
        # --------------------------------------------------------

        self.dibujar_hud()

        # --------------------------------------------------------
        # HOVER
        # --------------------------------------------------------

        if self.hovered_attack:

            encontrado = None

            ip = (
                self.hovered_attack[
                    "data"
                ].get(
                    "ip"
                )
            )

            for n in self.node_positions:

                if n["data"].get(
                    "ip"
                ) == ip:

                    encontrado = n
                    break

            if encontrado:

                self.hovered_attack = encontrado

                self._render_hover_hud(
                    encontrado
                )

    # ============================================================
    # HOVER HUD
    # ============================================================

    def _render_hover_hud(
        self,
        item
    ):

        x = item["x"] + 15

        y = item["y"] - 80

        if x + 290 > self.width:

            x = (
                item["x"]
                - 305
            )

        if y < 50:

            y = 50

        a = item["data"]

        self.canvas.create_rectangle(
            x,
            y,
            x + 290,
            y + 75,
            fill="#020d10",
            outline=CYAN,
            width=1
        )

        self.canvas.create_text(
            x + 8,
            y + 10,
            anchor="w",
            text=(
                f"◉ {a.get('ip', 'UNKNOWN')}"
            ),
            fill=RED,
            font=(
                "Consolas",
                8,
                "bold"
            )
        )

        self.canvas.create_text(
            x + 8,
            y + 27,
            anchor="w",
            text=(
                f"COUNTRY: "
                f"{a.get('pais', 'UNKNOWN')}"
            ),
            fill=WHITE,
            font=(
                "Consolas",
                7
            )
        )

        self.canvas.create_text(
            x + 8,
            y + 42,
            anchor="w",
            text=(
                f"INTENT: "
                f"{a.get('intencion', 'UNKNOWN')}"
            ),
            fill=YELLOW,
            font=(
                "Consolas",
                7
            )
        )

        self.canvas.create_text(
            x + 8,
            y + 57,
            anchor="w",
            text=(
                f"ROUTE: "
                f"{a.get('ruta_objetivo', 'EDR')}"
            ),
            fill=CYAN,
            font=(
                "Consolas",
                7
            )
        )

        self.canvas.create_text(
            x + 8,
            y + 69,
            anchor="w",
            text="DOUBLE CLICK → GOOGLE MAPS",
            fill="#657d80",
            font=(
                "Consolas",
                6
            )
        )

    # ============================================================
    # ANIMACIÓN
    # ============================================================

    def _animar(
        self
    ):

        if not self.animating:
            return

        self.animation_tick += 1

        # --------------------------------------------------------
        # MOVER PROYECTILES
        # --------------------------------------------------------

        for key in list(
            self.attack_particles.keys()
        ):

            self.attack_particles[key] += (
                0.012
            )

            if (
                self.attack_particles[key]
                >= 1.0
            ):

                self.attack_particles[key] = 0.0

        # --------------------------------------------------------
        # REDIBUJAR
        # --------------------------------------------------------

        self.redibujar_mapa()

        self.after(
            55,
            self._animar
        )

    # ============================================================
    # MOUSE LEFT
    # ============================================================

    def _mouse_left_down(
        self,
        event
    ):

        self.dragging_left = True

        self.last_mouse_x = event.x
        self.last_mouse_y = event.y

        self._seleccionar_en_posicion(
            event.x,
            event.y
        )

    # ============================================================
    # MOUSE LEFT DRAG
    # ============================================================

    def _mouse_left_drag(
        self,
        event
    ):

        if not self.dragging_left:
            return

        # En mapa plano:
        # botón izquierdo mueve el mapa

        dx = (
            event.x
            - self.last_mouse_x
        )

        dy = (
            event.y
            - self.last_mouse_y
        )

        self.pan_x += dx
        self.pan_y += dy

        self.last_mouse_x = event.x
        self.last_mouse_y = event.y

        self.redibujar_mapa()

    # ============================================================
    # LEFT UP
    # ============================================================

    def _mouse_left_up(
        self,
        event
    ):

        self.dragging_left = False

    # ============================================================
    # RIGHT DOWN
    # ============================================================

    def _mouse_right_down(
        self,
        event
    ):

        self.dragging_right = True

        self.last_mouse_x = event.x
        self.last_mouse_y = event.y

    # ============================================================
    # RIGHT DRAG
    # ============================================================

    def _mouse_right_drag(
        self,
        event
    ):

        if not self.dragging_right:
            return

        dx = (
            event.x
            - self.last_mouse_x
        )

        dy = (
            event.y
            - self.last_mouse_y
        )

        self.pan_x += dx
        self.pan_y += dy

        self.last_mouse_x = event.x
        self.last_mouse_y = event.y

        self.redibujar_mapa()

    # ============================================================
    # RIGHT UP
    # ============================================================

    def _mouse_right_up(
        self,
        event
    ):

        self.dragging_right = False

    # ============================================================
    # ZOOM
    # ============================================================

    def _aplicar_zoom(
        self,
        factor
    ):

        self.zoom *= factor

        self.zoom = max(
            self.min_zoom,
            min(
                self.max_zoom,
                self.zoom
            )
        )

        self.redibujar_mapa()

    # ============================================================
    # WINDOWS
    # ============================================================

    def _mouse_wheel(
        self,
        event
    ):

        if event.delta > 0:

            self._aplicar_zoom(
                1.10
            )

        else:

            self._aplicar_zoom(
                0.90
            )

    # ============================================================
    # LINUX
    # ============================================================

    def _mouse_wheel_linux(
        self,
        event
    ):

        if event.num == 4:

            self._aplicar_zoom(
                1.10
            )

        elif event.num == 5:

            self._aplicar_zoom(
                0.90
            )

    # ============================================================
    # SELECCIÓN
    # ============================================================

    def _seleccionar_en_posicion(
        self,
        x,
        y
    ):

        for node in self.node_positions:

            distancia = math.hypot(
                x - node["x"],
                y - node["y"]
            )

            if distancia < 22:

                self.hovered_attack = node

                self.redibujar_mapa()

                return

    # ============================================================
    # HOVER
    # ============================================================

    def _on_hover(
        self,
        event
    ):

        encontrado = None

        for node in self.node_positions:

            distancia = math.hypot(
                event.x - node["x"],
                event.y - node["y"]
            )

            if distancia < 15:

                encontrado = node

                break

        if encontrado != self.hovered_attack:

            self.hovered_attack = encontrado

            self.redibujar_mapa()

    # ============================================================
    # DOUBLE CLICK
    # ============================================================

    def _on_double_click_map(
        self,
        event
    ):

        for node in self.node_positions:

            distancia = math.hypot(
                event.x - node["x"],
                event.y - node["y"]
            )

            if distancia < 25:

                ataque = node["data"]

                lat = ataque.get(
                    "lat",
                    40.4168
                )

                lon = ataque.get(
                    "lon",
                    -3.7038
                )

                url = (
                    "https://www.google.com/maps/"
                    "?api=1"
                    f"&query={lat},{lon}"
                )

                webbrowser.open(
                    url
                )

                return

    # ============================================================
    # SELECCIONAR POR IP
    # ============================================================

    def seleccionar_ataque_por_ip(
        self,
        ip_target
    ):

        for node in self.node_positions:

            if (
                node["data"].get("ip")
                ==
                ip_target
            ):

                self.hovered_attack = node

                self.redibujar_mapa()

                return

    # ============================================================
    # GOOGLE MAPS
    # ============================================================

    def abrir_google_maps_web(
        self
    ):

        lat = 40.4168
        lon = -3.7038

        if self.hovered_attack:

            ataque = (
                self.hovered_attack[
                    "data"
                ]
            )

            lat = ataque.get(
                "lat",
                lat
            )

            lon = ataque.get(
                "lon",
                lon
            )

        elif self.ataques:

            ataque = self.ataques[0]

            lat = ataque.get(
                "lat",
                lat
            )

            lon = ataque.get(
                "lon",
                lon
            )

        url = (
            "https://www.google.com/maps/"
            f"search/?api=1&query={lat},{lon}"
        )

        webbrowser.open(
            url
        )

    # ============================================================
    # STREET VIEW
    # ============================================================

    def abrir_street_view_seleccion(
        self
    ):

        lat = 40.4168
        lon = -3.7038

        if self.hovered_attack:

            ataque = (
                self.hovered_attack[
                    "data"
                ]
            )

            lat = ataque.get(
                "lat",
                lat
            )

            lon = ataque.get(
                "lon",
                lon
            )

        elif self.ataques:

            ataque = self.ataques[0]

            lat = ataque.get(
                "lat",
                lat
            )

            lon = ataque.get(
                "lon",
                lon
            )

        url = (
            "https://www.google.com/maps/"
            "@?api=1"
            "&map_action=pano"
            f"&viewpoint={lat},{lon}"
        )

        webbrowser.open(
            url
        )

    # ============================================================
    # ACTUALIZAR ATAQUES
    # ============================================================

    def actualizar_ataques(
        self,
        lista_ataques
    ):

        self.ataques = (
            lista_ataques
            if lista_ataques
            else []
        )

        # limpiar partículas de IP
        # que ya no existen

        ips = {
            a.get("ip")
            for a in self.ataques
        }

        for key in list(
            self.attack_particles.keys()
        ):

            if key not in ips:

                del self.attack_particles[
                    key
                ]

        self.redibujar_mapa()


# ================================================================
# DEMO
# ================================================================

if __name__ == "__main__":

    root = tk.Tk()

    root.title(
        "CYBER THREAT MAP"
    )

    root.geometry(
        "1400x850"
    )

    root.configure(
        bg="#01080a"
    )

    mapa = ThreatMapCanvas(
        root
    )

    mapa.pack(
        fill="both",
        expand=True
    )

    # ============================================================
    # ATAQUES DE PRUEBA
    # ============================================================

    ataques_demo = [

        {
            "ip": "185.234.219.11",
            "lat": 40.7,
            "lon": -74.0,
            "pais": "United States",
            "codigo_pais": "US",
            "severidad": "CRÍTICO",
            "intencion": "DDoS",
            "ruta_objetivo": "/api/login",
            "es_vpn": False
        },

        {
            "ip": "193.204.126.67",
            "lat": 52.5,
            "lon": 13.4,
            "pais": "Germany",
            "codigo_pais": "DE",
            "severidad": "ALTO",
            "intencion": "SQL Injection",
            "ruta_objetivo": "/admin",
            "es_vpn": False
        },

        {
            "ip": "45.77.32.11",
            "lat": -23.5,
            "lon": -46.6,
            "pais": "Brazil",
            "codigo_pais": "BR",
            "severidad": "CRÍTICO",
            "intencion": "Brute Force",
            "ruta_objetivo": "/ssh",
            "es_vpn": True,
            "proveedor_vpn": "Cloud VPN"
        },

        {
            "ip": "223.198.12.45",
            "lat": 28.6,
            "lon": 77.2,
            "pais": "India",
            "codigo_pais": "IN",
            "severidad": "ALTO",
            "intencion": "Malware",
            "ruta_objetivo": "/upload",
            "es_vpn": False
        },

        {
            "ip": "81.17.23.19",
            "lat": 48.8,
            "lon": 2.3,
            "pais": "France",
            "codigo_pais": "FR",
            "severidad": "MEDIO",
            "intencion": "Phishing",
            "ruta_objetivo": "/mail",
            "es_vpn": True,
            "proveedor_vpn": "Private VPN"
        },

        {
            "ip": "202.123.55.91",
            "lat": -33.8,
            "lon": 151.2,
            "pais": "Australia",
            "codigo_pais": "AU",
            "severidad": "CRÍTICO",
            "intencion": "DDoS",
            "ruta_objetivo": "/",
            "es_vpn": False
        },

        {
            "ip": "103.45.67.89",
            "lat": 35.6,
            "lon": 139.6,
            "pais": "Japan",
            "codigo_pais": "JP",
            "severidad": "ALTO",
            "intencion": "SQL Injection",
            "ruta_objetivo": "/database",
            "es_vpn": False
        },

        {
            "ip": "185.156.73.25",
            "lat": 1.35,
            "lon": 103.8,
            "pais": "Singapore",
            "codigo_pais": "SG",
            "severidad": "MEDIO",
            "intencion": "Malware",
            "ruta_objetivo": "/download",
            "es_vpn": True,
            "proveedor_vpn": "TOR/VPN"
        },

        {
            "ip": "91.212.44.33",
            "lat": 55.7,
            "lon": 37.6,
            "pais": "Russia",
            "codigo_pais": "RU",
            "severidad": "CRÍTICO",
            "intencion": "DDoS",
            "ruta_objetivo": "/api",
            "es_vpn": False
        },

        {
            "ip": "114.33.88.12",
            "lat": 31.2,
            "lon": 121.4,
            "pais": "China",
            "codigo_pais": "CN",
            "severidad": "ALTO",
            "intencion": "Brute Force",
            "ruta_objetivo": "/ssh",
            "es_vpn": True,
            "proveedor_vpn": "Unknown VPN"
        }
    ]

    mapa.actualizar_ataques(
        ataques_demo
    )
