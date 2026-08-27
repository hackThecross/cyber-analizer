import pyvista as pv
from pyvista import examples

# --- Carga de recursos ---
# Descarga automáticamente la textura y la malla la primera vez que se ejecuta
print("Cargando textura y malla de la Tierra...")
earth_texture = examples.load_globe_texture()
earth_mesh = examples.load_globe()

# --- Configuración de la ventana ---
# notebook=False asegura que se abra una ventana externa del sistema operativo
plotter = pv.Plotter(notebook=False, off_screen=False)

# --- Renderizado ---
# smooth_shading=True mejora la apariencia visual eliminando facetas visibles
plotter.add_mesh(earth_mesh, texture=earth_texture, smooth_shading=True)
plotter.set_background('black')  # Fondo espacial
plotter.add_title("Mapa Mundi 3D - Escritorio", font_size=15, color='white')

# --- Ejecución ---
print("Mostrando ventana. Cierra la ventana para salir del programa.")
plotter.show()   