import os
import platform
import tkinter as tk

import customtkinter as ctk

from app import Aplicacion

try:
    from PIL import Image
except ImportError:  # Pillow no disponible; se recurre a PhotoImage
    Image = None


SPLASH_DURATION_MS = 4000
VENTANA_ANCHO = 760
VENTANA_ALTO = 520
SPLASH_IMAGEN_MARGEN_ANCHO = 220
SPLASH_IMAGEN_MARGEN_ALTO = 240
COLOR_TRANSPARENTE = "#010203"

# Detectar sistema operativo
ES_WINDOWS = platform.system() == "Windows"
ES_LINUX = platform.system() == "Linux"


def _mostrar_splash(raiz: ctk.CTk) -> None:
    """Muestra un splash con el logotipo antes de la ventana principal."""

    # En Linux, usar un color de fondo sólido en lugar de transparente
    if ES_LINUX:
        color_fondo = "#2b2b2b"  # Gris oscuro para modo oscuro
        usar_bordes = True
    else:
        color_fondo = COLOR_TRANSPARENTE
        usar_bordes = False
    
    splash = ctk.CTkToplevel(raiz, fg_color=color_fondo)
    splash.overrideredirect(True)
    splash.attributes("-topmost", True)
    splash.resizable(False, False)
    
    # Transparencia solo funciona correctamente en Windows
    if ES_WINDOWS:
        try:
            splash.wm_attributes("-transparentcolor", COLOR_TRANSPARENTE)
        except tk.TclError:
            pass

    ruta_imagen = os.path.join(os.path.dirname(__file__), "img", "splash.png")
    imagen_ctk: ctk.CTkImage | None = None
    imagen_tk: tk.PhotoImage | None = None
    ancho_imagen = 0
    alto_imagen = 0
    
    if os.path.exists(ruta_imagen):
        if Image is not None:
            try:
                imagen_base = Image.open(ruta_imagen)
                max_ancho = max(VENTANA_ANCHO - SPLASH_IMAGEN_MARGEN_ANCHO, 160)
                max_alto = max(VENTANA_ALTO - SPLASH_IMAGEN_MARGEN_ALTO, 160)
                escala = min(
                    max_ancho / imagen_base.width,
                    max_alto / imagen_base.height,
                    1.0,
                )
                ancho_destino = max(int(imagen_base.width * escala), 1)
                alto_destino = max(int(imagen_base.height * escala), 1)
                
                # Guardar dimensiones de la imagen
                ancho_imagen = ancho_destino
                alto_imagen = alto_destino
                
                imagen_ctk = ctk.CTkImage(
                    light_image=imagen_base,
                    dark_image=imagen_base,
                    size=(ancho_destino, alto_destino),
                )
            except Exception:
                imagen_ctk = None
        if imagen_ctk is None:
            try:
                imagen_tk = tk.PhotoImage(file=ruta_imagen)
                # Obtener dimensiones de PhotoImage
                if imagen_tk is not None:
                    ancho_imagen = imagen_tk.width()
                    alto_imagen = imagen_tk.height()
            except tk.TclError:
                imagen_tk = None

    # Actualizar para obtener dimensiones correctas de la pantalla
    splash.update_idletasks()
    
    # Calcular tamaño de ventana según el sistema operativo
    if ES_LINUX and ancho_imagen > 0 and alto_imagen > 0:
        # En Linux, ajustar ventana al tamaño de la imagen + padding + bordes + texto
        padding_horizontal = 24 + 20  # 12*2 (pack) + 10*2 (frame)
        padding_vertical = 28 + 20 + 50  # 16+12 (pack superior/inferior) + 10*2 (frame) + 50 (texto)
        ventana_ancho = ancho_imagen + padding_horizontal
        ventana_alto = alto_imagen + padding_vertical
    else:
        # En Windows, usar tamaño predeterminado
        ventana_ancho = VENTANA_ANCHO
        ventana_alto = VENTANA_ALTO
    
    # Obtener información de la pantalla principal
    pantalla_ancho = splash.winfo_screenwidth()
    pantalla_alto = splash.winfo_screenheight()
    
    # Calcular posición centrada
    posicion_x = int((pantalla_ancho - ventana_ancho) / 2)
    posicion_y = int((pantalla_alto - ventana_alto) / 2)
    
    # Asegurar que no quede fuera de la pantalla
    posicion_x = max(0, posicion_x)
    posicion_y = max(0, posicion_y)
    
    splash.geometry(f"{ventana_ancho}x{ventana_alto}+{posicion_x}+{posicion_y}")
    
    # En Linux, forzar actualización de posición y centrado
    if ES_LINUX:
        splash.update()
        # Recalcular después de update
        posicion_x = int((splash.winfo_screenwidth() - ventana_ancho) / 2)
        posicion_y = int((splash.winfo_screenheight() - ventana_alto) / 2)
        splash.geometry(f"{ventana_ancho}x{ventana_alto}+{posicion_x}+{posicion_y}")

    # Frame contenedor con bordes redondeados en Linux
    contenedor = ctk.CTkFrame(
        splash,
        fg_color=color_fondo if not usar_bordes else "#1e1e1e",
        corner_radius=20 if usar_bordes else 0,
        border_width=2 if usar_bordes else 0,
        border_color="#4a4a4a" if usar_bordes else None,
    )
    contenedor.pack(fill="both", expand=True, padx=10 if usar_bordes else 0, pady=10 if usar_bordes else 0)

    # Variable para mantener referencia a las imágenes y evitar garbage collection
    if imagen_ctk is not None:
        etiqueta_imagen = ctk.CTkLabel(
            contenedor,
            image=imagen_ctk,
            text="",
            fg_color="transparent",
        )
        # Mantener referencia usando atributo del contenedor
        contenedor._imagen_ref = imagen_ctk  # type: ignore
        etiqueta_imagen.pack(padx=12, pady=(16, 12))
    elif imagen_tk is not None:
        etiqueta_imagen = tk.Label(
            contenedor,
            image=imagen_tk,
            bd=0,
            bg=color_fondo,
        )
        # Mantener referencia usando atributo del contenedor
        contenedor._imagen_ref = imagen_tk  # type: ignore
        etiqueta_imagen.pack(padx=12, pady=(16, 12))

    # Ajustar tamaño de fuente según el sistema operativo y ancho de ventana
    if ES_LINUX and ventana_ancho < 300:
        # Ventana pequeña: fuente más pequeña
        tamano_fuente = 9
    elif ES_LINUX:
        # Ventana mediana: fuente pequeña
        tamano_fuente = 11
    else:
        # Windows: fuente original
        tamano_fuente = 14
    
    mensaje = ctk.CTkLabel(
        contenedor,
        text="Creado por entreunosyceros.net",
        font=("Segoe UI", tamano_fuente, "bold"),
        fg_color="transparent",
        text_color=("black", "white"),
    )
    mensaje.pack(padx=12, pady=(0, 16))

    def cerrar_splash() -> None:
        try:
            splash.destroy()
        finally:
            raiz.deiconify()

    splash.after(SPLASH_DURATION_MS, cerrar_splash)


def main() -> None:
    ctk.set_appearance_mode("system")
    ctk.set_default_color_theme("blue")
    raiz = ctk.CTk()
    raiz.withdraw()
    _mostrar_splash(raiz)
    app = Aplicacion(raiz)
    app.ejecutar()


if __name__ == "__main__":
    main()
