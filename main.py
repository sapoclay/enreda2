import os
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


def _mostrar_splash(raiz: ctk.CTk) -> None:
    """Muestra un splash con el logotipo antes de la ventana principal."""

    splash = ctk.CTkToplevel(raiz, fg_color=COLOR_TRANSPARENTE)
    splash.overrideredirect(True)
    splash.attributes("-topmost", True)
    splash.resizable(False, False)
    try:
        splash.wm_attributes("-transparentcolor", COLOR_TRANSPARENTE)
    except tk.TclError:
        pass

    ruta_imagen = os.path.join(os.path.dirname(__file__), "img", "splash.png")
    imagen_ctk: ctk.CTkImage | None = None
    imagen_tk: tk.PhotoImage | None = None
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
            except tk.TclError:
                imagen_tk = None

    pantalla_ancho = splash.winfo_screenwidth()
    pantalla_alto = splash.winfo_screenheight()
    posicion_x = int((pantalla_ancho - VENTANA_ANCHO) / 2)
    posicion_y = int((pantalla_alto - VENTANA_ALTO) / 2)
    splash.geometry(f"{VENTANA_ANCHO}x{VENTANA_ALTO}+{posicion_x}+{posicion_y}")

    contenedor = ctk.CTkFrame(
        splash,
        fg_color="transparent",
        corner_radius=0,
    )
    contenedor.pack(fill="both", expand=True)

    if imagen_ctk is not None:
        etiqueta_imagen = ctk.CTkLabel(
            contenedor,
            image=imagen_ctk,
            text="",
            fg_color="transparent",
        )
        etiqueta_imagen.image = imagen_ctk  # Mantiene la referencia
        etiqueta_imagen.pack(padx=12, pady=(16, 12))
    elif imagen_tk is not None:
        etiqueta_imagen = tk.Label(
            contenedor,
            image=imagen_tk,
            bd=0,
            bg=COLOR_TRANSPARENTE,
        )
        etiqueta_imagen.image = imagen_tk
        etiqueta_imagen.pack(padx=12, pady=(16, 12))

    mensaje = ctk.CTkLabel(
        contenedor,
        text="Creado por entreunosyceros.net",
        font=("Segoe UI", 14, "bold"),
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
