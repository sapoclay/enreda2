from __future__ import annotations

import os
import tkinter as tk
import webbrowser
from typing import Optional

import customtkinter as ctk

try:
    from PIL import Image
except ImportError:  # Pillow no disponible
    Image = None

from config import get_config

ABOUT_WIDTH = 420
ABOUT_HEIGHT = 520
ABOUT_URL = "https://github.com/sapoclay/enreda2"
LOGO_MAX_WIDTH = 200
LOGO_MAX_HEIGHT = 200


class MenuAplicacion:
    """Configura el menú superior y sus acciones."""

    def __init__(self, raiz: ctk.CTk, app_callbacks: dict = None) -> None:
        self.raiz = raiz
        self.app_callbacks = app_callbacks or {}
        self.menu_principal = tk.Menu(self.raiz)
        self.about_window: Optional[ctk.CTkToplevel] = None
        self.preferences_window: Optional[ctk.CTkToplevel] = None
        self._tema_var: Optional[ctk.StringVar] = None
        self._logo_ctk: Optional[ctk.CTkImage] = None
        self._logo_tk: Optional[tk.PhotoImage] = None
        self._construir_menu()

    def _construir_menu(self) -> None:
        menu_archivo = tk.Menu(self.menu_principal, tearoff=0)
        menu_archivo.add_command(label="Exportar CSV...", command=self._exportar_csv)
        menu_archivo.add_separator()
        menu_archivo.add_command(label="Salir", command=self._salir)

        menu_opciones = tk.Menu(self.menu_principal, tearoff=0)
        menu_opciones.add_command(label="Preferencias", command=self._mostrar_preferencias)
        menu_opciones.add_command(label="About", command=self._mostrar_about)

        self.menu_principal.add_cascade(label="Archivo", menu=menu_archivo)
        self.menu_principal.add_cascade(label="Opciones", menu=menu_opciones)
        self.raiz.configure(menu=self.menu_principal)

    def _exportar_csv(self) -> None:
        """Llama al callback de exportación CSV de la aplicación."""
        if "exportar_csv" in self.app_callbacks:
            self.app_callbacks["exportar_csv"]()

    def _salir(self) -> None:
        self.raiz.destroy()

    def _mostrar_about(self) -> None:
        if self.about_window is not None and self.about_window.winfo_exists():
            self.about_window.lift()
            self.about_window.focus_force()
            return

        ventana = ctk.CTkToplevel(self.raiz)
        ventana.title("Acerca de")
        ventana.resizable(False, False)
        ventana.transient(self.raiz)

        pantalla_ancho = ventana.winfo_screenwidth()
        pantalla_alto = ventana.winfo_screenheight()
        posicion_x = int((pantalla_ancho - ABOUT_WIDTH) / 2)
        posicion_y = int((pantalla_alto - ABOUT_HEIGHT) / 2)
        ventana.geometry(f"{ABOUT_WIDTH}x{ABOUT_HEIGHT}+{posicion_x}+{posicion_y}")

        contenedor = ctk.CTkFrame(ventana)
        contenedor.pack(fill="both", expand=True, padx=24, pady=24)

        color_fondo = contenedor.cget("fg_color")
        if isinstance(color_fondo, tuple):
            modo = ctk.get_appearance_mode()
            color_tk = color_fondo[0] if modo == "Light" else color_fondo[1]
        else:
            color_tk = color_fondo

        self._cargar_logo()
        if self._logo_ctk is not None:
            etiqueta_logo = ctk.CTkLabel(contenedor, image=self._logo_ctk, text="")
            etiqueta_logo.image = self._logo_ctk
            etiqueta_logo.pack(pady=(4, 16))
        elif self._logo_tk is not None:
            etiqueta_logo = tk.Label(
                contenedor,
                image=self._logo_tk,
                borderwidth=0,
                background=color_tk,
            )
            etiqueta_logo.image = self._logo_tk
            etiqueta_logo.pack(pady=(4, 16))

        ctk.CTkLabel(
            contenedor,
            text="Escáner de red",
            font=("Segoe UI", 18, "bold"),
        ).pack(pady=(0, 8))

        descripcion = (
            "Aplicación para detectar dispositivos activos en la red local, "
            "consultar detalles de hosts, explorar recursos compartidos y "
            "cualquier otra funcionalidad que se me ocurra."
        )
        ctk.CTkLabel(
            contenedor,
            text=descripcion,
            font=("Segoe UI", 13),
            wraplength=ABOUT_WIDTH - 80,
            justify="center",
        ).pack(pady=(0, 20))

        ctk.CTkButton(
            contenedor,
            text="Abrir repositorio",
            command=lambda: webbrowser.open_new_tab(ABOUT_URL),
        ).pack(pady=(0, 12))

        ctk.CTkButton(
            contenedor,
            text="Cerrar",
            command=self._cerrar_about,
        ).pack()

        ventana.protocol("WM_DELETE_WINDOW", self._cerrar_about)
        self.about_window = ventana

    def _mostrar_preferencias(self) -> None:
        if self.preferences_window is not None and self.preferences_window.winfo_exists():
            self.preferences_window.lift()
            self.preferences_window.focus_force()
            return

        ventana = ctk.CTkToplevel(self.raiz)
        ventana.title("Preferencias")
        ventana.resizable(False, False)
        ventana.transient(self.raiz)

        ancho, alto = 620, 480
        pantalla_ancho = ventana.winfo_screenwidth()
        pantalla_alto = ventana.winfo_screenheight()
        posicion_x = int((pantalla_ancho - ancho) / 2)
        posicion_y = int((pantalla_alto - alto) / 2)
        ventana.geometry(f"{ancho}x{alto}+{posicion_x}+{posicion_y}")

        # Contenedor principal
        contenedor_principal = ctk.CTkFrame(ventana)
        contenedor_principal.pack(fill="both", expand=True, padx=20, pady=20)

        # Crear TabView con pestañas
        tabview = ctk.CTkTabview(contenedor_principal)
        tabview.pack(fill="both", expand=True)

        # Crear pestañas
        tab_apariencia = tabview.add("🎨 Apariencia")
        tab_mensajeria = tabview.add("💬 Mensajería")

        # ===== PESTAÑA: APARIENCIA =====
        contenedor_apariencia = ctk.CTkScrollableFrame(tab_apariencia)
        contenedor_apariencia.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(
            contenedor_apariencia,
            text="Tema de la aplicación",
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        self._tema_var = ctk.StringVar(master=self.raiz, value=ctk.get_appearance_mode())

        tema_frame = ctk.CTkFrame(contenedor_apariencia)
        tema_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkRadioButton(
            tema_frame,
            text="🌞 Tema claro",
            value="Light",
            variable=self._tema_var,
            command=self._aplicar_tema,
            font=("Segoe UI", 12),
        ).pack(anchor="w", padx=12, pady=8)

        ctk.CTkRadioButton(
            tema_frame,
            text="🌙 Tema oscuro",
            value="Dark",
            variable=self._tema_var,
            command=self._aplicar_tema,
            font=("Segoe UI", 12),
        ).pack(anchor="w", padx=12, pady=8)

        # Información sobre temas
        info_tema_frame = ctk.CTkFrame(contenedor_apariencia)
        info_tema_frame.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            info_tema_frame,
            text="ℹ️ Información:",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=12, pady=(8, 4))

        ctk.CTkLabel(
            info_tema_frame,
            text="El tema se aplica inmediatamente y se guardará automáticamente.",
            font=("Segoe UI", 9),
            wraplength=520,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        # ===== PESTAÑA: MENSAJERÍA =====
        contenedor_mensajeria = ctk.CTkScrollableFrame(tab_mensajeria)
        contenedor_mensajeria.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(
            contenedor_mensajeria,
            text="Configuración de Mensajería",
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        config = get_config()
        metodo_actual = config.get("messaging.method", "msg")

        mensajeria_frame = ctk.CTkFrame(contenedor_mensajeria)
        mensajeria_frame.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            mensajeria_frame,
            text="Método de envío:",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", padx=12, pady=(12, 4))

        self._metodo_var = ctk.StringVar(master=self.raiz, value=metodo_actual)

        # Opciones de método
        metodos = [
            ("msg", "Comando MSG (Windows estándar)", "Usa RPC (puerto 135) y SMB (puerto 445)"),
            ("powershell", "PowerShell Remoting", "Usa WinRM (puerto 5985). Requiere configuración."),
            ("ssh_linux", "SSH para Linux/Unix", "Usa SSH (puerto 22). Requiere autenticación por clave."),
        ]

        for valor, nombre, descripcion in metodos:
            radio = ctk.CTkRadioButton(
                mensajeria_frame,
                text=nombre,
                value=valor,
                variable=self._metodo_var,
                font=("Segoe UI", 11),
            )
            radio.pack(anchor="w", padx=24, pady=4)
            
            ctk.CTkLabel(
                mensajeria_frame,
                text=f"    → {descripcion}",
                font=("Segoe UI", 9),
                text_color=("#666666", "#999999"),
            ).pack(anchor="w", padx=24, pady=(0, 8))

        # Información adicional
        info_frame = ctk.CTkFrame(contenedor_mensajeria)
        info_frame.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            info_frame,
            text="ℹ️ Información:",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=12, pady=(8, 4))

        info_text = (
            "• Comando MSG: Método tradicional de Windows. Funciona en la mayoría "
            "de redes locales pero puede estar deshabilitado en Windows 10/11.\n\n"
            "• PowerShell: Más moderno y flexible, pero requiere que WinRM esté "
            "habilitado en el dispositivo destino.\n\n"
            "• SSH Linux: Para sistemas Linux/Unix. Requiere SSH habilitado y "
            "autenticación por clave pública configurada. Usa notify-send o wall."
        )

        ctk.CTkLabel(
            info_frame,
            text=info_text,
            font=("Segoe UI", 9),
            wraplength=520,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        # ===== BOTONES (fuera de las pestañas) =====
        botones_frame = ctk.CTkFrame(contenedor_principal, fg_color="transparent")
        botones_frame.pack(fill="x", pady=(12, 0))

        def guardar():
            config.set("messaging.method", self._metodo_var.get())
            config.save()
            ventana.destroy()

        ctk.CTkButton(
            botones_frame,
            text="💾 Guardar cambios",
            command=guardar,
            fg_color=("#2e7d32", "#43a047"),
            hover_color=("#1b5e20", "#2e7d32"),
            font=("Segoe UI", 11, "bold"),
        ).pack(side="left", expand=True, padx=(0, 8))

        ctk.CTkButton(
            botones_frame,
            text="Cerrar",
            command=self._cerrar_preferencias,
            font=("Segoe UI", 11),
        ).pack(side="right", expand=True, padx=(8, 0))

        ventana.protocol("WM_DELETE_WINDOW", self._cerrar_preferencias)
        self.preferences_window = ventana

    def _cerrar_about(self) -> None:
        if self.about_window is None:
            return
        try:
            self.about_window.grab_release()
        except tk.TclError:
            pass
        try:
            self.about_window.destroy()
        except tk.TclError:
            pass
        finally:
            self.about_window = None

    def _cargar_logo(self) -> None:
        ruta_logo = os.path.join(os.path.dirname(__file__), "img", "logo.png")
        if not os.path.exists(ruta_logo):
            self._logo_ctk = None
            self._logo_tk = None
            return

        if Image is not None:
            try:
                imagen_base = Image.open(ruta_logo)
                escala = min(
                    LOGO_MAX_WIDTH / imagen_base.width,
                    LOGO_MAX_HEIGHT / imagen_base.height,
                    1.0,
                )
                ancho_destino = max(int(imagen_base.width * escala), 1)
                alto_destino = max(int(imagen_base.height * escala), 1)
                self._logo_ctk = ctk.CTkImage(
                    light_image=imagen_base,
                    dark_image=imagen_base,
                    size=(ancho_destino, alto_destino),
                )
                self._logo_tk = None
                return
            except Exception:
                self._logo_ctk = None

        try:
            self._logo_tk = tk.PhotoImage(file=ruta_logo)
        except tk.TclError:
            self._logo_tk = None
        self._logo_ctk = None

    def _aplicar_tema(self) -> None:
        if self._tema_var is None:
            return
        modo = self._tema_var.get()
        if modo not in {"Light", "Dark"}:
            return
        if ctk.get_appearance_mode() == modo:
            return
        self._cerrar_preferencias()
        ctk.set_appearance_mode(modo)

    def _cerrar_preferencias(self) -> None:
        if self.preferences_window is None:
            return
        try:
            self.preferences_window.destroy()
        except tk.TclError:
            pass
        finally:
            self.preferences_window = None
            self._tema_var = None