from __future__ import annotations

import ipaddress
import os
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from typing import Optional
import csv

import customtkinter as ctk

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    import pystray
    from pystray import MenuItem as item
    PYSTRAY_DISPONIBLE = True
except ImportError:
    pystray = None
    item = None
    PYSTRAY_DISPONIBLE = False

from menu import MenuAplicacion
from networking.deep_scan import DeepScanResult, realizar_escaneo_profundo
from networking.interfaces import InterfaceInfo, obtener_interfaces_locales
from networking.scanner import EscanerRed, MAXIMO_HOSTS
from networking.messaging import (
    enviar_mensaje, 
    enviar_mensaje_multiple,
    verificar_disponibilidad_mensajeria,
    detectar_sistema_operativo_por_puertos,
)
from config import get_config


class Aplicacion:
    """Controla la interfaz de usuario y coordina los escaneos."""

    def __init__(self, raiz: ctk.CTk):
        self.raiz = raiz
        self.raiz.title("enredA2 - Network Scanner")
        self.raiz.geometry("760x520")

        self.interfaces: list[InterfaceInfo] = obtener_interfaces_locales()
        self.cola_resultados: queue.Queue[
            Optional[tuple[str, str, bool, int, list[int], Optional[int]]]
        ] = queue.Queue()
        self.escaner: Optional[EscanerRed] = None

        self.estado_base = "Listo"
        self.estado = ctk.StringVar(value=self.estado_base)
        self.total_hosts = 0
        self.hosts_procesados = 0
        self.red_actual: Optional[ipaddress.IPv4Network] = None
        self.ventana_profunda: Optional[ctk.CTkToplevel] = None
        self.menu_aplicacion = MenuAplicacion(self.raiz, app_callbacks={
            "exportar_csv": self.exportar_csv
        })
        self._splash_image: Optional[ctk.CTkImage] = None
        self._hosts_cache: list[dict] = []  # Cache de hosts para filtrado y exportación
        
        # Icono de bandeja del sistema
        self.tray_icon = None
        self.tray_thread = None

        self._construir_interfaz()
        self._rellenar_interfaces()
        self._configurar_estilos_tabla()
        self._cargar_imagen_splash()
        self._iniciar_icono_bandeja()
        
        # Configurar evento de cerrar ventana
        self.raiz.protocol("WM_DELETE_WINDOW", self._minimizar_a_bandeja)

    def _construir_interfaz(self) -> None:
        """Crea todos los widgets principales con CustomTkinter."""

        padding = {"padx": 12, "pady": 8}

        marco_superior = ctk.CTkFrame(self.raiz)
        marco_superior.pack(fill="x", **padding)
        marco_superior.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(marco_superior, text="Red detectada:").grid(row=0, column=0, sticky="w")
        self.selector_interfaz = ctk.CTkComboBox(marco_superior, values=[])
        self.selector_interfaz.grid(row=0, column=1, sticky="ew", padx=8)
        ctk.CTkButton(
            marco_superior,
            text="Escanear red seleccionada",
            command=self.iniciar_escaneo_interfaz,
        ).grid(row=0, column=2, padx=8)

        ctk.CTkLabel(marco_superior, text="Red personalizada (CIDR):").grid(
            row=1, column=0, sticky="w", pady=(16, 0)
        )
        self.campo_red_personalizada = ctk.CTkEntry(marco_superior)
        self.campo_red_personalizada.grid(row=1, column=1, sticky="ew", padx=8, pady=(16, 0))
        ctk.CTkButton(
            marco_superior,
            text="Escanear red personalizada",
            command=self.iniciar_escaneo_red_personalizada,
        ).grid(row=1, column=2, padx=8, pady=(16, 0))

        marco_estado = ctk.CTkFrame(self.raiz)
        marco_estado.pack(fill="x", **padding)
        ctk.CTkLabel(marco_estado, textvariable=self.estado).pack(anchor="w", padx=6, pady=4)
        self.barra_progreso = ctk.CTkProgressBar(marco_estado)
        self.barra_progreso.pack(fill="x", padx=6, pady=(0, 10))
        self.barra_progreso.set(0)

        # Barra de búsqueda/filtrado
        marco_busqueda = ctk.CTkFrame(self.raiz)
        marco_busqueda.pack(fill="x", **padding)
        
        ctk.CTkLabel(marco_busqueda, text="🔍 Buscar:", width=70).pack(side="left", padx=(8, 4))
        
        self.entrada_buscar = ctk.CTkEntry(
            marco_busqueda, 
            placeholder_text="Filtrar por IP, sistema operativo, puertos o estado..."
        )
        self.entrada_buscar.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.entrada_buscar.bind("<KeyRelease>", lambda e: self._filtrar_tabla())
        
        ctk.CTkButton(
            marco_busqueda, 
            text="Limpiar", 
            width=90,
            command=self._limpiar_filtro
        ).pack(side="right", padx=(4, 8))

        marco_tabla = ctk.CTkFrame(self.raiz)
        marco_tabla.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        columnas = ("ip", "sistema", "puertos", "estado")
        self.tabla = ttk.Treeview(marco_tabla, columns=columnas, show="headings", height=12, selectmode="extended")
        self.tabla.heading("ip", text="Dirección IP")
        self.tabla.heading("sistema", text="Sistema operativo")
        self.tabla.heading("puertos", text="Puertos abiertos")
        self.tabla.heading("estado", text="Estado")
        self.tabla.column("ip", width=160, anchor="w")
        self.tabla.column("sistema", width=220, anchor="w")
        self.tabla.column("puertos", width=220, anchor="w")
        self.tabla.column("estado", width=120, anchor="center")
        self.tabla.pack(fill="both", expand=True, side="left", padx=(0, 8), pady=10)

        barra = ctk.CTkScrollbar(marco_tabla, command=self.tabla.yview)
        barra.pack(fill="y", side="right", pady=10)
        self.tabla.configure(yscrollcommand=barra.set)

        # Menú contextual (se construirá dinámicamente)
        self.menu_contextual = tk.Menu(self.tabla, tearoff=0)
        self.tabla.bind("<Button-3>", self._mostrar_menu_contextual)

        self.boton_cancelar = ctk.CTkButton(
            self.raiz, text="Cancelar escaneo", command=self.cancelar_escaneo, state="disabled"
        )
        self.boton_cancelar.pack(pady=(0, 16))

    def _configurar_estilos_tabla(self) -> None:
        """Adapta los colores del Treeview al tema activo."""

        estilo = ttk.Style(self.raiz)
        estilo.theme_use("clam")
        modo = ctk.get_appearance_mode()

        if modo == "Dark":
            fondo = "#1f1f1f"
            texto = "#f5f5f5"
        else:
            fondo = "#f4f4f4"
            texto = "#1a1a1a"

        estilo.configure(
            "Treeview",
            background=fondo,
            fieldbackground=fondo,
            foreground=texto,
            rowheight=28,
            borderwidth=0,
        )
        estilo.map("Treeview", background=[("selected", "#3b8ed0")], foreground=[("selected", "white")])
        estilo.configure("Treeview.Heading", font=("Segoe UI", 11, "bold"))
        estilo.configure("Treeview", font=("Segoe UI", 11))
        estilo.configure("Treeview", highlightthickness=0)
        estilo.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    def _rellenar_interfaces(self) -> None:
        """Carga las opciones de red disponibles en el selector."""

        if not self.interfaces:
            self.estado.set("No se detectaron interfaces con IPv4")
            self.selector_interfaz.configure(values=["—"])
            self.selector_interfaz.set("—")
            return

        etiquetas = [interfaz.etiqueta for interfaz in self.interfaces]
        self.selector_interfaz.configure(values=etiquetas)
        self.selector_interfaz.set(etiquetas[0])

    def iniciar_escaneo_interfaz(self) -> None:
        if not self.interfaces:
            messagebox.showwarning("Seleccionar red", "No hay interfaces disponibles para escanear.")
            return

        etiquetas = [interfaz.etiqueta for interfaz in self.interfaces]
        seleccion = self.selector_interfaz.get()
        try:
            indice = etiquetas.index(seleccion)
        except ValueError:
            messagebox.showwarning(
                "Seleccionar red", "Elija una interfaz válida antes de escanear."
            )
            return

        interfaz = self.interfaces[indice]
        self._iniciar_escaneo(interfaz.red)

    def iniciar_escaneo_red_personalizada(self) -> None:
        texto = self.campo_red_personalizada.get().strip()
        if not texto:
            messagebox.showinfo(
                "Entrada requerida", "Indique una red en formato CIDR, por ejemplo 192.168.1.0/24."
            )
            return

        try:
            red = ipaddress.IPv4Network(texto, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            messagebox.showerror(
                "Formato incorrecto", "Use un formato CIDR válido, por ejemplo 10.0.0.0/24."
            )
            return

        self._iniciar_escaneo(red)

    def _iniciar_escaneo(self, red: ipaddress.IPv4Network) -> None:
        """Limpia la tabla y lanza un nuevo hilo de escaneo."""

        cantidad_hosts = max(red.num_addresses - 2, 0)
        if cantidad_hosts == 0:
            messagebox.showwarning("Red vacía", "La red indicada no contiene hosts para escanear.")
            return

        if cantidad_hosts > MAXIMO_HOSTS:
            continuar = messagebox.askyesno(
                "Red grande",
                (
                    f"La red {red.with_prefixlen} contiene {cantidad_hosts} hosts posibles y puede tardar.\n"
                    "¿Desea continuar?"
                ),
            )
            if not continuar:
                return

        # Mostrar advertencia legal
        advertencia_legal = self._mostrar_advertencia_legal()
        
        if not advertencia_legal:
            return

        self._restablecer_tabla()
        self.red_actual = red
        self.total_hosts = cantidad_hosts
        self.hosts_procesados = 0
        self.estado_base = f"Escaneando {red.with_prefixlen}…"
        self._actualizar_estado_progreso()
        self.boton_cancelar.configure(state="normal")

        self.escaner = EscanerRed(red, self.cola_resultados)
        self.escaner.start()
        self.raiz.after(100, self._procesar_resultados)

    def _procesar_resultados(self) -> None:
        """Consume la cola del hilo para actualizar la tabla."""

        try:
            while True:
                item = self.cola_resultados.get_nowait()
                if item is None:
                    self._finalizar_escaneo()
                    return
                if isinstance(item, tuple) and len(item) >= 5:
                    direccion_ip = item[0]
                    sistema = item[1]
                    activo = item[2]
                    procesados = item[3]
                    puertos = item[4]
                    ttl = item[5] if len(item) >= 6 else None
                    self.hosts_procesados = procesados
                else:
                    direccion_ip, sistema, activo = item  # type: ignore[misc]
                    puertos = []
                    ttl = None
                    self.hosts_procesados += 1
                self._actualizar_estado_progreso()
                if not activo:
                    # Solo mostramos los hosts que responden para mantener la vista limpia.
                    continue
                texto_puertos = ", ".join(str(p) for p in puertos) if puertos else "—"
                sistema_mostrar = sistema or "Sistema desconocido"
                
                # Añadir a cache para filtrado y exportación
                self._hosts_cache.append({
                    "ip": direccion_ip,
                    "os": sistema_mostrar,
                    "puertos": puertos,
                    "estado": "Activo"
                })
                
                self.tabla.insert(
                    "",
                    "end",
                    values=(direccion_ip, sistema_mostrar, texto_puertos, "Activo"),
                )
        except queue.Empty:
            pass

        self.raiz.after(150, self._procesar_resultados)

    def _finalizar_escaneo(self) -> None:
        """Actualiza el estado cuando no quedan hosts pendientes."""

        if self.estado_base.startswith("Cancelando"):
            self.estado_base = "Escaneo cancelado"
        else:
            self.estado_base = "Escaneo finalizado"
        if self.total_hosts > 0:
            progreso = min(self.hosts_procesados / self.total_hosts, 1.0)
            self.barra_progreso.set(progreso)
        else:
            self.barra_progreso.set(0)
        self.estado.set(self.estado_base)
        self.boton_cancelar.configure(state="disabled")
        self.escaner = None
        self.total_hosts = 0
        self.red_actual = None

    def _restablecer_tabla(self) -> None:
        for item in self.tabla.get_children():
            self.tabla.delete(item)
        self.barra_progreso.set(0)
        self.tabla.selection_remove(self.tabla.selection())
        self._hosts_cache.clear()  # Limpiar cache al iniciar nuevo escaneo

    def cancelar_escaneo(self) -> None:
        if self.escaner:
            self.estado_base = "Cancelando…"
            self.estado.set(self.estado_base)
            self.escaner.detener()

    def _mostrar_menu_contextual(self, evento: tk.Event) -> None:
        item = self.tabla.identify_row(evento.y)
        if item:
            self.tabla.selection_set(item)
            self.tabla.focus(item)
            
            # Obtener información del host seleccionado
            valores = self.tabla.item(item, "values")
            if not valores or len(valores) < 3:
                return
            
            ip = valores[0]
            puertos_texto = valores[2]
            
            # Extraer lista de puertos
            puertos = []
            if puertos_texto and puertos_texto != "—":
                try:
                    puertos = [int(p.strip()) for p in puertos_texto.split(",")]
                except (ValueError, AttributeError):
                    puertos = []
            
            # Reconstruir menú contextual dinámicamente
            self.menu_contextual.delete(0, tk.END)
            
            # Opciones siempre disponibles
            self.menu_contextual.add_command(
                label="Escaneo profundo…",
                command=self._iniciar_escaneo_profundo,
            )
            
            self.menu_contextual.add_separator()
            
            # Opciones de mensajería
            self.menu_contextual.add_command(
                label="Enviar mensaje…",
                command=self._iniciar_envio_mensaje,
            )
            self.menu_contextual.add_command(
                label="Enviar mensaje a múltiples…",
                command=self._iniciar_envio_mensaje_multiple,
            )
            
            # Opción SSH si puerto 22 está disponible
            if 22 in puertos:
                self.menu_contextual.add_separator()
                self.menu_contextual.add_command(
                    label="🔐 Conectar por SSH…",
                    command=lambda: self._conectar_ssh(ip),
                )
            
            try:
                self.menu_contextual.tk_popup(evento.x_root, evento.y_root)
            finally:
                self.menu_contextual.grab_release()

    def _iniciar_escaneo_profundo(self) -> None:
        item_id = self.tabla.focus()
        if not item_id:
            messagebox.showinfo(
                "Escaneo profundo",
                "Seleccione un dispositivo activo antes de iniciar el escaneo.",
            )
            return

        valores = self.tabla.item(item_id, "values")
        if not valores:
            return

        direccion_ip = valores[0]
        if not direccion_ip:
            messagebox.showwarning(
                "Escaneo profundo",
                "No se pudo determinar la dirección IP del elemento seleccionado.",
            )
            return

        self._abrir_dialogo_profundo(direccion_ip)

    def _iniciar_envio_mensaje(self) -> None:
        item_id = self.tabla.focus()
        if not item_id:
            messagebox.showinfo(
                "Enviar mensaje",
                "Seleccione un dispositivo activo antes de enviar un mensaje.",
            )
            return

        valores = self.tabla.item(item_id, "values")
        if not valores:
            return

        direccion_ip = valores[0]
        if not direccion_ip:
            messagebox.showwarning(
                "Enviar mensaje",
                "No se pudo determinar la dirección IP del elemento seleccionado.",
            )
            return

        # Verificar si el dispositivo puede recibir mensajes
        tiene_puertos, puertos_abiertos = verificar_disponibilidad_mensajeria(direccion_ip)
        
        if not tiene_puertos:
            respuesta = messagebox.askyesno(
                "Mensajería no disponible",
                f"El dispositivo {direccion_ip} no tiene puertos de mensajería abiertos.\n\n"
                "Puertos verificados: 445 (SMB), 135 (RPC), 139 (NetBIOS), 5985 (WinRM)\n\n"
                "Esto puede deberse a:\n"
                "• No es un dispositivo Windows\n"
                "• Los puertos están bloqueados por firewall\n"
                "• El servicio de mensajería está deshabilitado\n\n"
                "¿Desea intentar enviar el mensaje de todos modos?",
                icon="warning"
            )
            if not respuesta:
                return
        else:
            # Mostrar puertos disponibles
            puertos_str = ", ".join(str(p) for p in puertos_abiertos)
            messagebox.showinfo(
                "Puertos disponibles",
                f"Puertos abiertos detectados en {direccion_ip}:\n{puertos_str}\n\n"
                "Se intentará enviar el mensaje usando el método configurado."
            )

        self._abrir_dialogo_mensaje(direccion_ip)

    def _abrir_dialogo_mensaje(self, direccion_ip: str) -> None:
        ventana = ctk.CTkToplevel(self.raiz)
        ventana.title(f"Enviar mensaje a {direccion_ip}")
        ventana.geometry("500x480")
        ventana.resizable(False, False)
        ventana.transient(self.raiz)
        ventana.grab_set()

        # Centrar ventana
        ventana.update_idletasks()
        pantalla_ancho = ventana.winfo_screenwidth()
        pantalla_alto = ventana.winfo_screenheight()
        ancho = 500
        alto = 480
        posicion_x = int((pantalla_ancho - ancho) / 2)
        posicion_y = int((pantalla_alto - alto) / 2)
        ventana.geometry(f"{ancho}x{alto}+{posicion_x}+{posicion_y}")

        contenedor = ctk.CTkFrame(ventana)
        contenedor.pack(fill="both", expand=True, padx=20, pady=20)

        # Obtener configuración
        config = get_config()
        metodo = config.get("messaging.method", "msg")
        
        # Mostrar método configurado
        metodo_nombre = {
            "msg": "Comando MSG (Windows)",
            "powershell": "PowerShell Remoting",
            "net_send": "Net Send (obsoleto)"
        }.get(metodo, metodo)

        # Encabezado
        header_frame = ctk.CTkFrame(contenedor, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 8))
        
        ctk.CTkLabel(
            header_frame,
            text=f"💬 Enviar mensaje a {direccion_ip}",
            font=("Segoe UI", 16, "bold"),
        ).pack(side="left", anchor="w")

        # Información
        info_frame = ctk.CTkFrame(contenedor)
        info_frame.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            info_frame,
            text=f"Método: {metodo_nombre}",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        ).pack(padx=12, pady=(8, 2), anchor="w")
        
        ctk.CTkLabel(
            info_frame,
            text="ℹ️ El mensaje aparecerá como una notificación en el dispositivo destino.",
            font=("Segoe UI", 9),
            wraplength=440,
            anchor="w",
        ).pack(padx=12, pady=(2, 4), anchor="w")
        
        # Enlace de ayuda
        ayuda_label = ctk.CTkLabel(
            info_frame,
            text="❓ ¿Problemas al enviar? Ver guía de solución de problemas",
            font=("Segoe UI", 9, "underline"),
            text_color=("#1976d2", "#42a5f5"),
            cursor="hand2",
            anchor="w",
        )
        ayuda_label.pack(padx=12, pady=(0, 8), anchor="w")
        ayuda_label.bind("<Button-1>", lambda e: self._mostrar_ayuda_mensajeria())

        # Campo de texto para el mensaje
        ctk.CTkLabel(
            contenedor,
            text="Escribe tu mensaje:",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        texto_mensaje = ctk.CTkTextbox(
            contenedor,
            height=150,
            font=("Segoe UI", 11),
        )
        texto_mensaje.pack(fill="both", expand=True, pady=(0, 12))
        texto_mensaje.focus()

        # Etiqueta de estado
        estado_label = ctk.CTkLabel(
            contenedor,
            text="",
            font=("Segoe UI", 10),
        )
        estado_label.pack(pady=(0, 12))

        # Botones
        botones_frame = ctk.CTkFrame(contenedor, fg_color="transparent")
        botones_frame.pack(fill="x")

        def enviar():
            mensaje = texto_mensaje.get("1.0", "end-1c").strip()
            if not mensaje:
                estado_label.configure(
                    text="⚠️ El mensaje no puede estar vacío.",
                    text_color=("#d32f2f", "#ef5350")
                )
                return

            # Deshabilitar botones mientras se envía
            boton_enviar.configure(state="disabled")
            boton_cancelar.configure(state="disabled")
            estado_label.configure(
                text="📤 Enviando mensaje...",
                text_color=("#1976d2", "#42a5f5")
            )
            ventana.update()

            # Obtener configuración y enviar mensaje
            config = get_config()
            metodo = config.get("messaging.method", "msg")
            exito, mensaje_resultado = enviar_mensaje(direccion_ip, mensaje, metodo)

            if exito:
                estado_label.configure(
                    text=f"✅ {mensaje_resultado}",
                    text_color=("#2e7d32", "#43a047")
                )
                ventana.after(2000, ventana.destroy)
            else:
                # Mostrar error detallado en un messagebox si es error RPC
                if "RPC" in mensaje_resultado or "1722" in mensaje_resultado:
                    messagebox.showerror(
                        "Error de mensajería",
                        mensaje_resultado,
                        parent=ventana
                    )
                    estado_label.configure(
                        text="❌ Error: RPC no disponible. Intente otro método en Preferencias.",
                        text_color=("#d32f2f", "#ef5350")
                    )
                else:
                    estado_label.configure(
                        text=f"❌ {mensaje_resultado}",
                        text_color=("#d32f2f", "#ef5350")
                    )
                
                boton_enviar.configure(state="normal")
                boton_cancelar.configure(state="normal")

        def cerrar():
            ventana.destroy()

        boton_enviar = ctk.CTkButton(
            botones_frame,
            text="📤 Enviar mensaje",
            command=enviar,
            fg_color=("#1976d2", "#42a5f5"),
            hover_color=("#1565c0", "#1e88e5"),
        )
        boton_enviar.pack(side="left", expand=True, padx=(0, 8))

        boton_cancelar = ctk.CTkButton(
            botones_frame,
            text="Cancelar",
            command=cerrar,
            fg_color=("#757575", "#9e9e9e"),
            hover_color=("#616161", "#757575"),
        )
        boton_cancelar.pack(side="right", expand=True, padx=(8, 0))

        ventana.protocol("WM_DELETE_WINDOW", cerrar)

    def _iniciar_envio_mensaje_multiple(self) -> None:
        """Envía un mensaje a múltiples dispositivos seleccionados."""
        items_seleccionados = self.tabla.selection()
        if not items_seleccionados:
            messagebox.showinfo(
                "Enviar mensaje múltiple",
                "Seleccione uno o más dispositivos para enviar el mensaje.\n\n"
                "Puede seleccionar múltiples dispositivos manteniendo presionada la tecla Ctrl."
            )
            return

        # Recopilar direcciones IP
        direcciones_ip = []
        for item_id in items_seleccionados:
            valores = self.tabla.item(item_id, "values")
            if valores and valores[0]:
                direcciones_ip.append(valores[0])

        if not direcciones_ip:
            messagebox.showwarning(
                "Enviar mensaje múltiple",
                "No se pudo determinar las direcciones IP de los dispositivos seleccionados."
            )
            return

        # Verificar disponibilidad de mensajería en los dispositivos
        dispositivos_info = []
        for ip in direcciones_ip:
            tiene_puertos, puertos = verificar_disponibilidad_mensajeria(ip)
            so_detectado = detectar_sistema_operativo_por_puertos(ip)
            dispositivos_info.append({
                "ip": ip,
                "tiene_puertos": tiene_puertos,
                "puertos": puertos,
                "so": so_detectado
            })

        # Mostrar resumen de disponibilidad
        disponibles = sum(1 for d in dispositivos_info if d["tiene_puertos"])
        no_disponibles = len(dispositivos_info) - disponibles

        if no_disponibles > 0:
            respuesta = messagebox.askyesno(
                "Verificación de mensajería",
                f"Dispositivos seleccionados: {len(direcciones_ip)}\n"
                f"✅ Con puertos de mensajería: {disponibles}\n"
                f"⚠️ Sin puertos detectados: {no_disponibles}\n\n"
                "Algunos dispositivos pueden no recibir el mensaje.\n\n"
                "¿Desea continuar de todos modos?",
                icon="warning"
            )
            if not respuesta:
                return

        self._abrir_dialogo_mensaje_multiple(direcciones_ip, dispositivos_info)

    def _abrir_dialogo_mensaje_multiple(self, direcciones_ip: list[str], dispositivos_info: list[dict]) -> None:
        """Muestra el diálogo para enviar mensaje a múltiples dispositivos."""
        ventana = ctk.CTkToplevel(self.raiz)
        ventana.title(f"Enviar mensaje a {len(direcciones_ip)} dispositivos")
        ventana.geometry("700x550")
        ventana.resizable(False, False)
        ventana.transient(self.raiz)
        ventana.grab_set()

        # Centrar ventana
        ventana.update_idletasks()
        pantalla_ancho = ventana.winfo_screenwidth()
        pantalla_alto = ventana.winfo_screenheight()
        ancho = 700
        alto = 550
        posicion_x = int((pantalla_ancho - ancho) / 2)
        posicion_y = int((pantalla_alto - alto) / 2)
        ventana.geometry(f"{ancho}x{alto}+{posicion_x}+{posicion_y}")

        contenedor = ctk.CTkFrame(ventana)
        contenedor.pack(fill="both", expand=True, padx=20, pady=20)

        # Obtener configuración
        config = get_config()
        metodo = config.get("messaging.method", "msg")
        
        metodo_nombre = {
            "msg": "Comando MSG (Windows)",
            "powershell": "PowerShell Remoting",
            "net_send": "Net Send (obsoleto)",
            "ssh_linux": "SSH para Linux/Unix"
        }.get(metodo, metodo)

        # Encabezado
        header_frame = ctk.CTkFrame(contenedor, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 8))
        
        ctk.CTkLabel(
            header_frame,
            text=f"💬 Envío masivo ({len(direcciones_ip)} dispositivos)",
            font=("Segoe UI", 16, "bold"),
        ).pack(side="left", anchor="w")

        # Información
        info_frame = ctk.CTkFrame(contenedor)
        info_frame.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            info_frame,
            text=f"Método: {metodo_nombre}",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        ).pack(padx=12, pady=(8, 2), anchor="w")
        
        # Mostrar dispositivos objetivo
        ips_texto = ", ".join(direcciones_ip[:5])
        if len(direcciones_ip) > 5:
            ips_texto += f" y {len(direcciones_ip) - 5} más..."
        
        ctk.CTkLabel(
            info_frame,
            text=f"Destinos: {ips_texto}",
            font=("Segoe UI", 9),
            wraplength=640,
            anchor="w",
        ).pack(padx=12, pady=(2, 8), anchor="w")

        # Campo de texto para el mensaje
        ctk.CTkLabel(
            contenedor,
            text="Escribe tu mensaje:",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        texto_mensaje = ctk.CTkTextbox(
            contenedor,
            height=120,
            font=("Segoe UI", 11),
        )
        texto_mensaje.pack(fill="x", pady=(0, 12))
        texto_mensaje.focus()

        # Tabla de resultados
        ctk.CTkLabel(
            contenedor,
            text="Estado del envío:",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        # Frame para tabla con scrollbar
        tabla_frame = ctk.CTkFrame(contenedor)
        tabla_frame.pack(fill="both", expand=True, pady=(0, 12))

        columnas_resultado = ("ip", "estado", "mensaje")
        tabla_resultados = ttk.Treeview(
            tabla_frame,
            columns=columnas_resultado,
            show="headings",
            height=8
        )
        tabla_resultados.heading("ip", text="IP")
        tabla_resultados.heading("estado", text="Estado")
        tabla_resultados.heading("mensaje", text="Detalles")
        tabla_resultados.column("ip", width=130, anchor="w")
        tabla_resultados.column("estado", width=100, anchor="center")
        tabla_resultados.column("mensaje", width=400, anchor="w")

        scrollbar_tabla = ttk.Scrollbar(tabla_frame, orient="vertical", command=tabla_resultados.yview)
        tabla_resultados.configure(yscrollcommand=scrollbar_tabla.set)
        
        tabla_resultados.pack(side="left", fill="both", expand=True)
        scrollbar_tabla.pack(side="right", fill="y")

        # Inicializar filas con estado pendiente
        for ip in direcciones_ip:
            tabla_resultados.insert("", "end", values=(ip, "⏳ Pendiente", "Esperando..."))

        # Etiqueta de estado general
        estado_label = ctk.CTkLabel(
            contenedor,
            text="",
            font=("Segoe UI", 10),
        )
        estado_label.pack(pady=(0, 12))

        # Botones
        botones_frame = ctk.CTkFrame(contenedor, fg_color="transparent")
        botones_frame.pack(fill="x")

        def enviar():
            mensaje = texto_mensaje.get("1.0", "end-1c").strip()
            if not mensaje:
                estado_label.configure(
                    text="⚠️ El mensaje no puede estar vacío.",
                    text_color=("#d32f2f", "#ef5350")
                )
                return

            # Deshabilitar botones mientras se envía
            boton_enviar.configure(state="disabled")
            boton_cancelar.configure(state="disabled")
            texto_mensaje.configure(state="disabled")
            
            estado_label.configure(
                text=f"📤 Enviando a {len(direcciones_ip)} dispositivos...",
                text_color=("#1976d2", "#42a5f5")
            )
            ventana.update()

            def tarea_envio():
                # Obtener configuración
                config = get_config()
                metodo = config.get("messaging.method", "msg")
                
                # Enviar a todos los dispositivos
                resultados = enviar_mensaje_multiple(direcciones_ip, mensaje, metodo)
                
                # Actualizar UI en el hilo principal
                def actualizar_ui():
                    exitos = 0
                    fallos = 0
                    
                    # Limpiar tabla
                    for item in tabla_resultados.get_children():
                        tabla_resultados.delete(item)
                    
                    # Insertar resultados
                    for ip, (exito, msg_resultado) in resultados.items():
                        if exito:
                            tabla_resultados.insert("", "end", values=(ip, "✅ Enviado", msg_resultado))
                            exitos += 1
                        else:
                            tabla_resultados.insert("", "end", values=(ip, "❌ Error", msg_resultado))
                            fallos += 1
                    
                    # Actualizar estado general
                    if fallos == 0:
                        estado_label.configure(
                            text=f"✅ Enviado correctamente a todos los dispositivos ({exitos}/{len(direcciones_ip)})",
                            text_color=("#2e7d32", "#43a047")
                        )
                        ventana.after(3000, ventana.destroy)
                    else:
                        estado_label.configure(
                            text=f"⚠️ Completado: {exitos} exitosos, {fallos} fallidos",
                            text_color=("#f57c00", "#fb8c00")
                        )
                        boton_cancelar.configure(state="normal", text="Cerrar")
                
                self.raiz.after(0, actualizar_ui)

            # Ejecutar en hilo separado
            hilo = threading.Thread(target=tarea_envio, daemon=True)
            hilo.start()

        def cerrar():
            ventana.destroy()

        boton_enviar = ctk.CTkButton(
            botones_frame,
            text="📤 Enviar a todos",
            command=enviar,
            fg_color=("#1976d2", "#42a5f5"),
            hover_color=("#1565c0", "#1e88e5"),
        )
        boton_enviar.pack(side="left", expand=True, padx=(0, 8))

        boton_cancelar = ctk.CTkButton(
            botones_frame,
            text="Cancelar",
            command=cerrar,
            fg_color=("#757575", "#9e9e9e"),
            hover_color=("#616161", "#757575"),
        )
        boton_cancelar.pack(side="right", expand=True, padx=(8, 0))

        ventana.protocol("WM_DELETE_WINDOW", cerrar)

    def _abrir_dialogo_profundo(self, direccion_ip: str) -> None:
        if self.ventana_profunda is not None:
            try:
                self.ventana_profunda.destroy()
            except tk.TclError:
                pass

        ventana = ctk.CTkToplevel(self.raiz)
        ventana.title(f"Escaneo profundo — {direccion_ip}")
        ventana.geometry("900x600")
        ventana.transient(self.raiz)
        ventana.grab_set()
        ventana.protocol("WM_DELETE_WINDOW", lambda: self._cerrar_ventana_profunda(ventana))

        etiqueta = ctk.CTkLabel(ventana, text=f"Analizando {direccion_ip}…")
        etiqueta.pack(padx=20, pady=(20, 12), anchor="w")

        barra = ctk.CTkProgressBar(ventana, mode="indeterminate")
        barra.pack(fill="x", padx=20, pady=(0, 20))
        try:
            barra.start()
        except AttributeError:
            pass

        self.ventana_profunda = ventana

        def tarea() -> None:
            resultado = realizar_escaneo_profundo(direccion_ip)
            self.raiz.after(
                0, lambda: self._mostrar_resultado_profundo(ventana, barra, resultado)
            )

        hilo = threading.Thread(target=tarea, daemon=True)
        hilo.start()

    def _mostrar_resultado_profundo(
        self,
        ventana: ctk.CTkToplevel,
        barra: ctk.CTkProgressBar,
        resultado: DeepScanResult,
    ) -> None:
        try:
            barra.stop()
        except AttributeError:
            pass
        for widget in ventana.winfo_children():
            widget.destroy()

        # Contenedor principal con scroll
        contenedor_principal = ctk.CTkScrollableFrame(ventana)
        contenedor_principal.pack(fill="both", expand=True, padx=20, pady=(20, 12))

        # Información básica
        ctk.CTkLabel(
            contenedor_principal,
            text="Información del dispositivo",
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w", pady=(0, 12))

        info_frame = ctk.CTkFrame(contenedor_principal)
        info_frame.pack(fill="x", pady=(0, 16))

        for atributo, valor in self._formatear_resultado_profundo(resultado):
            fila = ctk.CTkFrame(info_frame, fg_color="transparent")
            fila.pack(fill="x", pady=2)
            ctk.CTkLabel(fila, text=f"{atributo}:", font=("Segoe UI", 11, "bold"), width=200, anchor="w").pack(side="left", padx=(8, 4))
            ctk.CTkLabel(fila, text=valor, font=("Segoe UI", 11), anchor="w").pack(side="left", fill="x", expand=True, padx=(4, 8))

        # Análisis de seguridad
        if resultado.vulnerabilidades:
            ctk.CTkLabel(
                contenedor_principal,
                text="⚠️ Análisis de Seguridad",
                font=("Segoe UI", 16, "bold"),
                text_color=("#d32f2f", "#ef5350"),
            ).pack(anchor="w", pady=(16, 12))

            for vuln in resultado.vulnerabilidades:
                vuln_frame = ctk.CTkFrame(contenedor_principal)
                vuln_frame.pack(fill="x", pady=4)
                
                # Color según severidad
                color_nivel = {
                    "CRITICO": ("#b71c1c", "#e53935"),
                    "ALTO": ("#e65100", "#ff6f00"),
                    "MEDIO": ("#f57c00", "#fb8c00"),
                    "BAJO": ("#fbc02d", "#fdd835"),
                    "INFO": ("#1976d2", "#42a5f5"),
                }
                color = color_nivel.get(vuln.nivel, ("#757575", "#9e9e9e"))
                
                nivel_label = ctk.CTkLabel(
                    vuln_frame,
                    text=vuln.nivel,
                    font=("Segoe UI", 10, "bold"),
                    text_color=color,
                    width=80,
                )
                nivel_label.pack(side="left", padx=8, pady=8)
                
                info_vuln = ctk.CTkFrame(vuln_frame, fg_color="transparent")
                info_vuln.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=8)
                
                ctk.CTkLabel(
                    info_vuln,
                    text=vuln.titulo,
                    font=("Segoe UI", 11, "bold"),
                    anchor="w",
                ).pack(anchor="w")
                
                ctk.CTkLabel(
                    info_vuln,
                    text=vuln.descripcion,
                    font=("Segoe UI", 10),
                    anchor="w",
                    wraplength=650,
                ).pack(anchor="w", pady=(2, 0))

        # Recomendaciones
        if resultado.recomendaciones:
            ctk.CTkLabel(
                contenedor_principal,
                text="💡 Recomendaciones",
                font=("Segoe UI", 16, "bold"),
            ).pack(anchor="w", pady=(16, 12))

            rec_frame = ctk.CTkFrame(contenedor_principal)
            rec_frame.pack(fill="x", pady=(0, 16))

            for rec in resultado.recomendaciones:
                ctk.CTkLabel(
                    rec_frame,
                    text=f"• {rec}",
                    font=("Segoe UI", 11),
                    anchor="w",
                ).pack(anchor="w", padx=12, pady=4)

        # Recursos compartidos
        recursos_filtrados = self._filtrar_recursos_compartidos(resultado.recursos_compartidos)
        if recursos_filtrados:
            ctk.CTkLabel(
                contenedor_principal,
                text="📁 Recursos Compartidos",
                font=("Segoe UI", 16, "bold"),
            ).pack(anchor="w", pady=(16, 12))

            contenedor_botones = ctk.CTkFrame(contenedor_principal)
            contenedor_botones.pack(fill="x", pady=(0, 16))
            columnas = 3
            for indice, recurso in enumerate(recursos_filtrados):
                fila = indice // columnas
                columna = indice % columnas
                ruta = f"\\\\{resultado.ip}\\{recurso}"
                boton = ctk.CTkButton(
                    contenedor_botones,
                    text=ruta,
                    command=lambda r=recurso: self._abrir_recurso_compartido(resultado.ip, r),
                )
                boton.grid(row=fila, column=columna, padx=4, pady=4, sticky="ew")
            for columna in range(columnas):
                contenedor_botones.grid_columnconfigure(columna, weight=1)

        ctk.CTkButton(
            ventana,
            text="Cerrar",
            command=lambda: self._cerrar_ventana_profunda(ventana),
        ).pack(pady=(0, 16))

    def _formatear_resultado_profundo(self, resultado: DeepScanResult) -> list[tuple[str, str]]:
        filas: list[tuple[str, str]] = []
        filas.append(("Dirección IP", resultado.ip))
        filas.append(("Nombre de host", resultado.nombre or "—"))
        filas.append(("Tipo de dispositivo", resultado.tipo_dispositivo))
        filas.append(("Sistema operativo", resultado.sistema_operativo))
        filas.append(("TTL detectado", str(resultado.ttl) if resultado.ttl is not None else "—"))

        if resultado.puertos_abiertos:
            filas.append(("Puertos abiertos", ", ".join(str(p) for p in resultado.puertos_abiertos)))
        else:
            filas.append(("Puertos abiertos", "—"))

        recursos_filtrados = self._filtrar_recursos_compartidos(resultado.recursos_compartidos)
        if recursos_filtrados:
            filas.append(("Recursos compartidos", ", ".join(recursos_filtrados)))
        else:
            filas.append(("Recursos compartidos", "—"))

        if resultado.advertencias:
            filas.append(("Advertencias", " | ".join(resultado.advertencias)))

        return filas

    def _filtrar_recursos_compartidos(self, recursos: list[str]) -> list[str]:
        recursos_validos: list[str] = []
        for recurso in recursos:
            texto = recurso.strip()
            if not texto:
                continue
            if "se ha completado el comando correctamente" in texto.lower():
                continue
            recursos_validos.append(texto)
        return recursos_validos

    def _cerrar_ventana_profunda(self, ventana: ctk.CTkToplevel) -> None:
        try:
            ventana.grab_release()
        except tk.TclError:
            pass
        ventana.destroy()
        if self.ventana_profunda is ventana:
            self.ventana_profunda = None

    def _abrir_recurso_compartido(self, ip: str, recurso: str) -> None:
        ruta = f"\\\\{ip}\\{recurso}"
        try:
            os.startfile(ruta)
        except OSError as exc:
            messagebox.showerror(
                "Abrir recurso compartido",
                f"No se pudo abrir {ruta}.\nDetalle: {exc}",
            )

    def _actualizar_estado_progreso(self) -> None:
        if self.total_hosts <= 0:
            self.barra_progreso.set(0)
            self.estado.set(self.estado_base)
            return

        progreso = min(self.hosts_procesados / self.total_hosts, 1.0)
        self.barra_progreso.set(progreso)
        if self.estado_base.startswith("Escaneando") and self.red_actual:
            self.estado.set(
                f"{self.estado_base} {self.hosts_procesados}/{self.total_hosts}"
            )
        else:
            self.estado.set(self.estado_base)

    def _cargar_imagen_splash(self) -> None:
        """Carga la imagen del splash para usar en la advertencia legal."""
        ruta_imagen = os.path.join(os.path.dirname(__file__), "img", "splash.png")
        if not os.path.exists(ruta_imagen):
            self._splash_image = None
            return

        if Image is not None:
            try:
                imagen_base = Image.open(ruta_imagen)
                # Redimensionar a tamaño pequeño (máximo 80x80)
                max_size = 80
                escala = min(max_size / imagen_base.width, max_size / imagen_base.height, 1.0)
                ancho = max(int(imagen_base.width * escala), 1)
                alto = max(int(imagen_base.height * escala), 1)
                self._splash_image = ctk.CTkImage(
                    light_image=imagen_base,
                    dark_image=imagen_base,
                    size=(ancho, alto),
                )
            except Exception:
                self._splash_image = None
        else:
            self._splash_image = None

    def _mostrar_advertencia_legal(self) -> bool:
        """Muestra ventana personalizada de advertencia legal con imagen."""
        resultado = [False]  # Usar lista para permitir modificación en funciones anidadas

        ventana = ctk.CTkToplevel(self.raiz)
        ventana.title("⚠️ Advertencia Legal")
        ventana.resizable(False, False)
        ventana.transient(self.raiz)
        ventana.grab_set()

        ancho, alto = 520, 420
        pantalla_ancho = ventana.winfo_screenwidth()
        pantalla_alto = ventana.winfo_screenheight()
        posicion_x = int((pantalla_ancho - ancho) / 2)
        posicion_y = int((pantalla_alto - alto) / 2)
        ventana.geometry(f"{ancho}x{alto}+{posicion_x}+{posicion_y}")

        # Contenedor principal
        contenedor = ctk.CTkFrame(ventana)
        contenedor.pack(fill="both", expand=True, padx=20, pady=20)

        # Frame superior con título e imagen
        header_frame = ctk.CTkFrame(contenedor, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 16))

        # Título a la izquierda
        ctk.CTkLabel(
            header_frame,
            text="⚠️ IMPORTANTE",
            font=("Segoe UI", 18, "bold"),
            text_color=("#d32f2f", "#ef5350"),
        ).pack(side="left", anchor="w")

        # Imagen a la derecha con borde
        if self._splash_image is not None:
            imagen_container = ctk.CTkFrame(
                header_frame,
                border_width=2,
                border_color=("#cccccc", "#555555"),
            )
            imagen_container.pack(side="right", anchor="e")
            
            imagen_label = ctk.CTkLabel(
                imagen_container,
                image=self._splash_image,
                text="",
            )
            imagen_label.pack(padx=4, pady=4)

        # Subtítulo
        ctk.CTkLabel(
            contenedor,
            text="Responsabilidad Legal",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        # Mensaje de advertencia
        mensaje_frame = ctk.CTkFrame(contenedor, fg_color="transparent")
        mensaje_frame.pack(fill="x", pady=(0, 12))

        mensajes = [
            "• Solo escanee redes de su propiedad o con autorización explícita.",
            "• El escaneo no autorizado de redes puede ser ilegal.",
            "• El uso de esta herramienta es bajo su propia responsabilidad.",
            "• El autor no se hace responsable del uso indebido.",
        ]

        for msg in mensajes:
            ctk.CTkLabel(
                mensaje_frame,
                text=msg,
                font=("Segoe UI", 11),
                anchor="w",
                justify="left",
            ).pack(anchor="w", padx=8, pady=2)

        # Pregunta final
        ctk.CTkLabel(
            contenedor,
            text="¿Confirma que tiene autorización para escanear esta red?",
            font=("Segoe UI", 12, "bold"),
            wraplength=460,
        ).pack(pady=(12, 16))

        # Botones
        botones_frame = ctk.CTkFrame(contenedor, fg_color="transparent")
        botones_frame.pack(fill="x")

        def aceptar():
            resultado[0] = True
            ventana.destroy()

        def cancelar():
            resultado[0] = False
            ventana.destroy()

        ctk.CTkButton(
            botones_frame,
            text="Sí, tengo autorización",
            command=aceptar,
            fg_color=("#2e7d32", "#43a047"),
            hover_color=("#1b5e20", "#2e7d32"),
        ).pack(side="left", expand=True, padx=(0, 8))

        ctk.CTkButton(
            botones_frame,
            text="No, cancelar",
            command=cancelar,
            fg_color=("#c62828", "#e53935"),
            hover_color=("#b71c1c", "#c62828"),
        ).pack(side="right", expand=True, padx=(8, 0))

        ventana.protocol("WM_DELETE_WINDOW", cancelar)
        ventana.wait_window()

        return resultado[0]

    def _limpiar_filtro(self) -> None:
        """Limpia la entrada de búsqueda y muestra todos los resultados."""
        self.entrada_buscar.delete(0, "end")
        self._filtrar_tabla()

    def _conectar_ssh(self, ip: str) -> None:
        """Abre una conexión SSH al dispositivo seleccionado."""
        ventana = ctk.CTkToplevel(self.raiz)
        ventana.title(f"Conexión SSH - {ip}")
        ventana.geometry("520x480")
        ventana.resizable(False, False)
        ventana.transient(self.raiz)
        ventana.grab_set()

        # Centrar ventana
        ventana.update_idletasks()
        pantalla_ancho = ventana.winfo_screenwidth()
        pantalla_alto = ventana.winfo_screenheight()
        ancho = 520
        alto = 480
        posicion_x = int((pantalla_ancho - ancho) / 2)
        posicion_y = int((pantalla_alto - alto) / 2)
        ventana.geometry(f"{ancho}x{alto}+{posicion_x}+{posicion_y}")

        contenedor = ctk.CTkFrame(ventana)
        contenedor.pack(fill="both", expand=True, padx=20, pady=20)

        # Encabezado
        header_frame = ctk.CTkFrame(contenedor, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 12))
        
        ctk.CTkLabel(
            header_frame,
            text=f"🔐 Conexión SSH a {ip}",
            font=("Segoe UI", 16, "bold"),
        ).pack(side="left", anchor="w")

        # Información
        info_frame = ctk.CTkFrame(contenedor)
        info_frame.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            info_frame,
            text="Puerto SSH detectado (22) - Dispositivo accesible por SSH",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        ).pack(padx=12, pady=(8, 4), anchor="w")

        # Campo de usuario
        ctk.CTkLabel(
            contenedor,
            text="Usuario SSH:",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 4))

        entrada_usuario = ctk.CTkEntry(
            contenedor,
            placeholder_text="root, admin, usuario...",
            font=("Segoe UI", 11),
        )
        entrada_usuario.pack(fill="x", pady=(0, 12))
        entrada_usuario.insert(0, "root")  # Usuario por defecto
        entrada_usuario.focus()

        # Opciones
        opciones_frame = ctk.CTkFrame(contenedor)
        opciones_frame.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            opciones_frame,
            text="Opciones de conexión:",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=12, pady=(8, 4))

        var_terminal_externo = ctk.BooleanVar(value=False)
        
        ctk.CTkCheckBox(
            opciones_frame,
            text="Usar terminal externo (Windows Terminal / PowerShell)",
            variable=var_terminal_externo,
            font=("Segoe UI", 10),
        ).pack(anchor="w", padx=24, pady=4)

        # Información adicional
        info_adicional = ctk.CTkFrame(contenedor)
        info_adicional.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            info_adicional,
            text="ℹ️ Nota: Requiere cliente SSH instalado (OpenSSH en Windows 10/11)\n"
                 "La autenticación puede requerir contraseña o clave SSH.",
            font=("Segoe UI", 9),
            wraplength=460,
            justify="left",
        ).pack(padx=12, pady=8)

        # Etiqueta de estado
        estado_label = ctk.CTkLabel(
            contenedor,
            text="",
            font=("Segoe UI", 10),
        )
        estado_label.pack(pady=(0, 12))

        # Botones
        botones_frame = ctk.CTkFrame(contenedor, fg_color="transparent")
        botones_frame.pack(fill="x")

        def conectar():
            usuario = entrada_usuario.get().strip()
            if not usuario:
                estado_label.configure(
                    text="⚠️ Ingrese un nombre de usuario.",
                    text_color=("#d32f2f", "#ef5350")
                )
                return

            usar_externo = var_terminal_externo.get()
            
            # Opciones SSH para compatibilidad con dispositivos antiguos
            # -o HostKeyAlgorithms=+ssh-rsa: Permite ssh-rsa (routers/dispositivos antiguos)
            # -o PubkeyAcceptedKeyTypes=+ssh-rsa: Acepta claves RSA antiguas
            opciones_ssh = '-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa'
            
            try:
                if usar_externo:
                    # Intentar abrir Windows Terminal primero, luego PowerShell
                    comando_wt = f'wt.exe ssh {opciones_ssh} {usuario}@{ip}'
                    comando_ps = f'start powershell.exe -NoExit -Command "ssh {opciones_ssh} {usuario}@{ip}"'
                    
                    try:
                        subprocess.Popen(comando_wt, shell=True)
                        estado_label.configure(
                            text="✅ Terminal externo abierto.",
                            text_color=("#2e7d32", "#43a047")
                        )
                    except:
                        subprocess.Popen(comando_ps, shell=True)
                        estado_label.configure(
                            text="✅ PowerShell abierto.",
                            text_color=("#2e7d32", "#43a047")
                        )
                    ventana.after(1500, ventana.destroy)
                else:
                    # Abrir en terminal embebido de VS Code / sistema
                    comando = f'ssh {opciones_ssh} {usuario}@{ip}'
                    subprocess.Popen(comando, shell=True)
                    estado_label.configure(
                        text="✅ Conexión SSH iniciada en terminal del sistema.",
                        text_color=("#2e7d32", "#43a047")
                    )
                    ventana.after(1500, ventana.destroy)
                    
            except Exception as e:
                estado_label.configure(
                    text=f"❌ Error: {str(e)}",
                    text_color=("#d32f2f", "#ef5350")
                )

        def cerrar():
            ventana.destroy()

        boton_conectar = ctk.CTkButton(
            botones_frame,
            text="🔐 Conectar",
            command=conectar,
            fg_color=("#1976d2", "#42a5f5"),
            hover_color=("#1565c0", "#1e88e5"),
            font=("Segoe UI", 11, "bold"),
        )
        boton_conectar.pack(side="left", expand=True, padx=(0, 8))

        boton_cancelar = ctk.CTkButton(
            botones_frame,
            text="Cancelar",
            command=cerrar,
            font=("Segoe UI", 11),
        )
        boton_cancelar.pack(side="right", expand=True, padx=(8, 0))

        ventana.protocol("WM_DELETE_WINDOW", cerrar)

    def _mostrar_ayuda_mensajeria(self) -> None:
        """Muestra ayuda sobre errores comunes de mensajería."""
        ayuda_texto = """
🔧 SOLUCIÓN DE PROBLEMAS - MENSAJERÍA

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

❌ ERROR 1722: "El servidor RPC no está disponible"

Causas comunes:
• El firewall bloquea el puerto RPC (135)
• El servicio RPC está deshabilitado
• El dispositivo no soporta mensajería remota

Soluciones:

1️⃣ CAMBIAR MÉTODO (Más fácil)
   → Opciones > Preferencias > Mensajería
   → Seleccionar "PowerShell Remoting"

2️⃣ HABILITAR RPC EN DESTINO
   En el equipo que recibe el mensaje:
   • Firewall > Reglas de entrada
   • Habilitar "Administración remota (RPC)"
   • Habilitar "Compartir archivos e impresoras"

3️⃣ VERIFICAR SERVICIOS (en destino)
   • RPC: services.msc → "Llamada a procedimiento remoto (RPC)"
   • Debe estar en "Ejecutándose" y "Automático"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

❌ "No hay sesiones activas"

Solución:
• Debe haber un usuario con sesión iniciada en el destino
• No funciona si solo hay servicios ejecutándose

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

❌ "Acceso denegado"

Soluciones:
• Ejecutar esta aplicación como Administrador
• Verificar permisos en el equipo destino
• El usuario debe ser Admin en ambos equipos

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 MÉTODOS DISPONIBLES

• MSG (Windows): Puerto 135 + 445
  Requiere: RPC habilitado, sesión activa

• PowerShell: Puerto 5985
  Requiere: WinRM habilitado
  Comando (en destino): Enable-PSRemoting -Force

• SSH (Linux): Puerto 22
  Requiere: SSH + autenticación por clave

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 RECOMENDACIONES

Para Windows 10/11 modernos:
→ Usar PowerShell Remoting

Para redes tradicionales:
→ Usar MSG + configurar firewall

Para Linux/Unix:
→ Usar SSH con claves

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📄 Consulte SOLUCION_PROBLEMAS_MENSAJERIA.md
   para instrucciones detalladas paso a paso.
"""
        messagebox.showinfo("Ayuda - Mensajería", ayuda_texto, parent=self.raiz)

    def _filtrar_tabla(self) -> None:
        """Filtra las filas del Treeview según el texto de búsqueda."""
        consulta = self.entrada_buscar.get().strip().lower()
        
        # Limpiar tabla actual
        for item in self.tabla.get_children():
            self.tabla.delete(item)
        
        # Recargar desde cache con filtro
        for host in self._hosts_cache:
            texto_puertos = ", ".join(str(p) for p in host.get("puertos", [])) if host.get("puertos") else "—"
            valores = (
                host.get("ip", ""),
                host.get("os", ""),
                texto_puertos,
                host.get("estado", "")
            )
            
            # Si no hay consulta o la consulta coincide, mostrar
            if not consulta:
                self.tabla.insert("", "end", values=valores)
            else:
                texto_concat = " ".join(str(v) for v in valores).lower()
                if consulta in texto_concat:
                    self.tabla.insert("", "end", values=valores)

    def exportar_csv(self) -> None:
        """Exporta los resultados del escaneo a un archivo CSV."""
        if not self._hosts_cache:
            messagebox.showinfo("Exportar CSV", "No hay datos para exportar.\nRealice un escaneo primero.")
            return
        
        ruta = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Todos los archivos", "*.*")],
            initialfile="escaneo_red.csv",
            title="Exportar resultados a CSV",
        )
        
        if not ruta:
            return
        
        try:
            with open(ruta, "w", newline='', encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=["IP", "Sistema Operativo", "Puertos Abiertos", "Estado"])
                writer.writeheader()
                
                for host in self._hosts_cache:
                    puertos_str = ", ".join(str(p) for p in host.get("puertos", [])) if host.get("puertos") else "—"
                    writer.writerow({
                        "IP": host.get("ip", ""),
                        "Sistema Operativo": host.get("os", ""),
                        "Puertos Abiertos": puertos_str,
                        "Estado": host.get("estado", "")
                    })
            
            messagebox.showinfo(
                "Exportar CSV", 
                f"✅ Resultados exportados correctamente.\n\n"
                f"Archivo: {ruta}\n"
                f"Dispositivos: {len(self._hosts_cache)}"
            )
        except Exception as exc:
            messagebox.showerror("Error al exportar", f"No se pudo exportar el archivo CSV:\n\n{exc}")

    def _iniciar_icono_bandeja(self) -> None:
        """Inicia el icono en la bandeja del sistema."""
        if not PYSTRAY_DISPONIBLE:
            return
        
        # Cargar imagen para el icono de bandeja
        ruta_icono = os.path.join(os.path.dirname(__file__), "img", "splash.png")
        
        if not os.path.exists(ruta_icono):
            return
        
        try:
            # Cargar imagen con PIL
            icono_imagen = Image.open(ruta_icono)
            
            # Crear menú del icono
            menu = pystray.Menu(
                item('Mostrar/Ocultar', self._toggle_ventana, default=True),
                item('Salir', self._salir_aplicacion)
            )
            
            # Crear icono de bandeja
            self.tray_icon = pystray.Icon(
                "enreda2",
                icono_imagen,
                "enredA2 - Network Scanner",
                menu
            )
            
            # Ejecutar icono en hilo separado
            self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
            self.tray_thread.start()
            
        except Exception as e:
            print(f"No se pudo crear icono de bandeja: {e}")

    def _toggle_ventana(self, icon=None, item=None) -> None:
        """Alterna entre mostrar y ocultar la ventana principal."""
        if self.raiz.state() == 'withdrawn' or not self.raiz.winfo_viewable():
            # Mostrar ventana
            self.raiz.deiconify()
            self.raiz.lift()
            self.raiz.focus_force()
        else:
            # Ocultar ventana
            self.raiz.withdraw()

    def _minimizar_a_bandeja(self) -> None:
        """Minimiza la aplicación a la bandeja del sistema en lugar de cerrarla."""
        if PYSTRAY_DISPONIBLE and self.tray_icon:
            self.raiz.withdraw()
        else:
            # Si no hay icono de bandeja, cerrar normalmente
            self._salir_aplicacion()

    def _salir_aplicacion(self, icon=None, item=None) -> None:
        """Cierra completamente la aplicación."""
        # Detener icono de bandeja si existe
        if self.tray_icon:
            self.tray_icon.stop()
        
        # Cerrar ventana principal
        try:
            self.raiz.quit()
            self.raiz.destroy()
        except:
            pass

    def ejecutar(self) -> None:
        self.raiz.mainloop()
