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
import webbrowser

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
from networking.public_ip import obtener_ip_publica_async
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
        self.ip_publica: Optional[str] = None  # IP pública del usuario
        self.label_ip_publica: Optional[ctk.CTkLabel] = None  # Label para mostrar IP pública
        
        # Icono de bandeja del sistema
        self.tray_icon = None
        self.tray_thread = None

        self._construir_interfaz()
        self._rellenar_interfaces()
        self._configurar_estilos_tabla()
        self._cargar_imagen_splash()
        self._iniciar_icono_bandeja()
        self._obtener_ip_publica_inicial()  # Obtener IP pública al iniciar
        
        # Configurar evento de cerrar ventana
        self.raiz.protocol("WM_DELETE_WINDOW", self._minimizar_a_bandeja)

    def _configurar_ventana_modal(self, ventana: ctk.CTkToplevel) -> None:
        """Configura una ventana como modal de forma segura."""
        ventana.transient(self.raiz)
        # Actualizar para que la ventana sea visible antes de grab_set
        ventana.update_idletasks()
        ventana.deiconify()
        # Hacer grab_set de forma segura
        try:
            ventana.grab_set()
        except tk.TclError:
            # Si falla, continuar sin modal
            pass

    def _construir_interfaz(self) -> None:
        """Crea todos los widgets principales con CustomTkinter."""

        padding = {"padx": 12, "pady": 8}

        marco_superior = ctk.CTkFrame(self.raiz)
        marco_superior.pack(fill="x", **padding)
        marco_superior.grid_columnconfigure(1, weight=1)

        # Primera fila: Red detectada + IP Pública (derecha)
        ctk.CTkLabel(marco_superior, text="Red detectada:").grid(row=0, column=0, sticky="w")
        self.selector_interfaz = ctk.CTkComboBox(marco_superior, values=[])
        self.selector_interfaz.grid(row=0, column=1, sticky="ew", padx=8)
        ctk.CTkButton(
            marco_superior,
            text="Escanear red seleccionada",
            command=self.iniciar_escaneo_interfaz,
        ).grid(row=0, column=2, padx=8)
        
        # Frame para IP pública alineada a la derecha en la primera fila
        marco_ip_publica = ctk.CTkFrame(marco_superior, fg_color="transparent")
        marco_ip_publica.grid(row=0, column=3, columnspan=3, sticky="e", padx=(16, 0))
        
        # Label para IP pública
        self.label_ip_publica = ctk.CTkLabel(
            marco_ip_publica,
            text="🌍 IP Pública: Obteniendo...",
            font=("Segoe UI", 10),
            anchor="e"
        )
        self.label_ip_publica.pack(side="left", padx=(0, 8))
        
        # Botón para copiar IP pública
        self.boton_copiar_ip = ctk.CTkButton(
            marco_ip_publica,
            text="📋",
            width=32,
            height=24,
            font=("Segoe UI", 10),
            command=self._copiar_ip_publica,
            state="disabled"
        )
        self.boton_copiar_ip.pack(side="left", padx=(0, 4))
        
        # Botón para actualizar IP pública
        ctk.CTkButton(
            marco_ip_publica,
            text="🔄",
            width=32,
            height=24,
            font=("Segoe UI", 10),
            command=self._actualizar_ip_publica
        ).pack(side="left")

        # Segunda fila: Red personalizada
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
        """Consume la cola del hilo para actualizar la tabla (optimizado con procesamiento por lotes)."""
        resultados_pendientes = []
        actualizar_progreso = False
        
        try:
            # Procesar múltiples elementos de la cola a la vez (mejora rendimiento)
            while True:
                item = self.cola_resultados.get_nowait()
                if item is None:
                    self._finalizar_escaneo()
                    return
                
                resultados_pendientes.append(item)
                
                # Procesar en lotes de 5 para reducir actualizaciones de UI
                if len(resultados_pendientes) >= 5:
                    break
        except queue.Empty:
            pass

        # Procesar resultados acumulados
        for item in resultados_pendientes:
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
            
            actualizar_progreso = True
            
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
        
        # Actualizar progreso solo una vez por lote
        if actualizar_progreso:
            self._actualizar_estado_progreso()

        # Ajustar intervalo según carga (más rápido cuando hay actividad)
        intervalo = 50 if resultados_pendientes else 150
        self.raiz.after(intervalo, self._procesar_resultados)

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
            
            # Opción análisis DNS si puerto 53 está disponible
            if 53 in puertos:
                self.menu_contextual.add_separator()
                self.menu_contextual.add_command(
                    label="🌐 Analizar servidor DNS…",
                    command=lambda: self._analizar_dns(ip),
                )
            
            # Opciones para abrir en navegador si hay puertos web abiertos
            puertos_web = []
            if 80 in puertos:
                puertos_web.append(("http", 80))
            if 443 in puertos:
                puertos_web.append(("https", 443))
            if 8080 in puertos:
                puertos_web.append(("http", 8080))
            if 8443 in puertos:
                puertos_web.append(("https", 8443))
            
            # Otros puertos comunes de web
            for puerto in puertos:
                if puerto in [3000, 5000, 8000, 8888, 9090] and ("http", puerto) not in puertos_web:
                    puertos_web.append(("http", puerto))
            
            if puertos_web:
                self.menu_contextual.add_separator()
                self.menu_contextual.add_command(
                    label="🌐 Abrir en navegador",
                    command=lambda: None,
                    state="disabled",
                    foreground="gray"
                )
                
                for protocolo, puerto in puertos_web:
                    if puerto in [80, 443]:
                        # Puertos estándar, no mostrar el puerto en la etiqueta
                        label = f"   • {protocolo.upper()} ({ip})"
                    else:
                        # Puertos no estándar, mostrar el puerto
                        label = f"   • {protocolo.upper()} ({ip}:{puerto})"
                    
                    self.menu_contextual.add_command(
                        label=label,
                        command=lambda p=protocolo, pt=puerto, i=ip: self._abrir_en_navegador(i, p, pt),
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
        
        # Configurar como modal de forma segura
        self._configurar_ventana_modal(ventana)

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
            "net_send": "Net Send (obsoleto)",
            "ssh_linux": "SSH para Linux/Unix",
            "samba_linux": "Samba/NetBIOS (Linux)",
            "netcat": "Netcat (Socket TCP)",
            "write_unix": "Write Unix (obsoleto)"
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
            so_detectado = detectar_sistema_operativo_por_puertos(puertos)  # Pasar lista de puertos, no IP
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
        
        # Configurar como modal de forma segura
        self._configurar_ventana_modal(ventana)

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
            "ssh_linux": "SSH para Linux/Unix",
            "samba_linux": "Samba/NetBIOS (Linux)",
            "netcat": "Netcat (Socket TCP)",
            "write_unix": "Write Unix (obsoleto)"
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
        
        # Configurar como modal de forma segura
        self._configurar_ventana_modal(ventana)
        
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

        # Crear TabView para organizar la información
        tabview = ctk.CTkTabview(ventana)
        tabview.pack(fill="both", expand=True, padx=20, pady=(20, 12))
        
        # Pestaña 1: Información General
        tab_info = tabview.add("📊 Información General")
        self._crear_tab_informacion_general(tab_info, resultado)
        
        # Pestaña 2: Análisis de Seguridad
        tab_seguridad = tabview.add("🔒 Seguridad")
        self._crear_tab_seguridad(tab_seguridad, resultado)
        
        # Pestaña 3: Opciones Nmap
        tab_nmap = tabview.add("🔍 Nmap Avanzado")
        self._crear_tab_nmap(tab_nmap, resultado.ip)
        
        # Seleccionar primera pestaña por defecto
        tabview.set("📊 Información General")

        ctk.CTkButton(
            ventana,
            text="Cerrar",
            command=lambda: self._cerrar_ventana_profunda(ventana),
        ).pack(pady=(0, 16))
    
    def _crear_tab_informacion_general(self, tab: ctk.CTkFrame, resultado: DeepScanResult) -> None:
        """Crea el contenido de la pestaña de información general"""
        # Contenedor principal con scroll
        contenedor_principal = ctk.CTkScrollableFrame(tab)
        contenedor_principal.pack(fill="both", expand=True, padx=10, pady=10)

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
    
    def _crear_tab_seguridad(self, tab: ctk.CTkFrame, resultado: DeepScanResult) -> None:
        """Crea el contenido de la pestaña de seguridad"""
        contenedor_principal = ctk.CTkScrollableFrame(tab)
        contenedor_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        #Recomendaciones
        if resultado.recomendaciones:
            ctk.CTkLabel(
                contenedor_principal,
                text="💡 Recomendaciones de Seguridad",
                font=("Segoe UI", 16, "bold"),
            ).pack(anchor="w", pady=(0, 12))

            rec_frame = ctk.CTkFrame(contenedor_principal)
            rec_frame.pack(fill="x", pady=(0, 16))

            for rec in resultado.recomendaciones:
                ctk.CTkLabel(
                    rec_frame,
                    text=f"• {rec}",
                    font=("Segoe UI", 11),
                    anchor="w",
                ).pack(anchor="w", padx=12, pady=4)
        else:
            ctk.CTkLabel(
                contenedor_principal,
                text="✅ No se encontraron problemas de seguridad",
                font=("Segoe UI", 14),
                text_color=("#2e7d32", "#66bb6a"),
            ).pack(anchor="w", pady=20)
    
    def _crear_tab_nmap(self, tab: ctk.CTkFrame, ip: str) -> None:
        """Crea el contenido de la pestaña de Nmap avanzado"""
        from networking.nmap_integration import nmap_disponible, obtener_info_nmap, scan_host_nmap, requiere_privilegios
        
        contenedor_principal = ctk.CTkScrollableFrame(tab)
        contenedor_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Verificar disponibilidad de Nmap
        disponible, mensaje = obtener_info_nmap()
        
        # Título
        ctk.CTkLabel(
            contenedor_principal,
            text="🔍 Escaneo Avanzado con Nmap",
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w", pady=(0, 8))
        
        # Estado de Nmap
        color_estado = ("#2e7d32", "#66bb6a") if disponible else ("#d32f2f", "#ef5350")
        ctk.CTkLabel(
            contenedor_principal,
            text=mensaje,
            font=("Segoe UI", 11),
            text_color=color_estado,
        ).pack(anchor="w", pady=(0, 16))
        
        if not disponible:
            ctk.CTkLabel(
                contenedor_principal,
                text="Para usar las funciones avanzadas de Nmap:",
                font=("Segoe UI", 11, "bold"),
            ).pack(anchor="w", pady=(8, 4))
            
            ctk.CTkLabel(
                contenedor_principal,
                text="1. Instale Nmap: https://nmap.org/download.html",
                font=("Segoe UI", 10),
            ).pack(anchor="w", padx=20, pady=2)
            
            ctk.CTkLabel(
                contenedor_principal,
                text="2. Instale python-nmap: pip install python-nmap",
                font=("Segoe UI", 10),
            ).pack(anchor="w", padx=20, pady=2)
            return
        
        # Opciones de escaneo
        ctk.CTkLabel(
            contenedor_principal,
            text="Opciones de Escaneo",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(16, 8))
        
        # Frame para opciones
        opciones_frame = ctk.CTkFrame(contenedor_principal)
        opciones_frame.pack(fill="x", pady=(0, 16))
        
        # Variables para almacenar selecciones
        scan_options = {}
        
        # Opción 1: Detección de servicios y versiones
        scan_options["deteccion_servicios"] = ctk.CTkCheckBox(
            opciones_frame,
            text="Detección de servicios y versiones (-sV)",
        )
        scan_options["deteccion_servicios"].pack(anchor="w", padx=12, pady=4)
        scan_options["deteccion_servicios"].select()  # Seleccionado por defecto
        
        # Opción 2: Detección de Sistema Operativo
        scan_options["deteccion_os"] = ctk.CTkCheckBox(
            opciones_frame,
            text="Detección de Sistema Operativo (-O)",
        )
        scan_options["deteccion_os"].pack(anchor="w", padx=12, pady=4)
        
        # Opción 3: Scripts de NSE
        scan_options["scripts_nse"] = ctk.CTkCheckBox(
            opciones_frame,
            text="Scripts de vulnerabilidades (--script=vuln)",
        )
        scan_options["scripts_nse"].pack(anchor="w", padx=12, pady=4)
        
        # Opción 4: Escaneo agresivo
        scan_options["agresivo"] = ctk.CTkCheckBox(
            opciones_frame,
            text="Escaneo agresivo (-A: OS, versión, scripts, traceroute)",
        )
        scan_options["agresivo"].pack(anchor="w", padx=12, pady=4)
        
        # Opción 5: Velocidad de escaneo
        ctk.CTkLabel(
            opciones_frame,
            text="Velocidad de escaneo:",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=12, pady=(12, 4))
        
        scan_options["velocidad"] = ctk.CTkSegmentedButton(
            opciones_frame,
            values=["Lento (-T2)", "Normal (-T3)", "Rápido (-T4)", "Muy rápido (-T5)"],
        )
        scan_options["velocidad"].pack(anchor="w", padx=12, pady=4, fill="x")
        scan_options["velocidad"].set("Rápido (-T4)")  # Valor por defecto
        
        # Opción 6: Puertos a escanear
        ctk.CTkLabel(
            opciones_frame,
            text="Puertos a escanear:",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=12, pady=(12, 4))
        
        scan_options["puertos"] = ctk.CTkSegmentedButton(
            opciones_frame,
            values=["Top 100", "Top 1000", "Todos", "Personalizado"],
        )
        scan_options["puertos"].pack(anchor="w", padx=12, pady=4, fill="x")
        scan_options["puertos"].set("Top 1000")  # Valor por defecto
        
        # Entry para puertos personalizados
        scan_options["puertos_custom"] = ctk.CTkEntry(
            opciones_frame,
            placeholder_text="Ej: 22,80,443,8080 o 1-1000",
        )
        scan_options["puertos_custom"].pack(anchor="w", padx=12, pady=4, fill="x")
        
        # Área de resultados
        ctk.CTkLabel(
            contenedor_principal,
            text="Resultados del Escaneo",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(16, 8))
        
        resultado_text = ctk.CTkTextbox(
            contenedor_principal,
            height=300,
            font=("Consolas", 10),
        )
        resultado_text.pack(fill="both", expand=True, pady=(0, 12))
        resultado_text.insert("1.0", f"Host objetivo: {ip}\n\nHaga clic en 'Iniciar Escaneo' para comenzar...\n")
        resultado_text.configure(state="disabled")
        
        # Barra de progreso
        progreso = ctk.CTkProgressBar(contenedor_principal, mode="indeterminate")
        progreso.pack(fill="x", pady=8)
        progreso.pack_forget()  # Ocultar inicialmente
        
        # Botón para iniciar escaneo
        def iniciar_escaneo_nmap():
            # Construir argumentos de nmap
            args = []
            
            # Agregar opciones seleccionadas
            if scan_options["agresivo"].get():
                args.append("-A")
            else:
                if scan_options["deteccion_servicios"].get():
                    args.append("-sV")
                if scan_options["deteccion_os"].get():
                    args.append("-O")
                if scan_options["scripts_nse"].get():
                    args.append("--script=vuln")
            
            # Velocidad
            velocidad_map = {
                "Lento (-T2)": "-T2",
                "Normal (-T3)": "-T3",
                "Rápido (-T4)": "-T4",
                "Muy rápido (-T5)": "-T5",
            }
            args.append(velocidad_map[scan_options["velocidad"].get()])
            
            # Puertos
            puertos_sel = scan_options["puertos"].get()
            if puertos_sel == "Top 100":
                args.append("--top-ports 100")
            elif puertos_sel == "Top 1000":
                args.append("--top-ports 1000")
            elif puertos_sel == "Personalizado":
                puertos_custom = scan_options["puertos_custom"].get().strip()
                if puertos_custom:
                    args.append(f"-p {puertos_custom}")
            # "Todos" no requiere argumento especial
            
            argumentos_nmap = " ".join(args)
            
            # Verificar si requiere privilegios
            import platform
            necesita_privilegios = requiere_privilegios(argumentos_nmap)
            sudo_password = None
            
            if necesita_privilegios:
                sistema = platform.system()
                
                if sistema == "Windows":
                    # En Windows, verificar si es admin
                    import ctypes
                    try:
                        es_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                        if not es_admin:
                            messagebox.showwarning(
                                "Privilegios requeridos",
                                "Esta operación requiere privilegios de administrador.\n\n"
                                "Por favor, cierre la aplicación y ejecútela como administrador."
                            )
                            return
                    except:
                        messagebox.showwarning(
                            "Advertencia",
                            "No se pudo verificar los privilegios de administrador.\n"
                            "Si el escaneo falla, ejecute la aplicación como administrador."
                        )
                else:
                    # En Linux/Mac, solicitar contraseña si no es root
                    import subprocess
                    if subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() != '0':
                        # Crear diálogo para solicitar contraseña
                        dialog = ctk.CTkToplevel(self.raiz)
                        dialog.title("Privilegios de Administrador")
                        dialog.geometry("400x220")
                        dialog.transient(self.raiz)
                        
                        # Centrar el diálogo
                        dialog.update_idletasks()
                        x = (dialog.winfo_screenwidth() // 2) - (400 // 2)
                        y = (dialog.winfo_screenheight() // 2) - (220 // 2)
                        dialog.geometry(f"400x220+{x}+{y}")
                        
                        ctk.CTkLabel(
                            dialog,
                            text="⚠️ Privilegios de Administrador Requeridos",
                            font=("Segoe UI", 14, "bold"),
                        ).pack(pady=(20, 10))
                        
                        ctk.CTkLabel(
                            dialog,
                            text="Esta operación requiere privilegios elevados.\n"
                                 "Por favor, introduzca su contraseña de sudo:",
                            font=("Segoe UI", 11),
                        ).pack(pady=(0, 15))
                        
                        password_var = ctk.StringVar()
                        password_entry = ctk.CTkEntry(
                            dialog,
                            textvariable=password_var,
                            show="●",
                            placeholder_text="Contraseña",
                            width=300,
                            height=35,
                        )
                        password_entry.pack(pady=10)
                        
                        resultado_dialog = {"aceptado": False}
                        
                        def aceptar():
                            resultado_dialog["aceptado"] = True
                            dialog.destroy()
                        
                        def cancelar():
                            resultado_dialog["aceptado"] = False
                            dialog.destroy()
                        
                        # Bind Enter key
                        password_entry.bind("<Return>", lambda e: aceptar())
                        
                        # Botones
                        botones_frame = ctk.CTkFrame(dialog)
                        botones_frame.pack(pady=15)
                        
                        ctk.CTkButton(
                            botones_frame,
                            text="Cancelar",
                            command=cancelar,
                            width=120,
                            fg_color="gray",
                        ).pack(side="left", padx=5)
                        
                        ctk.CTkButton(
                            botones_frame,
                            text="Aceptar",
                            command=aceptar,
                            width=120,
                        ).pack(side="left", padx=5)
                        
                        # Asegurarse de que la ventana esté completamente visible antes de grab_set
                        dialog.update()
                        dialog.deiconify()
                        
                        # Ahora sí capturar el foco
                        try:
                            dialog.grab_set()
                            password_entry.focus()
                        except:
                            # Si falla grab_set, no es crítico, el diálogo sigue funcionando
                            password_entry.focus()
                        
                        dialog.wait_window()
                        
                        if not resultado_dialog["aceptado"]:
                            return
                        
                        sudo_password = password_var.get()
                        if not sudo_password:
                            messagebox.showwarning("Error", "Debe introducir una contraseña")
                            return
            
            # Mostrar progreso
            resultado_text.configure(state="normal")
            resultado_text.delete("1.0", "end")
            resultado_text.insert("1.0", f"Escaneando {ip} con opciones: {argumentos_nmap}\n\n")
            resultado_text.insert("end", "Esto puede tardar varios minutos dependiendo de las opciones seleccionadas...\n")
            resultado_text.configure(state="disabled")
            progreso.pack(fill="x", pady=8)
            progreso.start()
            boton_escanear.configure(state="disabled")
            
            def ejecutar_escaneo():
                try:
                    result = scan_host_nmap(ip, argumentos_nmap, sudo_password)
                    self.raiz.after(0, lambda: mostrar_resultado_nmap(result, None))
                except Exception as e:
                    error_msg = str(e)
                    self.raiz.after(0, lambda: mostrar_resultado_nmap(None, error_msg))
            
            def mostrar_resultado_nmap(result, error):
                progreso.stop()
                progreso.pack_forget()
                boton_escanear.configure(state="normal")
                
                resultado_text.configure(state="normal")
                resultado_text.delete("1.0", "end")
                
                if error:
                    resultado_text.insert("1.0", f"❌ Error al escanear:\n{error}\n")
                else:
                    # Formatear resultado
                    resultado_text.insert("1.0", f"✅ Escaneo completado para {ip}\n")
                    resultado_text.insert("end", "=" * 60 + "\n\n")
                    
                    resultado_text.insert("end", f"Estado: {result.get('state', 'desconocido')}\n")
                    resultado_text.insert("end", f"Hostname: {result.get('hostname', 'N/A')}\n")
                    resultado_text.insert("end", f"Protocolos: {', '.join(result.get('protocols', []))}\n\n")
                    
                    # Puertos
                    if result.get('ports'):
                        resultado_text.insert("end", "PUERTOS ABIERTOS:\n")
                        resultado_text.insert("end", "-" * 60 + "\n")
                        for port_info in result['ports']:
                            puerto = port_info['port']
                            estado = port_info['state']
                            servicio = port_info['service']
                            producto = port_info['product']
                            version = port_info['version']
                            
                            linea = f"{puerto}/tcp\t{estado}\t{servicio}"
                            if producto:
                                linea += f" ({producto}"
                                if version:
                                    linea += f" {version}"
                                linea += ")"
                            resultado_text.insert("end", linea + "\n")
                        resultado_text.insert("end", "\n")
                    
                    # Sistema Operativo
                    if result.get('os'):
                        resultado_text.insert("end", "SISTEMA OPERATIVO:\n")
                        resultado_text.insert("end", "-" * 60 + "\n")
                        for os_info in result['os']:
                            resultado_text.insert("end", f"{os_info['name']} (certeza: {os_info['accuracy']}%)\n")
                        resultado_text.insert("end", "\n")
                
                resultado_text.configure(state="disabled")
            
            # Ejecutar en hilo separado
            thread = threading.Thread(target=ejecutar_escaneo, daemon=True)
            thread.start()
        
        boton_escanear = ctk.CTkButton(
            contenedor_principal,
            text="🚀 Iniciar Escaneo",
            command=iniciar_escaneo_nmap,
            font=("Segoe UI", 12, "bold"),
            height=40,
        )
        boton_escanear.pack(fill="x", pady=8)

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
        """
        Abre un recurso compartido SMB en el explorador de archivos.
        Compatible con Windows, Linux y macOS.
        """
        import platform
        import shutil
        
        ruta_windows = f"\\\\{ip}\\{recurso}"
        ruta_smb = f"smb://{ip}/{recurso}"
        sistema = platform.system()
        exito = False
        
        try:
            if sistema == "Windows":
                # Windows: intentar varios métodos
                try:
                    # Método 1: os.startfile (más confiable en Windows)
                    if hasattr(os, 'startfile'):
                        os.startfile(ruta_windows)  # type: ignore
                        exito = True
                    else:
                        # Método 2: explorer.exe
                        resultado = subprocess.run(
                            ["explorer", ruta_windows],
                            capture_output=True,
                            timeout=2
                        )
                        exito = resultado.returncode == 0
                        
                except Exception as e:
                    # Si falla, mostrar diálogo con opciones
                    self._mostrar_dialogo_recurso_compartido(ip, recurso, ruta_windows, str(e), es_windows=True)
                    return
                    
            elif sistema == "Darwin":  # macOS
                # macOS: usar open con smb://
                try:
                    subprocess.Popen(["open", ruta_smb])
                    exito = True
                except Exception as e:
                    self._mostrar_dialogo_recurso_compartido(ip, recurso, ruta_smb, str(e), es_windows=False)
                    return
                
            else:  # Linux
                # En Linux, probar varios métodos en orden de preferencia
                
                # Método 1: Nautilus con smb:// (GNOME)
                if shutil.which("nautilus"):
                    try:
                        subprocess.Popen(["nautilus", ruta_smb], 
                                       stderr=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL)
                        exito = True
                        return
                    except Exception:
                        pass
                
                # Método 2: Dolphin (KDE)
                if shutil.which("dolphin"):
                    try:
                        subprocess.Popen(["dolphin", ruta_smb],
                                       stderr=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL)
                        exito = True
                        return
                    except Exception:
                        pass
                
                # Método 3: Thunar (XFCE)
                if shutil.which("thunar"):
                    try:
                        subprocess.Popen(["thunar", ruta_smb],
                                       stderr=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL)
                        exito = True
                        return
                    except Exception:
                        pass
                
                # Método 4: PCManFM (LXDE)
                if shutil.which("pcmanfm"):
                    try:
                        subprocess.Popen(["pcmanfm", ruta_smb],
                                       stderr=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL)
                        exito = True
                        return
                    except Exception:
                        pass
                
                # Método 5: Caja (MATE)
                if shutil.which("caja"):
                    try:
                        subprocess.Popen(["caja", ruta_smb],
                                       stderr=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL)
                        exito = True
                        return
                    except Exception:
                        pass
                
                # Método 6: Nemo (Cinnamon)
                if shutil.which("nemo"):
                    try:
                        subprocess.Popen(["nemo", ruta_smb],
                                       stderr=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL)
                        exito = True
                        return
                    except Exception:
                        pass
                
                # Si ningún explorador gráfico funciona, mostrar diálogo con opciones
                if not exito:
                    self._mostrar_dialogo_recurso_compartido(ip, recurso, ruta_smb, 
                                                            "No se encontró explorador de archivos compatible", 
                                                            es_windows=False)
                
        except Exception as exc:
            # Si hay error, mostrar diálogo con opciones
            ruta_mostrar = ruta_windows if sistema == "Windows" else ruta_smb
            self._mostrar_dialogo_recurso_compartido(ip, recurso, ruta_mostrar, str(exc), 
                                                    es_windows=(sistema == "Windows"))
    
    def _mostrar_dialogo_recurso_compartido(self, ip: str, recurso: str, 
                                           ruta: str, error: Optional[str] = None,
                                           es_windows: bool = False) -> None:
        """
        Muestra un diálogo con opciones para acceder al recurso compartido.
        Instrucciones específicas para Windows y Linux.
        """
        import platform
        
        # Si no se especificó, detectar sistema
        if not es_windows and platform.system() == "Windows":
            es_windows = True
        
        ventana = ctk.CTkToplevel(self.raiz)
        ventana.title("Recurso Compartido SMB")
        ventana.geometry("600x500")
        ventana.resizable(False, False)
        
        # Configurar como modal
        self._configurar_ventana_modal(ventana)
        
        # Centrar ventana
        ventana.update_idletasks()
        pantalla_ancho = ventana.winfo_screenwidth()
        pantalla_alto = ventana.winfo_screenheight()
        ancho = 600
        alto = 500
        posicion_x = int((pantalla_ancho - ancho) / 2)
        posicion_y = int((pantalla_alto - alto) / 2)
        ventana.geometry(f"{ancho}x{alto}+{posicion_x}+{posicion_y}")
        
        contenedor = ctk.CTkFrame(ventana)
        contenedor.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Encabezado
        sistema_texto = "Windows" if es_windows else "Linux/macOS"
        ctk.CTkLabel(
            contenedor,
            text=f"📁 Acceder a Recurso Compartido ({sistema_texto})",
            font=("Segoe UI", 16, "bold"),
        ).pack(pady=(0, 12))
        
        # Información del recurso
        info_frame = ctk.CTkFrame(contenedor)
        info_frame.pack(fill="x", pady=(0, 12))
        
        ctk.CTkLabel(
            info_frame,
            text=f"IP: {ip}",
            font=("Segoe UI", 11),
            anchor="w"
        ).pack(padx=12, pady=4, anchor="w")
        
        ctk.CTkLabel(
            info_frame,
            text=f"Recurso: {recurso}",
            font=("Segoe UI", 11),
            anchor="w"
        ).pack(padx=12, pady=4, anchor="w")
        
        # Ruta
        titulo_ruta = "Ruta UNC:" if es_windows else "Ruta SMB:"
        ctk.CTkLabel(
            contenedor,
            text=titulo_ruta,
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(8, 4))
        
        entrada_ruta = ctk.CTkEntry(
            contenedor,
            font=("Consolas", 10),
        )
        entrada_ruta.pack(fill="x", pady=(0, 4))
        entrada_ruta.insert(0, ruta)
        entrada_ruta.configure(state="readonly")
        
        # Botón copiar ruta
        ctk.CTkButton(
            contenedor,
            text="📋 Copiar ruta",
            command=lambda: self._copiar_texto(ruta, ventana),
            width=150
        ).pack(pady=(0, 12))
        
        # Instrucciones específicas por sistema
        ctk.CTkLabel(
            contenedor,
            text="📝 Instrucciones:",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(8, 4))
        
        instrucciones_frame = ctk.CTkScrollableFrame(contenedor, height=200)
        instrucciones_frame.pack(fill="both", expand=True, pady=(0, 12))
        
        if es_windows:
            instrucciones = f"""
MÉTODO 1: Explorador de Archivos (Recomendado)
  1. Abrir Explorador de Windows (Win + E)
  2. En la barra de direcciones, pegar: {ruta}
  3. Presionar Enter
  4. Si pide credenciales, ingresar usuario y contraseña

MÉTODO 2: Ejecutar (Win + R)
  1. Presionar Win + R
  2. Escribir: {ruta}
  3. Presionar Enter

MÉTODO 3: Mapear Unidad de Red
  1. Clic derecho en "Este equipo" → "Conectar a unidad de red"
  2. Elegir letra de unidad (ej: Z:)
  3. Carpeta: {ruta}
  4. Marcar "Conectar de nuevo al iniciar sesión" (opcional)
  5. Clic en "Finalizar"

MÉTODO 4: Línea de Comandos (CMD/PowerShell)
  cmd: net use Z: {ruta} /persistent:yes
  powershell: New-PSDrive -Name "Z" -PSProvider "FileSystem" -Root "{ruta}"

NOTA: Puede requerir:
  • Usuario de red válido
  • Habilitar SMB en Windows (si está deshabilitado)
  • Agregar el host a redes de confianza
            """
        else:  # Linux/macOS
            instrucciones = f"""
MÉTODO 1: Explorador de Archivos (Recomendado)
  1. Abrir explorador de archivos
  2. Presionar Ctrl+L (GNOME) o F3 (otros)
  3. Pegar la ruta: {ruta}
  4. Presionar Enter
  5. Ingresar credenciales si es necesario

MÉTODO 2: Línea de Comandos
  # GNOME/Nautilus
  nautilus '{ruta}'
  
  # KDE/Dolphin
  dolphin '{ruta}'
  
  # XFCE/Thunar
  thunar '{ruta}'

MÉTODO 3: Montar con smbclient
  smbclient //{ip}/{recurso} -U usuario
  # Listar archivos: ls
  # Descargar: get archivo.txt
  # Subir: put archivo.txt

MÉTODO 4: Montar como sistema de archivos
  # Crear punto de montaje
  sudo mkdir -p /mnt/smb_{recurso}
  
  # Montar (temporal)
  sudo mount -t cifs //{ip}/{recurso} /mnt/smb_{recurso} -o username=USUARIO
  
  # Montar (permanente en /etc/fstab)
  //{ip}/{recurso} /mnt/smb_{recurso} cifs username=USUARIO,password=PASS 0 0

REQUISITOS:
  • Paquetes: smbclient, gvfs-backends (o gvfs-smb)
  • Ubuntu/Debian: sudo apt install smbclient gvfs-backends
  • Fedora: sudo dnf install samba-client gvfs-smb
  • Arch: sudo pacman -S smbclient gvfs-smb
            """
        
        ctk.CTkLabel(
            instrucciones_frame,
            text=instrucciones.strip(),
            font=("Consolas", 9),
            justify="left",
            anchor="w"
        ).pack(padx=8, pady=8, fill="x")
        
        # Mensaje de error si existe
        if error:
            ctk.CTkLabel(
                contenedor,
                text=f"⚠️ Error: {error}",
                font=("Segoe UI", 9),
                text_color=("#d32f2f", "#ef5350"),
                wraplength=540
            ).pack(pady=(8, 0))
        
        # Botón cerrar
        ctk.CTkButton(
            contenedor,
            text="Cerrar",
            command=ventana.destroy,
        ).pack(pady=(8, 0))
    
    def _copiar_texto(self, texto: str, ventana_padre: Optional[ctk.CTkToplevel] = None) -> None:
        """Copia texto al portapapeles y muestra confirmación."""
        try:
            if ventana_padre:
                ventana_padre.clipboard_clear()
                ventana_padre.clipboard_append(texto)
            else:
                self.raiz.clipboard_clear()
                self.raiz.clipboard_append(texto)
            
            messagebox.showinfo(
                "Copiado",
                "Ruta copiada al portapapeles",
                parent=ventana_padre if ventana_padre else self.raiz
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"No se pudo copiar: {e}",
                parent=ventana_padre if ventana_padre else self.raiz
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

    def _obtener_ip_publica_inicial(self) -> None:
        """Obtiene la IP pública al iniciar la aplicación."""
        def callback(ip: Optional[str], proveedor: str):
            """Callback para actualizar la UI con la IP pública."""
            if ip:
                self.ip_publica = ip
                self.label_ip_publica.configure(
                    text=f"🌍 IP Pública: {ip} (vía {proveedor})"
                )
                self.boton_copiar_ip.configure(state="normal")
            else:
                self.ip_publica = None
                self.label_ip_publica.configure(
                    text=f"🌍 IP Pública: {proveedor}",
                    text_color=("#666666", "#999999")
                )
                self.boton_copiar_ip.configure(state="disabled")
        
        # Obtener IP pública de forma asíncrona
        obtener_ip_publica_async(callback, timeout=5)
    
    def _actualizar_ip_publica(self) -> None:
        """Actualiza la IP pública manualmente."""
        self.label_ip_publica.configure(
            text="🌍 IP Pública: Actualizando..."
        )
        self.boton_copiar_ip.configure(state="disabled")
        
        def callback(ip: Optional[str], proveedor: str):
            """Callback para actualizar la UI con la IP pública."""
            if ip:
                self.ip_publica = ip
                self.label_ip_publica.configure(
                    text=f"🌍 IP Pública: {ip} (vía {proveedor})"
                )
                self.boton_copiar_ip.configure(state="normal")
            else:
                self.ip_publica = None
                self.label_ip_publica.configure(
                    text=f"🌍 IP Pública: {proveedor}",
                    text_color=("#666666", "#999999")
                )
                self.boton_copiar_ip.configure(state="disabled")
        
        # Obtener IP pública de forma asíncrona
        obtener_ip_publica_async(callback, timeout=5)
    
    def _copiar_ip_publica(self) -> None:
        """Copia la IP pública al portapapeles."""
        if self.ip_publica:
            self.raiz.clipboard_clear()
            self.raiz.clipboard_append(self.ip_publica)
            
            # Mostrar confirmación temporal
            texto_original = self.boton_copiar_ip.cget("text")
            self.boton_copiar_ip.configure(text="✅ Copiada")
            
            def restaurar_texto():
                self.boton_copiar_ip.configure(text=texto_original)
            
            self.raiz.after(2000, restaurar_texto)

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

        ancho, alto = 520, 420
        pantalla_ancho = ventana.winfo_screenwidth()
        pantalla_alto = ventana.winfo_screenheight()
        posicion_x = int((pantalla_ancho - ancho) / 2)
        posicion_y = int((pantalla_alto - alto) / 2)
        ventana.geometry(f"{ancho}x{alto}+{posicion_x}+{posicion_y}")
        
        # Configurar como modal de forma segura
        self._configurar_ventana_modal(ventana)

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

    def _abrir_en_navegador(self, ip: str, protocolo: str = "http", puerto: int = 80) -> None:
        """Abre la dirección IP en el navegador predeterminado del sistema."""
        try:
            # Construir URL
            if (protocolo == "http" and puerto == 80) or (protocolo == "https" and puerto == 443):
                # Puerto estándar, no incluir en la URL
                url = f"{protocolo}://{ip}"
            else:
                # Puerto no estándar, incluir en la URL
                url = f"{protocolo}://{ip}:{puerto}"
            
            # Abrir en el navegador predeterminado
            webbrowser.open(url)
            
            # Mostrar notificación
            self.estado.set(f"Abriendo {url} en el navegador...")
            self.raiz.after(3000, lambda: self.estado.set(self.estado_base))
            
        except Exception as e:
            messagebox.showerror(
                "Error al abrir navegador",
                f"No se pudo abrir la dirección en el navegador:\n{e}"
            )

    def _conectar_ssh(self, ip: str) -> None:
        """Abre una conexión SSH al dispositivo seleccionado."""
        ventana = ctk.CTkToplevel(self.raiz)
        ventana.title(f"Conexión SSH - {ip}")
        ventana.geometry("520x480")
        ventana.resizable(False, False)
        
        # Configurar como modal de forma segura
        self._configurar_ventana_modal(ventana)

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

    def _analizar_dns(self, ip: str) -> None:
        """Analiza un servidor DNS detectado en el puerto 53."""
        from networking.dns_analysis import (
            analizar_servidor_dns,
            obtener_descripcion_dns,
            obtener_recomendaciones_seguridad_dns,
        )
        
        ventana = ctk.CTkToplevel(self.raiz)
        ventana.title(f"Análisis DNS - {ip}")
        ventana.geometry("700x650")
        
        # Configurar como modal de forma segura
        self._configurar_ventana_modal(ventana)

        # Centrar ventana
        ventana.update_idletasks()
        pantalla_ancho = ventana.winfo_screenwidth()
        pantalla_alto = ventana.winfo_screenheight()
        ancho = 700
        alto = 650
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
            text=f"🌐 Análisis de Servidor DNS",
            font=("Segoe UI", 18, "bold"),
        ).pack(side="left", anchor="w")

        # IP del servidor
        ctk.CTkLabel(
            contenedor,
            text=f"Dirección IP: {ip}",
            font=("Segoe UI", 12),
        ).pack(anchor="w", pady=(0, 8))

        # Label de estado
        estado_label = ctk.CTkLabel(
            contenedor,
            text="🔍 Analizando servidor DNS...",
            font=("Segoe UI", 11),
        )
        estado_label.pack(pady=8)

        # Frame scrollable para resultados
        scroll_frame = ctk.CTkScrollableFrame(contenedor, height=450)
        scroll_frame.pack(fill="both", expand=True, pady=(0, 12))

        # Botón de cerrar
        boton_cerrar = ctk.CTkButton(
            contenedor,
            text="Cerrar",
            command=ventana.destroy,
            font=("Segoe UI", 11),
        )
        boton_cerrar.pack(pady=(0, 0))

        def realizar_analisis():
            """Realiza el análisis en segundo plano."""
            try:
                resultado = analizar_servidor_dns(ip)
                
                # Limpiar frame de resultados
                for widget in scroll_frame.winfo_children():
                    widget.destroy()
                
                if resultado["es_dns"]:
                    estado_label.configure(
                        text="✅ Servidor DNS detectado y analizado",
                        text_color=("#2e7d32", "#43a047")
                    )
                    
                    # Tipo de servidor
                    tipo_frame = ctk.CTkFrame(scroll_frame)
                    tipo_frame.pack(fill="x", pady=(0, 12))
                    
                    ctk.CTkLabel(
                        tipo_frame,
                        text=f"📋 Tipo de servidor: {resultado['tipo_servidor']}",
                        font=("Segoe UI", 12, "bold"),
                    ).pack(padx=12, pady=8, anchor="w")
                    
                    # Estado de consultas
                    consultas_text = "✅ Responde a consultas DNS" if resultado["responde_consultas"] else "❌ No responde a consultas DNS"
                    ctk.CTkLabel(
                        tipo_frame,
                        text=consultas_text,
                        font=("Segoe UI", 10),
                    ).pack(padx=24, pady=2, anchor="w")
                    
                    # Estado de recursión
                    if resultado["permite_recursion"]:
                        recursion_text = "⚠️ Permite consultas recursivas (riesgo de seguridad)"
                        recursion_color = ("#d32f2f", "#ef5350")
                    else:
                        recursion_text = "✅ No permite consultas recursivas"
                        recursion_color = ("#2e7d32", "#43a047")
                    
                    ctk.CTkLabel(
                        tipo_frame,
                        text=recursion_text,
                        font=("Segoe UI", 10),
                        text_color=recursion_color,
                    ).pack(padx=24, pady=2, anchor="w")
                    
                    # Información adicional
                    if resultado["informacion"]:
                        info_frame = ctk.CTkFrame(scroll_frame)
                        info_frame.pack(fill="x", pady=(0, 12))
                        
                        ctk.CTkLabel(
                            info_frame,
                            text="📊 Información adicional:",
                            font=("Segoe UI", 12, "bold"),
                        ).pack(padx=12, pady=8, anchor="w")
                        
                        for info in resultado["informacion"]:
                            ctk.CTkLabel(
                                info_frame,
                                text=f"• {info}",
                                font=("Segoe UI", 10),
                                wraplength=620,
                                justify="left",
                            ).pack(padx=24, pady=2, anchor="w")
                    
                    # Recomendaciones de seguridad
                    if resultado["recomendaciones"]:
                        rec_frame = ctk.CTkFrame(scroll_frame)
                        rec_frame.pack(fill="x", pady=(0, 12))
                        
                        ctk.CTkLabel(
                            rec_frame,
                            text="🔒 Recomendaciones de seguridad:",
                            font=("Segoe UI", 12, "bold"),
                        ).pack(padx=12, pady=8, anchor="w")
                        
                        for rec in resultado["recomendaciones"]:
                            ctk.CTkLabel(
                                rec_frame,
                                text=f"• {rec}",
                                font=("Segoe UI", 10),
                                wraplength=620,
                                justify="left",
                            ).pack(padx=24, pady=4, anchor="w")
                    
                    # Información general sobre DNS
                    info_general_frame = ctk.CTkFrame(scroll_frame)
                    info_general_frame.pack(fill="x", pady=(0, 0))
                    
                    ctk.CTkLabel(
                        info_general_frame,
                        text="ℹ️ ¿Qué puedes hacer con un servidor DNS?",
                        font=("Segoe UI", 12, "bold"),
                    ).pack(padx=12, pady=8, anchor="w")
                    
                    desc_texto = """
• Consultas DNS: Resolver nombres de dominio a IPs
• Consultas inversas: Convertir IPs a nombres de dominio
• Verificar registros: MX (correo), TXT (SPF, DKIM), etc.
• Análisis de seguridad: Detectar configuraciones inseguras
• Identificar tipo de dispositivo: Router, servidor, controlador de dominio

🔧 Comandos útiles:
  nslookup google.com {ip}
  dig @{ip} google.com
  dig @{ip} version.bind txt chaos (detectar versión)
  nslookup {ip} (consulta inversa)
                    """.format(ip=ip)
                    
                    ctk.CTkLabel(
                        info_general_frame,
                        text=desc_texto,
                        font=("Segoe UI", 9),
                        justify="left",
                    ).pack(padx=24, pady=8, anchor="w")
                    
                else:
                    estado_label.configure(
                        text="❌ El servidor no responde a consultas DNS",
                        text_color=("#d32f2f", "#ef5350")
                    )
                    
                    ctk.CTkLabel(
                        scroll_frame,
                        text="El puerto 53 está abierto pero el servidor no responde correctamente "
                             "a consultas DNS. Puede estar:\n\n"
                             "• Configurado solo para escuchar en interfaces específicas\n"
                             "• Bloqueado por firewall\n"
                             "• Utilizando el puerto para otro servicio\n"
                             "• Requerir autenticación especial",
                        font=("Segoe UI", 10),
                        wraplength=600,
                        justify="left",
                    ).pack(padx=12, pady=12)
                    
            except Exception as e:
                estado_label.configure(
                    text=f"❌ Error al analizar: {str(e)}",
                    text_color=("#d32f2f", "#ef5350")
                )
                
                for widget in scroll_frame.winfo_children():
                    widget.destroy()
                
                ctk.CTkLabel(
                    scroll_frame,
                    text=f"Se produjo un error durante el análisis:\n{str(e)}",
                    font=("Segoe UI", 10),
                    wraplength=600,
                    justify="left",
                ).pack(padx=12, pady=12)

        # Iniciar análisis en hilo separado
        threading.Thread(target=realizar_analisis, daemon=True).start()

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
        
        # Verificar que las dependencias estén disponibles
        if Image is None or pystray is None or item is None:
            return
        
        # Cargar imagen para el icono de bandeja
        ruta_icono = os.path.join(os.path.dirname(__file__), "img", "splash.png")
        
        if not os.path.exists(ruta_icono):
            return
        
        try:
            # Cargar imagen con PIL (ya verificado que Image no es None)
            icono_imagen = Image.open(ruta_icono)  # type: ignore
            
            # Crear menú del icono (ya verificado que pystray e item no son None)
            menu = pystray.Menu(  # type: ignore
                item('Mostrar/Ocultar', self._toggle_ventana, default=True),  # type: ignore
                item('Salir', self._salir_aplicacion)  # type: ignore
            )
            
            # Crear icono de bandeja (ya verificado que pystray no es None)
            self.tray_icon = pystray.Icon(  # type: ignore
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
