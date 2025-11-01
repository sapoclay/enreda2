from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
import unicodedata
from dataclasses import dataclass
from typing import Iterable, List, Optional


@dataclass
class InterfaceInfo:
    """Representa una interfaz con los datos mínimos para calcular su red."""

    nombre: str
    direccion_ip: str
    mascara: str

    @property
    def red(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network((self.direccion_ip, self.mascara), strict=False)

    @property
    def etiqueta(self) -> str:
        return f"{self.nombre} — {self.red.with_prefixlen}"


def obtener_interfaces_locales() -> List[InterfaceInfo]:
    """Detecta y devuelve las interfaces IPv4 activas del sistema."""
    
    sistema = platform.system()
    
    if sistema == "Windows":
        return _obtener_interfaces_windows()
    elif sistema in ("Linux", "Darwin"):  # Darwin es macOS
        return _obtener_interfaces_linux()
    else:
        return []


def _obtener_interfaces_windows() -> List[InterfaceInfo]:
    """Ejecuta ipconfig en Windows y devuelve las interfaces IPv4 activas."""
    try:
        salida = subprocess.check_output(
            ["ipconfig", "/all"],
            text=True,
            encoding="cp850",
            errors="ignore",
        )
    except (OSError, subprocess.CalledProcessError):
        return []

    return list(_parsear_ipconfig(salida.splitlines()))


def _obtener_interfaces_linux() -> List[InterfaceInfo]:
    """Ejecuta comandos de Linux para obtener las interfaces IPv4 activas."""
    interfaces = []
    
    # Primero intentamos con 'ip addr' (comando moderno)
    try:
        salida = subprocess.check_output(
            ["ip", "-4", "addr", "show"],
            text=True,
            errors="ignore",
        )
        interfaces = list(_parsear_ip_addr(salida))
        if interfaces:
            return interfaces
    except (OSError, subprocess.CalledProcessError):
        pass
    
    # Si falla, intentamos con 'ifconfig' (comando antiguo/tradicional)
    try:
        salida = subprocess.check_output(
            ["ifconfig"],
            text=True,
            errors="ignore",
        )
        interfaces = list(_parsear_ifconfig(salida))
        if interfaces:
            return interfaces
    except (OSError, subprocess.CalledProcessError):
        pass
    
    return []


def _parsear_ip_addr(salida: str) -> Iterable[InterfaceInfo]:
    """Parsea la salida del comando 'ip addr' de Linux."""
    lineas = salida.splitlines()
    interfaz_actual = None
    
    for linea in lineas:
        linea = linea.strip()
        
        # Línea de interfaz: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
        if ": " in linea and not linea.startswith("inet"):
            partes = linea.split(":")
            if len(partes) >= 2:
                nombre = partes[1].strip()
                # Ignorar loopback
                if nombre != "lo":
                    interfaz_actual = nombre
        
        # Línea de dirección IPv4: "inet 192.168.1.100/24 ..."
        elif linea.startswith("inet ") and interfaz_actual:
            partes = linea.split()
            if len(partes) >= 2:
                direccion_cidr = partes[1]  # Formato: 192.168.1.100/24
                
                # Ignorar direcciones APIPA (169.254.x.x)
                if direccion_cidr.startswith("169.254."):
                    continue
                
                try:
                    # Separar IP y prefijo
                    if "/" in direccion_cidr:
                        ip_str, prefijo_str = direccion_cidr.split("/")
                        prefijo = int(prefijo_str)
                        
                        # Convertir prefijo a máscara de subred
                        mascara = str(ipaddress.IPv4Network(f"0.0.0.0/{prefijo}", strict=False).netmask)
                        
                        yield InterfaceInfo(
                            nombre=interfaz_actual,
                            direccion_ip=ip_str,
                            mascara=mascara
                        )
                except (ValueError, ipaddress.AddressValueError):
                    continue


def _parsear_ifconfig(salida: str) -> Iterable[InterfaceInfo]:
    """Parsea la salida del comando 'ifconfig' de Linux."""
    lineas = salida.splitlines()
    interfaz_actual = None
    ip_actual = None
    mascara_actual = None
    
    for linea in lineas:
        # Nueva interfaz (no comienza con espacio)
        if linea and not linea[0].isspace():
            # Guardar interfaz anterior si tiene datos completos
            if interfaz_actual and ip_actual and mascara_actual:
                # Ignorar loopback y direcciones APIPA
                if interfaz_actual != "lo" and not ip_actual.startswith("169.254."):
                    yield InterfaceInfo(
                        nombre=interfaz_actual,
                        direccion_ip=ip_actual,
                        mascara=mascara_actual
                    )
            
            # Resetear para nueva interfaz
            interfaz_actual = linea.split()[0].rstrip(":")
            ip_actual = None
            mascara_actual = None
        
        # Buscar dirección IPv4
        elif "inet " in linea and interfaz_actual:
            # Formato puede ser: "inet 192.168.1.100  netmask 255.255.255.0"
            # o "inet addr:192.168.1.100  Mask:255.255.255.0"
            
            # Buscar IP
            match_ip = re.search(r'inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)', linea)
            if match_ip:
                ip_actual = match_ip.group(1)
            
            # Buscar máscara
            match_mask = re.search(r'(?:netmask|Mask:)\s*(\d+\.\d+\.\d+\.\d+)', linea)
            if match_mask:
                mascara_actual = match_mask.group(1)
            else:
                # Si no encuentra máscara en formato decimal, buscar en hexadecimal
                match_hex = re.search(r'(?:netmask|Mask:)\s*(0x[0-9a-fA-F]+)', linea)
                if match_hex:
                    hex_mask = int(match_hex.group(1), 16)
                    mascara_actual = str(ipaddress.IPv4Address(hex_mask))
    
    # No olvidar la última interfaz
    if interfaz_actual and ip_actual and mascara_actual:
        if interfaz_actual != "lo" and not ip_actual.startswith("169.254."):
            yield InterfaceInfo(
                nombre=interfaz_actual,
                direccion_ip=ip_actual,
                mascara=mascara_actual
            )


def _parsear_ipconfig(lineas: Iterable[str]) -> Iterable[InterfaceInfo]:
    encabezado_actual: Optional[str] = None
    cuerpo_actual: list[str] = []

    for linea in lineas:
        linea_sin_fin = linea.rstrip()
        texto = linea_sin_fin.strip()

        if not texto:
            # Ignora líneas vacías pero no cierra bloques; algunos encabezados se separan por líneas en blanco.
            continue

        if not linea_sin_fin.startswith(" ") and texto.endswith(":"):
            if encabezado_actual and cuerpo_actual:
                resultado = _procesar_bloque(encabezado_actual, cuerpo_actual)
                if resultado:
                    yield resultado
            encabezado_actual = texto.rstrip(":")
            cuerpo_actual = []
            continue

        if encabezado_actual is None:
            continue

        cuerpo_actual.append(linea_sin_fin)

    if encabezado_actual and cuerpo_actual:
        resultado_final = _procesar_bloque(encabezado_actual, cuerpo_actual)
        if resultado_final:
            yield resultado_final


def _procesar_bloque(encabezado: str, cuerpo: list[str]) -> Optional[InterfaceInfo]:
    if _debe_ignorar(encabezado, cuerpo):
        return None

    ipv4 = _extraer_valor(cuerpo, "IPv4")
    mascara = _extraer_valor(cuerpo, "Máscara de subred") or _extraer_valor(cuerpo, "Mascara de subred")
    if not mascara:
        mascara = _extraer_valor(cuerpo, "Subnet Mask")

    if not ipv4 or not mascara:
        return None

    return InterfaceInfo(nombre=encabezado, direccion_ip=ipv4, mascara=mascara)


def _debe_ignorar(encabezado: str, bloque: list[str]) -> bool:
    encabezado_norm = _normalizar(encabezado)
    if "loopback" in encabezado_norm or "tunel" in encabezado_norm or "tunnel" in encabezado_norm:
        return True

    cuerpo = _normalizar(" ".join(bloque))
    if "desconectado" in cuerpo or "disconnected" in cuerpo:
        return True

    return False


def _extraer_valor(bloque: list[str], clave: str) -> Optional[str]:
    clave_normalizada = _normalizar(clave)
    for linea in bloque:
        linea_limpia = _limpiar_espacios(linea)
        if clave_normalizada not in _normalizar(linea_limpia):
            continue

        if ":" not in linea_limpia:
            continue

        valor = linea_limpia.split(":", 1)[1].strip()
        if "(" in valor:
            valor = valor.split("(", 1)[0].strip()

        if valor.startswith("169.254."):
            return None

        return valor

    return None


def _normalizar(texto: str) -> str:
    """Convierte a minúsculas y elimina diacríticos para comparaciones robustas."""

    texto_min = texto.lower().replace("\u00a0", " ")
    normalizado = "".join(
        caracter
        for caracter in unicodedata.normalize("NFD", texto_min)
        if unicodedata.category(caracter) != "Mn"
    )
    return normalizado


def _limpiar_espacios(texto: str) -> str:
    """Reemplaza espacios no separables y recorta la línea."""

    return texto.replace("\u00a0", " ").strip()
