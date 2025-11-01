"""
Módulo para obtener la dirección IP pública del usuario.
"""
import urllib.request
import urllib.error
import socket
from typing import Optional, Tuple


def obtener_ip_publica(timeout: int = 3) -> Tuple[Optional[str], str]:
    """
    Obtiene la dirección IP pública del usuario.
    
    Args:
        timeout: Tiempo máximo de espera en segundos
    
    Returns:
        Tupla (ip_publica, proveedor) donde:
        - ip_publica: Dirección IP pública o None si hay error
        - proveedor: Nombre del servicio usado o mensaje de error
    """
    # Lista de servicios para obtener IP pública (en orden de preferencia)
    servicios = [
        ("https://api.ipify.org", "ipify"),
        ("https://icanhazip.com", "icanhazip"),
        ("https://ifconfig.me/ip", "ifconfig.me"),
        ("https://ident.me", "ident.me"),
        ("https://checkip.amazonaws.com", "AWS"),
    ]
    
    for url, nombre in servicios:
        try:
            # Configurar request con timeout
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'enredA2-NetworkScanner/1.0'}
            )
            
            with urllib.request.urlopen(req, timeout=timeout) as response:
                ip = response.read().decode('utf-8').strip()
                
                # Validar que sea una IP válida
                if _validar_ip(ip):
                    return ip, nombre
                    
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout):
            # Si este servicio falla, probar con el siguiente
            continue
        except Exception:
            continue
    
    # Si todos los servicios fallan
    return None, "No disponible (sin conexión a Internet)"


def _validar_ip(ip: str) -> bool:
    """
    Valida que una cadena sea una dirección IP válida.
    
    Args:
        ip: Cadena a validar
    
    Returns:
        True si es una IP válida
    """
    try:
        # Intentar parsear como IPv4
        partes = ip.split('.')
        if len(partes) != 4:
            return False
        
        for parte in partes:
            num = int(parte)
            if num < 0 or num > 255:
                return False
        
        return True
        
    except (ValueError, AttributeError):
        return False


def obtener_info_ip_publica() -> dict:
    """
    Obtiene información completa sobre la IP pública.
    
    Returns:
        Diccionario con información de la IP pública
    """
    ip, proveedor = obtener_ip_publica()
    
    info = {
        "ip": ip,
        "disponible": ip is not None,
        "proveedor": proveedor,
        "es_privada": False,
        "tipo": "Desconocido"
    }
    
    if ip:
        # Determinar si es IP privada (no debería, pero verificar)
        if _es_ip_privada(ip):
            info["es_privada"] = True
            info["tipo"] = "IP Privada (detrás de NAT)"
        else:
            info["tipo"] = "IP Pública"
    
    return info


def _es_ip_privada(ip: str) -> bool:
    """
    Verifica si una IP es privada (RFC 1918).
    
    Args:
        ip: Dirección IP a verificar
    
    Returns:
        True si es IP privada
    """
    try:
        partes = ip.split('.')
        if len(partes) != 4:
            return False
        
        primer_octeto = int(partes[0])
        segundo_octeto = int(partes[1])
        
        # 10.0.0.0 - 10.255.255.255
        if primer_octeto == 10:
            return True
        
        # 172.16.0.0 - 172.31.255.255
        if primer_octeto == 172 and 16 <= segundo_octeto <= 31:
            return True
        
        # 192.168.0.0 - 192.168.255.255
        if primer_octeto == 192 and segundo_octeto == 168:
            return True
        
        # 127.0.0.0 - 127.255.255.255 (localhost)
        if primer_octeto == 127:
            return True
        
        return False
        
    except (ValueError, IndexError):
        return False


def obtener_ip_publica_async(callback, timeout: int = 3) -> None:
    """
    Obtiene la IP pública de forma asíncrona y ejecuta un callback.
    
    Args:
        callback: Función a ejecutar con el resultado (ip, proveedor)
        timeout: Tiempo máximo de espera
    """
    import threading
    
    def worker():
        ip, proveedor = obtener_ip_publica(timeout)
        callback(ip, proveedor)
    
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
