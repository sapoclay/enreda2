"""
Integración opcional con Nmap usando python-nmap.
Requiere:
  1) Instalar Nmap en el sistema (https://nmap.org/download.html).
  2) pip install python-nmap
"""
from typing import Any, Dict, List, Tuple
import shutil

try:
    import nmap
    NMAP_DISPONIBLE = True
except ImportError:
    nmap = None
    NMAP_DISPONIBLE = False


def nmap_disponible() -> bool:
    """Comprueba si nmap y python-nmap están disponibles."""
    if not NMAP_DISPONIBLE:
        return False
    return shutil.which("nmap") is not None


def scan_host_nmap(target: str, arguments: str = "-sV -O --osscan-guess -T4") -> Dict[str, Any]:
    """
    Lanza un escaneo de nmap sobre un host específico.
    
    Args:
        target: IP del host (ej. 192.168.1.5)
        arguments: argumentos de nmap (cadena)
    
    Returns:
        Diccionario con resultados del escaneo
    """
    if not nmap_disponible():
        raise RuntimeError("Nmap no está disponible. Instale Nmap desde https://nmap.org/download.html")
    
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, arguments=arguments)
        
        if target not in scanner.all_hosts():
            return {
                "error": "Host no responde o no fue escaneado",
                "target": target
            }
        
        host_info = scanner[target]
        
        # Extraer información útil
        resultado = {
            "target": target,
            "hostname": host_info.hostname() if hasattr(host_info, 'hostname') else "",
            "state": host_info.state(),
            "protocols": list(host_info.all_protocols()),
            "ports": [],
            "os": [],
        }
        
        # Información de puertos
        if 'tcp' in host_info:
            for port in host_info['tcp'].keys():
                port_info = host_info['tcp'][port]
                resultado["ports"].append({
                    "port": port,
                    "state": port_info.get('state', 'unknown'),
                    "service": port_info.get('name', 'unknown'),
                    "product": port_info.get('product', ''),
                    "version": port_info.get('version', ''),
                    "extrainfo": port_info.get('extrainfo', ''),
                })
        
        # Información del sistema operativo
        if 'osmatch' in host_info:
            for os_match in host_info['osmatch']:
                resultado["os"].append({
                    "name": os_match.get('name', ''),
                    "accuracy": os_match.get('accuracy', '0'),
                })
        
        return resultado
        
    except Exception as exc:
        raise RuntimeError(f"Error ejecutando nmap: {exc}")


def scan_network_nmap(network: str, arguments: str = "-sn -T4") -> List[str]:
    """
    Escaneo rápido de red para descubrir hosts activos.
    
    Args:
        network: Rango de red (ej. 192.168.1.0/24)
        arguments: argumentos de nmap (por defecto -sn para ping scan)
    
    Returns:
        Lista de IPs activas
    """
    if not nmap_disponible():
        raise RuntimeError("Nmap no está disponible. Instale Nmap desde https://nmap.org/download.html")
    
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=network, arguments=arguments)
        
        hosts_activos = []
        for host in scanner.all_hosts():
            if scanner[host].state() == 'up':
                hosts_activos.append(host)
        
        return hosts_activos
        
    except Exception as exc:
        raise RuntimeError(f"Error ejecutando nmap: {exc}")


def obtener_info_nmap() -> Tuple[bool, str]:
    """
    Obtiene información sobre la disponibilidad de Nmap.
    
    Returns:
        Tupla (disponible, mensaje)
    """
    if not NMAP_DISPONIBLE:
        return False, "Módulo python-nmap no instalado. Ejecute: pip install python-nmap"
    
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return False, "Nmap no encontrado en el sistema. Descárguelo de https://nmap.org/download.html"
    
    try:
        scanner = nmap.PortScanner()
        version = scanner.nmap_version()
        return True, f"Nmap v{version[0]}.{version[1]} disponible en: {nmap_path}"
    except Exception as e:
        return False, f"Error al verificar Nmap: {e}"
