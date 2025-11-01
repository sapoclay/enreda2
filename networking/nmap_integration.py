"""
Integración opcional con Nmap usando python-nmap.
Requiere:
  1) Instalar Nmap en el sistema (https://nmap.org/download.html).
  2) pip install python-nmap
"""
from typing import Any, Dict, List, Tuple, Optional
import shutil
import platform
import subprocess

try:
    import nmap  # type: ignore
    NMAP_DISPONIBLE = True
except ImportError:
    nmap = None  # type: ignore
    NMAP_DISPONIBLE = False


def nmap_disponible() -> bool:
    """Comprueba si nmap y python-nmap están disponibles."""
    if not NMAP_DISPONIBLE:
        return False
    return shutil.which("nmap") is not None


def requiere_privilegios(arguments: str) -> bool:
    """
    Determina si los argumentos de nmap requieren privilegios de administrador.
    
    Args:
        arguments: Cadena con los argumentos de nmap
    
    Returns:
        True si requiere privilegios elevados
    """
    # Opciones que requieren root/admin
    opciones_privilegiadas = ['-O', '-A', '--osscan-guess', '-sS', '-sU', '-sN', '-sF', '-sX']
    
    for opcion in opciones_privilegiadas:
        if opcion in arguments:
            return True
    
    return False


def verificar_privilegios_nmap(password: Optional[str] = None) -> Tuple[bool, str]:
    """
    Verifica si nmap se puede ejecutar con privilegios elevados.
    
    Args:
        password: Contraseña de administrador (solo Linux/Mac)
    
    Returns:
        Tupla (éxito, mensaje)
    """
    sistema = platform.system()
    
    try:
        if sistema == "Windows":
            # En Windows, verificar si se ejecuta como administrador
            import ctypes
            es_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if es_admin:
                return True, "Ejecutando con privilegios de administrador"
            else:
                return False, "Se requieren privilegios de administrador. Ejecute la aplicación como administrador."
        else:
            # En Linux/Mac, verificar si es root o puede usar sudo
            if subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() == '0':
                return True, "Ejecutando como root"
            
            # Verificar si sudo está disponible
            if shutil.which("sudo"):
                if password:
                    # Verificar la contraseña con sudo -S
                    test_cmd = f"echo '{password}' | sudo -S echo 'test' 2>&1"
                    result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        return True, "Contraseña de sudo verificada"
                    else:
                        return False, "Contraseña incorrecta"
                else:
                    return False, "Se requiere contraseña de sudo"
            else:
                return False, "sudo no está disponible en el sistema"
                
    except Exception as e:
        return False, f"Error al verificar privilegios: {e}"


def scan_host_nmap(target: str, arguments: str = "-sV -O --osscan-guess -T4", sudo_password: Optional[str] = None) -> Dict[str, Any]:
    """
    Lanza un escaneo de nmap sobre un host específico.
    
    Args:
        target: IP del host (ej. 192.168.1.5)
        arguments: argumentos de nmap (cadena)
        sudo_password: Contraseña de sudo (Linux/Mac) si se requieren privilegios
    
    Returns:
        Diccionario con resultados del escaneo
    """
    if not nmap_disponible():
        raise RuntimeError("Nmap no está disponible. Instale Nmap desde https://nmap.org/download.html")
    
    # Verificar si se necesitan privilegios
    necesita_privilegios = requiere_privilegios(arguments)
    sistema = platform.system()
    host_info = None
    
    try:
        # Configurar nmap con sudo si es necesario
        if necesita_privilegios and sistema != "Windows":
            # En Linux/Mac, usar sudo
            if subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() == '0':
                # Ya es root, usar normalmente
                scanner = nmap.PortScanner()
                scanner.scan(hosts=target, arguments=arguments)
                
                if target not in scanner.all_hosts():
                    return {
                        "error": "Host no responde o no fue escaneado",
                        "target": target
                    }
                
                host_info = scanner[target]
            else:
                # Necesita sudo
                if not sudo_password:
                    raise RuntimeError("Se requiere contraseña de administrador para esta operación")
                
                # Ejecutar nmap directamente con subprocess y sudo
                nmap_path = shutil.which("nmap")
                cmd = f"echo '{sudo_password}' | sudo -S {nmap_path} {arguments} {target} -oX -"
                
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutos timeout
                )
                
                if result.returncode != 0:
                    error_msg = result.stderr
                    # Limpiar mensaje de contraseña
                    if sudo_password in error_msg:
                        error_msg = error_msg.replace(sudo_password, "***")
                    raise RuntimeError(f"Error ejecutando nmap con sudo: {error_msg}")
                
                # Parsear el XML de salida con python-nmap
                scanner = nmap.PortScanner()
                scanner.analyse_nmap_xml_scan(result.stdout)
                
                if target not in scanner.all_hosts():
                    return {
                        "error": "Host no responde o no fue escaneado",
                        "target": target
                    }
                
                host_info = scanner[target]
        elif necesita_privilegios and sistema == "Windows":
            # En Windows, verificar que se ejecuta como admin
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                raise RuntimeError("Se requieren privilegios de administrador. Ejecute la aplicación como administrador.")
            
            scanner = nmap.PortScanner()
            scanner.scan(hosts=target, arguments=arguments)
            
            if target not in scanner.all_hosts():
                return {
                    "error": "Host no responde o no fue escaneado",
                    "target": target
                }
            
            host_info = scanner[target]
        else:
            # No requiere privilegios, usar normalmente
            scanner = nmap.PortScanner()
            scanner.scan(hosts=target, arguments=arguments)
            
            if target not in scanner.all_hosts():
                return {
                    "error": "Host no responde o no fue escaneado",
                    "target": target
                }
            
            host_info = scanner[target]
        
        # Verificar que host_info fue asignado
        if host_info is None:
            return {
                "error": "No se pudo obtener información del host",
                "target": target
            }
        
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
        
    except subprocess.TimeoutExpired:
        raise RuntimeError("El escaneo excedió el tiempo límite de 5 minutos")
    except Exception as exc:
        error_msg = str(exc)
        # Limpiar mensaje de error para no mostrar la contraseña
        if sudo_password and sudo_password in error_msg:
            error_msg = error_msg.replace(sudo_password, "***")
        raise RuntimeError(f"Error ejecutando nmap: {error_msg}")


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
