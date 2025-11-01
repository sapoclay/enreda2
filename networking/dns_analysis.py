"""
Análisis de servidores DNS (puerto 53).
Proporciona información útil sobre servicios DNS detectados.
"""
import socket
import subprocess
from typing import Any, Dict, List, Optional, Tuple


def analizar_servidor_dns(ip: str) -> Dict[str, Any]:
    """
    Analiza un servidor DNS en la IP especificada.
    
    Args:
        ip: Dirección IP del servidor DNS
    
    Returns:
        Diccionario con información del servidor DNS
    """
    resultado = {
        "es_dns": False,
        "tipo_servidor": "Desconocido",
        "responde_consultas": False,
        "permite_recursion": False,
        "informacion": [],
        "recomendaciones": []
    }
    
    # Verificar si responde a consultas DNS
    responde, version = _verificar_respuesta_dns(ip)
    resultado["responde_consultas"] = responde
    
    if responde:
        resultado["es_dns"] = True
        
        # Determinar tipo de servidor
        tipo = _determinar_tipo_servidor_dns(ip)
        resultado["tipo_servidor"] = tipo
        
        if version:
            resultado["informacion"].append(f"Versión detectada: {version}")
        
        # Verificar recursión
        recursion = _verificar_recursion(ip)
        resultado["permite_recursion"] = recursion
        
        if recursion:
            resultado["informacion"].append("⚠️ Permite consultas recursivas")
            resultado["recomendaciones"].append(
                "Considere deshabilitar la recursión DNS si no es necesaria "
                "para evitar ataques de amplificación DDoS"
            )
        
        # Verificar transferencias de zona (solo si es servidor DNS real)
        if tipo in ["Servidor DNS autoritativo", "Controlador de dominio Windows"]:
            permite_axfr = _verificar_transferencia_zona(ip)
            if permite_axfr:
                resultado["informacion"].append("⚠️ CRÍTICO: Permite transferencias de zona (AXFR)")
                resultado["recomendaciones"].append(
                    "URGENTE: Las transferencias de zona están habilitadas públicamente. "
                    "Esto permite a atacantes obtener toda la información de su dominio. "
                    "Restrinja AXFR solo a servidores DNS autorizados."
                )
        
        # Información adicional según tipo
        if tipo == "Router/Gateway con DNS":
            resultado["informacion"].append(
                "Este dispositivo probablemente reenvía consultas DNS a servidores upstream"
            )
            resultado["recomendaciones"].append(
                "Verifique que el router esté usando servidores DNS confiables (Google: 8.8.8.8, Cloudflare: 1.1.1.1)"
            )
        
        elif tipo == "Controlador de dominio Windows":
            resultado["informacion"].append(
                "Servidor DNS integrado con Active Directory"
            )
            resultado["recomendaciones"].append(
                "Asegúrese de que este servidor DNS no sea accesible desde Internet"
            )
        
        elif tipo == "Servidor DNS autoritativo":
            resultado["informacion"].append(
                "Servidor DNS que gestiona zonas de dominio"
            )
            resultado["recomendaciones"].append(
                "Mantenga actualizado el software DNS (BIND, PowerDNS, etc.)"
            )
    
    return resultado


def _verificar_respuesta_dns(ip: str, timeout: int = 2) -> Tuple[bool, Optional[str]]:
    """
    Verifica si el servidor responde a consultas DNS.
    
    Returns:
        Tupla (responde, versión_software)
    """
    try:
        # Intenta resolver google.com usando este DNS
        resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        resolver.settimeout(timeout)
        
        # Consulta DNS simple para google.com
        # Formato: ID(2) + Flags(2) + Counts(8) + Query
        query = (
            b'\xaa\xaa'  # ID de transacción
            b'\x01\x00'  # Flags: consulta estándar
            b'\x00\x01'  # 1 pregunta
            b'\x00\x00\x00\x00\x00\x00'  # 0 respuestas, autoridad, adicionales
            b'\x06google\x03com\x00'  # google.com
            b'\x00\x01'  # Tipo A
            b'\x00\x01'  # Clase IN
        )
        
        resolver.sendto(query, (ip, 53))
        data, _ = resolver.recvfrom(512)
        resolver.close()
        
        # Si recibimos respuesta, el servidor DNS funciona
        if len(data) > 12:
            # Intentar detectar versión con consulta VERSION.BIND
            version = _detectar_version_bind(ip)
            return True, version
        
        return False, None
        
    except (socket.timeout, socket.error, Exception):
        return False, None


def _detectar_version_bind(ip: str) -> Optional[str]:
    """
    Intenta detectar la versión de BIND usando consulta TXT VERSION.BIND.
    """
    try:
        # Usar dig o nslookup si está disponible
        result = subprocess.run(
            ['dig', '@' + ip, 'version.bind', 'txt', 'chaos', '+short'],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0 and result.stdout.strip():
            version = result.stdout.strip().strip('"')
            return version
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    
    return None


def _determinar_tipo_servidor_dns(ip: str) -> str:
    """
    Determina el tipo de servidor DNS basándose en características.
    """
    # Verificar si es IP privada (probablemente router o servidor interno)
    octetos = ip.split('.')
    if len(octetos) == 4:
        primer_octeto = int(octetos[0])
        segundo_octeto = int(octetos[1])
        
        # Rango 192.168.x.x - Probablemente router doméstico
        if primer_octeto == 192 and segundo_octeto == 168:
            # Si termina en .1, .254, etc., probablemente es gateway
            ultimo_octeto = int(octetos[3])
            if ultimo_octeto in [1, 254]:
                return "Router/Gateway con DNS"
        
        # Rango 10.x.x.x o 172.16-31.x.x - Servidor corporativo
        if primer_octeto == 10 or (primer_octeto == 172 and 16 <= segundo_octeto <= 31):
            # Verificar si tiene puertos de Active Directory
            if _verificar_puerto_abierto(ip, 389):  # LDAP
                return "Controlador de dominio Windows"
            return "Servidor DNS corporativo"
    
    # Si es IP pública
    return "Servidor DNS autoritativo"


def _verificar_recursion(ip: str) -> bool:
    """
    Verifica si el servidor DNS permite consultas recursivas.
    """
    try:
        # Intentar resolver un dominio externo
        resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        resolver.settimeout(2)
        
        # Consulta con RD (Recursion Desired) flag activado
        query = (
            b'\xbb\xbb'  # ID
            b'\x01\x00'  # Flags: RD=1 (recursión deseada)
            b'\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x07example\x03com\x00'  # example.com
            b'\x00\x01\x00\x01'  # Tipo A, Clase IN
        )
        
        resolver.sendto(query, (ip, 53))
        data, _ = resolver.recvfrom(512)
        resolver.close()
        
        # Verificar flag RA (Recursion Available) en la respuesta
        if len(data) > 3:
            flags = int.from_bytes(data[2:4], 'big')
            ra_flag = (flags & 0x0080) != 0  # Bit RA
            return ra_flag
        
        return False
        
    except Exception:
        return False


def _verificar_transferencia_zona(ip: str) -> bool:
    """
    Verifica si el servidor permite transferencias de zona (AXFR).
    
    IMPORTANTE: Esta es una vulnerabilidad crítica si está habilitada.
    """
    try:
        # Intentar transferencia de zona con dig
        result = subprocess.run(
            ['dig', '@' + ip, 'axfr', 'example.com'],
            capture_output=True,
            text=True,
            timeout=3
        )
        
        # Si no hay error y hay contenido, podría permitir AXFR
        # (Aunque example.com probablemente falle, un error de permisos vs. formato indica configuración)
        if result.returncode == 0:
            output = result.stdout.lower()
            # Buscar indicadores de que AXFR está habilitado
            if 'transfer failed' not in output and 'refused' not in output:
                return True
        
        return False
        
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False


def _verificar_puerto_abierto(ip: str, puerto: int, timeout: float = 0.5) -> bool:
    """
    Verifica si un puerto está abierto.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        resultado = sock.connect_ex((ip, puerto))
        sock.close()
        return resultado == 0
    except Exception:
        return False


def obtener_descripcion_dns() -> str:
    """
    Retorna una descripción de qué es el puerto 53 y qué se puede hacer.
    """
    return """
    🌐 PUERTO 53 - DNS (Domain Name System)
    
    ¿Qué es?
    El puerto 53 es usado por el protocolo DNS, que traduce nombres de dominio 
    (como google.com) a direcciones IP (como 142.250.185.46).
    
    ¿Qué se puede hacer?
    
    1. CONSULTAS DNS:
       - Resolver nombres de dominio a IPs
       - Consultas inversas (IP a nombre)
       - Verificar registros MX (servidores de correo)
       - Consultar registros TXT (SPF, DKIM, verificaciones)
    
    2. ANÁLISIS DE SEGURIDAD:
       - Verificar si permite recursión (riesgo de abuso)
       - Detectar transferencias de zona abiertas (vulnerabilidad crítica)
       - Identificar versión del software DNS
       - Comprobar configuración DNSSec
    
    3. TIPO DE DISPOSITIVO:
       - Router/Gateway: DNS local que reenvía consultas
       - Servidor corporativo: DNS interno de empresa
       - Controlador de dominio: Active Directory con DNS integrado
       - Servidor autoritativo: Gestiona dominios públicos
    
    ⚠️ RIESGOS COMUNES:
    
    - Recursión abierta: Puede usarse para ataques DDoS de amplificación
    - Transferencia de zona: Revela toda la estructura de red/dominios
    - Software desactualizado: Vulnerabilidades conocidas (CVE)
    - DNS cache poisoning: Respuestas DNS maliciosas
    
    🔧 COMANDOS ÚTILES:
    
    # Consulta simple
    nslookup google.com <IP>
    
    # Consulta detallada
    dig @<IP> google.com
    
    # Verificar versión BIND
    dig @<IP> version.bind txt chaos
    
    # Intentar transferencia de zona
    dig @<IP> axfr example.com
    
    # Consulta inversa
    nslookup <IP>
    """


def obtener_recomendaciones_seguridad_dns() -> List[str]:
    """
    Retorna lista de recomendaciones de seguridad para servidores DNS.
    """
    return [
        "🔒 Deshabilitar recursión DNS si no es necesaria",
        "🔒 Restringir transferencias de zona (AXFR) solo a servidores autorizados",
        "🔒 Implementar DNSSEC para validación de respuestas",
        "🔒 Mantener actualizado el software DNS (BIND, PowerDNS, etc.)",
        "🔒 Usar listas de rate-limiting para prevenir ataques DDoS",
        "🔒 Separar DNS autoritativo de DNS recursivo",
        "🔒 Monitorear logs DNS para detectar actividad sospechosa",
        "🔒 Configurar respuestas rate-limiting (RRL)",
        "🔒 No exponer DNS internos a Internet",
        "🔒 Usar servidores DNS confiables como upstream (1.1.1.1, 8.8.8.8)"
    ]
