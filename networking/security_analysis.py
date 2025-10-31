from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class VulnerabilityCheck:
    """Resultado de una comprobación de seguridad."""
    nivel: str  # "CRITICO", "ALTO", "MEDIO", "BAJO", "INFO"
    titulo: str
    descripcion: str
    puertos_relacionados: List[int]


# Diccionario de puertos peligrosos y sus descripciones
PUERTOS_PELIGROSOS = {
    21: ("MEDIO", "FTP", "FTP sin cifrar - Credenciales en texto plano"),
    23: ("ALTO", "Telnet", "Telnet sin cifrar - Muy inseguro, usar SSH en su lugar"),
    25: ("BAJO", "SMTP", "SMTP abierto - Posible relay de correo"),
    53: ("INFO", "DNS", "Servidor DNS detectado"),
    69: ("MEDIO", "TFTP", "TFTP sin autenticación"),
    80: ("INFO", "HTTP", "Servidor web HTTP detectado"),
    110: ("MEDIO", "POP3", "POP3 sin cifrar - Usar POP3S (995)"),
    135: ("ALTO", "RPC", "Puerto RPC de Windows - Vulnerable a exploits"),
    137: ("MEDIO", "NetBIOS", "NetBIOS Name Service expuesto"),
    138: ("MEDIO", "NetBIOS", "NetBIOS Datagram Service expuesto"),
    139: ("ALTO", "NetBIOS", "NetBIOS Session Service - Expone recursos de red"),
    143: ("MEDIO", "IMAP", "IMAP sin cifrar - Usar IMAPS (993)"),
    161: ("ALTO", "SNMP", "SNMP v1/v2 - Community strings en texto plano"),
    162: ("ALTO", "SNMP Trap", "SNMP Trap expuesto"),
    389: ("MEDIO", "LDAP", "LDAP sin cifrar - Usar LDAPS (636)"),
    445: ("CRITICO", "SMB", "SMB expuesto - Vulnerable a ransomware y exploits"),
    512: ("ALTO", "rexec", "Servicio rexec sin cifrar - Muy inseguro"),
    513: ("ALTO", "rlogin", "Servicio rlogin sin cifrar - Muy inseguro"),
    514: ("MEDIO", "rsh", "Remote Shell sin cifrar"),
    873: ("MEDIO", "rsync", "rsync expuesto - Verificar configuración"),
    1433: ("ALTO", "MS SQL", "SQL Server expuesto - Configurar firewall"),
    1521: ("ALTO", "Oracle DB", "Oracle Database expuesto"),
    2049: ("ALTO", "NFS", "NFS expuesto - Posible acceso no autorizado"),
    3306: ("ALTO", "MySQL", "MySQL expuesto - Configurar acceso remoto"),
    3389: ("ALTO", "RDP", "RDP expuesto - Usar VPN o restringir acceso"),
    5432: ("ALTO", "PostgreSQL", "PostgreSQL expuesto"),
    5900: ("ALTO", "VNC", "VNC sin cifrar - Usar túnel SSH"),
    5901: ("ALTO", "VNC", "VNC sin cifrar - Usar túnel SSH"),
    6379: ("CRITICO", "Redis", "Redis sin autenticación - Vulnerable a ataques"),
    8080: ("BAJO", "HTTP-Alt", "Servidor web alternativo detectado"),
    8443: ("INFO", "HTTPS-Alt", "Servidor web HTTPS alternativo detectado"),
}

# Servicios comunes seguros (para información)
SERVICIOS_SEGUROS = {
    22: "SSH - Acceso seguro",
    443: "HTTPS - Servidor web seguro",
    587: "SMTP-TLS - Envío de correo seguro",
    993: "IMAPS - Correo IMAP seguro",
    995: "POP3S - Correo POP3 seguro",
}


def analizar_puertos(puertos_abiertos: List[int]) -> List[VulnerabilityCheck]:
    """Analiza una lista de puertos abiertos y devuelve comprobaciones de seguridad."""
    
    vulnerabilidades: List[VulnerabilityCheck] = []
    
    # Analizar puertos peligrosos
    for puerto in puertos_abiertos:
        if puerto in PUERTOS_PELIGROSOS:
            nivel, servicio, descripcion = PUERTOS_PELIGROSOS[puerto]
            vulnerabilidades.append(VulnerabilityCheck(
                nivel=nivel,
                titulo=f"{servicio} detectado en puerto {puerto}",
                descripcion=descripcion,
                puertos_relacionados=[puerto]
            ))
    
    # Detectar combinaciones peligrosas
    puertos_set = set(puertos_abiertos)
    
    # SMB + NetBIOS (típico de Windows vulnerable)
    if 445 in puertos_set and any(p in puertos_set for p in [135, 139]):
        vulnerabilidades.append(VulnerabilityCheck(
            nivel="CRITICO",
            titulo="Configuración SMB/NetBIOS insegura",
            descripcion="Múltiples puertos de Windows expuestos. Alto riesgo de ransomware como WannaCry o exploits tipo EternalBlue.",
            puertos_relacionados=[p for p in [135, 139, 445] if p in puertos_set]
        ))
    
    # FTP + Telnet (servicios obsoletos)
    if 21 in puertos_set and 23 in puertos_set:
        vulnerabilidades.append(VulnerabilityCheck(
            nivel="ALTO",
            titulo="Servicios obsoletos sin cifrar",
            descripcion="FTP y Telnet detectados. Usar SFTP/SCP y SSH en su lugar.",
            puertos_relacionados=[21, 23]
        ))
    
    # Bases de datos múltiples expuestas
    db_ports = [p for p in [1433, 3306, 5432, 1521, 6379] if p in puertos_set]
    if len(db_ports) >= 2:
        vulnerabilidades.append(VulnerabilityCheck(
            nivel="ALTO",
            titulo="Múltiples bases de datos expuestas",
            descripcion=f"Se detectaron {len(db_ports)} servicios de bases de datos. Restringir acceso mediante firewall.",
            puertos_relacionados=db_ports
        ))
    
    # Redis sin protección (puerto común de ataque)
    if 6379 in puertos_set:
        vulnerabilidades.append(VulnerabilityCheck(
            nivel="CRITICO",
            titulo="Redis expuesto sin protección",
            descripcion="Redis es frecuentemente atacado. Asegurar con autenticación, bind a localhost y firewall.",
            puertos_relacionados=[6379]
        ))
    
    # RDP expuesto (objetivo común de ataques)
    if 3389 in puertos_set:
        vulnerabilidades.append(VulnerabilityCheck(
            nivel="ALTO",
            titulo="Escritorio remoto (RDP) expuesto",
            descripcion="RDP es objetivo de ataques de fuerza bruta. Usar VPN, cambiar puerto o deshabilitar si no es necesario.",
            puertos_relacionados=[3389]
        ))
    
    return vulnerabilidades


def generar_recomendaciones(vulnerabilidades: List[VulnerabilityCheck]) -> List[str]:
    """Genera una lista de recomendaciones basadas en las vulnerabilidades encontradas."""
    
    if not vulnerabilidades:
        return ["✓ No se detectaron puertos con vulnerabilidades conocidas."]
    
    recomendaciones: List[str] = []
    
    # Contar por nivel de severidad
    criticos = sum(1 for v in vulnerabilidades if v.nivel == "CRITICO")
    altos = sum(1 for v in vulnerabilidades if v.nivel == "ALTO")
    medios = sum(1 for v in vulnerabilidades if v.nivel == "MEDIO")
    
    if criticos > 0:
        recomendaciones.append(f"⚠️ URGENTE: {criticos} problema(s) CRÍTICO(S) detectado(s)")
    if altos > 0:
        recomendaciones.append(f"⚠️ {altos} problema(s) de severidad ALTA")
    if medios > 0:
        recomendaciones.append(f"⚠️ {medios} problema(s) de severidad MEDIA")
    
    # Recomendaciones generales
    recomendaciones.append("Cerrar puertos innecesarios mediante firewall")
    recomendaciones.append("Actualizar sistemas operativos y servicios")
    recomendaciones.append("Usar autenticación fuerte y cifrado")
    
    return recomendaciones


def obtener_tipo_dispositivo(puertos_abiertos: List[int], sistema_operativo: str) -> str:
    """Intenta identificar el tipo de dispositivo basándose en puertos y OS."""
    
    puertos_set = set(puertos_abiertos)
    
    # Detectar router/firewall
    if any(p in puertos_set for p in [22, 23, 80, 443, 8080]) and len(puertos_abiertos) <= 5:
        if "desconocido" in sistema_operativo.lower() or "dispositivo de red" in sistema_operativo.lower():
            return "Router / Dispositivo de red"
    
    # Detectar NAS
    if 445 in puertos_set and any(p in puertos_set for p in [80, 443, 5000, 5001]):
        return "NAS / Servidor de archivos"
    
    # Detectar servidor web
    if (80 in puertos_set or 443 in puertos_set) and len(puertos_abiertos) >= 3:
        return "Servidor web / Aplicación"
    
    # Detectar impresora
    if any(p in puertos_set for p in [9100, 515, 631]):
        return "Impresora de red"
    
    # Detectar cámara IP
    if any(p in puertos_set for p in [554, 8000, 8001]) and 80 in puertos_set:
        return "Cámara IP / DVR"
    
    # Detectar servidor de base de datos
    if any(p in puertos_set for p in [1433, 3306, 5432, 1521, 6379, 27017]):
        return "Servidor de base de datos"
    
    # Detectar Windows Server
    if "Windows" in sistema_operativo and any(p in puertos_set for p in [135, 139, 445, 3389]):
        return "Windows Server / PC"
    
    # Detectar Linux Server
    if "Linux" in sistema_operativo or "Unix" in sistema_operativo:
        if 22 in puertos_set:
            return "Servidor Linux/Unix"
    
    # Por defecto, usar el sistema operativo detectado
    return sistema_operativo
