from __future__ import annotations

import platform
import subprocess
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .ping import resolver_nombre
from .ports import escanear_puertos_extenso
from .security_analysis import (
    analizar_puertos,
    generar_recomendaciones,
    obtener_tipo_dispositivo,
    VulnerabilityCheck,
)


@dataclass
class DeepScanResult:
    ip: str
    nombre: Optional[str]
    ttl: Optional[int]
    sistema_operativo: str
    tipo_dispositivo: str
    puertos_abiertos: List[int]
    recursos_compartidos: List[str]
    vulnerabilidades: List[VulnerabilityCheck]
    recomendaciones: List[str]
    advertencias: List[str]


def realizar_escaneo_profundo(ip: str) -> DeepScanResult:
    """Recolecta información adicional de un host activo."""

    advertencias: List[str] = []
    nombre = resolver_nombre(ip)
    ttl = _obtener_ttl(ip)
    puertos = escanear_puertos_extenso(ip)
    sistema = inferir_sistema(ttl, puertos)  # Pasar puertos para mejor detección
    recursos, advertencia_recursos = _listar_recursos(ip)
    if advertencia_recursos:
        advertencias.append(advertencia_recursos)
    
    # Análisis de seguridad
    vulnerabilidades = analizar_puertos(puertos)
    recomendaciones = generar_recomendaciones(vulnerabilidades)
    tipo_dispositivo = obtener_tipo_dispositivo(puertos, sistema)

    return DeepScanResult(
        ip=ip,
        nombre=nombre,
        ttl=ttl,
        sistema_operativo=sistema,
        tipo_dispositivo=tipo_dispositivo,
        puertos_abiertos=puertos,
        recursos_compartidos=recursos,
        vulnerabilidades=vulnerabilidades,
        recomendaciones=recomendaciones,
        advertencias=advertencias,
    )


def _obtener_ttl(ip: str) -> Optional[int]:
    # Detectar sistema operativo para usar los parámetros correctos
    sistema = platform.system()
    
    if sistema == "Windows":
        comando = ["ping", "-n", "1", "-w", "600", ip]
        encoding = "cp850"
    else:
        # Linux/Unix/macOS
        comando = ["ping", "-c", "1", "-W", "1", ip]
        encoding = "utf-8"
    
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding=encoding,
            errors="ignore",
            check=False,
            timeout=4,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if resultado.returncode not in (0, 1):  # ping puede devolver 1 aunque haya TTL
        salida = resultado.stdout or ""
    else:
        salida = resultado.stdout or ""

    for linea in salida.splitlines():
        linea_upper = linea.upper()
        if "TTL=" in linea_upper:
            try:
                ttl_str = linea_upper.split("TTL=")[1].split()[0]
                return int(ttl_str)
            except (IndexError, ValueError):
                continue
    return None


def inferir_sistema(ttl: Optional[int], puertos: Optional[list[int]] = None, debug: bool = False) -> str:
    """
    Infiere el sistema operativo basándose en TTL y puertos abiertos.
    PRIORIZA LA DETECCIÓN POR PUERTOS sobre TTL (más confiable).
    
    Args:
        ttl: Time To Live detectado en el ping
        puertos: Lista de puertos abiertos (opcional para mejor precisión)
        debug: Si es True, imprime información de depuración
    
    Returns:
        Nombre del sistema operativo detectado
    """
    if ttl is None:
        ttl = 0  # Valor por defecto para permitir detección por puertos
    
    if debug:
        print(f"[DEBUG] inferir_sistema: TTL={ttl}, Puertos={puertos}")
    
    # Convertir puertos a set para búsquedas rápidas
    puertos_set = set(puertos) if puertos else set()
    
    # Patrones de puertos característicos
    puertos_windows = {135, 139, 445, 3389, 5357, 5985, 5986}  # RPC, SMB, NetBIOS, RDP, WS-Discovery, WinRM
    puertos_apple = {548, 5900, 62078}  # AFP, VNC, AirPlay
    puertos_android = {5555}  # ADB (Android Debug Bridge)
    puertos_linux = {22}  # SSH (común en Linux pero también en otros)
    puertos_iot = {80, 8080, 8888, 9000}  # Dispositivos IoT comunes
    
    # Calcular coincidencias
    coincidencias_windows = len(puertos_set & puertos_windows)
    coincidencias_apple = len(puertos_set & puertos_apple)
    coincidencias_android = puertos_set & puertos_android
    tiene_ssh = 22 in puertos_set
    tiene_http = 80 in puertos_set or 8080 in puertos_set
    
    # ===== PRIORIDAD 1: DETECCIÓN POR PUERTOS (MÁS CONFIABLE) =====
    
    # Windows: requiere al menos 2 puertos característicos
    # EXCEPCIÓN: Si TTL=64 exacto (típico Linux), necesita 3+ puertos Windows o puertos RPC específicos
    if coincidencias_windows >= 2:
        # Múltiples puertos Windows detectados
        if debug:
            print(f"[DEBUG] {coincidencias_windows} puertos Windows detectados")
        
        # Si TTL es exactamente 64 (típico de Linux), ser más estricto
        # Samba en Linux abre 139/445, pero no RPC (135)
        if ttl == 64:
            # TTL 64 es MÁS probable Linux que Windows
            # Solo marcar como Windows si hay evidencia MUY fuerte:
            # - Tiene RPC (135) que es exclusivo de Windows
            # - O tiene 3+ puertos Windows (no solo Samba)
            tiene_rpc = 135 in puertos_set
            if tiene_rpc or coincidencias_windows >= 3:
                if debug:
                    print(f"[DEBUG] TTL 64 pero evidencia fuerte de Windows (RPC={tiene_rpc}, puertos={coincidencias_windows})")
                return "Windows (TTL modificado)"
            else:
                # TTL 64 + solo Samba (139/445) = Linux con Samba
                if debug:
                    print(f"[DEBUG] TTL 64 + solo puertos Samba → Linux con Samba")
                # Continuar con la detección normal (caerá en la sección de TTL 64)
                pass
        else:
            # TTL != 64, confiar en los puertos Windows
            if ttl >= 128 or ttl == 0:
                return "Windows 10/11"
            elif ttl >= 100:
                return "Windows 7/8"
            else:
                return "Windows"
    
    # macOS/iOS: puertos característicos de Apple
    if coincidencias_apple >= 1:
        # Puertos característicos de Apple
        if debug:
            print(f"[DEBUG] Detectado como macOS/iOS: {coincidencias_apple} puertos Apple")
        if ttl >= 64 or ttl == 0:
            return "macOS / iOS"
        else:
            return "macOS"
    
    # Android: puerto ADB
    if coincidencias_android:
        if debug:
            print(f"[DEBUG] Detectado como Android: Puerto ADB abierto")
        return "Android"
    
    # Linux/Unix: SSH sin puertos Windows
    # IMPORTANTE: Si tiene SSH pero NO tiene puertos Windows, es Linux
    if tiene_ssh and coincidencias_windows == 0:
        if debug:
            print(f"[DEBUG] Detectado como Linux: SSH abierto, sin puertos Windows")
        if tiene_http:
            # Probablemente un servidor Linux
            return "Linux (servidor)"
        # Solo SSH - alta probabilidad Linux/Unix
        return "Linux/Unix"
    
    # ===== PRIORIDAD 2: DETECCIÓN POR TTL (CUANDO NO HAY PUERTOS CLAROS) =====
    
    if debug:
        print(f"[DEBUG] Detección basada en TTL: {ttl}")
    
    # TTL muy alto: dispositivos de red
    if ttl >= 200:
        return "Dispositivo de red / Router"
    
    # TTL típico Windows (128)
    if ttl >= 128:
        # Tiene TTL de Windows
        if tiene_ssh and coincidencias_windows == 0:
            # TTL alto pero tiene SSH y no tiene puertos Windows -> Linux modificado
            return "Linux/Unix (TTL modificado)"
        # Si solo tiene 1 puerto Windows o ninguno, probablemente sea Windows de todos modos
        if coincidencias_windows >= 1:
            return "Windows 10/11"
        return "Windows"
    
    # Zona intermedia (100-127)
    if ttl >= 100 and ttl < 128:
        # Puede ser Windows con TTL reducido o Linux con TTL aumentado
        if coincidencias_windows > 0:
            return "Windows"
        if tiene_ssh:
            return "Linux/Unix"
        return "Sistema Windows/Unix"
    
    # TTL típico Linux/Unix/macOS (64)
    if ttl >= 64 and ttl < 100:
        # TTL típico de Linux/Unix/macOS/iOS/Android
        if tiene_ssh:
            # SSH detectado - es Linux/Unix
            if coincidencias_apple > 0:
                return "macOS"
            if tiene_http:
                return "Linux (servidor)"
            return "Linux/Unix"
        
        # Caso especial: TTL 64 con puertos Samba (139/445) pero sin SSH
        # Esto es típico de Linux con Samba pero SSH deshabilitado
        if coincidencias_windows >= 1 and not (135 in puertos_set):
            # Tiene puertos SMB/NetBIOS pero NO tiene RPC (135)
            # RPC (135) es exclusivo de Windows, su ausencia indica Linux con Samba
            if debug:
                print(f"[DEBUG] TTL 64 + Samba sin RPC → Linux con Samba")
            return "Linux/Unix (Samba)"
        
        if tiene_http and not tiene_ssh:
            # Solo HTTP sin SSH - podría ser dispositivo embebido
            return "Dispositivo IoT / Embebido"
        # TTL 64 sin puertos específicos
        # IMPORTANTE: TTL 64 es MÁS típico de Linux que de Windows
        # Solo marcar como Windows si hay EVIDENCIA CLARA (2+ puertos Windows)
        if coincidencias_windows >= 2:
            # Tiene TTL 64 pero múltiples puertos Windows -> Windows con TTL modificado
            return "Windows (TTL modificado)"
        # En cualquier otro caso con TTL 64, es más probable Linux/Unix
        return "Linux/Unix"
    
    # TTL bajo (32-63): dispositivos embebidos
    if ttl >= 32 and ttl < 64:
        if tiene_http:
            return "Dispositivo IoT / Cámara IP"
        return "Sistema embebido / Móvil"
    
    # ===== PRIORIDAD 3: SIN TTL, SOLO PUERTOS =====
    if ttl == 0 and puertos_set:
        # No hay TTL pero hay puertos detectados
        if tiene_ssh and coincidencias_windows == 0:
            return "Linux/Unix"
        if tiene_http:
            return "Dispositivo web"
        if coincidencias_windows >= 1:
            return "Windows"
        return "Sistema operativo desconocido"
    
    return "Sistema operativo desconocido"


def _listar_recursos(ip: str) -> Tuple[List[str], Optional[str]]:
    # net view es específico de Windows
    sistema = platform.system()
    
    if sistema == "Windows":
        comando = ["net", "view", f"\\\\{ip}"]
        encoding = "cp850"
    else:
        # En Linux, usar smbclient (parte de samba)
        # Si no está instalado, simplemente retornará un mensaje de error
        comando = ["smbclient", "-L", ip, "-N"]  # -N: sin contraseña
        encoding = "utf-8"
    
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding=encoding,
            errors="ignore",
            check=False,
            timeout=6,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [], "No fue posible consultar los recursos compartidos (comando no disponible)."

    if resultado.returncode != 0:
        mensaje = resultado.stderr or resultado.stdout or ""
        mensaje_limpio = mensaje.strip() or "Error desconocido al consultar recursos compartidos."
        return [], mensaje_limpio

    recursos: List[str] = []
    capturar = False
    
    for linea in (resultado.stdout or "").splitlines():
        linea = linea.strip()
        if not linea:
            continue
        linea_min = linea.lower()
        
        # Detectar inicio de la sección de recursos
        if linea_min.startswith("compartidos") or linea_min.startswith("shared") or linea_min.startswith("sharename"):
            capturar = True
            continue
        if linea.startswith("Nombre") or linea.startswith("Name"):
            capturar = True
            continue
        if set(linea) <= {"-"}:
            continue
        if linea_min.startswith("el comando se complet") or linea_min.startswith("the command completed"):
            break
        
        if capturar:
            # Para smbclient, las líneas son del formato: "  nombre_recurso     Tipo  Comentario"
            # Para net view, son del formato: "nombre_recurso     Tipo  Comentario"
            partes = re.split(r"\s{2,}", linea)
            if not partes:
                continue
            recurso = partes[0].strip()
            # Filtrar líneas que no son recursos (como IPC$, print$)
            if recurso and not recurso.endswith("$"):
                recursos.append(recurso)

    return recursos, None
