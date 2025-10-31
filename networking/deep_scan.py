from __future__ import annotations

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
    sistema = inferir_sistema(ttl)
    puertos = escanear_puertos_extenso(ip)
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
    comando = ["ping", "-n", "1", "-w", "600", ip]
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="cp850",
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


def inferir_sistema(ttl: Optional[int]) -> str:
    if ttl is None:
        return "Sistema operativo desconocido"

    if ttl >= 200:
        return "Dispositivo de red / Unix (TTL alto)"
    if ttl >= 128:
        return "Windows (TTL ≈ 128)"
    if ttl >= 100:
        return "Sistema Windows/Unix ajustado"
    if ttl >= 64:
        return "Linux/Unix (TTL ≈ 64)"
    if ttl >= 32:
        return "Sistema embebido o TTL reducido"
    return "Sistema operativo desconocido"


def _listar_recursos(ip: str) -> Tuple[List[str], Optional[str]]:
    comando = ["net", "view", f"\\\\{ip}"]
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="ignore",
            check=False,
            timeout=6,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [], "No fue posible consultar los recursos compartidos (net view)."

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
        if linea_min.startswith("compartidos") or linea_min.startswith("shared"):
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
            partes = re.split(r"\s{2,}", linea)
            if not partes:
                continue
            recurso = partes[0].strip()
            if recurso:
                recursos.append(recurso)

    return recursos, None
