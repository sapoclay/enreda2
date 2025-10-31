from __future__ import annotations

import ipaddress
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
    """Ejecuta ipconfig y devuelve una lista con las interfaces IPv4 activas."""

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
