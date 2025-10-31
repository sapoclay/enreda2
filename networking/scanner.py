from __future__ import annotations

import ipaddress
import queue
import threading

from .deep_scan import inferir_sistema
from .ping import ping_host
from .ports import escanear_puertos


MAXIMO_HOSTS = 512


class EscanerRed(threading.Thread):
    """Hilo dedicado a recorrer los hosts de una red IPv4."""

    def __init__(self, red: ipaddress.IPv4Network, cola_resultados: queue.Queue):
        super().__init__(daemon=True)
        self.red = red
        self.cola_resultados = cola_resultados
        self._evento_detener = threading.Event()

    def detener(self) -> None:
        self._evento_detener.set()

    def run(self) -> None:  # noqa: D401 - firma obligatoria de Thread
        for indice, host in enumerate(self.red.hosts(), start=1):
            if self._evento_detener.is_set():
                break

            direccion_ip = str(host)
            activo, ttl = ping_host(direccion_ip)
            puertos = []
            if activo:
                puertos = escanear_puertos(direccion_ip)
            sistema = inferir_sistema(ttl)
            self.cola_resultados.put((direccion_ip, sistema, activo, indice, puertos, ttl))

        self.cola_resultados.put(None)
