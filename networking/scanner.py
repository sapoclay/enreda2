from __future__ import annotations

import ipaddress
import queue
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, Optional

from .deep_scan import inferir_sistema
from .ping import ping_host
from .ports import escanear_puertos


MAXIMO_HOSTS = 512
MAX_WORKERS = 10  # Número de hilos para escaneo paralelo


class EscanerRed(threading.Thread):
    """Hilo dedicado a recorrer los hosts de una red IPv4 con escaneo paralelo."""

    def __init__(self, red: ipaddress.IPv4Network, cola_resultados: queue.Queue):
        super().__init__(daemon=True)
        self.red = red
        self.cola_resultados = cola_resultados
        self._evento_detener = threading.Event()

    def detener(self) -> None:
        self._evento_detener.set()

    def _escanear_host(self, host: ipaddress.IPv4Address, indice: int) -> Tuple[str, str, bool, int, list[int], Optional[int]]:
        """Escanea un único host y retorna sus datos."""
        if self._evento_detener.is_set():
            return ("", "", False, indice, [], None)
        
        direccion_ip = str(host)
        activo, ttl = ping_host(direccion_ip)
        puertos = []
        
        if activo:
            puertos = escanear_puertos(direccion_ip)
        
        sistema = inferir_sistema(ttl, puertos)  # Pasar puertos para mejor detección
        return (direccion_ip, sistema, activo, indice, puertos, ttl)

    def run(self) -> None:  # noqa: D401 - firma obligatoria de Thread
        """Ejecuta el escaneo usando ThreadPoolExecutor para paralelismo."""
        hosts_list = list(self.red.hosts())
        total_hosts = len(hosts_list)
        
        # Determinar número óptimo de workers
        num_workers = min(MAX_WORKERS, total_hosts, 20)
        
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            # Enviar todas las tareas
            futures = {
                executor.submit(self._escanear_host, host, idx): idx 
                for idx, host in enumerate(hosts_list, start=1)
            }
            
            # Procesar resultados a medida que se completan
            for future in as_completed(futures):
                if self._evento_detener.is_set():
                    # Cancelar tareas pendientes
                    for f in futures:
                        f.cancel()
                    break
                
                try:
                    resultado = future.result()
                    if resultado[0]:  # Si hay IP (no fue detenido)
                        self.cola_resultados.put(resultado)
                except Exception as e:
                    # Loguear error pero continuar
                    print(f"Error escaneando host: {e}")
                    continue
        
        # Señal de finalización
        self.cola_resultados.put(None)
