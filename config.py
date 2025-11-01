from __future__ import annotations

import json
import os
from typing import Any, Optional


CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "messaging": {
        "method": "msg",  # msg, net_send, powershell
        "check_ports": [445, 135, 139, 5985],  # Puertos a verificar antes de enviar
        "preferred_port": None,  # None = automático según método
    },
    "appearance": {
        "mode": "system",  # system, Light, Dark
    },
}


class Config:
    """Maneja la configuración de la aplicación."""
    
    def __init__(self):
        self.config_path = os.path.join(os.path.dirname(__file__), CONFIG_FILE)
        self.data = self._load()
    
    def _load(self) -> dict[str, Any]:
        """Carga la configuración desde el archivo o usa valores por defecto."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    # Mezclar con defaults para asegurar que existan todas las claves
                    return self._merge_dicts(DEFAULT_CONFIG.copy(), loaded)
            except (json.JSONDecodeError, OSError):
                return DEFAULT_CONFIG.copy()
        return DEFAULT_CONFIG.copy()
    
    def _merge_dicts(self, base: dict, update: dict) -> dict:
        """Mezcla dos diccionarios recursivamente."""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                base[key] = self._merge_dicts(base[key], value)
            else:
                base[key] = value
        return base
    
    def save(self) -> bool:
        """Guarda la configuración actual al archivo."""
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            return True
        except OSError:
            return False
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Obtiene un valor de configuración usando notación de punto.
        """
        keys = key_path.split(".")
        value = self.data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value
    
    def set(self, key_path: str, value: Any) -> None:
        """
        Establece un valor de configuración usando notación de punto.
        """
        keys = key_path.split(".")
        target = self.data
        for key in keys[:-1]:
            if key not in target:
                target[key] = {}
            target = target[key]
        target[keys[-1]] = value


# Instancia global de configuración
_config_instance: Optional[Config] = None


def get_config() -> Config:
    """Obtiene la instancia global de configuración."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance
