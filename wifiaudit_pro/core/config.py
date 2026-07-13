"""Cargador de configuración global."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """Almacena los valores de configuración global de WiFiAudit-Pro."""

    # Interfaz de red en modo monitor
    interface: str = "wlan0mon"
    # Duración del escaneo en segundos
    scan_duration: int = 60
    # Ruta al archivo de alcance
    scope_file: str = "scope.json"
    # Ruta al diccionario para ataques
    wordlist: str = "rockyou.txt"
    # Directorio de salida para reportes
    output_dir: str = "reports"
    # Ruta al archivo de log de auditoría
    log_file: str = "audit_log.jsonl"
    # Configuración adicional (clave-valor libre)
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str | Path) -> Config:
        """Carga configuración desde un archivo JSON, usando valores por defecto si no existe."""
        path = Path(path)
        if not path.exists():
            return cls()

        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)

        return cls(
            interface=data.get("interface", "wlan0mon"),
            scan_duration=data.get("scan_duration", 60),
            scope_file=data.get("scope_file", "scope.json"),
            wordlist=data.get("wordlist", "rockyou.txt"),
            output_dir=data.get("output_dir", "reports"),
            log_file=data.get("log_file", "audit_log.jsonl"),
            extra=data.get("extra", {}),
        )
