"""Gestor de alcance — valida BSSIDs contra un archivo de alcance autorizado."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ScopeEntry:
    """Representa una red autorizada dentro del alcance."""
    bssid: str
    ssid: str
    note: str = ""


@dataclass
class ScopeManager:
    """Carga y valida BSSIDs contra un archivo JSON de alcance.

    Los módulos activos **deben** llamar ``is_authorized`` antes de realizar
    cualquier acción (captura, deauth, ataque de diccionario). El escaneo
    pasivo no requiere validación de alcance.
    """

    # Nombre de quien autorizó la auditoría
    authorized_by: str = ""
    # Fecha de la autorización
    authorization_date: str = ""
    # Lista de redes autorizadas
    networks: list[ScopeEntry] = field(default_factory=list)

    # -- construcción -------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> ScopeManager:
        """Carga un archivo de alcance y devuelve una instancia de ``ScopeManager``."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Archivo de alcance no encontrado: {path}")

        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)

        # Convertir cada red del JSON en un ScopeEntry con BSSID en mayúsculas
        networks = [
            ScopeEntry(
                bssid=net["bssid"].upper(),
                ssid=net.get("ssid", ""),
                note=net.get("note", ""),
            )
            for net in data.get("networks", [])
        ]

        return cls(
            authorized_by=data.get("authorized_by", ""),
            authorization_date=data.get("authorization_date", ""),
            networks=networks,
        )

    # -- consultas ----------------------------------------------------------

    def is_authorized(self, bssid: str) -> bool:
        """Devuelve ``True`` si el *bssid* está presente en el alcance autorizado."""
        return bssid.upper() in {n.bssid for n in self.networks}

    def get_entry(self, bssid: str) -> ScopeEntry | None:
        """Devuelve el ``ScopeEntry`` para el *bssid* indicado, o ``None``."""
        bssid_upper = bssid.upper()
        for entry in self.networks:
            if entry.bssid == bssid_upper:
                return entry
        return None

    @property
    def bssids(self) -> set[str]:
        """Devuelve el conjunto de todos los BSSIDs autorizados."""
        return {n.bssid for n in self.networks}
