"""Logger de auditoría append-only — registra cada acción ejecutada por la herramienta."""

from __future__ import annotations

import getpass
import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    """Logger append-only que escribe registros en formato JSONL.

    Cada registro contiene: marca de tiempo (UTC ISO-8601), usuario del
    sistema, acción ejecutada, BSSID objetivo y resultado. El archivo solo
    puede ser extendido (append); no existe método para sobrescribir ni
    truncar.
    """

    def __init__(self, path: str | Path = "audit_log.jsonl") -> None:
        self._path = Path(path)
        # Asegurar que el archivo exista (lo crea si no existe)
        self._path.touch(exist_ok=True)

    # -- API pública --------------------------------------------------------

    def log(
        self,
        action: str,
        bssid: str,
        result: str,
        *,
        extra: dict | None = None,
    ) -> dict:
        """Agrega un registro de auditoría y lo devuelve como diccionario."""
        record: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": self._current_user(),
            "action": action,
            "bssid": bssid,
            "result": result,
        }
        if extra:
            record["extra"] = extra

        # Escribir en modo append para garantizar integridad del log
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

        return record

    def log_denied(self, action: str, bssid: str) -> dict:
        """Atajo para registrar una acción denegada (BSSID fuera del alcance)."""
        return self.log(action, bssid, "DENIED_NOT_IN_SCOPE")

    def read_all(self) -> list[dict]:
        """Lee y devuelve todos los registros del log (para tests y reportes)."""
        records: list[dict] = []
        with open(self._path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    # -- internos ----------------------------------------------------------

    @staticmethod
    def _current_user() -> str:
        """Obtiene el usuario actual del sistema."""
        try:
            return getpass.getuser()
        except Exception:
            return "unknown"
