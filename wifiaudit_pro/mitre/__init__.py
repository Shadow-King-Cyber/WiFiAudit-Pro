"""Módulo de mapeo MITRE ATT&CK — asocia hallazgos a técnicas del framework."""

from __future__ import annotations


# Referencia: https://attack.mitre.org/techniques/enterprise/
# Mapa de hallazgos del escáner a técnicas MITRE ATT&CK correspondientes
TECHNIQUE_MAP: dict[str, dict[str, str]] = {
    "passive_sniffing": {
        "id": "T1040",
        "name": "Network Sniffing",
        "tactic": "Credential Access",
        "description": "Captura pasiva de frames beacon y respuestas de probe WiFi.",
    },
    "handshake_capture": {
        "id": "T1040",
        "name": "Network Sniffing",
        "tactic": "Credential Access",
        "description": "Captura del handshake de 4 vías WPA/WPA2 para cracking offline.",
    },
    "dictionary_attack": {
        "id": "T1110.002",
        "name": "Brute Force: Password Cracking",
        "tactic": "Credential Access",
        "description": "Ataque de diccionario offline contra handshake capturado.",
    },
    "wps_attack": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Fuerza bruta de PIN WPS / vector de ataque Pixie Dust.",
    },
    "default_credentials": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Uso de credenciales de fábrica conocidas por el fabricante.",
    },
    "evil_twin": {
        "id": "T1557",
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "description": "AP rogue que impersona una red legítima (función futura).",
    },
    "open_network": {
        "id": "T1040",
        "name": "Network Sniffing",
        "tactic": "Credential Access",
        "description": "Red abierta (sin cifrado) permite interceptación pasiva de tráfico.",
    },
}


def get_technique(finding_key: str) -> dict[str, str] | None:
    """Devuelve el diccionario de técnica MITRE ATT&CK para un hallazgo, o ``None``."""
    return TECHNIQUE_MAP.get(finding_key)


def map_findings(finding_keys: list[str]) -> list[dict[str, str]]:
    """Mapea una lista de claves de hallazgo a técnicas MITRE ATT&CK (deduplicadas)."""
    seen: set[str] = set()
    results: list[dict[str, str]] = []
    for key in finding_keys:
        tech = TECHNIQUE_MAP.get(key)
        # Solo agregar si no se ha visto esta técnica antes
        if tech and tech["id"] not in seen:
            seen.add(tech["id"])
            results.append(tech)
    return results
