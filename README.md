# WiFiAudit-Pro

Herramienta de Auditoría de Seguridad WiFi para pruebas de penetración y evaluaciones de seguridad autorizadas.

> **ADVERTENCIA**: Esta herramienta es **únicamente para pruebas de seguridad autorizadas**. El acceso no autorizado a redes informáticas es ilegal. Siempre obtén permiso por escrito antes de realizar pruebas.

## Características

- Escaneo y clasificación pasiva de redes WiFi
- Análisis de cifrado (WEP / WPA / WPA2 / WPA3 / Abierto)
- Detección de WPS y evaluación de vulnerabilidades
- Verificación de credenciales por defecto contra valores de fábrica conocidos
- Captura de handshake WPA/WPA2 (solo objetivos autorizados)
- Ataque de diccionario offline contra handshakes capturados
- Motor de scoring de riesgo con factores configurables
- Mapeo de técnicas MITRE ATT&CK
- Generación de reportes JSON y HTML con visualizaciones Chart.js
- Validación de autorización basada en alcance (scope)
- Registro de auditoría append-only (solo escritura)

## Aviso Legal

Esta herramienta se proporciona únicamente con fines educativos y para pruebas de seguridad autorizadas. El usuario asume toda la responsabilidad de garantizar que cuenta con la autorización adecuada antes de usar esta herramienta contra cualquier red.

**Al usar este software, aceptas que:**
- Solo lo usarás en redes que poseas o para las que tengas autorización explícita por escrito
- El acceso no autorizado a sistemas informáticos es ilegal en la mayoría de jurisdicciones
- Los autores no asumen responsabilidad por uso indebido

Leyes aplicables (incluyendo pero no limitándose a):
- **Panamá**: Ley 51 de 2012 — Delitos Informáticos
- **USA**: Computer Fraud and Abuse Act (CFAA)
- **UE**: Directive on Attacks against Information Systems (2013/40/EU)

## Requisitos

- Python 3.11+
- Linux con adaptador inalámbrico que soporte modo monitor
- Suite [aircrack-ng](https://www.aircrack-ng.org/) instalada (`sudo apt install aircrack-ng`)
- Adaptador inalámbrico compatible con inyección en modo monitor

### Dependencias del Sistema

```bash
# Debian/Ubuntu
sudo apt install aircrack-ng

# Arch
sudo pacman -S aircrack-ng
```

### Dependencias de Python

```bash
pip install -r requirements.txt
```

## Inicio Rápido

```bash
# 1. Copiar y personalizar el archivo de alcance
cp scope.example.json scope.json
# Editar scope.json con tus BSSIDs autorizados

# 2. Poner el adaptador en modo monitor
sudo airmon-ng start wlan0

# 3. Ejecutar escaneo pasivo
wifiaudit scan --interface wlan0mon --duration 60

# 4. O usar datos simulados (sin hardware necesario)
wifiaudit scan --mock

# 5. Generar un reporte
wifiaudit report --scan-data scan_results.json --format html --output reporte
```

## Comandos del CLI

```bash
# Escaneo pasivo (no requiere alcance)
wifiaudit scan --interface wlan0mon --duration 60

# Capturar handshake (requiere BSSID en scope.json)
wifiaudit capture --bssid AA:BB:CC:DD:EE:FF --interface wlan0mon

# Ataque de diccionario offline (requiere BSSID en scope.json)
wifiaudit crack --handshake capture.cap --wordlist rockyou.txt --bssid AA:BB:CC:DD:EE:FF

# Generar reporte HTML/JSON
wifiaudit report --scan-data results.json --format both --output reporte

# Lanzar interfaz gráfica
wifiaudit gui
```

## Configuración de Alcance

Los módulos activos (captura, crack) validan el BSSID objetivo contra `scope.json` antes de ejecutar. Cualquier BSSID que no esté en el alcance será **denegado** y registrado en el log de auditoría.

```json
{
  "authorized_by": "Tu Nombre",
  "authorization_date": "2026-01-01",
  "networks": [
    {
      "bssid": "AA:BB:CC:DD:EE:FF",
      "ssid": "TuRed",
      "note": "Autorizada para pruebas de seguridad"
    }
  ]
}
```

## Scoring de Riesgo

| Factor | Puntos |
|---|---|
| Abierto (sin cifrado) | +50 |
| WEP | +40 |
| Credenciales por defecto sospechadas | +30 |
| WPA (sin WPA2/3) | +25 |
| WPS habilitado | +20 |
| WPA2 (sin WPA3) | +5 |
| Solapamiento de canal (>2 redes) | +5 |

**Niveles de Riesgo:** 0-15 Bajo | 16-35 Medio | 36-60 Alto | 61+ Crítico

## Estructura del Proyecto

```
WiFiAudit-Pro/
├── wifiaudit_pro/
│   ├── core/           # Gestor de alcance, logger de auditoría, configuración
│   ├── scanner/        # Escaneo pasivo de redes
│   ├── capture/        # Captura de handshakes
│   ├── analysis/       # Cifrado, scoring de riesgo, WPS, credenciales por defecto
│   ├── attack/         # Ataque de diccionario
│   ├── mitre/          # Mapeo de técnicas ATT&CK
│   ├── reporting/      # Generación de reportes JSON/HTML
│   └── ui/             # CLI y GUI Tkinter
├── tests/              # Suite de tests con pytest
├── scope.example.json  # Ejemplo de archivo de alcance
├── requirements.txt    # Dependencias de Python
├── pyproject.toml      # Configuración del proyecto
└── LICENSE             # Licencia MIT
```

## Ejecutar Tests

```bash
pytest -v
```

## Interfaz Gráfica

```bash
wifiaudit gui
```

## Licencia

Licencia MIT — ver [LICENSE](LICENSE)
