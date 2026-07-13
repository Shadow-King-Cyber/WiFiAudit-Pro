"""GUI Tkinter para WiFiAudit-Pro (opcional)."""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from ..core.scope_manager import ScopeManager
from ..scanner.passive_scanner import scan_networks_mock
from ..analysis.encryption_analyzer import classify_encryption
from ..analysis.risk_scoring import score_network, ScoringFactors
from ..analysis.default_creds_db import check_default_creds
from ..reporting.report_builder import AuditReport, NetworkReport, build_hardening_recommendations
from ..reporting.json_exporter import export_json
from ..reporting.html_exporter import export_html
from ..mitre import map_findings


class WiFiAuditGUI:
    """Ventana principal de la aplicación gráfica."""

    def __init__(self) -> None:
        # Crear ventana principal
        self.root = tk.Tk()
        self.root.title("WiFiAudit-Pro")
        self.root.geometry("900x600")
        self.root.configure(bg="#0d1117")

        # Estado de la aplicación
        self.scope: ScopeManager | None = None
        self.scan_results: list = []

        # Construir interfaz
        self._build_ui()

    def _build_ui(self) -> None:
        """Construye los elementos de la interfaz gráfica."""
        # Estilo visual (tema oscuro tipo GitHub)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#0d1117")
        style.configure("TLabel", background="#0d1117", foreground="#c9d1d9")
        style.configure("TButton", background="#21262d", foreground="#c9d1d9")
        style.configure("Treeview", background="#161b22", foreground="#c9d1d9", fieldbackground="#161b22")
        style.configure("Treeview.Heading", background="#21262d", foreground="#58a6ff")

        # Barra superior con botones de acción
        top = ttk.Frame(self.root)
        top.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(top, text="Cargar Alcance", command=self._load_scope).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Escanear (Mock)", command=self._mock_scan).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Generar Reporte", command=self._generate_report).pack(side=tk.LEFT, padx=4)

        # Etiqueta de estado del alcance
        self.scope_label = ttk.Label(top, text="Alcance: No cargado")
        self.scope_label.pack(side=tk.RIGHT, padx=4)

        # Tabla de resultados (Treeview)
        columns = ("bssid", "ssid", "channel", "encryption", "signal", "wps", "creds", "risk", "score")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=15)
        # Configurar cabeceras de columna
        for col, heading in zip(columns, ["BSSID", "SSID", "Ch", "Cifrado", "Señal", "WPS", "Creds", "Riesgo", "Score"]):
            self.tree.heading(col, text=heading)
            self.tree.column(col, width=100)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _load_scope(self) -> None:
        """Carga un archivo de alcance seleccionado por el usuario."""
        path = filedialog.askopenfilename(
            title="Seleccionar scope.json",
            filetypes=[("Archivos JSON", "*.json")],
        )
        if path:
            try:
                self.scope = ScopeManager.from_file(path)
                self.scope_label.config(text=f"Alcance: {len(self.scope.networks)} redes")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def _mock_scan(self) -> None:
        """Ejecuta un escaneo simulado y carga los resultados en la tabla."""
        self.scan_results = scan_networks_mock()
        self._populate_tree()

    def _populate_tree(self) -> None:
        """Pobla la tabla con los resultados del escaneo."""
        # Limpiar tabla existente
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Insertar cada red escaneada con su nivel de riesgo
        for r in self.scan_results:
            enc = classify_encryption(r.encryption)
            factors = ScoringFactors(encryption=enc)
            score, level = score_network(factors)

            self.tree.insert("", tk.END, values=(
                r.bssid, r.ssid, r.channel, enc, f"{r.signal_dbm}dBm",
                "N/A", "N/A", level, score,
            ))

    def _generate_report(self) -> None:
        """Genera un reporte a partir de los resultados del escaneo."""
        if not self.scan_results:
            messagebox.showwarning("Advertencia", "Primero ejecuta un escaneo.")
            return

        # Solicitar ubicación para guardar el reporte
        path = filedialog.asksaveasfilename(
            title="Guardar reporte",
            defaultextension=".html",
            filetypes=[("Archivos HTML", "*.html"), ("Archivos JSON", "*.json")],
        )
        if not path:
            return

        # Construir reporte con todas las redes escaneadas
        report_obj = AuditReport()
        for r in self.scan_results:
            enc = classify_encryption(r.encryption)
            factors = ScoringFactors(encryption=enc)
            score, level = score_network(factors)
            findings = ["passive_sniffing"] if enc == "Open" else []

            report_obj.networks.append(
                NetworkReport(
                    bssid=r.bssid, ssid=r.ssid, channel=r.channel,
                    encryption=enc, signal_strength=r.signal_dbm,
                    wps_enabled=False, default_creds_suspected=False,
                    vendor=None, risk_score=score, risk_level=level,
                    mitre_techniques=map_findings(findings),
                    hardening_recommendations=build_hardening_recommendations(enc, False, False),
                    in_scope=self.scope.is_authorized(r.bssid) if self.scope else False,
                )
            )

        report_obj.build_summary()

        # Exportar según la extensión seleccionada
        if path.endswith(".html"):
            export_html(report_obj, path)
        else:
            export_json(report_obj, path)

        messagebox.showinfo("Éxito", f"Reporte guardado: {path}")

    def run(self) -> None:
        """Inicia el bucle principal de la interfaz gráfica."""
        self.root.mainloop()


def launch_gui() -> None:
    """Lanza la interfaz gráfica."""
    app = WiFiAuditGUI()
    app.run()
