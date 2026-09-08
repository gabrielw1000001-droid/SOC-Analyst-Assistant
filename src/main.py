"""
main.py

Ponto de entrada da aplicacao SOC Analyst Assistant.

Interface grafica simples (Tkinter) que permite:
    1) Selecionar um arquivo de log;
    2) Executar a analise (parsing + deteccao + classificacao);
    3) Visualizar os eventos/alertas encontrados, sua severidade e evidencias;
    4) Visualizar a tecnica MITRE ATT&CK associada e as recomendacoes;
    5) Gerar e salvar um relatorio de incidente em JSON.

Este e um projeto educacional. Nenhuma acao ofensiva, de exploracao ou
de acesso nao autorizado e executada por esta interface.
"""

from __future__ import annotations

import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Garante que os modulos irmaos (log_analyzer, alert_classifier, mitre,
# incident_report) sejam encontrados independentemente do diretorio de
# onde o script for executado.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import alert_classifier
import incident_report
import log_analyzer
import mitre

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_LOG_PATH = os.path.join(_BASE_DIR, "data", "sample_auth.log")
_REPORTS_DIR = os.path.join(_BASE_DIR, "reports")

_SEVERITY_COLORS = {
    "LOW": "#4caf50",
    "MEDIUM": "#ffb300",
    "HIGH": "#fb8c00",
    "CRITICAL": "#e53935",
}


class SocAnalystAssistantApp:
    """Janela principal da aplicacao."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("SOC Analyst Assistant (V1 - Educacional)")
        self.root.geometry("980x620")

        self.current_log_path = tk.StringVar(value="Nenhum arquivo selecionado.")
        self.reports = []  # relatorios gerados a partir da ultima analise
        self.alerts_by_row = {}  # mapeia iid da Treeview -> relatorio

        self._build_layout()

    # ------------------------------------------------------------------ #
    # Construcao da interface
    # ------------------------------------------------------------------ #

    def _build_layout(self) -> None:
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill="x")

        ttk.Button(
            top_frame, text="Selecionar arquivo de log", command=self._select_log_file
        ).pack(side="left")

        ttk.Button(
            top_frame, text="Executar analise", command=self._run_analysis
        ).pack(side="left", padx=8)

        ttk.Label(top_frame, textvariable=self.current_log_path, foreground="#555").pack(
            side="left", padx=8
        )

        main_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        main_frame.pack(fill="both", expand=True)

        # --- Lista de alertas (esquerda) ---
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(side="left", fill="both", expand=True)

        ttk.Label(list_frame, text="Eventos / Alertas detectados").pack(anchor="w")

        columns = ("type", "severity", "source_ip", "user")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=18)
        self.tree.heading("type", text="Tipo")
        self.tree.heading("severity", text="Severidade")
        self.tree.heading("source_ip", text="IP de Origem")
        self.tree.heading("user", text="Usuario")
        self.tree.column("type", width=140)
        self.tree.column("severity", width=90)
        self.tree.column("source_ip", width=130)
        self.tree.column("user", width=100)
        self.tree.pack(fill="both", expand=True, pady=4)
        self.tree.bind("<<TreeviewSelect>>", self._on_select_alert)

        ttk.Button(
            list_frame, text="Gerar relatorio (.json)", command=self._generate_report
        ).pack(anchor="w", pady=4)

        # --- Detalhes do alerta selecionado (direita) ---
        detail_frame = ttk.Frame(main_frame)
        detail_frame.pack(side="left", fill="both", expand=True, padx=(10, 0))

        ttk.Label(detail_frame, text="Detalhes do incidente").pack(anchor="w")

        self.detail_text = tk.Text(detail_frame, wrap="word", height=30, state="disabled")
        self.detail_text.pack(fill="both", expand=True, pady=4)

        status_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        status_frame.pack(fill="x")
        self.status_label = ttk.Label(status_frame, text="Pronto.", foreground="#555")
        self.status_label.pack(anchor="w")

    # ------------------------------------------------------------------ #
    # Acoes
    # ------------------------------------------------------------------ #

    def _select_log_file(self) -> None:
        initial_dir = os.path.join(_BASE_DIR, "data")
        file_path = filedialog.askopenfilename(
            title="Selecionar arquivo de log",
            initialdir=initial_dir if os.path.isdir(initial_dir) else _BASE_DIR,
            filetypes=[("Arquivos de log", "*.log"), ("Todos os arquivos", "*.*")],
        )
        if file_path:
            self.current_log_path.set(file_path)

    def _run_analysis(self) -> None:
        log_path = self.current_log_path.get()
        if log_path == "Nenhum arquivo selecionado." or not os.path.isfile(log_path):
            if os.path.isfile(_DEFAULT_LOG_PATH):
                log_path = _DEFAULT_LOG_PATH
                self.current_log_path.set(log_path)
            else:
                messagebox.showwarning(
                    "Nenhum arquivo", "Selecione um arquivo de log valido antes de analisar."
                )
                return

        try:
            events = log_analyzer.parse_log_file(log_path)
            rules = alert_classifier.load_detection_rules()
            baseline = alert_classifier.load_user_baseline()
            alerts = alert_classifier.run_all_detections(events, rules, baseline)
            self.reports = incident_report.build_reports_from_alerts(alerts)
        except Exception as exc:  # tratamento de excecao amplo na borda da UI
            messagebox.showerror("Erro ao analisar o log", str(exc))
            return

        self._populate_tree()

        if not events:
            self.status_label.config(
                text="Analise concluida. Nenhum evento reconhecido no arquivo selecionado."
            )
        elif not self.reports:
            self.status_label.config(
                text=f"Analise concluida. {len(events)} evento(s) lido(s), "
                     "nenhum padrao suspeito identificado."
            )
        else:
            self.status_label.config(
                text=f"Analise concluida. {len(events)} evento(s) lido(s), "
                     f"{len(self.reports)} alerta(s) gerado(s)."
            )

    def _populate_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.alerts_by_row.clear()
        self._clear_detail_panel()

        for report in self.reports:
            row_id = self.tree.insert(
                "",
                "end",
                values=(
                    report["event_type"],
                    report["severity"],
                    report["source_ip"],
                    report["affected_user"],
                ),
                tags=(report["severity"],),
            )
            self.alerts_by_row[row_id] = report

        for severity, color in _SEVERITY_COLORS.items():
            self.tree.tag_configure(severity, foreground=color)

    def _on_select_alert(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        report = self.alerts_by_row.get(selection[0])
        if report is None:
            return
        self._show_detail(report)

    def _show_detail(self, report: dict) -> None:
        text = incident_report.format_report_text(report)
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, text)
        self.detail_text.config(state="disabled")

    def _clear_detail_panel(self) -> None:
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.config(state="disabled")

    def _generate_report(self) -> None:
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo(
                "Nenhum alerta selecionado",
                "Selecione um alerta na lista antes de gerar o relatorio.",
            )
            return

        report = self.alerts_by_row.get(selection[0])
        if report is None:
            return

        try:
            saved_path = incident_report.save_report_json(report, _REPORTS_DIR)
        except OSError as exc:
            messagebox.showerror("Erro ao salvar relatorio", str(exc))
            return

        messagebox.showinfo("Relatorio gerado", f"Relatorio salvo em:\n{saved_path}")
        self.status_label.config(text=f"Relatorio salvo em: {saved_path}")


def main() -> None:
    root = tk.Tk()
    SocAnalystAssistantApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
