#!/usr/bin/env python3

import os
import csv
import sys
import tkinter as tk
from tkinter import filedialog, messagebox

import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from scanner import scan_directory, scan_file

# ---------------------------
# Severity mapping
# ---------------------------
SEVERITY_MAP = {
    "AWS Access Key": "High",
    "GitHub Token": "High",
    "Google API Key": "Medium",
    "JWT": "Medium",
    "Generic API Key": "Medium",
    "Password": "High",
    "Username": "Low",
    "Email Address": "Low",
}


class SecretScannerGUI:
    def __init__(self, root: ttk.Window):
        self.root = root
        self.path = None
        self.findings_cache = []

        self.show_raw = tk.BooleanVar(master=self.root, value=False)
        self.path_var = tk.StringVar(value="No file selected")
        self.path_name_var = tk.StringVar(value="")

        self.build_ui()

    # ---------------------------
    # UI
    # ---------------------------
    def build_ui(self):
        container = ttk.Frame(self.root, padding=15)
        container.pack(fill=BOTH, expand=True)

        title = ttk.Label(container, text="Secret & API Key Detector", font=("Segoe UI", 18, "bold"))
        title.pack(anchor=W, pady=(0, 12))

        main = ttk.Frame(container)
        main.pack(fill=BOTH, expand=True)

        # ===== Sidebar =====
        sidebar = ttk.Frame(main, padding=15)
        sidebar.pack(side=LEFT, fill=Y)

        ttk.Label(sidebar, text="Scan Controls", font=("Segoe UI", 11, "bold")).pack(anchor=W)

        # Selected file box
        path_frame = ttk.Labelframe(sidebar, text="Selected file", padding=10)
        path_frame.pack(fill=X, pady=(10, 10))

        row = ttk.Frame(path_frame)
        row.pack(fill=X)

        ttk.Label(row, text="📄", font=("Segoe UI", 12)).pack(side=LEFT)
        ttk.Label(row, textvariable=self.path_name_var, font=("Segoe UI", 10, "bold"), wraplength=180).pack(side=LEFT, padx=6)

        ttk.Label(path_frame, textvariable=self.path_var, wraplength=220, bootstyle=SECONDARY).pack(anchor=W, pady=(6, 0))

        self.clear_btn = ttk.Button(path_frame, text="Clear selection", bootstyle=OUTLINE, command=self.confirm_clear)
        self.clear_btn.pack(anchor=W, pady=(8, 0))
        self.clear_btn.config(state=DISABLED)

        ttk.Button(sidebar, text="Select File", bootstyle=PRIMARY, command=self.select_file).pack(fill=X, pady=(6, 4))
        ttk.Button(sidebar, text="Select Folder", bootstyle=PRIMARY, command=self.select_folder).pack(fill=X, pady=(0, 6))
        ttk.Button(sidebar, text="Scan", bootstyle=SUCCESS, command=self.scan).pack(fill=X, pady=(6, 6))

        ttk.Separator(sidebar).pack(fill=X, pady=12)

        ttk.Checkbutton(sidebar, text="Reveal full values", variable=self.show_raw, command=self.refresh_view, bootstyle=WARNING).pack(anchor=W, pady=6)
        ttk.Button(sidebar, text="Export CSV", bootstyle=SECONDARY, command=self.export_csv).pack(fill=X, pady=(6, 6))

        ttk.Separator(sidebar).pack(fill=X, pady=12)

        ttk.Label(sidebar, text="Filter by type", font=("Segoe UI", 10, "bold")).pack(anchor=W)
        self.filter_var = tk.StringVar(value="All")
        self.filter_menu = ttk.Combobox(sidebar, textvariable=self.filter_var, state="readonly")
        self.filter_menu.pack(fill=X, pady=6)
        self.filter_menu.bind("<<ComboboxSelected>>", self.apply_filter)

        # ===== Results =====
        results = ttk.Frame(main, padding=(10, 0, 0, 0))
        results.pack(side=RIGHT, fill=BOTH, expand=True)

        columns = ("file", "line", "type", "severity", "value")
        self.tree = ttk.Treeview(results, columns=columns, show="headings", bootstyle=INFO)

        for col, text, width in [
            ("file", "File", 300),
            ("line", "Line", 60),
            ("type", "Secret Type", 160),
            ("severity", "Severity", 90),
            ("value", "Value", 420),
        ]:
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor=CENTER if col in ("line", "severity") else W)

        scroll = ttk.Scrollbar(results, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        scroll.pack(side=RIGHT, fill=Y)

        self.status = ttk.Label(
            container,
            text="Ready",
            font=("Segoe UI", 9),
            bootstyle=LIGHT
            )
        self.status.pack(anchor=W, pady=(10, 0))

    # ---------------------------
    # Actions
    # ---------------------------
    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.path = path
            self.path_var.set(path)
            self.path_name_var.set(os.path.basename(path))
            self.clear_btn.config(state=NORMAL)
            self.status.config(text="File selected")

    def select_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.path = path
            self.path_var.set(path)
            self.path_name_var.set(os.path.basename(path))
            self.clear_btn.config(state=NORMAL)
            self.status.config(text="Folder selected")

    def confirm_clear(self):
        if self.path and messagebox.askyesno("Clear selection", "Remove the selected file or folder?"):
            self.clear_selection()

    def clear_selection(self):
        self.path = None
        self.path_var.set("No file selected")
        self.path_name_var.set("")
        self.clear_btn.config(state=DISABLED)
        self.clear_results()
        self.status.config(text="Selection cleared")

    def clear_results(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def scan(self):
        if not self.path:
            messagebox.showwarning("No Path", "Select a file or folder to scan")
            return

        self.clear_results()
        self.findings_cache = []
        self.status.config(text="Scanning...")
        self.root.update_idletasks()

        findings = scan_file(self.path) if os.path.isfile(self.path) else scan_directory(self.path)

        if not findings:
            self.status.config(text="No secrets detected")
            return

        for f in findings:
            self.findings_cache.append({**f, "severity": SEVERITY_MAP.get(f["type"], "Low")})

        self.populate_filter()
        self.populate_table(self.findings_cache)
        self.status.config(text=f"{len(self.findings_cache)} findings detected")

    def populate_table(self, records):
        self.clear_results()
        for f in records:
            value = f.get("raw_value") if self.show_raw.get() else f.get("masked_value", f.get("value"))
            self.tree.insert("", END, values=(f["file"], f["line"], f["type"], f["severity"], value))

    def populate_filter(self):
        types = sorted({f["type"] for f in self.findings_cache})
        self.filter_menu["values"] = ["All"] + types
        self.filter_menu.set("All")

    def apply_filter(self, event=None):
        sel = self.filter_var.get()
        self.populate_table(self.findings_cache if sel == "All" else [f for f in self.findings_cache if f["type"] == sel])

    def refresh_view(self):
        self.apply_filter()

    def export_csv(self):
        if not self.findings_cache:
            messagebox.showinfo("No Data", "No findings to export")
            return

        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path:
            return

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["file", "line", "type", "severity", "value"])
            writer.writeheader()
            for row in self.findings_cache:
                writer.writerow({
                    "file": row["file"],
                    "line": row["line"],
                    "type": row["type"],
                    "severity": row["severity"],
                    "value": row.get("raw_value") if self.show_raw.get() else row.get("masked_value", row.get("value"))
                })

        self.status.config(text=f"Exported results to {path}")


# ---------------------------
# Entry point
# ---------------------------
if __name__ == "__main__":
    print("Running with:", sys.executable)

    root = ttk.Window(
        themename="superhero",
        title="Secret & API Key Detector",
        size=(1200, 650),
        resizable=(False, False),
    )

    app = SecretScannerGUI(root)
    root.mainloop()
