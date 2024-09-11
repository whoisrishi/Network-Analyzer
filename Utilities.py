import tkinter as tk
from tkinter import ttk
import subprocess

class NetworkDiagnosticsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Diagnostics")

        self.create_ui()
    
    def create_ui(self):
        # Create a notebook for tabs with a modern theme
        style = ttk.Style()
        style.theme_use("clam")  # Use a modern theme
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create Ping tab
        ping_tab = ttk.Frame(self.notebook)
        self.notebook.add(ping_tab, text="Ping")

        self.create_ping_ui(ping_tab)

        # Create Trace Route tab
        trace_tab = ttk.Frame(self.notebook)
        self.notebook.add(trace_tab, text="Trace Route")

        self.create_trace_ui(trace_tab)

    def create_ping_ui(self, tab):
        # Entry for entering the target IP/hostname
        self.ping_entry_label = tk.Label(tab, text="Target IP/Hostname:")
        self.ping_entry_label.pack(pady=10)
        self.ping_entry = tk.Entry(tab)
        self.ping_entry.pack()

        # Button to perform ping
        self.ping_button = tk.Button(tab, text="Ping", command=self.ping)
        self.ping_button.pack()

        # Text widget to display ping results with scrollbars
        self.ping_results_text = tk.Text(tab, height=10, width=40)
        self.ping_results_text.pack(fill=tk.BOTH, expand=True)
        self.ping_results_text.config(state=tk.DISABLED)  # Make it read-only

        # Add scrollbars to the Text widget
        scroll_y = tk.Scrollbar(tab, orient=tk.VERTICAL, command=self.ping_results_text.yview)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.ping_results_text.config(yscrollcommand=scroll_y.set)

    def create_trace_ui(self, tab):
        # Entry for entering the target IP/hostname
        self.trace_entry_label = tk.Label(tab, text="Target IP/Hostname:")
        self.trace_entry_label.pack(pady=10)
        self.trace_entry = tk.Entry(tab)
        self.trace_entry.pack()

        # Button to perform trace route
        self.trace_button = tk.Button(tab, text="Trace Route", command=self.trace_route)
        self.trace_button.pack()

        # Text widget to display trace route results with scrollbars
        self.trace_results_text = tk.Text(tab, height=10, width=40)
        self.trace_results_text.pack(fill=tk.BOTH, expand=True)
        self.trace_results_text.config(state=tk.DISABLED)  # Make it read-only

        # Add scrollbars to the Text widget
        scroll_y = tk.Scrollbar(tab, orient=tk.VERTICAL, command=self.trace_results_text.yview)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.trace_results_text.config(yscrollcommand=scroll_y.set)

    def ping(self):
        target = self.ping_entry.get()
        try:
            result = subprocess.run(["ping", target], capture_output=True, text=True, timeout=10)
            self.ping_results_text.config(state=tk.NORMAL)
            self.ping_results_text.delete(1.0, tk.END)
            self.ping_results_text.insert(tk.END, result.stdout)
            self.ping_results_text.config(state=tk.DISABLED)
        except subprocess.CalledProcessError:
            self.ping_results_text.config(state=tk.NORMAL)
            self.ping_results_text.delete(1.0, tk.END)
            self.ping_results_text.insert(tk.END, "Ping failed.")
            self.ping_results_text.config(state=tk.DISABLED)
        except subprocess.TimeoutExpired:
            self.ping_results_text.config(state=tk.NORMAL)
            self.ping_results_text.delete(1.0, tk.END)
            self.ping_results_text.insert(tk.END, "Ping timed out.")
            self.ping_results_text.config(state=tk.DISABLED)

    def trace_route(self):
        target = self.trace_entry.get()
        try:
            result = subprocess.run(["tracert", target], capture_output=True, text=True, timeout=60)
            self.trace_results_text.config(state=tk.NORMAL)
            self.trace_results_text.delete(1.0, tk.END)
            self.trace_results_text.insert(tk.END, result.stdout)
            self.trace_results_text.config(state=tk.DISABLED)
        except subprocess.CalledProcessError as e:
            self.trace_results_text.config(state=tk.NORMAL)
            self.trace_results_text.delete(1.0, tk.END)
            self.trace_results_text.insert(tk.END, f"Trace route failed : {str(e)}")
            self.trace_results_text.config(state=tk.DISABLED)
        except subprocess.TimeoutExpired:
            self.trace_results_text.config(state=tk.NORMAL)
            self.trace_results_text.delete(1.0, tk.END)
            self.trace_results_text.insert(tk.END, "Trace route timed out.")
            self.trace_results_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkDiagnosticsApp(root)
    #app.ping_entry.insert(0, "google.com")
    app.trace_entry.insert(0, "facebook.com")
    root.mainloop()