import subprocess
import tkinter as tk
from tkinter import messagebox

# Function to check if a rule with the specified name exists
def rule_exists(rule_name):
    result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=" + rule_name], capture_output=True, text=True)
    return "No rules match the specified criteria." not in result.stdout

# Function to block outbound traffic to an IP using Windows Firewall
def block_outbound_ip(ip):
    try:
        rule_name = "BlockOutboundIP"
        if not rule_exists(rule_name):
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=" + rule_name, "dir=out", "action=block",
                            f"remoteip={ip}/32"])
        else:
            subprocess.run(["netsh", "advfirewall", "firewall", "set", "rule", "name=" + rule_name, f"new remoteip={ip}/32"])
        messagebox.showinfo("Success", f" traffic to IP {ip} blocked successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to block  traffic to IP {ip}: {str(e)}")

# Function to unblock outbound traffic to an IP using Windows Firewall
def unblock_outbound_ip(ip):
    try:
        rule_name = "BlockOutboundIP"
        if rule_exists(rule_name):
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=" + rule_name])
            messagebox.showinfo("Success", f" traffic to IP {ip} unblocked successfully.")
        else:
            messagebox.showinfo("Info", f"Outbound traffic to IP {ip} was not blocked.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to unblock  traffic to IP {ip}: {str(e)}")

# Create a GUI using tkinter
def create_gui():
    root = tk.Tk()
    root.title(" IP Blocker")

    # Create and set a custom window icon
    root.iconbitmap("icon.ico")

    label = tk.Label(root, text="Enter IP Address:")
    label.pack(pady=10)

    ip_entry = tk.Entry(root)
    ip_entry.pack()

    block_button = tk.Button(root, text="Block  IP", command=lambda: block_outbound_ip(ip_entry.get()))
    block_button.pack(pady=10)

    unblock_button = tk.Button(root, text="Unblock  IP", command=lambda: unblock_outbound_ip(ip_entry.get()))
    unblock_button.pack(pady=10)

    # Center the window on the screen
    window_width = 300
    window_height = 200
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")

    root.mainloop()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        # Run the GUI version
        create_gui()
    elif len(sys.argv) == 2:
        # Run from the terminal with an IP address as a parameter
        ip_address = sys.argv[1]
        block_outbound_ip(ip_address)
    else:
        print("Usage:")
        print("To block outbound traffic to an IP from the terminal: python script.py <IP_ADDRESS>")
        print("To run the GUI version: python script.py --gui")
