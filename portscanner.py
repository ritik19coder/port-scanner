import tkinter as tk
from tkinter import messagebox
import nmap

def scan_ports():
    target_ip = target_entry.get()
    ports = port_entry.get()
    scan_type = scan_type_var.get()

    # Initialize the PortScanner object
    scanner = nmap.PortScanner()
    
    try:
        # Define the Nmap arguments based on the selected scan type
        arguments = {
            'TCP SYN': '-sS',
            'TCP Connect': '-sT',
            'TCP ACK': '-sA',
            'TCP Window': '-sW',
            'TCP Masquerade': '-sM',
            'TCP Null': '-sN',
            'TCP FIN': '-sF',
            'TCP Xmas': '-sX',
            'UDP': '-sU',
            'Intense': '-A',
            'Intense Scan Plus': '-A -sV -sC',
            'OS Detection': '-O',
            'Version Detection': '-sV',
            'Script Scan': '-sC',
            'Traceroute': '--traceroute',
        }

        # Perform the scan on the target IP for the specified ports
        scanner.scan(target_ip, ports, arguments=arguments[scan_type])

        results_text.delete(1.0, tk.END)  # Clear previous results

        # Check for results and append to results_text
        if 'tcp' in scanner[target_ip]:
            results_text.insert(tk.END, "TCP Ports:\n")
            for port in scanner[target_ip]['tcp']:
                state = scanner[target_ip]['tcp'][port]['state']
                results_text.insert(tk.END, f"Port {port}: {state}\n")

        if 'udp' in scanner[target_ip]:
            results_text.insert(tk.END, "UDP Ports:\n")
            for port in scanner[target_ip]['udp']:
                state = scanner[target_ip]['udp'][port]['state']
                results_text.insert(tk.END, f"Port {port}: {state}\n")

        if 'tcp' not in scanner[target_ip] and 'udp' not in scanner[target_ip]:
            results_text.insert(tk.END, f"No open ports found on {target_ip} in the range {ports}.\n")

    except nmap.PortScannerError as e:
        messagebox.showerror("Nmap Error", str(e))
    except KeyError:
        messagebox.showerror("Error", f"Scan could not be completed for {target_ip}. The target may be down or unreachable.")
    except Exception as e:
        messagebox.showerror("Unexpected Error", str(e))

# Create the main window
root = tk.Tk()
root.title("Nmap Port Scanner")

# Create and place the input fields
tk.Label(root, text="Target IP Address:").grid(row=0, column=0, padx=5, pady=5)
target_entry = tk.Entry(root, width=30)
target_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(root, text="Port Range (e.g., 22-80):").grid(row=1, column=0, padx=5, pady=5)
port_entry = tk.Entry(root, width=30)
port_entry.grid(row=1, column=1, padx=5, pady=5)

# Create scan type selection
tk.Label(root, text="Select Scan Type:").grid(row=2, column=0, padx=5, pady=5)
scan_type_var = tk.StringVar(value='TCP SYN')
scan_type_options = ['TCP SYN', 'TCP Connect', 'TCP ACK', 'TCP Window', 'TCP Masquerade',
                     'TCP Null', 'TCP FIN', 'TCP Xmas', 'UDP', 'Intense', 
                     'Intense Scan Plus', 'OS Detection', 'Version Detection', 
                     'Script Scan', 'Traceroute']
scan_type_menu = tk.OptionMenu(root, scan_type_var, *scan_type_options)
scan_type_menu.grid(row=2, column=1, padx=5, pady=5)

# Create the scan button
scan_button = tk.Button(root, text="Scan", command=scan_ports)
scan_button.grid(row=3, columnspan=2, padx=5, pady=5)

# Create a text box for results
results_text = tk.Text(root, width=50, height=15)
results_text.grid(row=4, columnspan=2, padx=5, pady=5)

# Start the GUI event loop
root.mainloop()
