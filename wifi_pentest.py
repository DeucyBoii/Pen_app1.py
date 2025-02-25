import streamlit as st
import subprocess
import threading
import time
import os
from queue import Queue

# Check if running with sudo privileges
if os.geteuid() != 0:
    st.error("This application requires root privileges. Please run with sudo.")
    st.stop()

# Global variables for automation control
scan_running = False
results_queue = Queue()

def run_command(command):
    """Execute shell commands and return output"""
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8')}"

def nmap_scan(target, ports="1-1000"):
    """Nmap scanning function"""
    return run_command(f"nmap -sV -p {ports} {target}")

def john_crack(password_file):
    """John the Ripper password cracking"""
    return run_command(f"john {password_file}")

def metasploit_scan(target):
    """Metasploit scanning function"""
    return run_command(f"msfconsole -q -x 'nmap {target}; exit'")

def hydra_attack(target, userlist, passlist):
    """Hydra password attack"""
    return run_command(f"hydra -L {userlist} -P {passlist} {target} ssh")

def snort_monitor(interface):
    """Snort network monitoring"""
    return run_command(f"snort -i {interface} -c /etc/snort/snort.conf")

def automated_pentest(target, interface, userlist, passlist):
    """Automated pentesting sequence"""
    global scan_running
    scan_running = True
    
    results = {"nmap": "", "metasploit": "", "hydra": "", "snort": "", "john": ""}
    
    # Nmap scan
    results["nmap"] = nmap_scan(target)
    results_queue.put(("Nmap", results["nmap"]))
    
    # Metasploit scan
    results["metasploit"] = metasploit_scan(target)
    results_queue.put(("Metasploit", results["metasploit"]))
    
    # Hydra attack
    results["hydra"] = hydra_attack(target, userlist, passlist)
    results_queue.put(("Hydra", results["hydra"]))
    
    # Snort monitoring (runs for 60 seconds)
    snort_thread = threading.Thread(target=lambda: results_queue.put(
        ("Snort", snort_monitor(interface))))
    snort_thread.start()
    time.sleep(60)
    
    scan_running = False

# Streamlit UI
st.title("WiFi Pentesting Suite")
st.warning("For authorized security testing only. Use responsibly and legally.")

# Sidebar controls
st.sidebar.header("Configuration")
target_ip = st.sidebar.text_input("Target IP", "192.168.1.1")
interface = st.sidebar.text_input("Network Interface", "wlan0")
userlist = st.sidebar.text_input("Username List File", "/path/to/users.txt")
passlist = st.sidebar.text_input("Password List File", "/path/to/passwords.txt")
port_range = st.sidebar.text_input("Port Range", "1-1000")

# Tabs for different tools
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "Nmap", "Metasploit", "Hydra", "John", "Snort", "Automated"
])

# Individual tool controls
with tab1:
    if st.button("Run Nmap Scan"):
        with st.spinner("Scanning..."):
            result = nmap_scan(target_ip, port_range)
            st.text_area("Nmap Results", result, height=300)

with tab2:
    if st.button("Run Metasploit Scan"):
        with st.spinner("Scanning..."):
            result = metasploit_scan(target_ip)
            st.text_area("Metasploit Results", result, height=300)

with tab3:
    if st.button("Run Hydra Attack"):
        with st.spinner("Attacking..."):
            result = hydra_attack(target_ip, userlist, passlist)
            st.text_area("Hydra Results", result, height=300)

with tab4:
    password_file = st.text_input("Password File", "/path/to/passwords")
    if st.button("Run John the Ripper"):
        with st.spinner("Cracking..."):
            result = john_crack(password_file)
            st.text_area("John Results", result, height=300)

with tab5:
    if st.button("Run Snort Monitor"):
        with st.spinner("Monitoring..."):
            result = snort_monitor(interface)
            st.text_area("Snort Results", result, height=300)

# Automated testing tab
with tab6:
    st.subheader("Automated Pentest")
    if st.button("Start Automated Scan") and not scan_running:
        st.write("Starting automated pentest sequence...")
        scan_thread = threading.Thread(
            target=automated_pentest,
            args=(target_ip, interface, userlist, passlist)
        )
        scan_thread.start()
    
    # Display results as they come in
    results_container = st.empty()
    current_results = {}
    
    while scan_running or not results_queue.empty():
        try:
            tool, result = results_queue.get_nowait()
            current_results[tool] = result
            results_container.json(current_results)
            time.sleep(1)
        except:
            time.sleep(1)

if scan_running:
    st.sidebar.warning("Scan in progress...")
else:
    st.sidebar.success("Ready")

# Footer
st.sidebar.markdown("---")
st.sidebar.info("Built with Streamlit for educational purposes")
