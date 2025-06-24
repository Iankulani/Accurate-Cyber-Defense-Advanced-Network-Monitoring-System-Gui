import sys
import os
import socket
import threading
import subprocess
import time
import datetime
import platform
import re
import json
from collections import defaultdict
import dpkt
from dpkt.compat import compat_ord
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import queue
import psutil
import netifaces
import requests
from ipwhois import IPWhois
import whois
import geoip2.database
import logging
from logging.handlers import RotatingFileHandler
import configparser

# Constants
VERSION = "1.0.0"
CONFIG_FILE = "cybershield_config.ini"
LOG_FILE = "cybershield.log"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5
SAMPLE_RATE = 0.1  # Sample 10% of packets when under heavy load
THREAT_DB_FILE = "threat_signatures.json"
GEOIP_DB_FILE = "GeoLite2-City.mmdb"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CyberShield")

# Threat signatures database
THREAT_SIGNATURES = {
    "ddos": {
        "description": "Distributed Denial of Service attack",
        "patterns": [
            {"condition": "packet_count > 1000 and time_window < 1", "severity": "high"},
            {"condition": "syn_count > 500 and ack_count < 10", "severity": "high"}
        ]
    },
    "port_scan": {
        "description": "Port scanning activity",
        "patterns": [
            {"condition": "unique_ports > 50 and time_window < 5", "severity": "medium"},
            {"condition": "unique_ports > 20 and packet_count > 100", "severity": "medium"}
        ]
    },
    "dos": {
        "description": "Denial of Service attack",
        "patterns": [
            {"condition": "packet_count > 500 and time_window < 1", "severity": "high"}
        ]
    },
    "udp_flood": {
        "description": "UDP flood attack",
        "patterns": [
            {"condition": "udp_count > 500 and time_window < 1", "severity": "high"}
        ]
    },
    "http_flood": {
        "description": "HTTP flood attack",
        "patterns": [
            {"condition": "http_count > 500 and time_window < 1", "severity": "high"}
        ]
    },
    "https_flood": {
        "description": "HTTPS flood attack",
        "patterns": [
            {"condition": "https_count > 500 and time_window < 1", "severity": "high"}
        ]
    }
}

class NetworkMonitor:
    def __init__(self, target_ip=None, interface=None):
        self.target_ip = target_ip
        self.interface = interface or self.get_default_interface()
        self.running = False
        self.packet_count = 0
        self.threat_count = defaultdict(int)
        self.stats = {
            "start_time": None,
            "total_packets": 0,
            "ip_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "threats_detected": 0
        }
        self.time_window_stats = {
            "packet_count": 0,
            "syn_count": 0,
            "ack_count": 0,
            "udp_count": 0,
            "http_count": 0,
            "https_count": 0,
            "unique_ports": set(),
            "start_time": time.time()
        }
        self.packet_queue = queue.Queue()
        self.geoip_reader = None
        self.load_geoip_database()
        self.load_threat_signatures()

    def load_geoip_database(self):
        try:
            self.geoip_reader = geoip2.database.Reader(GEOIP_DB_FILE)
            logger.info("GeoIP database loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load GeoIP database: {e}")
            self.geoip_reader = None

    def load_threat_signatures(self):
        global THREAT_SIGNATURES
        try:
            with open(THREAT_DB_FILE, 'r') as f:
                THREAT_SIGNATURES = json.load(f)
                logger.info("Threat signatures database loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load threat signatures: {e}. Using default signatures.")

    def get_default_interface(self):
        """Get the default network interface"""
        if platform.system() == "Windows":
            return "Ethernet"
        else:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface.startswith('eth') or iface.startswith('en'):
                    return iface
            return interfaces[0] if interfaces else "lo"

    def start_monitoring(self):
        """Start monitoring network traffic"""
        if self.running:
            logger.warning("Monitoring is already running")
            return False

        self.running = True
        self.stats["start_time"] = datetime.datetime.now()
        
        # Start packet processing thread
        processing_thread = threading.Thread(target=self.process_packets)
        processing_thread.daemon = True
        processing_thread.start()
        
        # Start packet capture thread
        capture_thread = threading.Thread(target=self.capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        # Start time window stats reset thread
        stats_thread = threading.Thread(target=self.reset_time_window_stats)
        stats_thread.daemon = True
        stats_thread.start()
        
        logger.info(f"Started monitoring on interface {self.interface}" + 
                   (f" for target IP {self.target_ip}" if self.target_ip else ""))
        return True

    def stop_monitoring(self):
        """Stop monitoring network traffic"""
        self.running = False
        logger.info("Stopped network monitoring")
        return True

    def capture_packets(self):
        """Capture network packets using Scapy"""
        try:
            if self.target_ip:
                filter_str = f"host {self.target_ip}"
            else:
                filter_str = "ip or arp"
                
            sniff(iface=self.interface, filter=filter_str, prn=self.packet_handler, 
                  store=False, stop_filter=lambda x: not self.running)
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            self.running = False

    def packet_handler(self, packet):
        """Handle captured packets"""
        if not self.running:
            return
            
        self.packet_queue.put(packet)
        self.packet_count += 1
        
        # Sample packets if under heavy load
        if self.packet_count % int(1/SAMPLE_RATE) == 0:
            while self.packet_queue.qsize() > 1000:  # Prevent memory overload
                self.packet_queue.get()

    def process_packets(self):
        """Process captured packets from the queue"""
        while self.running or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self.analyze_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Packet processing error: {e}")

    def analyze_packet(self, packet):
        """Analyze packet for threats"""
        self.update_stats(packet)
        self.update_time_window_stats(packet)
        self.detect_threats(packet)

    def update_stats(self, packet):
        """Update general statistics"""
        self.stats["total_packets"] += 1
        
        if IP in packet:
            self.stats["ip_packets"] += 1
            
            if TCP in packet:
                self.stats["tcp_packets"] += 1
            elif UDP in packet:
                self.stats["udp_packets"] += 1
            elif ICMP in packet:
                self.stats["icmp_packets"] += 1
            else:
                self.stats["other_packets"] += 1
        else:
            self.stats["other_packets"] += 1

    def update_time_window_stats(self, packet):
        """Update time window statistics for threat detection"""
        self.time_window_stats["packet_count"] += 1
        
        if TCP in packet:
            tcp = packet[TCP]
            if tcp.flags & 0x02:  # SYN flag
                self.time_window_stats["syn_count"] += 1
            if tcp.flags & 0x10:  # ACK flag
                self.time_window_stats["ack_count"] += 1
            
            if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                self.time_window_stats["http_count"] += 1
            elif TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                self.time_window_stats["https_count"] += 1
                
            if TCP in packet:
                self.time_window_stats["unique_ports"].add(packet[TCP].dport)
                
        elif UDP in packet:
            self.time_window_stats["udp_count"] += 1

    def reset_time_window_stats(self):
        """Reset time window statistics periodically"""
        while self.running:
            time.sleep(5)  # 5-second window
            self.time_window_stats = {
                "packet_count": 0,
                "syn_count": 0,
                "ack_count": 0,
                "udp_count": 0,
                "http_count": 0,
                "https_count": 0,
                "unique_ports": set(),
                "start_time": time.time()
            }

    def detect_threats(self, packet):
        """Detect potential threats based on packet analysis"""
        current_time = time.time()
        time_window = current_time - self.time_window_stats["start_time"]
        
        # Evaluate each threat signature
        for threat_type, signature in THREAT_SIGNATURES.items():
            for pattern in signature["patterns"]:
                try:
                    # Create a context dictionary for evaluation
                    context = {
                        "packet_count": self.time_window_stats["packet_count"],
                        "time_window": time_window,
                        "syn_count": self.time_window_stats["syn_count"],
                        "ack_count": self.time_window_stats["ack_count"],
                        "udp_count": self.time_window_stats["udp_count"],
                        "http_count": self.time_window_stats["http_count"],
                        "https_count": self.time_window_stats["https_count"],
                        "unique_ports": len(self.time_window_stats["unique_ports"])
                    }
                    
                    # Evaluate the condition
                    if eval(pattern["condition"], {}, context):
                        self.threat_count[threat_type] += 1
                        self.stats["threats_detected"] += 1
                        logger.warning(f"Potential {threat_type.upper()} detected: {signature['description']}")
                        self.log_threat_details(packet, threat_type, pattern["severity"])
                        break
                except Exception as e:
                    logger.error(f"Error evaluating threat pattern: {e}")

    def log_threat_details(self, packet, threat_type, severity):
        """Log detailed information about detected threats"""
        threat_details = {
            "timestamp": datetime.datetime.now().isoformat(),
            "threat_type": threat_type,
            "severity": severity,
            "source_ip": packet[IP].src if IP in packet else "N/A",
            "destination_ip": packet[IP].dst if IP in packet else "N/A",
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "OTHER",
            "source_port": packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0,
            "destination_port": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0,
            "packet_size": len(packet),
            "geo_info": self.get_geo_info(packet[IP].src) if IP in packet else {}
        }
        
        logger.info(f"Threat details: {json.dumps(threat_details, indent=2)}")

    def get_geo_info(self, ip_address):
        """Get geographical information for an IP address"""
        if not self.geoip_reader:
            return {}
            
        try:
            response = self.geoip_reader.city(ip_address)
            return {
                "country": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude
            }
        except Exception as e:
            logger.debug(f"Could not get GeoIP info for {ip_address}: {e}")
            return {}

    def get_whois_info(self, ip_address):
        """Get WHOIS information for an IP address"""
        try:
            obj = IPWhois(ip_address)
            results = obj.lookup_rdap()
            return {
                "asn": results.get("asn"),
                "asn_description": results.get("asn_description"),
                "network": results.get("network", {}).get("name"),
                "cidr": results.get("network", {}).get("cidr")
            }
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {ip_address}: {e}")
            return {}

    def get_interface_info(self):
        """Get information about network interfaces"""
        interfaces = {}
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            interfaces[iface] = {
                "mac": addrs.get(netifaces.AF_LINK, [{}])[0].get('addr'),
                "ipv4": addrs.get(netifaces.AF_INET, [{}])[0].get('addr'),
                "netmask": addrs.get(netifaces.AF_INET, [{}])[0].get('netmask'),
                "broadcast": addrs.get(netifaces.AF_INET, [{}])[0].get('broadcast')
            }
        return interfaces

    def get_network_stats(self):
        """Get network statistics"""
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "monitoring_time": str(datetime.datetime.now() - self.stats["start_time"]) if self.stats["start_time"] else "N/A",
            "total_packets": self.stats["total_packets"],
            "ip_packets": self.stats["ip_packets"],
            "tcp_packets": self.stats["tcp_packets"],
            "udp_packets": self.stats["udp_packets"],
            "icmp_packets": self.stats["icmp_packets"],
            "other_packets": self.stats["other_packets"],
            "threats_detected": self.stats["threats_detected"],
            "threat_breakdown": dict(self.threat_count)
        }

class CyberShieldTerminal:
    def __init__(self, monitor):
        self.monitor = monitor
        self.commands = {
            "help": self.show_help,
            "ping": self.ping,
            "netstat": self.netstat,
            "ifconfig": self.ifconfig,
            "netsh": self.netsh,
            "net": self.net_command,
            "start": self.start_monitoring,
            "stop": self.stop_monitoring,
            "stats": self.show_stats,
            "threats": self.show_threats,
            "whois": self.whois,
            "geo": self.geo_lookup,
            "clear": self.clear_screen,
            "exit": self.exit_terminal
        }
        
        # Add all Windows command prompt commands
        self.windows_commands = [
            "ASSOC", "ATTRIB", "BREAK", "BCDEDIT", "CACLS", "CALL", "CD", "CHCP",
            "CHDIR", "CHKDSK", "CHKNTFS", "CLS", "CMD", "COLOR", "COMP", "COMPACT",
            "CONVERT", "COPY", "DATE", "DEL", "DIR", "DISKPART", "DOSKEY", "DRIVERQUERY",
            "ECHO", "ENDLOCAL", "ERASE", "EXIT", "FC", "FIND", "FINDSTR", "FOR", "FORMAT",
            "FSUTIL", "FTYPE", "GOTO", "GPRESULT", "GRAFTABL", "HELP", "ICACLS", "IF",
            "LABEL", "MD", "MKDIR", "MKLINK", "MODE", "MORE", "MOVE", "OPENFILES",
            "PATH", "PAUSE", "POPD", "PRINT", "PROMPT", "PUSHD", "RD", "RECOVER", "REM",
            "REN", "RENAME", "REPLACE", "RMDIR", "ROBOCOPY", "SET", "SETLOCAL", "SC",
            "SCHTASKS", "SHIFT", "SHUTDOWN", "SORT", "START", "SUBST", "SYSTEMINFO",
            "TASKLIST", "TASKKILL", "TIME", "TITLE", "TREE", "TYPE", "VER", "VERIFY",
            "VOL", "XCOPY", "WMIC"
        ]

    def run(self):
        """Run the terminal interface"""
        print(f"CyberShield NIDS Terminal v{VERSION}")
        print("Type 'help' for available commands\n")
        
        while True:
            try:
                command = input("CyberShield> ").strip()
                if not command:
                    continue
                    
                self.process_command(command)
            except (KeyboardInterrupt, EOFError):
                print("\nUse the 'exit' command to quit")
            except Exception as e:
                print(f"Error: {e}")

    def process_command(self, command):
        """Process user command"""
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd in self.commands:
            self.commands[cmd](*args)
        elif cmd.upper() in self.windows_commands:
            self.execute_system_command(command)
        else:
            print(f"Unknown command: {cmd}. Type 'help' for available commands")

    def show_help(self):
        """Display help information"""
        print("\nCyberShield NIDS Terminal Commands:")
        print("  help                       - Show this help message")
        print("  ping <ip>                  - Ping an IP address")
        print("  netstat                    - Show network statistics")
        print("  ifconfig [/all]            - Show network interface information")
        print("  netsh wlan show network    - Show wireless networks")
        print("  net <command>              - Execute NET command (see Windows NET commands)")
        print("  start [ip]                 - Start monitoring (optionally for a specific IP)")
        print("  stop                       - Stop monitoring")
        print("  stats                      - Show monitoring statistics")
        print("  threats                    - Show detected threats")
        print("  whois <ip>                 - Get WHOIS information for an IP")
        print("  geo <ip>                   - Get geographical info for an IP")
        print("  clear                      - Clear the screen")
        print("  exit                       - Exit the terminal")
        print("\nAll standard Windows command prompt commands are also supported")
        print("For NET command help, type: net help")

    def ping(self, ip_address=None):
        """Ping an IP address"""
        if not ip_address:
            print("Usage: ping <ip_address>")
            return
            
        param = "-n" if platform.system().lower() == "windows" else "-c"
        count = "4"
        
        try:
            print(f"Pinging {ip_address}...")
            subprocess.run(["ping", param, count, ip_address], check=True)
        except subprocess.CalledProcessError:
            print(f"Could not ping {ip_address}")
        except Exception as e:
            print(f"Error: {e}")

    def netstat(self):
        """Display network statistics"""
        try:
            subprocess.run(["netstat", "-ano"] if platform.system().lower() == "windows" else ["netstat", "-tuln"], check=True)
        except Exception as e:
            print(f"Error executing netstat: {e}")

    def ifconfig(self, *args):
        """Display network interface configuration"""
        if platform.system().lower() == "windows":
            self.execute_system_command("ipconfig " + " ".join(args))
        else:
            self.execute_system_command("ifconfig " + " ".join(args))

    def netsh(self, *args):
        """Execute netsh commands (Windows only)"""
        if platform.system().lower() != "windows":
            print("netsh is only available on Windows")
            return
            
        try:
            subprocess.run(["netsh"] + list(args), check=True)
        except Exception as e:
            print(f"Error executing netsh: {e}")

    def net_command(self, *args):
        """Execute NET commands (Windows only)"""
        if platform.system().lower() != "windows":
            print("NET commands are only available on Windows")
            return
            
        if not args:
            print("Usage: net <command> [args]")
            print("Available NET commands:")
            print("  ACCOUNTS       HELPMSG        STATISTICS")
            print("  COMPUTER       LOCALGROUP     STOP")
            print("  CONFIG         PAUSE          TIME")
            print("  CONTINUE       SESSION        USE")
            print("  FILE           SHARE          USER")
            print("  GROUP          START          VIEW")
            print("  HELP")
            return
            
        try:
            subprocess.run(["net"] + list(args), check=True)
        except Exception as e:
            print(f"Error executing NET command: {e}")

    def start_monitoring(self, ip_address=None):
        """Start network monitoring"""
        if self.monitor.running:
            print("Monitoring is already running")
            return
            
        if ip_address:
            self.monitor.target_ip = ip_address
            
        if self.monitor.start_monitoring():
            print(f"Started monitoring on interface {self.monitor.interface}" + 
                 (f" for target IP {self.monitor.target_ip}" if self.monitor.target_ip else ""))
        else:
            print("Failed to start monitoring")

    def stop_monitoring(self):
        """Stop network monitoring"""
        if not self.monitor.running:
            print("Monitoring is not running")
            return
            
        if self.monitor.stop_monitoring():
            print("Stopped monitoring")
        else:
            print("Failed to stop monitoring")

    def show_stats(self):
        """Show monitoring statistics"""
        if not self.monitor.stats["start_time"]:
            print("Monitoring has not been started")
            return
            
        stats = self.monitor.get_network_stats()
        print("\nNetwork Monitoring Statistics:")
        print(f"Monitoring duration: {stats['monitoring_time']}")
        print(f"Total packets: {stats['total_packets']}")
        print(f"IP packets: {stats['ip_packets']}")
        print(f"TCP packets: {stats['tcp_packets']}")
        print(f"UDP packets: {stats['udp_packets']}")
        print(f"ICMP packets: {stats['icmp_packets']}")
        print(f"Other packets: {stats['other_packets']}")
        print(f"Threats detected: {stats['threats_detected']}")
        
        if stats['threats_detected'] > 0:
            print("\nThreat breakdown:")
            for threat, count in stats['threat_breakdown'].items():
                print(f"  {threat.upper()}: {count}")

    def show_threats(self):
        """Show detected threats"""
        if not self.monitor.threat_count:
            print("No threats detected")
            return
            
        print("\nDetected Threats:")
        for threat, count in self.monitor.threat_count.items():
            desc = THREAT_SIGNATURES.get(threat, {}).get("description", "Unknown threat")
            print(f"  {threat.upper()} ({desc}): {count}")

    def whois(self, ip_address=None):
        """Perform WHOIS lookup"""
        if not ip_address:
            print("Usage: whois <ip_address>")
            return
            
        try:
            info = self.monitor.get_whois_info(ip_address)
            if not info:
                print("No WHOIS information available")
                return
                
            print(f"\nWHOIS information for {ip_address}:")
            print(f"ASN: {info.get('asn', 'N/A')}")
            print(f"ASN Description: {info.get('asn_description', 'N/A')}")
            print(f"Network: {info.get('network', 'N/A')}")
            print(f"CIDR: {info.get('cidr', 'N/A')}")
        except Exception as e:
            print(f"Error performing WHOIS lookup: {e}")

    def geo_lookup(self, ip_address=None):
        """Perform geographical IP lookup"""
        if not ip_address:
            print("Usage: geo <ip_address>")
            return
            
        try:
            geo_info = self.monitor.get_geo_info(ip_address)
            if not geo_info:
                print("No geographical information available")
                return
                
            print(f"\nGeographical information for {ip_address}:")
            print(f"Country: {geo_info.get('country', 'N/A')}")
            print(f"City: {geo_info.get('city', 'N/A')}")
            print(f"Latitude: {geo_info.get('latitude', 'N/A')}")
            print(f"Longitude: {geo_info.get('longitude', 'N/A')}")
        except Exception as e:
            print(f"Error performing geo lookup: {e}")

    def execute_system_command(self, command):
        """Execute a system command"""
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with exit code {e.returncode}")
        except Exception as e:
            print(f"Error executing command: {e}")

    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if platform.system().lower() == 'windows' else 'clear')

    def exit_terminal(self):
        """Exit the terminal"""
        if self.monitor.running:
            self.monitor.stop_monitoring()
        print("Exiting CyberShield NIDS Terminal")
        sys.exit(0)

class CyberShieldGUI(tk.Tk):
    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor
        self.title(f"Accurate Cyber Defense Advanced Monitoring System v{VERSION}")
        self.geometry("1200x800")
        self.configure(bg="black")
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background='black', foreground='green', font=('Courier', 10))
        self.style.configure('TFrame', background='black')
        self.style.configure('TLabel', background='black', foreground='green')
        self.style.configure('TButton', background='black', foreground='green', 
                           bordercolor='green', lightcolor='black', darkcolor='black')
        self.style.configure('TEntry', fieldbackground='black', foreground='green')
        self.style.configure('TCombobox', fieldbackground='black', foreground='green')
        self.style.map('TButton', background=[('active', 'green'), ('disabled', 'gray')],
                      foreground=[('active', 'black'), ('disabled', 'gray')])
        
        # Create main frames
        self.create_widgets()
        
        # Start update thread
        self.update_thread = threading.Thread(target=self.update_gui, daemon=True)
        self.update_thread.start()
        
        # Bind close event
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_widgets(self):
        """Create GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel (controls and info)
        left_frame = ttk.Frame(main_frame, width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        left_frame.pack_propagate(False)
        
        # Right panel (terminal and stats)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create left panel widgets
        self.create_left_panel(left_frame)
        
        # Create right panel widgets
        self.create_right_panel(right_frame)

    def create_left_panel(self, parent):
        """Create widgets in the left panel"""
        # Monitoring control frame
        control_frame = ttk.LabelFrame(parent, text="Monitoring Controls")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Target IP
        ttk.Label(control_frame, text="Target IP:").pack(anchor=tk.W)
        self.target_ip_entry = ttk.Entry(control_frame)
        self.target_ip_entry.pack(fill=tk.X, padx=5, pady=2)
        
        # Interface selection
        ttk.Label(control_frame, text="Network Interface:").pack(anchor=tk.W)
        self.interface_combo = ttk.Combobox(control_frame, state="readonly")
        self.interface_combo.pack(fill=tk.X, padx=5, pady=2)
        self.update_interface_list()
        
        # Buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        self.start_button = ttk.Button(button_frame, text="Start", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=2, expand=True)
        
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=2, expand=True)
        
        # Network info frame
        info_frame = ttk.LabelFrame(parent, text="Network Information")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.info_text = scrolledtext.ScrolledText(info_frame, bg="black", fg="green", 
                                                 insertbackground="green", wrap=tk.WORD)
        self.info_text.pack(fill=tk.BOTH, expand=True)
        self.update_network_info()
        
        # Quick commands frame
        cmd_frame = ttk.LabelFrame(parent, text="Quick Commands")
        cmd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        cmd_buttons = [
            ("Ping", self.run_ping),
            ("Netstat", self.run_netstat),
            ("Ifconfig", self.run_ifconfig),
            ("Threats", self.show_threats),
            ("Stats", self.show_stats)
        ]
        
        for i, (text, cmd) in enumerate(cmd_buttons):
            btn = ttk.Button(cmd_frame, text=text, command=cmd)
            btn.grid(row=i//3, column=i%3, padx=2, pady=2, sticky=tk.EW)
            
        for i in range(3):
            cmd_frame.grid_columnconfigure(i, weight=1)

    def create_right_panel(self, parent):
        """Create widgets in the right panel"""
        # Terminal frame
        terminal_frame = ttk.LabelFrame(parent, text="Terminal")
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.terminal_text = scrolledtext.ScrolledText(terminal_frame, bg="black", fg="green", 
                                                     insertbackground="green", wrap=tk.WORD)
        self.terminal_text.pack(fill=tk.BOTH, expand=True)
        
        # Redirect stdout to terminal
        sys.stdout = TextRedirector(self.terminal_text, "stdout")
        sys.stderr = TextRedirector(self.terminal_text, "stderr")
        
        # Command entry
        cmd_entry_frame = ttk.Frame(terminal_frame)
        cmd_entry_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(cmd_entry_frame, text="Command:").pack(side=tk.LEFT)
        self.cmd_entry = ttk.Entry(cmd_entry_frame)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.cmd_entry.bind("<Return>", self.execute_command)
        
        self.cmd_button = ttk.Button(cmd_entry_frame, text="Execute", command=self.execute_command)
        self.cmd_button.pack(side=tk.LEFT)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(parent, text="Live Statistics")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Create a figure for the live chart
        self.figure = plt.Figure(figsize=(6, 3), dpi=100, facecolor='black')
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor('black')
        self.ax.tick_params(colors='green')
        for spine in self.ax.spines.values():
            spine.set_color('green')
            
        self.chart = FigureCanvasTkAgg(self.figure, stats_frame)
        self.chart.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initialize chart data
        self.chart_data = {
            "time": [],
            "packets": [],
            "threats": []
        }

    def update_interface_list(self):
        """Update the list of available network interfaces"""
        interfaces = netifaces.interfaces()
        self.interface_combo["values"] = interfaces
        if interfaces:
            self.interface_combo.set(self.monitor.interface)

    def update_network_info(self):
        """Update network information display"""
        info = self.monitor.get_interface_info()
        self.info_text.delete(1.0, tk.END)
        
        for iface, details in info.items():
            self.info_text.insert(tk.END, f"{iface}:\n")
            self.info_text.insert(tk.END, f"  MAC: {details.get('mac', 'N/A')}\n")
            self.info_text.insert(tk.END, f"  IPv4: {details.get('ipv4', 'N/A')}\n")
            self.info_text.insert(tk.END, f"  Netmask: {details.get('netmask', 'N/A')}\n")
            self.info_text.insert(tk.END, f"  Broadcast: {details.get('broadcast', 'N/A')}\n\n")

    def start_monitoring(self):
        """Start network monitoring"""
        target_ip = self.target_ip_entry.get().strip() or None
        interface = self.interface_combo.get()
        
        self.monitor.target_ip = target_ip
        self.monitor.interface = interface
        
        if self.monitor.start_monitoring():
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            print(f"Started monitoring on interface {interface}" + 
                 (f" for target IP {target_ip}" if target_ip else ""))

    def stop_monitoring(self):
        """Stop network monitoring"""
        if self.monitor.stop_monitoring():
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            print("Stopped monitoring")

    def run_ping(self):
        """Run ping command"""
        target_ip = self.target_ip_entry.get().strip()
        if not target_ip:
            messagebox.showwarning("Input Error", "Please enter a target IP address")
            return
            
        threading.Thread(target=self.execute_ping, args=(target_ip,), daemon=True).start()

    def execute_ping(self, ip_address):
        """Execute ping command in a thread"""
        param = "-n" if platform.system().lower() == "windows" else "-c"
        count = "4"
        
        try:
            print(f"Pinging {ip_address}...")
            subprocess.run(["ping", param, count, ip_address], check=True)
        except subprocess.CalledProcessError:
            print(f"Could not ping {ip_address}")
        except Exception as e:
            print(f"Error: {e}")

    def run_netstat(self):
        """Run netstat command"""
        threading.Thread(target=self.execute_netstat, daemon=True).start()

    def execute_netstat(self):
        """Execute netstat command in a thread"""
        try:
            subprocess.run(["netstat", "-ano"] if platform.system().lower() == "windows" 
                          else ["netstat", "-tuln"], check=True)
        except Exception as e:
            print(f"Error executing netstat: {e}")

    def run_ifconfig(self):
        """Run ifconfig/ipconfig command"""
        threading.Thread(target=self.execute_ifconfig, daemon=True).start()

    def execute_ifconfig(self):
        """Execute ifconfig/ipconfig command in a thread"""
        if platform.system().lower() == "windows":
            self.execute_system_command("ipconfig /all")
        else:
            self.execute_system_command("ifconfig")

    def show_threats(self):
        """Show detected threats"""
        if not self.monitor.threat_count:
            print("No threats detected")
            return
            
        print("\nDetected Threats:")
        for threat, count in self.monitor.threat_count.items():
            desc = THREAT_SIGNATURES.get(threat, {}).get("description", "Unknown threat")
            print(f"  {threat.upper()} ({desc}): {count}")

    def show_stats(self):
        """Show monitoring statistics"""
        if not self.monitor.stats["start_time"]:
            print("Monitoring has not been started")
            return
            
        stats = self.monitor.get_network_stats()
        print("\nNetwork Monitoring Statistics:")
        print(f"Monitoring duration: {stats['monitoring_time']}")
        print(f"Total packets: {stats['total_packets']}")
        print(f"IP packets: {stats['ip_packets']}")
        print(f"TCP packets: {stats['tcp_packets']}")
        print(f"UDP packets: {stats['udp_packets']}")
        print(f"ICMP packets: {stats['icmp_packets']}")
        print(f"Other packets: {stats['other_packets']}")
        print(f"Threats detected: {stats['threats_detected']}")
        
        if stats['threats_detected'] > 0:
            print("\nThreat breakdown:")
            for threat, count in stats['threat_breakdown'].items():
                print(f"  {threat.upper()}: {count}")

    def execute_command(self, event=None):
        """Execute terminal command"""
        command = self.cmd_entry.get().strip()
        if not command:
            return
            
        self.cmd_entry.delete(0, tk.END)
        print(f"\nCyberShield> {command}")
        
        # Process the command in a separate thread to avoid freezing the GUI
        threading.Thread(target=self.process_command, args=(command,), daemon=True).start()

    def process_command(self, command):
        """Process terminal command"""
        terminal = CyberShieldTerminal(self.monitor)
        terminal.process_command(command)

    def execute_system_command(self, command):
        """Execute a system command"""
        try:
            result = subprocess.run(command, shell=True, check=True, 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with exit code {e.returncode}")
            if e.stdout:
                print(e.stdout)
            if e.stderr:
                print(e.stderr)
        except Exception as e:
            print(f"Error executing command: {e}")

    def update_gui(self):
        """Update GUI elements periodically"""
        while True:
            try:
                # Update stats chart
                if self.monitor.running:
                    self.update_chart()
                    
                # Update monitoring status
                if self.monitor.running:
                    self.start_button.config(state=tk.DISABLED)
                    self.stop_button.config(state=tk.NORMAL)
                else:
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    
                # Keep terminal scrolled to bottom
                self.terminal_text.see(tk.END)
                
            except Exception as e:
                logger.error(f"GUI update error: {e}")
                
            time.sleep(1)

    def update_chart(self):
        """Update the statistics chart"""
        stats = self.monitor.get_network_stats()
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Add new data point
        self.chart_data["time"].append(current_time)
        self.chart_data["packets"].append(stats["total_packets"])
        self.chart_data["threats"].append(stats["threats_detected"])
        
        # Limit data points to 20
        if len(self.chart_data["time"]) > 20:
            for key in self.chart_data:
                self.chart_data[key] = self.chart_data[key][-20:]
        
        # Update chart
        self.ax.clear()
        self.ax.plot(self.chart_data["time"], self.chart_data["packets"], 'g-', label="Packets")
        self.ax.plot(self.chart_data["time"], self.chart_data["threats"], 'r-', label="Threats")
        self.ax.set_title("Network Activity", color='green')
        self.ax.set_xlabel("Time", color='green')
        self.ax.set_ylabel("Count", color='green')
        self.ax.legend()
        self.ax.tick_params(axis='x', rotation=45)
        
        # Set colors
        self.ax.set_facecolor('black')
        for spine in self.ax.spines.values():
            spine.set_color('green')
            
        self.chart.draw()

    def on_close(self):
        """Handle window close event"""
        if self.monitor.running:
            self.monitor.stop_monitoring()
        self.destroy()
        sys.exit(0)

class TextRedirector:
    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag

    def write(self, str):
        self.widget.configure(state="normal")
        self.widget.insert("end", str, (self.tag,))
        self.widget.configure(state="disabled")

    def flush(self):
        pass

def main():
    """Main function"""
    # Initialize network monitor
    monitor = NetworkMonitor()
    
    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] in ("-t", "--terminal"):
            # Run in terminal mode
            terminal = CyberShieldTerminal(monitor)
            terminal.run()
        elif sys.argv[1] in ("-h", "--help"):
            print(f"CyberShield NIDS v{VERSION}")
            print("Usage:")
            print("  python cybershield.py          - Start in GUI mode")
            print("  python cybershield.py -t       - Start in terminal mode")
            print("  python cybershield.py -h       - Show this help")
            return
    else:
        # Run in GUI mode
        app = CyberShieldGUI(monitor)
        app.mainloop()

if __name__ == "__main__":
    main()