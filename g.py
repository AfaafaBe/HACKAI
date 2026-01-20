import time
import random
import subprocess
import sys
from getpass import getpass

class HackingSimulator:
    def __init__(self):
        self.admin_user = "afaafabe"
        self.admin_pass = "afaafabe"
        self.current_user = None
        self.logged_in = False
        self.is_admin = False
        self.connected_servers = []
        
    def clear_screen(self):
        """Efface l'écran"""
        print("\033c", end="")
    
    def typewriter_effect(self, text, delay=0.03):
        """Effet machine à écrire"""
        for char in text:
            print(char, end='', flush=True)
            time.sleep(delay)
        print()
    
    def simulate_loading(self, seconds=1, message="Chargement"):
        """Simule un chargement"""
        print(f"\n{message}", end="")
        for _ in range(3):
            for _ in range(3):
                print(".", end="", flush=True)
                time.sleep(seconds/6)
            print("\b\b\b   \b\b\b", end="", flush=True)
        print(f"\n{message}... Terminé!")
        time.sleep(0.5)
    
    def print_banner(self):
        """Affiche la bannière"""
        banner = """
╔══════════════════════════════════════════════════════════╗
║                 PORTAL ACCESS INTERFACE                  ║
║               SECURE ADMINISTRATION PORTAL               ║
╚══════════════════════════════════════════════════════════╝
"""
        print(banner)
    
    def login(self):
        """Interface de connexion"""
        self.clear_screen()
        self.print_banner()
        
        print("\n" + "═" * 60)
        self.typewriter_effect("[SYSTEM] Initializing secure connection...")
        self.simulate_loading(0.8)
        
        attempts = 0
        while attempts < 3:
            print("\n" + "─" * 40)
            print(" AUTHENTICATION REQUIRED")
            print("─" * 40)
            
            username = input("Username: ").strip()
            password = getpass("Password: ").strip()
            
            self.typewriter_effect("[SYSTEM] Verifying credentials...")
            time.sleep(1.2)
            
            if username == self.admin_user and password == self.admin_pass:
                self.typewriter_effect("[SUCCESS] Authentication successful!")
                self.typewriter_effect(f"[SYSTEM] Welcome back, {username}")
                self.current_user = username
                self.logged_in = True
                self.is_admin = True
                time.sleep(1)
                return True
            else:
                attempts += 1
                self.typewriter_effect(f"[ERROR] Invalid credentials. Attempt {attempts}/3")
                time.sleep(0.8)
        
        self.typewriter_effect("[CRITICAL] Maximum login attempts exceeded!")
        self.typewriter_effect("[SYSTEM] Locking system...")
        time.sleep(2)
        return False
    
    def admin_panel(self):
        """Panneau d'administration"""
        if not self.logged_in or not self.is_admin:
            return
        
        self.clear_screen()
        self.print_banner()
        print("\n" + "═" * 60)
        self.typewriter_effect(f"[SYSTEM] Initializing admin session for {self.current_user}")
        self.simulate_loading(1)
        
        self.typewriter_effect("\n╔════════════════════════════════════════════════╗")
        self.typewriter_effect("║            BIENVENU DANS HACKAI                ║")
        self.typewriter_effect("║                by Gael                         ║")
        self.typewriter_effect("╚════════════════════════════════════════════════╝")
        time.sleep(1)
        
        while True:
            print("\n" + "─" * 60)
            print("ADMIN PANEL - NETWORK SECURITY SUITE")
            print("─" * 60)
            print("1. User Management")
            print("2. Network Scanner")
            print("3. Vulnerability Assessment")
            print("4. Remote Access")
            print("5. System Audit")
            print("6. View Connected Servers")
            print("7. Exit")
            print("─" * 60)
            
            choice = input("\nHACKAI> ").strip()
            
            if choice == "1":
                self.user_management()
            elif choice == "2":
                self.network_scanner()
            elif choice == "3":
                self.vulnerability_assessment()
            elif choice == "4":
                self.remote_access()
            elif choice == "5":
                self.system_audit()
            elif choice == "6":
                self.view_servers()
            elif choice == "7":
                self.typewriter_effect("[SYSTEM] Logging out...")
                time.sleep(1)
                break
            else:
                self.typewriter_effect("[ERROR] Invalid command")
    
    def user_management(self):
        """Gestion des utilisateurs AD"""
        print("\n" + "─" * 50)
        self.typewriter_effect("[MODULE] Active Directory Management Tool")
        print("─" * 50)
        
        ad_user = input("Enter AD Username: ").strip()
        
        if ad_user.lower() == "pencq.ss":
            self.typewriter_effect(f"[SYSTEM] Querying user: {ad_user}")
            self.simulate_loading(1.2)
            
            self.typewriter_effect("[INFO] User found: pencq.ss")
            self.typewriter_effect("[INFO] Privilege Level: Domain Administrator")
            self.typewriter_effect("[INFO] Last login: Today 14:32:18")
            self.typewriter_effect("[INFO] Status: Active")
            
            print("\n[COMMANDS AVAILABLE]:")
            print("adduser <username> - Add new user")
            print("resetpass <username> - Reset password")
            print("enable <username> - Enable user account")
            print("disable <username> - Disable user account")
            print("priv <username> <level> - Set privilege level")
            
            while True:
                cmd = input(f"\nAD-MGMT[{ad_user}]> ").strip().lower()
                
                if cmd.startswith("adduser"):
                    user = cmd.split()[1] if len(cmd.split()) > 1 else "newuser"
                    self.typewriter_effect(f"[PROCESS] Creating user: {user}")
                    self.simulate_loading(1)
                    self.typewriter_effect(f"[SUCCESS] User {user} created successfully")
                    
                elif cmd.startswith("resetpass"):
                    self.typewriter_effect("[SYSTEM] Generating secure password...")
                    self.simulate_loading(0.8)
                    self.typewriter_effect("[INFO] New password: MLKJmlkj****9876")
                    self.typewriter_effect("[SUCCESS] Password reset successful")
                    
                elif cmd.startswith("enable"):
                    self.typewriter_effect("[SYSTEM] Enabling account...")
                    self.simulate_loading(0.7)
                    self.typewriter_effect("[SUCCESS] Account enabled")
                    
                elif cmd.startswith("disable"):
                    self.typewriter_effect("[SYSTEM] Disabling account...")
                    self.simulate_loading(0.7)
                    self.typewriter_effect("[SUCCESS] Account disabled")
                    
                elif cmd.startswith("priv"):
                    self.typewriter_effect("[SYSTEM] Elevating privileges...")
                    self.simulate_loading(1)
                    self.typewriter_effect("[SUCCESS] Privilege escalation successful!")
                    self.typewriter_effect("[INFO] User now has Domain Admin rights")
                    
                elif cmd == "exit":
                    break
                elif cmd == "":
                    continue
                else:
                    self.typewriter_effect("[ERROR] Command not recognized")
        else:
            self.typewriter_effect(f"[ERROR] User {ad_user} not found in AD")
    
    def network_scanner(self):
        """Simulation de scan Nmap"""
        print("\n" + "─" * 50)
        self.typewriter_effect("[MODULE] Nmap Network Security Scanner")
        print("─" * 50)
        
        target = input("Target IP/Range: ").strip()
        
        self.typewriter_effect(f"[SCAN] Starting Nmap scan against {target}")
        self.typewriter_effect("[INFO] Initializing packet injection module...")
        self.simulate_loading(1.5)
        
        print("\n[SCAN RESULTS]:")
        print(f"Scan report for {target}")
        print("Host is up (0.023s latency).")
        print("\nPORT     STATE    SERVICE      VERSION")
        print("22/tcp   open     ssh          OpenSSH 8.2p1")
        print("80/tcp   open     http         Apache 2.4.41")
        print("443/tcp  open     ssl/https    Apache 2.4.41")
        print("3389/tcp open     ms-wbt-server")
        print("5985/tcp open     http         Microsoft HTTPAPI")
        print("\n[INFO] 5 ports open, 995 ports filtered")
        
        time.sleep(2)
    
    def vulnerability_assessment(self):
        """Simulation de scan Nessus"""
        print("\n" + "─" * 50)
        self.typewriter_effect("[MODULE] Nessus Vulnerability Scanner")
        print("─" * 50)
        
        self.typewriter_effect("[SYSTEM] Loading vulnerability database...")
        self.simulate_loading(1.8)
        
        print("\n[VULNERABILITY ASSESSMENT]:")
        print("Critical (3):")
        print("  • CVE-2021-34527 - PrintNightmare RCE")
        print("  • CVE-2021-1675 - Windows Print Spooler Elevation")
        print("  • CVE-2020-1472 - Netlogon EoP (Zerologon)")
        
        print("\nHigh (7):")
        print("  • CVE-2019-0708 - BlueKeep RCE")
        print("  • CVE-2017-0144 - EternalBlue")
        print("  • Weak TLS/SSL configurations")
        
        print("\nMedium (12):")
        print("  • Default credentials on network devices")
        print("  • Outdated software versions")
        
        self.typewriter_effect("\n[RECOMMENDATION] Apply patches immediately!")
        time.sleep(2)
    
    def remote_access(self):
        """Simulation de connexion RDP"""
        print("\n" + "─" * 50)
        self.typewriter_effect("[MODULE] Remote Desktop Protocol Client")
        print("─" * 50)
        
        target_ip = input("Target Server IP: ").strip()
        
        if not target_ip:
            self.typewriter_effect("[ERROR] IP address required")
            return
        
        self.typewriter_effect(f"[SYSTEM] Initializing RDP connection to {target_ip}")
        self.typewriter_effect("[INFO] Using alternative: xfreerdp (Linux compatibility)")
        
        username = "pencq.ss"
        password = "MLKJmlkj****9876"
        
        print(f"\n[CONNECTION PARAMETERS]:")
        print(f"Server: {target_ip}")
        print(f"Username: {username}")
        print(f"Password: {'*' * 12}")
        print(f"Port: 3389")
        
        confirm = input("\nProceed with connection? (y/n): ").strip().lower()
        
        if confirm == 'y':
            self.typewriter_effect("[SYSTEM] Establishing secure tunnel...")
            self.simulate_loading(2)
            
            self.typewriter_effect("[SUCCESS] Authentication successful!")
            self.typewriter_effect(f"[INFO] Connected to {target_ip} as {username}")
            self.typewriter_effect("[SYSTEM] Session: DOMAIN\\pencq.ss (Administrator)")
            
            self.connected_servers.append({
                'ip': target_ip,
                'user': username,
                'access': 'Administrator',
                'timestamp': time.strftime("%H:%M:%S")
            })
            
            print("\n[REMOTE SESSION ACTIVE]")
            print("Type 'exit' to disconnect")
            
            while True:
                cmd = input(f"\nRDP[{target_ip}]> ").strip().lower()
                
                if cmd == "whoami":
                    self.typewriter_effect("DOMAIN\\pencq.ss")
                elif cmd == "hostname":
                    self.typewriter_effect(f"SERVER-{target_ip.replace('.', '-')}")
                elif cmd == "net user":
                    self.typewriter_effect("Administrator            Guest")
                elif cmd == "exit":
                    self.typewriter_effect("[SYSTEM] Closing RDP session...")
                    time.sleep(0.8)
                    break
                elif cmd:
                    self.typewriter_effect(f"[EXECUTE] {cmd}")
                    self.simulate_loading(0.5)
                    self.typewriter_effect("[SUCCESS] Command executed")
                else:
                    continue
        else:
            self.typewriter_effect("[INFO] Connection cancelled")
    
    def system_audit(self):
        """Simulation d'audit système"""
        print("\n" + "─" * 50)
        self.typewriter_effect("[MODULE] System Security Audit")
        print("─" * 50)
        
        self.typewriter_effect("[SYSTEM] Collecting system information...")
        self.simulate_loading(1.5)
        
        print("\n[AUDIT RESULTS]:")
        print("System: Windows Server 2019 Standard")
        print("Domain: CORP.DOMAIN.LOCAL")
        print("Users with Admin rights: 3")
        print("Last patch: 45 days ago")
        print("Firewall: Enabled")
        print("AV Status: Outdated")
        print("UAC: Disabled (CRITICAL)")
        print("SMB Signing: Not required")
        
        self.typewriter_effect("\n[SECURITY SCORE]: 4.2/10")
        time.sleep(2)
    
    def view_servers(self):
        """Affiche les serveurs connectés"""
        if not self.connected_servers:
            self.typewriter_effect("[INFO] No active server connections")
            return
        
        print("\n" + "─" * 60)
        print("ACTIVE SERVER CONNECTIONS")
        print("─" * 60)
        print(f"{'IP Address':<20} {'Username':<15} {'Access':<15} {'Time':<10}")
        print("─" * 60)
        
        for server in self.connected_servers:
            print(f"{server['ip']:<20} {server['user']:<15} {server['access']:<15} {server['timestamp']:<10}")
    
    def run(self):
        """Lance le simulateur"""
        try:
            if self.login():
                self.admin_panel()
            else:
                self.typewriter_effect("\n[SYSTEM] Access denied. Terminating...")
                time.sleep(2)
        except KeyboardInterrupt:
            self.typewriter_effect("\n\n[SYSTEM] Session terminated by user")
        except Exception as e:
            self.typewriter_effect(f"\n[ERROR] System failure: {str(e)}")

if __name__ == "__main__":
    simulator = HackingSimulator()
    simulator.run()
