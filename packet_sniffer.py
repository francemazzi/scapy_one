from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
import logging
import subprocess
import re
import psutil

class PacketSniffer:
    def __init__(self, interface=None, packet_count=1):
        if interface is None:
            interfaces = get_if_list()
            if interfaces:
                if 'en0' in interfaces:
                    interface = 'en0'
                else:
                    preferred = [i for i in interfaces if i.startswith('en')]
                    interface = preferred[0] if preferred else [i for i in interfaces if i != 'lo0'][0]
            else:
                raise ValueError("Nessuna interfaccia di rete trovata")
        
        print(f"Interfacce disponibili: {get_if_list()}")
        print(f"Usando interfaccia: {interface}")
        self.interface = interface
        self.packet_count = packet_count
        
        # Abilita modalità promiscua
        try:
            conf.sniff_promisc = True
            subprocess.run(['sudo', 'ifconfig', self.interface, 'promisc'], check=True)
            print("Modalità promiscua abilitata")
        except Exception as e:
            print(f"Impossibile abilitare modalità promiscua: {e}")
        
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    

    def get_active_connections(self, target_ip=None):
        """Ottiene informazioni dettagliate sulle connessioni attive"""
        try:
            # Ottieni tutte le connessioni di rete
            connections_info = []
            
            # Usa lsof per ottenere informazioni sui processi
            cmd = ['sudo', 'lsof', '-i', '-n', '-P']
            if target_ip:
                cmd.extend(['-s', 'TCP:ESTABLISHED'])
            
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Analizza l'output di lsof
            for line in output.split('\n')[1:]:  # Salta l'header
                if not line:
                    continue
                    
                parts = line.split()
                if len(parts) < 8:
                    continue
                
                process_name = parts[0]
                pid = parts[1]
                user = parts[2]
                
                # Ottieni informazioni aggiuntive sul processo usando psutil
                try:
                    process = psutil.Process(int(pid))
                    created_time = process.create_time()
                    cpu_percent = process.cpu_percent(interval=0.1)
                    memory_info = process.memory_info()
                    
                    # Ottieni il percorso dell'eseguibile
                    try:
                        exe_path = process.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        exe_path = "Access Denied"
                        
                    # Verifica se è un'applicazione nota
                    app_name = "Unknown"
                    if "Google Chrome" in exe_path:
                        app_name = "Chrome"
                    elif "Firefox" in exe_path:
                        app_name = "Firefox"
                    elif "Safari" in exe_path:
                        app_name = "Safari"
                    elif "Notes" in exe_path:
                        app_name = "Notes"
                    elif "Cursor" in exe_path:
                        app_name = "Cursor"
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    created_time = 0
                    cpu_percent = 0
                    memory_info = None
                    exe_path = "N/A"
                    app_name = "Unknown"
                
                connection_info = {
                    'process_name': process_name,
                    'app_name': app_name,
                    'pid': pid,
                    'user': user,
                    'connection': parts[-1],
                    'exe_path': exe_path,
                    'created_time': created_time,
                    'cpu_percent': cpu_percent,
                    'memory_usage': memory_info.rss if memory_info else 0,
                    'state': 'ESTABLISHED' if 'ESTABLISHED' in line else 'UNKNOWN'
                }
                
                if target_ip is None or target_ip in parts[-1]:
                    connections_info.append(connection_info)
            
            return connections_info
            
        except Exception as e:
            print(f"Errore nell'ottenere le connessioni: {e}")
            return []

    def print_connection_details(self, connections):
        """Stampa i dettagli delle connessioni in formato leggibile"""
        if not connections:
            print("Nessuna connessione attiva trovata")
            return
            
        print("\nConnessioni di rete attive:")
        print("-" * 80)
        print(f"{'Applicazione':<20} {'Utente':<15} {'PID':<8} {'Connessione':<30} {'CPU %':<8} {'Memoria (MB)':<12}")
        print("-" * 80)
        
        for conn in connections:
            memory_mb = conn['memory_usage'] / (1024 * 1024)  # Converti in MB
            print(f"{conn['app_name']:<20} {conn['user']:<15} {conn['pid']:<8} "
                  f"{conn['connection']:<30} {conn['cpu_percent']:<8.1f} {memory_mb:<12.1f}")
        
        print("-" * 80)

    def sniff_packets(self, target_ip):
        """Analizza il traffico di rete per un IP specifico"""
        try:
            print(f"\nAnalisi traffico di rete per {target_ip}:")
            print("-" * 50)
            
            # Ottieni e analizza le connessioni attive
            active_connections = self.get_active_connections(target_ip)
            
            # Stampa i dettagli delle connessioni
            self.print_connection_details(active_connections)
            
            if not active_connections:
                # Prova a fare sniffing diretto dei pacchetti
                print("Nessuna connessione attiva trovata, avvio sniffing diretto...")
                packets = sniff(
                    iface=self.interface,
                    count=100,
                    filter=f"host {target_ip}",
                    timeout=15,
                    prn=lambda x: self._packet_callback(x)
                )
                
                if not packets:
                    print(f"Nessun traffico rilevato per {target_ip}")
                
                return {
                    "active_connections": [],
                    "packets": packets
                }
                
            # Raggruppa le connessioni per processo
            connections_by_process = {}
            for conn in active_connections:
                process = conn['process']
                if process not in connections_by_process:
                    connections_by_process[process] = []
                connections_by_process[process].append(conn)
            
            # Stampa le connessioni raggruppate
            for process, conns in connections_by_process.items():
                print(f"\nProcesso: {process}")
                for conn in conns:
                    print(f"└── Connesso a: {conn['connection']}")
            
            print("\nAvvio cattura pacchetti in tempo reale...")
            packets = sniff(
                iface=self.interface,
                count=100,
                filter=f"host {target_ip}",
                timeout=15,
                prn=lambda x: self._packet_callback(x)
            )
            
            return {
                "active_connections": active_connections,
                "packets": packets
            }
            
        except Exception as e:
            print(f"Errore durante lo sniffing: {e}")
            return {
                "active_connections": [],
                "packets": []
            }

    def _packet_callback(self, packet):
        """Callback per analizzare ogni pacchetto catturato"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                
                print(f"Pacchetto rilevato - Protocollo: {proto}")
                print(f"Sorgente: {src_ip} -> Destinazione: {dst_ip}")
                
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = packet[TCP].flags
                    
                    # Determina il tipo di traffico
                    service = ""
                    if dst_port == 80 or src_port == 80:
                        service = "HTTP"
                    elif dst_port == 443 or src_port == 443:
                        service = "HTTPS"
                    else:
                        service = f"TCP:{dst_port}"
                    
                    print(f"Connessione {service}: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [Flags: {flags}]")
                    print(f"TCP Flags: {packet[TCP].flags}")
                    print(f"TCP Payload Length: {len(packet[TCP].payload)}")
                
                # Analizza pacchetti UDP
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    
                    # Determina il tipo di servizio UDP comune
                    service = ""
                    if dst_port == 53 or src_port == 53:
                        service = "DNS"
                    elif dst_port == 67 or dst_port == 68:
                        service = "DHCP"
                    elif dst_port == 161 or dst_port == 162:
                        service = "SNMP"
                    else:
                        service = f"UDP:{dst_port}"
                    
                    print(f"Connessione {service}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"UDP Payload Length: {len(packet[UDP].payload)}")
                
                # Altri tipi di pacchetti IP
                else:
                    print(f"Altro traffico IP: {src_ip} -> {dst_ip} [{packet[IP].proto}]")

        except Exception as e:
            print(f"Errore nell'analisi del pacchetto: {e}")

    def scan_network(self):
        """Scansiona la rete per trovare dispositivi connessi"""
        try:
            # Ottieni l'IP dell'interfaccia
            interface_ip = get_if_addr(self.interface)
            if not interface_ip or interface_ip == "0.0.0.0":
                print(f"Nessun IP valido trovato su {self.interface}")
                return []
            
            # Ottieni l'IP base della rete (assumendo una subnet /24)
            network = '.'.join(interface_ip.split('.')[:-1]) + '.0/24'
            print(f"\nScansione della rete {network}...")
            print(f"Usando interfaccia {self.interface} ({interface_ip})")
            
            # Crea un pacchetto ARP request
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Invia il pacchetto e attendi le risposte
            print("Invio richieste ARP...")
            result = srp(packet, timeout=3, verbose=0, iface=self.interface)[0]
            
            # Analizza le risposte
            devices = []
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc
                })
                
            # Stampa i risultati
            print(f"\nDispositivi trovati: {len(devices)}")
            print("-" * 50)
            for device in devices:
                print(f"IP: {device['ip']:<15} MAC: {device['mac']}")
                
            return devices
            
        except Exception as e:
            print(f"Errore durante la scansione della rete: {e}")
            return []

        