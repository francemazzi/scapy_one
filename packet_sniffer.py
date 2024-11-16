from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
import logging
import subprocess
import re

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
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    

    def get_active_connections(self, target_ip):
        try:
            output = subprocess.check_output(
                ['sudo', 'lsof', '-i', '-n'], 
                universal_newlines=True
            )
            
            connections = []
            for line in output.split('\n'):
                if target_ip in line and 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        connections.append({
                            'process': parts[0],
                            'pid': parts[1],
                            'user': parts[2],
                            'connection': parts[8],
                            'state': 'ESTABLISHED'
                        })
            
            return connections
            
        except Exception as e:
            return {"error": f"Errore nell'ottenere le connessioni: {e}"}

    def sniff_packets(self, target_ip):
        """Analizza il traffico di rete per un IP specifico"""
        try:
            print(f"\nAnalisi traffico di rete per {target_ip}:")
            print("-" * 50)
            
            # Ottieni e analizza le connessioni attive
            active_connections = self.get_active_connections(target_ip)
            
            if not active_connections:
                # Prova a fare sniffing diretto dei pacchetti
                print("Nessuna connessione attiva trovata, avvio sniffing diretto...")
                packets = sniff(
                    iface=self.interface,
                    count=self.packet_count,
                    filter=f"host {target_ip}",
                    timeout=5,  # Aggiungi un timeout di 5 secondi
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
                count=self.packet_count,
                filter=f"host {target_ip}",
                timeout=5,  # Aggiungi un timeout di 5 secondi
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
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Analizza pacchetti TCP
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
                
            # Altri tipi di pacchetti IP
            else:
                print(f"Altro traffico IP: {src_ip} -> {dst_ip} [{packet[IP].proto}]")

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

        