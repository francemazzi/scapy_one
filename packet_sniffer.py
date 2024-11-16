from scapy.all import *
from scapy.layers.inet import IP, TCP
import logging
import subprocess
import re

class PacketSniffer:
    def __init__(self, interface=None, packet_count=1):
        if interface is None:
            interfaces = get_if_list()
            if interfaces:
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
        try:
            print(f"Avvio sniffing su interfaccia {self.interface} per IP {target_ip}")
            
            print("Cercando connessioni attive...")
            active_connections = self.get_active_connections(target_ip)
            print(f"Connessioni trovate: {active_connections}")
            
            print("Avvio cattura pacchetti...")
            packets = sniff(
                iface=self.interface,
                count=self.packet_count,
                filter=f"host {target_ip}",
                prn=lambda x: print(f"Pacchetto catturato: {x.summary()}")
            )
            
            results = {
                "active_connections": active_connections,
                "packets": []
            }
            
            if packets:
                for packet in packets:
                    if IP in packet:
                        packet_info = {
                            "source": packet[IP].src,
                            "destination": packet[IP].dst,
                            "protocol": packet.name,
                            "length": len(packet),
                            "time": packet.time,
                            "summary": packet.summary()
                        }
                        results["packets"].append(packet_info)
            
            return results
            
        except Exception as e:
            return {"error": f"Errore durante lo sniffing: {e}"}
        

        