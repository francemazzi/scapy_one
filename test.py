from packet_sniffer import PacketSniffer
import subprocess
import platform
import socket


def ping(host):
    """Verifica se un host è raggiungibile"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]
    try:
        output = subprocess.check_output(command, universal_newlines=True)
        print("Output ping:", output)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Errore ping: {e}")
        return False

def check_port(ip, port):
    """Verifica se una porta specifica è aperta"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"Porta {port} è aperta")
            return True
        else:
            print(f"Porta {port} è chiusa")
            return False
    except socket.error as e:
        print(f"Errore connessione socket: {e}")
        return False
    finally:
        sock.close()

def get_current_ip():
    """Ottiene l'IP pubblico della connessione corrente"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        current_ip = s.getsockname()[0]
        s.close()
        return current_ip
    except Exception as e:
        print(f"Errore nel recupero dell'IP: {e}")
        return None

ip = get_current_ip()

# TEST 1

# Sostituisci la riga con l'IP hardcoded con questa
# target_ip = get_current_ip()
# if target_ip:
#     print(f"Il tuo IP corrente è: {target_ip}")
# else:
#     print("Non è stato possibile determinare l'IP")

# print(f"\nVerifica connettività per {target_ip}:")
# print("-" * 50)

# # Verifica DNS inverso
# try:
#     hostname = socket.gethostbyaddr(target_ip)[0]
#     print(f"Hostname: {hostname}")
# except socket.herror as e:
#     print(f"DNS inverso non disponibile: {e}")

# # Test ping
# if ping(target_ip):
#     print(f"\nL'IP {target_ip} è raggiungibile")
    
#     # Test porte comuni
#     common_ports = [80, 443, 22, 21]
#     print("\nVerifica porte comuni:")
#     for port in common_ports:
#         check_port(target_ip, port)
    
#     # Sniffing pacchetti
#     print("\nAvvio sniffing pacchetti...")
#     sniffer = PacketSniffer()
#     results = sniffer.sniff_packets(target_ip)
#     print("\nRisultati:")
#     print("Connessioni attive:", results["active_connections"])
#     print("\nPacchetti catturati:", results["packets"])
# else:
#     print(f"\nL'IP {target_ip} non è raggiungibile")
#     print("\nPossibili cause:")
#     print("1. L'IP potrebbe essere bloccato dal firewall")
#     print("2. L'host potrebbe essere offline")
#     print("3. La rete potrebbe avere problemi di routing")
#     print("4. I pacchetti ICMP (ping) potrebbero essere bloccati")


##TEST 2

sniffer = PacketSniffer(interface="en0")  # o l'interfaccia che vuoi usare
devices = sniffer.scan_network()

print("\nAnalisi del traffico per tutti i dispositivi trovati:")
print("-" * 50)
print(f"Devices: {devices}")


for device in devices:
    ip = device['ip']
    mac = device['mac']
   
    print(f"\nAnalisi traffico per {ip} ({mac}):")
    print("-" * 30)
    
    if ping(ip):
        results = sniffer.sniff_packets(ip)
        
        if "active_connections" in results and results["active_connections"]:
            connections_by_dest = {}
            for conn in results["active_connections"]:
                if '->' in conn['connection']:
                    src, dest = conn['connection'].split('->')
                    dest = dest.strip().split(':')[0]  
                    
                    if dest not in connections_by_dest:
                        connections_by_dest[dest] = []
                    connections_by_dest[dest].append(conn)
            
            # Stampa le connessioni raggruppate
            for dest, conns in connections_by_dest.items():
                print(f"\nConnessioni verso {dest}:")
                for conn in conns:
                    print(f"└── Processo: {conn['process']}")
                    if 'pid' in conn:
                        print(f"    └── PID: {conn['pid']}")
                    if 'user' in conn:
                        print(f"    └── Utente: {conn['user']}")
                    if 'state' in conn:
                        print(f"    └── Stato: {conn['state']}")
        else:
            print("Nessuna connessione attiva trovata")
    else:
        print(f"L'IP {ip} non è raggiungibile")
        print("Possibili cause:")
        print("1. L'IP potrebbe essere bloccato dal firewall")
        print("2. L'host potrebbe essere offline")
        print("3. La rete potrebbe avere problemi di routing")
        print("4. I pacchetti ICMP (ping) potrebbero essere bloccati")
    
# TEST 3
# sniffer = PacketSniffer(interface="en0")
# devices = sniffer.scan_network()

# print("\nAnalisi del traffico per tutti i dispositivi trovati:")
# print("-" * 50)

# for device in devices:
#     ip = device['ip']
#     mac = device['mac']
#     print(f"\nAnalisi traffico per {ip} ({mac}):")
#     print("-" * 30)
    
#     if ping(ip):
#         results = sniffer.sniff_packets(ip)
#         if not results["active_connections"] and not results["packets"]:
#             print(f"Nessun traffico rilevato per {ip}")
#     else:
#         print(f"L'IP {ip} non è raggiungibile")