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

# Test della connessione
target_ip = "78.210.61.161"

print(f"\nVerifica connettività per {target_ip}:")
print("-" * 50)

# Verifica DNS inverso
try:
    hostname = socket.gethostbyaddr(target_ip)[0]
    print(f"Hostname: {hostname}")
except socket.herror as e:
    print(f"DNS inverso non disponibile: {e}")

# Test ping
if ping(target_ip):
    print(f"\nL'IP {target_ip} è raggiungibile")
    
    # Test porte comuni
    common_ports = [80, 443, 22, 21]
    print("\nVerifica porte comuni:")
    for port in common_ports:
        check_port(target_ip, port)
    
    # Sniffing pacchetti
    print("\nAvvio sniffing pacchetti...")
    sniffer = PacketSniffer()
    results = sniffer.sniff_packets(target_ip)
    print("\nRisultati:")
    print("Connessioni attive:", results["active_connections"])
    print("\nPacchetti catturati:", results["packets"])
else:
    print(f"\nL'IP {target_ip} non è raggiungibile")
    print("\nPossibili cause:")
    print("1. L'IP potrebbe essere bloccato dal firewall")
    print("2. L'host potrebbe essere offline")
    print("3. La rete potrebbe avere problemi di routing")
    print("4. I pacchetti ICMP (ping) potrebbero essere bloccati")