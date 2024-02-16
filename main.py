from scapy.all import sniff
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import subprocess

def block_ip(ip_address):
    command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    subprocess.run(command, shell=True)
    print(f"Blocked IP: {ip_address}")

ip_counter = Counter()
connection_counter = defaultdict(int)
start_time = datetime.now()
reset_interval = timedelta(seconds=60)
threshold = 100
dynamic_threshold = defaultdict(lambda: 100)  

def adjust_threshold():
    global dynamic_threshold
    current_hour = datetime.now().hour
    
    if 18 <= current_hour <= 22:
        for ip in dynamic_threshold:
            dynamic_threshold[ip] = 200  
    else:
        for ip in dynamic_threshold:
            dynamic_threshold[ip] = 100  

def handle_packet(packet):
    global start_time
    if 'IP' in packet and ('UDP' in packet or 'TCP' in packet):
        ip_src = packet['IP'].src
        port_dst = packet['UDP'].dport if 'UDP' in packet else packet['TCP'].dport
        
        if port_dst == 2077:
            ip_counter[ip_src] += 1
            connection_counter[ip_src] += 1

            adjust_threshold()

            if datetime.now() - start_time > reset_interval:
                for ip, count in ip_counter.items():
                    if count > dynamic_threshold[ip]:
                        block_ip(ip)
                ip_counter.clear()
                connection_counter.clear()
                start_time = datetime.now()

sniff(prn=handle_packet, filter="tcp port 2077 or udp port 2077")
