import pyshark
from scapy.all import sniff, wrpcap
import argparse
import time
import os
from colorama import Fore, Style, init
from collections import defaultdict

class NetworkCompromiseAssessment:
    def __init__(self):
        init(autoreset=True)
        self.suspicious_keywords = ["password", "credential", "secret", "token"]  
        self.syn_counter = defaultdict(int)
        self.slowloris_counter = defaultdict(int)
        self.number_packet = 10  

    def save_to_file(self, message):
        with open("assessment_log.txt", "a") as log_file:
            log_file.write(message + "\n")

    def detect_suspicious_activity(self, packet):
        """
        Analyze a packet for suspicious activities and vulnerabilities.
        """
        
        if 'HTTP' in packet:
            if hasattr(packet.http, 'file_data'):
                for keyword in self.suspicious_keywords:
                    if keyword in packet.http.file_data.lower():
                        print(f"{Fore.RED}[!] Suspicious keyword found: '{keyword}' in packet from {packet.ip.src}{Style.RESET_ALL}")
                        self.save_to_file(f"Suspicious keyword '{keyword}' found in packet from {packet.ip.src}")

        
        if 'TCP' in packet and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
            self.syn_counter[packet.ip.src] += 1
            if self.syn_counter[packet.ip.src] > 50:  
                print(f"{Fore.RED}[!] Potential SYN flood attack from {packet.ip.src}{Style.RESET_ALL}")
                self.save_to_file(f"Potential SYN flood attack from {packet.ip.src}")

        
        if 'HTTP' in packet and hasattr(packet.http, 'request_method'):
            self.slowloris_counter[packet.ip.src] += 1
            if self.slowloris_counter[packet.ip.src] > 20:
                print(f"{Fore.RED}[!] Potential Slowloris attack from {packet.ip.src}{Style.RESET_ALL}")
                self.save_to_file(f"Potential Slowloris attack from {packet.ip.src}")

    def get_all_ip_addresses(self, capture):
        ip_addresses = set()
        for packet in capture:
            if hasattr(packet, 'ip'):
                ip_addresses.add(packet.ip.src)
        return ip_addresses

    def main(self):
        start_time = time.time()  

        
        print(f"{Fore.YELLOW}[+] Capturing network traffic...{Style.RESET_ALL}")
        live_capture_file = "live_capture.pcap"
        
        
        packets = sniff(count=self.number_packet, timeout=30)  
        
        
        wrpcap(live_capture_file, packets)
        print(f"{Fore.GREEN}[+] Live capture saved to: {live_capture_file}{Style.RESET_ALL}")

        
        capture = pyshark.FileCapture(live_capture_file, keep_packets=False)
        ip_addresses = self.get_all_ip_addresses(capture)

        
        for source_ip in ip_addresses:
            print(f"\n{Fore.CYAN}[+] Checking for IP address: {Style.RESET_ALL} {source_ip}")
            capture.reset()  
            for packet in capture:
                self.detect_suspicious_activity(packet)  

        end_time = time.time()
        elapsed_time = end_time - start_time
        msg = f"Scanning completed in {elapsed_time:.2f} seconds"
        print(msg)
        self.save_to_file(msg)  

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Compromise Assessment Tool")
    parser.add_argument('-n', '--number', type=int, default=10, help='Number of packets to capture')
    args = parser.parse_args()
    
    assessment = NetworkCompromiseAssessment()
    assessment.number_packet = args.number
    assessment.main()
