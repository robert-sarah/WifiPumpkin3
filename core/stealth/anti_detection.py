#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module Anti-Détection
Masquage et furtivité avancée
"""

import os
import time
import random
import subprocess
import threading
from scapy.all import *

class AntiDetection:
    """Classe pour l'anti-détection et la furtivité"""
    
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.original_mac = None
        self.mac_rotation_thread = None
        
    def get_random_mac(self):
        """Génère une adresse MAC aléatoire"""
        # Préfixes d'entreprises légitimes
        prefixes = [
            "00:50:56",  # VMware
            "00:0C:29",  # VMware
            "00:1A:11",  # Google
            "00:16:3E",  # Xen
            "00:15:5D",  # Microsoft
            "00:05:69",  # VMware
            "00:1C:14",  # Dell
            "00:0D:60",  # Dell
            "00:1B:21",  # Dell
            "00:1E:C9",  # Dell
        ]
        
        prefix = random.choice(prefixes)
        mac_suffix = ":".join([f"{random.randint(0, 255):02X}" for _ in range(3)])
        return f"{prefix}:{mac_suffix}"
    
    def change_mac_address(self, interface, new_mac=None):
        """Change l'adresse MAC d'une interface"""
        try:
            if not new_mac:
                new_mac = self.get_random_mac()
            
            # Sauvegarde de l'adresse MAC originale
            if not self.original_mac:
                result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'ether' in line:
                        self.original_mac = line.split('ether')[1].strip()
                        break
            
            # Arrêt de l'interface
            subprocess.run(['ifconfig', interface, 'down'], capture_output=True)
            
            # Changement de l'adresse MAC
            subprocess.run(['ifconfig', interface, 'hw', 'ether', new_mac], capture_output=True)
            
            # Démarrage de l'interface
            subprocess.run(['ifconfig', interface, 'up'], capture_output=True)
            
            self.logger.log("INFO", f"Adresse MAC changée: {new_mac}")
            return True
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur changement MAC: {str(e)}")
            return False
    
    def restore_original_mac(self, interface):
        """Restaure l'adresse MAC originale"""
        if self.original_mac:
            self.change_mac_address(interface, self.original_mac)
            self.original_mac = None
    
    def start_mac_rotation(self, interface, interval=300):
        """Démarre la rotation automatique des adresses MAC"""
        self.running = True
        
        def rotate_mac():
            while self.running:
                try:
                    new_mac = self.get_random_mac()
                    self.change_mac_address(interface, new_mac)
                    time.sleep(interval)
                except Exception as e:
                    self.logger.log("ERROR", f"Erreur rotation MAC: {str(e)}")
        
        self.mac_rotation_thread = threading.Thread(target=rotate_mac)
        self.mac_rotation_thread.daemon = True
        self.mac_rotation_thread.start()
        
        self.logger.log("INFO", f"Rotation MAC démarrée (intervalle: {interval}s)")
    
    def stop_mac_rotation(self):
        """Arrête la rotation des adresses MAC"""
        self.running = False
        if self.mac_rotation_thread:
            self.mac_rotation_thread.join(timeout=2)
    
    def modify_packet_signatures(self, packet):
        """Modifie les signatures des paquets pour éviter la détection"""
        try:
            # Modification des TTL pour masquer l'OS
            if IP in packet:
                packet[IP].ttl = random.randint(64, 128)
            
            # Modification des fenêtres TCP
            if TCP in packet:
                packet[TCP].window = random.randint(1024, 65535)
            
            # Modification des options TCP
            if TCP in packet and packet[TCP].options:
                # Suppression des options qui peuvent révéler l'OS
                packet[TCP].options = []
            
            return packet
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur modification paquet: {str(e)}")
            return packet
    
    def add_noise_traffic(self, interface, duration=60):
        """Ajoute du trafic de bruit pour masquer les activités"""
        try:
            self.logger.log("INFO", "Génération de trafic de bruit")
            
            # Génération de paquets de bruit
            noise_packets = []
            
            # Paquets ICMP (ping)
            for i in range(10):
                noise_packet = IP(dst="8.8.8.8")/ICMP()
                noise_packets.append(noise_packet)
            
            # Paquets TCP vers des ports communs
            common_ports = [80, 443, 22, 21, 25, 53]
            for port in common_ports:
                noise_packet = IP(dst="8.8.8.8")/TCP(dport=port, flags="S")
                noise_packets.append(noise_packet)
            
            # Envoi des paquets de bruit
            for packet in noise_packets:
                send(packet, iface=interface, verbose=False)
                time.sleep(random.uniform(0.1, 0.5))
            
            self.logger.log("INFO", "Trafic de bruit généré")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur génération bruit: {str(e)}")
    
    def spoof_network_behavior(self, interface):
        """Spoof le comportement réseau pour paraître légitime"""
        try:
            # Simulation d'un client normal
            self.logger.log("INFO", "Spoof du comportement réseau")
            
            # Génération de requêtes DNS normales
            dns_queries = [
                "www.google.com",
                "www.facebook.com", 
                "www.youtube.com",
                "www.amazon.com",
                "www.github.com"
            ]
            
            for domain in dns_queries:
                dns_packet = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
                send(dns_packet, iface=interface, verbose=False)
                time.sleep(random.uniform(1, 3))
            
            # Génération de trafic HTTPS normal
            https_packet = IP(dst="8.8.8.8")/TCP(dport=443, flags="S")
            send(https_packet, iface=interface, verbose=False)
            
            self.logger.log("INFO", "Comportement réseau spoofé")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur spoof réseau: {str(e)}")
    
    def hide_process_activities(self):
        """Masque les activités des processus"""
        try:
            # Renommage des processus sensibles
            sensitive_processes = [
                "airodump-ng",
                "aircrack-ng", 
                "aireplay-ng",
                "dnsmasq",
                "dhcpd"
            ]
            
            for process in sensitive_processes:
                # Vérification si le processus existe
                result = subprocess.run(['pgrep', process], capture_output=True)
                if result.returncode == 0:
                    # Renommage temporaire
                    pid = result.stdout.decode().strip()
                    if pid:
                        # Modification du nom du processus (technique avancée)
                        try:
                            os.system(f"echo '{random.choice(['python', 'systemd', 'init'])}' > /proc/{pid}/comm")
                        except:
                            pass
            
            self.logger.log("INFO", "Activités des processus masquées")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur masquage processus: {str(e)}")
    
    def encrypt_logs(self, log_file):
        """Chiffre les logs sensibles"""
        try:
            if os.path.exists(log_file):
                # Chiffrement simple avec XOR (à améliorer)
                with open(log_file, 'rb') as f:
                    data = f.read()
                
                # Clé de chiffrement
                key = b'WIFIPUMPKIN3'
                
                # Chiffrement XOR
                encrypted_data = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
                
                # Sauvegarde chiffrée
                with open(f"{log_file}.enc", 'wb') as f:
                    f.write(encrypted_data)
                
                # Suppression du fichier original
                os.remove(log_file)
                
                self.logger.log("INFO", f"Logs chiffrés: {log_file}")
                
        except Exception as e:
            self.logger.log("ERROR", f"Erreur chiffrement logs: {str(e)}")
    
    def setup_stealth_mode(self, interface, enable_mac_rotation=True, enable_noise=True):
        """Configure le mode furtif complet"""
        try:
            self.logger.log("INFO", "Activation du mode furtif")
            
            # Rotation des adresses MAC
            if enable_mac_rotation:
                self.start_mac_rotation(interface)
            
            # Génération de trafic de bruit
            if enable_noise:
                self.add_noise_traffic(interface)
            
            # Spoof du comportement réseau
            self.spoof_network_behavior(interface)
            
            # Masquage des processus
            self.hide_process_activities()
            
            self.logger.log("INFO", "Mode furtif activé")
            return True
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur mode furtif: {str(e)}")
            return False
    
    def cleanup_stealth_mode(self, interface):
        """Nettoie le mode furtif"""
        try:
            # Arrêt de la rotation MAC
            self.stop_mac_rotation()
            
            # Restauration de l'adresse MAC originale
            self.restore_original_mac(interface)
            
            # Chiffrement des logs
            log_files = [
                '/tmp/captured_credentials.json',
                '/tmp/wifi_scan.log',
                '/tmp/attack.log'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    self.encrypt_logs(log_file)
            
            self.logger.log("INFO", "Mode furtif nettoyé")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur nettoyage furtif: {str(e)}") 