#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gestionnaire de réseau WiFi
Gère les interfaces, les scans et les configurations
"""

import os
import subprocess
import psutil
from scapy.all import *

# Import conditionnel de netifaces
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

class NetworkManager:
    """Gestionnaire des interfaces réseau"""
    
    def __init__(self):
        self.interfaces = self.get_wifi_interfaces()
        self.primary_interface = self.get_primary_interface()
        
    def get_wifi_interfaces(self):
        """Récupère la liste des interfaces WiFi"""
        wifi_interfaces = []
        
        # Détection Windows avec psutil (plus fiable)
        try:
            for interface in psutil.net_if_addrs():
                # Sur Windows, les interfaces WiFi ont souvent des noms spécifiques
                if any(keyword in interface.lower() for keyword in ['wi-fi', 'wireless', 'wlan', 'wifi']):
                    wifi_interfaces.append(interface)
                    
        except Exception as e:
            print(f"Erreur lors de la détection des interfaces WiFi: {str(e)}")
            
        # Fallback: utilisation de netsh pour Windows
        if not wifi_interfaces:
            try:
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                     capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Name' in line and ':' in line:
                            interface_name = line.split(':')[1].strip().strip('"')
                            if interface_name and not interface_name.startswith('Microsoft'):
                                wifi_interfaces.append(interface_name)
                                
            except Exception as e:
                print(f"Erreur lors de la détection des interfaces WiFi: {str(e)}")
                
        # Fallback: utilisation de iwconfig pour Linux
        if not wifi_interfaces:
            try:
                result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    current_interface = None
                    
                    for line in lines:
                        if line.strip() and not line.startswith(' '):
                            # Nouvelle interface
                            current_interface = line.split()[0]
                            if 'IEEE 802.11' in line or 'ESSID' in line:
                                wifi_interfaces.append(current_interface)
                                
            except Exception as e:
                print(f"Erreur lors de la détection des interfaces WiFi: {str(e)}")
                
        # Fallback: utilisation de netifaces si disponible
        if not wifi_interfaces and NETIFACES_AVAILABLE:
            try:
                for interface in netifaces.interfaces():
                    if interface.startswith(('wlan', 'wifi', 'ath')):
                        wifi_interfaces.append(interface)
            except:
                pass
        
        # Fallback: utilisation de psutil pour Windows
        if not wifi_interfaces:
            try:
                for interface in psutil.net_if_addrs():
                    if interface.startswith(('Wi-Fi', 'Wireless', 'wlan')):
                        wifi_interfaces.append(interface)
            except:
                pass
                
        return wifi_interfaces
        
    def get_primary_interface(self):
        """Récupère l'interface WiFi principale"""
        if self.interfaces:
            return self.interfaces[0]
        return None
        
    def get_interfaces(self):
        """Retourne la liste des interfaces WiFi"""
        return self.interfaces
        
    def scan_networks(self):
        """Scanne les réseaux WiFi disponibles"""
        networks = []
        
        if not self.primary_interface:
            return networks
            
        try:
            # Utilisation de iwlist pour scanner
            result = subprocess.run(['iwlist', self.primary_interface, 'scan'], 
                                 capture_output=True, text=True)
            
            if result.returncode == 0:
                networks = self.parse_scan_output(result.stdout)
            else:
                # Fallback avec airodump-ng
                networks = self.scan_with_airodump(self.primary_interface)
                
        except Exception as e:
            print(f"Erreur lors du scan: {str(e)}")
            # Dernier recours avec Scapy
            networks = self.scan_with_scapy(self.primary_interface)
            
        return networks
        
    def parse_scan_output(self, output):
        """Parse la sortie de iwlist scan"""
        networks = []
        lines = output.split('\n')
        
        current_network = {}
        
        for line in lines:
            line = line.strip()
            
            if 'Cell' in line and 'Address' in line:
                # Nouveau réseau
                if current_network:
                    networks.append(current_network)
                current_network = {}
                
                # Extraction du BSSID
                bssid = line.split('Address: ')[-1]
                current_network['bssid'] = bssid
                
            elif 'ESSID' in line:
                # SSID
                ssid = line.split('ESSID:')[1].strip().strip('"')
                current_network['ssid'] = ssid
                
            elif 'Channel' in line:
                # Canal
                channel = line.split('Channel:')[1].strip()
                current_network['channel'] = int(channel)
                
            elif 'Quality' in line and 'Signal' in line:
                # Puissance du signal
                signal = line.split('Signal level=')[1].split()[0]
                current_network['signal'] = signal
                
            elif 'Encryption key' in line:
                # Chiffrement
                encryption = 'WPA2' if 'on' in line else 'Open'
                current_network['encryption'] = encryption
                
        # Ajout du dernier réseau
        if current_network:
            networks.append(current_network)
            
        return networks
        
    def scan_with_airodump(self, interface):
        """Scan avec airodump-ng"""
        networks = []
        try:
            # Création du répertoire de sortie
            output_dir = '/tmp/wifi_scan'
            os.makedirs(output_dir, exist_ok=True)
            
            # Lancement d'airodump-ng
            cmd = [
                'airodump-ng',
                '--output-format', 'csv',
                '--write', f'{output_dir}/scan',
                '--write-interval', '1',
                interface
            ]
            
            # Démarrage du processus
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Attente de 10 secondes
            import time
            time.sleep(10)
            
            # Arrêt du processus
            process.terminate()
            process.wait()
            
            # Lecture des résultats
            csv_file = f'{output_dir}/scan-01.csv'
            if os.path.exists(csv_file):
                with open(csv_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                # Parsing des lignes
                for line in lines:
                    if line.strip() and ',' in line:
                        parts = line.split(',')
                        if len(parts) >= 15:
                            try:
                                network = {
                                    'ssid': parts[13].strip(),
                                    'bssid': parts[0].strip(),
                                    'channel': int(parts[3].strip()) if parts[3].strip().isdigit() else 0,
                                    'signal': parts[8].strip(),
                                    'encryption': parts[6].strip()
                                }
                                
                                # Filtrage des réseaux valides
                                if network['bssid'] and network['bssid'] != 'BSSID':
                                    networks.append(network)
                                    
                            except (ValueError, IndexError):
                                continue
                                
        except Exception as e:
            print(f"Erreur scan airodump: {str(e)}")
            
        return networks
    
    def scan_with_scapy(self, interface):
        """Scan avec Scapy en dernier recours"""
        networks = []
        try:
            # Mise en mode monitor
            self.set_monitor_mode(interface)
            
            # Fonction de callback pour capturer les beacons
            def beacon_handler(pkt):
                if pkt.haslayer(Dot11Beacon):
                    try:
                        # Extraction des informations du beacon
                        bssid = pkt[Dot11].addr2
                        ssid = None
                        channel = None
                        encryption = "Unknown"
                        
                        # Recherche du SSID
                        if pkt.haslayer(Dot11Elt):
                            for layer in pkt[Dot11Elt]:
                                if layer.ID == 0:  # SSID
                                    ssid = layer.info.decode('utf-8', errors='ignore')
                                elif layer.ID == 3:  # Channel
                                    channel = ord(layer.info)
                        
                        # Recherche du type d'encryption
                        if pkt.haslayer(Dot11Elt):
                            for layer in pkt[Dot11Elt]:
                                if layer.ID == 48:  # RSN
                                    encryption = "WPA2"
                                elif layer.ID == 221:  # Vendor specific
                                    if b'WPA' in layer.info:
                                        encryption = "WPA"
                        
                        # Création de l'entrée réseau
                        if ssid and bssid:
                            network = {
                                'ssid': ssid,
                                'bssid': bssid,
                                'channel': channel or 0,
                                'signal': 'N/A',
                                'encryption': encryption
                            }
                            
                            # Ajout si pas déjà présent
                            if not any(n['bssid'] == bssid for n in networks):
                                networks.append(network)
                                
                    except Exception as e:
                        pass
            
            # Capture des paquets pendant 10 secondes
            sniff(iface=interface, prn=beacon_handler, timeout=10, store=0)
            
        except Exception as e:
            print(f"Erreur scan Scapy: {str(e)}")
            
        return networks
        
    def set_monitor_mode(self, interface):
        """Met l'interface en mode monitor"""
        try:
            # Arrêt de l'interface
            subprocess.run(['ifconfig', interface, 'down'], 
                         capture_output=True, text=True)
            
            # Mise en mode monitor
            subprocess.run(['iwconfig', interface, 'mode', 'monitor'], 
                         capture_output=True, text=True)
            
            # Démarrage de l'interface
            subprocess.run(['ifconfig', interface, 'up'], 
                         capture_output=True, text=True)
            
            print(f"Interface {interface} mise en mode monitor")
            
        except Exception as e:
            print(f"Erreur lors de la mise en mode monitor: {str(e)}")
            raise
            
    def set_managed_mode(self, interface):
        """Remet l'interface en mode managed"""
        try:
            # Arrêt de l'interface
            subprocess.run(['ifconfig', interface, 'down'], 
                         capture_output=True, text=True)
            
            # Mise en mode managed
            subprocess.run(['iwconfig', interface, 'mode', 'managed'], 
                         capture_output=True, text=True)
            
            # Démarrage de l'interface
            subprocess.run(['ifconfig', interface, 'up'], 
                         capture_output=True, text=True)
            
            print(f"Interface {interface} remise en mode managed")
            
        except Exception as e:
            print(f"Erreur lors de la remise en mode managed: {str(e)}")
            
    def get_interface_info(self, interface):
        """Récupère les informations d'une interface"""
        try:
            result = subprocess.run(['iwconfig', interface], 
                                 capture_output=True, text=True)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return None
                
        except Exception as e:
            print(f"Erreur lors de la récupération des infos: {str(e)}")
            return None
            
    def get_connected_clients(self, interface):
        """Récupère la liste des clients connectés"""
        clients = []
        
        try:
            # Utilisation de airodump-ng pour détecter les clients
            result = subprocess.run(['airodump-ng', '--output-format', 'csv', 
                                   '--write', '/tmp/clients', interface], 
                                 capture_output=True, text=True, timeout=10)
            
            # Lecture du fichier de sortie
            if os.path.exists('/tmp/clients-01.csv'):
                with open('/tmp/clients-01.csv', 'r') as f:
                    lines = f.readlines()
                    
                for line in lines:
                    if line.strip() and ',' in line:
                        parts = line.split(',')
                        if len(parts) > 1 and parts[0].strip():
                            mac = parts[0].strip()
                            if mac and mac != 'Station MAC':
                                clients.append(mac)
                                
        except Exception as e:
            print(f"Erreur lors de la détection des clients: {str(e)}")
            
        return clients
        
    def get_interface_status(self, interface):
        """Récupère le statut d'une interface"""
        try:
            result = subprocess.run(['iwconfig', interface], 
                                 capture_output=True, text=True)
            
            if result.returncode == 0:
                output = result.stdout
                
                status = {
                    'interface': interface,
                    'mode': 'unknown',
                    'channel': None,
                    'ssid': None
                }
                
                lines = output.split('\n')
                for line in lines:
                    if 'Mode:' in line:
                        mode = line.split('Mode:')[1].split()[0]
                        status['mode'] = mode
                    elif 'Channel:' in line:
                        channel = line.split('Channel:')[1].split()[0]
                        status['channel'] = int(channel)
                    elif 'ESSID:' in line:
                        ssid = line.split('ESSID:')[1].strip().strip('"')
                        status['ssid'] = ssid
                        
                return status
            else:
                return None
                
        except Exception as e:
            print(f"Erreur lors de la récupération du statut: {str(e)}")
            return None
            
    def is_monitor_mode(self, interface):
        """Vérifie si l'interface est en mode monitor"""
        status = self.get_interface_status(interface)
        return status and status['mode'] == 'Monitor'
        
    def is_managed_mode(self, interface):
        """Vérifie si l'interface est en mode managed"""
        status = self.get_interface_status(interface)
        return status and status['mode'] == 'Managed' 