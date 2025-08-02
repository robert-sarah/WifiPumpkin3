#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Onglet Logs - Affichage et gestion des logs
"""

import os
import time
from datetime import datetime
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QComboBox, QLineEdit, QSpinBox,
                             QCheckBox, QGroupBox, QTextEdit, QTableWidget,
                             QTableWidgetItem, QMessageBox, QProgressBar,
                             QFileDialog, QSplitter)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QTextCursor

class LogsTab(QWidget):
    """Onglet pour l'affichage et la gestion des logs"""
    
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        """Configuration de l'interface utilisateur"""
        layout = QVBoxLayout(self)
        
        # Section de contrôle
        self.setup_control_section(layout)
        
        # Section d'affichage des logs
        self.setup_logs_section(layout)
        
        # Section de statistiques
        self.setup_stats_section(layout)
        
    def setup_control_section(self, layout):
        """Section de contrôle des logs"""
        control_group = QGroupBox("Contrôle des Logs")
        control_layout = QHBoxLayout(control_group)
        
        # Filtres
        control_layout.addWidget(QLabel("Niveau:"))
        self.level_filter = QComboBox()
        self.level_filter.addItems(["Tous", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.level_filter.currentTextChanged.connect(self.apply_filters)
        control_layout.addWidget(self.level_filter)
        
        control_layout.addWidget(QLabel("Recherche:"))
        self.search_filter = QLineEdit()
        self.search_filter.setPlaceholderText("Rechercher dans les logs...")
        self.search_filter.textChanged.connect(self.apply_filters)
        control_layout.addWidget(self.search_filter)
        
        # Boutons
        self.refresh_btn = QPushButton("Actualiser")
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        self.refresh_btn.clicked.connect(self.refresh_logs)
        control_layout.addWidget(self.refresh_btn)
        
        self.clear_btn = QPushButton("Effacer")
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        self.clear_btn.clicked.connect(self.clear_logs)
        control_layout.addWidget(self.clear_btn)
        
        self.export_btn = QPushButton("Exporter")
        self.export_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        self.export_btn.clicked.connect(self.export_logs)
        control_layout.addWidget(self.export_btn)
        
        control_layout.addStretch()
        
        layout.addWidget(control_group)
        
    def setup_logs_section(self, layout):
        """Section d'affichage des logs"""
        logs_group = QGroupBox("Logs de l'Application")
        logs_layout = QVBoxLayout(logs_group)
        
        # Zone de texte pour les logs
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setFont(QFont("Consolas", 9))
        
        # Configuration des couleurs pour les niveaux
        self.setup_log_colors()
        
        logs_layout.addWidget(self.logs_text)
        
        layout.addWidget(logs_group)
        
    def setup_stats_section(self, layout):
        """Section des statistiques"""
        stats_group = QGroupBox("Statistiques des Logs")
        stats_layout = QGridLayout(stats_group)
        
        # Statistiques
        stats_layout.addWidget(QLabel("Total d'entrées:"), 0, 0)
        self.total_entries = QLabel("0")
        stats_layout.addWidget(self.total_entries, 0, 1)
        
        stats_layout.addWidget(QLabel("Fichier de log:"), 1, 0)
        self.log_file_path = QLabel(self.logger.get_log_file_path())
        stats_layout.addWidget(self.log_file_path, 1, 1)
        
        stats_layout.addWidget(QLabel("Taille du fichier:"), 2, 0)
        self.file_size = QLabel("0 KB")
        stats_layout.addWidget(self.file_size, 2, 1)
        
        # Compteurs par niveau
        stats_layout.addWidget(QLabel("DEBUG:"), 3, 0)
        self.debug_count = QLabel("0")
        stats_layout.addWidget(self.debug_count, 3, 1)
        
        stats_layout.addWidget(QLabel("INFO:"), 4, 0)
        self.info_count = QLabel("0")
        stats_layout.addWidget(self.info_count, 4, 1)
        
        stats_layout.addWidget(QLabel("WARNING:"), 5, 0)
        self.warning_count = QLabel("0")
        stats_layout.addWidget(self.warning_count, 5, 1)
        
        stats_layout.addWidget(QLabel("ERROR:"), 6, 0)
        self.error_count = QLabel("0")
        stats_layout.addWidget(self.error_count, 6, 1)
        
        stats_layout.addWidget(QLabel("CRITICAL:"), 7, 0)
        self.critical_count = QLabel("0")
        stats_layout.addWidget(self.critical_count, 7, 1)
        
        layout.addWidget(stats_group)
        
    def setup_log_colors(self):
        """Configure les couleurs pour les différents niveaux de log"""
        # Définition des couleurs pour chaque niveau
        self.log_colors = {
            'DEBUG': '#6c757d',    # Gris
            'INFO': '#17a2b8',     # Bleu clair
            'WARNING': '#ffc107',  # Jaune
            'ERROR': '#dc3545',    # Rouge
            'CRITICAL': '#721c24'  # Rouge foncé
        }
        
    def setup_timer(self):
        """Configure le timer pour l'actualisation automatique"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_logs)
        self.update_timer.start(1000)  # Actualisation toutes les secondes
        
        # Connexion du signal de log
        self.logger.log_signal.connect(self.add_log_entry)
        
    def add_log_entry(self, log_entry):
        """Ajoute une entrée de log à l'affichage"""
        cursor = self.logs_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        # Détermination de la couleur selon le niveau
        color = self.get_log_color(log_entry)
        
        # Formatage de l'entrée
        cursor.insertHtml(f'<span style="color: {color};">{log_entry}</span><br>')
        
        # Auto-scroll vers le bas
        self.logs_text.setTextCursor(cursor)
        
    def get_log_color(self, log_entry):
        """Détermine la couleur selon le niveau de log"""
        for level, color in self.log_colors.items():
            if level in log_entry:
                return color
        return '#000000'  # Noir par défaut
        
    def apply_filters(self):
        """Applique les filtres sur les logs"""
        level_filter = self.level_filter.currentText()
        search_text = self.search_filter.text().lower()
        
        # Récupération de tous les logs
        all_logs = self.logger.get_history()
        
        # Filtrage
        filtered_logs = []
        for log in all_logs:
            # Filtre par niveau
            if level_filter != "Tous" and level_filter not in log:
                continue
                
            # Filtre par recherche
            if search_text and search_text not in log.lower():
                continue
                
            filtered_logs.append(log)
            
        # Affichage des logs filtrés
        self.display_logs(filtered_logs)
        
    def display_logs(self, logs):
        """Affiche une liste de logs"""
        self.logs_text.clear()
        
        for log in logs:
            color = self.get_log_color(log)
            self.logs_text.append(f'<span style="color: {color};">{log}</span>')
            
    def refresh_logs(self):
        """Actualise l'affichage des logs"""
        self.update_stats()
        self.apply_filters()
        
    def clear_logs(self):
        """Efface les logs"""
        reply = QMessageBox.question(self, "Confirmation", 
                                   "Voulez-vous vraiment effacer tous les logs ?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.logger.clear_history()
            self.logs_text.clear()
            self.update_stats()
            
    def export_logs(self):
        """Exporte les logs vers un fichier"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Exporter les logs", 
            f"logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Fichiers texte (*.txt);;Tous les fichiers (*)"
        )
        
        if filename:
            try:
                success = self.logger.export_logs(filename)
                if success:
                    QMessageBox.information(self, "Succès", 
                                          f"Logs exportés vers {filename}")
                else:
                    QMessageBox.critical(self, "Erreur", 
                                       "Erreur lors de l'export des logs")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", 
                                   f"Erreur lors de l'export:\n{str(e)}")
                
    def update_logs(self):
        """Met à jour l'affichage des logs"""
        # Cette méthode est appelée par le timer
        # Elle peut être utilisée pour des mises à jour en temps réel
        pass
        
    def update_stats(self):
        """Met à jour les statistiques"""
        try:
            stats = self.logger.get_log_stats()
            
            # Mise à jour des statistiques
            self.total_entries.setText(str(stats['total_entries']))
            self.log_file_path.setText(stats['file_path'])
            
            # Formatage de la taille du fichier
            size_kb = stats['file_size'] / 1024
            if size_kb < 1024:
                self.file_size.setText(f"{size_kb:.1f} KB")
            else:
                size_mb = size_kb / 1024
                self.file_size.setText(f"{size_mb:.1f} MB")
                
            # Compteurs par niveau
            level_counts = stats.get('level_counts', {})
            self.debug_count.setText(str(level_counts.get('DEBUG', 0)))
            self.info_count.setText(str(level_counts.get('INFO', 0)))
            self.warning_count.setText(str(level_counts.get('WARNING', 0)))
            self.error_count.setText(str(level_counts.get('ERROR', 0)))
            self.critical_count.setText(str(level_counts.get('CRITICAL', 0)))
            
        except Exception as e:
            print(f"Erreur lors de la mise à jour des statistiques: {str(e)}")
            
    def show_log_details(self, log_entry):
        """Affiche les détails d'une entrée de log"""
        # Cette méthode peut être utilisée pour afficher plus de détails
        # sur une entrée de log sélectionnée
        QMessageBox.information(self, "Détails du Log", log_entry)
        
    def get_filtered_logs(self):
        """Récupère les logs filtrés selon les critères actuels"""
        level_filter = self.level_filter.currentText()
        search_text = self.search_filter.text().lower()
        
        all_logs = self.logger.get_history()
        filtered_logs = []
        
        for log in all_logs:
            # Filtre par niveau
            if level_filter != "Tous" and level_filter not in log:
                continue
                
            # Filtre par recherche
            if search_text and search_text not in log.lower():
                continue
                
            filtered_logs.append(log)
            
        return filtered_logs