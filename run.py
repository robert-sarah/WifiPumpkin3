 #!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de lancement pour WiFiPumpkin3
"""

import sys
import os

# Ajout du répertoire courant au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Point d'entrée principal"""
    try:
        # Import et lancement de l'application
        from main import main
        main()
    except ImportError as e:
        print(f"Erreur d'import: {e}")
        print("Veuillez installer les dépendances avec: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"Erreur lors du lancement: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()