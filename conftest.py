"""
conftest.py racine — charge le .env avant tout import de packages.
Placé à la racine du projet (même niveau que pyproject.toml).
"""
import os
from dotenv import load_dotenv

# Charge le .env depuis la racine du projet (où pytest est lancé)
load_dotenv(override=True)