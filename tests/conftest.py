"""Configuracao compartilhada dos testes: garante que os modulos em src/
sejam importaveis a partir dos arquivos de teste, independente de onde
o pytest for executado."""

import os
import sys

SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
