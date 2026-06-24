# lanzador del toolkit preliminar (prototipo)
#
# agrega el directorio padre al path para que el paquete sea importable y
# arranca el menu principal, sin importar desde donde se ejecute.
#
# uso:
#   python run.py

import os
import sys

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT_DIR = os.path.dirname(_PACKAGE_DIR)
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

from toolkitPreeliminar.main import main

if __name__ == "__main__":
    main()
