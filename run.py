# lanzador del toolkit
#
# agrega el directorio del proyecto al path para que los modulos internos se
# puedan importar sin importar desde donde se ejecute el script, y arranca el
# menu principal.
#
# uso:
#   python run.py

import os
import sys

_DIR_PROYECTO = os.path.dirname(os.path.abspath(__file__))
if _DIR_PROYECTO not in sys.path:
    sys.path.insert(0, _DIR_PROYECTO)

from main import main

if __name__ == "__main__":
    main()
