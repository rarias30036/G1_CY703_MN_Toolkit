# configuracion compartida para las pruebas
#
# agrega el directorio raiz del proyecto al path para que los modulos internos
# (common, network_module, web_module) se puedan importar desde las pruebas.

import os
import sys

_DIR_PROYECTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _DIR_PROYECTO not in sys.path:
    sys.path.insert(0, _DIR_PROYECTO)
