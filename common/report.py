# generacion de reportes en pdf
#
# consolida los hallazgos de la sesion en un reporte pdf con un resumen
# ejecutivo y el detalle priorizado por severidad. los reportes se guardan
# en la carpeta reportes dentro del directorio del proyecto.

import os
from datetime import datetime

from common import findings as F

# reportlab se importa de forma opcional para que el resto del toolkit
# funcione aunque la libreria no este instalada todavia.
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )
    _REPORTLAB = True
except ImportError:
    _REPORTLAB = False

# la carpeta de reportes queda dentro del directorio del proyecto
DIR_REPORTES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reportes"
)


def asegurar_directorio():
    os.makedirs(DIR_REPORTES, exist_ok=True)
    return DIR_REPORTES


def _color_severidad(severidad):
    # devuelve un color para cada severidad en el pdf
    mapa = {
        "CRITICA": colors.HexColor("#c0392b"),
        "ALTA": colors.HexColor("#e67e22"),
        "MEDIA": colors.HexColor("#d4ac0d"),
        "BAJA": colors.HexColor("#3498db"),
        "INFO": colors.HexColor("#7f8c8d"),
    }
    return mapa.get(severidad, colors.black)


def _escapar(texto):
    # escapa los caracteres que reportlab interpreta como etiquetas
    texto = texto or ""
    return texto.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def generar_reporte_pdf(hallazgos, objetivos, usuario):
    # arma el pdf con los hallazgos de la sesion y devuelve la ruta del archivo,
    # o None si reportlab no esta instalado.
    if not _REPORTLAB:
        print("  [-] reportlab no esta instalado. ejecute: python install.py")
        return None

    asegurar_directorio()
    nombre = "reporte_seguridad_%s.pdf" % datetime.now().strftime("%Y%m%d_%H%M%S")
    ruta = os.path.join(DIR_REPORTES, nombre)

    doc = SimpleDocTemplate(
        ruta, pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40,
    )
    estilos = getSampleStyleSheet()
    est_titulo = ParagraphStyle("titulo", parent=estilos["Title"], fontSize=18)
    est_sub = ParagraphStyle("sub", parent=estilos["Normal"], fontSize=9, textColor=colors.grey)
    est_seccion = ParagraphStyle("seccion", parent=estilos["Heading2"], fontSize=13)
    est_cuerpo = ParagraphStyle("cuerpo", parent=estilos["Normal"], fontSize=10, leading=13)

    historia = []
    historia.append(Paragraph("Toolkit preliminar - Reporte de seguridad", est_titulo))
    historia.append(Paragraph(
        "generado el %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"), est_sub
    ))
    historia.append(Paragraph("usuario: %s" % _escapar(usuario), est_sub))
    if objetivos:
        historia.append(Paragraph(
            "objetivos analizados: %s" % _escapar(", ".join(objetivos)), est_sub
        ))
    historia.append(Spacer(1, 14))

    # resumen ejecutivo
    puntaje = F.calcular_puntaje(hallazgos)
    conteo = F.resumen_por_severidad(hallazgos)
    datos = [
        ["Puntaje de seguridad", "%d/100" % puntaje],
        ["Total de hallazgos", str(len(hallazgos))],
        ["Criticos / Altos", "%d / %d" % (conteo["CRITICA"], conteo["ALTA"])],
        ["Medios / Bajos / Info",
         "%d / %d / %d" % (conteo["MEDIA"], conteo["BAJA"], conteo["INFO"])],
    ]
    tabla = Table(datos, colWidths=[200, 320])
    tabla.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f4f4")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5dbdb")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    historia.append(Paragraph("Resumen ejecutivo", est_seccion))
    historia.append(tabla)
    historia.append(Spacer(1, 16))

    # detalle de hallazgos ordenados de mas grave a menos grave
    historia.append(Paragraph("Detalle de hallazgos", est_seccion))
    if not hallazgos:
        historia.append(Paragraph("no se registraron hallazgos en esta sesion.", est_cuerpo))

    for h in F.ordenar_por_severidad(hallazgos):
        est_sev = ParagraphStyle(
            "sev", parent=est_cuerpo,
            textColor=_color_severidad(h["severidad"]), fontName="Helvetica-Bold",
        )
        historia.append(Spacer(1, 8))
        historia.append(Paragraph(
            "[%s] (%s) %s" % (h["severidad"], h["modulo"], _escapar(h["titulo"])), est_sev
        ))
        historia.append(Paragraph(_escapar(h["descripcion"]), est_cuerpo))
        if h["recomendacion"]:
            historia.append(Paragraph(
                "recomendacion: %s" % _escapar(h["recomendacion"]), est_cuerpo
            ))

    doc.build(historia)
    return ruta
