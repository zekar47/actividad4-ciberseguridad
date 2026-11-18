#!/usr/bin/env python3
"""Renderiza una transcripción de terminal como PNG para el informe."""

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT_PATH = "/usr/share/fonts/TTF/DejaVuSansMono.ttf"


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("uso: render-terminal.py entrada.txt salida.png")
    text = Path(sys.argv[1]).read_text().rstrip("\n")
    lines = text.splitlines()
    font = ImageFont.truetype(FONT_PATH, 16)
    char_w = font.getlength("M")
    line_h = 21
    pad = 18
    width = int(max(len(line) for line in lines) * char_w + 2 * pad)
    height = len(lines) * line_h + 2 * pad
    img = Image.new("RGB", (width, height), (24, 26, 32))
    draw = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        draw.text((pad, pad + i * line_h), line, font=font, fill=(214, 220, 230))
    img.save(sys.argv[2])


if __name__ == "__main__":
    main()
