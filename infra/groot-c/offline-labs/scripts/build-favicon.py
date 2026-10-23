#!/usr/bin/env python3
"""Render this repository's axis-aligned SVG icon to offline PNG/ICO assets.

Standard library only; the SVG remains the design source. No downloads/fonts.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import xml.etree.ElementTree as ET
import zlib

BASE = Path(__file__).resolve().parent.parent / 'static'


def geometry():
    root = ET.fromstring((BASE / 'favicon.svg').read_bytes())
    assert root.attrib['viewBox'] == '0 0 48 48'
    rect, group = list(root)
    assert rect.attrib == {'x': '1', 'y': '1', 'width': '46', 'height': '46',
                          'rx': '4', 'fill': '#181817', 'stroke': '#eeede7', 'stroke-width': '2'}
    assert group.attrib.get('stroke-width') == '2'
    tokens = re.findall(r'[A-Za-z]|[-+]?(?:\d*\.\d+|\d+)', list(group)[0].attrib['d'])
    segments = []
    x = y = sx = sy = 0.0
    i = 0
    while i < len(tokens):
        command = tokens[i]; i += 1
        if command in 'Mm':
            a, b = float(tokens[i]), float(tokens[i + 1]); i += 2
            x, y = (a, b) if command == 'M' else (x + a, y + b)
            sx, sy = x, y
            continue
        old = x, y
        if command in 'HhVv':
            value = float(tokens[i]); i += 1
            if command == 'H': x = value
            elif command == 'h': x += value
            elif command == 'V': y = value
            else: y += value
        elif command in 'Zz': x, y = sx, sy
        else: raise ValueError('SVG command outside the reviewed icon subset')
        segments.append((min(old[0], x) - 1, min(old[1], y) - 1,
                         max(old[0], x) + 1, max(old[1], y) + 1))
    return segments


def rounded(x, y, low, high, radius):
    if not low <= x <= high or not low <= y <= high: return False
    cx, cy = min(max(x, low + radius), high - radius), min(max(y, low + radius), high - radius)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2


def pixels(size, segments):
    samples = 4
    background, foreground = (24, 24, 23), (238, 237, 231)
    rows = bytearray()
    for py in range(size):
        for px in range(size):
            total = [0, 0, 0]; count = 0
            for sy in range(samples):
                y = (py + (sy + .5) / samples) * 48 / size
                for sx in range(samples):
                    x = (px + (sx + .5) / samples) * 48 / size
                    if not rounded(x, y, 0, 48, 5): continue
                    color = background if rounded(x, y, 2, 46, 3) else foreground
                    if any(a <= x <= c and b <= y <= d for a, b, c, d in segments): color = foreground
                    for channel in range(3): total[channel] += color[channel]
                    count += 1
            rows.extend([round(value / count) if count else 0 for value in total])
            rows.append(round(count * 255 / (samples * samples)))
    return bytes(rows)


def png(size, segments):
    rgba = pixels(size, segments)
    rows = b''.join(b'\0' + rgba[y * size * 4:(y + 1) * size * 4] for y in range(size))
    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data) & 0xffffffff)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!IIBBBBB', size, size, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(rows, 9)) + chunk(b'IEND', b'')


def dib(size, segments):
    """Conventional 32-bit ICO bitmap, including its padded AND mask."""
    rgba = pixels(size, segments)
    bitmap = bytearray()
    mask = bytearray()
    mask_stride = ((size + 31) // 32) * 4
    for y in reversed(range(size)):
        row = rgba[y * size * 4:(y + 1) * size * 4]
        mask_row = bytearray(mask_stride)
        for x in range(size):
            r, g, b, a = row[x * 4:x * 4 + 4]
            bitmap.extend((b, g, r, a))
            if not a: mask_row[x // 8] |= 1 << (7 - x % 8)
        mask.extend(mask_row)
    header = struct.pack('<IiiHHIIiiII', 40, size, size * 2, 1, 32, 0,
                         len(bitmap) + len(mask), 0, 0, 0, 0)
    return header + bitmap + mask


def main():
    segments = geometry()
    images = [(n, dib(n, segments)) for n in (16, 32, 48)]
    offset = 6 + 16 * len(images)
    directory = bytearray(struct.pack('<HHH', 0, 1, len(images)))
    for size, data in images:
        directory.extend(struct.pack('<BBBBHHII', size, size, 0, 0, 1, 32, len(data), offset))
        offset += len(data)
    ico = bytes(directory) + b''.join(data for _, data in images)
    outputs = {'favicon.png': png(64, segments), 'apple-touch-icon.png': png(180, segments),
               'favicon.ico': ico, 'lab-console-icon.ico': ico}
    for name, data in outputs.items(): (BASE / name).write_bytes(data)
    print(json.dumps({name: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)} for name, data in outputs.items()}, sort_keys=True))


if __name__ == '__main__': main()
