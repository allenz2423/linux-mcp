"""Small, bounded PNG helpers for startup-authorized screen captures."""

from __future__ import annotations

import struct
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_PNG_BYTES = 32 * 1024 * 1024
MAX_PNG_PIXELS = 50_000_000


def png_dimensions(image: bytes) -> tuple[int, int]:
    if len(image) < 24 or not image.startswith(PNG_SIGNATURE):
        raise ValueError("Screenshot provider did not return a PNG image.")
    width, height = struct.unpack(">II", image[16:24])
    if not (1 <= width <= 32768 and 1 <= height <= 32768):
        raise ValueError("Screenshot dimensions are invalid.")
    if width * height > MAX_PNG_PIXELS:
        raise ValueError("Screenshot pixel count exceeds the image processing limit.")
    return width, height


def _decode_rgb_png(image: bytes) -> tuple[int, int, int, bytearray]:
    """Decode a bounded 8-bit RGB/RGBA non-interlaced PNG."""
    if len(image) > MAX_PNG_BYTES:
        raise ValueError("Screenshot exceeds the 32 MiB input limit.")
    image_width, image_height = png_dimensions(image)
    offset = len(PNG_SIGNATURE)
    compressed: list[bytes] = []
    header: tuple[int, int, int, int, int, int, int] | None = None
    saw_end = False
    while offset + 12 <= len(image):
        length = int.from_bytes(image[offset : offset + 4], "big")
        chunk_type = image[offset + 4 : offset + 8]
        end = offset + 12 + length
        if length > MAX_PNG_BYTES or end > len(image):
            raise ValueError("PNG chunk exceeds the screenshot bounds.")
        chunk_data = image[offset + 8 : offset + 8 + length]
        expected_crc = int.from_bytes(image[offset + 8 + length : end], "big")
        if zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF != expected_crc:
            raise ValueError("PNG checksum validation failed.")
        if chunk_type == b"IHDR":
            if header is not None or length != 13:
                raise ValueError("PNG header is malformed.")
            header = struct.unpack(">IIBBBBB", chunk_data)
        elif chunk_type == b"IDAT":
            compressed.append(chunk_data)
        elif chunk_type == b"IEND":
            saw_end = True
            offset = end
            break
        offset = end

    if header is None or not saw_end or not compressed:
        raise ValueError("PNG is missing required image chunks.")
    encoded_width, encoded_height, bit_depth, color_type, compression, filtering, interlace = header
    if (encoded_width, encoded_height) != (image_width, image_height):
        raise ValueError("PNG header dimensions changed during parsing.")
    if bit_depth != 8 or color_type not in {2, 6} or compression != 0 or filtering != 0 or interlace != 0:
        raise ValueError("Only 8-bit RGB/RGBA non-interlaced screenshots can be processed.")
    bytes_per_pixel = 3 if color_type == 2 else 4
    stride = image_width * bytes_per_pixel
    decoded_limit = (stride + 1) * image_height
    if decoded_limit > 256 * 1024 * 1024:
        raise ValueError("Decoded screenshot exceeds the image processing limit.")
    decompressor = zlib.decompressobj()
    try:
        raw = decompressor.decompress(b"".join(compressed), decoded_limit + 1)
    except zlib.error as exc:
        raise ValueError("PNG pixel data is invalid.") from exc
    if len(raw) > decoded_limit or decompressor.unconsumed_tail or not decompressor.eof:
        raise ValueError("PNG pixel data exceeds the screenshot bounds.")
    if len(raw) != decoded_limit:
        raise ValueError("PNG pixel data has an invalid length.")

    pixels = bytearray(stride * image_height)
    previous = bytearray(stride)
    cursor = 0
    for row_number in range(image_height):
        filter_type = raw[cursor]
        encoded = raw[cursor + 1 : cursor + 1 + stride]
        cursor += stride + 1
        row = bytearray(stride)
        if filter_type > 4:
            raise ValueError("PNG uses an unsupported row filter.")
        for index, value in enumerate(encoded):
            left = row[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            above = previous[index]
            upper_left = previous[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = above
            elif filter_type == 3:
                predictor = (left + above) // 2
            else:
                estimate = left + above - upper_left
                left_distance = abs(estimate - left)
                above_distance = abs(estimate - above)
                upper_left_distance = abs(estimate - upper_left)
                predictor = left if left_distance <= above_distance and left_distance <= upper_left_distance else (
                    above if above_distance <= upper_left_distance else upper_left
                )
            row[index] = (value + predictor) & 0xFF
        row_start = row_number * stride
        pixels[row_start : row_start + stride] = row
        previous = row
    return image_width, image_height, bytes_per_pixel, pixels


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(4, "big")
        + kind
        + payload
        + (zlib.crc32(kind + payload) & 0xFFFFFFFF).to_bytes(4, "big")
    )


def _encode_rgb_png(width: int, height: int, channels: int, pixels: bytearray) -> bytes:
    color_type = 2 if channels == 3 else 6
    header = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    stride = width * channels
    compressor = zlib.compressobj(level=6)
    compressed: list[bytes] = []
    for row_number in range(height):
        start = row_number * stride
        compressed.append(compressor.compress(b"\x00" + bytes(pixels[start : start + stride])))
    compressed.append(compressor.flush())
    encoded = PNG_SIGNATURE + _chunk(b"IHDR", header) + _chunk(b"IDAT", b"".join(compressed)) + _chunk(b"IEND", b"")
    if len(encoded) > MAX_PNG_BYTES:
        raise ValueError("Processed screenshot exceeds the 32 MiB output limit.")
    return encoded


def crop_png(image: bytes, x: int, y: int, width: int, height: int) -> bytes:
    """Crop an 8-bit RGB/RGBA non-interlaced PNG using only the standard library."""
    image_width, image_height, channels, pixels = _decode_rgb_png(image)
    if any(not isinstance(value, int) or isinstance(value, bool) for value in (x, y, width, height)):
        raise ValueError("Crop bounds must be integers.")
    if x < 0 or y < 0 or width <= 0 or height <= 0 or x + width > image_width or y + height > image_height:
        raise ValueError("Crop bounds fall outside the screenshot.")

    source_stride = image_width * channels
    crop_stride = width * channels
    cropped_pixels = bytearray(crop_stride * height)
    start = x * channels
    for row_number in range(height):
        source_start = (y + row_number) * source_stride + start
        target_start = row_number * crop_stride
        cropped_pixels[target_start : target_start + crop_stride] = pixels[source_start : source_start + crop_stride]
    return _encode_rgb_png(width, height, channels, cropped_pixels)


_DIGITS = {
    "0": ("01110", "10001", "10011", "10101", "11001", "10001", "01110"),
    "1": ("00100", "01100", "00100", "00100", "00100", "00100", "01110"),
    "2": ("01110", "10001", "00001", "00010", "00100", "01000", "11111"),
    "3": ("11110", "00001", "00001", "01110", "00001", "00001", "11110"),
    "4": ("00010", "00110", "01010", "10010", "11111", "00010", "00010"),
    "5": ("11111", "10000", "10000", "11110", "00001", "00001", "11110"),
    "6": ("01110", "10000", "10000", "11110", "10001", "10001", "01110"),
    "7": ("11111", "00001", "00010", "00100", "01000", "01000", "01000"),
    "8": ("01110", "10001", "10001", "01110", "10001", "10001", "01110"),
    "9": ("01110", "10001", "10001", "01111", "00001", "00001", "01110"),
}


def _blend_pixel(
    pixels: bytearray,
    offset: int,
    channels: int,
    color: tuple[int, int, int],
    alpha: int,
) -> None:
    if channels == 3:
        inverse = 255 - alpha
        for channel in range(3):
            pixels[offset + channel] = (pixels[offset + channel] * inverse + color[channel] * alpha + 127) // 255
        return

    source_alpha = pixels[offset + 3]
    output_alpha = alpha + (source_alpha * (255 - alpha) + 127) // 255
    if output_alpha == 0:
        return
    for channel in range(3):
        source_premultiplied = pixels[offset + channel] * source_alpha * (255 - alpha) // 255
        output_premultiplied = color[channel] * alpha + source_premultiplied
        pixels[offset + channel] = min(255, (output_premultiplied + output_alpha // 2) // output_alpha)
    pixels[offset + 3] = output_alpha


def _draw_grid_label(
    pixels: bytearray,
    width: int,
    height: int,
    channels: int,
    text: str,
    anchor_x: int,
    anchor_y: int,
    scale: int,
    *,
    center_x: bool,
    center_y: bool,
) -> None:
    text_units = len(text) * 5 + max(0, len(text) - 1)
    box_width = text_units * scale + 4
    box_height = 7 * scale + 4
    if box_width > width or box_height > height:
        return
    left = anchor_x - box_width // 2 if center_x else anchor_x
    top = anchor_y - box_height // 2 if center_y else anchor_y
    left = max(0, min(width - box_width, left))
    top = max(0, min(height - box_height, top))
    background = (12, 18, 25)
    for y in range(top, top + box_height):
        for x in range(left, left + box_width):
            _blend_pixel(pixels, (y * width + x) * channels, channels, background, 220)

    cursor_x = left + 2
    glyph_top = top + 2
    for character in text:
        glyph = _DIGITS[character]
        for glyph_y, glyph_row in enumerate(glyph):
            for glyph_x, enabled in enumerate(glyph_row):
                if enabled != "1":
                    continue
                for dy in range(scale):
                    y = glyph_top + glyph_y * scale + dy
                    for dx in range(scale):
                        x = cursor_x + glyph_x * scale + dx
                        _blend_pixel(pixels, (y * width + x) * channels, channels, (255, 255, 255), 255)
        cursor_x += 6 * scale


def coordinate_grid_png(image: bytes, interval: int = 100) -> bytes:
    """Overlay a numbered x/y pixel grid on an 8-bit RGB/RGBA PNG."""
    if not isinstance(interval, int) or isinstance(interval, bool) or not 50 <= interval <= 1000:
        raise ValueError("Pixel grid interval must be an integer from 50 through 1000.")
    width, height, channels, pixels = _decode_rgb_png(image)

    for x in range(0, width, interval):
        for y in range(height):
            _blend_pixel(pixels, (y * width + x) * channels, channels, (30, 210, 255), 120)
    for y in range(0, height, interval):
        row_start = y * width
        for x in range(width):
            _blend_pixel(pixels, (row_start + x) * channels, channels, (30, 210, 255), 120)

    largest_coordinate = max(width - 1, height - 1)
    largest_digits = len(str(largest_coordinate))
    unit_width = largest_digits * 5 + max(0, largest_digits - 1)
    scale = max(1, min(3, (interval - 4) // unit_width))
    label_height = 7 * scale + 4
    for x in range(0, width, interval):
        _draw_grid_label(pixels, width, height, channels, str(x), x, 2, scale, center_x=True, center_y=False)
    for y in range(0, height, interval):
        if y == 0:
            _draw_grid_label(
                pixels, width, height, channels, str(y), 2, label_height + 4, scale,
                center_x=False, center_y=False,
            )
        else:
            _draw_grid_label(pixels, width, height, channels, str(y), 2, y, scale,
                             center_x=False, center_y=True)

    return _encode_rgb_png(width, height, channels, pixels)
