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


def crop_png(image: bytes, x: int, y: int, width: int, height: int) -> bytes:
    """Crop an 8-bit RGB/RGBA non-interlaced PNG using only the standard library."""
    if len(image) > MAX_PNG_BYTES:
        raise ValueError("Screenshot exceeds the 32 MiB input limit.")
    image_width, image_height = png_dimensions(image)
    if any(not isinstance(value, int) or isinstance(value, bool) for value in (x, y, width, height)):
        raise ValueError("Crop bounds must be integers.")
    if x < 0 or y < 0 or width <= 0 or height <= 0 or x + width > image_width or y + height > image_height:
        raise ValueError("Crop bounds fall outside the screenshot.")

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
        raise ValueError("Only 8-bit RGB/RGBA non-interlaced screenshots can be cropped.")
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

    rows: list[bytes] = []
    previous = bytearray(stride)
    cursor = 0
    for _row_number in range(image_height):
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
        rows.append(bytes(row))
        previous = row

    start = x * bytes_per_pixel
    end = (x + width) * bytes_per_pixel
    cropped_pixels = b"".join(b"\x00" + row[start:end] for row in rows[y : y + height])
    new_header = struct.pack(">IIBBBBB", width, height, bit_depth, color_type, compression, filtering, interlace)

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            len(payload).to_bytes(4, "big")
            + kind
            + payload
            + (zlib.crc32(kind + payload) & 0xFFFFFFFF).to_bytes(4, "big")
        )

    cropped = (
        PNG_SIGNATURE
        + chunk(b"IHDR", new_header)
        + chunk(b"IDAT", zlib.compress(cropped_pixels, level=6))
        + chunk(b"IEND", b"")
    )
    if len(cropped) > MAX_PNG_BYTES:
        raise ValueError("Cropped screenshot exceeds the 32 MiB output limit.")
    return cropped
