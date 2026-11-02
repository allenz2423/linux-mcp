from __future__ import annotations

import struct
import zlib

import pytest

from wayland_mcp.png import PNG_SIGNATURE, crop_png, png_dimensions


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(4, "big")
        + kind
        + payload
        + (zlib.crc32(kind + payload) & 0xFFFFFFFF).to_bytes(4, "big")
    )


def _rgb_png(width: int, height: int, pixels: bytes, filters: list[int]) -> bytes:
    stride = width * 3
    rows = [pixels[row * stride : (row + 1) * stride] for row in range(height)]
    encoded_rows = bytearray()
    previous = bytes(stride)

    def paeth(left: int, above: int, upper_left: int) -> int:
        estimate = left + above - upper_left
        distances = (abs(estimate - left), abs(estimate - above), abs(estimate - upper_left))
        return (left, above, upper_left)[distances.index(min(distances))]

    for row_number, row in enumerate(rows):
        filter_type = filters[row_number]
        encoded_rows.append(filter_type)
        filtered = bytearray(stride)
        for index, value in enumerate(row):
            left = row[index - 3] if index >= 3 else 0
            above = previous[index]
            upper_left = previous[index - 3] if index >= 3 else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = above
            elif filter_type == 3:
                predictor = (left + above) // 2
            else:
                predictor = paeth(left, above, upper_left)
            filtered[index] = (value - predictor) & 0xFF
        encoded_rows.extend(filtered)
        previous = row

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return PNG_SIGNATURE + _chunk(b"IHDR", header) + _chunk(b"IDAT", zlib.compress(encoded_rows)) + _chunk(b"IEND", b"")


def _decoded_rgb_pixels(image: bytes) -> tuple[int, int, bytes]:
    width, height = png_dimensions(image)
    offset = len(PNG_SIGNATURE)
    compressed = bytearray()
    while offset < len(image):
        length = int.from_bytes(image[offset : offset + 4], "big")
        kind = image[offset + 4 : offset + 8]
        data = image[offset + 8 : offset + 8 + length]
        if kind == b"IDAT":
            compressed.extend(data)
        offset += length + 12
        if kind == b"IEND":
            break
    raw = zlib.decompress(compressed)
    stride = width * 3
    assert all(raw[row * (stride + 1)] == 0 for row in range(height))
    return width, height, b"".join(raw[row * (stride + 1) + 1 : (row + 1) * (stride + 1)] for row in range(height))


def test_crop_png_decodes_all_png_row_filters_and_preserves_exact_pixels():
    width, height = 5, 5
    pixels = bytes((index * 17) % 256 for index in range(width * height * 3))
    image = _rgb_png(width, height, pixels, [0, 1, 2, 3, 4])

    cropped = crop_png(image, 1, 2, 3, 2)

    assert png_dimensions(cropped) == (3, 2)
    got_width, got_height, got_pixels = _decoded_rgb_pixels(cropped)
    expected_rows = [pixels[row * width * 3 : (row + 1) * width * 3] for row in (2, 3)]
    expected = b"".join(row[3:12] for row in expected_rows)
    assert (got_width, got_height, got_pixels) == (3, 2, expected)


@pytest.mark.parametrize("bounds", [(-1, 0, 1, 1), (0, 0, 0, 1), (4, 4, 2, 2)])
def test_crop_png_rejects_out_of_bounds_or_empty_regions(bounds):
    image = _rgb_png(5, 5, bytes(range(75)), [0, 0, 0, 0, 0])

    with pytest.raises(ValueError):
        crop_png(image, *bounds)


def test_crop_png_rejects_corrupt_chunk_crc():
    image = bytearray(_rgb_png(1, 1, b"\x10\x20\x30", [0]))
    image[-5] ^= 0xFF

    with pytest.raises(ValueError, match="checksum"):
        crop_png(bytes(image), 0, 0, 1, 1)
