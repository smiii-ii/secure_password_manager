import json
from PIL import Image

def to_bin(data):
    """Convert string data to binary string (0/1 chars)."""
    if isinstance(data, str):
        return ''.join(format(ord(i), '08b') for i in data)
    else:
        raise TypeError("Input should be a string")

def from_bin(binary_str):
    """Convert binary string (0/1 chars) back to string."""
    chars = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

def encode_image(image_path, data_dict, output_path):
    image = Image.open(image_path).convert('RGB')
    json_data = json.dumps(data_dict)
    delimiter = '1111111111111110'
    binary_data = to_bin(json_data) + delimiter

    width, height = image.size
    num_pixels = width * height
    if len(binary_data) > num_pixels * 3:
        raise ValueError("Image not large enough for data! Choose a larger image.")

    pixels = list(image.getdata())
    new_pixels = []
    data_index = 0
    data_len = len(binary_data)

    for pixel in pixels:
        r, g, b = pixel
        if data_index < data_len:
            r = (r & ~1) | int(binary_data[data_index])
            data_index += 1
        if data_index < data_len:
            g = (g & ~1) | int(binary_data[data_index])
            data_index += 1
        if data_index < data_len:
            b = (b & ~1) | int(binary_data[data_index])
            data_index += 1
        new_pixels.append((r, g, b))

    image.putdata(new_pixels)
    image.save(output_path)
    return output_path

def decode_image(image_path):
    image = Image.open(image_path).convert('RGB')
    binary_data = ""
    for pixel in list(image.getdata()):
        r, g, b = pixel
        binary_data += str(r & 1)
        binary_data += str(g & 1)
        binary_data += str(b & 1)

    end_marker = "1111111111111110"
    end_idx = binary_data.find(end_marker)
    if end_idx == -1:
        return {}

    data_bits = binary_data[:end_idx]
    decoded = from_bin(data_bits)

    try:
        data_dict = json.loads(decoded)
    except json.JSONDecodeError:
        data_dict = {}

    return data_dict
