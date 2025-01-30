import hashlib
import json

def calculate_hash(block):
    # Преобразование блока в строку для хеширования
    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def read_blocks_from_json(file_path):
    # Чтение блока из json файла
    with open(file_path, 'r') as file:
        blocks = json.load(file)
    return blocks

def write_hashes_to_file(blocks, output_file_path):
    # Запись хешей в файл
    with open(output_file_path, 'w') as file:
        for block in blocks:
            block_hash = calculate_hash(block)
            file.write(f"Block {block['index']} and his hash: {block_hash}\n")

# Путь к файлу с блоками
input_file_path = 'task1.json'
# Путь к выходному файлу с хешами
output_file_path = 'block_hashes.txt'

# Чтение блоков из JSON файла
blocks = read_blocks_from_json(input_file_path)

# Вычисление хешей и запись их в файл
write_hashes_to_file(blocks, output_file_path)

print(f"Хеши блоков записаны в файл: {output_file_path}")
