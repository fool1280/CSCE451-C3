import subprocess
import sys
import re
import os

def disassemble_and_process(file_name, cache_dir = '.'):
    file_path = file_name
    file_name = os.path.basename(file_name)
    # Disassemble the file
    print(f"Disassembling {file_name}...")
    try:
        disassembly_output = subprocess.run(["objdump", "-d", file_path], capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        print(f"Command failed with return code {e.returncode}: {e.stderr}")
        exit(1)

    # Write the disassembly to a file
    disassembly_file_name = f"{cache_dir}/{file_name}_disassembly.txt"
    opcodes_file_name = f"{cache_dir}/{file_name}_opcodes.txt"
    with open(disassembly_file_name, "w") as f:
        f.write(disassembly_output)

    # Process the disassembly file
    print(f"Processing {disassembly_file_name}...")
    process_disassembly(disassembly_file_name, opcodes_file_name, cache_dir)

def extract_opcodes(line):
    parts = line.split('\t')
    if len(parts) > 2:
        # The opcode is typically the second part of the line, after splitting by tab
        opcode = parts[2].split()[0]
        # opcode = parts[1].strip() # FOR MAC ONLY 
        return opcode
    return None

def process_disassembly(disassembly_file_name, opcodes_file_name, cache_dir = '.'):
    with open(disassembly_file_name, "r") as file:
        lines = file.readlines()

    # Extract content between ".text" and ".fini" sections
    start = None
    end = None
    for i, line in enumerate(lines):
        if 'Disassembly of section .text:' in line:
            start = i
        elif 'Disassembly of section .fini:' in line:
            end = i
            break

    if start is not None and end is not None:
        lines = lines[start:end]

    # Remove unwanted lines
    pattern = re.compile(r'^[0-9a-f]{16} <[^>]+>:')
    lines = [line for line in lines if not pattern.match(line) and line.strip()]

    # Write the processed content back to the disassembly file
    with open(disassembly_file_name, "w") as file:
        file.writelines(lines)

    opcodes = [extract_opcodes(line) for line in lines if extract_opcodes(line)]

    opcodes_output = " ".join(opcodes)

    with open(opcodes_file_name, 'w') as file:
        for opcode in opcodes:
            file.write(opcode + '\n')
    with open(f"{cache_dir}/ml_input.txt", 'w') as file:
        file.write(opcodes_output)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <filename>")
    else:
        disassemble_and_process(sys.argv[1])
        print("Disassembly processed.")
