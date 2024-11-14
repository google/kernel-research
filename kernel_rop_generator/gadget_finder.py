import subprocess
import re
import sys
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


def get_text_section_range(binary_path):
    """
    Returns the start and end addresses of the .text section in a binary.

    Args:
      binary_path: The path to the binary file.

    Returns:
      A tuple containing the start and end addresses of the .text section,
      or None if the section is not found.
    """
    with open(binary_path, 'rb') as f:
        elffile = ELFFile(f)
        # Get the .text section
        text_section = elffile.get_section_by_name('.text')
        if not text_section:
            raise ELFError("Error: .text section not found in the binary.")

        text_section_start = text_section['sh_addr']
        text_section_end = text_section_start + text_section['sh_size']
        return text_section_start, text_section_end


def run_rp(context_size, binary_path):
    """
    Runs the rp++ tool and returns a dictionary of gadgets.

    Args:
      context_size: The context size to use for gadget search.
      binary_path: The path to the binary file.

    Returns:
      A dictionary where keys are addresses and values are the corresponding gadgets.
    """
    gadgets = {}
    text_section_range = get_text_section_range(binary_path)
    text_section_start, text_section_end = text_section_range

    try:
        # Run rp++ command and capture the output
        result = subprocess.run(['rp++', '-r', str(context_size), '-f',
                                binary_path], capture_output=True, text=True, check=True)
        # Split the output into lines and remove empty lines
        for line in result.stdout.splitlines():
            if line.strip():
                # Split the line into address and gadget
                try:
                    address, gadget = line.split(':', 1)
                    address = int(address.strip(), 16)
                    if text_section_start <= address < text_section_end:
                        # Split off "1 found" from rp++ output
                        gadget = gadget.rsplit('(', 1)[0]
                        gadgets[address] = gadget
                except ValueError:
                    print(
                        f"Warning: Skipping line with unexpected format: {line}")
        return gadgets
    except FileNotFoundError as e:
        raise FileNotFoundError(
            "Error: rp++ tool not found. Please make sure it is installed and in your PATH.") from e


def remove_duplicate_gadgets(gadgets):
    """
    Removes duplicate gadgets from a dictionary of gadgets.

    Args:
      gadgets: A dictionary of gadgets (key: address, value: gadget).

    Returns:
      A new dictionary with duplicate gadgets removed.
    """
    seen_gadgets = set()
    unique_gadgets = {}
    for address, gadget in gadgets.items():
        if gadget not in seen_gadgets:
            unique_gadgets[address] = gadget
            seen_gadgets.add(gadget)
    return unique_gadgets


def filter_gadgets(gadgets, registers):
    """
    Filters a list of gadgets to exclude those containing specific registers.

    Args:
      gadgets: A list of gadgets.
      registers: A list of registers to exclude.

    Returns:
      A list of filtered gadgets.
    """
    # Create a regex pattern to match any of the registers
    pattern = re.compile(r'\b(?:' + '|'.join(registers) + r')\b')
    # Filter out gadgets that match the pattern
    filtered_gadgets = [
        gadget for gadget in gadgets if not pattern.search(gadget)]
    return filtered_gadgets


def split_instructions(gadgets):
    """
    Splits the gadget string into separate instructions 
    """
    split_gadgets = {}
    for addr, gad in gadgets.items():
        split_gadgets[addr] = [x.strip()
                               for x in gad.strip("; '{}").split(";")]
    return split_gadgets


def find_gadgets(binary_path, context_size):
    """
    Filters the found gadgets and returns a dict of unique gadgets
    """
    gadgets = run_rp(context_size, binary_path)
    gadgets = remove_duplicate_gadgets(gadgets)
    gadgets = split_instructions(gadgets)
    return gadgets


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    context_size = 5
    try:
        gadgets = find_gadgets(binary_path, context_size)
    except (FileNotFoundError, ValueError, subprocess.CalledProcessError) as exc:
        print(exc)

    for address, gad in gadgets.items():
        print(hex(address), gad)

    start, end = get_text_section_range(binary_path)
    print(f"Text section start addr: {hex(start)}, end addr: {hex(end)}")
