# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import subprocess
import logging
import re


def load_symbols(vmlinux_path):
    """Loads symbols from a vmlinux file into a dictionary.

    Args:
        vmlinux_path (Path): Path to the vmlinux file.

    Returns:
        dictionary mapping symbol names to their addresses.
    """
    # Run nm command to get symbol information
    result = subprocess.run(
        ["nm", vmlinux_path],
        capture_output=True,
        text=True,
        check=True,
    )

    # Parse nm output
    symbols = {}
    for line in result.stdout.splitlines():
        # Example line: "ffffffff81000000 t _stext"
        match = re.match(r"([0-9a-fA-F]+) . (.+)", line)
        if match:
            address_str, name = match.groups()
            # Convert hex address to integer
            address = int(address_str, 16)
            symbols[name] = address

    return symbols


def get_offset(elffile, va):
    """Converts a virtual address to a file offset in an ELF file.

    Args:
        elffile: An ELFFile object.
        va: The virtual address to convert.

    Returns:
        The corresponding file offset, or None if the VA is not found in any segment.
    """
    for segment in elffile.iter_segments():
        if segment['p_type'] == 'PT_LOAD':  # Look for loadable segments
            seg_start_va = segment['p_vaddr']
            seg_end_va = seg_start_va + segment['p_memsz']
            if seg_start_va <= va < seg_end_va:  # Check if VA is within segment range
                offset_in_segment = va - seg_start_va
                return segment['p_offset'] + offset_in_segment
    return None  # VA not found in any segment


def get_segment_by_addr(elffile, va):
    """Returns segment containing an address.

    Args:
        elffile: An ELFFile object.
        va: The virtual address to convert.

    Returns:
        The corresponding file offset, or None if the VA is not found in any segment.
    """
    for segment in elffile.iter_segments():
        if segment['p_type'] == 'PT_LOAD':  # Look for loadable segments
            seg_start_va = segment['p_vaddr']
            seg_end_va = seg_start_va + segment['p_memsz']
            if seg_start_va <= va < seg_end_va:  # Check if VA is within segment range
                return segment


def setup_logger(name):
    """
    Sets up a logger with a name that logs to the console.

    Returns:
    A configured logging.Logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    return logger
