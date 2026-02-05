#!/usr/bin/env -S python3 -u
# Copyright 2026 Google LLC
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

import logging
import sys

from elftools.elf.elffile import ELFFile
from typing import List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

HUGE_PAGE_SIZE = 2 * 1024 * 1024

def get_segments(elf: ELFFile) -> List[Dict[str, int]]:
    """Extracts PT_LOAD segments from the ELF file."""
    segments = []
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            phys_addr = segment['p_paddr']
            mem_size = segment['p_memsz']
            segments.append({'phys_addr': phys_addr, 'size': mem_size})
    return segments
    
def get_sections(elf: ELFFile) -> Dict[str, Dict[str, int]]:
    """Extracts section headers from the ELF file."""
    sections = {}
    for section in elf.iter_sections():
        name = section.name
        size = section['sh_size']
        sections[name] = {'size': size}
    return sections

def get_elf_data(vmlinux_path: str) -> Dict[str, Any]:
    """Parses the ELF file and returns segments and sections."""
    with open(vmlinux_path, 'rb') as f:
        elf = ELFFile(f)    
        return {'segments': get_segments(elf), 'sections': get_sections(elf)}

def merge_segments(segments: List[Dict[str, int]]) -> List[Tuple[int, int]]:
    """
    Merges contiguous or overlapping physical memory ranges.
    Returns a list of (start, end) tuples.
    """
    if not segments:
        return []

    segments.sort(key=lambda x: x['phys_addr'])
    
    merged = []
    
    current_start = segments[0]['phys_addr']
    current_end = current_start + segments[0]['size']
    
    for i in range(1, len(segments)):
        seg_start = segments[i]['phys_addr']
        seg_end = seg_start + segments[i]['size']
        
        if seg_start <= current_end:
            current_end = max(current_end, seg_end)
        else:
            merged.append((current_start, current_end))
            current_start = seg_start
            current_end = seg_end
            
    merged.append((current_start, current_end))
    return merged

def calculate_total_initial_pages(data: Dict[str, Any]) -> int:
    """Calculates the total number of pages spanned by the kernel segments."""
    merged_blocks = merge_segments(data['segments'])

    start, _ = merged_blocks[0]
    _, end = merged_blocks[-1]

    start_page_idx = start // HUGE_PAGE_SIZE
    end_page_idx = (end - 1) // HUGE_PAGE_SIZE

    return end_page_idx - start_page_idx + 1

def calculate_reclaimable_pages(data: Dict[str, Any]) -> int:
    """Calculates the number of pages that can be reclaimed from .init.scratch."""
    init_scratch_size = data['sections'].get('.init.scratch', {'size': 0})['size']
    return init_scratch_size // HUGE_PAGE_SIZE

def calculate_pages(vmlinux_path: str) -> int:
    """Calculates the final runtime pages for the kernel."""

    logger.info(f"Analyzing: {vmlinux_path}")
    logger.info(f"Page Size: 2 MB ({HUGE_PAGE_SIZE:,} bytes)")
    logger.info("-" * 40)

    data = get_elf_data(vmlinux_path)
    total_initial_pages = calculate_total_initial_pages(data)
    reclaimable_pages = calculate_reclaimable_pages(data)
    runtime_pages = total_initial_pages - reclaimable_pages

    logger.info(f"Calculation:")
    logger.info(f"   {total_initial_pages} (Initial) - {reclaimable_pages} (Freed) = {runtime_pages}")
    logger.info("=" * 40)
    logger.info(f"   RUNTIME PAGES: {runtime_pages}")
    logger.info("=" * 40)

    return runtime_pages

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./kernel_pages.py <path_to_vmlinux>")
        sys.exit(1)
    
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    print(calculate_pages(sys.argv[1]))
