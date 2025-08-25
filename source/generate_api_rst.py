import os

def generate_api_rst(groups, output_file='api.rst'):
    """
    Generates an api.rst file with sections for each Doxygen group.

    Args:
        groups (list): A list of tuples, where each tuple contains
                       (group_id, group_title).
        output_file (str): The name of the output .rst file.
    """
    with open(output_file, 'w') as f:
        f.write("API Reference\n")
        f.write("=============\n\n")
        f.write(".. toctree::\n")
        f.write("   :maxdepth: 2\n\n")

        for group_id, group_title in groups:
            # Add a link to the group section in the toctree
            f.write(f"   {group_id}\n")

            # Create a separate .rst file for each group
            with open(f"{group_id}.rst", 'w') as group_file:
                group_file.write(f"{group_title}\n")
                group_file.write(f"{'=' * len(group_title)}\n\n")
                group_file.write(f".. doxygengroup:: {group_id}\n")
                group_file.write("   :project: kernelXDK\n")
                group_file.write("   :members:\n")
                group_file.write("   :content-only:\n")

if __name__ == "__main__":
    # Your Doxygen groups from the project
    doxygen_groups = [
        ("xdk_device_classes", "XDK Device Module"),
        ("rip_classes", "RIP Module"),
        ("target_classes", "Target Module"),
        ("util_classes", "Utility Module"),
        ("pivot_classes", "Pivot Module"),
        ("payloads_classes", "Payloads Module")
    ]

    generate_api_rst(doxygen_groups)
    print("Successfully generated api.rst and individual group files.")
