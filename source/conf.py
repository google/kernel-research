# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'kernelXDK'
copyright = '2025, Chani Jindal'
author = 'Chani Jindal'
release = '1.0.0'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'exhale',
    'breathe',
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon'
]

templates_path = ['_templates']
exclude_patterns = []

breathe_projects = {
    "kernelXDK": "/usr/local/google/home/chanijindal/kernel-research/xml"
}
breathe_default_project = "kernelXDK"


exhale_args = {
    "containmentFolder":    "./api",  # The directory where the rst files will be generated
                                        # Relative to conf.py, e.g., docs/api/
    "rootFileName":         "library_root.rst", # The main rst file that lists all generated documentation
    "doxygenStripFromPath": "..",       # The path to strip from your Doxygen XML paths
                                        # This is usually the path from your Doxygen working directory
                                        # to your conf.py, so it can resolve source links correctly.
                                        # Common values are ".", "..", or "../../" depending on your setup.
    "rootFileTitle":        "Library API", # Title for the root generated file
    #"fullDependencies":    True,       # Whether to generate dependencies for all nodes
    "createTreeView":       True,       # Whether to create a file tree view of the generated documentation
    "unabridgedOrphanKinds": [
        "struct",
        "class",
        "enum",
        "variable",
        "define",
        "typedef",
    ],                                  # Kinds of objects to put into the root file,
                                        # even if they are documented elsewhere (e.g., in a file or namespace).
                                        # Helps ensure everything is listed.
}

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
