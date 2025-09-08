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

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'kernelXDK'
copyright = '2025, Google'
author = 'Google'
release = '0.0.1'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'exhale',
    'breathe',
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinxcontrib.mermaid',
    'myst_parser',
]

templates_path = ['_templates']
exclude_patterns = []

breathe_projects = {
    "kernelXDK": "../_build/xml"
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

source_suffix = {
    '.rst': 'restructuredtext',
    '.txt': 'markdown',
    '.md': 'markdown',
}

myst_fence_as_directive = ["mermaid"]
