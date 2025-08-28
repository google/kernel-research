Kernel Image Tools
==================

This component contains tools to download and process Kernel images. In addition it contains scripts to run these images in a virtualized environment.

Kernel Image Database
---------------------

`image_db` is responsible for downloading kernel distro files and managing a local database of kernel images. It provides a structured way to store and retrieve different kernel versions and configurations.

Kernel Image Runner
-------------------

The `image_runner` is a tool for running various kernel distribution images. It supports features for kernel exploitation, including debugging capabilities and the ability to compile custom kernel modules directly within the provisioned environment.
