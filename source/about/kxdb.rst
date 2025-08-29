KXDB
=============

A database builder which contains exploitation information (symbol addresses, ROP gadgets, stack pivots, structure field offsets) for multiple kernel targets and consumed by the exploit kit to customize exploits for targets.

The recommended extension for the target db file: ``.kpwn``.

Prerequisites
--------------

* ``rop_generator`` (part of the kernel-researcher tools)
----

Usage
------

.. code-block:: none

    ./kpwn_db.py
      [--image-db-path=<path to the image_db tool to add targets from>]
      [--release-filter=<regex for distro/release_name>]
      [--input-file=<full file path to the source target_db.{kpwn,json,yaml}>]
      [--output-file=<full file path to the destination target_db.{kpwn,json,yaml}>]
      [--indent=<int, json indent>]
      [--log-level=<DEBUG|INFO|WARNING|ERROR|CRITICAL>]

-----

Arguments
----------

* ``input-file`` (optional): location of the current database to convert or extend. Supported file formats: kpwn, json, yaml.

* ``output-file`` (required): where to save the resulting database. Supported file formats: kpwn, json, yaml.

* ``image-db-path`` (optional): location of the ``image_db`` folder. If supplied then its targets will be added to the database.

* ``release-filter`` (optional): regex expression to filter which releases to process from ``image_db``, e.g. ``lts-6.1.81`` or ``kernelctf/lts-6.1.81`` or ``kernelctf/.*``. By default, there is no filter, so all downloaded releases will be part of the database.

You need to specify either ``input-file`` (to convert) or ``image-db-path`` (to build from), but you can also specify both (to extend).

If you specify ``input-file`` then the configuration will be reused from that file, otherwise the default configuration (from ``config.py``) will be used.

-----

Example usages
---------------

Processes all downloaded releases from the ``../image_db`` folder and extends the ``target_db.kpwn`` database with these new releases:

.. code-block:: none

    ./kpwn_db.py --image-db-path ../image_db -i target_db.kpwn -o  target_db.kpwn

Processes only the ``kernelctf/lts-6.1.81`` release from the ``../image_db/releases`` folder and save the resulting database to the ``../expkit/test/artifacts/target_db_lts-6.1.81.kpwn`` file:

.. code-block:: none

    ./kpwn_db.py --image-db-path ../image_db --release-filter lts-6.1.81 --output-path ../expkit/test/artifacts/target_db_lts-6.1.81.kpwn


Processes all downloaded releases from ``../image_db`` and save the resulting database to ``target_db.kpwn``:

.. code-block:: none

    ./kpwn_db.py --image-db-path ../image_db -o target_db.kpwn

Converts the database from a binary format (``.kpwn``) to JSON:

.. code-block:: none

    ./kpwn_db.py -i target_db.kpwn -o target_db.json
