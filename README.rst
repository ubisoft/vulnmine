Vulnmine
========

Vulnmine uses simple Machine Learning to mine Microsoft's **SCCM** host
and software inventory data for **vulnerable 3rd-party software**.

**NIST's NVD** vulnerability feeds are pulled in on a daily basis to
determine the latest vulnerabilities to search for.

Running Vulnmine
----------------

There is a public container with test data ready for use on Docker Hub:
`lorgor/vulnmine <https://hub.docker.com/r/lorgor/vulnmine>`__

To download and run the Vulnmine container:

.. code:: bash

    docker run -it --rm lorgor/vulnmine bash

    python vulnmine/__main__.py -a 'all'

Commandline Start Options
~~~~~~~~~~~~~~~~~~~~~~~~~

Here are the possible options when starting Vulnmine:

::

    vulnmine.py  [-h] [--version] [-l Logging] [-a Action] [-y Years] [-w Workdir]

    -h --help             Help information
    -l --loglevel         Set desired verbosity for logging:
                            'debug','info','warning','error','critical'
    -a --action           Desired action to perform:
                                'rd_sccm_hosts'   Read SCCM host inventory data
                                'rd_sccm_sft'     Read SCCM software inventory
                                'rd_cpe'          Read/parse NIST CPE
                                                     vendor/product file
                                'rd_cve'          Read/parse NIST CVE
                                                     vulnerability data
                                'match_vendors'   Match SCCM publishers to NIST
                                                     CPE vendors
                                'match_sft'       Match SCCM software to NIST CPE
                                                     software
                                'upd_hots_vulns'  Produce consolidated host / vulnerable
                                                     software data
                                'output_stats'    Output statistics
    -y --years            Number of yrs of CVE vulnerability data to download. There is
                            one file for each year
    -w --workdir          Specify the working directory

Production mode
~~~~~~~~~~~~~~~

If no parameters are specified, then Vulnmine runs in *production mode*:

-  The main vulnmine.py starts and sets up an endless schedule loop.
-  The loop fires once daily by default.
-  Each day Vulnmine:

   -  Reads the SCCM inventory data files (UTF16 csv format) in the its
      CSV directory.
   -  Downloads updated NVD feed files.
   -  Processes the SCCM and NVD data.
   -  Produces output JSON files into the same csv directory.

Yet more information ...
------------------------

Where to get more information
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Vulnmine is on Github: https://github.com/lorgor/vulnmine
And on Docker Hub: https://hub.docker.com/r/lorgor/vulnmine/

The docs directory has the full Vulnmine documentation.


To install vulnmine directly
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Vulnmine can be installed using pip.

.. code:: bash

    pip install [-U] python-dev vulnmine


On Ubuntu at least, the python-dev library must be installed on
the system.

Change log
~~~~~~~~~~

**1.0**
    Initial release

**1.3.0**
    Alpha release of .INI configuration support, publish to PyPI

**1.4.0**
    Beta release
