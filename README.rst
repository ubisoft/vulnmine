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

    python src/vulnmine.py -a 'all'

Commandline Start Options
~~~~~~~~~~~~~~~~~~~~~~~~~

Here are the possible options when starting Vulnmine:

::

    vulnmine.py  [-h] [--version] [-l Logging] [-a Action] [-y Years] [-w Workdir]

+------------+-----------------+
| Parameter  | Use             |
+============+=================+
| -h         | Help information|
| --help     |                 |
+------------+-----------------+
| -l         | Set desired     |
|            | verbosity for   |
|            | logging:        |
| --loglevel | - debug         |
|            | - info          | 
|            | - warning       |
|            | - error         |
|            | - critical      |
+------------+-----------------+
| -a         | Desired action  |
|            | to perform:     |
| --action   | - rd_sccm_hosts |
|            |   (Read SCCM    |
|            |    host data)   |
|            | - rd_sccm_sft   |
|            |   (Read SCCM    |
|            |    software     |
|            |    data)        |
|            | - rd_cpe        |
|            |   (Download NIST|
|            |    CPE file)    |
|            | - rd_cve        |
|            |   (Download NIST|
|            |    CVE files    |
|            | - match_vendors |
|            |   (Match vendors|
|            |   from SCCM A/R |
|            |   registry to   |
|            |   NIST CPE data |
|            | - match_sft     |
|            |   (Match sftware|
|            |    from SCCM to |
|            |    NIST)        |
|            | -upd_hosts_vulns|
|            |   (Produce      |
|            |    consolidated | 
|            |    host / vuln  |
|            |    data)        |
|            | - output_stats  |
|            | - all           |
|            |   (Run all the  |
|            |    above)       |
+------------+-----------------+
| -y         | Number of years |
| --years    | to download     |
|            | There is one CVE|
|            | file/year       |
+------------+-----------------+
| -w         | Specifies       |
| --workdir  | working         |
|            | directory       |
+------------+-----------------+

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

Where to get more information
-----------------------------

Vulnmine is on Github: https://github.com/lorgor/vulnmine

The docs directory has the full Vulnmine documentation.
