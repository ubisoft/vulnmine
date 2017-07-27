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

+------------+------+
| Parameter  | Use  |
+============+======+
| -h         | Help |
|            | info |
|            | rmat |
|            | ion  |
+------------+------+
| -help      |      |
+------------+------+
|            |      |
+------------+------+
| -l         | Set  |
|            | desi |
|            | red  |
|            | verb |
|            | osit |
|            | y    |
|            | for  |
|            | logg |
|            | ing: |
+------------+------+
| --loglevel | *deb |
|            | ug*  |
|            | *inf |
|            | o*   |
|            | *war |
|            | ning |
|            | *    |
|            | *err |
|            | or*  |
|            | *cri |
|            | tica |
|            | l*   |
+------------+------+
|            |      |
+------------+------+
| -a         | Desi |
|            | red  |
|            | acti |
|            | on   |
|            | to   |
|            | perf |
|            | orm: |
+------------+------+
| --action   | *rd\ |
|            | _scc |
|            | m\_h |
|            | osts |
|            | :*   |
|            | Read |
|            | SCCM |
|            | host |
|            | data |
+------------+------+
|            | *rd\ |
|            | _scc |
|            | m\_s |
|            | ft:* |
|            | Read |
|            | SCCM |
|            | soft |
|            | ware |
|            | data |
+------------+------+
|            | *rd\ |
|            | _cpe |
|            | :*   |
|            | Down |
|            | load |
|            | /    |
|            | inpu |
|            | t    |
|            | NIST |
|            | CPE  |
|            | Vend |
|            | or-P |
|            | rodu |
|            | ct   |
|            | dict |
|            | iona |
|            | ry   |
+------------+------+
|            | *rd\ |
|            | _cve |
|            | :*   |
|            | Down |
|            | load |
|            | /    |
|            | inpu |
|            | t    |
|            | NIST |
|            | CVE  |
|            | Vuln |
|            | erab |
|            | ilit |
|            | y    |
|            | feed |
|            | data |
+------------+------+
|            | *mat |
|            | ch\_ |
|            | vend |
|            | ors: |
|            | *    |
+------------+------+
|            | Matc |
|            | h    |
|            | vend |
|            | ors  |
|            | from |
|            | SCCM |
|            | "Add |
|            | -Rem |
|            | ove" |
|            | regi |
|            | stry |
|            | data |
|            | to   |
|            | NVD  |
|            | CPE  |
|            | data |
+------------+------+
|            | *mat |
|            | ch\_ |
|            | sft: |
|            | *    |
+------------+------+
|            | Matc |
|            | h    |
|            | soft |
|            | ware |
|            | from |
|            | SCCM |
|            | "Add |
|            | -Rem |
|            | ove" |
|            | regi |
|            | stry |
|            | data |
|            | to   |
|            | NVD  |
|            | CPE  |
|            | data |
+------------+------+
|            | *upd |
|            | \_ho |
|            | sts\ |
|            | _vul |
|            | ns:* |
|            | Dete |
|            | rmin |
|            | e    |
|            | vuln |
|            | erab |
|            | ilit |
|            | ies  |
|            | for  |
|            | each |
|            | host |
|            | in   |
|            | SCCM |
+------------+------+
|            | *out |
|            | put\ |
|            | _sta |
|            | ts:* |
|            | Outp |
|            | ut   |
|            | the  |
|            | resu |
|            | lts  |
+------------+------+
|            | *all |
|            | :*   |
|            | Run  |
|            | all  |
|            | the  |
|            | abov |
|            | e    |
|            | in   |
|            | sequ |
|            | ence |
+------------+------+
|            |      |
+------------+------+
| -y         | Numb |
|            | er   |
|            | of   |
|            | year |
|            | s    |
|            | to   |
|            | down |
|            | load |
|            | .    |
|            | Ther |
|            | e    |
|            | is   |
|            | one  |
|            | CVE  |
|            | feed |
|            | file |
|            | for  |
|            | each |
|            | year |
|            | 's   |
|            | data |
|            | .    |
+------------+------+
| --years    |      |
+------------+------+
|            |      |
+------------+------+
| -w         | Spec |
|            | ifie |
|            | s    |
|            | work |
|            | dire |
|            | ctor |
|            | y    |
+------------+------+
| --workdir  |      |
+------------+------+

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
