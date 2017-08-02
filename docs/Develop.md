# Notes for vulnmine developers

This article gives some quick notes for people interested in customizing /
developing Vulnmine.

## Plugins

### Overview

There are two sample plugins provided in the  _vulnmine/plugins_ directory:

* _plugin1.py_: Shows how complementary information can be used to augment the
SCCM host record.
* _plugin2.py_: Shows how to produce customized statistics and output files.

The plugins use the [python yapsy framework](http://yapsy.sourceforge.net/)

Plugins are defined using the _*.yapsy-plugin_ files (also in the _plugins_ directory.)

In Vulnmine, plugins are loaded by _util.py_'s _load_plugins()_ function. The plugin
manager object is initialized there.

The mainline vulnmine.py calls the plugins (in the _rd_sccm_hosts()_ and
_output_stats()_ functions.)

### Plugin Interaction with Vulnmine class objects

Plugins can access the main Vulnmine class objects:

* The object instance is passed to the plugin as an I/P parameter. The safest
approach is for the plugin to load the pickled version of the class object, then
call the object's "get()" method. This provides a copy of the object's pandas
dataframe to the plugin.

* The plugin code can modify the object contents. This includes adding new
custom columns to the object's dataframe. The sample plugin1.py provided
has examples of this.

* The custom fields added to the SccmHost object's dataframe pass through the
processing and show up in the final consolidated dataframe. The sample
plugin2.py then uses these custom fields to produce site-specific statistics.

### Plugin Input / Output

Plugin code can also read input data sets and print output.

For simplicity, python "print()" is used.

## The test data

Realistic test data is provided with the released code. This section
gives a basic description of this data

### The organization "mycorp.com"

The "mycorp.com" company has 4 sites: **North, South, East, West**

There are two regions:  **A** (sites North, West) and **B** (sites South, East).

 In the organization's Active Directory:

 * VIP people's desktops / laptops are in the AD group **"VIP"**.

 * **Desktops, laptops, and servers** are grouped each in their own OUs. This is
reflected in the host's Distinguished Name.

In general, older vulnerable software was used to build the test data. However
the NIST NVD data was the most recent available at the time. This ensured that
lots of vulnerabilities would be found.

### The input data sets

The corresponding input data flat files are all found in _data/csv_:

* __v_R_System_.csv__:  The CSV version of the corresponding SCCM view.
* __v_GS_ADD_REMOVE_PROGRAMS / _64__: Idem

* __ps-ad-vip.csv__: A CSV flat file containing the contents of the AD host group
"VIP" which contains VIP PCs.

## Publishing on PyPI

This section documents commands used to build / publish the PyPI version of vulnmine.

Setup a virtualenv in the test directory. Copy test data to the test environment.
Install software for building, uploading python to PyPI, converting to python3.

```bash
mkdir -p ~/wip/vulnmine/test/data/csv
cd ~/wip/vulnmine/
virtualenv vulnmine-py2
source ~/wip/vulnmine/vulnmine-py2/bin/activate
pip install -U pip coverage \
future pylint caniusepython3 tox \
setuptools wheel twine  pypandoc

cd ~/src/git/vulnmine-pub/tests/data
cp ./ps-ad-vip.csv ~/wip/vulnmine/test/data/csv/
cp ./df_sys_base.csv ~/wip/vulnmine/test/data/csv/v_R_System.csv
cp ./df_v_gs_add_rem_base_x64.csv \
  ~/wip/vulnmine/test/data/csv/v_GS_ADD_REMOVE_PROGRAMS_64.csv
cp ./df_v_gs_add_rem_base_x86.csv \
  ~/wip/vulnmine/test/data/csv/v_GS_ADD_REMOVE_PROGRAMS.csv
```


## Different ways to run the code

Note that there are 4 different modes in which the code can run:
1. In a docker container in normal execution.
2. In a docker container running the tests.
3. In the source code directory directly (as a module)
4. In a test directory, running the packaged module.

### Running in Docker

This has been described elsewhere (see _docs/Use.md_ and _docs/Tests.md_).

### Running as a packaged module in a test directory.

The following is used to to test a new version of the PyPI package locally. Note that before tests can run directly from the source code, the tarball has to be installed in the virtualenv at least once in order to pick up the requirements.

```bash
# Move to the git source directory
cd ~/src/git/vulnmine-pub
rm -rf dist build

# Build the new version
python setup.py sdist
python setup.py bdist_wheel

# Activate the test environment (if not already done)
source ~/wip/vulnmine/vulnmine-py2/bin/activate

# Move to the test directory and install from the source tarball
cd ~/wip/vulnmine/test

# To retest, uninstall the current version
pip uninstall vulnmine

# Install new version to be tested
pip install ~/src/git/vulnmine-pub/dist/vulnmine-1.0.3.tar.gz

# Run the new installed version
#python ../vulnmine-py2/lib/python2.7/site-packages/vulnmine/vulnmine.py -a rd_sccm_hosts -l debug -y 1

python -m vulnmine -a rd_sccm_hosts -l debug -y 1

# When all is working, upload to PyPI
cd ~/src/git/vulnmine-pub/
twine upload dist/*
```


To run directly as a module in the source code repository:
```bash
cd ~/src/git/vulnmine-pub
python -m vulnmine --help
```