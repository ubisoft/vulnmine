# README #

This README describes where to find things. It also gives an overview of the basic steps which are necessary to install vulnmine, develop code, as well as implement in production.

## What is this repository for?

Vulnmine mines SCCM host and software inventory data using NIST's NVD data sets.

* The NIST data sets used are:
    - The CPE vendor / product dictionary
    - The NVD vulnerability feeds.
* The SCCM views accessed are:
    - v_R_System
    - v_GS_ADD_REMOVE_PROGRAMS and v_GS_ADD_REMOVE_PROGRAMS_64

This is Vulnmine v1.0.

## Where to find things

* **/docs** Documentation
* **/vulnmine** The vulnmine source code
    - _/plugins:_ The plugin directory
    - _/vulnmine_data_: Default configuration data
* **/tests** The automated pytest framework code and data
* **/data** Configuration and other files used by vulnmine:
    - _/conf:_ Vulnmine configuration files
    - _/csv:_ Input csv files are placed here. Processing will result in output JSON files that are also put here.
    - _/models:_ The Machine Learning models. There is one for vendor matching, and one for software matching.
    - _/nvd:_ The files downloaded from the NIST NVD web site each day.
    - _/pck:_ Intermediate pandas data frame as pickled flat files. These are kept here for persistence use.
* **/samples** Templates and sample code for production use.
    - _/ansible:_ Configuration / scripts to do a full production deployment using Ansible
    - _/ansible_docker:_ Sample docker configuration to build a working Ansible docker container
    - _/scripts:_ Powershell scripts used in production to:
        - Dump SCCM views as CSV flat files.
        - Output relevant Active Directory data as CSV flat files.
        - scp the CSV flat files to the Vulnmine Linux server.

## Installation: How do I get set up?

There are two basic setups possible.

### 1) If you just want to try Vulnmine:

A standalone container is available on Docker Hub. See the main README.md file in the root directory for instructions.

### 2) You want to develop or do more extensive testing.

The recommended approach is to use docker-compose to automate local docker use.

The _docker-compose.yml_ configuration provided fully integrates the local repository contents with the container. This gives a developer full control to:
- Update source
- Run automated tests
- Inspect output file contents.

For detailed instructions, see:
* **docs/Installation.md**: Initial setup / installation instructions:
* **docs/Quickstart.md**: How to run Vulnmine tests using docker-compose.
* **docs/Develop.md**: Notes for developers

### Dependencies

Vulnmine only runs on python V2 (for now! :-( ).
Dependencies are documented in requirements.txt.

### Production configuration

In production, there will normally be two servers:
* **Windows server**
    * Dumps the MS SCCM views, and (optionally) read selected AD data.
    * Scp the data to the Vulnmine Linux server
* **Linux server**
    * Runs Vulnmine's docker container.

The samples/ directory has a detailed Ansible template to show how the production environment could be configured.

## Contribution guidelines

See **doc/CONTRIBUTING.md** for the contribution guidelines.

## Markdown

The documentation is formatted using markdown.
Markdown files end in ".md" by convention.

[Learn Markdown](https://bitbucket.org/tutorials/markdowndemo)
