# Vulnmine Installation

There are two ways to install vulnmine:

* Directly using pip (and virtualenv)
* In a Docker container.

## Installing directly with pip

Vulnmine can be installed using pip.
On Ubuntu at least, python-dev needs to be installed (to compile python-levenshtein).

Since vulnmine has several large pre-requisites, probably you will want to use a virtualenv for installation.

```bash
pip install [-U] python-dev vulnmine
```

## Building a Docker container with vulnmine

The following installation instructions describe how to build a local container and set up a fully integrated development environment.

### Pre-requisites

First of all:

1) [Install docker](https://docs.docker.com/engine/installation/)
2) [Install virtualenv](https://docs.docker.com/engine/installation/)
3) Install git and clone this repository from github.

### Install docker-compose, pytest

Suppose that the vulnmine public github repository was cloned into the local respository _mygit/vulnmine-pub_.

Then in the _mygit/vulnmine-pub_ directory:

```bash
mkdir compose

virtualenv compose
source compose/bin/activate

pip install -U pip
pip install -U docker-compose
pip install -U pytest
```

Note: Be sure to install and use **python2** not python 3.

### Build the local docker container

The following will build the local vulnmine docker container.

Note that this container will be named **pyprod**, not vulnmine. This is to avoid confusion with the public container on Docker Hub.

```bash
cd mygit/vulnmine-pub/
docker-compose build
```

Note the pyprod container is fully integrated with the local repository directories on disk. For example, in the pyprod container:

* _/home/jovyan/work/csv/_ will access _mygit/vulnmine-pub/data/csv_
* _/home/jovyan/work/src/_ will access _mygit/vulnmine-pub/vulnmine_

### Run the automated tests

Test that the installation is working correctly by running the automated tests:

```bash
docker-compose run --rm pyprod bash
cd tests
pytest
```

## Instructions for running Vulnmine, developing, testing

See the following for more information:

* **/doc/Use.md**: Guidelines for using Vulnmine.
* **/doc/Tests.md**: Instructions on running tests.
* **/doc/Develop.md**: Notes for developers

