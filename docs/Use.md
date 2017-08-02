# Running Vulnmine / Doing development

This article has code snippets and suggestions for running Vulnmine as well as doing development.

##   Start the docker container

```bash
source mygit/vulnmine-pub/compose/bin/activate

cd mygit/vulnmine-pub/

docker-compose run [-u "root"] --rm pyprod [bash]
```

See the main README.md file in the root directory for a description of Vulnmine commandline start options. To run all the function:

```bash
python vulnmine/__main__.py -a 'all'
```


### Docker-compose commands

Here are some basic commands for docker-compose:

Bring up the container and execute it:
```bash
docker-compose up
```

Take down the container and optionally remove the data volume:
```bash
docker-compose down [-v]
```

Clean up everything:
```bash
docker-compose rm -v
```

Look at the docker logs:
```bash
docker-compose logs
```

Rebuild the docker image:
```bash
docker-compose build [--pull]
```

Turn off the python virtualenv:
```bash
deactivate
```

### Proxy support

To build and run Vulnmine, there must be unfettered access to the Internet.

Using the docker-compose.yml script provided should eliminate most, if not all, difficulties if you are behind a corporate proxy. However for this to work, the bash environment needs to be set with _http_proxy_ / _https_proxy_ variables (including any authentication credentials needed by the proxy.)

##   Inside the bash shell in the pyprod Docker container

Once the pyprod container is running, here is a list of the main work directories:

```bash
jovyan@0d1ec2502487:~/work$ pwd
/home/jovyan/work
jovyan@0d1ec2502487:~/work$ ls -alF
total 88
drwxrwxr-x 9 jovyan jovyan  4096 Jan 15 22:12 ./
drwxr-xr-x 3 jovyan jovyan  4096 Jan 15 22:08 ../
drwxrwxr-x 2 jovyan jovyan  4096 Jan 15 21:19 conf/
drwxrwxr-x 2 jovyan jovyan  4096 Jan 15 21:19 csv/
drwxrwxr-x 2 jovyan jovyan 57344 Jan 15 21:19 models/
drwxrwxr-x 2 jovyan jovyan  4096 Jan 15 21:19 nvd/
drwxrwxr-x 2 jovyan jovyan  4096 Jan 15 21:19 pck/
drwxrwxr-x 4 jovyan jovyan  4096 Jan 15 21:19 scripts/
drwxrwxr-x 2 jovyan jovyan  4096 Jan 14 14:45 src/
```

As mentioned, these directories are integrated with the local repo directories on disk.

To run some python code:
```bash
python vulnmine/__main__.py -l 'debug' [-a 'all'] [-y 1]
```

To run "ad-hoc" python code e.g. to load a pandas dataframe and inspect the contents:
```bash
cd /home/jovyan/work/vulnmine
python
```

Here is some sample "ad hoc" code to load / sample contents of the df_sys dataframe:
```python
import pandas as pd
import numpy as np

import os
import sys

import sccm

# Load pickled baseline hosts dataframe for comparison
print("Initialize sccm dataframe.")
myhosts = sccm.SccmHosts()
myhosts.load(mydir="../data/pck/rf_df_sys.pck")
my_df_sys = myhosts_base.get()

my_df_sys.shape
my_df_sys.columns
my_df_sys.sample(10)
. . .
```


## Important notes

### Persistence of Pandas data frames

Note that Vulnmine stores a copy of each main processed Pandas data frame on disk (cf data/pck).

This allows execution to be restarted manually at arbitrary points in the workflow.

As development / testing progresses, care should be taken to keep the dataframe contents synchronized with the data/csv I/P files. Manually executing specific function (to speed up development) can sometimes cause data to become desynchronized. Running automated tests using the pytest framework can also cause desyncronization.

The classic symptoms are:

* Data starts "appearing" that should no longer be there.
* Key errors start occurring.

The easiest way to synchronize everything is to start a bash shell in the pyprod container as described above, and then do a full 'all' run.


### Pinned versions of python software

The versions of the main Python librairies are pinned in the Requirements.txt file.

#### scikit-learn

In particular, scikit-learn is pinned.

The reason for this is that if the scikit-learn version changes, then the ML classification algorithms should be retrained to produce new models. This process is described below.

#### python / pandas

If the python / pandas versions change, then all pickled data will most likely be no longer usable. Weird error messages will result that apparently have nothing to do with the real root cause.

### Long story short

In summary, whenever the Vulnmine model training is done, the latest version of the following Docker Hub container is used: [jupyter/scipy-notebook](https://hub.docker.com/r/jupyter/scipy-notebook/) (on Docker Hub), see also [Jupyter's github repository](https://github.com/jupyter/docker-stacks).

(Note that this jupyter/scipy-notebook container does not necessarily have latest and greatest versions of all major libraries.)

The Vulnmine requirements.txt file pins all versions to be compatible with this Jupyter public container (python 2).

### Training models

As mentioned above, when the python / pandas / scikit-learn versions change, the ML algorithms should be retrained. This will avoid compatibility issues.

Sample scipy iPython notebooks are included in the Vulnmine repository **_/docs/html_**.

These notebooks can be run on the Jupyter scipy-notebook container (python 2) to produce new retrained model files.

### Docker housekeeping

Clean up the local Docker environment by running the following commands from time to time:

```bash
docker-compose down -v --remove-orphans
docker-compose rm -v -s

docker ps -a | grep Exited | awk '{print $1}' | xargs docker rm
docker rmi $(docker images -f "dangling=true" -q)
```

