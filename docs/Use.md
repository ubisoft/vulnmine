# Running Vulnmine in Docker; Other notes for use

This article has code snippets and suggestions for running Vulnmine as well as doing development.

##   To start the docker container

```bash
cd ~/src/git/vulnmine/

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


### Proxy support

To build and run Vulnmine, there must be open access to the Internet.

Using the docker-compose.yml script provided should eliminate most, if not all, difficulties if you are behind a corporate proxy. However for this to work, the bash environment needs to be set with _http_proxy_ / _https_proxy_ variables (including any authentication credentials needed by the proxy.)

##   Inside the bash shell in the pyprod Docker container

Once the pyprod container is running, here is a list of the main directories:

```bash
jovyan@574694787c68:~/work$ ls -alF
total 4
drwxr-xr-x. 4 root   root     34 Aug  5 02:29 ./
drwxr-xr-x. 3 jovyan jovyan   69 Aug  5 02:25 ../
drwxrwxr-x. 5 jovyan jovyan   39 Aug  5 02:30 data/
drwxrwxr-x. 4 jovyan jovyan 4096 Aug  5 02:30 vulnmine/
jovyan@574694787c68:~/work$
jovyan@574694787c68:~/work$ ls -alF data/
total 8
drwxrwxr-x. 5 jovyan jovyan     39 Aug  5 02:30 ./
drwxr-xr-x. 4 root   root       34 Aug  5 02:29 ../
drwxrwxr-x. 2  15839 srm_sccm 4096 Aug  5 03:15 csv/
drwxr-xr-x. 2 jovyan jovyan   4096 Aug  5 02:31 nvd/
drwxr-xr-x. 2 jovyan jovyan    194 Aug  5 03:15 pck/
jovyan@574694787c68:~/work$
jovyan@574694787c68:~/work$ ls -alF vulnmine/
total 320
drwxrwxr-x. 4 jovyan jovyan  4096 Aug  5 02:30 ./
drwxr-xr-x. 4 root   root      34 Aug  5 02:29 ../
-rw-rw-r--. 1 jovyan jovyan    26 Aug  5 02:23 __init__.py
-rw-rw-r--. 1 jovyan jovyan   212 Aug  5 02:23 __main__.py
-rw-rw-r--. 1 jovyan jovyan  3484 Aug  5 02:23 gbls.py
-rw-rw-r--. 1 jovyan jovyan 37225 Aug  5 02:23 matchsft.py
-rw-rw-r--. 1 jovyan jovyan 20557 Aug  5 02:23 matchven.py
-rw-rw-r--. 1 jovyan jovyan 14873 Aug  5 02:23 ml.py
-rw-rw-r--. 1 jovyan jovyan 33995 Aug  5 02:23 nvd.py
drwxrwxr-x. 2 jovyan jovyan   136 Aug  5 02:30 plugins/
-rw-rw-r--. 1 jovyan jovyan 13936 Aug  5 02:23 sccm.py
-rw-rw-r--. 1 jovyan jovyan 11414 Aug  5 02:23 utils.py
-rw-rw-r--. 1 jovyan jovyan 10094 Aug  5 02:23 vulnmine.py
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
* "Key" errors start occurring.

The easiest way to synchronize everything is to start a bash shell in the pyprod container as described above, and then do a full 'all' run.


### Pinned versions of python software

The versions of the main Python librairies are pinned in the Requirements.txt file.

#### scikit-learn

In particular, scikit-learn is pinned.

The reason for this is that if the scikit-learn version changes, then the ML classification algorithms need to be retrained to produce new models. This process is described below.

#### python / pandas

If the python / pandas versions change, then all pickled data will most likely be no longer usable. Weird error messages will result that apparently have nothing to do with the real root cause. In particular, the test "base" files will need to be rebuilt.

### Same software as jupyter/scipy-notebook

Whenever the Vulnmine model training is done, the latest version of the following Docker Hub container is used: [jupyter/scipy-notebook](https://hub.docker.com/r/jupyter/scipy-notebook/) (on Docker Hub), see also [Jupyter's github repository](https://github.com/jupyter/docker-stacks).

(Note that this jupyter/scipy-notebook container does not necessarily have latest and greatest versions of all major libraries.)

The Vulnmine requirements.txt file pins all versions to be compatible with this Jupyter public container (python 3).

Quick commands:
```bash
# Run a cmd line in the Jupyter container
docker run -it --rm jupyter/scipy-notebook start.sh bash

# Start the iPython notebook server
docker run -d -p 8888:8888 -v ~/src/git/vulnmine:/home/jovyan/work jupyter/scipy-notebook start-notebook.sh
# find container id
docker ps
# look at logs to find specific URL for browser
docker logs CONTAINER-id
# browse to this URL
```

### Training models

Labelled data is provided for training the models (cf vulnmine_data/label*csv).

As mentioned above, when the python / pandas / scikit-learn versions change, the ML algorithms should be retrained. This will avoid compatibility issues.

Sample scipy iPython notebooks are included in the Vulnmine repository **_/vulnmine/ipynb_**. Html versions are in **_/docs/html_**.

These notebooks can be run on the Jupyter scipy-notebook container (python3) to produce new retrained model files.

### Docker housekeeping

Clean up the local Docker environment by running the following commands from time to time:

```bash
docker-compose down -v --remove-orphans
docker-compose rm -v -s

docker ps -a | grep Exited | awk '{print $1}' | xargs docker rm
docker rmi $(docker images -f "dangling=true" -q)
```

