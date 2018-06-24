import logging
import argparse
import sys
import os
import schedule
import time
import functools
from yapsy.PluginManager import PluginManager

from . import vulnmine

# Run the pkg as a script
sys.exit(vulnmine.main())