######
#   Initialize for testing
######

import pytest
import logging
from context import gbls
from context import utils

# Initialize execution environment including logging
@pytest.fixture(scope="module")
def init_testenv():
    print("init_testenv: Initialize execution environment.")

    gbls.wkdir = '/home/jovyan/work/'
    utils.init_globals()

    gbls.loglvl = gbls.LEVELS.get(
            'debug',
            logging.NOTSET
            )
    logging.basicConfig(level=gbls.loglvl)
    logger = logging.getLogger(__name__)
    logger.setLevel(gbls.loglvl)
    utils.load_plugins()
    return 'Initialized'

