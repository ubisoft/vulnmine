# Use test code to dummy up an environment to be able to produce
# baseline dataframes. Offload to csv for manual verification.

# This rtn rebuilds sccm, nvd test data sets.

from yapsy.PluginManager import PluginManager
import logging
from context import gbls
from context import utils
from context import sccm
from context import nvd

# Initialize execution environment including logging
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
    print ('Initialized')
    return None

# Bypass this test unless specifically needed

# Rebuild packed data sets for test baseline comparison by essentially
# doing the test runs in reverse

######
######==================NB NB
# Comment the following line to activate this test
######==================NB NB
######

@pytest.mark.skip(reason="Only run if rebuilding baseline test data.")

def test_run():

    init_testenv()

    # Read in and process hosts baseline test i/p file
    hosts = sccm.SccmHosts()
    hosts.read(mydir='data/df_sys_base.csv')
    hosts.save()

    gbls.ad_vip_grps = 'data/ps-ad-vip.csv'

    # Invoke Input plugin for customized I/P data
    plugin1 = gbls.plugin_manager.getPluginByName(gbls.PLUGINIP)
    plugin1.plugin_object.modify_hosts(hosts)

    df_hosts = hosts.get()
    df_hosts.to_pickle('data/df_sys_base.pck')
    print ('Hosts file initialized')

    # Read in sccm software inventory files
    sft = sccm.SccmSoft()
    sft.read(
        mydir_x86='data/df_v_gs_add_rem_base_x86.csv',
        mydir_x64='data/df_v_gs_add_rem_base_x64.csv',
        )
    df_sft = sft.get()
    df_sft.to_pickle('data/df_v_gs_add_rem_base.pck')
    print ('Software file initialized')

    # use edited CPE file to produce a packed dataframe for baseline
    # comparison

    # Convert the i/p XML file to a dataframe
    cpe = nvd.NvdCpe()
    cpe.read(my_cpe='data/official-cpe-dictionary_v2.3.base.xml')
    df_cpe = cpe.get()
    df_cpe.to_pickle('data/df_cpe4_base.pck')
    print ('NVD CPE file initialized')

    # use CVE I/P file to produce a packed dataframe for baseline
    # comparison

    cve = nvd.NvdCve()
    df_cve = cve.read(my_dir='data/')
    df_cve = cve.get()
    df_cve.to_pickle("data/df_cve_base.pck")
    print ('NVD CVE file initialized')

    # Force error see o/p
    assert False
