# Use test code to dummy up an environment to be able to produce
# baseline dataframes. Offload to csv for manual verification.

# This rtn rebuilds match data sets, execution is quite long.

import logging
from context import gbls
from context import utils
from context import sccm
from context import nvd
from context import matchven
from context import matchsft
from context import vulns

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

    # initialize data for match tests

    cpe = nvd.NvdCpe()
    cpe.read(my_cpe='data/match_official-cpe-dictionary_v2.3.xml')
    df_cpe = cpe.get()
    df_cpe.to_pickle('data/df_match_cpe4.pck')
    print ('Match tests: NVD CPE file initialized')

    sft = sccm.SccmSoft()
    sft.read(
        mydir_x86='data/df_match_sccm_86.csv',
        mydir_x64='data/df_match_sccm_64.csv',
        )
    df_sft = sft.get()
    df_sft.to_pickle('data/df_match_sccm.pck')
    print ('Match tests: Software file initialized')

    # Run vendor matching

    match_vendor = matchven.MatchVendor()

    match_vendor.match(
                df_cpe,
                df_sft
                )
    df_match_vendor = match_vendor.get()
    df_match_vendor.to_pickle('data/df_match_vendor_baseline.pck')
    print ('Match tests: Vendor match dframe initialized')

    # Run software matching.

    # - First load cve dframe

    cve_base = nvd.NvdCve()
    cve_base.load(mypck="data/df_cve_base.pck")
    df_cve = cve_base.get()

    match_soft = matchsft.MatchSoft()

    match_soft.match(
            df_match_vendor,
            df_sft,
            df_cpe
            )
    df_match_sft = match_soft.get()
    df_match_sft.to_pickle('data/df_match_sft_baseline.pck')
    print ('Match tests: Software match dframe initialized')

    # Match vulns to software

    # - First load hosts dframe

    hosts_base = sccm.SccmHosts()
    hosts_base.load(mydir="data/df_sys_base.pck")
    df_hosts = hosts_base.get()

    match_vulns = vulns.MatchVulns()

    match_vulns.data_merge(
                df_cve,
                df_match_sft,
                df_sft,
                df_hosts
                )

    df_match_vulns = match_vulns.get()
    df_match_vulns.to_pickle('data/df_match_vulns_baseline.pck')
    print ('Match tests: Vuln match dframe initialized')

    # Force error see o/p
    assert False
