import pytest
# from pandas.io.common import DtypeWarning
import pandas as pd
from context import gbls
from context import utils
from context import nvd
from context import sccm
from context import matchven
from context import matchsft
from context import vulns

class TestMatch:

    ######
    #   Fixtures for initialization of tests
    ######

    @pytest.fixture(scope='class')
    def init_matching(self):

        print('init_matching: Initialize for matching.')

        sft = sccm.SccmSoft()
        sft.load(mydir='data/df_match_sccm.pck')
        df_sft = sft.get()
        print ('Match tests: Software inventory file initialized')

        cpe = nvd.NvdCpe()
        cpe.load(mypck='data/df_match_cpe4.pck')
        df_cpe = cpe.get()
        print ('Match tests: NVD CPE file initialized')

        # Load cve dframe
        cve = nvd.NvdCve()
        cve.load(mypck="data/df_cve_base.pck")
        df_cve = cve.get()
        print ('Match tests: NVD CVE file initialized')

        # Vendor matching baseline comparison dframe
        match_vendor_base = matchven.MatchVendor()
        match_vendor_base.load(mypck='data/df_match_vendor_baseline.pck')
        df_match_vendor_base = match_vendor_base.get()
        print ('Match tests: Vendor match baseline dframe initialized')

        # Software matching baseline comparison dframe
        match_soft_base = matchsft.MatchSoft()
        match_soft_base.load(mypck='data/df_match_sft_baseline.pck')
        df_match_sft_base = match_soft_base.get()
        print ('Match tests: Software match baseline dframe initialized')


        return (
            df_sft,
            df_cpe,
            df_cve,
            df_match_vendor_base,
            df_match_sft_base
            )

    ######
    #   Test routines - matchven.MatchVendor
    ######

    def test_match_vendor(self, init_testenv, init_matching):
        """Test the vendor matching logic """
        if init_testenv != 'Initialized':
            exit('test_match_vendor - Initialization failed, exiting')

        (df_sft,
        df_cpe,
        df_cve,
        df_match_vendor_base,
        df_match_sft_base
        ) = init_matching

        # Fire up the code to be tested
        match_vendor = matchven.MatchVendor()

        match_vendor.match(
                    df_cpe,
                    df_sft
                    )
        df_match_vendor = match_vendor.get()

        # check equality
        assert df_match_vendor_base.equals(df_match_vendor)

    def test_match_soft(self, init_testenv, init_matching):
        """Test the software matching logic """
        if init_testenv != 'Initialized':
            exit('test_match_vendor - Initialization failed, exiting')

        (df_sft,
        df_cpe,
        df_cve,
        df_match_vendor_base,
        df_match_sft_base
        ) = init_matching

        # Fire up the code to be tested
        match_soft = matchsft.MatchSoft()

        match_soft.match(
                df_match_vendor_base,
                df_sft,
                df_cpe
                )
        df_match_sft = match_soft.get()

        # check equality
        assert df_match_sft_base.equals(df_match_sft)

        # Force failure for debugging o/p
        # assert False

    def test_match_vulns(self, init_testenv, init_matching):
        """Test the software matching logic """
        if init_testenv != 'Initialized':
            exit('test_match_vendor - Initialization failed, exiting')

        (df_sft,
        df_cpe,
        df_cve,
        df_match_vendor_base,
        df_match_sft_base
        ) = init_matching

        # Need hosts inventory as well
        hosts = sccm.SccmHosts()
        hosts.load(mydir="data/df_sys_base.pck")
        df_hosts = hosts.get()

        # Fire up the code to be tested
        match_vulns = vulns.MatchVulns()

        match_vulns.data_merge(
                df_cve,
                df_match_sft_base,
                df_sft,
                df_hosts
                )
        df_match_vulns = match_vulns.get()

        # Load baseline comparison dframe
        match_vulns_base = vulns.MatchVulns()
        match_vulns_base.load('data/df_match_vulns_baseline.pck')
        df_match_vulns_base = match_vulns_base.get()

        # check equality
        assert df_match_vulns_base.equals(df_match_vulns)

        # Force failure for debugging o/p
        # assert False
