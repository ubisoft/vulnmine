import pytest
# from pandas.io.common import DtypeWarning
from yapsy.PluginManager import PluginManager
import pandas as pd
from context import gbls
from context import utils
from context import sccm

class TestSccm:

    ######
    #   Test routines - sccm.SccmHosts
    ######

    def test_read_hosts(self, init_testenv):
        if init_testenv != "Initialized":
            exit('sccm - Initialization failed, exiting')

        # Load pickled baseline hosts dataframe for comparison
        print("init_sccm_hosts: Initialize for sccm host tests.")
        hosts_base = sccm.SccmHosts()
        hosts_base.load(mydir="data/df_sys_base.pck")
        df_sys_base = hosts_base.get()

        # Read in fresh raw CSV data
        hosts = sccm.SccmHosts()
        # with pytest.raises(DtypeWarning):
        hosts.read(mydir="data/df_sys_base.csv")
        hosts.save()

        # Force test AD groups
        gbls.ad_vip_grps = 'data/ps-ad-vip.csv'

        # Invoke Input plugin for customized I/P data
        plugin1 = gbls.plugin_manager.getPluginByName(gbls.PLUGINIP)
        plugin1.plugin_object.modify_hosts(hosts)

        # Get final updated dframe which plugin has saved
        hosts.load()
        df_sys = hosts.get()

        # Verify that all values all equal
        assert df_sys.equals(df_sys_base)

    ######
    #   Test routines - sccm.SccmSoft
    ######

    def test_sccm_sft(self, init_testenv):

        if init_testenv != "Initialized":
            exit('sccm - Initialization failed, exiting')

        # Load pickled baseline hosts dataframe for comparison
        print("init_sccm_sft: Initialize for sccm sft tests.")
        sft_base = sccm.SccmSoft()
        sft_base.load(mydir="data/df_v_gs_add_rem_base.pck")

        # Read in fresh software inventory data.
        sft = sccm.SccmSoft()
        sft.read(
            mydir_x86="data/df_v_gs_add_rem_base_x86.csv",
            mydir_x64="data/df_v_gs_add_rem_base_x64.csv",
            )

        # Check same number of sft records read as in base dframe
        assert sft_base.df_add_rem_g.shape == sft.df_add_rem_g.shape

        # Need to reset indices to have dataframes test equal
        df1 = sft_base.df_add_rem_g.reset_index(drop=True)
        df2 = sft.df_add_rem_g.reset_index(drop=True)

        assert df1.equals(df2)
