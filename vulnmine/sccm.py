"""Input / Process SCCM host and software data.

Purpose
=======

The sccm module inputs, parses, persists SCCM host and software data.

Public classes
==============

SccmHosts       SCCM Hosts class
SccmSoft        SCCM Software class

"""
import pandas as pd
import sys
import logging

import gbls
import utils

# Public classes
__all__ = (
        'SccmHosts',
        'SccmSoft'
        )


class SccmHosts(object):
    """Input, parse, persist SCCM-managed host data.

    Methods
    -------
    __init__    Class constructor to configure logging, initialize empty data
                frame
    read        Input the raw SCCM CSV file. Clean data. Remove columns.
    load        Load hosts dataframe from the pickled file.
    save        Save the hosts dataframe to the corresponding pickled file.
    get         Return a *copy* of the hosts dataframe.

    Restrictions
    ------------
    The class instance variable self.df_sys should not be accessed directly
    by external callers.

    """

    def __init__(self, mylogger=None):
        """Initialize class by configuring logging,  initializing dataframe.

        This is the class constructor. It initializes logging and allocates
        an empty dataframe to contain sccm hosts data.

        I/P Parameters
        --------------
        mylogger    logging object. If None, then a new object is initialzed.

        """
        # Configure logging

        if mylogger is None:
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(gbls.loglvl)
        else:
            self.logger = mylogger

        self.logger.debug('\n\nInitializing SccmHosts class\n\n')

        self.df_sys = pd.DataFrame({
            'ResourceID': []
            })

    def read(self, mydir=None):
        """Read the raw SCCM CSV host data.

        Actions
        =======

        Reads v_R_System view raw data. v_R_System is the SCCM view
        listing managed hosts.

        Cleans data:
            * Remove extraneous columns
            * Only keep valid entries; remove unmanaged / inactive hosts.

        Exceptions
        ==========
        IOError     Produce a message, then ignore.
        """
        # Read the i/p raw CSV file containing extracted SCCM software data

        self.logger.info('\n\nEntering SccmHosts.read_csv()\n\n')

        if mydir is None:
            mydir = gbls.v_r_system

        self.logger.debug(
                        'Reading file {0},\nsep: {1}\n\n'.format(
                                mydir,
                                gbls.SEP)
                        )

        try:
            df_sys_tmp = pd.io.parsers.read_csv(
                                    mydir,
                                    sep=gbls.SEP,
                                    error_bad_lines=False,
                                    warn_bad_lines=True,
                                    quotechar='"',
                                    encoding='utf-16')
            # Note the use of utf-16 for this data.
        except IOError as e:
            self.logger.critical('\n\n***I/O error({0}): {1}\n\n'.format(
                        e.errno, e.strerror))

        # except ValueError:
        #    self.logger.critical('Could not convert data to an integer.')
        except:
            self.logger.critical(
                '\n\n***Unexpected error: {0}\n\n'.format(
                    sys.exc_info()[0]))
            raise

        # Only keep interesting columns

        self.df_sys = df_sys_tmp.loc[
                            :, [
                                'ResourceID',
                                'Active0',
                                'AD_Site_Name0',
                                'Distinguished_Name0',
                                'Resource_Domain_OR_Workgr0'
                                ]]

        # Convert site data to a pandas category
        self.df_sys['Site_X'] = self.df_sys[
                                    'AD_Site_Name0'
                                    ].astype('category')

        # Remove inactive hosts
        self.df_sys = self.df_sys[self.df_sys.Active0 > 0]

        # self.logger.debug() basic information
        self.logger.debug('\nv_R_System: \n{0}\n{1}\n\n'.format(
            self.df_sys.shape,
            self.df_sys.columns))
        return None

    def load(self, mydir=None):
        """Load hosts dataframe that was previously pickled."""
        self.logger.info(
            '\n\nLoading v_R_System into '
            'SccmHosts.df_sys dataframe\n\n'
            )

        if mydir is None:
            mydir = gbls.df_sys_pck

        self.df_sys = pd.read_pickle(mydir)
        return None

    def save(self):
        """Save hosts dataframe in a serialized pickle flat file."""
        self.logger.info('\n\nSaving SccmHosts.df_sys dataframe\n\n')
        self.df_sys.to_pickle(gbls.df_sys_pck)
        return None

    def get(self):
        """Return a *copy* of the main hosts dataframe."""
        df_tmp = self.df_sys.copy()
        self.logger.info(
                '\n\n Get SccmHosts.df_sys: \n{0}\n{1}\n\n'.format(
                                df_tmp.shape,
                                df_tmp.columns
                                )
                )
        return df_tmp


class SccmSoft(object):
    """Read, process, persist SCCM Software inventory data.

    Actions
    =======
    The data extracted from the SCCM views v_gs_add_rem_pgms and
    v_gs_add_rem_pgms_64 is input and processed into a dataframe.

    Methods
    =======
    __init__    Class constructor to configure logging, initialize empty data
                frame
    read        Input the raw SCCM CSV file. Clean data and save in dataframe.
    load        Load hosts dataframe from the pickled file.
    save        Save the hosts dataframe to the corresponding pickled file.
    get         Return a *copy* of the hosts dataframe.

    """

    def __init__(self, mylogger=None):
        """Initialize class by configuring logging,  initializing dataframe.

        This is the class constructor. It initializes logging and allocates
        an empty dataframe to contain sccm software data.

        I/P Parameters
        --------------
        mylogger    logging object. If None, then a new object is initialzed.

        """
        # Configure logging

        if mylogger is None:
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(gbls.loglvl)
        else:
            self.logger = mylogger

        self.logger.debug('\n\nInitializing SccmSoft Class\n\n')

        # Empty dataframe

        self.df_add_rem_g_empty = pd.DataFrame({
            #   Fields in SCCM software record
            'ResourceID': [],
            'AgentID': [],
            'DisplayName0': [],
            'GroupID': [],
            'InstallDate0': [],
            'ProdID0': [],
            'Publisher0': [],
            'RevisionID': [],
            'TimeStamp': [],
            'Version0': [],

            #   Fields added during processing
            'arch_X': []
            })

        # Initialize to empty dataframe
        self.df_add_rem_g = self.df_add_rem_g_empty

    def read(self, mydir_x86=None, mydir_x64=None):
        """Read the raw SCCM CSV host data.

        Actions
        =======

        Reads v_GS_ADD_REMOVE_PROGRAMS and  v_GS_ADD_REMOVE_PROGRAMS_64 view
        raw data. These SCCM view list software installed on each managed
        host.

        The two tables are consolidated into one.

        A field is added to show the processor architecture.

        Entries with missing Publisher0 or DisplayName0 values are dropped
        since these records are not usable in any case.

        Microsoft inventory data is also dropped since MS software inventory /
        vuln information can be handled more efficiently using MS-specific
        files.

        Exceptions
        ==========
        IOError     Produce a message, then ignore.

        """
        self.logger.info('\n\nEntering SccmSoft.read()\n\n')

        if mydir_x86 is None:
            mydir_x86 = gbls.v_gs_add_rem_pgms

        if mydir_x64 is None:
            mydir_x64 = gbls.v_gs_add_rem_pgms_64


        self.logger.debug(
                            'files {0} \n   {1} \n   sep: {2}'.format(
                                mydir_x86,
                                mydir_x64,
                                gbls.SEP
                                )
                            )

        try:
            df_v_gs_add_rem_tmp = pd.io.parsers.read_csv(
                    mydir_x86,
                    sep=gbls.SEP,
                    error_bad_lines=False,
                    warn_bad_lines=True,
                    quotechar='"',
                    encoding='utf-16')

        except IOError as e:
            self.logger.critical('\n\n***I/O error({0}): {1}\n\n'.format(
                        e.errno, e.strerror))

        # ValueError Exception could mean empty data set read
        # Initialize an empty dataframe
        except ValueError as e:
            self.logger.critical(
                            '\n\n***Value error: {0}\n- empty data set '
                            'returned\n\n'.format(
                                        sys.exc_info()[0]
                                        )
                            )
            df_v_gs_add_rem_tmp = self.df_add_rem_g_empty

        except:
            self.logger.critical(
                '\n\n***Unexpected error: {0}\n\n'.format(
                    sys.exc_info()[0]))
            raise

        self.logger.debug(
                    '\n\nFinished reading x86 view, starting x64 view\n\n')

        try:
            df_v_gs_add_rem64_tmp = pd.io.parsers.read_csv(
                    mydir_x64,
                    sep=gbls.SEP,
                    error_bad_lines=False,
                    warn_bad_lines=True,
                    quotechar='"',
                    encoding='utf-16')

        except IOError as e:
            self.logger.critical('\n\n***I/O error({0}): {1}\n\n'.format(
                        e.errno, e.strerror))

        # ValueError Exception could mean empty data set read
        # Initialize an empty dataframe
        except ValueError as e:
            self.logger.critical(
                            '\n\n***Value error: {0}\n- empty data set '
                            'returned\n\n'.format(
                                        sys.exc_info()[0]
                                        )
                            )
            df_v_gs_add_rem64_tmp = self.df_add_rem_g_empty

        except:
            self.logger.critical(
                '\n\n***Unexpected error: {0}\n\n'.format(
                    sys.exc_info()[0]))
            raise

        self.logger.debug(
            '\n\nFinished reading both v_gs_add_rem_pgms_xx views\n\n')

        # indicate processor architecture
        df_v_gs_add_rem_tmp['arch_X'] = False
        df_v_gs_add_rem64_tmp['arch_X'] = True

        # consolidate the "GS_add_remove" dataframes
        df_add_rem_g0 = pd.concat(
                [df_v_gs_add_rem_tmp, df_v_gs_add_rem64_tmp],
                axis=0,
                join='outer'
                )

        # Print basic information
        self.logger.debug('\nv_gs_Add_Remove_Programs:\n{0}\n{1}\n\n'.format(
                df_add_rem_g0.shape,
                df_add_rem_g0.columns)
                )

        # drop rows with either missing Publisher0 or DisplayName0 data
        df_add_rem_g1 = df_add_rem_g0[
                    df_add_rem_g0.Publisher0.notnull()
                    & df_add_rem_g0.DisplayName0.notnull()
                    ]

        self.logger.debug(
            '\nSCCM inventory data-no missing '
            'data \n{0}\n{1}\n\n'.format(
                    df_add_rem_g1.shape,
                    df_add_rem_g1.columns
                    )
            )

        # dont want MS inventory data either
        self.df_add_rem_g = df_add_rem_g1[
                            ~df_add_rem_g1.Publisher0.str.contains(
                                    'microsoft',
                                    case=False)
                                    ]

        self.logger.info(
            '\n\nSCCM inventory data after removing '
            'entries with missing values and also '
            'microsoft-related entries \n{0}\n{1}\n\n'.format(
                    self.df_add_rem_g.shape,
                    self.df_add_rem_g.columns
                    )
            )

        return None

    def load(self, mydir=None):
        """Load Software dataframe that was previously pickled."""
        self.logger.info(
            '\n\nLoading v_gs_Add_Remove_Programs '
            'into SccmSoft.df_add_rem_g dataframe\n\n'
            )

        if mydir is None:
            mydir = gbls.df_add_rem_g_pck

        self.df_add_rem_g = pd.read_pickle(mydir)

        self.logger.info(
            '\n\nSCCM inventory data loaded: '
            '\n{0}\n{1}\n\n'.format(
                    self.df_add_rem_g.shape,
                    self.df_add_rem_g.columns
                    )
            )
        return None

    def save(self):
        """Save Software dataframe in serialized pickle format."""
        self.logger.info(
            '\n\nSaving SccmSoft.df_add_rem_g dataframe\n\n'
            )
        self.df_add_rem_g.to_pickle(
            gbls.df_add_rem_g_pck
            )
        return None

    def get(self):
        """Return a *copy* of the main software dataframe."""
        df_tmp = self.df_add_rem_g.copy()
        self.logger.info(
                '\n\nGet SccmHosts.df_add_rem_g: \n{0}\n{1}\n\n'.format(
                                df_tmp.shape,
                                df_tmp.columns
                                )
                )
        return df_tmp
