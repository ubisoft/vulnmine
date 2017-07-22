"""matchsft: Match CPE "Software" data with SCCM Software Inventory data.

Purpose
=======

The matchven module previously produced a dataframe with CPE "Vendor" - SCCM
"Publisher" matches. This dataframe is used by matchsft as follows:

*   The CPE dictionary documents the software produced by each Vendor.
    Likewise, SCCM Sotware Inventory contains the set of software installed
    for each SCCM "Publisher".

*   For a given Vendor-Publisher pair, the Cartesiasn Product of the two
    respective software sets is formed to give the set of all possible
    matching software.

*   This data set is reduced using simple heuristics, refined using manually
    labelled data, and then input to ML Classification.


The result is a dataframe giving matches NVD CPE "Software" data to the
corresponding SCCM "Software" data originally from the "Add-Remove" entries in
the Windows Registry.


Public classes
==============

MatchSoft     Match NVD CPE "Software" data to SCCM "Software" inventory data

              This class uses heuristics and ML Classification to match NVD
              CPE "Software" data to the corresponding SCCM "Software"
              inventory data.

"""
import re
from time import time

import pandas as pd
import numpy as np

import sys

from fuzzywuzzy import fuzz as fz
from sklearn.externals import joblib

import logging

import gbls
import utils
import sccm
import nvd
import ml

# Public classes
__all__ = (
        'MatchSoft'
        )


class MatchSoft(object):
    """Match NVD CPE "Software" data to SCCM "Software" inventory data.

    Actions
    -------

    *  Both the SCCM software inventory data and the CPE Sofware data are
       cleaned, and normalized. Extraneous columns are dropped. Missing
       values are initialized. Both sets of input data are sorted / grouped.

    *  The cartesian product is formed for each Vendor-Publisher tuple:
       {CPE "Software" for this vendor} X
            {SCCM Software installed for this "Publisher"}

       Simple heuristics are used to reduce # potential matches. "Fuzzy
       matching" statistics are calculated as ML "features".

    *  Manually labelled match data is read in. The new data to be
       classified is updated using this labelled data. This ensures that only
       new unclassified data is input to ML classification.

    *  The Random Forest Classification algorithm is run.

    *  The newly-classifed test data is concatenated with the manually
       labelled data to form the final dataframe of CPE-SCCM Software
       matches.

    Methods
    -------
    __init__    The class constructor which initializes logging, and an empty
                dataframe for the resulting matches.

    load        Load CPE-SCCM software correspondance dataframe that was
                previously saved in pickled format.

    save        Save CPE-SCCM software correspondance dataframe to a
                serialized pickled flat file.

    get         Return a *copy* of the Vendor-Publisher matches dataframe.
    match       Prepare SCCM software data for ML Classification.
                Prepare CPE software data for ML Classification.
                Form the Cartesian product of potential software matches for
                each Vendor-Publisher tuple.
                Update the new data to be classified using manually labelled
                data. This ensures that only new unclassified data is input
                to the ML Matching.
                Run the ML Classification to match CPE Software to SCCM
                Software.
                Eliminate duplicate matches by choosing the "best" match
                based on a "Fuzzy Matching" statistic.
                Concatenate the new classified data with the manually
                labelled data to form the final result dataframe.

    Exceptions
    ----------
    IOError     Log error message and ignore

    Returns
    -------
    None

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

        self.logger.info('\n\nInitializing MatchSoft class\n\n')

        self.df_match_cpe_sft = pd.DataFrame({
            # For each CPE Vendor_X, that vendor's software is mapped to
            # the corresponding SCCM software
            'vendor_X': [],
            'DisplayName0': [],
            'Version0': [],
            't_cve_name_x': [],
            't_cve_name_y': [],
            't_cve_name': []
            })

        # Initialize ML Classification
        self.__ML = ml.MLClassify('software')

        return None

    def load(self, mypck=None):
        """Load CPE-SCCM software match dataframe that was saved."""
        self.logger.info(
                '\n\nLoading CPE - SCCM software correspondance data into '
                'df_match_cpe_sft dataframe\n\n'
                )

        if mypck is None:
            mypck = gbls.df_match_cpe_sft_pck

        self.df_match_cpe_sft = pd.read_pickle(mypck)
        return None

    def save(self):
        """Save the CPE-SCCM software match dataframe."""
        self.logger.info('\n\nSaving df_match_cpe_sft dataframe\n\n')
        self.df_match_cpe_sft.to_pickle(gbls.df_match_cpe_sft_pck)
        return None

    def get(self):
        """Return a *copy* of the dataframe."""
        df_tmp = self.df_match_cpe_sft.copy()
        self.logger.info(
                '\n\nGet MatchVendor.df_match_cpe_sft: \n{0}\n{1}\n\n'.format(
                                df_tmp.shape,
                                df_tmp.columns
                                )
                )
        return df_tmp

    def match(
                self,
                df_match_vendor_publisher,
                df_sccm_ar,
                df_cpe4
                ):
        """Match the CPE "Software" data to the SCCM "Software" data.

        Actions
        -------

        *  The SCCM Software data is prepared for ML Classification:
                - Data is normalized.
                - Extraneous columns are dropped.
                - Missing values are initialized.
                - Vendor_Publisher correspondance dataframe is used to add
                  CPE Vendor to the SCCM record.
                - Data is grouped and sorted.

        *  Likewise the CPE Software data is prepared for ML Classification.
           Extraneous columns are dropped and data is grouped / sorted.

        *  The cartesian product is formed for each Vendor-Publisher tuple:
           {CPE "Software" for this vendor} X
                {SCCM Software installed for this "Publisher"}

            - Cisco Webex and all Microsoft software is ignored.
            - Java release data is normalized.
            - Simple heuristics are used to eliminate improbable matches.
            - "Fuzzy matching" statistics are calculated as ML "features".

        *  Manually labelled match data is read in. The new data to be
           classified is updated using this labelled data. This ensures that
           the ML Classification will run only on new unknown data.

        *  The Random Forest Classification algorithm is run.


        *  Duplicate matches are eliminated from both the newly classified
           data as well as the manually labelled data.

            - Only +ve matches are considered.
            - The row which has the highest fuzzy match statistic is
              picked as the "best" match.
            - The rest of the duplicate data in the group is discarded.

        *  The newly-classifed test data is concatenated with the manually
           labelled data to form the final dataframe of Vendor - Publisher
           correspondances.

        Exceptions
        ----------
        IOError     Log error message and ignore

        Returns
        -------
        None

        """
        ######
        # Utility Function to handle Java 'Release' data programmatically
        ######

        def _fix_java_rel(my_cpe_sft):

            # Java "release" data has varied widely over the years. The
            # transition from Sun to Oracle complicated things further.
            #
            # This rtn attempts to deal with the exception cases in order
            # to normalize the data.

            # handle cases where release is of form 'update[_]nn'

            if 'update' in my_cpe_sft:
                pattern = re.compile(
                                'cpe:2.3:a:(oracle|sun):'
                                '(?P<sft>(jdk|jre)):'
                                '1.(?P<rel>[\d\.]*):'
                                'update[_]*(?P<upd>[\d]*)',
                                re.IGNORECASE | re.UNICODE
                                )

                my_match = pattern.search(my_cpe_sft)

                if my_match:
                    sft = my_match.group('sft')
                    rel = my_match.group('rel')
                    upd = my_match.group('upd')

                    tmp_str = (
                                my_match.group('rel')
                                + '.'
                                + my_match.group('upd')
                                + '0'
                                )

                # if no match, then either not jre/jdk or version info missing

                else:
                    return '-'

            # the other possibilities is that only 'release' is provided
            else:
                pattern = re.compile(
                            'cpe:2.3:a:'
                            '(oracle|sun):'
                            '(?P<sft>(jdk|jre)):'
                            '1.(?P<rel>[\d\.\_]*):',
                            re.IGNORECASE | re.UNICODE
                            )

                my_match = pattern.search(my_cpe_sft)

                if my_match:
                    sft = my_match.group('sft')
                    rel = my_match.group('rel')

                    tmp_str = my_match.group('rel')

                # if no match, then either not jre/jdk or version info missing
                else:
                    return '-'

            # Handle case of a really old version: Has embedded '_'
            if '_' in rel:
                return ('1.' + rel)

            # JRE version is good 'as is'
            elif sft == 'jre':
                        return(tmp_str)

            # JDKS up to / including 1.7.x have release 1.7.x
            # JDKS 1.8.x have release '8.x'

            elif sft == 'jdk':

                if rel.startswith('8.'):
                    return tmp_str
                else:
                    return('1.' + tmp_str)
            else:
                self.logger.info('*** error rtn java')

        # Prepare the SCCM data for ML classification

        def _match_prepare_sccm_data(
                            df_add_rem_g,
                            df_match_vendor1
                            ):

            # Prepare sccm data for 2cd phase of machine learning matching
            # - Clean and normalize SCCM software data. Remove extraneous
            #   columns.
            # - Add CPE Vendor_X based on Publisher0-VendorX correspondance
            # - Group SCCM data by vendor_X, software name, release

            ######
            #   Access SCCM software inventory data
            ######

            self.logger.info('\n\nEntering match_prepare_sccm_data\n\n')

            # lower-case Publisher0 string for matching
            df_add_rem_g0 = df_add_rem_g
            df_add_rem_g0['publisher0'] = df_add_rem_g0[
                                                'Publisher0'
                                                ].str.lower()

            df_add_rem_g1 = df_add_rem_g0.drop('Publisher0', 1)

            self.logger.info(
                        '\n\nSCCM inventory dataframe \n{0}\n{1}\n\n'.format(
                            df_add_rem_g1.shape,
                            df_add_rem_g1.columns
                            )
                        )

            # Merge CPE vendor data with SCCM Publisher0 data from SCCM
            # inventory

            df_add_rem_g3 = pd.merge(
                                df_add_rem_g1,
                                df_match_vendor_publisher,
                                how='left',
                                on='publisher0'
                                )

            self.logger.info(
                        '\n\nMerged CPE vendor - '
                        'SCCM inventory dataframe \n{0}\n{1}\n\n'.format(
                            df_add_rem_g3.shape,
                            df_add_rem_g3.columns
                            )
                        )

            # Clean up the SCCM inventory data and prepare it for product
            # matching

            # Remove extraneous columns
            df_arSft = df_add_rem_g3[[
                                'vendor_X',
                                'DisplayName0',
                                'Version0'
                                ]]

            # and initialize missing release values. NVD CPE uses '-' for
            # missing release data, and so will we.

            df_arSft.loc[df_arSft.Version0.isnull(), 'Version0'] = '-'

            self.logger.info(
                        '\n\nSCCM Inventory dataframe summary:\n'
                        'Add_Remove Publishers:\n{0}\n'
                        'AR software:\n{1}\n\n'.format(
                            df_arSft['vendor_X'].nunique(),
                            df_arSft['DisplayName0'].nunique()
                            )
                        )

            # Group SCCM data by vendor_X, software name, release

            df_arSft_grp = df_arSft.groupby([
                                    'vendor_X',
                                    'DisplayName0',
                                    'Version0'
                                    ])

            return (df_arSft_grp)

        # Prepare the CPE Software data for ML classification

        def _match_prepare_cpe_data(df_cpe4):

            # Read in the CPE vendor / software data and prepare it for
            # product matching

            self.logger.info(
                        '\n\n Starting prepare_cpe_data\n'
                        'cpe data\n{0}\n{1}\n\n'.format(
                            df_cpe4.shape,
                            df_cpe4.columns
                            )
                        )

            # keep relevant columns
            df_cpeSoft = df_cpe4[[
                                'vendor_X',
                                'software_X',
                                'release_X',
                                'title_X',
                                'cpe23-item-name',
                                '@name'
                                ]]

            self.logger.debug(
                            'CPE vendors:\n{0}\n\n'.format(
                                df_cpeSoft['vendor_X'].nunique()
                                )
                            )

            self.logger.debug(
                            'CPE products:\n{0}\n\n'.format(
                                    df_cpeSoft['software_X'].nunique()
                                    )
                            )

            # Group CPE data by vendor_X

            df_cpeSoft_grp = df_cpeSoft.groupby(['vendor_X'])

            self.logger.info(
                        '\nCPE vendors: \n{0}\n'
                        'CPE products: \n{1}\n\n'
                        '{2}\n{3}\n'.format(
                                df_cpeSoft['vendor_X'].nunique(),
                                df_cpeSoft['software_X'].nunique(),
                                df_cpeSoft.shape,
                                df_cpeSoft.columns
                                )
                        )

            return (df_cpeSoft_grp)

        # Form the cartesian product is formed for each Vendor-Publisher
        # tuple:
        #       {CPE "Software" for this vendor} X
        #          {SCCM Software installed for this "Publisher"}

        # This gives a set of potential matches to input to ML
        # classification.

        def _cartesian_product(
                        df_arSft_grp,
                        df_cpeSoft_grp
                        ):

            # Loop thru the data to find potential matches

            self.logger.info('\n\nEntering cartesian_product\n\n')

            # list of product tuples to check
            lst_dict = []

            t0 = time()

            self.logger.info(
                        '\n\nStarting generation of '
                        'cartesian product of CPE products '
                        'to SCCM software ... \n'
                        '*** This can take some time - '
                        'maybe 5 min or more.\n\n'
                        )
            n = 0
            m = 0
            for key, df_ar_grp in df_arSft_grp:

                # split out vendor / SCCM DisplayName0 / SCCM Version0 strings
                (t_ar_vndrX, t_ar_dsply0, t_ar_ver0) = key

                # microsoft will be handled separately as service bulletins
                if t_ar_vndrX == 'microsoft':
                    continue

                # some cisco webex products are also hard to match
                if t_ar_vndrX == 'cisco':
                    if t_ar_ver0 == '-' and 'webex' in t_ar_dsply0.lower():
                        continue

                # get the corresponding CPE data for this vendor
                try:
                    df_cpe_grp = df_cpeSoft_grp.get_group((t_ar_vndrX))

                except KeyError as e:
                    self.logger.critical(
                        '\n\n***matchsft.py cartes product loop -'
                        ' KeyError: {0}\n\n'.format(e)
                        )
                    continue

                for (
                        t_cpeix,
                        t_cpe_vdr_X,
                        t_cpe_sft_X,
                        t_cpe_relX,
                        t_cpe_titleX,
                        t_cpe23_name,
                        t_cve_name
                        ) in df_cpe_grp.itertuples():

                    # 'normal' CPE release #
                    t_cpe_relX_tmp = t_cpe_relX

                    # but .... java - an exception (as always!)
                    if t_cpe_vdr_X in ['oracle', 'sun']:
                        if t_cpe_sft_X == 'jre' or t_cpe_sft_X == 'jdk':
                            t_cpe_relX_tmp = _fix_java_rel(t_cpe23_name)

                    # don't consider vendor name in fuzzy matching

                    t_cpe_titleX_tmp = t_cpe_titleX.lower().replace(
                                                                t_cpe_vdr_X,
                                                                ' '
                                                                )
                    t_ar_dsply0_tmp = t_ar_dsply0.lower().replace(
                                                            t_cpe_vdr_X,
                                                            ' '
                                                            )
                    ######
                    #   Apply quick heuristics to reduce the number of
                    #   possible matches
                    ######

                    # 1) Release #'s should at least partially match

                    fz_rel_ratio = fz.ratio(
                                        t_cpe_relX_tmp,
                                        t_ar_ver0
                                        )
                    fz_rel_ptl_ratio = fz.partial_ratio(
                                                t_cpe_relX_tmp,
                                                t_ar_ver0
                                                )

                    if (t_cpe_relX_tmp != '-') and (t_ar_ver0 != '-'):

                        # If release data is specified, then check that
                        # there is at least a partial match

                        if fz_rel_ratio < 90 or fz_rel_ptl_ratio < 100:
                            continue

                    # 2) There should be at least one occurence of one word in
                    # the cpe full name somewhere in sccm full name

                    fz_ptl_tok_set_ratio = fz.partial_token_set_ratio(
                                                t_cpe_titleX_tmp,
                                                t_ar_dsply0_tmp,
                                                force_ascii=False
                                                )

                    if fz_ptl_tok_set_ratio < 70:
                        continue

                    ######
                    # calculate fuzzy matching statistics for this match
                    ######

                    lst_dict.append({
                        'vendor_X': t_cpe_vdr_X,
                        'software_X': t_cpe_sft_X,
                        'Version0': t_ar_ver0,
                        'release_X': t_cpe_relX,
                        'title_X': t_cpe_titleX,
                        'DisplayName0': t_ar_dsply0,

                        'fz_ratio': fz.ratio(
                                        t_cpe_titleX_tmp,
                                        t_ar_dsply0_tmp
                                        ),
                        'fz_ptl_ratio': fz.partial_ratio(
                                                t_cpe_titleX_tmp,
                                                t_ar_dsply0_tmp
                                                ),
                        'fz_tok_set_ratio': fz_ptl_tok_set_ratio,
                        'fz_ptl_tok_sort_ratio': fz.token_sort_ratio(
                                                    t_cpe_titleX_tmp,
                                                    t_ar_dsply0_tmp,
                                                    force_ascii=False
                                                    ),
                        'fz_uwratio': fz.UWRatio(
                                        t_cpe_titleX_tmp,
                                        t_ar_dsply0_tmp
                                        ),

                        'fz_rel_ratio': fz_rel_ratio,
                        'fz_rel_ptl_ratio': fz_rel_ptl_ratio,
                        't_cve_name': t_cve_name
                        })
                    m = m+1

                n = n+1
                if n % 100 < 1:
                    self.logger.debug(
                            '---Working ar: '
                            'sccm sft i/p: {0} '
                            ', potential matches output: {1}\n'.format(n, m)
                            )
                # # debug code to speed thru looping process
                # if n > 2000:
                #     break

            duration = time() - t0
            self.logger.info(
                        '\n\nDone in {0} sec.\n\n'.format(
                                                duration
                                                )
                        )

            df_match = pd.DataFrame(lst_dict)

            if df_match.empty:
                self.logger.info(
                    '\n\nResulting cartesian product is empty\n\n'
                    )
                return (df_match)

            else:
                df_match1 = df_match[[
                                'vendor_X',
                                'software_X',
                                'title_X',
                                'DisplayName0',
                                'release_X',
                                'Version0',
                                'fz_ratio',
                                'fz_ptl_ratio',
                                'fz_tok_set_ratio',
                                'fz_ptl_tok_sort_ratio',
                                'fz_uwratio', 'fz_rel_ratio',
                                'fz_rel_ptl_ratio',
                                't_cve_name']]

                # add in length of names as features

                df_match1['titlX_len'] = df_match1['title_X'].apply(len)
                df_match1['DsplyNm0_len'] = df_match1[
                                                    'DisplayName0'
                                                    ].apply(len)

                self.logger.info(
                            '\n\n Results of matching: \n'
                            '# matches: {0}\n'
                            '# vendors: {1}\n'
                            '# CPE software: {2}\n'
                            '# SCCM inventory products: {3}\n'
                            '{4}\n{5}'.format(
                                        df_match1['t_cve_name'].count(),
                                        df_match1['vendor_X'].nunique(),
                                        df_match1['software_X'].nunique(),
                                        df_match1['DisplayName0'].nunique(),
                                        df_match1.shape,
                                        df_match1.columns
                                        )
                            )
                return (df_match1)

        # Previously manually labelled data is used to update the new data to
        # be classified. This ensures that only new, unknown data is input
        # into the ML Classification algorithm.

        def _update_with_labelled_data(df_match1):

            self.logger.info('\n\nEntering update_with_labelled_data\n\n')

            # Input the manually labelled data. This is a subset of the
            # 'match' data for selected vendors. This data was originally used
            # to train the classification model. We recycle it here since it
            # has already been classified (manually).

            try:
                labelled_sft_data = pd.io.parsers.read_csv(
                                                gbls.df_label_software,
                                                sep=gbls.SEP2,
                                                error_bad_lines=False,
                                                warn_bad_lines=True,
                                                index_col=0,
                                                encoding='utf-8')
            except IOError as e:
                self.logger.critical('\n\n***I/O error({0}): {1}\n\n'.format(
                            e.errno, e.strerror))

            except:
                self.logger.critical(
                    '\n\n***Unexpected error: {0}\n\n'.format(
                        sys.exc_info()[0]))
                raise

            self.logger.info(
                            '\n\nRead in manually matched '
                            'product-software '
                            'dataframe\n{0}\n{1}\n{2}\n\n'.format(
                                labelled_sft_data.shape,
                                labelled_sft_data.columns,
                                labelled_sft_data['match'].value_counts()
                                )
                            )

            # Use the manually labelled data to update the data to be ML
            #   matched.
            # Merge in 'match' information from labelled data

            df_match1_lbl = self.__ML.upd_using_labelled_data(
                                            df_match1,
                                            labelled_sft_data
                                            )
            self.logger.debug(
                '\n\nUpdated dframe\n'
                '{0}\n{1}\n\n'.format(
                    df_match1_lbl.shape,
                    df_match1_lbl.columns
                    )
                )

            # make sure the manually 'matched' data set is still intact

            if df_match1_lbl.empty:
                self.logger.info('Updated dframe is empty')
            else:
                self.logger.info(
                    '\n\nResults of updating the CPE software - '
                    'SCCM inventory dataframe with labelled data: \n'
                    '# matches: {0} \n'
                    '# vendors: {1} \n'
                    '# CPE software: {2} \n'
                    '# SCCM inventory products: {3} \n\n'.format(
                        df_match1_lbl['t_cve_name'].count(),
                        df_match1_lbl['vendor_X'].nunique(),
                        df_match1_lbl['software_X'].nunique(),
                        df_match1_lbl['DisplayName0'].nunique(),
                        df_match1_lbl.shape,
                        df_match1_lbl.columns
                        )
                )

            return (df_match1_lbl, labelled_sft_data)

        # Concatentate the manually labelled data with the newly classified
        # data. Drop extraneous columns and eliminate duplicate data to form
        # the final dataframe of CPE-SCCM "Software" matches.

        def _post_process_matched_data(
                            p_df_match1_test2,
                            p_labelled_sft_data
                            ):

            # Utility fn to eliminate duplicates

            # - Duplicates are grouped. Only +ve matches are considered.
            # - Then a simple heuristic is used to pick the "best" match.
            # - The rest of the duplicates are discarded.

            def replace_dups_by_best_match(p_df_match1_test2a):

                self.logger.info(
                    '\n\nEntering replace_dups_by_best_match\n\n'
                    )

                if p_df_match1_test2a.empty:
                    self.logger.critical(
                            '\n\n*** replace_dups - No hosts I/P!\n\n'
                            )
                    return p_df_match1_test2a

                # Force copy by value
                df_match1_test2a = p_df_match1_test2a.copy()

                self.logger.debug(
                        '\n\nDframe before removing duplicates '
                        '\n{0}\n{1}\n{2}\n\n'.format(
                            df_match1_test2a.shape,
                            df_match1_test2a.columns,
                            df_match1_test2a.apply(pd.Series.nunique)
                            )
                        )

                # Are only interested in +ve matches
                df_match1_test2a = df_match1_test2a[
                                        df_match1_test2a.match == 1
                                        ]

                # Pick out the row in group which has maximum fz_uwratio
                # value. This is likely to be the best match possible.

                df_match1_tst2a_gp = df_match1_test2a.groupby([
                                                            "vendor_X",
                                                            "DisplayName0",
                                                            "Version0"])

                df_match1_tst2b = df_match1_test2a[
                                        df_match1_test2a['fz_uwratio']
                                        == df_match1_tst2a_gp[
                                                'fz_uwratio'
                                                ].transform(max)]

                # Clean out the rest of the duplicates for the ML-classified
                # data
                df_match1_tst2c = df_match1_tst2b.drop_duplicates(
                                                        subset=[
                                                            u'vendor_X',
                                                            u'DisplayName0',
                                                            u'Version0']
                                                            )

                self.logger.info(
                        '\n\nDframe with duplicates removed '
                        '\n{0}\n{1}\n{2}\n\n'.format(
                            df_match1_tst2c.shape,
                            df_match1_tst2c.columns,
                            df_match1_tst2c.apply(pd.Series.nunique)
                            )
                        )
                return(df_match1_tst2c)

            ######
            # Main code for _post_process_matched_data function
            ######

            self.logger.info('\n\nEntering post_process_matched_data\n\n')

            # Force "call by value"

            df_match1_test2 = p_df_match1_test2.copy()
            labelled_sft_data = p_labelled_sft_data.copy()

            if df_match1_test2.empty:
                self.logger.critical(
                        '\n\n\n*** Product-software dframe is empty.\n\n')
                self.df_match_cpe_sft = df_match1_test2
            else:

                self.logger.info(
                            'Product-software match '
                            'dataframe\n{0}\n{1}\n{2}\n\n'.format(
                                df_match1_test2.shape,
                                df_match1_test2.columns,
                                df_match1_test2['match'].value_counts()
                                )
                            )

                # Eliminate duplicates from the ML Classified data

                df_match1_tst2d = replace_dups_by_best_match(df_match1_test2)

                self.logger.info(
                        '\n\nManually labelled '
                        'data\n {0}\n {1}\n {2}\n\n'.format(
                            labelled_sft_data.shape,
                            labelled_sft_data.columns,
                            labelled_sft_data['match'].value_counts()
                            )
                        )

                # Idem for the manually labelled data

                df_match1_lbl3 = replace_dups_by_best_match(
                                                labelled_sft_data)

                # Consolidate the new ML data with the manually labelled data

                df_match1_lbl4 = self.__ML.post_process_matched_data(
                                                    df_match1_tst2d,
                                                    df_match1_lbl3
                                                    )
                # drop extraneous columns
                self.df_match_cpe_sft = df_match1_lbl4[[
                                            'vendor_X',
                                            'DisplayName0',
                                            'Version0',
                                            't_cve_name'
                                            ]]

                self.logger.info(
                    '\n\nConsolidated product-software '
                    'match dataframe after removing '
                    'duplicates\n{0}\n{1}\n\n'.format(
                                    self.df_match_cpe_sft.shape,
                                    self.df_match_cpe_sft.columns
                                    )
                    )
            return None

        ######
        # Main code for "match" method
        ######

        self.logger.info('\n\nEntering match_soft\n\n')

        self.logger.info(
                        '\nSCCM Inventory dataframe shape: \n{0}\n\n'.format(
                                                df_sccm_ar.shape
                                                )
                        )

        # Prepare SCCM software data for matching

        df_arSft_grp = _match_prepare_sccm_data(
                                df_sccm_ar,
                                df_match_vendor_publisher
                                )

        # Prepare CPE vendor / software data for matching

        df_cpeSoft_grp = _match_prepare_cpe_data(df_cpe4)

        # Form cartesian product of CPE vendor/software data with SCCM
        # inventory software data

        df_match1 = _cartesian_product(
                        df_arSft_grp,
                        df_cpeSoft_grp
                        )

        # Update the set of potential match data with known matches
        # from the labelled data

        (df_match1_lbl, labelled_sft_data) = _update_with_labelled_data(
                                                                    df_match1
                                                                    )
        # Do actual ML classification

        (df_match1_test2, df_match_labelled) = self.__ML.ml_classify(
                                                            df_match1_lbl)

        # Post-process the ML matched data and the labelled data to
        # eliminate duplicates and then concatenate into one dataframe

        _post_process_matched_data(df_match1_test2, labelled_sft_data)

        return None
