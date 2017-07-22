"""matchven: Match NVD CPE "Vendor" data with SCCM "Publisher" data.

Purpose
=======

The matchven module uses heuristics as well as Machine Learning
classification techniques to match NVD CPE "vendor" data to the corresponding
SCCM "Publisher" data originally from the "Add-Remove" entries in the Windows
Registry.

The set of corresponding data is placed in a pandas dataframe which is
persisted.

Public classes
==============

MatchVendor     Match NVD CPE "Vendor" data to SCCM "Publisher" data


                This class uses heuristics and ML Classification to match NIST
                CPE "Vendors" to SCCM "Publishers".

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
        'MatchVendor'
        )


class MatchVendor(object):
    """Match CPE "Vendor" data to SCCM "Publisher" data.

    The NIST CPE Vendor data is matched to SCCM "Publisher" data.

    *  The input data is normalized, tokenized, and common "stop" words are
       removed.

    *  The Cartesian Product of all possible matches is formed, then reduced
       using simple heuristics.

    *  ML Random Forest classification is used to find matches.

    *  The newly-classified data is concatenated with manually labelled data
       to form the final dataframe of "Vendor" - "Publisher" correspondances.

    Once a reasonably reliable set of Vendor-Publisher corespondances is
    found, this data will be leveraged in the matchsft module to match CPE
    Software titles to SCCM Software inventory data.

    Methods
    -------
    __init__    Class constructor to configure logging, initialize empty data
                frame, and read in "stop" words for the ML Classification.
    load        Load Vendor-Publisher dataframe from the serialized pickled
                file.
    save        Save the Vendor-Publisher dataframe to the corresponding
                serialized, pickled file.
    get         Return a *copy* of the Vendor-Publisher dataframe.
    match       Match the CPE "Vendor" data to the SCCM "Publisher" data

    """

    def __init__(self, mylogger=None):
        """Initialize class by configuring logging,  initializing dataframe.

        This is the class constructor.

        Actions
        -------

        * Initializes logging.
        * Allocates an empty dataframe to contain Vendor-Publisher match data.
        * Reads "stop" words for elimination of common tokens. eg "Inc"

        I/P Parameters
        --------------
        mylogger    logging object. If None, then a new object is initialzed.

        Exceptions
        ----------
        IOError     A message is logged and the error is ignored.

        """
        # Configure logging

        if mylogger is None:
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(gbls.loglvl)
        else:
            self.logger = mylogger

        self.logger.info('\n\nInitializing MatchVendor class\n\n')

        self.df_match_vendor_publisher = pd.DataFrame({
            'Match': [],
            'publisher0': [],
            'vendor_X': []
            })

        # "stop" words to improve token matching

        self.__lst_stop_wds = []

        # ML classification

        self.__ML = ml.MLClassify('vendor')

        # Initialize algorithm for ML matching
        # Read stop words

        try:
            s_stop_wds = pd.io.parsers.read_csv(
                                gbls.s_vndr_stop_wds,
                                sep=gbls.SEP2,
                                error_bad_lines=False,
                                warn_bad_lines=True,
                                index_col=0,
                                squeeze=True,
                                header=None,
                                encoding='utf-8')
        except IOError as e:
            self.logger.critical('\n\n***I/O error({0}): {1}\n\n'.format(
                        e.errno, e.strerror))

        except:
            self.logger.critical(
                '\n\n***Unexpected error: {0}\n\n'.format(
                    sys.exc_info()[0]))
            raise

        self.__lst_stop_wds = s_stop_wds.tolist()

        self.logger.info(
                        '\n\nList of stop words: \n{0}\n\n'.format(
                            self.__lst_stop_wds
                            )
                        )

        return None

    def load(self, mypck=None):
        """Load Vendor-Publisher dataframe that was previously saved."""
        self.logger.info(
                '\n\nLoading saved Vendor-Publisher match data into '
                'MatchVendor.df_match_vendor_publisher dataframe\n\n'
                )
        if mypck is None:
            mypck = gbls.df_match_vendor_publisher_pck

        self.df_match_vendor_publisher = pd.read_pickle(mypck)
        return None

    def save(self):
        """Save Vendor-Publisher dataframe in serialized pickle format."""
        self.logger.info(
                    '\n\nSaving MatchVendor.df_match_vendor_publisher '
                    'dataframe\n\n'
                    )
        self.df_match_vendor_publisher.to_pickle(
                        gbls.df_match_vendor_publisher_pck
                        )
        return None

    def get(self):
        """Return a *copy* of the dataframe."""
        df_tmp = self.df_match_vendor_publisher.copy()
        self.logger.info(
                '\n\nGet MatchVendor.df_match_vendor_publisher: '
                '\n{0}\n{1}\n\n'.format(
                                df_tmp.shape,
                                df_tmp.columns
                                )
                )
        return df_tmp

    def match(self, df_cpe, df_sccm_ar):
        """Match the CPE "Vendor" data to the SCCM "Publisher" data.

        Actions
        -------

        *  The input string data is normalized and then converted into
           "tokens" and common "stop" words are removed.

        *  The cartesian product of both sets of data is formed:
           {CPE "Vendor" names} X {SCCM "Publisher" Names}

            - Both I/P dataframes are iterated through to form the set of all
              possible matches.
            - Simple heuristics are used to eliminate improbable matches.
            - "Fuzzy matching" statistics are calculated as ML "features".

        *  Manually labelled match data is read in. The new data to be
           classified is updated using this labelled data. This ensures that
           the ML Classification will run only on new unknown data.

        *  The Random Forest Classification algorithm is run.

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
        # Suppress tokens which match "stop" words, e.g. "Inc, Ltd"

        def _remove(x):

            result = ' '
            for str in x:
                if not(str in self.__lst_stop_wds) and (len(str) > 1):
                    result = result + ' ' + str
            return result

        # Prepare the data for ML Classification

        def _match_prepare(df_cpe, df_sccm_ar):

            self.logger.info('\n\nEntering match_prepare\n\n')

            self.logger.info(
                '\n\nMatching NVD vendors to SCCM publisher data\n\n'
                )
            # The I/P CPE 'Vendor' strings along with the SCCM registry
            #   'Add_Remove_Pgms' 'Publisher0' strings are normalized

            # Extract and normalize list of SCCM WMI publishers
            df_arPub = pd.DataFrame(
                            df_sccm_ar['Publisher0'].dropna().str.replace(
                                ' ', '_'
                                ).str.lower().unique(),
                            columns=['publisher0']
                            )

            self.logger.info(
                            '\n\nCount of SCCM Publisher0: {0}\n\n'.format(
                                    df_arPub.shape
                                    )
                            )

            # Extract and normalize list of CPE vendors
            df_cpeVen = pd.DataFrame(
                            df_cpe['vendor_X'].dropna().str.replace(
                                ' ', '_'
                                ).str.lower().unique(),
                            columns=['vendor_X']
                            )
            self.logger.info(
                            '\nCount of CPE vendors: \n{0}\n\n'.format(
                                    df_cpeVen.shape
                                    )
                            )

            # Tokenize names

            # Note:
            #
            # a) CPE data has "underscore" instead of "blank"
            #
            # b) For WMI data, hyphens / ampersands are left "as-is" since
            # these can form part of a vendor name

            df_arPub['pub0_toks'] = df_arPub['publisher0'].str.replace(
                                        '[_.,()+!]', ' '
                                        ).str.split()
            df_cpeVen['vend_toks'] = df_cpeVen['vendor_X'].str.replace(
                                        '[-_]', ' '
                                        ).str.split()

            # Produce new clean names from tokens, taking into account "stop"
            # words

            df_arPub['pub0_cln'] = df_arPub['pub0_toks'].apply(_remove)
            df_cpeVen['ven_cln'] = df_cpeVen['vend_toks'].apply(_remove)

            # show results of tokenization
            self.logger.info(
                '\n\nSample CPE vendors \n{0}\n\n'.format(
                    df_cpeVen[['vendor_X', 'vend_toks', 'ven_cln']].sample(10)
                    )
                )

            self.logger.info(
                '\n\nSample SCCM publishers \n'
                '{0}\n\n'.format(
                    df_arPub[
                        ['publisher0', 'pub0_toks', 'pub0_cln']].sample(10)
                    )
                )

            return (df_arPub, df_cpeVen)

        # Form the Cartesian product of WMI Publishers X CPE vendors

        def _cartesian_product(p_df_arPub, p_df_cpeVen):

            self.logger.info('\n\nEntering cartesian_product\n\n')

            # Force copy-by-value
            df_arPub = p_df_arPub.copy()
            df_cpeVen = p_df_cpeVen.copy()

            # List of name tuples to check
            lst_dict = []
            t0 = time()
            mycount = 0
            self.logger.info(
                            '\n\nStarting generation of '
                            'cartesian product of NIST vendors '
                            'to SCCM publishers ... \n'
                            ' *** This can take some time '
                            '- up to 20 min for large prod datasets.\n\n'
                            )

            # Build the the cartisan product of the two sets of names (CPE,
            # SCCM/WMI) by iterating through the input dataframes

            for (
                    t_cpeix,
                    t_cpeVen_orig,
                    t_cpevend_toks,
                    t_cpeVen
                    ) in df_cpeVen.itertuples():

                #   Ignore cpe vendors that are 1 character long (e.g. 'X')

                if (len(t_cpeVen) < 2):
                    self.logger.debug('cpeVen too short - continuing\n')
                    continue

                for (
                        t_arix,
                        t_arPub0_orig,
                        t_arpub_toks,
                        t_arPub0
                        ) in df_arPub.itertuples():

                    # quick heuristics:
                    #   a) 1st word of cpe Vendor string has to be in the
                    #            tokenized wmi Publisher0 string somewhere
                    #   b) condensed cpe name has to be shorter than the full
                    #           WMI 'Publisher0' name

                    if len(t_cpeVen) > len(t_arPub0):
                        # self.logger.debug('arPub0 too short - continuing'
                        continue

                    # Look for at least one occurence of one word in cpeVen
                    #       somewhere in arPub
                    if fz.partial_token_set_ratio(
                                            t_cpeVen,
                                            t_arPub0,
                                            force_ascii=False
                                            ) < 100:
                        continue

                    # Calculate fuzzy matching statistics as "features" for
                    # the subsequent ML classification

                    lst_dict.append({
                        'publisher0': t_arPub0_orig,
                        'pub0_cln': t_arPub0,
                        'vendor_X': t_cpeVen_orig,
                        'ven_cln': t_cpeVen,
                        'fz_ratio': fz.ratio(
                                t_cpeVen,
                                t_arPub0),
                        'fz_ptl_ratio': fz.partial_ratio(
                                t_cpeVen,
                                t_arPub0),
                        'fz_tok_set_ratio': fz.token_set_ratio(
                                t_cpeVen,
                                t_arPub0,
                                force_ascii=False),
                        'fz_ptl_tok_sort_ratio': fz.partial_token_sort_ratio(
                                    t_cpeVen,
                                    t_arPub0,
                                    force_ascii=False),
                        'fz_uwratio': fz.UWRatio(
                                t_cpeVen,
                                t_arPub0)
                        })
                    mycount = mycount + 1
                    if mycount % 1000 == 0:
                        self.logger.debug(
                                    '# entries produced: {0}\n'.format(
                                                mycount
                                                )
                                     )

                #     # debug code to shorten loop for testing
                #     if mycount > 1000:
                #         break

                # # debug code to speed thru loops
                # if mycount > 1000:
                #     break

            duration = time() - t0
            self.logger.info(
                    '\n\n*** Done in {0} sec\n\n'.format(
                            duration
                            )
                    )
            df_match = pd.DataFrame(lst_dict)

            if df_match.empty:
                self.logger.info(
                    'Resulting cartesian product is empty.\n\n'
                    )

            else:
                self.logger.info(
                            '\n\n Vendor match dataframe: \nCounts {0},\n'
                            'Columns: {1}\n\n'.format(
                                    df_match.shape,
                                    df_match.columns
                                    )
                            )
            return (df_match)

        # Previously manually labelled data is used to update the new data to
        # be classified. This ensures that only new, unknown data is input
        # into the ML Classification algorithm.

        def _update_with_labelled_data(p_df_match):

            self.logger.info('\n\nEntering update_with_labelled_data\n\n')

            df_match = p_df_match.copy()

            # add in length of names as features
            df_match['ven_len'] = df_match['vendor_X'].apply(len)
            df_match['pu0_len'] = df_match['publisher0'].apply(len)

            # Read in the data that was manually labelled in order to
            # originally train the ML model.

            try:
                df_match_lbl = pd.io.parsers.read_csv(
                                        gbls.df_label_vendors,
                                        sep=gbls.SEP2,
                                        error_bad_lines=False,
                                        warn_bad_lines=True,
                                        index_col=0,
                                        encoding='utf-8')
            except IOError as e:
                self.logger.critical('I/O error({0}): {1}'.format(
                    e.errno, e.strerror))

            except:
                self.logger.critical(
                    'Unexpected error: {0}'.format(
                        sys.exc_info()[0]))
                raise

            # Normalize the vendor_X field for this data
            df_match_lbl['vendor_X'] = df_match_lbl['vendor_X'].str.replace(
                                            ' ', '_').str.lower()

            self.logger.info(
                            '\n\n Manually labelled dataframe: counts: {0}\n'
                            ', columns: {1}\n'.format(
                                df_match_lbl.shape,
                                df_match_lbl.columns,
                                df_match_lbl['match'].value_counts()
                                )
                            )

            # Update the data to be matched with the results from manual
            # labelling effort. After doing all this hard manual
            # classification effort, why not use the data?

            df_match_upd = self.__ML.upd_using_labelled_data(
                                        df_match,
                                        df_match_lbl
                                        )

            return (df_match_upd, df_match_lbl)

        # Concatentate the manually labelled data with the newly classified
        # data. Drop extraneous columns to form the final dataframe of
        # "Vendor"-"Publisher" corresspondances.

        def _post_process_matched_data(
                    p_df_match_test2,
                    p_df_match_lbl
                    ):

            # concatenate the two sets of classified data: the manual set, and
            # the machine-classified one

            self.logger.info('\n\nEntering post_process_matched_data\n\n')

            # Force call-by-value
            df_match_test2 = p_df_match_test2.copy()
            df_match_lbl = p_df_match_lbl.copy()

            df_match_consol1 = self.__ML.post_process_matched_data(
                                        df_match_test2,
                                        df_match_lbl
                                        )

            # Drop unneeded columns.
            self.df_match_vendor_publisher = df_match_consol1[[
                                                        'publisher0',
                                                        'vendor_X'
                                                        ]]

            self.logger.debug(
                '\n\nMatched vendors-Publishers dataframe \n{0}\n\n'.format(
                    self.df_match_vendor_publisher .shape
                    )
                )

            self.logger.debug(
                            '\n\nSample matches: \n{0}\n\n'.format(
                                    self.df_match_vendor_publisher.sample(20)
                                    )
                            )

            return None

        ######
        # Mainline code for the "match" method
        ######

        # Prepare i/p data frames for matching
        (df_arPub, df_cpeVen) = _match_prepare(df_cpe, df_sccm_ar)

        # Form Cartesian product for potential matches
        df_match = _cartesian_product(df_arPub, df_cpeVen)

        # Update with labelled data
        (df_match_upd, df_match_lbl) = _update_with_labelled_data(df_match)

        # Do the actual machine learning classification
        (df_match_test2, df_match_labelled) = self.__ML.ml_classify(
                                                            df_match_upd
                                                            )

        # Post process matched vendor-Publisher data
        _post_process_matched_data(
                    df_match_test2,
                    df_match_lbl
                    )

        return None
