"""ml: Do Machine Learning Classification of test data.

Purpose
=======

The ml module does tha ML Classification using the Random Forest
Classifier.

There are in fact 2 different models being used:
*   CPE "Vendor" to SCCM "Publisher" matching
*   CPE "Software" to SCCM "Software" inventory data

The appropriate model is chosen at class initialization.

Manually labelled data is used to update the data to be classified. This
eliminates "known" matches from further processing.

The actual ML classification is done.

Then data is post-processed. Any duplicate records are eliminated. Then the
manually matched data is appended to the new classified data to form the final
dataframe.

Public classes
==============

MLClassify      ML Classification using Random Forest Classifier


Restrictions
------------
The following restrictions should be clearly understood and respected.

*  Fields and features *have* to be exactly as specified (same order, same
   names) as in the initialization code.

*  Labelled data always has a "match" attribute field.
"""

import pandas as pd
import numpy as np

from sklearn.externals import joblib

import logging
import sys

import gbls
import utils

# Public classes
__all__ = (
        'MLClassify'
        )


class MLClassify(object):
    """Match NVD CPE "Software" data to SCCM "Software" inventory data.

    Actions
    -------

    *  There are two different models being used for classification. The
       appropriate model is input when the class is initialized. At the same
       time the key and feature lists are initializedd acccordingg to the
       model chosen.

    *  The new data to be classified is updated using manually labelled data.
       This ensures that only new unclassified data is input to ML
       classification.

    *  The Random Forest Classification algorithm is run.

    *  The newly-classifed test data is concatenated with the manually
       labelled data. Duplicates are eliminated to form the final resulting
       dataframe.

    Methods
    -------
    __init__    The class constructor which:
                - initializes logging
                - initializes the key list and feature list variables
                - reads in the ML Model serialized data.

    upd_using_labelled_data
                Updates data to be classified using the manually labelled data

    ml_classify Do the ML Random Forest classification

    post_process_matched_data
                Concatenate the new classified data with the manally labelled
                data. Eliminate any duplicate data records.


    Exceptions
    ----------
    IOError     Log error message and ignore

    Restrictions
    ------------

    The key and feature field lists *must* be kept in the specified order
    since that is # how the ML algorithm was originally trained.

    (See the sccmgbl module for the corresponding definitions.)

    Returns
    -------
    None

    """

    def __init__(
            self,
            type_data=None,
            mylogger=None
            ):
        """Initialize class by configuring logging,  initializing dataframe.

        Actions
        -------

        This is the class constructor. To initialize:

        * Initialize logging
        * Initialize class attributes: key_list, feature_list, attr_list
        * Input the correct model from the serialized disk file.

        I/P Parameters
        --------------
        type_data   specifies which model is to be used:
                        'vendor'    CPE Vendor - SCCM Publisher0
                        'software'  CPE Sofware - SCCM Software inventory

        mylogger    logging object. If None, then a new object is initialzed.

        """
        # Configure logging

        if mylogger is None:
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(gbls.loglvl)
        else:
            self.logger = mylogger

        # Initialize key list and feature list for this model
        # Input the respective serialized ML model

        self.logger.info(
                '\n\nInitializing ML_Match class\n\n'
                'Type of data to be classified: \n{0}\n\n'.format(type_data)
                )

        if (type_data == 'vendor'):

            self._key_list = gbls.vendor_key_list
            self._feature_list = gbls.vendor_feature_list
            self._attr_list = gbls.vendor_attr_list

            model = gbls.clf_vendor

        elif (type_data == 'software'):

            self._key_list = gbls.sft_key_list
            self._feature_list = gbls.sft_feature_list
            self._attr_list = gbls.sft_attr_list

            model = gbls.clf_software

        else:
            self.logger.critical(
                '*** Bad input when initializing the ML_Match class\n\n'
                )
            return None

        # Input the serialized ML model

        try:
            self.__clf = joblib.load(model)

        except IOError as e:
            self.logger.critical(
                    '*** I/O error ML Model({0}): {1}\n\n'.format(
                                                e.errno, e.strerror
                                                )
                    )

        except:
            self.logger.critical(
                '*** Unexpected error loading ML model: {0}\n\n'.format(
                    sys.exc_info()[0]))
            raise

    def upd_using_labelled_data(self, p_df_match, p_df_match_lbl):
        """Update the data to be matched with the manually labelled data.

        Actions
        -------

        *   Discard columns that are not in the key_list. Drop records with
            null fields.

        *   Update the data to be matched (i.e. the cartesian product data)
            with "match" values from the labelled data.

        Returns
        -------
        Updated dataframe

        """
        self.logger.info('\n\nEntering upd_using_labelled_data\n\n')

        # force call-by-value
        df_match = p_df_match.copy()
        df_match_lbl = p_df_match_lbl.copy()

        if df_match_lbl.empty:
            self.logger.info('Input dataframe df_match_lbl is empty.')
            return (df_match)

        if df_match.empty:
            self.logger.info('Input dataframe df_match is empty.')
            return (df_match)

        self.logger.info(
                'Data set to be classified: {0}\n{1}\n{2}\n\n'
                'Labelled data: \n{3}\n{4}\n{5}\n\n'.format(
                                    df_match.shape,
                                    df_match.columns,
                                    df_match.apply(pd.Series.nunique),
                                    df_match_lbl.shape,
                                    df_match_lbl.columns,
                                    df_match_lbl.apply(pd.Series.nunique)
                                    )
                )

        # Update the data to be matched with the results from manual
        # labelling effort. After doing all this hard manual
        # classification effort, why not use it? df_match_upd =
        # pd.merge(df_match, df_match_lbl, how='left', on=['publisher0',
        # 'vendor_X'])

        # First keep only relevant columns from labelled data
        df_match_lbl1 = df_match_lbl.loc[
                                        :,
                                        self._key_list + ['match']
                                        ]

        # Next update new input data with known values from
        # the labelled data
        df_match_upd0 = pd.merge(
                            df_match,
                            df_match_lbl1,
                            how='left',
                            on=self._key_list
                            )

        # drop records with null fields (if any)

        df_match_upd = df_match_upd0.dropna(
                                how='any',
                                subset=self._attr_list
                                )

        # check that only Match values changed
        self.logger.debug(
                    '\n\nCheck that updating with the labelled '
                    'data did not add extra null records.\n'
                    '--Updated data set to be classified:'
                    '\n{0}\n{1}\n{2}\n\n'.format(
                            df_match_upd.shape,
                            df_match_upd.columns,
                            df_match_upd.apply(pd.Series.nunique)
                            )
            )

        return (df_match_upd)

    def ml_classify(self, p_df_match_upd):
        """Do the Machine Learning Classification.

        Actions
        -------

        *   Separate the test data to be classified from the data which has
            already been labelled.

        *   Format the test data as a numpy array and run the Random Forest
            Classification algorithm.

        *   Update the I/P test dataframe with the classification match
            results.

        Returns
        -------
        Dataframe containing classified test data
        Dataframe containing manually labelled data

        """
        # Force call by value
        df_match_upd = p_df_match_upd.copy()

        # Do ML classification
        self.logger.info('\n\nEntering ml_classify\n\n')

        if df_match_upd.empty:
            self.logger.critical(
                '*** ML: Input dframe is empty!'
                )
            return(df_match_upd, df_match_upd)

        # Separate out the test data (i.e. not yet classified)
        df_match_test = df_match_upd[df_match_upd['match'].isnull()]
        df_match_labelled = df_match_upd[
                                df_match_upd['match'].notnull()
                                ]

        if df_match_test.empty:
            df_match_test2 = df_match_test.reset_index(drop=True)
            self.logger.info(
                '\n\n ML: No elements to classify!'
                )
        else:
            self.logger.info(
                '\nStarting ML matching\n\n'
                )

            # Format the test data feature set.
            df_match_test1 = df_match_test[['match'] + self._feature_list]

            # Convert to a numpy array for input to the ML algorithm
            np_match_test1 = np.asarray(df_match_test1)
            Xt = np_match_test1[:, 1:]

            s_match_test = pd.Series(self.__clf.predict(Xt))
            df_match_test2 = df_match_test.reset_index(drop=True)
            df_match_test2['match'] = s_match_test

            # Most, if not all, test data pairs will be rejected
            # since the labelling effort was quite comprehensive

            self.logger.info(
                '\n\nResults of ML '
                'classification: \n\n'
                'Test data: {0}\n{1}\n '
                'Labelled data: {2}\n{3}\n '
                'Match counts: {4}\n'.format(
                    df_match_test2.shape,
                    df_match_test2.columns,
                    df_match_labelled.shape,
                    df_match_labelled.columns,
                    df_match_test2['match'].value_counts()
                    )
                )

            sample_size = min(
                            (df_match_test2.match == 1).sum(),
                            10
                            )

            if sample_size > 0:
                self.logger.info(
                        '\nSample matches: \n{0}\n\n'.format(
                        df_match_test2[
                                df_match_test2.match == 1
                                ].sample(sample_size)
                        )
                    )
            else:
                self.logger.info(
                        '\nNo matches!'
                        )

        return (df_match_test2, df_match_labelled)

    def post_process_matched_data(
                self,
                p_df_match_test2,
                p_df_match_lbl
                ):
        """Post-process the matched and labelled data.

        Actions
        -------

            Concatenate the manually labelled data with the data freshly
            classified by the ML algorithm.

            Eliminate duplicate records, if any.

            Keep +ve matches only.

        Returns
        -------

        Dataframe containing consolidated match data: ML-classified test data
        and labelled data

        """
        # Force call-by-value
        df_match_test2 = p_df_match_test2.copy()
        df_match_lbl = p_df_match_lbl.copy()

        # concatenate the two sets of classified data: the manual set, and
        # the machine-classified one

        self.logger.info('\n\nEntering post_process_matched_data\n\n')

        if df_match_lbl.empty:
            self.logger.info(
                'Input dataframe df_match_labelled is empty.\n\n'
                )
            return (df_match_test2)

        if df_match_test2.empty:
            self.logger.info(
                'Input dataframe df_match_test2 is empty.\n\n'
                )
            return (df_match_lbl)

        self.logger.info(
            'ML-matched data: {0}\n{1}\n{2}\n'
            'Labelled data: {3}\n{4}\n{5}\n\n'.format(
                                df_match_test2.shape,
                                df_match_test2.columns,
                                df_match_test2.apply(pd.Series.nunique),
                                df_match_lbl.shape,
                                df_match_lbl.columns,
                                df_match_lbl.apply(pd.Series.nunique)
                                )
            )

        df_match_consol1 = pd.concat([
                                df_match_test2[
                                    df_match_test2['match'].notnull()
                                    ],
                                df_match_lbl
                                ],
                                ignore_index=True
                                )

        # eliminate any possible remaining duplicate records
        df_match_consol = df_match_consol1.drop_duplicates(self._key_list)

        self.logger.info(
            '\nConsolidated Matched dataframe: '
            '\n{0}\n{1}\n{2}\n{3}\n\n'.format(
                    df_match_consol.shape,
                    df_match_consol.columns,
                    df_match_consol['match'].value_counts(),
                    df_match_consol.apply(pd.Series.nunique)
                    )
            )

        # Only interested in +ve matches
        df_match_consol1 = df_match_consol[
                                df_match_consol['match'] == 1
                                ]

        self.logger.debug(
            '\nFinal consolidated match data set \n{0}\n\n'.format(
                df_match_consol1.shape
                )
            )

        return (df_match_consol1)
