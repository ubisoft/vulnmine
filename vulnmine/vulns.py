"""vulns: Match NVD vuln data with SCCM host data, output basic stats.

Purpose
=======

The vulns module matches the NIST NVD CVE vulnerability data with the SCCM
host data.

The input CVE vulnerability data is categorized as "Low/Med/High" using a
simplistic mapping of the CVSS metrics.

Then the CVE vuln data is merged with the SCCM Software inventory data. This
is turn is merged with the SCCM Host data to produce a dataframe listing
vulnerable software for each host.

The data is grouped in various ways to produce summary statistics.


Public classes
==============

MatchVulns      Merge CVE Vuln data with SCCM host data, print basic stats.

"""
import re

import pandas as pd

import sys


import logging

import gbls
import utils
import sccm
import nvd

# Public classes
__all__ = (
        'MatchVulns'
        )


class MatchVulns(object):
    """Match NVD CPE "Software" data to SCCM "Software" inventory data.

    Actions
    -------
    The input CVE vulnerability data is categorized as "Low/Med/High" using a
    simplistic mapping of the CVSS metrics.

    Then the CVE vuln data is merged with the SCCM Software inventory data.
    This is turn is merged with the SCCM Host data to produce a dataframe
    listing vulnerable software for each host.

    The data is grouped in various ways to produce summary statistics.

    Methods
    -------
    __init__    The class constructor which initializes logging, and an empty
                dataframe for the resulting matches.

    load        Load merged software vulns dataframe that was
                previously saved in pickled format.

    save        Save merged software vulns dataframe to a
                serialized pickled flat file.

    get         Return a *copy* of the merged software vulns dataframe.

    data_merge  Categorize the I/P CVSS data by using a simplistic mapping of
                the CVSS metrics.

                Merge the SCCM Software inventory data is merged with the CPE
                Software - SCCM Software correspondance data.

                The CVE Vulnerability data is next merged with the above.

                Finally merge the SCCM host data to produce a dataframe that
                lists vulnerable software for each host.

    basic_stats Group / sort the merged software vuln data in various ways to
                produce various summary statistics.
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

        self.logger.info('\n\nInitializing MatchVulns class\n\n')

        self.df_sft_vuln = pd.DataFrame({
                                'ResourceID': []
                                })

    def load(self, mypck=None):
        """Load merged software vulns data that was previously saved."""
        self.logger.info(
                '\n\nLoading software vulns data into '
                'df_sft_vuln dataframe\n\n'
                )
        if mypck is None:
            mypck = gbls.df_sft_vuln_pck
        self.df_sft_vuln = pd.read_pickle(mypck)
        return None

    def save(self):
        """Save the merged software vulns data in pickle serialized form."""
        self.logger.info('\n\nSaving df_sft_vuln dataframe\n\n')
        self.df_sft_vuln.to_pickle(gbls.df_sft_vuln_pck)
        return None

    def get(self):
        """Return a *copy* of the data."""
        df_tmp = self.df_sft_vuln.copy()
        self.logger.info(
                '\n\nGet MatchVulns.df_sft_vuln:\n{0}\n{1}\n\n'.format(
                                df_tmp.shape,
                                df_tmp.columns
                                )
                )
        return df_tmp

    def data_merge(
                self,
                df_cve,
                df_match_cpe_sft,
                df_add_rem_g,
                df_sys
                ):
        """Match the CPE "Software" data to the SCCM "Software" data.

        Actions
        -------
        *   The input CVE vulnerability data is categorized.

        *   Calculate the worst case for each of the 3 CVSS metrics: score /
            access complexity / access vector.

        *   A simplistic fn uses the CVSS scores to classify the Vuln as "Low
            / Med / High":

                High:   Overall CVSS score > 7
                        Complexity: LOW / MED
                        Access: NETWORD / ADJACENT NETWORK

                Low:    Overall CVSS score < 4 *OR*
                        (Complexity: HIGH *AND* Local Access only)

                Medium: Everything else

        *   Rename some columns for easier access, drop extraneous columns as
            well.

        *   The SCCM Software inventory data is merged with the CPE Software -
            SCCM Software correspondance data.

        *   The CVE Vulnerability data (which is keyed on CPE Software) is
            next merged with the above.

        *   Finally the SCCM host data is merged with the above. This gives a
            dataframe that lists vulnerable software for each host.


        Returns
        -------
        None

        """
        self.logger.info('\n\nEntering match_vulns_sft\n\n')

        # Categorize the CVE vulnerabilities using a simplistic mapping of
        # the corresponding CVSS metrics.

        def _categorize_cvss_data(df_sft3):
            # The CVE vulnerability data is categorized.

            # Use the CVE vulnerability data as input.
            # Categorize the CVSS impact data
            # Calculate maximum impact for each software
            # Convert the "worst case" impact into a simple classification
            # "Hi-Med-Low"

            self.logger.info(
                    '\n\nEntering categorize_cvss_data\n\n')

            # Function to compute simplistic criticality value

            def myfn6(row):
                # self.logger.debug('input: ', row
                try:
                    my_score = row['cvss_score']
                    my_ease = row['cvss_acc_cmpl_cat'] in [
                                                        'LOW',
                                                        'MEDIUM'
                                                        ]
                    my_access = row['cvss_acc_vect_cat'] in [
                                                        'NETWORK',
                                                        'ADJACENT_NETWORK'
                                                        ]
                    if (my_score > 7) and my_ease and my_access:
                        return ('High')

                    elif (my_score < 4) or (
                                    (not my_ease)
                                    and (not my_access)
                                    ):
                        return('Low')

                    else:
                        return('Medium')
                except:
                    return("None")

            # Categorize the CVSS impact data

            # categories
            df_sft3['cvss_acc_cmpl_cat'] = df_sft3[
                        'cvss:access-complexity'].astype(
                            'category',
                            categories=['HIGH', 'MEDIUM', 'LOW'],
                            ordered=True
                            )

            df_sft3['cvss_acc_vect_cat'] = df_sft3[
                            'cvss:access-vector'].astype(
                                'category',
                                categories=[
                                        'LOCAL',
                                        'ADJACENT_NETWORK',
                                        'NETWORK'
                                        ],
                                ordered=True)

            # convert from string to float for max comparisons
            df_sft3['cvss_score'] = pd.to_numeric(
                                        df_sft3['cvss:score'],
                                        errors='coerce'
                                        )

            # get rid of extraneous data columns
            df_sft3.drop(
                    [
                        u'cvss:score',
                        u'cvss:access-complexity',
                        u'cvss:access-vector',
                        u'cvss:authentication',
                        u'cvss:availability-impact',
                        u'cvss:confidentiality-impact',
                        u'cvss:integrity-impact'],
                    # u'vuln:security-protection'],
                    # 170118 Bug fix: Sometimes not present
                    inplace=True,
                    axis=1)

            # rename some other columns for easier access
            df_sft4 = df_sft3.rename(
                                columns={
                                    'vuln:cve-id': 'cve_id',
                                    'vuln:product': 'cpe_prod',
                                    'cvss:source': 'cvss_src'}
                                    )

            self.logger.info(
                    '\n\nProcessing CVE '
                    'vulnerability data: \n{0}\n{1}\n\n'.format(
                            df_sft4.shape,
                            df_sft4.columns
                            )
                    )

            # Calculate maximum impact for each software

            # group vulns by software
            df_sft4_gp = df_sft4.groupby('cpe_prod')

            # compute worst case value for each software
            df_sft4_agg = df_sft4_gp.agg({'cvss_score': max,
                                          'cvss_acc_cmpl_cat': max,
                                          'cvss_acc_vect_cat': max})

            self.logger.debug(
                '\n\n Aggregated CVE vuln data '
                'for worst case\n{0}\n{1} '.format(
                        df_sft4_agg.shape,
                        df_sft4_agg.columns
                        )
                )

            # Convert the "worst case" impact into a simple classification
            # of "Hi-Med-Low"

            # Compute the criticality for the vuln data
            df_sft4_agg['crit_X'] = df_sft4_agg.apply(myfn6, axis=1)

            self.logger.debug(
                    '\nAggregated vuln data counts '
                    'by criticality \n{0}\n\n'.format(
                            df_sft4_agg.crit_X.value_counts()
                            )
                    )

            # The criticality value is converted to a pandas category
            my_crit_categories = ['None', 'Low', 'Medium', 'High']

            # and then convert the calculated value to a category
            df_sft4_agg['crit_X_cat'] = df_sft4_agg['crit_X'].astype(
                                            'category',
                                            categories=my_crit_categories,
                                            ordered=True
                                            )

            df_sft4_agg.drop(['crit_X'], axis=1, inplace=True)

            self.logger.info(
                    '\n\nAggregated vuln data: \n{0}\n{1}\n\n'.format(
                                                        df_sft4_agg.shape,
                                                        df_sft4_agg.columns
                                                        )
                    )

            return (df_sft4_agg)

        # Match vulnerabilities with software inventory data
        # Then merge this with the SCCM host data.

        def _update_hosts_with_vulns(df_sft4_agg):

            self.logger.info(
                    '\n\nEntering update_hosts_with_vulns\n\n')

            ######
            #   Process SCCM software inventory data
            ######

            # drop unused columns
            df_add_rem_g2 = df_add_rem_g.drop(
                                            [
                                                'AgentID',
                                                'GroupID',
                                                'ProdID0',
                                                'RevisionID',
                                                'TimeStamp'
                                                ],
                                            axis=1
                                            )

            self.logger.info(
                '\nSCCM inventory data to '
                'start with: \n{0}\n{1}\n\n'.format(
                        df_add_rem_g2.shape,
                        df_add_rem_g2.columns
                        )
                )

            ######
            # Merge SCCM inventory with "match" data
            ######

            self.logger.info(
                '\nProduct-software match dframe i/p '
                '\n{0}\n{1}\n\n'.format(
                        df_match_cpe_sft.shape,
                        df_match_cpe_sft.columns
                        )
                )

            df_add_rem_g3 = pd.merge(
                                df_add_rem_g2,
                                df_match_cpe_sft,
                                how='inner',
                                on=['DisplayName0', 'Version0']
                                )

            self.logger.debug(
                '\n\nSCCM inventory data after '
                'inner join with product-software '
                'match dataframe: \n{0}\n{1}\n\n'.format(
                        df_add_rem_g3.shape,
                        df_add_rem_g3.columns
                        )
                )

            ######
            # Merge vulnerability data with sccm software inventory data
            ######

            # Merge inventory data with aggregated vuln data
            # Index of df_sft4_agg is the CPE ID.

            self.logger.debug(
                '\nVuln dframe i/p '
                '\n{0}\n{1}\n\n'.format(
                        df_sft4_agg.shape,
                        df_sft4_agg.columns
                        )
                )

            df_add_rem_g4 = pd.merge(
                                df_add_rem_g3,
                                df_sft4_agg,
                                how='inner',
                                left_on='t_cve_name',
                                right_index=True
                                )

            self.logger.info(
                '\n\nSCCM inventory data after '
                'inner join with vulnerability data\n{0}\n{1}\n\n'.format(
                        df_add_rem_g4.shape,
                        df_add_rem_g4.columns
                        )
                )

            # Look at distribution of vuln criticality
            self.logger.info(
                '\nDistribution of vulnerabilities '
                'in installed software\n{0}\n\n'.format(
                    df_add_rem_g4['crit_X_cat'].value_counts()
                    )
                )

            ######
            # Now add in SCCM host data
            ######

            self.logger.debug(
                '\nSCCM discovered '
                'host data\n{0}\n{1}\n\n'.format(
                    df_sys.shape,
                    df_sys.columns
                    )
                )

            # Merge host data with inventory / vulnerability data
            self.df_sft_vuln = pd.merge(
                                    df_sys,
                                    df_add_rem_g4,
                                    how='inner',
                                    on='ResourceID'
                                    )

            self.logger.info(
                '\n\nSCCM host data with '
                'merged vulnerability information\n{0}\n{1}\n\n'.format(
                    self.df_sft_vuln.shape,
                    self.df_sft_vuln.columns
                    )
                )

            return None

        ######
        # mainline code for match_vulns_sft method
        ######

        # Do the matching

        if df_match_cpe_sft.empty:
            self.logger.critical(
                '\n\n*** I/P dframe df_match_cpe_sft empty. '
                'No host-vuln matching will be done.\n\n'
                )
            # initialize to an empty dframe
            self.df_sft_vuln = pd.DataFrame({'K1': []}, index=[])
        else:

            df_sft4_agg = _categorize_cvss_data(df_cve)

            if df_sft4_agg.empty:
                    self.logger.critical(
                        '\n\n*** dframe df_sft4_agg empty. '
                        'No host-vuln matching will be done.\n\n'
                        )
                    # initialize to an empty dframe
                    self.df_sft_vuln = pd.DataFrame({'K1': []}, index=[])
            else:

                _update_hosts_with_vulns(df_sft4_agg)

        return None

    def basic_stats(self):
        """Analyze vulnerable 3rd-party software.

        Actions
        -------

        Vuln / inventory data is grouped by vulnerability criticality. This
        shows which vulnerable software is the most widely-installed.

        Next data is sorted by site / criticality to show where vulnerable
        software is installed.

        Returns
        -------
        None
        """
        self.logger.info('\n\n*** Entering basic_stats\n')

        my_df_sft_vuln = self.get()

        if my_df_sft_vuln.empty:
            self.logger.critical(
                '\n\n*** Empty dframe MatchVulns.df_sft_vuln. '
                'No stats can be produced.\n\n')
            return None

        my_df_sft_vuln.to_csv(
                        sep=gbls.SEP,
                        encoding='utf-8',
                        path_or_buf="{0}".format(
                                            gbls.csvdir +
                                            "sft_vuln_raw.csv"
                                            )
                        )

        # Have to convert category to original dtype to avoid error
        # in pandas when aggregating / resetting indices.

        my_df_sft_vuln['crit_X'] = my_df_sft_vuln['crit_X_cat'].astype(object)


        # Group by vuln criticality, then look at each group
        df_3sft_most_vuln_gp = my_df_sft_vuln.groupby(['crit_X_cat'])

        # top 25 most widely deployed software in "High" group
        s_tmp = df_3sft_most_vuln_gp.get_group(
                        'High'
                        )['t_cve_name'].value_counts().nlargest(25)

        self.logger.info(
            '\n\nTop 25 most widely deployed software '
            'with "High" vulns:\n{0}\n\n'.format(s_tmp)
            )

        s_tmp.reset_index().to_json(
                orient="records",
                force_ascii=False,
                path_or_buf="{0}".format(
                                    gbls.csvdir +
                                    "top25_sft_high.json"
                                    )
                )

        ######
        # Where are these software installed?
        ######

        # Where are these software installed?

        # Group data by site / vuln criticality
        dfs1 = my_df_sft_vuln.groupby(['Site_X', 'crit_X']).size()

        try:

            dfs1a = dfs1.unstack('crit_X').fillna(0).nlargest(
                                                            10,
                                                            ['High', 'Medium']
                                                            )
        except KeyError as e:
            self.logger.critical(
                '\n\n***Site/ High-Med vulns - KeyError: {0}\n\n'.format(e)
                )

        # dfs1a.plot(kind='bar', stacked=True)

        self.logger.info(
            '\n\nGrouping host vuln data '
            'by site / vuln criticality:\n{0}\n\n'.format(dfs1a)
            )

        dfs1a.reset_index().to_json(
                    orient="records",
                    force_ascii=False,
                    path_or_buf="{0}".format(
                                        gbls.csvdir +
                                        "site_by_criticality.json"
                                        )
                    )

        return None
