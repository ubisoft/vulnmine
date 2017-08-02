import sys
import pandas as pd
import re
from yapsy.IPlugin import IPlugin

import vulnmine

# modify search path to include parent directory
sys.path.append("../")

# print ("debug plugin1: {0}".format(__package__))

# if hasattr(vulnmine, '_called_from_test'):
#     # called from within a pytest run
#     import sccm
#     import gbls
# else:
#     # called "normally" so import from pkg
#     if __package__ is None:
#         # Running in docker or directly from source
#         import sccm
#         import gbls
#     else:
#         # Running as pkg
#         import vulnmine.sccm as sccm
#         import vulnmine.gbls as gbls

# Imports change if running in docker
if 'jovyan' in open('/etc/passwd').read():
    import sccm
    import gbls
else:
    # Must be running as a package
    import vulnmine.sccm as sccm
    import vulnmine.gbls as gbls


class PluginOne(IPlugin):
    def print_name(self):
        print (
            'Plugin 1 for custom Vulnmine Input'
            ' has loaded successfully.'
            )


    def modify_hosts(self, my_hosts):
        """
        Functions
        =========

        _classify_using_sccm_data
            Classify discovered hosts using SCCM discovery data.
        _classify_using_DN_OUs
            Classify hosts by membership in AD OUs
        _classify_using_ad_grps
            Use membership in AD groups to classify hosts.

        """
        # Updated dframe
        new_df_sys = ''

        def _classify_using_sccm_data():
            """Classify discovered hosts using sccm v_R_System data.

            Actions
            =======

            To categorize by Region:

                The AD_Site_Name0 is used to map hosts to a Region.

            Hardcoded lists of sites are then used to classify by region.

            """
            ######
            #   Classify Sites by Region based on AD_Site_Name0 field in
            #       v_R_System record
            ######

            REGION_A = [u'NTH', u'WST']
            REGION_B = [u'STH', u'EST']

            print(
                '\n\n\nEntering plugin1 - _classify_using_sccm_data\n\n')

            # Map Site to corresponding Region

            def __classify_site_by_region(mysite):

                try:
                    if mysite in REGION_A:
                        myregion = 'Region_A'
                    elif mysite in REGION_B:
                        myregion = 'Region_B'
                    else:
                        myregion = 'Unknown'

                except:
                    print(
                        '\n\n***Error in classifying by '
                        '\nregion for value: "{0}"\n\n'.format(
                            mysite))
                    myregion = None
                return myregion

            # produce series with Region for each site
            s_myRegion = new_df_sys['Site_X'].apply(
                __classify_site_by_region
                ).astype('category')

            # place into the main dataframe
            new_df_sys['Region_X'] = pd.Series(
                                        s_myRegion,
                                        index=new_df_sys.index)

            # print() output Region values
            print(
                '\n\nRegions: \n{0}\n\n'.format(
                        pd.unique(new_df_sys['Region_X'].values)
                        )
                )

            # Number of hosts in each region
            print(
                '\n# hosts in each region: \n{0}\n\n'.format(
                    new_df_sys['Region_X'].value_counts()
                    )
                )
            return None





        def _classify_using_DN_OUs():
            """Classify hosts member of an AD OU.

            Actions
            =======
            Extract various patterns from 'Distinguished_Name0' field of
            the v_R_System table. Use these values to classify the hosts.

            Exceptions
            ==========
            IOError     Produce error message and then ignore

            """
            print('\n\nEntering plugin1 - _classify_using_DN_OUs\n\n')

            # Extract the Distinguished_Name0 field as a series and
            # prepare for pattern matching
            s_dn = new_df_sys[
                        'Distinguished_Name0'].str.strip().str.lower()

            # Look for generic desktops/laptops/servers

            pattern = re.compile(
                r'ou=[0-9A-Za-z_ ]*(desktop|laptop|server)',
                re.IGNORECASE | re.UNICODE
                )

            new_df_sys['HostFn_X'] = s_dn.str.extract(
                                            pattern,
                                            expand=False).astype('category')

            print(
                '\n\n# hosts of each type:\n{0}'.format(
                                    new_df_sys['HostFn_X'].value_counts()
                                    )
                )
            return None


        def _classify_using_ad_grps():
            """Classify hosts member of an AD group.

            Actions
            =======
            Read CSV format data which lists contents of the AD groups.

            Mark hosts that are members of these groups.

            Exceptions
            ==========
            IOError     Produce error message and then ignore

            """
            print('\n\nEntering plugin1 - _classify_using_ad_grps\n\n')

            try:
                df_ad_vip = pd.io.parsers.read_csv(
                                    gbls.ad_vip_grps,
                                    sep=gbls.SEP2,
                                    error_bad_lines=False,
                                    warn_bad_lines=True,
                                    quotechar='"',
                                    comment=gbls.HASH,
                                    encoding='utf-16')

            except IOError as e:
                print('\n\n***I/O error({0}): {1}\n\n'.format(
                            e.errno, e.strerror))

            # ValueError Exception could mean empty data set read
            # Initialize an empty dataframe
            except ValueError as e:
                print(
                    '\n\n***Value error: {0}\n- empty data set '
                    'returned\n\n'.format(
                                sys.exc_info()[0]
                                )
                    )
                df_ad_vip = pd.DataFrame({'distinguishedName': []})

            except:
                print(
                    '\n\n***Unexpected error: {0}\n\n'.format(
                        sys.exc_info()[0])
                        )
                raise

            # print() basic information
            print(
                '\n\nRaw input: Hosts in VIP AD '
                'group : \n{0}\n{1}\n\n'.format(
                    df_ad_vip.shape,
                    df_ad_vip.columns)
                )

            # mark hosts that are in the VIP AD group
            crit_ad_excl = new_df_sys.Distinguished_Name0.isin(
                df_ad_vip['distinguishedName'])
            new_df_sys.loc[crit_ad_excl, 'VIP_X'] = 'vip'

            # count of marked hosts
            print(
                '\n\nSCCM-managed hosts in '
                'VIP AD group: \n{0}\n\n'.format(
                        new_df_sys['VIP_X'].value_counts()
                        )
                )

            print(
                '\nSystem dataframe with '
                'additional classification columns: \n{0}\n{1}\n\n'.format(
                        new_df_sys.shape,
                        new_df_sys.columns
                        )
                )
            return None

        #####
        #   Mainline code
        #####
        # Read packed hosts dframe
        my_hosts.load()
        new_df_sys = my_hosts.get()

        print (
            '\nPlugin I/P sccm dframe:\n{0}\n{1}'.format(
                                                new_df_sys.shape,
                                                new_df_sys.columns
                                                )
            )

        # Classify hosts
        _classify_using_sccm_data()
        _classify_using_DN_OUs()
        _classify_using_ad_grps()

        # Modify hosts object internal dframe directly.

        # This is more direct and probably safer than pandas to_csv /
        # read_csv

        my_hosts.df_sys = new_df_sys
        my_hosts.save()
        return None