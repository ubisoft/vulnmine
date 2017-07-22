"""Initialize logging, global variables.

setup_logging: Initialize logging

init_globals: Initialize global variables

"""
import os
import json
import logging.config
import StringIO as strIO
import zipfile as zipf

import requests
from yapsy.PluginManager import PluginManager

import gbls

utils_logger = logging.getLogger(__name__)


def setup_logging(
        default_path=gbls.confdir + 'logging.json',
        default_level=logging.INFO,
        env_key='LOG_CFG'
        ):
    """Configure and initialize logging.

    I/P Parameters
    ==============

    default_path:   Directory / filename for json log output
    default_level:  Default logging level
    env_key:        Environment variable to configure logging.

    Return Value
    ============

    Returns None.

    """
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = json.load(f)
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)

    # Initialize logging for utils itself

    utils_logger.setLevel(gbls.loglvl)

    utils_logger.info('\n\nUtils: Logging initialized\n\n')

    return None


def init_globals():
    """Initialize global variables."""
    gbls.pckdir = gbls.wkdir + 'pck/'
    gbls.confdir = gbls.wkdir + 'conf/'
    gbls.csvdir = gbls.wkdir + 'csv/'
    gbls.nvddir = gbls.wkdir + 'nvd/'
    gbls.modeldir = gbls.wkdir + 'models/'

    # Create directories if do not exist
    if not os.path.isdir(gbls.pckdir):
        os.makedirs(gbls.pckdir)
    if not os.path.isdir(gbls.nvddir):
        os.makedirs(gbls.nvddir)

    ######
    #   CSV Input data
    ######

    gbls.v_r_system = gbls.csvdir + 'v_R_System.csv'
    gbls.v_gs_add_rem_pgms = gbls.csvdir + 'v_GS_ADD_REMOVE_PROGRAMS.csv'
    gbls.v_gs_add_rem_pgms_64 = (
                            gbls.csvdir
                            + 'v_GS_ADD_REMOVE_PROGRAMS_64.csv'
                            )
    gbls.ad_vip_grps = gbls.csvdir + 'ps-ad-vip.csv'
    gbls.s_vndr_stop_wds = gbls.csvdir + 's_vndr_stop_wds.csv'
    gbls.df_label_software = gbls.csvdir + 'label_software.csv'
    gbls.df_label_vendors = gbls.csvdir + 'label_vendors.csv'

    ######
    #   Saved dataframe names
    #   'rf_' - refactor code version
    ######
    gbls.df_sys_pck = gbls.pckdir + 'rf_df_sys.pck'
    gbls.df_add_rem_g_pck = gbls.pckdir + 'rf_df_add_rem_g.pck'
    gbls.df_cpe4_pck = gbls.pckdir + 'rf_df_cpe4.pck'
    gbls.df_cve_pck = gbls.pckdir + 'rf_df_cve.pck'
    gbls.df_v_R_System_3modified_pck = (
                        gbls.pckdir
                        + 'rf_df_v_R_System_3modified.pck'
                        )
    gbls.df_sft_vuln_pck = gbls.pckdir + 'rf_gbls.df_sft_vuln.pck'
    gbls.df_match_vendor_publisher_pck = (
                        gbls.pckdir
                        + 'rf_df_match_vendor_publisher.pck'
                        )
    gbls.df_match_cpe_sft_pck = (
                        gbls.pckdir
                        + 'rf_df_match_cpe_sft.pck'
                        )

    ######
    #   NVD data
    ######

    # https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2016.meta
    gbls.url_meta_base = (
                    'https://static.nvd.nist.gov'
                    + '/feeds/xml/cve/2.0/nvdcve-2.0-'
                    )
    gbls.url_meta_end = '.meta'

    # https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2016.xml.zip
    gbls.url_xml_base = 'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-'
    gbls.url_xml_end = '.xml.zip'

    gbls.url_cpe = (
                'http://static.nvd.nist.gov/feeds/xml/'
                'cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip'
                )

    # Hardcode the cpe filename in case.
    gbls.cpe_filename = 'official-cpe-dictionary_v2.3.xml'
    gbls.cve_filename = 'nvdcve-2.0-'

    # Update the cpe data if older than this value (in days)
    gbls.cpe_max_age = 7

    gbls.nvd_meta_filename = 'my_meta_'

    # The cpe dictionary lists standardized vendor - software names
    gbls.nvdcpe = gbls.nvddir + gbls.cpe_filename

    # The cve vulnerability data files are named by year
    #    eg nvdcve-2.0-2015.xml

    gbls.nvdcve = gbls.nvddir + gbls.cve_filename

    ######
    #   ML Models
    ######
    gbls.clf_vendor = (
                gbls.modeldir +
                'vendor_classif_trained_Rdm_Forest.pkl.z'
                )
    gbls.clf_software = (
                gbls.modeldir +
                'software_classif_trained_Rdm_Forest.pkl.z'
                )

    return None

def load_plugins():
    """Load plugins.

    I/P Parameters
    ==============

    None.

    Actions
    =======

    1. Sets yapsy logger's logging level to the global default.
    2. Loads the (one and only) plugin from the plugin directory.
    3. Invokes the plugin's "print_name" method to print the name.

    Return Value
    ============

    Returns None.

    """
    utils_logger.info('\n\nEntering load_plugins\n\n')

    # Set logging for the yapsy plugin framework
    logging.getLogger('yapsy').setLevel(gbls.loglvl)

    # Load the plugins from the plugin directory.
    gbls.plugin_manager = PluginManager()
    gbls.plugin_manager.setPluginPlaces([gbls.PLUGINFOLDER])
    gbls.plugin_manager.collectPlugins()

    # Loop through the plugins and print their names.
    for plugin in gbls.plugin_manager.getAllPlugins():
        plugin.plugin_object.print_name()

    return None

def get_zip(myurl):
    """Download and unzip a file

    This utility rtn downloads a file given the URL and then unzips it.

    Parameters
    ==========

    myurl   The URL of the file to be downloaded

    Returns
    =======
    (file_name, extracted_file)
            Filename    Name in file in the zip archive
            extracted_file
                        Contents of file

            (None, None) is returned if an error is detected.

    Exceptions
    ==========
    RequestException:   The requests module, used for https access, has
                    several exception conditions.

    Restrictions
    ============

    This rtn is designed to be used for NIST XML file downloads.
    The assumption is that the archive contains only 1 XML in zipped format.
    The contents of the file are read into memory.

    """
    utils_logger.info(
        '\n\nEntering get_zip to read {0}\n\n'.format(
                                            myurl
                                            )
        )

    try:
        resp = requests.get(myurl)

    except requests.exceptions.RequestException as e:
            utils_logger.critical(
                '\n\n***NVD XML feeds - Error: \n{0}\n{0}\n\n'.format(
                    myurl,
                    e
                    )
                )
            return (None, None)

    # unzip compressed archive
    my_zipfile = zipf.ZipFile(strIO.StringIO(resp.content))
    zip_names = my_zipfile.namelist()

    # should be only 1 file in the archive
    if len(zip_names) == 1:
        file_name = zip_names.pop()
        extracted_file = my_zipfile.open(file_name).read()
        utils_logger.info(
            'get_zip: Successfully extracted {0}'.format(
                                                        file_name
                                                        )
            )
        return (file_name, extracted_file)
    else:
        utils_logger.critical(
            'get_zip: Error in extracting NVD zip file'
            )
        return (None, None)
