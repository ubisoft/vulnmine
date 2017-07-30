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
from ConfigParser import SafeConfigParser
import pkg_resources

import gbls

utils_logger = logging.getLogger(__name__)


def setup_logging(
        default_path=gbls.pkgdir + 'logging.json',
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
    # Files distributed with vulnmine are installed in the python
    # '<sys.prefix>/vulnmine_data' directory
    gbls.pkgdir = pkg_resources.resource_filename(
                                            'vulnmine',
                                            'vulnmine_data/'
                                            )

    parser = SafeConfigParser()
    try:
        default_config_file = gbls.pkgdir + gbls.CONF_DEF_FILE
        parser.read(default_config_file, CONF_FILE)
    except Exception as e:
        print('***Error reading configuration file '
            '"data/vulnmine.ini": {0}'.format(e)
            )
    try:
        gbls.pckdir = gbls.wkdir + parser.get('Pckdir')
        gbls.csvdir = gbls.wkdir + parser.get('Csvdir')
        gbls.nvddir = gbls.wkdir + parser.get('Nvddir')

        # Create directories if do not exist
        if not os.path.isdir(gbls.pckdir):
            os.makedirs(gbls.pckdir)
        if not os.path.isdir(gbls.nvddir):
            os.makedirs(gbls.nvddir)

        ######
        #   Vulnmine pkg data files
        ######

        gbls.s_vndr_stop_wds = (gbls.pkgdir +
                    parser.get('S_vndr_stop_wds')
                    )
        gbls.df_label_software = (gbls.pkgdir +
                    parser.get('Df_label_software')
                    )
        gbls.df_label_vendors = (gbls.pkgdir +
                    parser.get('Df_label_vendors')
                    )

        gbls.clf_vendor = gbls.pkgdir + parser.get('Clf_vendor')
        gbls.clf_software = gbls.pkgdir + parser.get('Clf_software')
        gbls.log_conf = gbls.pkgdir + parser.get('Log_conf')

        ######
        #   CSV Input data
        ######

        gbls.v_r_system = (gbls.csvdir +
                    parser.get('V_r_system')
                    )
        gbls.v_gs_add_rem_pgms = (gbls.csvdir +
                    parser.get('V_gs_add_rem_pgms')
                    )
        gbls.v_gs_add_rem_pgms_64 = (gbls.csvdir +
                    parser.get('V_gs_add_rem_pgms_64')
                    )

        gbls.ad_vip_grps = gbls.csvdir + parser.get('Ad_vip_grps')

        ######
        #   Saved dataframe names
        #   'rf_' - refactor code version
        ######
        gbls.df_sys_pck = gbls.pckdir + parser.get('Df_sys_pck')
        gbls.df_add_rem_g_pck = (gbls.pckdir +
                    parser.get('Df_add_rem_g_pck'))
        gbls.df_cpe4_pck = gbls.pckdir + parser.get('Df_cpe4_pck')
        gbls.df_cve_pck = gbls.pckdir + parser.get('Df_cve_pck')

        gbls.df_v_R_System_3modified_pck = (gbls.pckdir +
                    parser.get('Df_v_R_System_3modified_pck')
                    )

        gbls.df_sft_vuln_pck = gbls.pckdir + parser.get('Df_sft_vuln_pck')
        gbls.df_match_vendor_publisher_pck = (gbls.pckdir +
                    parser.get('Df_match_vendor_publisher_pck')
                    )
        gbls.df_match_cpe_sft_pck = (gbls.pckdir +
                    parser.get('Df_match_cpe_sft_pck')
                    )

        ######
        #   NVD data
        ######

        # https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2016.meta
        gbls.url_meta_base = parser.get('Url_meta_base')
        gbls.url_meta_end = parser.get('Url_meta_end')
        gbls.url_xml_base = parser.get('Url_xml_base')
        gbls.url_xml_end = parser.get('Url_xml_end')
        gbls.url_cpe = parser.get('Url_cpe')
        gbls.cpe_filename = parser.get('Cpe_filename')
        gbls.cve_filename = parser.get('Cve_filename')
        gbls.cpe_max_age = parser.getint('Cpe_max_age')
        gbls.nvd_meta_filename = parser.get('Nvd_meta_filename')

        gbls.nvdcpe = gbls.nvddir + gbls.cpe_filename
        gbls.nvdcve = gbls.nvddir + gbls.cve_filename

    except Exception as e:
        print('*** Error in config file: {0}'.format(e))

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
