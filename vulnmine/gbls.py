"""Define Global variables and constants.

sccmgbls defines all global variables and constants.

See utils for initialization of default values.
"""
import logging

######
# Debug and logging output
######

# Logging levels, default level for logging

LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warning': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}

# Logging level

loglvl = logging.INFO

######
# Miscellaneous
######

# Version
VERSION = '1.0'

#   Working Directories
DATADIR = 'data/'
CONFDIR = 'vulnmine_data/'
wkdir = ''
pckdir = ''
csvdir = ''
nvddir = ''
pkgdir = ''

#   Configuration files
CONFIG_DEFAUlTS = 'vulnmine_defaults.ini'
CONF_FILE = 'vulnmine.ini'
log_conf = ''


# Scheduling
CANCEL_ON_FAILURE = False
SCHED_TIME = "11:00"
SCHED_SLEEP = 60

######
#   CSV Input data
######

# separate individual values in a particular field
SEP = "|"
SEP2 = ","
HASH = '#'

#######
#   Input data - mostly CSV
#######

v_r_system = ''
v_gs_add_rem_pgms = ''
v_gs_add_rem_pgms_64 = ''
ad_vip_grps = ''
s_vndr_stop_wds = ''
df_label_software = ''
df_label_vendors = ''

######
#   Saved dataframe names
#   'rf_' - refactor code version
######
df_sys_pck = ''
df_add_rem_g_pck = ''
df_cpe4_pck = ''
df_cve_pck = ''
df_v_R_System_3modified_pck = ''
df_sft_vuln_pck = ''
df_match_vendor_publisher_pck = ''
df_match_cpe_sft_pck = ''

######
#   NVD data
######

nvdcpe = ''
nvdcve = ''

# Downloads

url_meta_base = ''
url_meta_end = ''
url_xml_base = ''
url_xml_end = ''
url_cpe = ''

cpe_filename = ''
cpe_max_age = 7

#   Number of years of NVD CVD XML feed files
num_nvd_files = 0

nvd_meta_filename = ''
nvddir = ''

######
#   Models
######
clf_vendor = ''
clf_software = ''

######
#   Fields for the ML classification
######

# Important note: These fields *must* be kept in this order since that is
# how the ML algorithm was originally trained.

#   Vendor data fields
vendor_key_list = ['publisher0', 'vendor_X']
vendor_feature_list = [
                      'fz_ptl_ratio',
                      'fz_ptl_tok_sort_ratio',
                      'fz_ratio',
                      'fz_tok_set_ratio',
                      'fz_uwratio',
                      'ven_len',
                      'pu0_len'
                      ]
vendor_token_list = ['pub0_cln', 'ven_cln']
vendor_attr_list = vendor_key_list + vendor_feature_list + vendor_token_list


#   Software data fields
sft_key_list = [
                'vendor_X',
                'software_X',
                'title_X',
                'DisplayName0',
                'release_X',
                'Version0'
                ]
sft_feature_list = [
                    'fz_ratio',
                    'fz_ptl_ratio',
                    'fz_tok_set_ratio',
                    'fz_ptl_tok_sort_ratio',
                    'fz_uwratio',
                    'fz_rel_ratio',
                    'fz_rel_ptl_ratio',
                    'titlX_len',
                    'DsplyNm0_len'
                    ]

sft_attr_list = sft_key_list + sft_feature_list + ['t_cve_name']

######
#   Plugins
######

#   Plugins must be located in the following directory
plugin_folder = ''

#   Plugin names specified here must match those in the "*.yapsy-plugin"
#   configuration files

PLUGINIP = 'Plugin Input'
PLUGINRPT = 'Plugin Report'

#   Global plugin manager object
plugin_manager = None

#   Global plugin function switch
activate_plugins = True
