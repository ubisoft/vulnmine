"""Mine SCCM data for 3rd-party vulnerabilities.

Usage:

vulnmine.py [-h] [-d] [-l loglevel] [-w work_directory] [--help] [
            --debug] [--log=loglevel] [--workdir=work_directory]

-h --help   Produce this help messages

-l loglevel --log=loglevel

             Specify the level of logging:
                debug, info, warning, error, critical.
             Logging is to standard output.

-w work_directory --workdir=work_directory

            Specify work directory containing data

Function
--------

Input files are assumed to be in various sub-directories of the main work
directory for this program.

    SCCM data from Powershell scripts -- CSV files
    AD data from PS scripts -- CSV files
    NVD / CPE data from NIST -- zip archives
    Pickled pandas dataframes such as 'stop' words for tokenization
    Machine Learning models in scipy 'joblib' dump format

Outputs:
    Pickled pandas dataframes for
        SCCM data:
            Discovered hosts
            Software Inventory data for SCCM WMI Registry 'Add'
        NIST NVD data:
            CVE/CVSS vulnerability data
            CPE vendor-software database data
    JSON file with summarized, consolidated SCCM / NIST data

Examples
--------

    python vulnmine.py mydir
"""
import logging
import argparse
import sys
import os
import schedule
import time
import functools
from yapsy.PluginManager import PluginManager

import utils
import gbls
import sccm
import nvd
import matchven
import matchsft
import vulns

# Don't export any symbols
# __all__ = ()


######
#   Custom Exception Handlers
######

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg


class NameInvalid(Exception):
    """Handle exception if Working directory invalid."""

######
#   Functions to handle specific processing
######


def rd_sccm_hosts():
    """Read in the SCCM hosts data and munge it"""
    hosts = sccm.SccmHosts()
    hosts.read()
    hosts.save()

    # Invoke Input plugin for customized I/P data
    if gbls.activate_plugins:
        plugin1 = gbls.plugin_manager.getPluginByName(gbls.PLUGINIP)
        plugin1.plugin_object.modify_hosts(hosts)

def rd_sccm_sft():
    """Read SCCM software inventory data"""
    sft = sccm.SccmSoft()
    sft.read()
    sft.save()

def rd_cpe():
    """Read and process NIST NVD vendor / software data"""
    # This data describes (using a well-defined standardized format)
    # the software products produced by each vendor.

    cpe = nvd.NvdCpe()
    cpe.download_cpe()
    cpe.read()
    cpe.save()

def rd_cve():
    """Read and process NIST Vulnerability data"""

    # This data references the NIST CPE data to describe known
    # vulnerabilities for each software product / version.

    cve = nvd.NvdCve()
    cve.download_cve()
    cve.read()
    cve.save()

def match_vendors():
    """Match CPE vendor data to SCCM publisher data"""
    # Initialize inputs
    cpe = nvd.NvdCpe()
    cpe.load()
    sft = sccm.SccmSoft()
    sft.load()

    # Process
    match_vendor = matchven.MatchVendor()

    match_vendor.match(
                cpe.get(),
                sft.get()
                )
    match_vendor.save()

def match_sft():
    """Match CPE software to SCCM Publishers"""
    #   Use the set of vendor - publisher correspondance data
    #   to determine the possible software for each SCCM publisher.
    #
    #   Then match CPE software data to SCCM software inventory data

    # Initialize inputs
    sft = sccm.SccmSoft()
    sft.load()
    match_vendor = matchven.MatchVendor()
    match_vendor.load()
    cpe = nvd.NvdCpe()
    cpe.load()

    # Process
    match_soft = matchsft.MatchSoft()

    match_soft.match(
            match_vendor.get(),
            sft.get(),
            cpe.get()
            )
    match_soft.save()

def upd_hosts_vulns():
    """Determine vulnerable software installed on each SCCM host"""
    #   Update SCCM host data with consolidated vuln data
    #   Produce some basic statistics

    # Initialize inputs
    hosts = sccm.SccmHosts()
    hosts.load()
    cve = nvd.NvdCve()
    cve.load()
    sft = sccm.SccmSoft()
    sft.load()
    match_soft = matchsft.MatchSoft()
    match_soft.load()

    # Process

    match_vulns = vulns.MatchVulns()

    match_vulns.data_merge(
                cve.get(),
                match_soft.get(),
                sft.get(),
                hosts.get()
                )

    match_vulns.save()

def output_stats():
    match_vulns = vulns.MatchVulns()
    match_vulns.load()

    match_vulns.basic_stats()

    # Invoke Report plugin for customized stats
    if gbls.activate_plugins:
        plugin2 = gbls.plugin_manager.getPluginByName(gbls.PLUGINRPT)
        plugin2.plugin_object.custom_stats(match_vulns)

def do_all():
    rd_sccm_hosts()
    rd_sccm_sft()
    rd_cpe()
    rd_cve()
    match_vendors()
    match_sft()
    upd_hosts_vulns()
    output_stats()


######
#   Mainline code
######

def main():
    """Handle case where pgm is called as a script from the cmd line."""
    parser = argparse.ArgumentParser(
        description='Process SCCM, NVD data.'
        )

    parser.add_argument(
        '-l', '--loglevel',
        choices=[
            'debug',
            'info',
            'warning',
            'error',
            'critical'
            ],
        help='Set desired verbosity for logging.'
        )

    parser.add_argument(
        '-a', '--action',
        default='sched',
        nargs='+',
        choices=[
            'rd_sccm_hosts',
            'rd_sccm_sft',
            'rd_cpe',
            'rd_cve',
            'match_vendors',
            'match_sft',
            'upd_hosts_vulns',
            'output_stats',
            'all'
            ],
        help='Desired action to perform.'
        )

    parser.add_argument(
        '-w', '--workdir',
        default='./',
        help='Specify work directory.'
        )

    parser.add_argument(
        '-y', '--years',
        type=int,
        default=5,
        help="Number of CVE files to download - 1 file for each year's data."
        )

    parser.add_argument(
        '--version',
        action='version',
        version=gbls.VERSION
        )

    args = parser.parse_args()

    # Set working directory

    if not os.path.exists(args.workdir):
        print("{0} does not exist".format(args.workdir))
        raise NameInvalid("Directory does not exist")

    elif not os.path.isdir(args.workdir):
        raise NameInvalid("Element is not a directory")

    else:
        gbls.wkdir = args.workdir

    # Initialize global variables now that the working directory
    # is known
    retval = utils.init_globals()

    # If serious error initializing globals, then abort.
    if retval > 0:
        return retval

    # initialize logging
    utils.setup_logging()

    if args.loglevel is not None:
        gbls.loglvl = gbls.LEVELS.get(
            args.loglevel,
            logging.NOTSET
            )

    logging.basicConfig(level=gbls.loglvl)
    logger = logging.getLogger(__name__)
    logger.setLevel(gbls.loglvl)

    logger.debug(
        "\nLog level set to {0}\n\n".format(gbls.loglvl)
        )

    # Set number of years of CVE files to download
    gbls.num_nvd_files = args.years

    logger.info(
        '\n{0} CVE files (1 per yr of data) '
        'will be downloaded.\n\n'.format(gbls.num_nvd_files)
        )

    # Check that I/P directories are available

    if not os.path.isdir(gbls.csvdir):
        logger.critical('***"csv" dir is missing. Execution terminated.\n\n')
        return(100)

    logger.info(
        '\n\nWorking directory: {0}\n'
        'Action to perform: {1}\n'.format(
                                        gbls.wkdir,
                                        args.action
                                        )
        )

    # Load plugins

    if gbls.activate_plugins:
        utils.load_plugins()

    ######
    #   Scheduling functions
    ######

    def catch_exceptions(job_func):
        @functools.wraps(job_func)
        def wrapper(*args, **kwargs):
            try:
                return job_func(*args, **kwargs)
            except:
                import traceback
                print(traceback.format_exc())
                if gbls.CANCEL_ON_FAILURE:
                    return schedule.CancelJob
        return wrapper

    @catch_exceptions
    def run_job():
        logger.info(
            '\n\n'
            '*** Scheduled run starting. ***\n'
            '*** Scheduled run starting. ***\n'
            '*** Scheduled run starting. ***\n'
            '*** Scheduled run starting. ***\n'
            '\n\n'
            )
        do_all()

    #######
    #    Main Processing Loop
    ######

    # Perform specified actions

    if 'sched' in args.action:
        # Run scheduling loop to execute once daily

        # schedule.every(1).minutes.do(run_job)
        schedule.every().day.at(gbls.SCHED_TIME).do(run_job)

        while True:
            schedule.run_pending()
            time.sleep(gbls.SCHED_SLEEP)

    elif 'all' in args.action:
        do_all()

    else:
        for my_action in args.action:

            if my_action == 'rd_sccm_hosts':
                rd_sccm_hosts()

            elif my_action == 'rd_sccm_sft':
                rd_sccm_sft()

            elif my_action == 'rd_cpe':
                rd_cpe()

            elif my_action == 'rd_cve':
                rd_cve()

            elif my_action == 'match_vendors':
                match_vendors()

            elif my_action == 'match_sft':
                match_sft()

            elif my_action == 'upd_hosts_vulns':
                upd_hosts_vulns()

            elif my_action == 'output_stats':
                output_stats()

            else:
                logger.critical(
                            "***Error vulnmine: action: {0}\n\n".format(
                                                            my_action
                                                            )
                            )

# if __name__ == '__main__':
#     sys.exit(main())
