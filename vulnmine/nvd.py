"""Process, parse, persist NVD vendor and software data.

Purpose
=======

The nvd module ingests the following NIST NVD data:
    * CPE dictionary of vendor and software data.
    * CVE vulnerability data including CVSS data.

The data is parsed and placed in pandas dataframes.

The public classes are container objects used to input, persist, parse, and
process NVD data.

Public classes
==============

NvdCpe          NVD CPE vendor / software dictionary data

                The NVD CPE data base lists standardized vendor names /
                software names & versions. These are referenced by the CVE
                data which lists the actual vulnerabilities.


NvdCve          NVD CVE vulnerability data

"""
import re

import pandas as pd
import sys
import datetime
import time
import os

import requests
import xmltodict as xd
import logging

import gbls
import utils

# Public classes
__all__ = (
        'NvdCpe',
        'NvdCve'
        )


class NvdCpe(object):
    """Input, parse, persist NIST NVD vendor/software data.

    The NIST NVD Official Common Platform Enumeration (CPE) Dictionary is a
    structure dataset containing software products published by each vendor.

    From https://nvd.nist.gov/cpe.cfm:

        CPE is a structured naming scheme for information technology systems,
        software, and packages. Based upon the generic syntax for Uniform
        Resource Identifiers (URI), CPE includes a formal name format, a
        method for checking names against a system, and a description format
        for binding text and tests to a name.

    Following is a typical entry from the CPE XML flat file:

    ::

        <cpe-item name="cpe:/a:oracle:jdk:1.7.0:update_60">

            <title xml:lang="en-US">Oracle JDK 1.7.0 Update 60</title>

            <references>
                <reference
                    href="http://www.oracle.com/technetwork/topics/security
                        /cpujul2014-1972956.html">
                    Oracle July 2014 CPU
                </reference>
            </references>

            <cpe-23:cpe23-item
                    name="cpe:2.3:a:oracle:jdk:1.7.0:update_60:*:*:*:*:*:*"/>

        </cpe-item>

    **TL;DR: The CPE dictionary is an XML flat file which gives standardized
    vendor and software names. It also lists the software published by each
    vendor.**

    The I/P data is extracted from the XML flat file and placed in a pandas
    dataframe.

    Methods
    -------
    __init__    Class constructor to configure logging, initialize empty data
                frame

    download_cpe    Download NVD CPE XML dictionary data from the NIST website

    read        Input the NVD CPE dictionary XML file. Clean data and
                remove columns. Extract the nested XML data to form a
                simple pandas dataframe.

    load        Load CPE dataframe from the serialized pickled file.
    save        Save the CPE dataframe to the corresponding pickled file.
    get         Return a *copy* of the CPE dataframe.

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

        self.logger.info('\n\nInitializing NvdCpe class\n\n')

        self.df_cpe4 = pd.DataFrame({
            #   Fields in NVD software record
            '@name': [],
            'check': [],
            'cpe-23:cpe23-item': [],
            'notes': [],
            'references': [],
            'title': [],
            'cpe23-item-name': [],

            #   Fields added during processing
            'title_X': [],
            'vendor_X': [],
            'software_X': [],
            'release_X': []
            })

    def download_cpe(self):
        """Download NIST CPE XML dictionary data.

        The CPE dictionary lists known vendors / products in a normalized
        format.

        The NVD CVE ("Common Vulnerabilities and Exposures") XML flat files
        use this dictionary to reference vendors / software data.

        Actions
        -------

            Determine current time. Allocate download directory if it does not
            exist.

            if the file currently exists and is too old, then download / unzip
            a new copy.

        Exceptions
        ----------
        RequestException:   The requests module, used for https access, has
                            several exception conditions.

        Returns
        -------
        None

        """

        self.logger.info('\n\nEntering NvdCpe.download_cpe\n\n')

        # Determine current time
        now = time.time()

        do_download = False
        my_cpe = gbls.nvddir + gbls.cpe_filename

        self.logger.debug(
                '\nDownload of cpe file: \n{0}\n\n'.format(
                                            my_cpe
                                            )
                )

        # If CPE dictionary file has already been downloaded

        if os.path.isfile(my_cpe):
            # If CPE file is too old, then download a new copy
            cpe_timestamp = os.path.getmtime(my_cpe)
            cpe_age = (now - cpe_timestamp) / (60*60*24)

            do_download = cpe_age > gbls.cpe_max_age
            self.logger.debug(
                    '\nDownload cpe? \n{0}\n{1}\n\n'.format(
                                                cpe_age,
                                                do_download
                                                )
                    )
        else:
            do_download = True

        if do_download:
            self.logger.info(
                '\nDo CPE download\n\n')

            (cpe_filename, cpe_filecontents) = utils.get_zip(gbls.url_cpe)
            if cpe_filename:
                output_cpe = open(my_cpe, 'w')
                output_cpe.write(cpe_filecontents)
                output_cpe.close()

        return None

    def read(self, my_cpe=None):
        """Read the CPE XML file, parse, and store in pandas dataframe.

        Actions
        -------

        The NVD CPE XML flat file is read. This file documents vendors and
        corresponding published software in a formal, standardized format.

        * The XML file is parsed into a python dictionary. This in turn is
          loaded into a pandas dataframe.

        * The data is cleaned by removing deprecated entries along with
        accompanying columns.

        * The nested "name" data (in the form of an embedded python
          dictionary) is extracted and converted to a pandas dataframe. This
          new dataframe is concatenated to the original dataframe.

        * Entries pertaining to "OS" and "Hardware" are removed.

        * The nested software title information (in the form of an embedded
          python dictionary) is next accessed. Vendor, software name, and
          release data are extracted using pattern matching. The data is added
          to new columns in the pandas dataframe. If the software is released
          in multiple languages, only the en-US version is kept. All of this
          data is added to the dataframe in new columns.

        Exceptions
        ----------
        IOError:    Log an error message and ignore

        Returns
        -------
        None

        """
        self.logger.info('\n\nEntering NvdCpe.read\n\n')

        if my_cpe is None:
                my_cpe = gbls.nvdcpe

        self.logger.debug(
                        'Reading file {0},\nsep: {1}\n\n'.format(
                                my_cpe,
                                gbls.SEP)
                        )

        # read in the uncompressed NVD XML data
        self.logger.info(
            '\n\nReading NvdCpe dictionary\n{0}\n\n'.format(
                    my_cpe
                    )
                )

        with open(my_cpe) as fd:
            dict_cpe = xd.parse(fd.read())

        # convert the python dictionary to a pandas dataframe
        df_cpe = pd.DataFrame.from_dict(
                    dict_cpe['cpe-list']['cpe-item']
                    )

        self.logger.debug(
                    '\n\nRaw input: NIST CPE data: {0}\n\n'.format(
                                df_cpe.shape)
                    )

        # Do an initial cleaning of the data
        # remove deprecated entries
        df_cpe1 = df_cpe[~(df_cpe['@deprecated'] == 'true')]

        self.logger.info(
                    '\n\nCPE vendors left after removing '
                    'depecrated entries: \n{0}\n\n'.format(
                            df_cpe1.shape
                            )
                    )

        # drop the corresponding columns
        df_cpe1.drop(
                ['@deprecated', '@deprecation_date'],
                axis=1,
                inplace=True
                )

        # Extract the embedded 'name' data
        # extract embedded dictionary that has cpe 2.3 name data
        s_cpe_name_dict = df_cpe1['cpe-23:cpe23-item']

        # and convert this to a dataframe
        df_cpe_name = pd.DataFrame(s_cpe_name_dict.tolist())

        # rename column
        df_cpe_name = df_cpe_name.rename(
                columns={'@name': 'cpe23-item-name'}
                )

        # concatenate the two dframes by columns
        df_cpe2 = pd.concat(
            [df_cpe1.reset_index(drop=True), df_cpe_name],
            axis=1,
            join='outer')

        self.logger.debug(
                    '\n\nExtract embedded product name '
                    'data and outer join directly to the '
                    'NIST CPE DataFrame: \n{0} \n {1}\n\n'.format(
                        df_cpe2.shape,
                        df_cpe2.columns
                        )
                    )

        # Remove entries pertaining to 'OS' and 'Hardware'
        # look at applications only. Eliminate 'h' (hardware), 'o' OS
        pattern = re.compile('cpe:2.3:[oh]:', re.IGNORECASE | re.UNICODE)

        df_cpe3 = df_cpe2[
                ~(df_cpe2['cpe23-item-name'].str.contains(pattern))
                ]

        self.logger.info(
                        '\n\nUpdated vendor dataframe after '
                        'removing OS & Hardware entries: \n{0}\n\n'.format(
                            df_cpe3.shape
                            )
                        )

        # Extract embedded software title text
        # extract title text (which is also an embedded dictionary in an ... )
        s_cpe_title_dict = df_cpe3['title']

        def myfn4(row):

            # handle case of software with name in multiple languages

            if isinstance(row, list):
                for elt in row:
                    if elt['@xml:lang'] == 'en-US':
                        return elt['#text']
            else:
                return row['#text']

        df_cpe3['title_X'] = s_cpe_title_dict.apply(myfn4)

        # Extract vendor, software, release information

        pattern = re.compile(
            'cpe:2.3:a:'
            '(?P<vendor_X>[^:]*):'
            '(?P<software_X>[^:]*):'
            '?(?P<release_X>[^:]*):',
            re.IGNORECASE | re.UNICODE)

        df_tmp = df_cpe3['cpe23-item-name'].str.extract(
                                    pattern,
                                    expand=False)

        # add the new columns to the main dataframe
        self.df_cpe4 = pd.concat([df_cpe3, df_tmp], axis=1, join='outer')

        self.logger.debug(
                        '\n\nExtract vendor, software, release data '
                        'and add new columns to the vendor '
                        'dataframe: \n{0} \n{1}\n\n'.format(
                            self.df_cpe4.shape,
                            self.df_cpe4.columns
                            )
                        )

        self.logger.info(
                        '\n\nMajor vendor information: \n{0}\n\n'.format(
                                self.df_cpe4.vendor_X.value_counts().head(10)
                                )
                        )

        self.logger.info(
                        '\n\nMajor software information: \n{0}\n\n'.format(
                            self.df_cpe4.software_X.value_counts().head(10)
                            )
                        )

        return None

    def load(self, mypck=None):
        """Load CPE dataframe that was previously saved."""
        self.logger.info(
                '\n\nLoading saved cpe data into '
                'NvdCpe.df_cpe4 dataframe\n\n')

        if mypck is None:
            mypck = gbls.df_cpe4_pck

        self.df_cpe4 = pd.read_pickle(mypck)
        return None

    def save(self):
        """Save CPE dataframe in serialized pickle format."""
        self.logger.info('\n\nSaving NvdCpe.df_cpe4 dataframe\n\n')
        self.df_cpe4.to_pickle(gbls.df_cpe4_pck)
        return None

    def get(self):
        """Return a *copy* of the dataframe."""
        df_tmp = self.df_cpe4.copy()
        self.logger.info(
                '\n\nGet NvdCpe.df_cpe4: \n{0}\n{1}\n\n'.format(
                                df_tmp.shape,
                                df_tmp.columns
                                )
                )
        return df_tmp


class NvdCve(object):
    """Input, parse, persist NIST CVE vulnerability data.

    The NIST National Vulnerability Database ("NVD") is:

        "the U.S. government repository of standards based vulnerability
        management data."

    From https://nvd.nist.gov/download.cfm:

        XML Vulnerability Feeds - security related software flaws contained
        within XML documents. Each vulnerability in the file includes a
        description and associated reference links from the CVE dictionary
        feed, as well as a CVSS base score, vulnerable product configuration,
        and weakness categorization.

    "CVE" == "Common Vulnerabilities and Exposures". Each CVE entry describes
    "a known vulnerability. Included in the CVE entry are the CVSS scores.

    "CVSS" == "Common Vulnerability Scoring System". This is a set of metrics
    "to assess the severity / impact of a security vulnerability.

    Following is a typical NVD CVE entry from the XML flat file:

    ::

        <entry id="CVE-2015-1683">

            <vuln:vulnerable-configuration id="http://www.nist.gov/">

                <cpe-lang:logical-test operator="OR" negate="false">
                  <cpe-lang:fact-ref name="cpe:/a:microsoft:office:2007:sp3"/>
                </cpe-lang:logical-test>

            </vuln:vulnerable-configuration>

            <vuln:vulnerable-software-list>

                <vuln:product>
                    cpe:/a:microsoft:office:2007:sp3
                </vuln:product>

            </vuln:vulnerable-software-list>

            <vuln:cve-id>CVE-2015-1683</vuln:cve-id>

            <vuln:published-datetime>
                2015-05-13T06:59:14.880-04:00
            </vuln:published-datetime>

            <vuln:last-modified-datetime>
                2015-05-13T11:57:28.013-04:00
            </vuln:last-modified-datetime>

            <vuln:cvss>
              <cvss:base_metrics>

                <cvss:score>9.3</cvss:score>
                <cvss:access-vector>NETWORK</cvss:access-vector>
                <cvss:access-complexity>MEDIUM</cvss:access-complexity>
                <cvss:authentication>NONE</cvss:authentication>

                <cvss:confidentiality-impact>
                    COMPLETE
                </cvss:confidentiality-impact>

                <cvss:integrity-impact>COMPLETE</cvss:integrity-impact>
                <cvss:availability-impact>COMPLETE</cvss:availability-impact>
                <cvss:source>http://nvd.nist.gov</cvss:source>

                <cvss:generated-on-datetime>
                    2015-05-13T11:55:11.580-04:00
                </cvss:generated-on-datetime>

              </cvss:base_metrics>
            </vuln:cvss>

            <vuln:cwe id="CWE-119"/>
            <vuln:references xml:lang="en" reference_type="VENDOR_ADVISORY">
              <vuln:source>MS</vuln:source>

              <vuln:reference
                href="http://technet.microsoft.com/security/bulletin/MS15-046"
                xml:lang="en">

                MS15-046

              </vuln:reference>

            </vuln:references>

            <vuln:summary>
              Microsoft Office 2007 SP3 allows remote attackers to
              execute arbitrary code via a crafted document, aka "Microsoft
              Office Memory Corruption Vulnerability."
            </vuln:summary>

        </entry>

    **TL;DR: The NIST NVD is an standards-based repository of vulnerabilities.
    The vendor and software names can be found in the NIST CPE dictionary.**

    The I/P XML data is parsed, relevant data is extracted and then placed in
    a pandas dataframe.

    Methods
    -------
    __init__    Class constructor to configure logging, initialize empty data
                frame

    download_cve    Download NVD CVE XML feed data from the NIST website

    read        Input the NVD CVE data from the raw XML file. Clean data and
                remove columns. Extract the nested XML data to form a
                simple pandas dataframe.

    load        Load CVE dataframe from the serialized pickled file.
    save        Save the CVE dataframe to the corresponding pickled file.
    get         Return a *copy* of the CVE dataframe.

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

        self.logger.info('Initializing NvdCve class')

        self.df_cve = pd.DataFrame({
            #   Fields in NVD software record
            'vuln:cve-id': [],
            'vuln:product': [],
            'cvss:access-complexity': [],
            'cvss:access-vector': [],
            'cvss:authentication': [],
            'cvss:availability-impact': [],
            'cvss:confidentiality-impact': [],
            'cvss:integrity-impact': [],
            'cvss:score': [],
            # 170118 Bug fix - Key error, sometimes not present
            #            'vuln:security-protection': [],
            'cvss:source': []

            #   Fields added during processing
            })

    def download_cve(self):
        """Download NIST CVE XML feed data and store in local directory.

        The NVD CVE ("Common Vulnerabilities and Exposures") XML flat files
        are downloaded. These files list known vulnerabilities.

        The data is supplied as a series of files - one file for each
        year. As vulnerability information is updated, files from previous
        years can be updated depending on when the vulnerability was
        discovered.

        For each year, there is also a small file with "meta" data
        describing the main XML file: Time of last update, file size, hash
        of file contents. NIST's intention is apparently twofold: a) limit
        B/W requirements by avoiding downloads of files that have not
        changed, b) protect integrity of downloaded data.

        Actions
        -------

            Determine current year. Allocate download directory if it does not
            exist.

            For each year to be processed:

                Download that year's meta file.

                Compare meta file contents with previous meta file (if it
                exists)

                If meta file contents have changed, then download the updated
                XML Feed file.

                The XML file is unzipped and stored in the download directory.

        Exceptions
        ----------
        RequestException:   The requests module, used for https access, has
                            several exception conditions.

        Returns
        -------
        None

        """

        # Determine current year
        now = datetime.datetime.now()
        my_yr = now.year

        # Process cve files for last "n" years

        for index in range(gbls.num_nvd_files):
            yr_processed = my_yr - index
            self.logger.info(
                '\n\nProcessing NVD files for {0}\n'.format(yr_processed)
                )

            # get the meta file for the year being processed
            url_meta = (
                        gbls.url_meta_base
                        + str(yr_processed)
                        + gbls.url_meta_end
                        )
            self.logger.info(
                '\nReading meta file: \n{0}\n\n'.format(
                                url_meta
                                )
                )
            try:
                resp = requests.get(url_meta)

            except requests.exceptions.RequestException as e:
                    self.logger.critical(
                        '\n\n***NVD XML feeds - Error: '
                        '\n{0}\n{0}\n\n'.format(
                            url_meta,
                            e
                            )
                        )
                    continue

            meta_filename = (
                            gbls.nvddir
                            + gbls.nvd_meta_filename
                            + str(yr_processed)
                            )

            # if file already exists then read the contents
            if os.path.isfile(meta_filename):
                meta_filecontents = open(meta_filename, 'r').read()

                # read updated xml feed file since corresponding meta file
                # contents have changed.

                if meta_filecontents == resp.text:

                    self.logger.info(
                        '\nMeta file unchanged, continuing.\n{0}\n\n'.format(
                                                    meta_filename
                                                    )
                        )
                    continue
                else:
                    self.logger.debug(
                        '\nMeta files differ:\n'
                        '   Current file: {0}\n'
                        '   File read from NVD: {1}\n\n'.format(
                                                    meta_filecontents,
                                                    resp.text
                                                    )
                        )
            else:
                self.logger.debug('\nMeta file does not exist:{0}'.format(
                                                    meta_filename
                                                    )
                                )

            # save new / updated meta file to disk

            output_meta = open(meta_filename, 'w')
            output_meta.write(resp.text)
            output_meta.close()

            # Read the new XML feed file

            url_xml = (
                        gbls.url_xml_base
                        + str(yr_processed)
                        + gbls.url_xml_end
                        )

            (xml_filename, xml_filecontents) = utils.get_zip(url_xml)

            # write this new / updated xml feed file to disk as well

            if xml_filename:

                # hardcode the filenames to avoid problems if NIST changes
                # names

                my_cve_filename = (
                            gbls.nvdcve
                            + str(yr_processed)
                            + '.xml'
                            )

                self.logger.info(
                    '\nSaving XML file I/P {0} as {1}\n\n'.format(
                                                xml_filename,
                                                my_cve_filename
                                                )
                    )

                output_xml = open(my_cve_filename, 'wb')
                output_xml.write(xml_filecontents)
                output_xml.close()

        return None

    def read(self, my_dir=None):
        """Read the CVE XML file, parse, and store in pandas dataframe.

        Actions
        -------

        The NVD CVE ("Common Vulnerabilities and Exposures") XML flat file is
        read. This file contains a list of known vulnerabilities. The venodor
        and software names can be found in the NIST CPE dictionary.

        * The data is supplied in a series of files. There is one file for
          each year. As vulnerability information is updated, files from
          previous years can be updated depending on when the vulnerability
          was discovered.

          Each files is read, parsed into a python dictionary, then converted
          to a pandas dataframe.

          All of these individual data frames are appended to form one
          dataframe.

        * The data is cleaned by eliminating null entries.

        * The nested XML data is painstakingly extracted. The data from the
          corresponding python dictionaries and lists is used to populate new
          columns in the main pandas dataframe.   loaded into a pandas
          dataframe.

        *  The data is cleaned further by removing "OS" and "Hardware"
           entries. Extraneous columns are also dropped.

        *  The CVSS ("Common Vulnerability Scoring System" data in the CVE
           entry is extracted and used to populate additional columns in the
           dataframe.

        Exceptions
        ----------
        IOError:    Log an error message and ignore

        Returns
        -------
        None

        """
        self.logger.info('\n\nEntering NvdCve.read\n\n')

        # Read in the uncompressed NVD XML data
        try:
            fst_time = True

            if my_dir is None:
                my_dir = gbls.nvddir

            # List directory contents

            f = []

            for (dirpath, dirnames, filenames) in os.walk(my_dir):
                f.extend(filenames)
                break

            # Iterate through the cve files

            for my_file in filenames:

                # skip the cpe dictionary if it is there

                if not my_file.startswith(gbls.cve_filename):
                    continue

                my_file1 = my_dir + my_file

                self.logger.info(
                        '\nReading {0}\n\n'.format(
                            my_file1
                            )
                        )

                with open(my_file1) as fd:
                    my_dict = xd.parse(fd.read())

                df_tmp = pd.DataFrame.from_dict(
                            my_dict['nvd']['entry']
                            )
                if fst_time:
                    df_nvd = df_tmp
                    fst_time = False
                else:
                    df_nvd = df_nvd.append(df_tmp)

        except IOError as e:
            self.logger.critical('\n\n***I/O error({0}): {1}\n\n'.format(
                        e.errno, e.strerror))
        except:
            self.logger.critical(
                '\n\n***Unexpected error: {0}\n\n'.format(
                    sys.exc_info()[0]))
            raise

        self.logger.info(
            '\n\nNVD CVE raw data input counts: \n{0}\n{1}\n\n'.format(
                    df_nvd.shape,
                    df_nvd.columns
                    )
            )

        # eliminate null entries. Then reset index to sequential #'s
        df_nvd1 = df_nvd[
                df_nvd['vuln:cvss'].notnull()
                ].reset_index(drop=True)

        self.logger.debug(
            '\n\nNVD CVE data after eliminating '
            'null entries: \n{0}\n\n'.format(
                    df_nvd1.shape
                    )
            )

        # pull out cvss_dict hierarchical entry in each row
        s_cvss_dict = df_nvd1['vuln:cvss'].apply(
                        lambda mydict: mydict['cvss:base_metrics']
                        )

        # convert this series to a dataframe
        df_cvss = pd.DataFrame(s_cvss_dict.tolist())

        # Finally, concatenate the two dataframes into one (by columns)
        df_nvd2 = pd.concat([df_nvd1, df_cvss], axis=1, join='outer')

        self.logger.debug(
            '\n\nNVD CVE counts, columns after '
            'pulling out embedded CVSS data: \n{0}\n{1}\n\n'.format(
                        df_nvd2.shape,
                        df_nvd2.columns
                        )
            )

        # drop unneeded columns
        df_nvd2.drop(
                ['@id', 'vuln:cwe'],
                axis=1,
                inplace=True
                )

        # Build a table of vulns vs software

        # extract list of impacted software for each vulnerability
        # build a new dataframe with the vuln's cve-id
        df_sft = df_nvd2[['vuln:cve-id']]

        # then pull out the embedded list of vulnerable software
        # and if the software list is empty, then handle this gracefully
        df_sft['sftlist'] = df_nvd2[
            'vuln:vulnerable-software-list'].fillna(value='xx').apply(
                lambda mydict: [] if mydict == 'xx' else mydict[
                                                            'vuln:product'
                                                            ]
                )

        self.logger.info(
                '\n\n embedded software counts: \n{0}'.format(
                                df_sft.shape
                                )
                )

        # expand each embedded software list into a list containing tuples of
        # the form ['cve_id', 'software_id']

        # initialize an empty list
        lst_sft = []

        # This fn pulls out the embedded list and builds the tuples
        def myfn3(row):
            mylist = row['sftlist']

            # handle case where there is only 1 vuln software in the list
            if not(isinstance(mylist, list)):
                    mylist = [mylist]

            # append each new tuple onto the end of the existing list
            for sft in mylist:
                lst_sft.append([row['vuln:cve-id'], sft])

            # return some value to keep pandas happy
            return 1

        # Run through the dataframe and apply the fn to each row in turn
        df_sft.apply(myfn3, axis=1)

        # Now convert the list of tuples to a dataframe
        df_sft1 = pd.DataFrame(
                lst_sft,
                columns=['vuln:cve-id', 'vuln:product']
                )

        # remove os/hdware entries. Best to analyze MS OS vulns by using MS'
        # patch csv file

        pattern = re.compile(
                        'cpe:'
                        '/[oh]:',
                        re.IGNORECASE | re.UNICODE
                        )

        df_sft2 = df_sft1[
                        ~df_sft1['vuln:product'].str.contains(pattern)
                        ]

        # Finally add information describing the vulnerability add in cvss
        # information concerning the vuln characteristics and severity

        # pull out the cvss information for each vulnerability
        df_cvss = df_nvd2[[
                'vuln:cve-id',
                u'cvss:access-complexity',
                u'cvss:access-vector',
                u'cvss:authentication',
                u'cvss:availability-impact',
                u'cvss:confidentiality-impact',
                u'cvss:integrity-impact',
                u'cvss:score',
                # 170118 Bug fix: Sometimes not present
                #                u'vuln:security-protection',
                u'cvss:source'
                ]]

        # Now merge it into the new dataframe mapping software to vulns
        self.df_cve = pd.merge(
                        df_sft2,
                        df_cvss,
                        how='inner',
                        on='vuln:cve-id'
                        )

        self.logger.info(
                        '\n\nUpdated software dataframe '
                        'which maps software to vulns: \n{0}\n{1}\n\n'.format(
                                self.df_cve.shape,
                                self.df_cve.columns
                                )
                        )

        return None

    def load(self, mypck=None):
        """Load NvdCve vulnerability dataframe that was previously saved."""
        self.logger.info(
                '\n\nLoading saved CVE data into '
                'NvdCve.df_cve dataframe\n\n'
                )
        if mypck is None:
            mypck = gbls.df_cve_pck

        self.df_cve = pd.read_pickle(mypck)
        return None

    def save(self):
        """Save NvdCpe vuln dataframe in serialized pickle format."""
        self.logger.info('\n\nSaving NvdCve.df_cve dataframe\n\n')
        self.df_cve.to_pickle(gbls.df_cve_pck)
        return None

    def get(self):
        """Return a *copy* of the data."""
        df_tmp = self.df_cve.copy()
        self.logger.info(
                '\n\nGet NvdCve.df_cve: \n{0}\n{1}\n\n'.format(
                                df_tmp.shape,
                                df_tmp.columns
                                )
                )
        return df_tmp
