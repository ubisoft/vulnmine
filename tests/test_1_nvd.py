import pytest
import pandas as pd

import time
import datetime
import os
import io

import filecmp
from shutil import copyfile

# import StringIO as strIO
import requests
import responses
from requests.exceptions import HTTPError

from context import gbls
from context import utils
from context import nvd


class TestNvdCpe:

    ######
    #   Test NIST NVD CPE I/P
    ######

    @responses.activate

    def test_cpe1(self, init_testenv):
        if init_testenv != "Initialized":
            exit('nvd - TestNvdCpe initialization failed, exiting')

        # Read flat file as a string to return as mock http response
        try:
            with io.open(
                "data/official-cpe-dictionary_v2.3.xml.base.zip",
                "rb"
                ) as myfile:
                mybuf = myfile.read()
        except Exception as e:
            print (e)
            mybuf = None

        # Set up mock http response to return test file

        responses.add(
                responses.GET,
                gbls.url_cpe,
                body=mybuf,
                status=200,
                content_type='application/x-zip-compressed'
                )

        # target cpe file
        my_cpe = gbls.nvddir + gbls.cpe_filename

        # if file already exists, then timestamp the file with old date in the
        # past to force "download"

        if os.path.isfile(my_cpe):
            s = "01/12/2011"
            my_tm_stamp = time.mktime(
                datetime.datetime.strptime(
                    s,
                    "%d/%m/%Y"
                ).timetuple()
            )

            os.utime(
                my_cpe,
                (my_tm_stamp, my_tm_stamp)
                )

        # "Download" the test zip file

        cpe = nvd.NvdCpe()
        cpe.download_cpe()

        # Check that extracted file matches the baseline version

        assert filecmp.cmp(
                    my_cpe,
                    'data/official-cpe-dictionary_v2.3.base.xml',
                    False
                    )

    def test_cpe2(self, init_testenv):
        if init_testenv != "Initialized":
            exit('nvd - Initialization failed, exiting')

        # Convert the i/p XML file to a dataframe
        cpe = nvd.NvdCpe()
        cpe.read(my_cpe='data/official-cpe-dictionary_v2.3.base.xml')
        df_cpe_processed = cpe.get()

        # load up base dframe for comparison
        cpe.load(mypck="data/df_cpe4_base.pck")
        df_cpe_base = cpe.get()

        # Check calculated dframe against base dframe
        assert df_cpe_base.equals(df_cpe_processed)


class TestNvdCve:

    ######
    #   Test NIST NVD CVE I/P
    ######

    @responses.activate

    def test_cve_download(self, init_testenv):
        """ Test the CVE download function over multiple yrs / conditions """
        if init_testenv != "Initialized":
            exit('nvd - TestNvdCve initialization failed, exiting')

        def mock_http(my_url, my_file, my_content_type):
            """ Set up a mock http file download """

            # Read flat file as a string to return as mock http response
            print("Entering mock_http: {0}, {1}, {2}".format(
                                                            my_url,
                                                            my_file,
                                                            my_content_type
                                                            )
                )
            try:
                with io.open(
                    my_file,
                    "rb"
                    ) as myfile:
                    mybuf = myfile.read()

                    # print 1st 50 lines i/p
                    if '.zip' in my_file:
                        print("mock_http: Download of {0}".format(my_file))
                    else:
                        print("mock_http:\n{0}\n\n".format(
                                                    mybuf[:1000]
                                                    )
                            )
            except Exception as e:
                print (e)
                mybuf = None

            # Set up mock http response to return test file

            responses.add(
                    responses.GET,
                    my_url,
                    body=mybuf,
                    status=200,
                    content_type=my_content_type
                    )

        def set_fnames_urls(my_index):
            """Set the filenames and urls for a given yr"""

            if my_index < 0 or my_index > 1:
                print ("set_fnames_urls: index must be either 0 or 1")
                assert False
                return (None, None, None)

            # Determine yr being processed
            now = datetime.datetime.now()
            my_yr = now.year

            yr_processed = my_yr - my_index

            # Target meta file
            meta_dest_filename = (
                            gbls.nvddir
                            + gbls.nvd_meta_filename
                            + str(yr_processed)
                            )
            # Base meta file (used for comparison)
            meta_base_filename = "data/cve_meta_base" + str(my_index)

            # URL for mock download of CVE meta file
            url_meta = (
                    gbls.url_meta_base
                    + str(yr_processed)
                    + gbls.url_meta_end
                    )

            # Set up mock http download of meta file

            mock_http(
                url_meta,
                meta_base_filename,
                "text/plain"
                )

            # URL to read the corresponding CVE XML feed file
            url_xml = (
                        gbls.url_xml_base
                        + str(yr_processed)
                        + gbls.url_xml_end
                        )

            # Target cve xml file
            cve_filename = (
                gbls.nvdcve
                + str(yr_processed)
                + '.xml'
                )

            print(
                'set_fnames_urls:\n  {0}, {1}, {2}\n'
                '  {3}\n'.format(
                                meta_base_filename,
                                meta_dest_filename,
                                cve_filename,
                                url_xml
                                )
                )
            return(
                meta_base_filename,
                meta_dest_filename,
                cve_filename,
                url_xml
                )


        ######
        # Initialize for test: will read files for last 2 yrs
        #
        # Mock downloads of meta files for both yrs will occur.
        #
        # "Last yr" will be set to not download (i.e. meta files equal). if a
        # mock download nonetheless occurs this will throw an error.
        #
        # "Current yr" will be set cause a mock download of the corresponding
        # zipped XML file.
        ######


        gbls.num_nvd_files = 2

        # *** Set up last yr ***

        # Initialize filenames and urls

        (
        meta_base_filename,
        meta_dest_filename,
        cve_filename,
        url_xml
        ) = set_fnames_urls(1)

        # Ensure that meta files match so now download

        copyfile(
            meta_base_filename,
            meta_dest_filename
            )

        # Set url for cve xml download to throw error

        exception = HTTPError(
            'NIST Meta file check failed'
            '- Should have been no download of CVE XML files'
            )

        responses.add(
            responses.GET,
            url_xml,
            body=exception
            )

        # *** Set up current year ***

        # Initialize filenames and urls

        (
        meta_base_filename,
        meta_dest_filename,
        cve_filename,
        url_xml
        ) = set_fnames_urls(0)

        # Remove target meta file. This will force download of cve xml file

        try:
            os.remove(meta_dest_filename)
        except OSError:
            pass

        # Set up mock http download of meta file

        mock_http(
            url_xml,
            'data/cve_xml_base.zip',
            'application/x-zip-compressed'
            )

        # Fire up the code to be tested
        cve = nvd.NvdCve()
        cve.download_cve()

        # Check that extracted file matches the baseline version

        assert filecmp.cmp(
                    cve_filename,
                    'data/cve_xml_base',
                    False
                    )

        # Force an error for debugging test harness code
        # assert False

    def test_cve_read(self, init_testenv):
        """ Test the CVE parsing function """
        if init_testenv != "Initialized":
            exit('nvd - TestNvdCve initialization failed, exiting')

        # Fire up the code to be tested
        cve = nvd.NvdCve()
        cve.read(my_dir="data/")
        df_cve_processed = cve.get()

        # load up base dframe for comparison
        cve.load(mypck="data/df_cve_base.pck")
        df_cve_base = cve.get()

        # Check calculated dframe against base dframe
        assert df_cve_base.equals(df_cve_processed)

        # Force failure for debugging o/p
        # assert False
