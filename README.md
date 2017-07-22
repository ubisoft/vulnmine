# Vulnmine

Vulnmine uses simple Machine Learning to mine Microsoft's **SCCM** host and software inventory data for **vulnerable 3rd-party software**.

**NIST's NVD** vulnerability feeds are pulled in on a daily basis to determine the latest vulnerabilities to search for.

## Running Vulnmine

There is a public container with test data ready for use on Docker Hub: [lorgor/vulnmine](https://hub.docker.com/r/lorgor/vulnmine)

To download and run the Vulnmine container:

```bash
docker run -it --rm lorgor/vulnmine bash

python src/vulnmine.py -a 'all'
```

### Commandline Start Options

Here are the possible options when starting Vulnmine:

    vulnmine.py  [-h] [--version] [-l Logging] [-a Action] [-y Years] [-w Workdir]

| Parameter | Use |
| --------- | --- |
| -h | Help information |
| -help |  |
| | |
| -l | Set desired verbosity for logging: |
| --loglevel | _debug_ _info_ _warning_ _error_ _critical_ |
| | |
| -a | Desired action to perform: |
| --action | _rd_sccm_hosts:_   Read SCCM host data|
| | _rd_sccm_sft:_   Read SCCM software data |
| | _rd_cpe:_   Download / input NIST CPE Vendor-Product dictionary |
| | _rd_cve:_   Download / input NIST CVE Vulnerability feed data |
| | _match_vendors:_ |
| |    Match vendors from SCCM "Add-Remove" registry data to NVD CPE data |
| | _match_sft:_ |
| |    Match software from SCCM "Add-Remove"registry data to NVD CPE data |
| | _upd_hosts_vulns:_  Determine vulnerabilities for each host in SCCM |
| | _output_stats:_  Output the results |
| | _all:_  Run all the above in sequence |
| | |
| -y | Number of years to download. There is one CVE feed file for each year's data.|
| --years | |
| | |
| -w | Specifies work directory|
| --workdir | |

### Production mode

If no parameters are specified, then Vulnmine runs in *production mode*:

* The main vulnmine.py starts and sets up an endless schedule loop.
* The loop fires once daily by default.
* Each day Vulnmine:
    - Reads the SCCM inventory data files (UTF16 csv format) in the its CSV directory.
    - Downloads updated NVD feed files.
    - Processes the SCCM and NVD data.
    - Produces output JSON files into the same csv directory.

## Where to get more information

Vulnmine is on Github: <https://github.com/lorgor/vulnmine>

The docs directory has the full Vulnmine documentation.

