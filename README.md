## Table of Contents

   * [Introduction](#introduction)
   * [System Requirements](#system-requirements)
   * [Installation](#installation)
   * [Quick Start](#quick-start)
   * [Issues management](#issues-management)


## Introduction

This CLI tool automates the classification of Office documents with macros using MaliciousMacroBot. It allows to analyze a folder of sample files and to generate a report in multiple output formats.


## System Requirements

This tool was tested on an Ubuntu 16.04 with Python 2.7.

It uses the following libraries:
- `tinyscript` (required)
- [`mmbot`](https://github.com/egaus/MaliciousMacroBot) (required for classification)
- `pandas` (required for parsing MaliciousMacroBot results)
- `markdown2` (optional ; required if using report generation)
- `weasyprint` (optional ; required if using PDF report format)


## Installation

1. Clone this repository

 ```session
 $ git clone https://github.com/dhondta/malicious-macro-tester.git
 ```
 
 > **Behind a proxy ?**
 > 
 > Setting: `git config --global http.proxy http://[user]:[pwd]@[host]:[port]`
 > 
 > Unsetting: `git config --global --unset http.proxy`
 > 
 > Getting: `git config --global --get http.proxy`

2. Install Python requirements

 ```session
 $ sudo pip install -r requirements.txt
 ```

 > **Behind a proxy ?**
 > 
 > Do not forget to add option `--proxy=http://[user]:[pwd]@[host]:[port]` to your pip command.
 
3. [Facultative] Copy the Python script to your `bin` folder

 ```session
 $ chmod a+x malicious-macro-tester.py
 $ sudo cp malicious-macro-tester.py /usr/bin/malicious-macro-tester
 ```


## Quick Start

1. Help

 ```session
  $ python malicious-macro-tester.py -h
  usage: malicious-macro-tester [-h] [--api-key VT_KEY]
                                [--output {html,json,md,pdf}] [-d] [-f] [-l]
                                [-q] [-r] [-s] [-u] [-v]
                                FOLDER

  MaliciousMacroTester v2.2
  Author: Alexandre D'Hondt
  Reference: INFOM444 - Machine Learning - Hot Topic

  This tool uses MaliciousMacroBot to classify a list of samples as benign or
   malicious and provides a report. Note that it only works on an input folder
   and list every file to run it against mmbot.

  positional arguments:
    FOLDER                folder with the samples to be tested OR
                          pickle name if results are loaded with -l

  optional arguments:
    -h, --help            show this help message and exit
    --api-key VT_KEY      VirusTotal API key (default: none)
                            NB: key as a string or file path to the key
    --output {html,json,md,pdf}
                          report file format [html|json|md|pdf] (default: none)
    -d                    dump complete results (default: false)
    -f                    filter only DOC and XLS files (default: false)
    -l                    load previous pickled results (default: false)
    -q                    do not display results report (default: false)
    -r                    when loading pickle, retry VirusTotal hashes with None results
                           (default: false)
    -s                    pickle results to a file (default: false)
    -u                    when loading pickle, update VirusTotal results (default: false)
    -v                    debug verbose level (default: false)

  Usage examples:
    python malicious-macro-tester.py my_samples_folder
    python malicious-macro-tester.py samples --api-key virustotal-key.txt -lr
    python malicious-macro-tester.py samples -lsrv --api-key 098fa24...be724a0
    python malicious-macro-tester.py samples -lf --output pdf
   
 ```
 
2. Example of output

 ```session
 $ ./malicious-macro-tester.py samples -lfqv --output pdf
 XX:XX:XX [INFO] Loading previous results from pickle...
 XX:XX:XX [INFO] Processing samples...
 XX:XX:XX [DEBUG] Got results from loaded Pickle
 XX:XX:XX [DEBUG] VT check is disabled
 XX:XX:XX [INFO] Parsing results...
 XX:XX:XX [DEBUG] Generating the Markdown report (text)...
 XX:XX:XX [DEBUG] Generating the HTML report (text)...
 XX:XX:XX [DEBUG] Generating the PDF report...

 ```


## Issues management

Please [open an Issue](https://github.com/dhondta/malicious-macro-tester/issues/new) if you want to contribute or submit suggestions.
