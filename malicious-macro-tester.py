#!/usr/bin/env python
# -*- coding: UTF-8 -*-

__author__ = "Alexandre D'Hondt"
__version__ = "2.2"
__copyright__ = "AGPLv3 (http://www.gnu.org/licenses/agpl.html)"
__reference__ = "INFOM444 - Machine Learning - Hot Topic"
__doc__ = """
This tool uses MaliciousMacroBot to classify a list of samples as benign or
 malicious and provides a report. Note that it only works on an input folder
 and list every file to run it against mmbot.
"""
__examples__ = ["my_samples_folder",
                "samples --api-key virustotal-key.txt -lr",
                "samples -lsrv --api-key 098fa24...be724a0",
                "samples -lf --output pdf"]

import sys
if sys.version_info[0] > 2:
    print("Sorry, this script only works with Python 2...")
    sys.exit(0)
# -------------------- IMPORTS SECTION --------------------
import json
import pickle
import urllib2
from os.path import abspath, join
from pandas.core.series import Series
from tinyscript import *
# non-standard imports with warning if dependencies are missing
try:
    from mmbot import MaliciousMacroBot
except ImportError:
    print("Please install mmbot via 'pip install mmbot' first.")
    sys.exit(1)


# -------------------- CONSTANTS SECTION --------------------
PDF_CSS = "h1,h3{line-height:1}address,blockquote,dfn,em{font-style:italic}ht" \
          "ml{font-size:100.01%}body{font-size:75%;color:#222;background:#fff" \
          ";font-family:\"Helvetica Neue\",Arial,Helvetica,sans-serif}h1,h2,h" \
          "3,h4,h5,h6{font-weight:400;color:#111}h1{font-size:3em;margin-bott" \
          "om:.5em}h2{font-size:2em;margin-bottom:.75em}h3{font-size:1.5em;ma" \
          "rgin-bottom:1em}h4{font-size:1.2em;line-height:1.25;margin-bottom:" \
          "1.25em}h5,h6{font-size:1em;font-weight:700}h5{margin-bottom:1.5em}" \
          "h1 img,h2 img,h3 img,h4 img,h5 img,h6 img{margin:0}p{margin:0 0 1." \
          "5em}.left{float:left!important}p .left{margin:1.5em 1.5em 1.5em 0;" \
          "padding:0}.right{float:right!important}p .right{margin:1.5em 0 1.5" \
          "em 1.5em;padding:0}address,dl{margin:0 0 1.5em}a:focus,a:hover{col" \
          "or:#09f}a{color:#06c;text-decoration:underline}.quiet,blockquote,d" \
          "el{color:#666}blockquote{margin:1.5em}dfn,dl dt,strong,th{font-wei" \
          "ght:700}sub,sup{line-height:0}abbr,acronym{border-bottom:1px dotte" \
          "d #666}pre{margin:1.5em 0;white-space:pre}code,pre,tt{font:1em 'an" \
          "dale mono','lucida console',monospace;line-height:1.5}li ol,li ul{" \
          "margin:0}ol,ul{margin:0 1.5em 1.5em 0;padding-left:1.5em}ul{list-s" \
          "tyle-type:disc}ol{list-style-type:decimal}dd{margin-left:1.5em}tab" \
          "le{margin-bottom:1.4em;width:100%}thead th{background:#c3d9ff}capt" \
          "ion,td,th{padding:4px 10px 4px 5px}tbody tr.even td,tbody tr:nth-c" \
          "hild(even) td{background:#e5ecf9}tfoot{font-style:italic}caption{b" \
          "ackground:#eee}.small{font-size:.8em;margin-bottom:1.875em;line-he" \
          "ight:1.875em}.large{font-size:1.2em;line-height:2.5em;margin-botto" \
          "m:1.25em}.hide{display:none}.loud{color:#000}.highlight{background" \
          ":#ff0}.added{background:#060;color:#fff}.removed{background:#900;c" \
          "olor:#fff}.first{margin-left:0;padding-left:0}.last{margin-right:0" \
          ";padding-right:0}.top{margin-top:0;padding-top:0}.bottom{margin-bo" \
          "ttom:0;padding-bottom:0}"
OUTPUT_FORMATS = ["html", "json", "md", "pdf"]


# -------------------- CLASSES SECTION --------------------
class MacroSampleTester(object):
    """
    This class is aimed to test multiple documents from a given folder with
     MaliciousMacroBot.

    :param folder: path to the samples folder
    :param load: load previous results before starting
    :param save: save results after processing
    :param display: display report in terminal after processing
    :param key: VirusTotal API key
    """
    def __init__(self, folder, load=False, save=False, display=False, key=None):
        self.__display = display
        self.__save = save
        logger.debug("Instantiating and initializing MaliciousMacroBot...")
        self.bot = MaliciousMacroBot()
        self.bot.mmb_init_model()
        self.folder = folder
        logger.warn("Macros will be saved to: {}".format(join(folder, 'vba')))
        self.report = None
        self.results = None
        if load:
            self.load()
        self.vt = VirusTotalClient(key)

    def load(self):
        """
        Load results from a Pickle.
        """
        try:
            with open(self.folder + '.pickle', 'rb') as f:
                logger.info("Loading previous results from pickle...")
                self.results = pickle.load(f)
        except IOError:
            logger.warn("Pickled results do not exist")
            self.results = None

    def parse(self, filter_func=None):
        """
        Parse the results got from mmbot in order to generate a report.

        :param filter_func: function for filtering files
        """
        if not (isinstance(self.results, dict) and all(isinstance(x, Series)
                for x in self.results.values())):
            logger.error("Corrupted results, cannot parse.")
            return
        assert hasattr(filter_func, '__call__') or filter_func is None
        logger.info("Parsing results...")
        vba = abspath(join(self.folder, 'vba'))
        bf, mf = join(vba, 'benign'), join(vba, 'malicious')
        if not os.path.isdir(vba):
            os.makedirs(vba)
        if not os.path.isdir(bf):
            os.makedirs(bf)
        if not os.path.isdir(mf):
            os.makedirs(mf)
        benign, c_all, c_vba = [], [0] * 4, [0] * 4
        if self.vt.is_enabled:
            r = "{: <16}  {: <16}  {}\n".format("FILE", "PREDICTION",
                                            "VT DETECTION")
        else:
            r = "{: <16}  {}\n".format("FILE", "PREDICTION")
        j = {'results': []}
        for k, v in sorted(self.results.items()):
            # filter according to the input lambda function 'filter_func'
            if filter_func is not None and not filter_func(k):
                continue
            # define shortnames
            drate = v.get('vt_detection_rate')
            macro = v['extracted_vba']
            failed = macro.startswith("Error:'utf8'") \
                  or macro.startswith("Error:Failed") \
                  or macro == "No VBA Macros found"
            pred = v['prediction']
            malicious = pred == "malicious"
            i = {'file': k, 'prediction': pred}
            # save the VBA code to the samples folder in subfolder 'vba'
            if not failed:
                dest = [bf, mf][malicious]
                vba_fn = join(dest, "{}.vba".format(k))
                with open(vba_fn, 'w') as f:
                    f.write(macro)
                # add stats line to report if it has a valid macro
                if self.vt.is_enabled:
                    i['vt_detection'] = drate
                    r += "{: <16}  {: <16}  {}\n".format(k, pred, drate)
                else:
                    r += "{: <16}  {}\n".format(k, pred)
            j['results'].append(i)
            # perform counts
            if malicious:
                c_all[0] += 1
            else:
                benign.append(k)
            if drate is None:
                c_all[1] += 1
            if malicious and drate is not None:
                c_all[2] += 1
            c_all[-1] += 1
            if not failed:
                if malicious:
                    c_vba[0] += 1
                if drate is None:
                    c_vba[1] += 1
                if malicious and drate is not None:
                    c_vba[2] += 1
                c_vba[-1] += 1
        # make the report
        # - handle the whole list of files first
        j['statistics'] = {'all': {'malicious': c_all[0], 'total': c_all[-1]}}
        r += "\nAll files:" \
             "\n  Marked as malicious:                  {: >3}/{} ({}%)" \
             .format(c_all[0], c_all[-1], 100 * c_all[0] / c_all[-1])
        if self.vt.is_enabled:
            j['statistics']['all'].update({'vt_unknown': c_all[1],
                                           'malicious_and_vt_known': c_all[2]})
            r += "\n  Unknown from VT:                      {: >3}/{} ({}%)" \
                 .format(c_all[1], c_all[-1], 100 * c_all[1] / c_all[-1]) + \
                 "\n  Marked as malicious and known from VT:{: >3}/{} ({}%)" \
                 .format(c_all[2], c_all[-1], 100 * c_all[2] / c_all[-1])
        # - only handle files with a successfully extracted VBA macro
        j['statistics']['vba'] = {'malicious': c_vba[0], 'total': c_vba[-1]}
        r += "\n\nOnly files for which the VBA macro could be extracted:" \
             "\n  Marked as malicious:                  {: >3}/{} ({}%)" \
             .format(c_vba[0], c_vba[-1], 100 * c_vba[0] / c_vba[-1])
        if self.vt.is_enabled:
            j['statistics']['vba'].update({'vt_unknown': c_vba[1],
                                           'malicious_and_vt_known': c_vba[2]})
            r += "\n  Unknown from VT:                      {: >3}/{} ({}%)" \
                 .format(c_vba[1], c_vba[-1], 100 * c_vba[1] / c_vba[-1]) + \
                 "\n  Marked as malicious and known from VT:{: >3}/{} ({}%)" \
                 .format(c_vba[2], c_vba[-1], 100 * c_vba[2] / c_vba[-1])
        r += "\n\nBenign files:\n{}".format(", ".join(benign))
        if self.__display:
            print(r)
        self.report = r
        self.json = j

    def process(self, update=False, retry=False):
        """
        Test all files with mmbot in a given folder.

        :param update: force updating VirusTotal result
        :param retry: retry VirusTotal request if previous result was None
        """
        assert (isinstance(self.results, dict) and all(isinstance(x, Series)
               for x in self.results.values())) or self.results is None
        logger.info("Processing samples...")
        # first, get the results of mmbot
        if self.results is None:
            self.results = {}
            for fn in os.listdir(self.folder):
                fp = os.path.abspath(os.path.join(self.folder, fn))
                if os.path.isfile(fp):
                    logger.debug("MMBot: classifying '{}'...".format(fn))
                    try:
                        self.results[fn] = self.bot.mmb_predict(fp,
                                           datatype='filepath').iloc[0]
                        del self.results[fn]['filepath']
                    except (TypeError, ValueError):
                        logger.error("Failed to classify '{}'".format(fn))
                        self.results[fn] = None
        else:
            logger.debug("Got results from loaded Pickle")
        # second, if enabled, get the result from VirusTotal
        if self.vt.is_enabled:
            for k, v in self.results.items():
                check = False
                f = "vt_detection_rate"
                if f not in v:
                    check = not logger.debug("> Getting VT information...")
                elif update:
                    check = not logger.debug("> Updating VT information...")
                elif v.get(f) is None and retry:
                    check = not logger.debug("> Retrying VT information...")
                if check:
                    v["vt_detection_rate"] = self.vt.check(v['md5'])
        else:
            logger.debug("VT check is disabled")
        # finally, if flag 'save' was set, pickle results to a file
        if self.__save:
            self.save()

    def save(self):
        """
        Save results as a Pickle.
        """
        with open(self.folder + '.pickle', 'wb') as f:
            logger.info("Saving results to pickle...")
            pickle.dump(self.results, f)


class Report(object):
    """
    This class represents a results report.

    :param data: results to be presented in the report
    :param title: title for the report
    :param output: report output format (extension)
    :param fn: filename of the report (without extension)
    """
    def __init__(self, tester, title=None, output="pdf", fn="report"):
        assert isinstance(tester, MacroSampleTester)
        assert output in OUTPUT_FORMATS
        self.data = tester.report
        self.json = tester.json
        if output in ["html", "pdf"]:
            try:
                import markdown2
                self.__markdown2 = True
            except ImportError:
                logger.warn("(Install 'markdown2' for generating HTML/PDF"
                            " reports)")
                self.__markdown2 = False
        if output == "pdf":
            try:
                from weasyprint import HTML
                self.__weasyprint = True
            except ImportError:
                logger.warn("(Install 'weasyprint' for generating PDF reports)")
                self.__weasyprint = False
        self.file = "{}.{}".format(fn, output)
        self.title = title
        if fn is not None:
            getattr(self, "_Report__{}".format(output))()

    def __html(self, text=False):
        """
        Generate an HTML file from the report data.

        :param text: return as text anyway
        :return: None if filename is not None, HTML report in text otherwise
        """
        if not self.__markdown2:
            return
        import markdown2
        html = markdown2.markdown(self.__md(True), extras=["tables"])
        logger.debug("Generating the HTML report{}..."
                     .format(["", " (text only)"][text]))
        if self.file is not None and not text:
            with open(self.file, 'w') as f:
                f.write(html)
        else:
            return html
    
    def __json(self, text=False):
        """
        Generate a JSON object from the report data.
        
        :param text: return as text anyway
        :return: None if filename is not None, JSON report in text otherwise
        """
        js = {'title': self.title}
        js.update(self.json)
        if self.file is not None and not text:
            with open(self.file, 'w') as f:
                json.dump(js, f, indent=4)
        else:
            return js

    def __md(self, text=False):
        """
        Generate a Markdown file from the report data.

        :param text: return as text anyway
        :return: None if filename is not None, Markdown report in text otherwise
        """
        logger.debug("Generating the Markdown report{}..."
                     .format(["", " (text only)"][text]))
        md = "# {}\n\n\n".format(self.title) if self.title is not None else ""
        l, h = True, False
        max_w = None
        for i, line in enumerate(self.data.split('\n')):
            if line == "":
                break  # table goes up to the first empty line
            v = re.split(r'\s{2,}', line)
            if i == 0:
                v = ["**" + x + "**" for x in v]
                max_w = [0] * len(v)
            for j in range(len(max_w)):
                max_w[j] = max(max_w[j], len(v[j]))
        for i, line in enumerate(self.data.split('\n')):
            if line == "":
                l = False  # switch when the table is over
            if l:
                v = re.split(r'\s{2,}', line)
                if i == 0:  # headers
                    v = ["**" + x + "**" for x in v]
                    md += "| {} |\n|:{}:|\n".format(
                        " | ".join(x.center(max_w[i]) for i, x in enumerate(v)),
                        ":|:".join('-' * max_w[i] for i in range(len(max_w))))
                else:       # rows
                    md += "| {} |\n".format(
                        " | ".join(x.replace("None", "").center(max_w[i]) \
                            for i, x in enumerate(v)))
            else:
                if line == "":
                    md += "\n\n"
                    h = True
                else:
                    if h:
                        md += "**" + line.rstrip(":") + "**:\n\n"
                        h = False
                    else:
                        md += "> " + line + "\n" + "> \n"
        if self.file is not None and not text:
            with open(self.file, 'w') as f:
                f.write(md)
        else:
            return md

    def __pdf(self):
        """
        Generate a PDF file from the report data.
        """
        if self.file is None or not self.__markdown2 or not self.__weasyprint:
            return
        tmp_css = "/tmp/{}-style.css".format(__file__.replace("./", ""))
        with open(tmp_css, 'w') as f:
            f.write(PDF_CSS)
        from weasyprint import HTML
        html = HTML(string=self.__html(True))
        logger.debug("Generating the PDF report...")
        html.write_pdf(self.file, stylesheets=[tmp_css])
        os.remove(tmp_css)


class VirusTotalClient(object):
    """
    This class is a kind of wrapper for the VirusTotal class. It checks if the
     'virustotal' module is installed. If so, it also performs a test request
     to check if the API key is valid and if it works as expected.

    :param api_key: VirusTotal API key
    """
    TEST = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    def __init__(self, api_key=None):
        self.__vt = None
        try:
            from virustotal import VirusTotal
            vt_present = True
        except ImportError:
            logger.warn("'virustotal' module is required to use VirusTotal")
            vt_present = False
        if vt_present:
            if api_key is not None:
                if os.path.isfile(api_key):
                    with open(api_key) as f:
                        api_key = f.read().strip()
                self.__vt = VirusTotal(api_key)
                try:
                    logger.debug("Testing VirusTotal API...")
                    self.__vt.get(VirusTotalClient.TEST)
                except urllib2.HTTPError:
                    logger.warn("Invalid API key ; VirusTotal check disabled")
                    self.__vt = None
                except VirusTotal.ApiError:
                    logger.warn("API error ; VirusTotal check disabled")
        self.is_enabled = self.__vt is not None

    def check(self, h):
        """
        Get the VirusTotal report of an input hash.

        :param h: the hash in MD5, SHA1 or SHA256
        :return: a string indicating the detection rate if request succeeded

        Failure cases:
        - hash is not known
        - bad API key
        - network error
        """
        if self.__vt is None:
            return
        assert any([len(re.findall(r"([a-fA-F\d]{32})", h)) > 0,   # MD5
                    len(re.findall(r"([a-fA-F\d]{40})", h)) > 0,   # SHA1
                    len(re.findall(r"([a-fA-F\d]{64})", h)) > 0])  # SHA256
        from virustotal import VirusTotal
        try:
            r = self.__vt.get(h)
            return "{}/{}".format(r.positives, r.total)
        except (VirusTotal.ApiError, AttributeError):
            logger.warn("VT lookup failed for '{}'".format(h))


# -------------------- MAIN SECTION --------------------
if __name__ == '__main__':
    parser.add_argument("samples", metavar="FOLDER",
                        help="folder with the samples to be tested OR\n"
                             "pickle name if results are loaded with -l")
    parser.add_argument("--api-key", dest="vt_key", default=None,
                        help="VirusTotal API key (default: none)\n  NB: "
                             "key as a string or file path to the key")
    parser.add_argument("--output", choices=OUTPUT_FORMATS, default=None,
                        help="report file format [html|md|pdf] (default: none)")
    parser.add_argument("-d", dest="dump", action="store_true",
                        help="dump complete results (default: false)")
    parser.add_argument("-f", dest="filter", action="store_true",
                        help="filter only DOC and XLS files (default: false)")
    parser.add_argument("-l", dest="load", action="store_true",
                        help="load previous pickled results (default: false)")
    parser.add_argument("-q", dest="quiet", action="store_true",
                        help="do not display results report (default: false)")
    parser.add_argument("-r", dest="retry", action="store_true",
                        help="when loading pickle, retry VirusTotal hashes"
                             " with None results\n (default: false)")
    parser.add_argument("-s", dest="save", action="store_true",
                        help="pickle results to a file (default: false)")
    parser.add_argument("-u", dest="update", action="store_true",
                        help="when loading pickle, update VirusTotal results"
                             " (default: false)")
    initialize(globals())
    validate(globals(),
        ('samples', "not os.path.isdir( ? )",
         "Please enter a valid samples folder"),
    )
    # running the main stuff
    tester = MacroSampleTester(args.samples, args.load, args.save,
                               not args.quiet, args.vt_key)
    tester.process(args.update, args.retry)
    if args.dump:
        for k in sorted(tester.results.keys()):
            print(repr(tester.results[k]) + '\n\n')
    tester.parse((lambda x: any([x.endswith(e) for e \
                            in ['.doc', '.xls']])) if args.filter else None)
    if args.output is not None:
        Report(tester, "Malicious Macro Detection Report", args.output)
