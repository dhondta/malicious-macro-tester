#!/usr/bin/python3
# -*- coding: UTF-8 -*-

__author__ = "Alexandre D'Hondt"
__version__ = "2.4.2"
__copyright__ = "A. D'Hondt"
__license__   = "agpl-3.0"
__reference__ = "INFOM444 - Machine Learning - Hot Topic"
__doc__ = """
This tool uses MaliciousMacroBot to classify a list of samples as benign or malicious and provides a report. Note that
 it only works on an input folder and list every file to run it against mmbot.
"""
__examples__ = ["my_samples_folder", "my_samples_folder --api-key virustotal-key.txt -lr",
                "my_samples_folder -lsrv --api-key 098fa24...be724a0", "my_samples_folder -lf --output pdf",
                "my_samples_folder --output es --sent"]

import sys
if sys.version_info[0] < 3:
    print("Sorry, this script only works with Python 3...")
    sys.exit(0)
# -------------------- IMPORTS SECTION --------------------
import hashlib
import json
import markdown2
import pickle
import xmltodict
from collections import OrderedDict
from mmbot import MaliciousMacroBot
from os.path import abspath, exists, isdir, join
from subprocess import PIPE, Popen
from tinyscript import *
try:
    from elasticsearch import Elasticsearch, helpers
    es_enabled = True
except ImportError:
    es_enabled = False


# -------------------- CONSTANTS SECTION --------------------
PDF_CSS = "h1,h3{line-height:1}address,blockquote,dfn,em{font-style:italic}html{font-size:100.01%}body{font-size:75%;" \
          "color:#222;background:#fff;font-family:\"Helvetica Neue\",Arial,Helvetica,sans-serif}h1,h2,h3,h4,h5,h6{fon" \
          "t-weight:400;color:#111}h1{font-size:3em;margin-bottom:.5em}h2{font-size:2em;margin-bottom:.75em}h3{font-s" \
          "ize:1.5em;margin-bottom:1em}h4{font-size:1.2em;line-height:1.25;margin-bottom:1.25em}h5,h6{font-size:1em;f" \
          "ont-weight:700}h5{margin-bottom:1.5em}h1 img,h2 img,h3 img,h4 img,h5 img,h6 img{margin:0}p{margin:0 0 1.5e" \
          "m}.left{float:left!important}p .left{margin:1.5em 1.5em 1.5em 0;padding:0}.right{float:right!important}p ." \
          "right{margin:1.5em 0 1.5em 1.5em;padding:0}address,dl{margin:0 0 1.5em}a:focus,a:hover{color:#09f}a{color:" \
          "#06c;text-decoration:underline}.quiet,blockquote,del{color:#666}blockquote{margin:1.5em}dfn,dl dt,strong,t" \
          "h{font-weight:700}sub,sup{line-height:0}abbr,acronym{border-bottom:1px dotted #666}pre{margin:1.5em 0;whit" \
          "e-space:pre}code,pre,tt{font:1em 'andale mono','lucida console',monospace;line-height:1.5}li ol,li ul{marg" \
          "in:0}ol,ul{margin:0 1.5em 1.5em 0;padding-left:1.5em}ul{list-style-type:disc}ol{list-style-type:decimal}dd" \
          "{margin-left:1.5em}table{margin-bottom:1.4em;width:100%}thead th{background:#c3d9ff}caption,td,th{padding:" \
          "4px 10px 4px 5px}tbody tr.even td,tbody tr:nth-child(even) td{background:#e5ecf9}tfoot{font-style:italic}c" \
          "aption{background:#eee}.small{font-size:.8em;margin-bottom:1.875em;line-height:1.875em}.large{font-size:1." \
          "2em;line-height:2.5em;margin-bottom:1.25em}.hide{display:none}.loud{color:#000}.highlight{background:#ff0}" \
          ".added{background:#060;color:#fff}.removed{background:#900;color:#fff}.first{margin-left:0;padding-left:0}" \
          ".last{margin-right:0;padding-right:0}.top{margin-top:0;padding-top:0}.bottom{margin-bottom:0;padding-botto" \
          "m:0}"
OUTPUT_FORMATS = ["es", "html", "json", "md", "pdf", "xml"]
HBLOCKSIZE = 65536


# ------------------- FUNCTIONS SECTION -------------------
def hash_file(filename, algo="sha1"):
    try:
        h = getattr(hashlib, algo)()
    except AttributeError:
        return
    with open(filename, 'rb') as f:
        b = f.read(HBLOCKSIZE)
        while len(b) > 0:
            h.update(b)
            b = f.read(HBLOCKSIZE)
    return h.hexdigest()


# -------------------- CLASSES SECTION --------------------
class MacroSampleTester(object):
    """ This class is aimed to test multiple documents from a given folder with MaliciousMacroBot.

    :param folder:      path to the samples folder
    :param dump:        dump the extracted VBA macros
    :param load:        load previous results before starting
    :param save:        save results after processing
    :param display:     display report in terminal after processing
    :param filter_func: function for filtering files
    :param api_key:     VirusTotal API key
    :param update:      force updating VirusTotal result
    :param retry:       retry VirusTotal request if previous result was None
    """
    def __init__(self, folder, dump=True, load=False, save=False, display=False, filter_func=None, api_key=None,
                 update=False, retry=False):
        if filter_func is not None and not hasattr(filter_func, '__call__'):
            raise ValueError("filter_func must be a function")
        self.__display = display
        self.__dump = dump
        self.__filter_func = filter_func
        self.__retry = retry
        self.__save = save
        self.__update = update
        self.folder = folder
        self.report = None
        self.results = None
        self.vt = VirusTotalClient(api_key)
        if load:
            self._load()
            if self.results is None:
                return
        else:
            if not load and not isdir(folder):
                logger.error("'{}' isn't a valid samples folder".format(folder))
                return
            logger.info("Initializing MaliciousMacroBot...")
            self.bot = MaliciousMacroBot()
            self.bot.mmb_init_model()
        self.process()

    def _load(self):
        """ Load results from a Pickle. """
        fn = self.folder + ".pickle"
        try:
            with open(fn, 'rb') as f:
                logger.info("Loading previous results from pickle...")
                self.results = pickle.load(f)
        except IOError:
            logger.error("'{}' does not exist".format(fn))
            self.results = None

    def _save(self):
        """ Save results as a Pickle. """
        with open(self.folder + '.pickle', 'wb') as f:
            logger.info("Saving results to pickle...")
            pickle.dump(self.results, f)

    def process(self):
        """ Test all files with mmbot in a given folder and produce a report. """
        if self.results is not None and not isinstance(self.results, dict):
            raise ValueError("Bad results format")
        logger.info("Processing samples...")
        # first, get the results of mmbot
        if self.results is None:
            self.results = {}
            for fn in os.listdir(self.folder):
                fp = os.path.abspath(os.path.join(self.folder, fn))
                if os.path.isfile(fp):
                    logger.debug("MMBot: classifying '{}'...".format(fn))
                    try:
                        r = self.bot.mmb_predict(fp, datatype='filepath').iloc[0]
                        r = {k: v for k, v in r.iteritems() if k != 'result_dictionary'}
                        r['sha256'] = hash_file(fp, "sha256")
                        self.results[fn] = r
                    except (TypeError, ValueError):
                        logger.error("Failed to classify '{}'".format(fn))
                        self.results[fn] = None
        # second, if enabled, get the result from VirusTotal
        if self.vt.is_enabled:
            for k, v in self.results.items():
                check = False
                f = "vt_detection_rate"
                if f not in v:
                    check = not logger.debug("> Getting VT information ({})...".format(k))
                elif self.__update:
                    check = not logger.debug("> Updating VT information ({})...".format(k))
                elif v.get(f) is None and self.__retry:
                    check = not logger.debug("> Retrying VT information ({})...".format(k))
                if check:
                    v["vt_detection_rate"] = self.vt.check(v['sha256'])
        # if flag '__save' was set, pickle results to a file
        if self.__save:
            self._save()
        # prepare folders for extracting the macros
        if self.__dump:
            vba = join(self.folder, 'vba')
            logger.warn("Macros will be saved to: {}".format(vba))
            vba = abspath(vba)
            bf, mf = join(vba, 'benign'), join(vba, 'malicious')
            if not os.path.isdir(vba):
                os.makedirs(vba)
            if not os.path.isdir(bf):
                os.makedirs(bf)
            if not os.path.isdir(mf):
                os.makedirs(mf)
        # parse the results
        logger.info("Parsing results...")
        benign, c_all, c_vba = [], [0] * 4, [0] * 4
        if self.vt.is_enabled:
            r = "{: <16}  {: <16}  {}\n".format("FILE", "PREDICTION", "VT DETECTION")
        else:
            r = "{: <16}  {}\n".format("FILE", "PREDICTION")
        j = OrderedDict([('title', "Malicious Macro Detection Report"), ('statistics', None), ('results', [])])
        for k, v in sorted(self.results.items()):
            # filter according to the input lambda function 'filter_func'
            if self.__filter_func is not None and not self.__filter_func(k):
                continue
            # define shortnames
            drate = v.get('vt_detection_rate')
            macro = v['extracted_vba']
            failed = any(macro.startswith(x) for x in ["Error:'utf8'", "Error:Failed", "No VBA Macros found"])
            pred = v['prediction']
            malicious = pred == "malicious"
            i = {'file': k, 'prediction': pred, 'sha256': v['sha256']}
            # save the VBA code to the samples folder in subfolder 'vba'
            if not failed:
                if self.__dump:
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
        r += "\nAll files:\n  Marked as malicious:                  {: >3}/{} ({}%)" \
             .format(c_all[0], c_all[-1], 100 * c_all[0] / c_all[-1])
        if self.vt.is_enabled:
            j['statistics']['all'].update({'vt_unknown': c_all[1], 'malicious_and_vt_known': c_all[2]})
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
            j['statistics']['vba'].update({'vt_unknown': c_vba[1], 'malicious_and_vt_known': c_vba[2]})
            r += "\n  Unknown from VT:                      {: >3}/{} ({}%)" \
                 .format(c_vba[1], c_vba[-1], 100 * c_vba[1] / c_vba[-1]) + \
                 "\n  Marked as malicious and known from VT:{: >3}/{} ({}%)" \
                 .format(c_vba[2], c_vba[-1], 100 * c_vba[2] / c_vba[-1])
        r += "\n\nBenign files:\n{}".format(", ".join(benign))
        if self.__display:
            print(r)
        self.report = r
        self.json = j
        

class Report(object):
    """ This class represents a results report.

    :param data:   results to be presented in the report
    :param title:  title for the report
    :param output: report output format (extension)
    :param fn:     filename of the report (without extension)
    """
    def __init__(self, tester, title=None, output="pdf", fn="report"):
        if not isinstance(tester, MacroSampleTester):
            raise ValueError("Bad tester instance")
        if output not in OUTPUT_FORMATS:
            raise ValueError("This format is not supported")
        try:
            self.data = tester.report
            self.json = tester.json
        except AttributeError:
            return
        self.file = "{}.{}".format(fn, output)
        self.title = title
        if fn is not None:
            getattr(self, "_Report__{}".format(output))()
    
    def __es(self, text=False):
        """ Generate a JSON formatted for ElasticSearch.
        
        :param text: return as text anyway
        :return:     None if filename is not None, HTML report in text otherwise
        """
        if not es_enabled:
            return
        es = []
        for r in self.json['results']:
            action = {'_index': "mmbot-results", '_type': "file", 'doc': r}
            es.append(action)
        if self.file is not None and not text:
            with open(self.file, 'w') as f:
                json.dump(es, f, indent=4)
        else:
            return es

    def __html(self, text=False):
        """ Generate an HTML file from the report data.

        :param text: return as text anyway
        :return:     None if filename is not None, HTML report in text otherwise
        """
        
        html = markdown2.markdown(self.__md(True), extras=["tables"])
        logger.debug("Generating the HTML report{}...".format(["", " (text only)"][text]))
        if self.file is not None and not text:
            with open(self.file, 'w') as f:
                f.write(html)
        else:
            return html
    
    def __json(self, text=False):
        """ Generate a JSON object from the report data.
        
        :param text: return as text anyway
        :return:     None if filename is not None, JSON report in text otherwise
        """
        logger.debug("Generating the JSON report{}...".format(["", " (text only)"][text]))
        js = {'title': self.title}
        js.update(self.json)
        if self.file is not None and not text:
            with open(self.file, 'w') as f:
                json.dump(js, f, indent=4)
        else:
            return js

    def __md(self, text=False):
        """ Generate a Markdown file from the report data.

        :param text: return as text anyway
        :return:     None if filename is not None, Markdown report in text
                      otherwise
        """
        logger.debug("Generating the Markdown report{}...".format(["", " (text only)"][text]))
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
            else:
                v[0] = "`{}`".format(v[0])
            for j in range(len(max_w)):
                max_w[j] = max(max_w[j], len(v[j]))
        for i, line in enumerate(self.data.split('\n')):
            if line == "":
                l = False  # switch when the table is over
            if l:
                v = re.split(r'\s{2,}', line)
                if i == 0:  # headers
                    v = ["**" + x + "**" for x in v]
                    md += "| {} |\n|:{}:|\n".format(" | ".join(x.center(max_w[i]) for i, x in enumerate(v)),
                                                    ":|:".join('-' * max_w[i] for i in range(len(max_w))))
                else:       # rows
                    v[0] = "`{}`".format(v[0])
                    md += "| {} |\n".format(" | ".join(x.replace("None", "").center(max_w[i]) for i, x in enumerate(v)))
            else:
                if line == "":
                    md += "\n\n"
                    h, n = True, None
                else:
                    if h:
                        n = line.rstrip(":")
                        md += "**{}**:\n\n".format(n)
                        h = False
                    else:
                        b = []
                        for f in line.split(','):
                            f = f.strip()
                            if n == "Benign files":
                                f = "`{}`".format(f)
                            b.append(f)
                            line = ", ".join(b)
                        md += "> {}\n> \n".format(line)
        if self.file is not None and not text:
            with open(self.file, 'w') as f:
                f.write(md)
        else:
            return md

    def __pdf(self):
        """ Generate a PDF file from the report data.

        :param text: return as text anyway
        :return:     None if filename is not None, XML report in text otherwise
        """
        if self.file is None:
            return
        tmp_css = "/tmp/{}-style.css".format(__file__.replace("./", ""))
        with open(tmp_css, 'w') as f:
            f.write(PDF_CSS)
        from weasyprint import HTML
        html = HTML(string=self.__html(True))
        logger.debug("Generating the PDF report...")
        html.write_pdf(self.file, stylesheets=[tmp_css])
        os.remove(tmp_css)
    
    def __xml(self, text=False):
        """ Generate an XML output from the report data. """
        _ = self.__json(True)
        stats = OrderedDict()
        js = OrderedDict([('title', self.title), ('statistics', _['statistics']),
                          ('results', {'result': _['results']})])
        logger.debug("Generating the XML report{}...".format(["", " (text only)"][text]))
        xml = xmltodict.unparse({'report': js}, pretty=True)
        if self.file is not None and not text:
            with open(self.file, 'w') as f:
                f.write(xml)
        else:
            return xml


class ElasticSearchClient(object):
    """ This class is a wrapper for the ElasticSearch-Loader tool ; https://pypi.org/project/elasticsearch-loader/
    It first checks if the 'elasticsearch-loader' module is installed. If so,
     it determines the location of the config file according to this order:
     1. ./elasticsearch.conf
     2. /etc/elasticsearch/elasticsearch.conf
    """
    CFG_FILE = "elasticsearch.conf"
    CFG_PATH = "/etc/elasticsearch"
    LOADER   = "elasticsearch_loader"
    
    def __init__(self):
        try:
            check_output([LOADER])
            es_present = True
        except OSError:
            logger.warn("'{}' module is required".format(LOADER.replace('_', '-')))
            es_present = False
        self.config = None
        if es_present:
            for cfg in [self.CFG_FILE, join(self.CFG_PATH, self.CFG_FILE)]:
                try:
                    with open(cfg) as f:
                        pass
                    self.config = cfg
                    break
                except IOError:
                    pass
            if self.config is None:
                logger.error("No ElasticSearch configuration file found")
        self.is_enabled = self.config is not None
        
    def load(self, filename):
        """ This calls elasticsearch_loader for loading the file into the ES instance as configured in self.config.
         
        :param filename: JSON file to be loaded into ES
        """
        p = Popen([self.LOADER, "-c", self.config, "json", filename], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        if len(err) > 0:
            logger.error(err)


class VirusTotalClient(object):
    """ This class is a kind of wrapper for the VirusTotal class. It checks if the 'virustotal' module is installed.
    If so, it also performs a test request to check if the API key is valid and if it works as expected.

    :param api_key: VirusTotal API key
    """
    TEST = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    def __init__(self, api_key=None):
        self.__vt = None
        from virus_total_apis import PublicApi as VT
        try:
            vt_present = True
        except ImportError:
            logger.warn("'virustotal-api' module is required to use VirusTotal")
            vt_present = False
        if vt_present:
            if api_key is not None:
                if os.path.isfile(api_key):
                    with open(api_key) as f:
                        api_key = f.read().strip()
                self.__vt = VT(api_key)
                try:
                    logger.debug("Testing VirusTotal API...")
                    self.__vt.get_file_report(VirusTotalClient.TEST)
                except:
                    logger.error("VirusTotal check disabled")
        self.is_enabled = self.__vt is not None

    def check(self, h):
        """ Get the VirusTotal report of an input hash.

        :param h: the hash in MD5, SHA1 or SHA256
        :return: a string indicating the detection rate if request succeeded

        Failure cases:
        - hash is not known
        - network error
        """
        if self.__vt is None:
            return
        if not re.match(r"^([a-fA-F\d]{32}|[a-fA-F\d]{40}|[a-fA-F\d]{64})$", h):
            raise ValueError("Bad hash ; should be MD5, SHA1 or SHA256")
        try:
            r = self.__vt.get_file_report(h)
            return "{}/{}".format(r["results"]["positives"], r["results"]["total"])
        except:
            logger.warn("VT lookup failed for '{}'".format(h))


# -------------------- MAIN SECTION --------------------
if __name__ == '__main__':
    parser.add_argument("samples", metavar="FOLDER",
                        help="folder with the samples to be tested OR\npickle name if results are loaded with -l")
    parser.add_argument("-d", dest="dump", action="store_true", help="dump the VBA macros")
    parser.add_argument("-f", dest="filter", action="store_true", help="filter only DOC and XLS files")
    parser.add_argument("-l", dest="load", action="store_true", help="load previous pickled results")
    parser.add_argument("-q", dest="quiet", action="store_true", help="do not display results report")
    parser.add_argument("-r", dest="retry", action="store_true",
                        help="when loading pickle, retry VirusTotal hashes with None results\n")
    parser.add_argument("-s", dest="save", action="store_true", help="pickle results to a file")
    parser.add_argument("-u", dest="update", action="store_true", help="when loading pickle, update VirusTotal results")
    parser.add_argument("--api-key", dest="vt_key", default=None, help="VirusTotal API key",
                        note="key as a string or file path to the key")
    parser.add_argument("--output", choices=OUTPUT_FORMATS, default=None, help="report file format")
    parser.add_argument("--send", action="store_true", help="send the data to ElasticSearch",
                        note="only applies to 'es' format\n     the configuration is loaded with the following "
                             "precedence:\n     1. ./elasticsearch.conf\n     2. /etc/elasticsearch/elasticsearch.conf")
    initialize(noargs_action="wizard")
    # running the main stuff
    tester = MacroSampleTester(args.samples, args.dump, args.load, args.save, not args.quiet,
                               (lambda x: any([x.endswith(e) for e in ['.doc', '.xls']])) if args.filter else None,
                               args.vt_key, args.update, args.retry)
    if args.output is not None:
        r = Report(tester, "Malicious Macro Detection Report", args.output)
    if args.output == "es" and args.es_send:
        ElasticSearchClient().load(r.file)

