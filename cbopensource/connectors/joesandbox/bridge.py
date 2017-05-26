from __future__ import division

from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult, AnalysisInProgress)
import cbint.utils.feed
import logging
from jbxapi import joe_api


log = logging.getLogger(__name__)


class JoeSandboxProvider(BinaryAnalysisProvider):
    def __init__(self, name, apiurl, apikey, params={}, verify_ssl=True):
        super(JoeSandboxProvider, self).__init__(name)

        self.joe_api = joe_api(apikey, verify_ssl, apiurl=apiurl)
        self.apiurl = apiurl
        self.params = params

    def check_result_for(self, md5sum):
        md5sum = self._normalize_md5(md5sum)

        matches = self.joe_api.search(md5sum)

        # non-list answer
        if not isinstance(matches, list):
            raise AnalysisTemporaryError(matches)

        # joe_api.search() checks multiple fields, thus we need to limit
        # the results to md5 matches
        matches = [match for match in matches if match["md5"] == md5sum]

        # nothing found
        if not matches:
            return None

        # grab the first result
        result = matches[0]
        return self._analysis_from_status_dict(result)

    def analyze_binary(self, md5sum, binary_file_stream):
        md5sum = self._normalize_md5(md5sum)

        log.info("Submitting binary %s (md5) to Joe Sandbox" % md5sum)

        response = self.joe_api.analyze(binary_file_stream, "", **self.params)

        try:
            webid = response["webid"]
        except (TypeError, KeyError):
            raise AnalysisTemporaryError(response)

        status = self.joe_api.status(webid)

        if not isinstance(status, dict):
            raise AnalysisTemporaryError(status)

        return self._analysis_from_status_dict(status)

    def _analysis_from_status_dict(self, status):
        """
        Constructs an AnalysisResult or an AnalysisInProgress from a Joe Sandbox
        json status object to hand back to Carbon Black.

        Can throw AnalysisPermanentError or AnalysisTemporaryError.
        """

        # short-circuit in progress
        if status["status"] == "submitted":
            return AnalysisInProgress(retry_in=120)

        if status["status"] == "running":
            return AnalysisInProgress(retry_in=60)

        # from here on we only accept status finished
        if status["status"] != "finished":
            raise AnalysisTemporaryError("Unknown status {}".format(status["status"]))

        # check for errors
        systems = status["systems"].split(";")[:-1]
        raw_errors = status["errors"].split(";")[:-1]
        errors = ["{}: {}".format(s, e) for s, e in zip(systems, raw_errors) if e]
        if errors:
            raise AnalysisPermanentError("\n".join(errors))

        analysis_result = self._interpret_analysis(status)

        # assign web link
        analysis_result.link = self.apiurl + "/../analysis/{}".format(status["webid"])

        return analysis_result

    def _interpret_analysis(self, status):
        """
        Downloads the irjsonfixed report and constructs an AnalysisResult from it.
        """
        analysis_result = AnalysisResult()

        # determine the most important run based on the detection number
        try:
            raw_detections = [int(d) for d in status["detections"].split(";")[:-1]]
        except ValueError:
            raise AnalysisTemporaryError("Wrong format for detection.")
        else:
            main_run = raw_detections.index(max(raw_detections))

        # download ir report
        ir_report = self.joe_api.report(status["webid"], run=main_run)

        # assign carbon black score
        # https://github.com/carbonblack/cbfeeds
        try:
            minscore = ir_report["detection"]["minscore"]
            maxscore = ir_report["detection"]["maxscore"]
            score = ir_report["detection"]["score"]
        except KeyError:
            raise AnalysisTemporaryError("Unable to extract score from IR report")
        else:
            # distribute our score between 0 and 100
            analysis_result.score = int(round((score - minscore) / (maxscore - minscore) * 100.0))

        # assign message
        detection = raw_detections[main_run]
        if detection == 0:
            analysis_result.message = "Sample is clean"
        elif detection == 1:
            analysis_result.message = "Sample is suspicious"
        elif detection >= 2:
            analysis_result.message = "Sample is malicious"
        else:
            analysis_result.message = "Unknown classification"

        return analysis_result

    def _normalize_md5(self, md5sum):
        """
        Converts md5 strings to lower case.
        """
        if not isinstance(md5sum, str):
            raise TypeError("md5sum must be of type str")

        if not len(md5sum) == 32:
            raise ValueError("invalid length of md5 string")

        return md5sum.lower()

class JoeSandboxConnector(DetonationDaemon):
    def get_provider(self):
        return JoeSandboxProvider(
            self.name,
            apiurl=self.joesandbox_url,
            apikey=self.joesandbox_apikey,
            params=self.params,
            verify_ssl = self.joesandbox_url_sslverify,
        )

    def get_metadata(self):
        return cbint.utils.feed.generate_feed(
            self.name,
            summary="Joe Sandbox Detonation Analysis",
            tech_data="A Joe Sandbox Cloud account or an on-premise device is required to use this feed. There are no requirements to share any data with Carbon Black to use this feed.",
            provider_url="https://www.joesecurity.org/",
            icon_path='/usr/share/cb/integrations/joesandbox/joesandbox-logo.png',
            display_name="Joe Sandbox",
            category="Connectors"
        )

    def validate_config(self):
        super(JoeSandboxConnector, self).validate_config()

        self.check_required_options(["joesandbox_url", "joesandbox_apikey", "joesandbox_url_sslverify", "joesandbox_architecture"])
        self.joesandbox_url = self.get_config_string("joesandbox_url", None)
        self.joesandbox_apikey = self.get_config_string("joesandbox_apikey", None)
        self.joesandbox_url_sslverify = self.get_config_boolean("joesandbox_url_sslverify", True)

        self.params = {}
        # read boolean params from config
        bool_params =  [
            "inet", "scae", "dec", "ssl", "filter", "hyper", "export_to_jbxview",
            "cache_sha256", "ais", "vbainstr", "resubmit_dropped", "send_on_complete",
        ]
        for key in bool_params:
            params[key] = self.get_config_boolean("joesandbox_" + key, False)

        # read string params from config
        params["comments"] = self.get_config_string("joesandbox_comments", "")
        params["systems"] = self.get_config_string("systems")

        # rename parameters for compatibility with jbxapi.py
        params["sendoncomplete"] = params.pop("send_on_complete")
        params["exporttojbxview"] = params.pop("export_to_jbxview")

        return True

    @property
    def filter_spec(self):
        arch = self.get_config_string("joesandbox_architecture", None)

        filters = [
            'os_type:{}'.format(arch),                         # executable architecture
            'orig_mod_len:[1 TO {}]'.format(10 * 1024 * 1024), # max. size of binary at time of collection
        ]

        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        return ' '.join(filters)

    @property
    def num_quick_scan_threads(self):
        return self.get_config_integer("joesandbox_quick_scan_threads", 1)

    @property
    def num_deep_scan_threads(self):
        return self.get_config_integer("joesandbox_deep_scan_threads", 3)

if __name__ == '__main__':
    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/joesandbox"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = JoeSandboxConnector('joesandboxtest', configfile=config_path, work_directory=temp_directory)

    daemon.start()
