from __future__ import division

from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult, AnalysisInProgress)
import cbint.utils.feed
import logging
import jbxapi
import json
import time

logger = logging.getLogger(__name__)


class JoeSandboxProvider(BinaryAnalysisProvider):
    def __init__(self, name, apiurl, apikey, accept_tac, params, verify_ssl, analysis_timeout):
        super(JoeSandboxProvider, self).__init__(name)

        accept_tac = True
        timeout = 5
        self.joe = jbxapi.JoeSandbox(apikey=apikey,
                                     apiurl=apiurl,
                                     accept_tac=accept_tac,
                                     verify_ssl=verify_ssl,
                                     timeout=timeout,
                                     user_agent="Carbon Black")
        self.apiurl = apiurl
        self.analysis_timeout = analysis_timeout
        self.params = params

    def check_result_for(self, md5sum):
        logger.info("Checking result for {0}".format(md5sum))
        md5sum = self._normalize_md5(md5sum)

        found = False
        try:
            analyses = self.joe.analysis_search(md5sum)

            for analysis in analyses:
                info = self.joe.analysis_info(analysis["webid"])

                # 1. The search checks multiple fields, thus we need to limit
                #    the results to md5 matches
                # 2. We cannot use encrypted analyses so we ignore those.
                if self._normalize_md5(info["md5"]) == md5sum and not info["encrypted"]:
                    found = True
                    break

        except jbxapi.ServerOfflineError as e:
            raise AnalysisTemporaryError(str(e))
        except jbxapi.ConnectionError as e:
            raise AnalysisTemporaryError(str(e))
        except Exception as e:
            raise AnalysisPermanentError(str(e))

        # nothing found
        if not found:
            return None

        # short-circuit in progress
        if info["status"] != "finished":
            return AnalysisInProgress(retry_in=60)

        return self._interpret_analysis(info["webid"])

    def analyze_binary(self, md5sum, binary_file_stream):
        logger.info("Analyzing binary for {0}".format(md5sum))
        md5sum = self._normalize_md5(md5sum)

        try:
            response = self.joe.submit_sample((md5sum, binary_file_stream), params=self.params)
            submission_id = response["submission_id"]

            # wait until the analysis is finished
            start_time = time.time()
            while True:
                submission_info = self.joe.submission_info(submission_id)
                if submission_info["status"] == "finished":
                    break

                if start_time + self.analysis_timeout < time.time():
                    raise AnalysisPermanentError("Analysis timed out: ({0}s)".format(self.analysis_timeout))

                time.sleep(60)

        except jbxapi.ServerOfflineError as e:
            raise AnalysisTemporaryError(str(e))
        except jbxapi.ConnectionError as e:
            raise AnalysisTemporaryError(str(e))
        except Exception as e:
            raise AnalysisPermanentError(str(e))

        if submission_info["most_relevant_analysis"] is None:
            return AnalysisResult(score=0, title="Clean", message="Sample is empty")

        webid = submission_info["most_relevant_analysis"]["webid"]
        return self._interpret_analysis(webid)

    def _interpret_analysis(self, webid):
        """
        Constructs an AnalysisResult or an AnalysisInProgress for the given
        analysis (webid).

        Can throw AnalysisPermanentError or AnalysisTemporaryError.
        """
        analysis_result = AnalysisResult()

        # create analysis url
        parts = self.apiurl.split("/")
        while not parts[-1]:
            parts.pop()
        assert parts[-1] == "api"
        parts.pop()

        analysis_result.link = "/".join(parts) + "/analysis/{}".format(webid)

        # download ir report
        (_, ir_report) = self.joe.analysis_download(webid, type="irjsonfixed")
        ir_report = json.loads(ir_report)

        # assign carbon black score
        try:
            minscore = ir_report["analysis"]["detection"]["minscore"]
            maxscore = ir_report["analysis"]["detection"]["maxscore"]
            score = ir_report["analysis"]["detection"]["score"]
            detection = ("malicious"  if ir_report["analysis"]["detection"]["malicious"] else
                         "suspicious" if ir_report["analysis"]["detection"]["suspicious"] else
                         "clean"      if ir_report["analysis"]["detection"]["clean"] else
                         "unknown")
        except KeyError:
            raise AnalysisPermanentError("Unable to extract score from IR report")
        else:
            # distribute our score between 0 and 100
            analysis_result.score = int(round((score - minscore) / (maxscore - minscore) * 100.0))

        # assign message
        analysis_result.title = "Joe Sandbox Detection: " + detection

        return analysis_result

    def _normalize_md5(self, md5sum):
        """
        Converts md5 strings to lower case.
        """
        md5sum = md5sum.encode("ascii")

        if not isinstance(md5sum, str):
            raise TypeError("md5sum must be of type str, is {0}".format(type(md5sum)))

        if not len(md5sum) == 32:
            raise ValueError("invalid length of md5 string")

        return md5sum.lower()

class JoeSandboxConnector(DetonationDaemon):
    def get_provider(self):
        return JoeSandboxProvider(
            self.name,
            apiurl=self.joesandbox_apiurl,
            apikey=self.joesandbox_apikey,
            accept_tac=self.joesandbox_accept_tac,
            params=self.params,
            verify_ssl=self.joesandbox_sslverify,
            analysis_timeout=self.joesandbox_analysis_timeout
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

        self.check_required_options(["joesandbox_apiurl", "joesandbox_apikey", "joesandbox_sslverify"])

        self.params = {}

        self.joesandbox_apiurl = self.get_config_string("joesandbox_apiurl", None)
        self.joesandbox_apikey = self.get_config_string("joesandbox_apikey", None)
        self.joesandbox_sslverify = self.get_config_boolean("joesandbox_sslverify", True)
        self.joesandbox_accept_tac = self.get_config_boolean("joesandbox_accept_tac", False)
        self.joesandbox_analysis_timeout = self.get_config_integer("joesandbox_analysis_timeout", 3600)

        # params
        systems = self.get_config_string("joesandbox_systems", "").split(",")
        self.params["systems"] = [x.strip() for x in systems if x.strip()]
        tags = self.get_config_string("joesandbox_tags", "").split(",")
        self.params["tags"] = [x.strip() for x in tags if x.strip()]
        self.params["comments"] = self.get_config_string("joesandbox_comments", None)
        self.params["analysis-time"] = self.get_config_integer("joesandbox_analysis_time", None)
        self.params["localized-internet-country"] = self.get_config_string("joesandbox_localized_internet_country", None)
        self.params["internet-access"] = self.get_config_boolean("joesandbox_internet_access", None)
        self.params["internet-simulation"] = self.get_config_boolean("joesandbox_internet_simulation", None)
        self.params["report-cache"] = self.get_config_boolean("joesandbox_report_cache", None)
        self.params["hybrid-code-analysis"] = self.get_config_boolean("joesandbox_hybrid_code_analysis", None)
        self.params["hybrid-decompilation"] = self.get_config_boolean("joesandbox_hybrid_decompilation", None)
        self.params["ssl-inspection"] = self.get_config_boolean("joesandbox_ssl_inspection", None)
        self.params["vba-instrumentation"] = self.get_config_boolean("joesandbox_vba_instrumentation", None)
        self.params["js-instrumentation"] = self.get_config_boolean("joesandbox_js_instrumentation", None)
        self.params["java-jar-tracing"] = self.get_config_boolean("joesandbox_java_jar_tracing", None)
        self.params["static-only"] = self.get_config_boolean("joesandbox_static_only", None)
        self.params["start-as-normal-user"] = self.get_config_boolean("joesandbox_start_as_normal_user", None)
        self.params["anti-evasion-date"] = self.get_config_boolean("joesandbox_anti_evasion_date", None)
        self.params["language-and-locale"] = self.get_config_boolean("joesandbox_language_and_locale", None)
        self.params["archive-no-unpack"] = self.get_config_boolean("joesandbox_archive_no_unpack", None)
        self.params["hypervisor-based-inspection"] = self.get_config_boolean("joesandbox_hypervisor_based_inspection", None)
        self.params["fast-mode"] = self.get_config_boolean("joesandbox_fast_mode", None)
        self.params["secondary-results"] = self.get_config_boolean("joesandbox_secondary_results", None)
        self.params["apk-instrumentation"] = self.get_config_boolean("joesandbox_apk_instrumentation", None)
        self.params["amsi-unpacking"] = self.get_config_boolean("joesandbox_amsi_unpacking", None)

        # JOE SANDBOX CLOUD EXCLUSIVE PARAMETERS
        self.params["url-reputation"] = self.get_config_boolean("joesandbox_url_reputation", None)
        self.params["delete-after-days"] = self.get_config_boolean("joesandbox_delete_after_days", None)

        # ON PREMISE EXCLUSIVE PARAMETERS
        self.params["priority"] = self.get_config_boolean("joesandbox_priority", None)

        return True

    @property
    def filter_spec(self):
        filters = self.get_config_string("binary_filter_query", "")
        filters = filters.replace("\r", "\n")
        filters = filters.split("\n")

        # remove empty ones and rejoin
        filters = [x.strip() for x in filters if x.strip()]
        filters = ' '.join(filters)

        logger.info("Using filter spec: " + filters)

        return filters

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
    daemon = JoeSandboxConnector('joesandbox', configfile=config_path, work_directory=temp_directory)

    daemon.start()
