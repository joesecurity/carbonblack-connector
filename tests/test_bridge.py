import unittest
from copy import copy

from cbopensource.connectors.joesandbox.bridge import JoeSandboxConnector, JoeSandboxProvider
from cbint.utils.detonation.binary_analysis import (
    AnalysisPermanentError, AnalysisTemporaryError,
    AnalysisResult, AnalysisInProgress,
)

class ProviderTest(unittest.TestCase):
    def setUp(self):
        self.provider = JoeSandboxProvider(
            name="TestProvider",
            apiurl="localhost",
            apikey="myapikey",
            params={}
        )

        # mock joe_api
        assert hasattr(self.provider, "joe_api")
        self.provider.joe_api = MockJoeApi()

    def test_check_result_good_path(self):
        result = self.provider.check_result_for(FINISHED_MD5)
        self.assertIsInstance(result, AnalysisResult)

    def test_check_result_unknown_sample(self):
        result = self.provider.check_result_for(UNKNOWN_MD5)
        self.assertEqual(result, None)

    def test_check_result_error(self):
        with self.assertRaises(AnalysisTemporaryError):
            self.provider.check_result_for(ERROR_MD5)

    def test_analyze_binary_good_path(self):
        result = self.provider.analyze_binary(FINISHED_MD5, GOOD_FILE)
        self.assertIsInstance(result, AnalysisInProgress)

    def test_analyze_binary_error(self):
        with self.assertRaises(AnalysisTemporaryError):
            self.provider.analyze_binary(UNKNOWN_MD5, ERROR_FILE)

    def test_analysis_in_progress(self):
        result1 = self.provider._analysis_from_status_dict(status_obj_submitted)
        result2 = self.provider._analysis_from_status_dict(status_obj_running)

        self.assertIsInstance(result1, AnalysisInProgress)
        self.assertIsInstance(result2, AnalysisInProgress)

    def test_analysis_finished(self):
        result = self.provider._analysis_from_status_dict(status_obj_finished)
        self.assertIsInstance(result, AnalysisResult)

    def test_analysis_with_errors(self):
        obj = copy(status_obj_finished)
        obj["errors"] = ";someerror;"

        with self.assertRaises(AnalysisPermanentError):
            self.provider._analysis_from_status_dict(obj)

    def test_score(self):
        result = self.provider._interpret_analysis(status_obj_finished)
        self.assertEqual(result.score, 50)

class MockJoeApi(object):
    def analyze(self, handle, url, **params):
        if handle is ERROR_FILE:
            return "some error string"
        if handle is GOOD_FILE:
            return {"webid": SUBMITTED_WEBID}

        raise NotImplementedError()

    def status(self, webid):
        if webid == ERROR_WEBID:
            return "some error string"
        elif webid == SUBMITTED_WEBID:
            return status_obj_submitted

        raise NotImplementedError()

    def search(self, query):
        if UNKNOWN_MD5 in query:
            return []
        elif ERROR_MD5 in query:
            return "some error string"
        elif FINISHED_MD5 in query:
            return [copy(status_obj_finished)]

        raise NotImplementedError()

    def report(self, webid, run=0):
        return {"detection": {
            "score": 50,
            "minscore": 20,
            "maxscore": 80,
        }}

# DATA

UNKNOWN_MD5 = "a3cca2b2aa1e3b5b3b5aad99a8529074"
SUBMITTED_MD5 = "7e716d0e702df0505fc72e2b89467910"
FINISHED_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
RUNNING_MD5 = "c4ca4238a0b923820dcc509a6f75849b"
ERROR_MD5 = "c81e728d9d4c2f636f067f89cc14862c"

ERROR_WEBID = 999
SUBMITTED_WEBID = 10000
RUNNING_WEBID = 20000
FINISHED_WEBID = 30000

GOOD_FILE = "this is a file"
ERROR_FILE = "this is not a file"

status_obj_finished = {
    "webid": FINISHED_WEBID,
    "status": "finished",
    "md5": FINISHED_MD5,
    "systems": "w7;w7;",
    "errors": ";;",
    "detections": "1;-1;",
}

status_obj_submitted = {
    "webid": SUBMITTED_WEBID,
    "status": "submitted",
    "md5": SUBMITTED_MD5,
    "systems": "w7;",
    "errors": ";",
}

status_obj_running = {
    "webid": RUNNING_WEBID,
    "status": "submitted",
    "md5": RUNNING_MD5,
    "systems": "w7;",
    "errors": ";",
}

