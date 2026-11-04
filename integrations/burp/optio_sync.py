# Optio sync — a Burp Suite extension that forwards in-scope traffic to Optio.
#
# Live sync: as you browse/proxy through Burp, each in-scope request+response is
# POSTed to Optio's /ingest endpoint, which records it as a captured request and
# grows the attack-surface graph. Works in Burp Community and Pro.
#
# Load it:
#   1. Burp -> Extensions -> Installed -> Add
#   2. Extension type: Python   (Burp needs Jython 2.7 configured under
#      Extensions -> Settings -> Python environment)
#   3. Select this file.
#
# Scope: only traffic Burp considers in-scope is forwarded (set your scope under
# Target -> Scope), so Optio never fills up with CDN/analytics noise.
#
# Point it at your Optio web port (default 8788) via OPTIO_URL below.

import json
import threading

from burp import IBurpExtender, IHttpListener
from java.net import URL, HttpURLConnection

OPTIO_URL = "http://127.0.0.1:8788/ingest"
MAX_BODY = 50000  # cap forwarded bodies so a large response never stalls Burp


def _headers_to_dict(header_lines):
    """Burp gives headers as ['GET / HTTP/1.1', 'Host: x', ...]; drop the first
    line (request/status line) and split the rest on the first colon."""
    out = {}
    for line in list(header_lines)[1:]:
        i = line.find(":")
        if i > 0:
            out[line[:i].strip()] = line[i + 1:].strip()
    return out


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Optio sync")
        callbacks.registerHttpListener(self)
        self._out = callbacks.getStdout()
        self._log("Optio sync loaded -> %s (forwarding in-scope traffic)" % OPTIO_URL)

    def _log(self, msg):
        try:
            self._out.write((msg + "\n").encode("utf-8"))
        except Exception:
            pass

    def processHttpMessage(self, tool_flag, is_request, message):
        # Act only once the response is in — we want the full request+response.
        if is_request:
            return
        try:
            service = message.getHttpService()
            req = message.getRequest()
            resp = message.getResponse()
            req_info = self._helpers.analyzeRequest(service, req)
            url = req_info.getUrl()
            if not self._cb.isInScope(url):
                return

            req_headers = _headers_to_dict(req_info.getHeaders())
            req_body = self._body(req, req_info.getBodyOffset())

            resp_info = self._helpers.analyzeResponse(resp)
            resp_headers = _headers_to_dict(resp_info.getHeaders())
            resp_body = self._body(resp, resp_info.getBodyOffset())

            payload = {
                "method": req_info.getMethod(),
                "url": str(url),
                "req_headers": req_headers,
                "req_body": req_body,
                "status": int(resp_info.getStatusCode()),
                "resp_headers": resp_headers,
                "resp_body": resp_body,
            }
            # Off the Burp thread so a slow/absent Optio never blocks the proxy.
            threading.Thread(target=self._post, args=(payload,)).start()
        except Exception as e:
            self._log("Optio sync: skipped a message (%s)" % e)

    def _body(self, raw, offset):
        try:
            data = self._helpers.bytesToString(raw)[offset:]
        except Exception:
            return ""
        return data[:MAX_BODY]

    def _post(self, payload):
        try:
            conn = URL(OPTIO_URL).openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setDoOutput(True)
            conn.setConnectTimeout(2000)
            conn.setReadTimeout(4000)
            body = json.dumps(payload)
            conn.getOutputStream().write(body.encode("utf-8"))
            conn.getResponseCode()  # fire the request; response body unused
            conn.disconnect()
        except Exception as e:
            self._log("Optio sync: POST failed (%s) — is Optio running on %s?" % (e, OPTIO_URL))
