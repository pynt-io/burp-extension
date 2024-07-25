from burp import IBurpExtender, IExtensionStateListener, IProxyListener
from burp import IHttpRequestResponse
from java.io import PrintWriter
import threading


class BurpExtender(IBurpExtender, IExtensionStateListener, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("Pynt Extension")

        callbacks.registerProxyListener(self)
        callbacks.registerExtensionStateListener(self)

        self._stdout.println("Pynt Extension loaded")

        self._pynt_process = None
        self._pynt_monitor_thread = None
        self._stop_monitor = False

    def processProxyMessage(self, messageIsRequest, message):
        message_info = message.getMessageInfo()
        if messageIsRequest:
            request_info = self._helpers.analyzeRequest(message_info)
            url = request_info.getUrl()
            self._stdout.println("HTTP request to URL: {}".format(url))

            headers = request_info.getHeaders()
            body_offset = request_info.getBodyOffset()
            body = message_info.getRequest()[body_offset:].tostring()

            self._stdout.println("Request headers: {}".format(headers))
            self._stdout.println("Request body: {}".format(body))
        else:
            response_info = self._helpers.analyzeResponse(message.getResponse())
            status_code = response_info.getStatusCode()
            self._stdout.println("HTTP response with status code: {}".format(status_code))

            headers = response_info.getHeaders()
            body_offset = response_info.getBodyOffset()
            body = message.getResponse()[body_offset:].tostring()

            self._stdout.println("Response headers: {}".format(headers))
            self._stdout.println("Response body: {}".format(body))

    def run_pynt(self):
        self._stdout.println("Starting Pynt proxy with Docker container...")
        self._stdout.println("Pynt proxy started.")

        self._stop_monitor = False
        self._pynt_monitor_thread = threading.Thread(target=self.monitor_pynt_process)
        self._pynt_monitor_thread.start()

    def stop_pynt(self):
        self._stdout.println("Requesting pynt to stop...")
        if self._pynt_process:
            self._stop_monitor = True
            self._pynt_monitor_thread.join()
            self._pynt_process.terminate()
            self._stdout.println("Waiting for pynt to stop...")
            self._pynt_process.wait()
            self._stdout.println("Pynt stopped.")
            self._pynt_process = None
        else:
            self._stdout.println("No Pynt process was running.")

    def monitor_pynt_process(self):
        while not self._stop_monitor:
            retcode = self._pynt_process.poll()
            if retcode is not None:
                self._stdout.println("Pynt process completed.")
                break

    def extensionUnloaded(self):
        self.stop_pynt()
        self._stdout.println("Pynt Extension unloaded")
