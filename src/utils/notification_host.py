"""Host-side notification bridge HTTP server."""

from __future__ import annotations

import http.server
import json
import logging
import subprocess
import sys

logger = logging.getLogger(__name__)


class NotificationHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler to process notification requests and trigger OS toasts."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default HTTP logging to stdout, routing to logging framework instead."""
        logger.debug(format, *args)

    def do_POST(self) -> None:
        """Handle incoming POST requests to /notify."""
        if self.path != "/notify":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body)
            title = data.get("title", "Ransomware Alert")
            message = data.get("message", "Suspicious behavior detected!")
            
            logger.info("Received notification request: %s - %s", title, message)
            self.show_toast(title, message)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "success"}')
        except Exception as e:
            logger.error("Failed to parse request or display toast: %s", e)
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode("utf-8"))

    def show_toast(self, title: str, message: str) -> None:
        """Show a native Windows Toast notification using built-in PowerShell and WinRT APIs."""
        # Double single quotes to escape them in PowerShell string literals
        safe_title = title.replace("'", "''")
        safe_message = message.replace("'", "''")

        powershell_cmd = f"""
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
        $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $RawXml = [xml]$Template.GetXml()
        ($RawXml.toast.visual.binding.text | Where-Object {{ $_.id -eq "1" }}).AppendChild($RawXml.CreateTextNode('{safe_title}')) | Out-Null
        ($RawXml.toast.visual.binding.text | Where-Object {{ $_.id -eq "2" }}).AppendChild($RawXml.CreateTextNode('{safe_message}')) | Out-Null
        $SerializedXml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $SerializedXml.LoadXml($RawXml.OuterXml)
        $Toast = [Windows.UI.Notifications.ToastNotification]::new($SerializedXml)
        $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("RansomwareDetector")
        $Notifier.Show($Toast)
        """

        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", powershell_cmd],
                capture_output=True,
                check=True,
            )
            logger.info("Successfully displayed Toast notification.")
        except subprocess.CalledProcessError as e:
            logger.error("PowerShell toast execution failed. Stderr: %s", e.stderr.decode("utf-8", errors="ignore"))


def main() -> None:
    """Run the notification bridge HTTP server."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    port = 5454
    server_address = ("0.0.0.0", port)
    
    try:
        httpd = http.server.HTTPServer(server_address, NotificationHandler)
        logger.info("Notification bridge HTTP server starting on port %d...", port)
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server shutting down.")
        sys.exit(0)
    except Exception as e:
        logger.exception("Server error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
