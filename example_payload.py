# Note: This file is execed.
content = "Spoofed"
payload = "Content-Type: text/html; charset=utf-8\r\nContent-Length: " + str(len(content)) + "\r\nServer: Werkzeug/0.14.1 Python/2.7.10\r\n" + Chronos.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT') + "\r\n\r\n" + content