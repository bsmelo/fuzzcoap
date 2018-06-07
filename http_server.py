import http.server
import socketserver
import os
import sys

PORT = int(sys.argv[1])
WEB_DIR = sys.argv[2]

os.chdir(WEB_DIR)

Handler = http.server.SimpleHTTPRequestHandler
httpd = socketserver.TCPServer(("127.0.0.1", PORT), Handler)

print "serving directory %s at port %d" % (WEB_DIR, PORT)
httpd.serve_forever()
