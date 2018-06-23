# Copyright (C) 2018  Bruno Melo <brunom@lasca.ic.unicamp.br>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
