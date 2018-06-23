#!/bin/bash

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

mkdir /tmp/srvfiles
mkdir /tmp/srvfiles/dir
touch /tmp/srvfiles/dir/t
touch /tmp/srvfiles/ct
echo "Some Text" > /tmp/srvfiles/1
echo "Some
Multiline
  Random
 Text

 " > /tmp/srvfiles/a
