# Copyright (C) 2017 Binh Nguyen binh@cs.utah.edu.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/usr/bin/python


class Match(object):

  match_fields = { #all supported match fields. eg, curl -d "match="in_port=1,out_port=2,nw_src=::01""
  "in_port": "*",
  "out_port": "*",
  "nw_src": "*",
  "nw_dst": "*",
  "dl_src": "*",
  "dl_dst": "*"
  }
  
  def get_match_fields(self):
    return match_fields

  def parse_match_fields(self, str):
    tokens = str.split(',')
    for t in tokens:
      key = t.split("=")[0]
      value = t.split("=")[1]
      if key in self.match_fields:
        self.match_fields[key] = value
      else:
        print "Key %s: isn't supported!" % key
    return self.match_fields

  def __init__(self, **kwagrs):
    for key in kwagrs:
      self.match_fields[key] = kwagrs[key]
    

  def print_me(self):
    print "Match_fields -> value":
    for key in self.match_fields:
      print "%s -> %s" % (key, self.match_fields[key])
    