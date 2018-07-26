# Copyright (C) 2017 Binh Nguyen binh@cs.utah.edu.
# Copyright (C) 2018 Simon Redman sredman@cs.utah.edu
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

import logging

LOG = logging.getLogger('ryu.app.OSPF_monitor')
LOG.setLevel(logging.DEBUG)

class OSPF_monitor(object):

    def __init__(self, *args, **kwargs):
        super(OSPF_monitor, self).__init__(*args, **kwargs)

    def ospf_receive(self):
        return
