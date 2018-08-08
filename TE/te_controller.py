# Copyright (C) 2017 Binh Nguyen binh@cs.utah.edu.
# Copyright (C) 2018 Simon Redman sredman@cs.utah.edu
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.app.wsgi import ControllerBase
import logging
from webob import Response
from TE.structs import *
import json

LOG = logging.getLogger('ryu.app.Te_controller')
LOG.setLevel(logging.DEBUG)


class Te_controller(ControllerBase):

    #Graph, static variable
    graph = G()

    def __init__(self, req, link, data, **config):
        super(Te_controller, self).__init__(req, link, data, **config)
    
    #REST API - Return the topology graph, handle OPTIONS request in preflight request 
    def handle_get_topology_OPTIONS(self, req, **_kwargs):
        headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Access-Control-Allow-Headers': 'Origin, Content-Type',
                    'Content-Type':'application/json'}
        return Response(content_type='application/json', headers=headers)


    #REST API - Return the topology graph 
    def get_topology(self, req, **_kwargs):
        graph = Te_controller.graph.translate_to_dict()
        LOG.debug("Graph returned: %s" % (graph))
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST',
            'Access-Control-Allow-Headers': 'Origin, Content-Type',
            'Content-Type':'application/json'
        }
        return Response(content_type='application/json', body=json.dumps(graph), headers=headers)

    def get_topology_netjson(self, req, **_kwargs):
        graph = Te_controller.graph.translate_to_dict_netjson()
        headers = {
           'Access-Control-Allow-Origin': '*',
           'Access-Control-Allow-Methods': 'GET, POST',
           'Access-Control-Allow-Headers': 'Origin, Content-Type',
           'Content-Type':'application/json'
        }
        LOG.debug("Graph returned: %s" % (graph))
        return Response(content_type='application/json', json_body=graph, headers=headers)
