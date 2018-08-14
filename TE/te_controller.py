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
import ipaddress
import logging
from netdiff import NetJsonParser
import networkx
from webob import Response

LOG = logging.getLogger('ryu.app.Te_controller')
LOG.setLevel(logging.DEBUG)


class Te_controller(ControllerBase):
    graph = NetJsonParser(data={"type": "NetworkGraph",
                                "protocol": "static",
                                "version": None,
                                "metric": None,
                                "nodes": [],
                                "links": []})

    def __init__(self, req, link, data, **config):
        super(Te_controller, self).__init__(req, link, data, **config)
        self.data = data

    def netjson_import(self, req, **kwargs):
        incoming_json = req.body.decode(req.charset)
        importing_graph = NetJsonParser(incoming_json)
        # ASSUMPTION WARNING
        # I have conveniently used each node's IP address as its OSPF ID. That means, for me, it is
        # safe to convert the incoming labels back to dotted-quad form
        mapping = {}
        for id in importing_graph.graph.nodes:
            dotted_quad = ipaddress.IPv4Address(id)
            mapping[id] = str(dotted_quad)
        importing_graph.graph = networkx.relabel_nodes(importing_graph.graph, mapping)

        Te_controller.graph = importing_graph
        return Response(status=200, body="Yay")
    
    #REST API - Return the topology graph, handle OPTIONS request in preflight request 
    def handle_get_topology_OPTIONS(self, req, **_kwargs):
        headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Access-Control-Allow-Headers': 'Origin, Content-Type',
                    'Content-Type':'application/json'}
        return Response(content_type='application/json', headers=headers)

    def get_topology_netjson(self, req, **_kwargs):
        headers = {
            'Access-Control-Allow-Origin': '*', # Anybody may request this resource
            'Access-Control-Allow-Methods': 'GET',
            'Access-Control-Allow-Headers': 'Origin, Content-Type',
        }
        return Response(content_type='application/json',
                        json_body=Te_controller.graph.json(dict=True),
                        headers=headers,)
