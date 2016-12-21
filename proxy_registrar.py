#!/usr/bin/python3
# -*- coding: utf-8 -*-
import socketserver
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import sys

class ProxyHandler(ContentHandler):
    def __init__(self):
        self.Trunk = []
        self.General = {"server": ["name", "ip", "puerto"],
                        "database": ["path", "passwdpath"],
                        "log": ["path"]}


    def startElement(self, name, attrs):
        """obtencion datos del fichero xml."""
        if name in self.General:
            Value_Box = {}
            for i in self.General[name]:
                Value_Box[i] = attrs.get(i, "")
            General_Slice = {name: Value_Box}
            self.Trunk.append(General_Slice)

class EHand(socketserver.DatagramRequestHandler):
    def handle(self):
        """Recepcion y envio de mensajes."""
        line = self.rfile.read()
        line = line.decode("utf-8")
        print(line)

        self.wfile.write(b"...---...")




if __name__ == "__main__":
    try:
        PR_XML = sys.argv[1]
    except ValueError:
        sys.exit("Usabe: python3 proxy_registrar.py config")

    parser = make_parser()
    handler = ProxyHandler()
    parser.setContentHandler(handler)
    parser.parse(open(PR_XML))

    print(handler.Trunk)

    NAME = handler.Trunk[0]["server"]["name"]
    IP = handler.Trunk[0]["server"]["ip"]
    PORT = handler.Trunk[0]["server"]["puerto"]
    list_line = NAME + " listening at port " + PORT + "..."
    print(list_line)

    serv = socketserver.UDPServer((IP, int(PORT)), EHand)
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print("Finalizado servidor")