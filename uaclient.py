#!/usr/bin/python3
# -*- coding: utf-8 -*-

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import sys
import time
import socket

class ClientHandler(ContentHandler):
    def __init__(self):
        self.Trunk = []
        self.General = {"account": ["username", "passwd"],
                        "uaserver": ["ip", "puerto"],
                        "rtpaudio": ["puerto"],
                        "regproxy": ["ip", "puerto"],
                        "log": ["path"],
                        "audio": ["path"]}
#        self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
 #       self.my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  #      self.my_socket.connect(("127.0.0.1" , 5991))

    def to_log_txt(self, txt):
        log_xml = open(self.Trunk[4]["log"]["path"], 'a')

        Time = time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time()))
        Log_Record = str(Time) + " " + txt + "\r\n"

        log_xml.write(Log_Record)
        log_xml.close()

        #Imprime todo lo incluido al registro LOG /!\TRAZAS/!\
        print(Log_Record)

    def startElement(self, name, attrs):
        if name in self.General:
            Value_Box = {}
            for i in self.General[name]:
                Value_Box[i] = attrs.get(i, "")
            General_Slice = {name: Value_Box}
            self.Trunk.append(General_Slice)

    def get_tags(self):
        """ Devuelve los datos, con formato, obtenidos de "ua1.xml". """
        doc = ""
        for dict_trunk in self.Trunk:
            for key in dict_trunk:
                doc = doc + key + "\t"
                for k_2 in dict_trunk[key]:
                    doc = doc + k_2 + '="' + dict_trunk[key][k_2] + '"' + "\t"
                doc = doc + "\n"

        return doc
    def send(self, message):
        my_socket.send(bytes(message, 'utf-8'))


    def Register(self, option):
        """ Método REGISTER."""
        head_register = "REGISTER sip:" + self.Trunk[0]["account"]["username"] + ":"
        head_register += self.Trunk[1]["uaserver"]["puerto"] + " SIP/2.0\r\nExpires: " + option
        self.send(head_register)

        log_msg = "Sent to " + self.Trunk[3]["regproxy"]["ip"] + ":" + self.Trunk[3]["regproxy"]["puerto"]
        log_msg += " " + head_register
        self.to_log_txt(log_msg)

        print(head_register)
        #enviar al servidor de registro
        #recibir del servidor de registro

if __name__ == "__main__":
    try:
        UA1_XML, METHOD, OPTION = sys.argv[2:]
    except:
        sys.exit("Usage: python3 uaclient.py config metodo opcion")


    parser = make_parser()
    handler = ClientHandler()
    parser.setContentHandler(handler)
    parser.parse(open("ua1.xml"))

    proxy_ip = handler.Trunk[3]["regproxy"]["ip"]
    proxy_port = handler.Trunk[3]["regproxy"]["puerto"]
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((proxy_ip , int(proxy_port)))


    methods = ["REGISTER", "INVITE", "BYE"]
    if METHOD == methods[0]:
        handler.Register(OPTION)
    elif METHOD == methods[1]:
        print(METHOD)
    elif METHOD == methods[2]:
        print(METHOD)
    else:
        sys.exit("Usage: python3 uaclient.py config metodo opcion")


    #IP = handler.Trunk[1]["uaserver"]["ip"]
    #PORT = handler.Trunk[1]["uaserver"]["puerto"]

    #handler.to_log_txt("Error: No server listening at " + IP + " port " + PORT + "\r\n")