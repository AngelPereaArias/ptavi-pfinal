#!/usr/bin/python3
# -*- coding: utf-8 -*-

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import sys
import time
import socket
import hashlib


class ClientHandler(ContentHandler):
    def __init__(self):
        self.Trunk = []
        self.General = {"account": ["username", "passwd"],
                        "uaserver": ["ip", "puerto"],
                        "rtpaudio": ["puerto"],
                        "regproxy": ["ip", "puerto"],
                        "log": ["path"],
                        "audio": ["path"]}

    def to_log_txt(self, txt):
        log_xml = open(self.Trunk[4]["log"]["path"], 'a')

        Time = time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time()))
        Log_Record = str(Time) + " " + txt
        Log_Record_Fix = Log_Record.replace("\r\n", " ") + "\r\n"
        if txt == "":
            Log_Record_Fix = "\r\n"
        log_xml.write(Log_Record_Fix)
        log_xml.close()

        #Imprime todo lo incluido al registro LOG /!\TRAZAS/!\
        print(Log_Record_Fix[:-1])

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

    def receive(self):
        try:
            data = my_socket.recv(1024)
        except:
            log_txt = "Error: No server listening at " + proxy_ip
            log_txt += " port " + proxy_port + "\r\n"
            handler.to_log_txt(log_txt)
            sys.exit()

        #Guardamos en el LOG.
        proxy_ip = handler.Trunk[3]["regproxy"]["ip"]
        proxy_port = handler.Trunk[3]["regproxy"]["puerto"]
        data_rcv = data.decode("utf-8")
        log_ip_port = "Received from " + proxy_ip + ":" + proxy_port + ": "
        data_log = log_ip_port + data_rcv
        self.to_log_txt(data_log)

        #Respuesta No Autorizado.
        if data_rcv[:11] == "SIP/2.0 401":
            nonce = data_rcv[data_rcv.find('"')+1:data_rcv.rfind('"')]
            m = hashlib.sha1()
            PASSWORD = self.Trunk[0]["account"]["passwd"]

            m.update(bytes(PASSWORD + nonce, 'utf-8'))
            Dig_resp = m.hexdigest()

            acc_username = self.Trunk[0]["account"]["username"]
            serv_port = self.Trunk[1]["uaserver"]["puerto"]

            #Nuevo Mensaje con info de registro.
            head_register = "REGISTER sip:" + acc_username + ":" + serv_port
            head_register += " SIP/2.0\r\nExpires: " + OPTION
            head_register += '\r\nAuthorization: Digest response="'
            head_register += Dig_resp + '"' + "\r\n\r\n"
            self.send(head_register)

            #Guardamos en el LOG.
            log_msg = "Sent to " + self.Trunk[3]["regproxy"]["ip"] + ":"
            log_msg += self.Trunk[3]["regproxy"]["puerto"]
            log_msg += ": " + head_register
            self.to_log_txt(log_msg)

            #Recibiremos OK.
            self.receive()

        #Recibimos TRYING/RINGING/OK.
        elif data_rcv[:11] == "SIP/2.0 100":
            self.Ack(OPTION)                

    def send(self, message):
        my_socket.send(bytes(message, 'utf-8'))

    def Register(self, option):
        """ Método REGISTER."""
        head_register = "REGISTER sip:" + self.Trunk[0]["account"]["username"]
        head_register += ":" + self.Trunk[1]["uaserver"]["puerto"]
        head_register += " SIP/2.0\r\nExpires: " + option + "\r\n\r\n"
        self.send(head_register)

        #Guardamos en el LOG.
        log_msg = "Sent to " + self.Trunk[3]["regproxy"]["ip"] + ":"
        log_msg += self.Trunk[3]["regproxy"]["puerto"]
        log_msg += " " + head_register
        self.to_log_txt(log_msg)

        #Recibimos respuesta(SIN AUTORIZACIÓN).
        self.receive()

    def Invite(self, option):
        """ Método INVITE."""
        head_invite = "INVITE sip:" + option
        head_invite += " SIP/2.0\r\nContent-Type: application/sdp\r\n\r\n"
        head_invite += "v=0\r\no=" + self.Trunk[0]["account"]["username"]
        head_invite += " " + self.Trunk[1]["uaserver"]["puerto"]
        head_invite += "\r\ns=misesion\r\nt=0\r\nm=audio "
        head_invite += self.Trunk[2]["rtpaudio"]["puerto"] + " RTP\r\n"
        self.send(head_invite)

        #Guardamos en el LOG.
        log_msg = "Sent to " + self.Trunk[3]["regproxy"]["ip"] + ":"
        log_msg += self.Trunk[3]["regproxy"]["puerto"]
        log_msg += " " + head_invite
        self.to_log_txt(log_msg)

        #Recibiremos TRYING/RINGING/OK.
        self.receive()

    def Ack(self, option):
        """ Método ACK."""
        head_ack = "ACK sip:" + option + " SIP/2.0"
        self.send(head_ack)

        #Guardamos en el LOG.
        log_msg = "Sent to " + self.Trunk[3]["regproxy"]["ip"] + ":"
        log_msg += self.Trunk[3]["regproxy"]["puerto"]
        log_msg += " " + head_ack
        self.to_log_txt(log_msg)

    def Bye(self, option):
        """ Método BYE."""
        head_bye = "BYE sip:" + option + " SIP/2.0"
        self.send(head_bye)

        #Guardamos en el LOG.
        log_msg = "Sent to " + self.Trunk[3]["regproxy"]["ip"] + ":"
        log_msg += self.Trunk[3]["regproxy"]["puerto"]
        log_msg += " " + head_bye
        self.to_log_txt(log_msg)

        #Recibiremos OK.
        self.receive()

if __name__ == "__main__":

    try:
        UA1_XML, METHOD, OPTION = sys.argv[1:]
    except ValueError:
        sys.exit("Usage: python3 uaclient.py config metodo opcion")

    parser = make_parser()
    handler = ClientHandler()
    parser.setContentHandler(handler)
    parser.parse(open(UA1_XML))

    handler.to_log_txt("Starting...")

    proxy_ip = handler.Trunk[3]["regproxy"]["ip"]
    proxy_port = handler.Trunk[3]["regproxy"]["puerto"]
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((proxy_ip, int(proxy_port)))

    methods = ["REGISTER", "INVITE", "BYE"]
    if METHOD == methods[0]:
        handler.Register(OPTION)
    elif METHOD == methods[1]:
        handler.Invite(OPTION)
    elif METHOD == methods[2]:
        handler.Bye(OPTION)
    else:
        sys.exit("Usage: python3 uaclient.py config metodo opcion")

    handler.to_log_txt("Finishing.")
    handler.to_log_txt("")
