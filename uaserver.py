#!/usr/bin/python3
# -*- coding: utf-8 -*-
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import socketserver
import sys
import time
import socket
import hashlib
import os


class ServerHandler(ContentHandler):
    def __init__(self):
        self.Trunk = []
        self.General = {"account": ["username", "passwd"],
                        "uaserver": ["ip", "puerto"],
                        "rtpaudio": ["puerto"],
                        "regproxy": ["ip", "puerto"],
                        "log": ["path"],
                        "audio": ["path"]}

        self.MSGS = ["SIP/2.0 100 Trying",
                     "SIP/2.0 180 Ring",
                     "SIP/2.0 200 OK",
                     "SIP/2.0 400 Bad Request",
                     "SIP/2.1 401 Unauthorized",
                     "SIP/2.0 404 User Not Found",
                     "SIP/2.0 405 Method Not Allowed"]
        self.RTP_Port = ""

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

    def receive(self):
        try:
            data = my_socket.recv(1024)
        except:
            log_txt = "Error: No server listening at " + proxy_ip
            log_txt += " port " + proxy_port + "\r\n"
            handler.to_log_txt(log_txt)
            sys.exit()

        data_rcv = data.decode("utf-8")

        proxy_ip = handler.Trunk[3]["regproxy"]["ip"]
        proxy_port = handler.Trunk[3]["regproxy"]["puerto"]
        data_rcv = data.decode("utf-8")
        log_ip_port = "Received from " + proxy_ip + ":" + proxy_port + ": "
        data_log = log_ip_port + data_rcv
        self.to_log_txt(data_log)

        if data_rcv[:11] == "SIP/2.0 401":
            nonce = data_rcv[data_rcv.find('"')+1:data_rcv.rfind('"')]
            m = hashlib.sha1()
            PASSWORD = self.Trunk[0]["account"]["passwd"]

            m.update(bytes(PASSWORD + nonce, 'utf-8'))
            Dig_resp = m.hexdigest()

            USERNAME = self.Trunk[0]["account"]["username"]
            USER_PORT = self.Trunk[1]["uaserver"]["puerto"]
            head_register = "REGISTER sip:" + USERNAME + ":"
            head_register += USER_PORT + " SIP/2.0\r\nExpires: " + "0"
            head_register += '\r\nAuthorization: Digest response="'
            head_register += Dig_resp + '"' + "\r\n\r\n"
            self.send(head_register)

            log_msg = "Sent to " + self.Trunk[3]["regproxy"]["ip"] + ":"
            log_msg += self.Trunk[3]["regproxy"]["puerto"] + ": "
            log_msg += head_register
            self.to_log_txt(log_msg)

            self.receive()

    def send(self, message):
        my_socket.send(bytes(message, 'utf-8'))

    def Register(self):
        """ Método REGISTER."""
        head_register = "REGISTER sip:" + self.Trunk[0]["account"]["username"]
        head_register += ":" + self.Trunk[1]["uaserver"]["puerto"]
        head_register += " SIP/2.0\r\nExpires: " + "0" + "\r\n\r\n"
        self.send(head_register)

        log_msg = "Sent to " + self.Trunk[3]["regproxy"]["ip"] + ":"
        log_msg += self.Trunk[3]["regproxy"]["puerto"]
        log_msg += ": " + head_register
        self.to_log_txt(log_msg)

        self.receive()


class EHand(socketserver.DatagramRequestHandler):
    """Echo server class."""

    def handle(self):
        """Recepcion y envio de mensajes."""

        #Datos recibidos
        line = self.rfile.read()
        line = line.decode("utf-8")
        IP = self.client_address[0]
        PORT = self.client_address[1]
        method = line[:line.find(" ")]

        #Guardarlo en PROXY_LOG.TXT
        log_txt = "Received from " + IP + ":" + str(PORT) + ": " + line
        handler.to_log_txt(log_txt)
        METHODS = ["INVITE", "BYE", "ACK"]

        if method == "INVITE":
            handler.RTP_Port = line.split("m=audio ")[1][:-5]

            head_invite = handler.MSGS[0] + "\r\n\r\n"
            head_invite += handler.MSGS[1] + "\r\n\r\n"
            head_invite += handler.MSGS[2] + "\r\n\r\n"
            head_invite += "Content-Type: application/sdp\r\n\r\n\r\nv=0"
            head_invite += "\r\no=" + handler.Trunk[0]["account"]["username"]
            head_invite += "\r\ns=misesion\r\nt=0\r\nm=audio "
            head_invite += handler.Trunk[2]["rtpaudio"]["puerto"] + " RTP\r\n"
            #handler.send(head_invite)
            self.wfile.write(bytes(head_invite, 'utf-8'))

            log_msg = "Sent to " + handler.Trunk[3]["regproxy"]["ip"] + ":"
            log_msg += handler.Trunk[3]["regproxy"]["puerto"]
            log_msg += ": " + head_invite
            handler.to_log_txt(log_msg)
        elif method == "ACK":
            receptor_IP = "127.0.0.1"
            receptor_Puerto = handler.RTP_Port
            fichero_audio = handler.Trunk[5]["audio"]["path"]
            aEjec = "./mp32rtp -i " + receptor_IP + " -p " + receptor_Puerto
            aEjec += " < " + fichero_audio

            os.system(aEjec)
        elif method == "BYE":
            head_ok = handler.MSGS[2] + "\r\n\r\n"
            self.wfile.write(bytes(head_ok, 'utf-8'))

            log_msg = "Sent to " + handler.Trunk[3]["regproxy"]["ip"] + ":"
            log_msg += handler.Trunk[3]["regproxy"]["puerto"] + ": " + head_ok
            handler.to_log_txt(log_msg)

        elif method not in METHODS:

            head_MNA = handler.MSGS[6] + "\r\n\r\n"
            self.wfile.write(bytes(head_MNA, 'utf-8'))

            log_msg = "Sent to " + handler.Trunk[3]["regproxy"]["ip"] + ":"
            log_msg += handler.Trunk[3]["regproxy"]["puerto"] + ": " + head_MNA
            handler.to_log_txt(log_msg)

if __name__ == "__main__":
    try:
        UA2_XML = sys.argv[1]
    except:
        sys.exit("Usage: python3 uaserver.py config")

    print("Listening...")

    parser = make_parser()
    handler = ServerHandler()
    parser.setContentHandler(handler)
    parser.parse(open(UA2_XML))

    try:
        IP = handler.Trunk[1]["uaserver"]["ip"]
        PORT = int(handler.Trunk[1]["uaserver"]["puerto"])
        serv = socketserver.UDPServer((IP, PORT), EHand)
    except:
        sys.exit("Usage: python3 server.py.py IP Port cancion.mp3")

    handler.to_log_txt("Starting...")

    proxy_ip = handler.Trunk[3]["regproxy"]["ip"]
    proxy_port = handler.Trunk[3]["regproxy"]["puerto"]
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((proxy_ip, int(proxy_port)))

    handler.Register()
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        handler.to_log_txt("Finishing.")
        handler.to_log_txt("")
