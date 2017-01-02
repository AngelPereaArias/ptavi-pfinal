#!/usr/bin/python3
# -*- coding: utf-8 -*-
import socketserver
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import sys
import time
import random
import hashlib
import socket


class ProxyHandler(ContentHandler):
    def __init__(self):
        self.Trunk = []

        self.General = {"server": ["name", "ip", "puerto"],
                        "database": ["path", "passwdpath"],
                        "log": ["path"]}

        self.MSGS = ["SIP/2.0 100 Trying",
                     "SIP/2.0 180 Ring",
                     "SIP/2.0 200 OK",
                     "SIP/2.0 400 Bad Request",
                     "SIP/2.1 401 Unauthorized",
                     "SIP/2.0 404 User Not Found",
                     "SIP/2.0 405 Method Not Allowed"]
        self.NONCE = str(random.getrandbits(100))
        self.DataBase = "Database.txt"
        self.Invite_name = ""

    def startElement(self, name, attrs):
        """obtencion datos del fichero xml."""
        if name in self.General:
            Value_Box = {}
            for i in self.General[name]:
                Value_Box[i] = attrs.get(i, "")
            General_Slice = {name: Value_Box}
            self.Trunk.append(General_Slice)

    def to_log_txt(self, txt):
        log_xml = open(self.Trunk[2]["log"]["path"], 'a')

        Time = time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time()))
        Log_Record = str(Time) + " " + txt
        Log_Record_Fix = Log_Record.replace("\r\n", " ") + "\r\n"
        if txt == "":
            Log_Record_Fix = "\r\n"
        log_xml.write(Log_Record_Fix)
        log_xml.close()

        #Imprime todo lo incluido al registro LOG /!\TRAZAS/!\
        print(Log_Record_Fix[:-1])

    def Add_to_Database(self, txt):
        Found = False

        file = open(self.DataBase, 'r+')
        lines = file.readlines()
        for line in lines:
            if line.split(":")[0] == txt.split(":")[0]:
                Found = True
        if not Found:
            file.write(txt + '\r\n')
        file.close()


class EHand(socketserver.DatagramRequestHandler):
    def Check_passwd(self, user, Dig_resp):
        """Buscamos usuarios en passwords.txt, creamos Dig_resp y comparamos las dos para ver si son igauales"""
        Find = False
        passwd = open(handler.Trunk[1]["database"]["passwdpath"], 'r')
        lines = passwd.readlines()
        for line in lines:
            user_log = line.split(" ")[0]
            if user == user_log:
                passwd_log = line.split(" ")[1]
                m = hashlib.sha1()
                m.update(bytes(passwd_log[:-1] + handler.NONCE, 'utf-8'))
                Dig_resp_log = m.hexdigest()
                if Dig_resp == Dig_resp_log:
                    Find = True
        passwd.close()
        return Find

    def Get_IP_PORT(self, User):
        Database = open(handler.DataBase, 'r')
        lines = Database.readlines()
        for line in lines:
            User_line = line.split(":")[0]
            if User_line == User:
                IP_Line = line.split(":")[1]
                Port_Line = line.split(":")[2]
                IP_PORT = (IP_Line, int(Port_Line))
        Database.close()
        return(IP_PORT)

    def handle(self):
        """Recepcion y envio de mensajes."""

        #Datos recibidos
        line = self.rfile.read()
        line = line.decode("utf-8")
        method = line[:line.find(" ")]

        #Dirección de recepción
        IP = self.client_address[0]
        PORT = self.client_address[1]

        #Guardarlo en PROXY_LOG.TXT
        handler.to_log_txt("Received from " + IP + ":" + str(PORT) + ": " + line)
        #Gestión dependidento del método
        if method == "REGISTER":
            #Mensaje tipo register
            check = line[line.find("Authorization")]
            if check == "0":
                #Mensaje sin datos de Registro
                msg = handler.MSGS[4] + '\r\nWWW Authenticate: Digest nonce="' + handler.NONCE + '"\r\n\r\n'
                self.wfile.write(bytes(msg, 'utf-8'))
                handler.to_log_txt("Sent to " + IP + ":" + str(PORT) + ": " + msg)
            else:
                #Mensaje con datos de Registro
                list_msg = line.split('\r\n')
                user = list_msg[0].split(":")[1]
                Dig_resp = list_msg[2].split('"')[1]
                if self.Check_passwd(user, Dig_resp):
                    #Tupla usuario contraseña encontrado.
                    msg = handler.MSGS[2] + "\r\n\r\n"
                    self.wfile.write(bytes(msg, 'utf-8'))
                    handler.to_log_txt("Sent to " + IP + ":" + str(PORT) + ": " + msg)

                    #Registramos a los usuarios autenticados en nuestra base de datos "Database.txt".
                    new_line = line.split(":")
                    User = new_line[1]
                    Port_user = new_line[2].split(" ")[0]
                    Time = time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time()))
                    Exp_Time = new_line[3].split("\r\n")[0][1:]
                    data_user = User + ":" + IP + ":" + Port_user + ":" + Time + ":" + Exp_Time
                    handler.Add_to_Database(data_user)
                else:
                    #Tupla usuario contraseña no encontrado.
                    msg = handler.MSGS[5] + "\r\n\r\n"
                    self.wfile.write(bytes(msg, 'utf-8'))
                    handler.to_log_txt("Sent to " + IP + ":" + str(PORT) + ": " + msg)
        elif method == "INVITE":
            handler.Invite_name = line.split("o=")[1].split("\r\n")[0]

            To_user = line.split(" ")[1][4:]

            my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_socket.connect(self.Get_IP_PORT(To_user))
            my_socket.send(bytes(line, 'utf-8'))

            data = my_socket.recv(1024)
            data_rcv = data.decode("utf-8")

            self.wfile.write(bytes(data_rcv, 'utf-8'))

        elif method == "ACK":
            To_user = line.split(" ")[1][4:]

            my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_socket.connect(self.Get_IP_PORT(To_user))
            my_socket.send(bytes(line, 'utf-8'))
        elif method == "BYE":
            To_user = line.split(" ")[1][4:]

            my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_socket.connect(self.Get_IP_PORT(To_user))
            my_socket.send(bytes(line, 'utf-8'))

            data = my_socket.recv(1024)
            data_rcv = data.decode("utf-8")

            self.wfile.write(bytes(data_rcv, 'utf-8'))
if __name__ == "__main__":

    try:
        PR_XML = sys.argv[1]
    except ValueError:
        sys.exit("Usabe: python3 proxy_registrar.py config")

    parser = make_parser()
    handler = ProxyHandler()
    parser.setContentHandler(handler)
    parser.parse(open(PR_XML))

    handler.to_log_txt("Starting...")

    NAME = handler.Trunk[0]["server"]["name"]
    IP = handler.Trunk[0]["server"]["ip"]
    PORT = handler.Trunk[0]["server"]["puerto"]

    list_line = "Server " + NAME + " listening at port " + PORT + "..."
    handler.to_log_txt(list_line)

    serv = socketserver.UDPServer((IP, int(PORT)), EHand)

    try:
        serv.serve_forever()

    except KeyboardInterrupt:
        handler.to_log_txt("Finishing.")
        handler.to_log_txt("")
