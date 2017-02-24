import socket
import ssl


class NoSecureSocket:
    def __init__(self, host, port=80):
        self.host = host
        self.port = port
        self.socket = None
        self.message = str()
        self.headers = dict()
        self.body = str()

    def createsocket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

    def recvsocket(self, sizebuffer=3000):
        if self.socket:
            while True:
                recvmessage = self.socket.recv(sizebuffer)
                if len(recvmessage) is 0:
                    break
                else:
                    self.message += recvmessage
            self.__splitmessage()

    def sendsocket(self, method, path, version, header=None):
        if header is None:
            header = {}
        if self.socket:
            messagetosend = method + ' ' + path + ' ' + version + '\r\n'
            if 'Host' not in header:
                header['Host'] = self.host
            for items in header:
                messagetosend += items + ': ' + header[items] + '\r\n'
            messagetosend += '\r\n'
            self.socket.send(messagetosend)

    def closesocket(self):
        self.socket.close()

    def __splitmessage(self):
        if len(self.message) > 0:
            addheader = True
            allmessagesplitted = self.message.split('\r\n')
            for line in allmessagesplitted:
                if len(line) is 0:
                    addheader = False
                if addheader:
                    if line is not allmessagesplitted[0]:
                        self.headers[line[:line.index(':')].strip().lower()] = \
                            line[line.index(':') + 1:].strip().lower()
                else:
                    self.body = line


class SecureSocket:
    def __init__(self, host, port=443):
        self.host = host
        self.port = port
        self.sslsocket = None
        self.matchhostname = True
        self.message = str()
        self.headers = dict()
        self.body = str()

    def createsslsocket(self, cipher=None):

        try:
            typesocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sslsocket = ssl.wrap_socket(typesocket, ciphers=cipher)
            self.sslsocket.connect((self.host, self.port))
        except:
            pass

    def recvsocket(self, sizebuffer=2000):
        if self.sslsocket:
            """while True:
                recvmessage = self.sslsocket.recv(sizebuffer)
                if len(recvmessage) is 0:
                    break
                else:
                    self.message += recvmessage
            """
            self.message = self.sslsocket.recv(sizebuffer)
            self.__splitmessage()

    def sendsocket(self, method, path, version, header=None):
        if header is None:
            header = {}
        if self.sslsocket:
            messagetosend = method + ' ' + path + ' ' + version + '\r\n'
            if 'Host' not in header:
                header['Host'] = self.host
            for items in header:
                messagetosend += items + ': ' + header[items] + '\r\n'
            messagetosend += '\r\n'
            self.sslsocket.send(messagetosend)

    def __splitmessage(self):
        if len(self.message) > 0:
            addheader = True
            allmessagesplitted = self.message.split('\r\n')
            for line in allmessagesplitted:
                if len(line) is 0:
                    addheader = False
                if addheader:
                    if line is not allmessagesplitted[0]:
                        self.headers[line[:line.index(':')].strip().lower()] = \
                            line[line.index(':') + 1:].strip().lower()
                else:
                    self.body = line

    def closesocket(self):
        if self.sslsocket:
            self.sslsocket.close()