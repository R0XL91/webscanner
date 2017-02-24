from urlparse import urlparse
import sys
import analyzeheaders
from socketsfactory import *

_lastlocation = str()
httpsport = [443]
httpport = [80]


def _createobjtoconnecthost(_host, _port, _path):
    global _lastlocation
    _method = 'GET'
    _httpversion = 'HTTP/1.1'
    headerrespsocket = dict
    typeheader = 1

    socketcreated = None
    if 'https' in _host or _port in httpsport:
        typeheader = 1
        socketcreated = SecureSocket(_host)
        socketcreated.createsslsocket()
    elif 'http' in _host or _port is 80:
        typeheader = 0
        socketcreated = NoSecureSocket(_host)
        socketcreated.createsocket()

    if socketcreated:
        socketcreated.sendsocket(_method, _path, _httpversion)
        socketcreated.recvsocket()
        socketcreated.closesocket()
        headerrespsocket = socketcreated.headers

    if headerrespsocket.get('location'):
        _newurl = urlparse(headerrespsocket.get('location'))
        _lenurlbase = len(_newurl.scheme + '://' + _newurl.netloc)
        _newpath = headerrespsocket.get('location')[_lenurlbase:]
        if _lastlocation != _newpath:
            _lastlocation = _newpath
            _port = 443 if 'https' in _newurl.scheme else 80
            _createobjtoconnecthost(_host, _port, _newpath)
        else:
            print 'No se puede acceder al destino final'
            sys.exit(0)
    else:
        _analyzesecureheaders(headerrespsocket, typeheader)


def _analyzesecureheaders(response, typeheader):
    analyzeheaders.analyzebasicheadershttprequest(response, typeheader)
    analyzeheaders.analyzesecurityheadersfromhttprequest(response, typeheader)


def main(host, port, path):
    _createobjtoconnecthost(host, int(port), path)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print 'Usa el formato: python webhandler.py host port path'
        sys.exit(0)
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
