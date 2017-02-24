import re

serverdict = dict()
apachedict = {0: '\tHeader always set Strict-Transport-Security "max-age=10368000; includeSubdomains; preload"',
              1: '\tHeader set X-XSS-Protection "1; mode=block"',
              2: '\tHeader always append X-Frame-Options DENY',
              3: '\tHeader set X-Content-Type-Options nosniff',
              4: '\tHeader set Public-Key-Pins "pin-sha256=\"klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY=\"; '
                 'pin-sha256=\"633lt352PKRXbOwf4xSEa1M517scpD3l5f79xMD9r9Q=\"; max-age=5184000; includeSubDomains; '
                 'report-uri="http://...."'}
anotherdict = {0: '', 1: '', 2: '', 3: '', 4: ''}
serverdict['Apache'] = apachedict


def analyzebasicheadershttprequest(response, typehttp):
    print 'Analisis de cabeceras adicionales (Server, X-Powered-By, Set-Cookie):'
    _basicheadeinfo = 0

    if response.get('server'):
        _basicheadeinfo = 1
        listservers = ['Apache', 'nginx', 'Microsoft-IIS', 'Netscape-Enterprise', 'Sun-ONE-Web-Server']
        valueserver = response.get('server')
        serverinheader = filter(lambda n: n in valueserver, listservers)
        serverfound = ''
        if len(serverinheader) > 0:
            serverfound = serverinheader[0]

        print '-> Server'
        print '\tCabecera recibida: ' + valueserver

        if len(serverfound) is not 0 and serverfound in valueserver:
            extrainfo = 1 if len(str(valueserver).strip()) - len(serverfound) is 0 else 0
            if extrainfo:
                print '\t[!] Esta mostrando el nombre del servidor que usa para alojar su pagina web'
            else:
                print '\t[-] Esta mostrando informacion sensible que puede ser usada en su contra'
        elif 'gws' in valueserver:
            print '\t[+] Su nombre de servidor, se corresponde con los de google'
        else:
            print '\t[+] Su nombre de servidor, no se encuentra entre los conocidos'
    if response.get('x-powered-by'):
        _basicheadeinfo = 1
        print '-> X-Powered-By'
        print '\tCabecera recibida: ' + response.get('x-powered-by')
        print '\tEsta mostrando informacion sensible que puede ser usada en su contra, elimine la cabecera'
        print '\tPara eliminarla, en php.ini modifique el parametro expose_php a off = expose_php = off'
    if response.get('set-cookie'):
        _basicheadeinfo = 1
        valuesetcookie = response.get('set-cookie')
        print '-> Set-Cookie'
        print '\t Cabecera recibida: ' + valuesetcookie
        if 'httponly' in valuesetcookie.lower():
            print '\t[+] HttpOnly: Esta haciendo que las cookies solo sean accesibles por HTTP y no por ' \
                  'otros metodos como js'
        else:
            print '\t[!] HttpOnly: Sus cookies pueden ser accedidas por js (Document.cookie), por lo que ' \
                  'puede ser vulnerable a diferentes tipos de ataques'

        if 'secure' not in valuesetcookie and typehttp:
            print '\t[!] Secure: Esta enviando las cookies en texto plano sin cifrar, si quiere cifrarlas, ' \
                  'active la politica secure'
        elif 'Secure' in valuesetcookie and typehttp:
            print '\t[+] Secure: Esta enviando las cookies a traves de https y de manera cifrada'
        else:
            print '\t[!] Secure: Esta enviando sus cookies en texto plano sin proteger, si esta usando una ' \
                  'conexion https y quiere cifrar la cookie, active la politica secure en Set-Cookie'

    if not _basicheadeinfo:
        print 'No se ha encontrado ninguna cabecera basica activa'


def analyzesecurityheadersfromhttprequest(response, typehttp):
    __dictsecurityheader = dict()
    __dictdisabled = dict()
    _example = 'Ejemplo de configuracion - Apache:'

    if response.get('strict-transport-security'):

        if typehttp:
            policyhsts = dict()
            policyheader = response.get('strict-transport-security')
            hstssplitted = policyheader.split(';')
            patterndetected = True
            patternstring = '="?(\d*)"?'
            header = 'Cabecera recibida: ' + str(policyheader)
            for policy in hstssplitted:
                if 'preload' in policy:
                    policyhsts['preload'] = True
                elif 'includeSubDomains' in policy:
                    policyhsts['includeSubDomains'] = True
                elif 'max-age' in policy:
                    resultpattern = re.search(patternstring, policy.split('max-age')[1]).group(1)
                    if len(resultpattern) is 0:
                        patterndetected = False
                    policyhsts['max-age'] = resultpattern

            # Max-Age
            cadenatime = '[-] Max-Age: Se debe incluir el parametro Max-age con un valor minimo recomendado ' \
                         'para que la cabecera, tenga la minima configuracion basica para funcionar en caso ' \
                         'contrario la cabecera no funcionara correctamente. Un valor recomendado puede ser' \
                         'de 10368000 segundos. Si el sitio indicado, se corresponde con un en fase de pruebas' \
                         ' de configuracion del protocolo HTTPS para detectar algun fallo, ' \
                         'se recomienda usar valores bajos hasta que este todo correctamente configurado.'
            if 'max-age' in policyhsts and patterndetected:
                time = int(policyhsts['max-age'])
                if time is 0:
                    cadenatime = '[!] Max-Age: Estas eliminando la configuracion de la cabecera hsts ' \
                                 'en los navegadores'
                elif time <= 10368000:
                    cadenatime = '[!] Max-Age: Tu valor de Max-Age es muy bajo, ' \
                                 'lo recomendado es 10368000 o mas'
                else:
                    cadenatime = '[+] Max-Age: Tiene un valor adecuado'
            # Preload
            cadenapreload = '[!] Preload: Para evitar ataques MITM contra los clientes antes de que reciban ' \
                            'por primera vez de la cabecera HSTS deberia de incluir su sitio web en la preload' \
                            'list de Chrome. Para ello, visite esta pagina: https://hstspreload.org/'
            if 'preload' in policyhsts:
                cadenapreload = '[+] Preload: Esta indicando que su sitio se encuentra en la preload list y no ' \
                                'podra sufrir ataques MITM usando la vulnerabilidad de la primera conexion ' \
                                'conocida como "Trust On First Use"'
            # Domains
            cadenadomains = '[!] SubDomains: Deberia indicar que la cabecera hsts afecta a los subdominios,' \
                            ' para prevenir que algun subdominio pueda sufrir ataques MITM'
            if 'includeSubDomains' in policyhsts:
                cadenadomains = '[+] SubDomains: Los subdominios se encuentran protegidos por la cabecera hsts'

            __dictsecurityheader['strict-transport-security'] = [header] + sorted([cadenatime, cadenadomains,
                                                                                   cadenapreload])
        else:
            __dictsecurityheader['strict-transport-security'] = ['[-] Cabecera mal configurada, la cabecera hsts no '
                                                                 'puede ser configurada en el protocolo http']
    else:
        _hstsdisabled = 'Para forzar al cliente a utilizar el protocolo https, active la cabecera hsts'
        __dictdisabled['Strict-Transport-Security'] = [_hstsdisabled, _example, serverdict['Apache'][0]]
    if response.get('x-xss-protection'):

        _policyxss = dict()
        xsssplitted = response.get('x-xss-protection').split(';')
        header = 'Cabecera recibida: ' + str(xsssplitted)
        for policy in xsssplitted:
            if 'mode' in policy:
                _policyxss['mode'] = policy.split('=')[1]
            elif 'report' in policy:
                _policyxss['report'] = policy.split('=')[1]
            elif policy.isdigit() and (int(policy) is 0 or int(policy) is 1):
                _policyxss['code'] = int(policy)
            else:
                print policy
        # code
        _cadenacode = '[-] Code: Tiene un valor incorrecto o la cabecera esta mal configurada, ' \
                      'compruebe la configuracion'
        if _policyxss['code'] is 1:
            _cadenacode = '[+] Code: Tiene el filtro XSS activado, el navegador sanara la pagina al ' \
                          'detectar un ataque XSS'
        elif _policyxss['code'] is 0:
            _cadenacode = "[!] Code: Tiene el filtro XSS en los navegadores desactivado, activelo para " \
                          "proteger a los clientes de este tipo de ataques"

        if _policyxss['code'] is 1:
            # mode
            _cadenamode = '[!] Mode: Si desea evitar que se renderice la pagina cuando se detecte un ' \
                          'ataque XSS, active la politica mode=block'
            if 'mode' in _policyxss and 'block' in _policyxss['mode']:
                _cadenamode = '[+] Mode: El navegador evitara renderizar la pagina cuando se detecte un ' \
                              'ataque en vez de sanarla'
            # report
            _cadenareport = '[!] Report: Si desea enviar un reporte del ataque a una URI indicada mediante un mensaje' \
                            ' POST, active esta cabecera indicando la url a la cual hacer la peticion POST'
            if 'report' in _policyxss:
                _cadenareport = '[+] Report: Esta reportando los ataques XSS detectados a la URL indicada'
            __dictsecurityheader['x-xss-protection'] = [header] + sorted([_cadenacode, _cadenamode, _cadenareport])
        else:
            _cadenadisable = '[-] Para configurar el modo en que afectara al detectar el XSS o hacer un reporte, ' \
                             'primero debera de activar la cabecera X-XSS-Protection para forzar a los navegadores ' \
                             'a prevenir estos ataques'
            __dictsecurityheader['x-xss-protection'] = [header] + sorted([_cadenacode, _cadenadisable])
    else:
        _xssdisabled = 'Para forzar al navegador a prevenir la ejecucion de ataques tipo XSS, active la ' \
                       'cabecera X-XSS-Protection'
        __dictdisabled['x-xss-protection'] = [_xssdisabled, _example, serverdict['Apache'][1]]
    if response.get('x-frame-options'):

        _xframesplitted = response.get('x-frame-options')
        header = 'Cabecera recibida: ' + str(_xframesplitted)
        _cadenaframe = '[-] No existe una configuracion valida para la cabecera X-Frame-Options'
        if 'deny' in _xframesplitted:
            _cadenaframe = '[+] Frame: La pagina web no podra ser mostrada en ningun frame, iframe u object'
        elif 'sameorigin' in _xframesplitted:
            _cadenaframe = '[+] Frame: La pagina web podra ser mostrada en un frame, ' \
                           'iframe u object pero del mismo dominio'
        elif 'allow-from' in _xframesplitted:
            if 'http://' or 'https://' in _xframesplitted:
                _cadenaframe = '[!] ALLOW-FROM: Solo podra ser mostrada la pagina web en la uri indicada'
            else:
                _cadenaframe = '[-] ALLOW-FROM: No tiene configurado correctamente el parametro ALLOW-FROM, la ' \
                               'direccion indicada no sigue el estandar para una direccion URI'

        __dictsecurityheader['x-frame-options'] = [header, _cadenaframe]
    else:
        _framedisabled = 'Para prevenir que su pagina pueda ser renderizada en un frame, iframe u object, evitando ' \
                         'ataques de tipo clickjacking, active la cabecera X-Frame-Options'
        __dictdisabled['x-frame-options'] = [_framedisabled, _example, serverdict['Apache'][2]]
    if response.get('x-content-type-options'):
        header = 'Cabecera recibida: ' + str(response.get('x-content-type-options'))
        _cadenaxcontentype = '[-] Su cabecera presenta errores de configuracion, porfavor, revise su configuracion'
        if 'nosniff' in response.get('x-content-type-options'):
            _cadenaxcontentype = '[+] Content: No se esnifara ningun MIME. Se aplicara el tipo MIME indicado ' \
                                 'en Content Type'
        __dictsecurityheader['x-content-type-options'] = [header, _cadenaxcontentype]
    else:
        _contentdisabled = 'Para prevenir que se carguen hojas de estilo o scrips maliciosos camuflados en formatos ' \
                           'incorrectos, como por ejemplo un .zip, active esta cabecera'
        __dictdisabled['x-content-type-options'] = [_contentdisabled, _example, serverdict['Apache'][3]]
    if response.get('public-key-pins') or response.get('public-key-pins-report-only'):
        typeheaderpkp = ['public-key-pins', 'public-key-pins-report-only']
        valueheaderpkp = 0 if response.get('public-key-pins') else 1

        if typehttp:
            _policyhpkp = dict()
            hpkpsplitted = response.get(typeheaderpkp[valueheaderpkp]).split(';')
            header = 'Cabecera recibida: ' + str(hpkpsplitted)
            for policy in hpkpsplitted:
                if 'pin-sha256' in policy:
                    fulllistsha256 = list()
                    if 'pin-sha256' in _policyhpkp:
                        fulllistsha256 = _policyhpkp.get('pin-sha256')
                    fulllistsha256.append(policy.split('pin-sha256=')[1])
                    _policyhpkp['pin-sha256'] = fulllistsha256
                elif 'max-age' in policy:
                    _policyhpkp['max-age'] = policy.split('=')[1]
                elif 'includeSubDomains' in policy:
                    _policyhpkp['includeSubDomains'] = True
                elif 'report-uri' in policy:
                    _policyhpkp['report-uri'] = policy.split('=')[1]

            _cadenapinsha = '[-] Cabecera mal configurada, la politica "pin-sha256" tiene que ser incluida en la ' \
                            'cabecera Public-Key-Pins'
            if 'pin-sha256' in _policyhpkp:
                if len(_policyhpkp.get('pin-sha256')) is 2 or 3:
                    _cadenapinsha = '[+] Pin-sha256: La politica pin-sha256 esta configurada correctamente'
                elif len(_policyhpkp.get('pin-sha256')) is 1:
                    _cadenapinsha = '[!] Pin-sha256: Debe de incluir 2 o 3 pins para una configuracion adecuada'
                elif len(_policyhpkp.get('pin-sha256')) > 3:
                    _cadenapinsha = '[!] Pin-sha256: Deberia de incluir menos pins, ya que una cantidad elevada de ' \
                                    'pins, podria suponer alguna vulnerabilidad en su sistema'
                for pin in _policyhpkp.get('pin-sha256'):
                    if len(pin) is not 46:
                        print pin
            _cadenamaxage = '[-] Cabecera mal configurada, la politica "max-age" tiene que ser incluida en la cabecera' \
                            ' Public-Key-Pins'
            if 'max-age' in _policyhpkp:
                time = int(_policyhpkp.get('max-age'))
                _cadenamaxage = '[+] Max-Age: Tiene un valor de Max-Age adecuado'
                if time is 0:
                    _cadenamaxage = '[!] Max-Age: Estas eliminando la configuracion de la cabecera hpkp ' \
                                    'en los navegadores'
                elif time < 5184000:
                    _cadenamaxage = '[!] Max-Age: Tu valor de Max-Age es muy bajo, ' \
                                    'lo recomendado es 5184000'
                elif time > 5184000:
                    _cadenamaxage = '[+] Max-Age: Tiene un valor elevado, se recomienda bajarlo a 5184000, el ' \
                                    'equivalente a 60 dias'

            _cadenadomainshpkp = '[!] SubDomains: Deberia indicar que la cabecera Public-Key-Pins afecta a los ' \
                                 'subdominios'
            if 'includeSubDomains' in _policyhpkp:
                _cadenadomainshpkp = '[+] SubDomains: Los subdominios se encuentran protegidos por la ' \
                                     'cabecera Public-Key-Pins'

            reporthpkpnotreport = '[!] Si desea enviar un reporte cuando se detecte una validacion de pin fallada, ' \
                                  'active esta cabecera indicando la url a la cual hacer la peticion POST'
            reporthpkpreport = '[-] Cabecera mal configurada, la politica "report-uri" tiene que ser incluida en la ' \
                               'cabecera Public-Key-Pins-Report-Only para hacer el reporte'
            _cadenareporthpkp = reporthpkpnotreport if valueheaderpkp is 0 else reporthpkpreport

            if 'report-uri' in _policyhpkp:
                _cadenareporthpkp = '[+] Esta reportando los fallos en la validacion de pin a la URL indicada'

            __dictsecurityheader[typeheaderpkp[valueheaderpkp]] = [header] + sorted([_cadenapinsha, _cadenamaxage,
                                                                                     _cadenadomainshpkp,
                                                                                     _cadenareporthpkp])
        else:
            __dictdisabled[typeheaderpkp[valueheaderpkp]] = ['[-] Cabecera mal configurada, la cabecera hpkp no '
                                                             'puede ser configurada en el protocolo http']
    else:
        _pkpdisabled = 'Para evitar que los certificados TLS emitidos fraudulentamente puedan utilizarse para ' \
                       'suplantar su sitio web, active la cabecera Public-Key-Pins o la cabecera ' \
                       'Public-Key-Pins-Report-Only si desea permitir la conexion pero avisar del ataque detectado'

        __dictdisabled['public-key-pins'] = [_pkpdisabled, _example, serverdict['Apache'][4]]

    print '\nCabeceras de Seguridad activadas:'
    for header in __dictsecurityheader:
        print '-> ' + header
        for policy in __dictsecurityheader.get(header):
            print '\t' + policy
    print '\nCabeceras de Seguridad desactivadas:'
    for disabled in __dictdisabled:
        print '-> ' + disabled
        for policy in __dictdisabled.get(disabled):
            print '\t' + policy
