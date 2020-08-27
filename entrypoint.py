import os, random, string, sys, datetime

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.filesystems import UnixFilesystem

from OpenSSL import crypto

length = 8
chars = string.ascii_letters + string.digits
random.seed = (os.urandom(1024))

FTP_ROOT = '/home'
USER = os.getenv('USER', 'user')
IP = os.getenv('IP')
PASSWORD = os.getenv('PASSWORD', ''.join(random.choice(chars) for i in range(length)))
PORT = 21
PASSIVE_PORTS = '3000-3010'
ANONYMOUS = os.getenv('ANONYMOUS', False)

#Variables
TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA
now = datetime.datetime.now()
d = now.date()

#Pull these out of scope
cn = os.getenv("DOMAIN")
output = os.getcwd()
key = crypto.PKey()

keypath = output + "/" + cn + '-' + str(d) + '.key'
csrpath = output + "/" + cn + '-' + str(d) + '.csr'
crtpath = output + "/" + cn + '-' + str(d) + '.crt'

def generatekey():
    print("Generating Key Please standby")
    key.generate_key(TYPE_RSA, 4096)
    f = open(keypath, "w")
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    f.close()

#Generate CSR
def generatecsr():
    c = 'US'
    st = 'California'
    l = 'Berkley'
    o = 'CQB'
    ou = 'Network Operations'

    req = crypto.X509Req()
    req.get_subject().CN = cn
    req.get_subject().C = c
    req.get_subject().ST = st
    req.get_subject().L = l
    req.get_subject().O = o
    req.get_subject().OU = ou
    req.set_pubkey(key)
    req.sign(key, "sha256")

    f = open(csrpath, "w")
    f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
    f.close()
    print("Success")

    #Generate the certificate
    cert = crypto.X509()
    cert.get_subject().CN = cn
    cert.get_subject().C = c
    cert.get_subject().ST = st
    cert.get_subject().L = l
    cert.get_subject().O = o
    cert.get_subject().OU = ou
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    f = open(crtpath, "w")
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    f.close()
    print "CRT Stored Here :" + crtpath


def main():
    user_dir = os.path.join(FTP_ROOT, USER)
    if not os.path.isdir(user_dir):
        os.mkdir(user_dir)
    authorizer = DummyAuthorizer()
    authorizer.add_user(USER, PASSWORD, user_dir, perm="elradfmw")

    # Generate self-sign certificat
    generatekey()
    generatecsr()
    print "Key Stored Here :" + keypath
    print "CSR Stored Here :" + csrpath

    handler = TLS_FTPHandler
    handler.certfile = crtpath
    handler.keyfile = keypath

    handler.authorizer = authorizer
    handler.masquerade_address = IP

    handler.tls_control_required = True
    handler.tls_data_required = True

    handler.permit_foreign_addresses = True

    passive_ports = map(int, PASSIVE_PORTS.split('-'))
    handler.passive_ports = range(passive_ports[0], passive_ports[1])

    print('SERVER SETTINGS')
    print('---------------')
    print "FTP User: ",USER
    print "FTP Password: ",PASSWORD
    server = FTPServer(('', PORT), handler)
    server.serve_forever()
    
if __name__ == '__main__':
    main()
