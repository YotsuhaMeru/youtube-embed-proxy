const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const { URL } = require('url');
require("dotenv").config();

const PROXY_USER = process.env.PROXY_USER;
const PROXY_PASS = process.env.PROXY_PASS;

// authentication function
function authenticate(req, resOrSocket) {
    const authHeader = req.headers['proxy-authorization'];

    let authenticated = false;
    if (authHeader) {
        const auth = Buffer.from(authHeader.split(' ')[1], 'base64').toString();
        const [user, pass] = auth.split(':');
        if (user === PROXY_USER && pass === PROXY_PASS) {
            authenticated = true;
        }
    }

    if (!authenticated) {
        const realm = 'Restricted Proxy';
        if (resOrSocket instanceof http.ServerResponse) {
            resOrSocket.writeHead(407, { 'Proxy-Authenticate': `Basic realm="${realm}"` });
            resOrSocket.end('Proxy Authentication Required');
        } else { // It's a socket from a CONNECT request
            resOrSocket.write(`HTTP/1.1 407 Proxy Authentication Required\r\n`);
            resOrSocket.write(`Proxy-Authenticate: Basic realm="${realm}"\r\n`);
            resOrSocket.write(`Connection: close\r\n`);
            resOrSocket.write(`\r\n`);
            resOrSocket.end();
        }
        return false;
    }

    return true;
}

const CA_KEY_PATH = path.join(__dirname, 'ca-key.pem');
const CA_CERT_PATH = path.join(__dirname, 'ca-cert.pem');

// generate ca cert and key or load if exists
function getOrCreateCA() {    
    if (fs.existsSync(CA_KEY_PATH) && fs.existsSync(CA_CERT_PATH)) {
        return {
            key: fs.readFileSync(CA_KEY_PATH, 'utf8'),
            cert: fs.readFileSync(CA_CERT_PATH, 'utf8'),
        };
    }

    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

    const attrs = [
        { name: 'commonName', value: 'MyProxyCA' },
        { name: 'countryName', value: 'JP' },
        { name: 'organizationName', value: 'MyProxy' },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
        { name: 'basicConstraints', cA: true },
        { name: 'keyUsage', keyCertSign: true, digitalSignature: true, nonRepudiation: true, keyEncipherment: true, dataEncipherment: true },
        { name: 'extKeyUsage', serverAuth: true, clientAuth: true, codeSigning: true, emailProtection: true, timeStamping: true },
        { name: 'subjectKeyIdentifier' },
    ]);

    cert.sign(keys.privateKey, forge.md.sha256.create());

    const ca = {
        key: forge.pki.privateKeyToPem(keys.privateKey),
        cert: forge.pki.certificateToPem(cert),
    };

    fs.writeFileSync(CA_KEY_PATH, ca.key);
    fs.writeFileSync(CA_CERT_PATH, ca.cert);

    return ca;
}

const ca = getOrCreateCA();
const caKey = forge.pki.privateKeyFromPem(ca.key);
const caCert = forge.pki.certificateFromPem(ca.cert);

// generate server cert with hostname
function createServerCertificate(hostname) {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = new Date().getTime().toString();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [
        { name: 'commonName', value: hostname },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(caCert.subject.attributes);
    cert.setExtensions([
        { name: 'basicConstraints', cA: false },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
        { name: 'extKeyUsage', serverAuth: true },
        { name: 'subjectAltName', altNames: [{ type: 2, value: hostname }] },
        { name: 'subjectKeyIdentifier' },
    ]);

    cert.sign(caKey, forge.md.sha256.create());

    return {
        key: forge.pki.privateKeyToPem(keys.privateKey),
        cert: forge.pki.certificateToPem(cert),
    };
}


// HTTP/HTTPS request handler
function requestHandler(req, res, isHttps = false) {
    const protocol = isHttps ? 'https' : 'http';
    const fullUrl = `${protocol}://${req.headers.host}${req.url}`;
    const url = new URL(fullUrl);

    const options = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method: req.method,
        headers: { ...req.headers }, // copy header
    };

    // if url is youtube.com and path is embed, rewrite header to compatible
    if (url.hostname.endsWith('youtube.com') && url.pathname.startsWith("/embed")) {
        options.headers["Host"] = "www.youtube.com";
        options.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0";
        options.headers["Referer"] = process.env.REFERER;
        options.headers["Alt-Used"] = "www.youtube.com";
        options.headers["Sec-Fetch-Dest"] = "iframe";

    }

    const proxyReq = (isHttps ? https : http).request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res, { end: true });
    });

    proxyReq.on('error', (e) => {
        res.writeHead(502);
        res.end('Bad Gateway');
    });
    
    req.pipe(proxyReq, { end: true });
}

// spawn proxy server
const server = http.createServer((req, res) => {
    if (!authenticate(req, res)) {
        return;
    }
    requestHandler(req, res, false);
});

// connect
server.on('connect', (req, clientSocket, head) => {
    if (!authenticate(req, clientSocket)) {
        return;
    }
    const { port, hostname } = new URL(`http://${req.url}`);

    if (hostname.endsWith('youtube.com')) {
        clientSocket.on('error', (e) => {
            return;
        });

        clientSocket.write(
            'HTTP/1.1 200 Connection Established\r\n' +
            'Proxy-agent: Node.js-MITM-Proxy\r\n' +
            '\r\n',
            () => {
                const serverCert = createServerCertificate(hostname);
                const secureSocket = new tls.TLSSocket(clientSocket, {
                    isServer: true,
                    key: serverCert.key,
                    cert: serverCert.cert,
                });

                if (head && head.length) {
                    secureSocket.push(head);
                }

                const mitmServer = new http.Server();
                mitmServer.on('request', (mitmReq, mitmRes) => {
                    mitmReq.headers.host = hostname;
                    requestHandler(mitmReq, mitmRes, true);
                });
                
                mitmServer.emit('connection', secureSocket);

                secureSocket.on('error', (e) => {
                    return;
                });
            }
        );
    } else {
	// normal http tunnel
        const serverSocket = net.connect(port || 443, hostname, () => {
            clientSocket.write(
                'HTTP/1.1 200 Connection Established\r\n' +
                'Proxy-agent: Node.js-Proxy\r\n' +
                '\r\n'
            );
            serverSocket.write(head);
            clientSocket.pipe(serverSocket).pipe(clientSocket);
        });

        serverSocket.on('error', (e) => {
            clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
        });

        clientSocket.on('error', (e) => {
            serverSocket.end();
        });
    }
});

const PORT = 14822;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Proxy server listening on port ${PORT}`);
    console.log('Please configure your browser or system to use this proxy at 127.0.0.1:8080');
});

// f**k all errors
process.on('uncaughtException', (err, origin) => {
    console.log(`Caught exception: ${err}\n` + `Exception origin: ${origin}`)
})

process.on("unhandledRejection", () => {
    console.log('unhandledRejection')
})
