'use strict'

var net = require('net'),
    util = require('util'),
    DNS = require('dns'),
    log = function(){},///console.log,
    //log = console.log.bind(console),
    //info = console.info.bind(console),
    info = function(){},///console.log,
    errorLog = console.error.bind(console),
    ///clients = [],
    SOCKS_VERSION5 = 5,
    SOCKS_VERSION4 = 4,
    USERPASS,
    AUTHENTICATION = {
        NOAUTH: 0x00,
        GSSAPI: 0x01,
        USERPASS: 0x02,
        NONE: 0xFF
    },
    REQUEST_CMD = {
        CONNECT: 0x01,
        BIND: 0x02,
        UDP_ASSOCIATE: 0x03
    },
    ATYP = {
        IP_V4: 0x01,
        DNS: 0x03,
        IP_V6: 0x04
    },
    Address = {
        read: function (buffer, offset) {
                  if (buffer[offset] == ATYP.IP_V4) {
                      return util.format('%s.%s.%s.%s', buffer[offset+1], buffer[offset+2], buffer[offset+3], buffer[offset+4]);
                  } else if (buffer[offset] == ATYP.DNS) {
                      return buffer.toString('utf8', offset+2, offset+2+buffer[offset+1]);
                  } else if (buffer[offset] == ATYP.IP_V6) {
                      return buffer.slice(buffer[offset+1], buffer[offset+1+16]);
                  }
              },
        sizeOf: function(buffer, offset) {
                    if (buffer[offset] == ATYP.IP_V4) {
                        return 4;
                    } else if (buffer[offset] == ATYP.DNS) {
                        return buffer[offset+1];
                    } else if (buffer[offset] == ATYP.IP_V6) {
                        return 16;
                    }
                }
    },
    Port = {
        read: function (buffer, offset) {
                  if (buffer[offset] == ATYP.IP_V4) {
                      return buffer.readUInt16BE(8);
                  } else if (buffer[offset] == ATYP.DNS) {
                      return buffer.readUInt16BE(5+buffer[offset+1]);
                  } else if (buffer[offset] == ATYP.IP_V6) {
                      return buffer.readUInt16BE(20);
                  }
              },
    };

function createSocksServer(cb, userpass) {
    // record userpass 
    USERPASS = userpass;
    console.log('userpass:'+JSON.stringify(userpass));

    var socksServer = net.createServer();
    socksServer.on('listening', function() {
        var address = socksServer.address();
        console.log('LISTENING %s:%d', address.address, address.port);
    });
    socksServer.on('connection', function(socket) {
        info('CONNECTED %s:%d', socket.remoteAddress, socket.remotePort);
        initSocksConnection.bind(socket)(cb);
    });
    return socksServer;
}

// socket is available as this
function initSocksConnection(on_accept) {
    this.on('error', function(e) {
        errorLog('%j', e);
    });
    this.handshake = handshake.bind(this);
    this.on_accept = on_accept; // No bind. We want 'this' to be the server, like it would be for net.createServer
    this.once('data', this.handshake);
}

function handshake(chunk) {
    var method_count = 0;

    // SOCKS Version 5 is the only support version
    if (chunk[0] != SOCKS_VERSION5) {
        errorLog('socks5 handshake: wrong socks version: %d', chunk[0]);
        this.end();
        return;
    }
    // Number of authentication methods
    method_count = chunk[1];

    this.auth_methods = [];
    // i starts on 2, since we've read chunk 0 & 1 already
    for (var i=2; i < method_count + 2; i++) {
        this.auth_methods.push(chunk[i]);
    }
    log('Supported auth methods: %j', this.auth_methods);

    var resp = new Buffer(2);
    resp[0] = 0x05;

    // user/pass auth
    if (USERPASS) {
        errorLog('Unsuported authentication method -- disconnecting');
        resp[1] = 0xFF;
        this.end(resp);
    } else
        if (this.auth_methods.indexOf(AUTHENTICATION.NOAUTH) > -1) {
            log('Handing off to handleConnRequest');
            this.handleConnRequest = handleConnRequest.bind(this);
            this.once('data', this.handleConnRequest);
            resp[1] = AUTHENTICATION.NOAUTH;
            this.write(resp);
        } else {
            errorLog('Unsuported authentication method -- disconnecting');
            resp[1] = 0xFF;
            this.end(resp);
        }
}

function handleConnRequest(chunk) {
    var cmd=chunk[1],
        address,
        port,
        offset=3;
    // Wrong version!
    if (chunk[0] !== SOCKS_VERSION5) {
        this.end(new Buffer([0x05, 0x01]));
        errorLog('socks5 handleConnRequest: wrong socks version: %d', chunk[0]);
        return;
    } 
    try {
        address = Address.read(chunk, 3);
	port = Port.read(chunk, 3);
    } catch (e) {
        errorLog('socks5 handleConnRequest: Address.read '+e);
        return;
    }

    log('socks5 Request: type: %d -- to: %s:%d', chunk[1], address, port);

    if (cmd == REQUEST_CMD.CONNECT) {
        this.request = chunk;
        this.on_accept(this, port, address, proxyReady5.bind(this));
    } else {
        this.end(new Buffer([0x05, 0x01]));
        return;
    }
}

function proxyReady5() {
    log('Indicating to the client that the proxy is ready');
    // creating response
    var resp = new Buffer(this.request.length);
    this.request.copy(resp);
    // rewrite response header
    resp[0] = SOCKS_VERSION5;
    resp[1] = 0x00;
    resp[2] = 0x00;
    
    this.write(resp);
    
    log('socks5 Connected to: %s:%d', Address.read(resp, 3), resp.readUInt16BE(resp.length - 2));
}

module.exports = {
    createServer: createSocksServer
};
