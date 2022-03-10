'use strict';

var tls = require('net');
var fs = require('fs');
const forge = require('node-forge');
const PORT = 2626;
const HOST = '127.0.0.1'
const salt_len = 16;
const iv_len = 16;
var options = {
    rejectUnauthorized:false,
    key: fs.readFileSync('certs/ryans-key.pem'),
    cert: fs.readFileSync('certs/ryans-cert.pem'),
   
};

const encrypt=(data)=>{

    const salt = forge.random.getBytesSync(16);
    const iv = forge.random.getBytesSync(16);
    
    const key = forge.pkcs5.pbkdf2('my password', salt, 100000, 256/8, 'SHA256');
    
    const cipher = forge.cipher.createCipher('AES-CBC', key);
    
    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(data));
    cipher.finish();
    
    const encrypted = cipher.output.bytes();
    
    console.log({
      iv: forge.util.encode64(iv),
      salt: forge.util.encode64(salt),
      encrypted: forge.util.encode64(encrypted),
      concatenned: forge.util.encode64(salt + iv + encrypted)
    });
    
    return forge.util.encode64(salt + iv + encrypted);
    }
const decrypt=(data)=>{

   

const encrypted = forge.util.binary.base64.decode(data.toString());



const salt = forge.util.createBuffer(encrypted.slice(0, salt_len));
const iv = forge.util.createBuffer(encrypted.slice(0+salt_len, salt_len+iv_len));

const key = forge.pkcs5.pbkdf2('my password', salt.bytes(), 100000, 256/8, 'SHA256');
const decipher = forge.cipher.createDecipher('AES-CBC', key);

decipher.start({iv: iv});
decipher.update(
  forge.util.createBuffer(encrypted.slice(salt_len + iv_len))
);
decipher.finish();

console.log(decipher.output.toString());

}


var server = tls.createServer(function(socket) {

    // Send a friendly message
    socket.write(encrypt("halt"));

    // Print the data that we received
    socket.on('data', function(data) {
        console.log(data);
        decrypt(data);
        // console.log('Received: %s [it is %d bytes long]',
        //     data.toString().replace(/(\n)/gm,""),
        //     data.length);

    });

    // Let us know when the transmission is over
    socket.on('end', function() {

        console.log('EOT (End Of Transmission)');

    });

});

// Start listening on a specific port and address
server.listen(PORT, HOST, function() {

    console.log("I'm listening at %s, on port %s", HOST, PORT);

});

// When an error occurs, show it.
server.on('error', function(error) {

    console.error(error);

    // Close the connection after the error occurred.
    server.destroy();

});