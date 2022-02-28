'use strict';

var tls = require('tls');
var fs = require('fs');

const forge = require('node-forge');

const salt_len = 16;
const iv_len = 16;



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
const PORT = 2626;
const HOST = '127.0.0.1'

// Pass the certs to the server and let it know to process even unauthorized certs.
var options = {
    rejectUnauthorized:false,
    key: fs.readFileSync('certs/ryans-key.pem'),
    cert: fs.readFileSync('certs/ryans-cert.pem'),
   
    
};

var client = tls.connect(PORT, HOST,options,function() {

    // Check if the authorization worked
    if (client.authorized) {
        console.log("Connection authorized by a Certificate Authority.");
    } else {
        console.log("Connection not authorized: " + client.authorizationError)
    }

    // Send a friendly message
    try{
        
        client.write(encrypt("halt"));

    }catch(err){
        console.log(err);
    }
   
});

client.on("data", function(data) {
    console.log(data.toString())
    console.log(decrypt(data));
    console.log('Received: %s [it is %d bytes long]',
        data.toString().replace(/(\n)/gm,""),
        data.length);
        
    client.write(encrypt("hello"));
    // Close the connection after receiving the message
  

});

client.on('close', function() {

    console.log("Connection closed");

});

// When an error ocoures, show it.
client.on('error', function(error) {

    console.error(error);

    // Close the connection after the error occurred.
    client.destroy();

});
