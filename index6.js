const atob = require('atob');
const btoa = require('btoa');
const asn1js = require('asn1js');
const fs = require('fs');
const pkijs = require('pkijs');
const WebCrypto = require('node-webcrypto-ossl');
const pvutils = require('pvutils')
var ab2str = require('arraybuffer-to-string')
var str2ab = require('string-to-arraybuffer')

//const TextDecoder = require('text-encoder-lite').TextDecoderLite;
const TextEncoder = require('text-encoding');


var jwkToPem = require('jwk-to-pem')

const webcrypto = new WebCrypto();

const pubKeyFromBrowser = '{"crv":"P-256","ext":true,"key_ops":["verify"],"kty":"EC","x":"jKRlAOVYbUXj4heLHHLoi6NKdqY3oJ0bL-B8joT4xzg","y":"RWp90i6SlNsfEEowgnV86wTIRtrbmK7Cn65P1skwE2c"}'
const firmaFromBrowser = 'jNZDaKnR9w/EH5GvJ2T5/qQ/5E9cD/3baZKJf0fhn7QnbYx8iYaXyUXSlfGBE0uHY4pQB3vt11szz2CSprI2HA=='
const messageFromBrowser = 'ODQsMTA0LDEwMSwzMiwxMDEsOTcsMTAzLDEwOCwxMDEsMzIsMTAyLDEwOCwxMDUsMTAxLDExNSwzMiw5NywxMTYsMzIsMTE2LDExOSwxMDUsMTA4LDEwNSwxMDMsMTA0LDExNg=='
const messagePuro='The eagle flies at twilight';
const {
    Certificate,
    CryptoEngine,
    setEngine,
    getCrypto,
    AttributeTypeAndValue,
    BasicConstraints,
    Extension,
    getAlgorithmParameters
} = pkijs;

let certificateBuffer = new ArrayBuffer(0);

const hashAlg = 'SHA-256';
const signAlg = 'ECDSA';

pkijs.setEngine('nodeEngine', webcrypto, new CryptoEngine({
    crypto: webcrypto,
    subtle: webcrypto.subtle,
    name: 'nodeEngine'
}));

const crypto = getCrypto();

const llavePublicaCA_jwk = {
    kty: 'EC',
    crv: 'P-256',
    key_ops: ['verify'],
    x: 'PF0TDvUbuKwIAA4oSjZoFJ0tujW9psn2m-Bib37DNeY',
    y: '-1cIdaj8ezFZyWbbAbwzWQgMK04ERsI65WxKBNx-E4M'
}

const llavePrivadaCA_jwk = {
    kty: 'EC',
    crv: 'P-256',
    key_ops: ['sign'],
    x: 'PF0TDvUbuKwIAA4oSjZoFJ0tujW9psn2m-Bib37DNeY',
    y: '-1cIdaj8ezFZyWbbAbwzWQgMK04ERsI65WxKBNx-E4M',
    d: 'ytC3_EmginsC9mPZd8hDUJLFU4Z7IBKC54sjjAq5tL8'
}

async function init() {
    const algorithm = getAlgorithmParameters(signAlg, "importkey");
    //algorithm.algorithm.namedCurve="P-256";
    console.log("algoritmo:" + JSON.stringify(algorithm))
    if ('hash' in algorithm.algorithm) {
        algorithm.algorithm.hash.name = hashAlg;
    }

    var uint8array = new TextEncoder.TextEncoder().encode(messagePuro);
    
    
    console.log(typeof uint8array)
    

    let testit = str2ab(firmaFromBrowser)
    var keyToUseInVerify = await crypto.importKey("jwk", JSON.parse(pubKeyFromBrowser), algorithm.algorithm, true, algorithm.usages)
    
    console.log(str2ab(firmaFromBrowser))


    console.log(await webcrypto.subtle.verify(
        {
            name: "ECDSA",
            namedCurve: "P-256",
            hash: { name: "SHA-256" },
        },
        keyToUseInVerify,
        str2ab(firmaFromBrowser),
        uint8array));

    //webcrypto.subtle.verify()

}

function base64StringToArrayBuffer(b64str) {
    let byteStr = atob(b64str);

    let bytes = new Uint8Array(byteStr.length);
    for (let i = 0; i < byteStr.length; i++) {
        bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToBase64String(arrayBuffer) {
    var byteArray = new Uint8Array(arrayBuffer)
    var byteString = '';
    for (var i = 0; i < byteArray.byteLength; i++) {
        byteString += String.fromCharCode(byteArray[i]);
    }
    return btoa(byteString);
}



pkijs.setEngine('nodeEngine', webcrypto, new CryptoEngine({
    crypto: webcrypto,
    subtle: webcrypto.subtle,
    name: 'nodeEngine'
}));
init();



