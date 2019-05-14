const atob = require('atob');
const btoa = require('btoa');
const asn1js = require('asn1js');
const fs = require('fs');
const pkijs = require('pkijs');
const WebCrypto = require('node-webcrypto-ossl');
const pvutils = require('pvutils')
var ab2str = require('arraybuffer-to-string')

var jwkToPem = require('jwk-to-pem')

const webcrypto = new WebCrypto();

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

    const crypto = getCrypto();
    if (typeof crypto === 'undefined') {
        return Promise.reject('No WebCrypto extension found');
    }
	

	const algorithm = pkijs.getAlgorithmParameters(signAlg, 'generatekey');
	//console.log("algoritmo:"+JSON.stringify(algorithm))

	
	let keyPair = await pkijs.getCrypto().generateKey(algorithm.algorithm, true, algorithm.usages);
	

	let privateKey=await pkijs.getCrypto().importKey("jwk", llavePrivadaCA_jwk, algorithm.algorithm, true, algorithm.usages)
	let publicKey=await pkijs.getCrypto().importKey("jwk", llavePublicaCA_jwk, algorithm.algorithm, true, algorithm.usages)

	console.log("Private final: ",privateKey)
	console.log("Public final: ",publicKey)
    
    const certificate = new Certificate();

    certificate.version = 2;
    certificate.serialNumber = new asn1js.Integer({ value: 1 });
    certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.6', // Country name
        value: new asn1js.PrintableString({ value: 'RU' })
    }));
    certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.3', // Common name
        value: new asn1js.BmpString({ value: 'Test' })
    }));
    certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.6', // Country name
        value: new asn1js.PrintableString({ value: 'RU' })
    }));
    certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.3', // Common name
        value: new asn1js.BmpString({ value: 'Test' })
    }));

    certificate.notBefore.value = new Date(2016, 1, 1);
    certificate.notAfter.value = new Date(2019, 1, 1);

    // Extensions are not a part of certificate by default, it's an optional array
    certificate.extensions = [];

    const basicConstr = new BasicConstraints({
        cA: true,
        pathLenConstraint: 3
    });

    certificate.extensions.push(new Extension({
        extnID: '2.5.29.19',
        critical: true,
        extnValue: basicConstr.toSchema().toBER(false),
        parsedValue: basicConstr // Parsed value for well-known extensions
    }));

    const bitArray = new ArrayBuffer(1);
    const bitView = new Uint8Array(bitArray);

    // tslint:disable-next-line:no-bitwise
    bitView[0] = bitView[0] | 0x02; // Key usage "cRLSign" flag
    // tslint:disable-next-line:no-bitwise
    bitView[0] = bitView[0] | 0x04; // Key usage "keyCertSign" flag

    const keyUsage = new asn1js.BitString({ valueHex: bitArray });

    certificate.extensions.push(new Extension({
        extnID: '2.5.29.15',
        critical: false,
        extnValue: keyUsage.toBER(false),
        parsedValue: keyUsage // Parsed value for well-known extensions
    }));


    try {
        // signing final certificate
        await certificate.sign(privateKey, hashAlg);
        console.log(certificate)

        console.log('SEPT:',await certificate.verify());

    } catch (error) {
        throw new Error(`Error during signing: ${error}`);
    }
}

function convertPemToBinary(pem) {
	var lines = pem.split('\n');
	var encoded = '';
	for (var i = 0; i < lines.length; i++) {
		if (lines[i].trim().length > 0 &&
			lines[i].indexOf('-BEGIN RSA PRIVATE KEY-') < 0 &&
			lines[i].indexOf('-BEGIN RSA PUBLIC KEY-') < 0 &&
			lines[i].indexOf('-BEGIN PUBLIC KEY-') < 0 &&
			lines[i].indexOf('-BEGIN CERTIFICATE-') < 0 &&
			lines[i].indexOf('-BEGIN PRIVATE KEY-') < 0 &&
			lines[i].indexOf('-END PRIVATE KEY-') < 0 &&
			lines[i].indexOf('-END CERTIFICATE-') < 0 &&
			lines[i].indexOf('-END PUBLIC KEY-') < 0 &&
			lines[i].indexOf('-END RSA PRIVATE KEY-') < 0 &&
			lines[i].indexOf('-END RSA PUBLIC KEY-') < 0) {
			encoded += lines[i].trim();
		}
	}
	return base64StringToArrayBuffer(encoded);
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

function convertBinaryToPem(binaryData, label) {
	var base64Cert = arrayBufferToBase64String(binaryData);
	var pemCert = "-----BEGIN " + label + "-----\r\n";
	var nextIndex = 0;
	var lineLength;
	while (nextIndex < base64Cert.length) {
		if (nextIndex + 64 <= base64Cert.length) {
			pemCert += base64Cert.substr(nextIndex, 64) + "\r\n";
		} else {
			pemCert += base64Cert.substr(nextIndex) + "\r\n";
		}
		nextIndex += 64;
	}
	pemCert += "-----END " + label + "-----\r\n";
	return pemCert;
}

function printCertificate(certificateBuffer) {
	let asn1 = asn1js.fromBER(certificateBuffer);
	if (asn1.offset === (-1)) {
		console.log("Can not parse binary data");
	}

	const certificate = new Certificate({ schema: asn1.result });
	console.log(certificate);
	console.log('Certificate Serial Number');
	console.log(pvutils.bufferToHexCodes(certificate.serialNumber.valueBlock.valueHex));
	console.log('Certificate Issuance');
	console.log(certificate.notBefore.value.toString());
	console.log('Certificate Expiry');
	console.log(certificate.notAfter.value.toString());
	console.log(certificate.issuer);
}


pkijs.setEngine('nodeEngine', webcrypto, new CryptoEngine({
	crypto: webcrypto,
	subtle: webcrypto.subtle,
	name: 'nodeEngine'
}));
init();



