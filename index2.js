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

const Certificate = pkijs.Certificate
const CryptoEngine = pkijs.CryptoEngine

let certificateBuffer = new ArrayBuffer(0);

const hashAlg = 'SHA-256';
const signAlg = 'ECDSA';

async function init() {
	let pemFile = fs.readFileSync('C:/Users/jonat/OneDrive/Documentos/TT/tt_recetasmedicasfirmadigital/backend/api_sam/lib/pki/utils/certkey/certCA1.crt', 'utf8');
	certificateBuffer = convertPemToBinary(pemFile);
	//console.log(certificateBuffer);
	//printCertificate(certificateBuffer);

	pemFile = fs.readFileSync('C:/Users/jonat/OneDrive/Documentos/TT/tt_recetasmedicasfirmadigital/backend/api_sam/lib/pki/utils/certkey/certCA1.crt', 'utf8');
	certificateBuffer = convertPemToBinary(pemFile);
	const asn1 = asn1js.fromBER(certificateBuffer);
	const certificate = new Certificate({ schema: asn1.result });

	//console.log(certificate)
	console.log("xx: ", await certificate.verify())



	const algorithm = pkijs.getAlgorithmParameters(signAlg, 'generatekey');
	//console.log("algoritmo:"+JSON.stringify(algorithm))

	let keyPair = await pkijs.getCrypto().generateKey(algorithm.algorithm, true, algorithm.usages);
	console.log(keyPair)
	let pkcs8 = await pkijs.getCrypto().exportKey("pkcs8", keyPair.privateKey)
	let finalPkcs8=convertBinaryToPem(pkcs8, "PRIVATE KEY")
	console.log("pkcs8 privada:", finalPkcs8)


	let pkcs82 = await pkijs.getCrypto().exportKey("jwk", keyPair.publicKey)
	let finalPkcs82=convertBinaryToPem(pkcs82, "PUBLIC KEY")
	console.log("pkcs8 publica:", jwkToPem(pkcs82));



	try {
		pemFile = fs.readFileSync('C:/Users/jonat/OneDrive/Escritorio/myKey.pem', 'utf8');
		let binaryKey = convertPemToBinary(pemFile);

		let asn1 = asn1js.fromBER(binaryKey);
		console.log("file:", pemFile)

		let keyPair2 = await pkijs.getCrypto().importKey("pkcs8", convertPemToBinary(finalPkcs8), algorithm.algorithm, true, algorithm.usages)
		console.log(keyPair2)
	} catch (error) {
		throw new Error(`Error during key generation: ${error}`);
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



