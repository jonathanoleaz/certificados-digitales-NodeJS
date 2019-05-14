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

const pubKeyFromBrowser='{"crv": "P-256","ext": true,"key_ops": ["verify"],"kty": "EC","x": "2w10ssifoFS3KcPkKSfcOtieRKHl9kmlm0n4P77mzNw","y": "gFRM6yi5fFAhPYso1mhiuO2Mwh6tup-JRA5vvArTh68"}'

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
    const algorithm = getAlgorithmParameters(signAlg, 'generatekey');
    console.log("algoritmo:"+JSON.stringify(algorithm))
    if ('hash' in algorithm.algorithm) {
        algorithm.algorithm.hash.name = hashAlg;
    }

    let privateKey=await pkijs.getCrypto().importKey("jwk", llavePrivadaCA_jwk, algorithm.algorithm, true, algorithm.usages)
	let publicKey=await pkijs.getCrypto().importKey("jwk", llavePublicaCA_jwk, algorithm.algorithm, true, algorithm.usages)

	
	let pemFile = fs.readFileSync('C:/Users/jonat/OneDrive/Escritorio/certCA.pem', 'utf8');
	certificateBuffer = convertPemToBinary(pemFile);
	const asn1 = asn1js.fromBER(certificateBuffer);
	const certificateCA = new Certificate({ schema: asn1.result });

	//console.log(certificate)
    console.log("xx: ", await certificateCA.verify())
    

    createCertificate();
    


	
}

async function createCertificateInternal() {

    const certificate = new Certificate();

    const crypto = getCrypto();
    if (typeof crypto === 'undefined') {
        return Promise.reject('No WebCrypto extension found');
    }

    certificate.version = 2;
    certificate.serialNumber = new asn1js.Integer({ value: 1 });
    certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.6', // Country name
        value: new asn1js.PrintableString({ value: 'MX' })
    }));
    certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.3', // Common name
        value: new asn1js.BmpString({ value: 'SSALUD-COFEPRIS' })
    }));
    certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.6', // Country name
        value: new asn1js.PrintableString({ value: 'MX' })
    }));
    certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: '2.5.4.3', // Common name
        value: new asn1js.BmpString({ value: 'SSALUD-COFEPRIS' })
    }));

    certificate.notBefore.value = new Date(2019, 1, 1);
    certificate.notAfter.value = new Date(2021, 1, 1);

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

    // create a new key pair
    const algorithm = getAlgorithmParameters(signAlg, 'generatekey');
    console.log("algoritmo:"+JSON.stringify(algorithm))
    if ('hash' in algorithm.algorithm) {
        algorithm.algorithm.hash.name = hashAlg;
    }

    let keyPair = null;

    try {
        keyPair = await crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
        //console.log('zz:', keyPair);
        //console.log("jwk: ", await crypto.exportKey("jwk", keyPair.privateKey))
        //console.log("jwk: ", await crypto.exportKey("jwk", keyPair.publicKey))
        //console.log('yy: ', await crypto.exportKey("pkcs8", keyPair.privateKey), 'base64');
        //console.log('yy: ',ab2str(await crypto.exportKey("pkcs8", keyPair.privateKey), 'base64'));

        var atty= await crypto.importKey("jwk", JSON.parse(pubKeyFromBrowser), algorithm.algorithm, true, algorithm.usages)

        console.log("Del browser: ",atty)

        
    } catch (error) {
        throw new Error(`Error during key generation: ${error}`);
    }


    //const publicKey = keyPair.publicKey;
    //const privateKey = keyPair.privateKey;

    let privateKey=await pkijs.getCrypto().importKey("jwk", llavePrivadaCA_jwk, algorithm.algorithm, true, algorithm.usages)
	let publicKey=await pkijs.getCrypto().importKey("jwk", llavePublicaCA_jwk, algorithm.algorithm, true, algorithm.usages)


    // Exporting public key into "subjectPublicKeyInfo" value of certificate

    var atty3= await crypto.importKey("jwk", JSON.parse(pubKeyFromBrowser), algorithm.algorithm, true, algorithm.usages)

    await certificate.subjectPublicKeyInfo.importKey(atty3);
    //console.log(keyPair)


    try {
        // signing final certificate
        await certificate.sign(privateKey, hashAlg);


        let pemFile = fs.readFileSync('C:/Users/jonat/OneDrive/Escritorio/certCA.pem', 'utf8');
	let certificateBuffer = convertPemToBinary(pemFile);
	const asn1 = asn1js.fromBER(certificateBuffer);
	const certificateCA = new Certificate({ schema: asn1.result });

        console.log('Verificación Medico:',await certificate.verify(certificateCA));

    } catch (error) {
        throw new Error(`Error during signing: ${error}`);
    }
    //console.log(keyPair)

    // Encode certificate
    const certificateBuffer = certificate.toSchema(true).toBER(false);

    try {
        const privateKeyBuffer = await crypto.exportKey('pkcs8', privateKey);

        return {
            certificate: certificateBuffer,
            privateKey: privateKeyBuffer
        };

    } catch (error) {
        throw new Error(`Error during exporting of private key: ${error}`);
    }
}

async function createCertificate() {

    const { certificate, privateKey } = await createCertificateInternal();

    const certificateString =
        String.fromCharCode.apply(null, new Uint8Array(certificate));

    let resultString = '-----BEGIN CERTIFICATE-----\r\n';
    resultString = `${resultString}${formatPEM(btoa(certificateString))}`;
    resultString = `${resultString}\r\n-----END CERTIFICATE-----\r\n`;

    console.log('Certificate created successfully!');

    const privateKeyString = String.fromCharCode.apply(null, new Uint8Array(privateKey));

    resultString = `${resultString}\r\n-----BEGIN PRIVATE KEY-----\r\n`;
    resultString = `${resultString}${formatPEM(btoa(privateKeyString))}`;
    resultString = `${resultString}\r\n-----END PRIVATE KEY-----\r\n`;

    console.log(resultString);

    console.log('Private key exported successfully!');
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


function formatPEM(pemString) {
    /// <summary>Format string in order to have each line with length equal to 63</summary>
    /// <param name="pemString" type="String">String to format</param>

    const stringLength = pemString.length;
    let resultString = '';

    for (let i = 0, count = 0; i < stringLength; i++ , count++) {
        if (count > 63) {
            resultString = `${resultString}\r\n`;
            count = 0;
        }

        resultString = `${resultString}${pemString[i]}`;
    }

    return resultString;
}


pkijs.setEngine('nodeEngine', webcrypto, new CryptoEngine({
	crypto: webcrypto,
	subtle: webcrypto.subtle,
	name: 'nodeEngine'
}));
init();



