const atob = require('atob');
const asn1js = require('asn1js');
const fs = require('fs');
const pkijs = require('pkijs');
const WebCrypto = require('node-webcrypto-ossl');
const pvutils = require('pvutils')

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



