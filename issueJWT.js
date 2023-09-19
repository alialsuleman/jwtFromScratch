const base64url = require('base64url');
const crypto = require('crypto')
const signatureFunction = crypto.createSign('RSA-SHA256');
const verifyFunction = crypto.createVerify('RSA-SHA256');
const fs = require('fs');

/**
 * ISSUANCE
 */
const headerObj = {
    "alg": "RS256",
    "typ": "JWT"
}
const payloadObj = {
    "sub": "1234567890",
    "name": "John Doe",
    "admin": true,
    "iat": 1516239022
}

const headerObjString = JSON.stringify(headerObj);
const payloadObjString = JSON.stringify(payloadObj);
const base64urlHeader = base64url(headerObjString);
const base64urlPayload = base64url(payloadObjString);
signatureFunction.write(base64urlHeader + '.' + base64urlPayload);
signatureFunction.end();

const PRIV_KEY = fs.readFileSync(' ');
const signatureBase64 = signatureFunction.sign(PRIV_KEY, 'base64');
const signatureBase64Url = base64url.fromBase64(signatureBase64);

console.log(signatureBase64Url);
/**
 * END ISSUANCE
 */


/**
 * VERFICATION
 */
const JWT = ' ';
const jwtParts = JWT.split('.');
const headerInBase64UrlFormat = jwtParts[0];
const payloadInBase64UrlFormat = jwtParts[1];
const signatureInBase64UrlFormat = jwtParts[2];
verifyFunction.write(headerInBase64UrlFormat + '.' + payloadInBase64UrlFormat);
verifyFunction.end();
const jwtSignatureBase64 = base64url.toBase64(signatureInBase64UrlFormat);
const PUB_KEY = fs.readFileSync(' ');
const signatureIsValid = verifyFunction.verify(PUB_KEY, jwtSignatureBase64, 'base64');
console.log(signatureIsValid)
/**
 *   END VERFICATION
 */
