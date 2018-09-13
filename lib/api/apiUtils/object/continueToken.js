const crypto = require('crypto');

const ALGORITHM = 'aes-256-ctr';
// use empty string as password because goal is to obfuscate, not encrypt
const PASSWORD = '';

/**
 * generateToken - generates obfuscated continue token from object keyName
 * @param {String} keyName - name of key to obfuscate
 * @return {String} - obfuscated continue token
 */
function generateToken(keyName) {
    if (keyName === '' || keyName === undefined) {
        return undefined;
    }
    const cipher = crypto.createCipher(ALGORITHM, PASSWORD);
    let token = cipher.update(keyName, 'utf8', 'hex');
    token += cipher.final('hex');
    return token;
}

/**
 * decryptToken - decrypts object keyName from obfuscated continue token
 * @param {String} token - obfuscated continue token
 * @return {String} - object keyName
 */
function decryptToken(token) {
    if (token === '' || token === undefined) {
        return undefined;
    }
    const decipher = crypto.createDecipher(ALGORITHM, PASSWORD);
    let keyName = decipher.update(token, 'hex', 'utf8');
    keyName += decipher.final('utf8');
    return keyName;
}

module.exports = {
    generateToken,
    decryptToken,
};
