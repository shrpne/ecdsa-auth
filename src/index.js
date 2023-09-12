import {toBuffer} from 'ethereumjs-util/dist/bytes.js';
import {keccakFromString} from 'ethereumjs-util/dist/hash.js';
import {publicToAddress} from 'ethereumjs-util/dist/account.js';
import secp256k1 from 'secp256k1';

const {ecdsaSign, ecdsaVerify, publicKeyCreate} = secp256k1;


/**
 * @param {object|string} data
 * @param {string} privateKey
 * @param {boolean} [includePublicKey=true]
 * @return {string} - result consist of 64 byte signature + 1 byte recid + 33 byte compressed public key
 */
export function ecdsaAuthSign(data, privateKey, includePublicKey = true) {
    const privateKeyBuffer = toBuffer(privateKey);
    const dataHash = hashData(data);
    // recid is 0-3 number @see https://ethereum.stackexchange.com/a/118342
    const {signature, recid} = ecdsaSign(dataHash, privateKeyBuffer);

    const publicKey = publicKeyCreate(privateKeyBuffer, true);
    // result consist of 64 byte signature + 1 byte recid + 33 byte compressed public key
    let result = concatTypedList([
        signature,
        [recid],
        includePublicKey ? publicKey : [],
    ]);

    return bufferToString(Buffer.from(result));
}

/**
 * @param {string} authResult - hex string
 * @return {{signature: Buffer, publicKey: Buffer, recid: number}}
 */
export function ecdsaAuthParse(authResult) {
    const signature = toBuffer(authResult).subarray(0, 64);
    const recid = toBuffer(authResult)[64];
    const publicKey = toBuffer(authResult).subarray(65);

    return {signature, recid, publicKey};
}

export function ecdsaAuthVerify(data, authString) {
    const {signature, recid, publicKey} = ecdsaAuthParse(authString);
    const dataHash = hashData(data);
    const isValid = ecdsaVerify(signature, dataHash, publicKey);
    if (isValid) {
        return bufferToString(publicToAddress(publicKey, true));
    } else {
        return false;
    }
}


/**
 * @param {Array<Uint8Array|Array|Buffer>} list
 * @return {Uint8Array}
 */
function concatTypedList(list) {
    const totalLength = list.reduce((acc, value) => acc + value.length, 0);
    let result = new Uint8Array(totalLength);
    let offset = 0;
    for (const array of list) {
        result.set(array, offset);
        offset += array.length;
    }

    return result;
}



/**
 * @param {object|string} data
 * @return {Buffer}
 */
export function hashData(data) {
    data = typeof data === 'string' ? data : JSON.stringify(data)
    return keccakFromString(data);
}

/**
 * @param {Buffer|Uint8Array} buf
 * @return {string}
 */
export function bufferToString(buf) {
    return '0x' + toBuffer(buf).toString('hex');
}
