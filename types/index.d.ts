/**
 * @param {object|string} data
 * @param {string} privateKey
 * @param {boolean} [includePublicKey=true]
 * @return {string} - result consist of 64 byte signature + 1 byte recid + 33 byte compressed public key
 */
export function ecdsaAuthSign(data: object | string, privateKey: string, includePublicKey?: boolean): string;
/**
 * @param {string} authResult - hex string
 * @return {{signature: Buffer, publicKey: Buffer, recid: number}}
 */
export function ecdsaAuthParse(authResult: string): {
    signature: Buffer;
    publicKey: Buffer;
    recid: number;
};
/**
 * @param {object|string} data
 * @param {string} authString
 * @return {string|false}
 */
export function ecdsaAuthVerify(data: object | string, authString: string): string | false;
/**
 * @param {object|string} data
 * @return {Buffer}
 */
export function hashData(data: object | string): Buffer;
/**
 * @param {Buffer|Uint8Array} buf
 * @return {string}
 */
export function bufferToString(buf: Buffer | Uint8Array): string;
