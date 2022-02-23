import { base64url } from 'rfc4648';
import fetch from 'node-fetch';
/**
 * Custom Error extension.
 */
class JwtError extends Error {
    #body;
    #statusCode;
    constructor(statusCode, body) {
        super(
            `Salesforce JWT Token flow encountered an error with status code ${statusCode.toString()}`
        );
        Object.setPrototypeOf(this, JwtError.prototype);
        this.statusCode = statusCode;
        this.body = body;
    }
}

export default class SalesforceJWT {
    #iss;
    #sub;
    #aud;
    #privateKey;

    #GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    constructor(options) {
        this.#validateOptions(options);
        this.#iss = options.iss;
        this.#sub = options.sub;
        this.#aud = options.aud;
        this.#privateKey = options.privateKey;
    }

    get #token() {
        const existingString = this.#generatePayload();
        const sign = crypto.createSign('RSA-SHA256');

        sign.update(existingString);
        sign.end();

        return (
            existingString +
            '.' +
            base64url.stringify(sign.sign(this.#privateKey))
        );
    }

    get #postUrl() {
        return this.#aud + '/services/oauth2/token';
    }

    #generatePayload() {
        const header = { alg: 'RS256' };
        const claimsSet = {
            iss: this.#iss,
            sub: this.#sub,
            aud: this.#aud,
            exp: Math.floor(Date.now() / 1000) + 60 * 5
        };
        const encodedJWTHeader = base64url.stringify(JSON.stringify(header));
        const encodedJWTClaimsSet = base64url.stringify(
            JSON.stringify(claimsSet)
        );
        const existingString = encodedJWTHeader + '.' + encodedJWTClaimsSet;

        return existingString;
    }

    #validateOptions(options) {
        if (typeof options !== 'object') throw new Error('Missing parameters');

        const requiredProperties = ['iss', 'sub', 'aud', 'privateKey'];

        for (const property of requiredProperties) {
            if (
                !Object.prototype.hasOwnProperty.call(options, property) ||
                !options[property]
            ) {
                throw new Error('Missing required property ' + property);
            }
        }
    }

    async getToken() {
        const formData = new URLSearchParams();
        formData.append('grant_type', this.#GRANT_TYPE);
        formData.append('assertion', this.#token);
        const response = await fetch(this.#postUrl, {
            method: 'post',
            body: formData
        });

        if (response.ok) {
            return response.body;
        } else {
            throw new JwtError(body);
        }
    }

    static async getToken(options) {
        return await new SalesforceJwt(options).getToken();
    }
}
