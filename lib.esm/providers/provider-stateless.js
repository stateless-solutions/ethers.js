import * as crypto from "crypto";
import * as sshpk from "sshpk";
import * as nacl from "tweetnacl";
import { FetchRequest } from "../utils/index.js";
import { JsonRpcProvider, } from "./provider-jsonrpc";
export class StatelessProvider extends JsonRpcProvider {
    /**
     * Minimum number of matching attestations required to consider a response valid
     */
    minimumRequiredAttestations;
    /**
     * The expected identities for the attestations
     */
    identities;
    constructor(url, identities, minimumRequiredAttestations, network, options) {
        super(url, network, options);
        this.identities = identities;
        this.minimumRequiredAttestations = minimumRequiredAttestations || 1;
    }
    async _send(payload) {
        const request = this._getConnection();
        request.body = JSON.stringify(payload);
        request.setHeader("content-type", "application/json");
        const response = await request.send();
        response.assertOk();
        let resp = response.bodyJson;
        if (!Array.isArray(resp)) {
            resp = [resp];
        }
        // If it's a batch request, the identity is only included in the first response from the batch
        // We need to construct an ordered list of identities to use for verification
        for (let i = 0; i < resp.length; i++) {
            const result = resp[i];
            if (resp.length > 1 && i == 0 && result.attestations) {
                this.identities = result.attestations.map((attestation) => attestation.identity);
            }
            const isValid = await verifyAttestedJsonRpcResponse(result, this.minimumRequiredAttestations, this.identities);
            if (!isValid) {
                throw new Error(`Request did not meet the attestation threshold of ${this.minimumRequiredAttestations}.`);
            }
            delete result.attestations;
        }
        return resp;
    }
}
async function verifyAttestedJsonRpcResponse(response, minimumRequiredAttestations = 1, identities) {
    let resultHashes = [];
    if (Array.isArray(response.result)) {
        for (const result of response.result) {
            // Our attestation code in the ethereum client adds this field by default,
            // this is not ideal and should be revisited - fields that don't come from provider responses,
            // shouldn't be included by default
            if (!result.timestamp) {
                result.timestamp = "0x0";
            }
            const stringifiedResult = JSON.stringify(result);
            const resultBytes = Buffer.from(stringifiedResult);
            const hash = crypto.createHash("sha256").update(resultBytes).digest("hex");
            resultHashes.push(hash);
        }
    }
    else {
        const resultBytes = Buffer.from(JSON.stringify(response.result));
        const hash = crypto.createHash("sha256").update(resultBytes).digest("hex");
        resultHashes = [hash];
    }
    const validAttestations = [];
    for (const [i, attestation] of response.attestations.entries()) {
        // There's a chance the attestation does not have an identity if it's a batch response
        // In that case, use the provided identities
        if (identities && !attestation.identity) {
            attestation.identity = identities[i];
        }
        // If identities are provided, only use attestations from those identities
        if (identities && !identities.includes(attestation.identity)) {
            continue;
        }
        let sshPublicKey;
        try {
            sshPublicKey = await publicKeyFromIdentity(attestation.identity);
        }
        catch (error) {
            continue;
        }
        const key = sshpk.parseKey(sshPublicKey, "ssh");
        if (key.type !== "ed25519") {
            throw new Error("The provided key is not an ed25519 key");
        }
        // @ts-ignore
        const publicKeyUint8Array = new Uint8Array(key.part.A.data);
        const isValid = verifyAttestation(attestation, publicKeyUint8Array, resultHashes);
        if (!isValid) {
            continue;
        }
        validAttestations.push(attestation);
    }
    return validAttestations.length >= minimumRequiredAttestations;
}
function verifyAttestation(attestation, publicKey, resultHashes) {
    // Calls like `eth_getLogs` return a list of message hashes and signatures,
    // so we need to make sure the logs returned in the response are backed by the minimum amount of required attestations
    if (attestation.msgs && attestation.msgs.length > 0 && attestation.signatures) {
        const isSubset = resultHashes.every(hash => attestation.msgs?.includes(hash));
        if (!isSubset) {
            return false;
        }
        return attestation.msgs.every((msg, index) => {
            if (!attestation.signatures)
                return false;
            return verifySignature(msg, attestation.signatures[index], publicKey, attestation.hashAlgo);
        });
    }
    else if (attestation.msg && attestation.signature) {
        const isHashInResult = resultHashes.includes(attestation.msg);
        return isHashInResult && verifySignature(attestation.msg, attestation.signature, publicKey, attestation.hashAlgo);
    }
    return false;
}
function verifySignature(msgHash, signature, publicKey, hashAlgo) {
    const signatureBytes = Buffer.from(signature, "hex");
    const signatureUint8Array = new Uint8Array(signatureBytes);
    const msgHashBytes = Buffer.from(msgHash, 'hex');
    return nacl.sign.detached.verify(msgHashBytes, signatureUint8Array, publicKey);
}
async function publicKeyFromIdentity(identity) {
    const url = `${identity}/.well-known/stateless-key`;
    const req = new FetchRequest(url);
    const response = await req.send();
    response.assertOk();
    if (response.statusCode !== 200) {
        throw new Error(`Could not fetch public key from ${url}`);
    }
    return response.bodyText;
}
//# sourceMappingURL=provider-stateless.js.map