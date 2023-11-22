"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StatelessProvider = void 0;
const tslib_1 = require("tslib");
const crypto = tslib_1.__importStar(require("crypto"));
const sshpk = tslib_1.__importStar(require("sshpk"));
const nacl = tslib_1.__importStar(require("tweetnacl"));
const index_js_1 = require("../utils/index.js");
const provider_jsonrpc_1 = require("./provider-jsonrpc");
class StatelessProvider extends provider_jsonrpc_1.JsonRpcProvider {
    /**
     * Minimum number of matching attestations required to consider a response valid
     */
    minimumRequiredAttestations;
    constructor(url, network, options, minimumRequiredAttestations) {
        super(url, network, options);
        this.minimumRequiredAttestations = minimumRequiredAttestations || 1;
    }
    async _send(payload) {
        // Configure a POST connection for the requested method
        const request = this._getConnection();
        request.body = JSON.stringify(payload);
        request.setHeader("content-type", "application/json");
        const response = await request.send();
        response.assertOk();
        let resp = response.bodyJson;
        if (!Array.isArray(resp)) {
            resp = [resp];
        }
        let identities;
        // If it's a batch request, the identity is only included in the first response from the batch
        // We need to construct an ordered list of identities to use for verification
        for (let i = 0; i < resp.length; i++) {
            const result = resp[i];
            if (resp.length > 1 && i == 0 && result.attestations) {
                identities = result.attestations.map((attestation) => attestation.identity);
            }
            const isValid = await verifyAttestedJsonRpcResponse(result, this.minimumRequiredAttestations, identities);
            if (!isValid) {
                console.log("Failed verification for request:", payload);
                // throw new Error(
                //   `Request did not meet the attestation threshold of ${this.minimumRequiredAttestations}.`
                // );
            }
            delete result.attestations;
        }
        return resp;
    }
}
exports.StatelessProvider = StatelessProvider;
async function verifyAttestedJsonRpcResponse(response, minimumRequiredAttestations = 1, identities) {
    // Generate hash of the response result
    const resultBytes = Buffer.from(response.result);
    const hash = crypto.createHash("sha256").update(resultBytes).digest();
    const validAttestations = [];
    for (const [i, attestation] of response.attestations.entries()) {
        // There's a chance the attestation does not have an identity if it's a batch response
        // In that case, use the provided identities
        if (identities && !attestation.identity) {
            attestation.identity = identities[i];
        }
        // If identities are provided, only use attestations from those identities
        // if (identities && !identities.includes(attestation.identity)) {
        //   continue;
        // }
        const sshPublicKeyStr = await publicKeyFromIdentity(attestation.identity);
        const key = sshpk.parseKey(sshPublicKeyStr, "ssh");
        if (key.type !== "ed25519") {
            throw new Error("The provided key is not an ed25519 key");
        }
        // @ts-ignore
        const publicKeyUint8Array = new Uint8Array(key.part.A.data);
        if (!verifyAttestation(attestation, publicKeyUint8Array, hash)) {
            console.log("Hash:", hash.toString("hex"));
            console.log("Invalid attestation:", attestation);
            continue;
        }
        validAttestations.push(attestation);
    }
    // Count the number of attestations for each message
    const msgCounts = {};
    for (const attestation of validAttestations) {
        msgCounts[attestation.msg] = (msgCounts[attestation.msg] || 0) + 1;
    }
    // Determine if consensus threshold is met
    return Object.values(msgCounts).some((count) => count >= minimumRequiredAttestations);
}
function verifyAttestation(attestation, publicKey, hash) {
    const signatureBytes = Buffer.from(attestation.signature, "hex");
    const signatureUint8Array = new Uint8Array(signatureBytes);
    return nacl.sign.detached.verify(new Uint8Array(hash), signatureUint8Array, publicKey);
}
async function publicKeyFromIdentity(identity) {
    const url = `${identity}/.well-known/stateless-key`;
    const req = new index_js_1.FetchRequest(url);
    const response = await req.send();
    response.assertOk();
    if (response.statusCode !== 200) {
        throw new Error(`Could not fetch public key from ${url}`);
    }
    return response.bodyText;
}
//# sourceMappingURL=provider-stateless.js.map