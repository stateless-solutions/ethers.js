import crypto from "crypto";
import sshpk from "sshpk";
import nacl from "tweetnacl";
import { Trie } from "@ethereumjs/trie";
import { FetchRequest } from "../utils/index.js";
import { JsonRpcProvider, } from "./provider-jsonrpc.js";
export class StatelessProvider extends JsonRpcProvider {
    /**
     * Minimum number of matching attestations required to consider a response valid
     */
    minimumRequiredAttestations;
    /**
     * The expected identities for the attestations
     */
    identities;
    prover = null;
    constructor(url, identities, minimumRequiredAttestations, proverUrl, network, options) {
        super(url, network, options);
        this.identities = identities;
        this.minimumRequiredAttestations = minimumRequiredAttestations || 1;
        if (proverUrl) {
            this.prover = new JsonRpcProvider(proverUrl, network);
        }
    }
    async _send(payload) {
        if (this.prover) {
            const payloads = Array.isArray(payload) ? payload : [payload];
            for (let i = 0; i < payloads.length; i++) {
                if (payloads[i].method === "eth_call") {
                    await this.verifyStatelessProof(payloads[i].params);
                }
            }
        }
        const request = this._getConnection();
        request.body = JSON.stringify(payload);
        request.setHeader("content-type", "application/json");
        const response = await request.send();
        response.assertOk();
        let resp = response.bodyJson;
        if (!Array.isArray(resp)) {
            resp = [resp];
        }
        if (!this.prover) {
            return await this.verifyAttestations(resp);
        }
        return resp;
    }
    async verifyAttestations(resp) {
        const responses = [];
        // If it's a batch request, the identity is only included in the first response from the batch
        // We need to construct an ordered list of identities to use for verification
        for (let i = 0; i < resp.length; i++) {
            const result = resp[i];
            if (resp.length > 1 && i == 0 && result.attestations) {
                this.identities = result.attestations.map((attestation) => attestation.identity);
            }
            const isValid = await this.verifyAttestedJsonRpcResponse(result, this.minimumRequiredAttestations, this.identities);
            if (!isValid) {
                throw new Error(`Request did not meet the attestation threshold of ${this.minimumRequiredAttestations}.`);
            }
            delete result.attestations;
            responses.push(result);
        }
        return responses;
    }
    extractDefinedProperties(obj) {
        return Object.fromEntries(Object.entries(obj).filter(([_, v]) => v !== undefined));
    }
    async verifyStatelessProof(params) {
        const latestBlockNumber = await this.send("eth_blockNumber", []);
        const { stateRoot: stateRootHex } = await this.send("eth_getBlockByNumber", [latestBlockNumber, false]);
        const stateRoot = this.fromHexString(stateRootHex);
        let createAccessListParams;
        if (Array.isArray(params)) {
            const [firstParam] = params;
            createAccessListParams = this.extractDefinedProperties(firstParam);
        }
        else {
            createAccessListParams = this.extractDefinedProperties(params);
        }
        const { accessList } = await this.prover.send("eth_createAccessList", [createAccessListParams]);
        const { accountProof, storageProof, storageHash: storageHashHex, } = await this.prover.send("eth_getProof", [
            accessList[0].address,
            accessList[0].storageKeys,
            latestBlockNumber,
        ]);
        const storageHash = this.fromHexString(storageHashHex);
        // Verify state trie
        const trie = new Trie({ root: stateRoot, useKeyHashing: true });
        await trie.updateFromProof(accountProof.map((p) => this.fromHexString(p)));
        const accessListAddress = this.fromHexString(accessList[0].address);
        const val = await trie.get(accessListAddress, true);
        if (!val) {
            throw new Error("Account not found in state trie");
        }
        // Verify storage trie
        const storageTrie = new Trie({ root: storageHash, useKeyHashing: true });
        for (let i = 0; i < accessList[0].storageKeys.length; i++) {
            const proofBuffer = storageProof[i].proof.map((p) => this.fromHexString(p));
            await storageTrie.updateFromProof(proofBuffer);
            const storageVal = await storageTrie.get(this.fromHexString(accessList[0].storageKeys[i]));
            if (!storageVal) {
                throw new Error("Storage value not found");
            }
        }
        return;
    }
    async verifyAttestedJsonRpcResponse(response, minimumRequiredAttestations = 1, identities) {
        let content;
        let contentHashes = [];
        if ("result" in response) {
            content = response.result;
        }
        else if ("error" in response) {
            content = response.error;
        }
        if (content === undefined) {
            throw new Error("Response must contain either a result or an error field");
        }
        if (Array.isArray(content)) {
            for (const item of content) {
                // Our attestation code in the ethereum client adds this field by default,
                // this is not ideal and should be revisited - fields that don't come from provider responses,
                // shouldn't be included by default
                if (!item.timestamp) {
                    item.timestamp = "0x0";
                }
                const stringifiedItem = JSON.stringify(item);
                const itemBytes = Buffer.from(stringifiedItem);
                const hash = crypto
                    .createHash("sha256")
                    .update(itemBytes)
                    .digest("hex");
                contentHashes.push(hash);
            }
        }
        else {
            const contentBytes = Buffer.from(JSON.stringify(content));
            const hash = crypto
                .createHash("sha256")
                .update(contentBytes)
                .digest("hex");
            contentHashes = [hash];
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
                sshPublicKey = await this.publicKeyFromIdentity(attestation.identity);
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
            const isValid = this.verifyAttestation(attestation, publicKeyUint8Array, contentHashes);
            if (!isValid) {
                continue;
            }
            validAttestations.push(attestation);
        }
        return validAttestations.length >= minimumRequiredAttestations;
    }
    verifyAttestation(attestation, publicKey, resultHashes) {
        // Calls like `eth_getLogs` return a list of message hashes and signatures,
        // so we need to make sure the logs returned in the response are backed by the minimum amount of required attestations
        if (attestation.msgs &&
            attestation.msgs.length > 0 &&
            attestation.signatures) {
            const isSubset = resultHashes.every((hash) => attestation.msgs?.includes(hash));
            if (!isSubset) {
                return false;
            }
            return attestation.msgs.every((msg, index) => {
                if (!attestation.signatures)
                    return false;
                return this.verifySignature(msg, attestation.signatures[index], publicKey, attestation.hashAlgo);
            });
        }
        else if (attestation.msg && attestation.signature) {
            const isHashInResult = resultHashes.includes(attestation.msg);
            return (isHashInResult &&
                this.verifySignature(attestation.msg, attestation.signature, publicKey, attestation.hashAlgo));
        }
        return false;
    }
    verifySignature(msgHash, signature, publicKey, hashAlgo) {
        try {
            if (!publicKey)
                throw new Error("Public key is undefined.");
            if (!msgHash)
                throw new Error("Message hash is undefined.");
            if (!signature)
                throw new Error("Signature is undefined.");
            const signatureBytes = Buffer.from(signature, "hex");
            const signatureUint8Array = new Uint8Array(signatureBytes);
            const msgHashBytes = Buffer.from(msgHash, "hex");
            return nacl.sign.detached.verify(msgHashBytes, signatureUint8Array, publicKey);
        }
        catch (error) {
            console.error("Verification failed:", error);
            return false;
        }
    }
    async publicKeyFromIdentity(identity) {
        const url = `${identity}/.well-known/stateless-key`;
        const req = new FetchRequest(url);
        const response = await req.send();
        response.assertOk();
        if (response.statusCode !== 200) {
            throw new Error(`Could not fetch public key from ${url}`);
        }
        return response.bodyText;
    }
    fromHexString = (hexString) => {
        if (hexString.startsWith("0x")) {
            hexString = hexString.slice(2);
        }
        return Uint8Array.from((hexString.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16)));
    };
}
//# sourceMappingURL=provider-stateless.js.map