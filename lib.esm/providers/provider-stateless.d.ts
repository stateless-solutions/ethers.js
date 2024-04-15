import type { Networkish } from "./network.js";
import { JsonRpcApiProviderOptions, JsonRpcPayload, JsonRpcProvider, JsonRpcResult } from "./provider-jsonrpc";
/**
 * An attestation consists of the signature of the attester and cryptographic proof
 */
export type Attestation = {
    /**
     * The signature(s) of the attested message(s)
     */
    signature?: string;
    signatures?: string[];
    /**
     * The signature format (i.e. "ssh-ed25519")
     */
    signatureFormat: string;
    /**
     * The hashing algorithm used to hash the data (i.e. "sha256")
     */
    hashAlgo: string;
    /**
     * The hashed message(s) data
     */
    msg?: string;
    msgs?: string[];
    /**
     * The domain where the attester holds his public key to verify the signatures
     */
    identity: string;
};
export type AttestedJsonRpcResult = JsonRpcResult & {
    attestations: Array<Attestation>;
};
export declare class StatelessProvider extends JsonRpcProvider {
    /**
     * Minimum number of matching attestations required to consider a response valid
     */
    minimumRequiredAttestations: number;
    /**
     * The expected identities for the attestations
     */
    identities: string[];
    constructor(url: string, identities: string[], minimumRequiredAttestations?: number, network?: Networkish, options?: JsonRpcApiProviderOptions);
    _send(payload: JsonRpcPayload | Array<JsonRpcPayload>): Promise<Array<JsonRpcResult>>;
}
//# sourceMappingURL=provider-stateless.d.ts.map