import type { Networkish } from "./network.js";
import { JsonRpcApiProviderOptions, JsonRpcPayload, JsonRpcProvider, JsonRpcResult } from "./provider-jsonrpc";
export type Attestation = {
    signatures?: string[];
    signature?: string;
    signatureFormat: string;
    hashAlgo: string;
    msgs?: string[];
    msg?: string;
    identity: string;
};
export type AttestedJsonRpcResult = JsonRpcResult & {
    attestations: Array<Attestation>;
};
export declare class StatelessProvider extends JsonRpcProvider {
    minimumRequiredAttestations: number;
    identities: string[];
    constructor(url: string, identities: string[], minimumRequiredAttestations?: number, network?: Networkish, options?: JsonRpcApiProviderOptions);
    _send(payload: JsonRpcPayload | Array<JsonRpcPayload>): Promise<Array<JsonRpcResult>>;
}
//# sourceMappingURL=provider-stateless.d.ts.map