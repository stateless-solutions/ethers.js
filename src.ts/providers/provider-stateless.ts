import * as crypto from "crypto";
import * as sshpk from "sshpk";
import * as nacl from "tweetnacl";
import { FetchRequest } from "../utils/index.js";
import type { Networkish } from "./network.js";
import {
  JsonRpcApiProviderOptions,
  JsonRpcPayload,
  JsonRpcProvider,
  JsonRpcResult,
} from "./provider-jsonrpc";

/**
 * An attestation consists of the signature of the attester and cryptographic proof
 */
export type Attestation = {
  /**
   * The signature of the attester
   */
  signature: string;

  /**
   * The signature format (i.e. "ssh-ed25519")
   */
  signatureFormat: string;

  /**
   * The hashing algorithm used to hash the data (i.e. "sha256")
   */
  hashAlgo: string;

  /**
   * The hashed message data
   */
  msg: string;

  /**
   * The identifier of the attester
   */
  identity: string;
};

/**
 *  A JSON-RPC result, which are returned on success from a JSON-RPC server.
 */
export type AttestedJsonRpcResult = JsonRpcResult & {
  /**
   * Attestation data for the request.
   */
  attestations: Array<Attestation>;
};

export class StatelessProvider extends JsonRpcProvider {
  /**
   * Minimum number of matching attestations required to consider a response valid
   */
  minimumRequiredAttestations: number;

  constructor(
    url?: string | FetchRequest,
    network?: Networkish,
    options?: JsonRpcApiProviderOptions,
    minimumRequiredAttestations?: number
  ) {
    super(url, network, options);
    this.minimumRequiredAttestations = minimumRequiredAttestations || 1;
  }

  async _send(
    payload: JsonRpcPayload | Array<JsonRpcPayload>
  ): Promise<Array<JsonRpcResult>> {
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

    let identities: string[] | undefined;

    // If it's a batch request, the identity is only included in the first response from the batch
    // We need to construct an ordered list of identities to use for verification
    for (let i = 0; i < resp.length; i++) {
      const result = resp[i];
      if (resp.length > 1 && i == 0 && result.attestations) {
        identities = result.attestations.map(
          (attestation: Attestation) => attestation.identity
        );
      }

      const isValid = await verifyAttestedJsonRpcResponse(
        result,
        this.minimumRequiredAttestations,
        identities
      );

      if (!isValid) {
        throw new Error(
          `Request did not meet the attestation threshold of ${this.minimumRequiredAttestations}.`
        );
      }

      delete result.attestations;
    }

    return resp;
  }
}

async function verifyAttestedJsonRpcResponse(
  response: AttestedJsonRpcResult,
  minimumRequiredAttestations: number = 1,
  identities?: string[]
): Promise<boolean> {
  // Generate hash of the response result
  const resultBytes = Buffer.from(JSON.stringify(response.result));
  const hash = crypto.createHash("sha256").update(resultBytes).digest();

  const validAttestations: Attestation[] = [];

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
      continue;
    }

    validAttestations.push(attestation);
  }

  // Count the number of attestations for each message
  const msgCounts: { [key: string]: number } = {};
  for (const attestation of validAttestations) {
    msgCounts[attestation.msg] = (msgCounts[attestation.msg] || 0) + 1;
  }

  // Determine if consensus threshold is met
  return Object.values(msgCounts).some(
    (count) => count >= minimumRequiredAttestations
  );
}

function verifyAttestation(
  attestation: Attestation,
  publicKey: Uint8Array,
  hash: Buffer
): boolean {
  const signatureBytes = Buffer.from(attestation.signature, "hex");
  const signatureUint8Array = new Uint8Array(signatureBytes);

  return nacl.sign.detached.verify(
    new Uint8Array(hash),
    signatureUint8Array,
    publicKey
  );
}

async function publicKeyFromIdentity(identity: string): Promise<string> {
  const url = `${identity}/.well-known/stateless-key`;

  const req = new FetchRequest(url);
  const response = await req.send();
  response.assertOk();

  if (response.statusCode !== 200) {
    throw new Error(`Could not fetch public key from ${url}`);
  }

  return response.bodyText;
}
