import crypto from "crypto";
import sshpk from "sshpk";
import nacl from "tweetnacl";
import { Trie } from "@ethereumjs/trie";
import { FetchRequest } from "../utils/index.js";
import type { Networkish } from "./network.js";
import {
  JsonRpcApiProviderOptions,
  JsonRpcPayload,
  JsonRpcProvider,
  JsonRpcResult,
} from "./provider-jsonrpc.js";

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

type AccessListItem = { address: string; storageKeys: Array<string> };

export class StatelessProvider extends JsonRpcProvider {
  /**
   * Minimum number of matching attestations required to consider a response valid
   */
  minimumRequiredAttestations: number;

  /**
   * The expected identities for the attestations
   */
  identities: string[];

  private prover: JsonRpcProvider | null = null;

  constructor(
    url: string,
    identities: string[],
    minimumRequiredAttestations?: number,
    proverUrl?: string,
    network?: Networkish,
    options?: JsonRpcApiProviderOptions
  ) {
    super(url, network, options);
    this.identities = identities;
    this.minimumRequiredAttestations = minimumRequiredAttestations || 1;
    if (proverUrl) {
      this.prover = new JsonRpcProvider(proverUrl, network);
    }
  }

  async _send(
    payload: JsonRpcPayload | Array<JsonRpcPayload>
  ): Promise<Array<JsonRpcResult>> {
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
        this.identities = result.attestations.map(
          (attestation: Attestation) => attestation.identity
        );
      }

      const isValid = await this.verifyAttestedJsonRpcResponse(
        result,
        this.minimumRequiredAttestations,
        this.identities
      );

      if (!isValid) {
        throw new Error(
          `Request did not meet the attestation threshold of ${this.minimumRequiredAttestations}.`
        );
      }

      delete result.attestations;
    }

    if (this.prover) {
      const payloads = Array.isArray(payload) ? payload : [payload];
      for (let i = 0; i < payloads.length; i++) {
        if (payloads[i].method === "eth_call") {
          await this.verifyStatelessProof(payloads[i].params);
        }
      }
    }

    return resp as Array<JsonRpcResult>;
  }

  private async verifyStatelessProof(
    params: Record<string, any>
  ): Promise<void> {
    const latestBlockNumber = await this.send("eth_blockNumber", []);
    const { stateRoot: stateRootHex } = await this.send(
      "eth_getBlockByNumber",
      [latestBlockNumber, false]
    );
    const stateRoot = this.fromHexString(stateRootHex);

    const { accessList }: { accessList: AccessListItem[] } =
      await this.prover!.send("eth_createAccessList", [
        {
          to: params.to,
          data: params.data,
          gas: params.gas,
          gasPrice: params.gasPrice,
          value: params.value,
          from: params.from,
        },
      ]);

    const {
      accountProof,
      storageProof,
      storageHash: storageHashHex,
    } = await this.prover!.send("eth_getProof", [
      accessList[0].address,
      accessList[0].storageKeys,
      latestBlockNumber,
    ]);

    const storageHash = this.fromHexString(storageHashHex);

    // Verify state trie
    const trie = new Trie({ root: stateRoot, useKeyHashing: true });
    await trie.updateFromProof(
      accountProof.map((p: string) => this.fromHexString(p))
    );

    const accessListAddress = this.fromHexString(accessList[0].address);
    const val = await trie.get(accessListAddress, true);

    if (!val) {
      throw new Error("Account not found in state trie");
    }

    // Verify storage trie
    const storageTrie = new Trie({ root: storageHash, useKeyHashing: true });

    for (let i = 0; i < accessList[0].storageKeys.length; i++) {
      const proofBuffer = storageProof[i].proof.map((p: string) =>
        this.fromHexString(p)
      );
      await storageTrie.updateFromProof(proofBuffer);
      const storageVal = await storageTrie.get(
        this.fromHexString(accessList[0].storageKeys[i])
      );

      if (!storageVal) {
        throw new Error("Storage value not found");
      }
    }

    return;
  }

  private async verifyAttestedJsonRpcResponse(
    response: AttestedJsonRpcResult,
    minimumRequiredAttestations: number = 1,
    identities?: string[]
  ): Promise<boolean> {
    let resultHashes: string[] = [];

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
        const hash = crypto
          .createHash("sha256")
          .update(resultBytes)
          .digest("hex");
        resultHashes.push(hash);
      }
    } else {
      const resultBytes = Buffer.from(JSON.stringify(response.result));
      const hash = crypto
        .createHash("sha256")
        .update(resultBytes)
        .digest("hex");
      resultHashes = [hash];
    }

    const validAttestations: Attestation[] = [];

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

      let sshPublicKey: string;
      try {
        sshPublicKey = await this.publicKeyFromIdentity(attestation.identity);
      } catch (error) {
        continue;
      }

      const key = sshpk.parseKey(sshPublicKey, "ssh");
      if (key.type !== "ed25519") {
        throw new Error("The provided key is not an ed25519 key");
      }

      // @ts-ignore
      const publicKeyUint8Array = new Uint8Array(key.part.A.data);

      const isValid = this.verifyAttestation(
        attestation,
        publicKeyUint8Array,
        resultHashes
      );

      if (!isValid) {
        continue;
      }

      validAttestations.push(attestation);
    }

    return validAttestations.length >= minimumRequiredAttestations;
  }

  private verifyAttestation(
    attestation: Attestation,
    publicKey: Uint8Array,
    resultHashes: string[]
  ): boolean {
    // Calls like `eth_getLogs` return a list of message hashes and signatures,
    // so we need to make sure the logs returned in the response are backed by the minimum amount of required attestations
    if (
      attestation.msgs &&
      attestation.msgs.length > 0 &&
      attestation.signatures
    ) {
      const isSubset = resultHashes.every((hash) =>
        attestation.msgs?.includes(hash)
      );
      if (!isSubset) {
        return false;
      }

      return attestation.msgs.every((msg, index) => {
        if (!attestation.signatures) return false;
        return this.verifySignature(
          msg,
          attestation.signatures[index],
          publicKey,
          attestation.hashAlgo
        );
      });
    } else if (attestation.msg && attestation.signature) {
      const isHashInResult = resultHashes.includes(attestation.msg);
      return (
        isHashInResult &&
        this.verifySignature(
          attestation.msg,
          attestation.signature,
          publicKey,
          attestation.hashAlgo
        )
      );
    }
    return false;
  }

  private verifySignature(
    msgHash: string,
    signature: string,
    publicKey: Uint8Array,
    hashAlgo: string
  ): boolean {
    try {
      if (!publicKey) throw new Error("Public key is undefined.");
      if (!msgHash) throw new Error("Message hash is undefined.");
      if (!signature) throw new Error("Signature is undefined.");

      const signatureBytes = Buffer.from(signature, "hex");
      const signatureUint8Array = new Uint8Array(signatureBytes);
      const msgHashBytes = Buffer.from(msgHash, "hex");

      return nacl.sign.detached.verify(
        msgHashBytes,
        signatureUint8Array,
        publicKey
      );
    } catch (error) {
      console.error("Verification failed:", error);
      return false;
    }
  }

  private async publicKeyFromIdentity(identity: string): Promise<string> {
    const url = `${identity}/.well-known/stateless-key`;

    const req = new FetchRequest(url);
    const response = await req.send();
    response.assertOk();

    if (response.statusCode !== 200) {
      throw new Error(`Could not fetch public key from ${url}`);
    }

    return response.bodyText;
  }

  private fromHexString = (hexString: string): Uint8Array => {
    if (hexString.startsWith("0x")) {
      hexString = hexString.slice(2);
    }

    return Uint8Array.from(
      (hexString.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))
    );
  };
}
