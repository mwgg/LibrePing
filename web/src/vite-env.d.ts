/// <reference types="vite/client" />

declare module "tweetnacl-sealedbox-js" {
  const sealedbox: {
    seal(message: Uint8Array, publicKey: Uint8Array): Uint8Array;
    open(box: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array | null;
  };
  export default sealedbox;
}
