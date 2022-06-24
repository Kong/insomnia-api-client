import { encodeBase64, decodeBase64 } from '../base64';
import { BoxAcquireRequest, BoxAcquireResponse, BoxProvideRequest } from '../schema';
import { open, seal } from '../sealedbox';

export async function provideBox<T>(baseUri: string, data: T, publicKey: Uint8Array): Promise<void> {
  const enc = new TextEncoder();

  // Encode data to JSON, to bytes
  const rawData = enc.encode(JSON.stringify(data));

  // Seal bytes into box
  const sealedBox = seal(rawData, publicKey);

  // Base64 parameters into request
  const body: BoxProvideRequest = {
    key: await encodeBase64(publicKey),
    data: await encodeBase64(sealedBox),
  };

  // Send request
  const response = await fetch(`${baseUri}/v1/box/provide`, {
    body: JSON.stringify(body),
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (response.status != 200) {
    throw new Error("Request failed");
  }

  return;
}

export async function acquireBox<T>(baseUri: string, publicKey: Uint8Array, secretKey: Uint8Array): Promise<T|null> {
  const dec = new TextDecoder();

  // Base64 parameters into request
  const body: BoxAcquireRequest = {
    key: await encodeBase64(publicKey),
  };

  // Send request
  const response = await fetch(`${baseUri}/v1/box/acquire`, {
    body: JSON.stringify(body),
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (response.status === 404) {
    return null;
  } else if (response.status !== 200) {
    throw new Error("Request failed");
  }

  // Decode request as JSON
  const responseData: BoxAcquireResponse = await response.json();

  // Decode base64'd string
  const sealedBox = await decodeBase64(responseData.data);

  // Unseal box into bytes
  const rawData = open(sealedBox, publicKey, secretKey);

  if (!rawData) {
    throw new Error("Invalid data");
  }

  // Decode and parse bytes from JSON.
  return JSON.parse(dec.decode(rawData));
}
