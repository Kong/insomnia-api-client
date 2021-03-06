import axios, { AxiosError, AxiosResponse } from 'axios';
import { encodeBase64, decodeBase64 } from '../base64';
import { BoxAcquireRequest, BoxAcquireResponse, BoxProvideRequest } from '../schema';
import { open, seal } from '../sealedbox';
import { globalConfig } from './fetch';

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
  await axios.post(`${baseUri}/v1/box/provide`, body, globalConfig);
}

export async function acquireBox<T>(baseUri: string, publicKey: Uint8Array, secretKey: Uint8Array): Promise<T|null> {
  const dec = new TextDecoder();

  // Base64 parameters into request
  const body: BoxAcquireRequest = {
    key: await encodeBase64(publicKey),
  };

  let response: AxiosResponse<any>;
  // Send request
  try {
    response = await axios.post(`${baseUri}/v1/box/acquire`, body, globalConfig);
  } catch(error) {
    const axiosError = error as AxiosError
    if (axiosError.isAxiosError && axiosError.response?.status === 404) {
      return null;
    }
    throw error;
  }

  // Decode request as JSON
  const responseData: BoxAcquireResponse = response.data;

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
