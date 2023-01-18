"use strict";

import * as crypto from "crypto";
import { BigInteger } from "./bignum";
import { Buffer } from "buffer";

const zero = new BigInteger("0");

function invariant(condition: boolean, msg: string): asserts condition {
  if (!condition) {
    throw new Error(msg);
  }
}

type Params = {
  N_length_bits: number;
  g: BigInteger;
  hash: string;
  N: BigInteger;
};

/*
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 *
 * params:
 *         n (buffer)       Number to pad
 *         len (int)        length of the resulting Buffer
 *
 * returns: buffer
 */
function padTo(n: Buffer, len: number) {
  assertIsBuffer(n, "n");
  const padding = len - n.length;
  invariant(padding > -1, "Negative padding.  Very uncomfortable.");
  const result = Buffer.alloc(len);
  result.fill(0, 0, padding);
  n.copy(result, padding);
  invariant(result.length === len, "Padding is different than expected.");
  return result;
}

export function padToN(number: BigInteger, params: { N_length_bits: number }) {
  assertIsBignum(number);
  return padTo(number.toBuffer(), params.N_length_bits / 8);
}

export function padToH(number: BigInteger, params: { hash: string }) {
  assertIsBignum(number);
  let hashlen_bits: number;
  if (params.hash === "sha1") {
    hashlen_bits = 160;
  } else if (params.hash === "sha256") {
    hashlen_bits = 256;
  } else if (params.hash === "sha512") {
    hashlen_bits = 512;
  } else {
    throw Error(`Cannot determine length of hash '${params.hash}'`);
  }

  return padTo(number.toBuffer(), hashlen_bits / 8);
}

function assertIsBuffer(arg: any, argname = "arg") {
  invariant(
    Buffer.isBuffer(arg),
    "Type error: " + argname + " must be a buffer"
  );
}

function assertIsNBuffer(
  arg: any,
  params: { N_length_bits: number },
  argname = "arg"
) {
  invariant(
    Buffer.isBuffer(arg),
    "Type error: " + argname + " must be a buffer"
  );
  invariant(
    arg.length != params.N_length_bits / 8,
    argname + " was " + arg.length + ", expected " + params.N_length_bits / 8
  );
}

function assertIsBignum(arg: any) {
  invariant(arg.bigNum, "Type error: arg must be a bignum");
}

/*
 * Compute the intermediate value x as a hash of three buffers:
 * salt, identity, and password.  And a colon.  FOUR buffers.
 *
 *      x = H(s | H(I | ":" | P))
 *
 * params:
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: x (bignum)      user secret
 */
function getx(
  params: { hash: string },
  salt: crypto.BinaryLike,
  I: Uint8Array,
  P: Uint8Array
) {
  assertIsBuffer(salt, "salt (salt)");
  assertIsBuffer(I, "identity (I)");
  assertIsBuffer(P, "password (P)");

  const hashIP = Buffer.from(
    crypto
      .createHash(params.hash)
      .update(Buffer.concat([I, new Buffer(":"), P]))
      .digest()
  );

  const hashX = Buffer.from(
    crypto.createHash(params.hash).update(salt).update(hashIP).digest()
  );

  return BigInteger.fromBuffer(hashX);
}

/*
 * The verifier is calculated as described in Section 3 of [SRP-RFC].
 * We give the algorithm here for convenience.
 *
 * The verifier (v) is computed based on the salt (s), user name (I),
 * password (P), and group parameters (N, g).
 *
 *         x = H(s | H(I | ":" | P))
 *         v = g^x % N
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: buffer
 */
export function computeVerifier(
  params: { g: BigInteger; N: BigInteger; hash: string; N_length_bits: number },
  salt: crypto.BinaryLike,
  I: Uint8Array,
  P: Uint8Array
) {
  assertIsBuffer(salt, "salt (salt)");
  assertIsBuffer(I, "identity (I)");
  assertIsBuffer(P, "password (P)");
  const v_num = params.g.powm(getx(params, salt, I, P), params.N);
  return padToN(v_num, params);
}

/*
 * Calculate the SRP-6 multiplier
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *
 * returns: bignum
 */
function getk(params: {
  hash: string;
  N?: any;
  g: BigInteger;
  N_length_bits: number;
}) {
  const k_buf = crypto
    .createHash(params.hash)
    .update(padToN(params.N, params))
    .update(padToN(params.g, params))
    .digest();

  return BigInteger.fromBuffer(k_buf);
}

type GenKeyCallback = {
  (err: Error, key: undefined): void;
  (err: null, key: Buffer): void;
};

type genKeyArguments =
  | [bytes: number, callback: GenKeyCallback]
  | [callback: GenKeyCallback];
/*
 * Generate a random key
 *
 * params:
 *         bytes (int)      length of key (default=32)
 *         callback (func)  function to call with err,key
 *
 * returns: nothing, but runs callback with a Buffer
 */
export function genKey(...args: genKeyArguments) {
  let bytes = 32;
  let callback: GenKeyCallback;
  if (args.length === 1) {
    callback = args[0];
  } else if (args.length === 2) {
    bytes = args[0];
    callback = args[1];
  } else {
    throw "Invalid arguments";
  }

  invariant(typeof callback === "function", "Callback must be a function");

  crypto.randomBytes(bytes, (error, buffer) => {
    if (error) {
      return callback(error, undefined);
    }

    return callback(null, Buffer.from(buffer));
  });
}

/*
 * The server key exchange message also contains the server's public
 * value (B).  The server calculates this value as B = k*v + g^b % N,
 * where b is a random number that SHOULD be at least 256 bits in length
 * and k = H(N | PAD(g)).
 *
 * Note: as the tests imply, the entire expression is mod N.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         v (bignum)       verifier (stored)
 *         b (bignum)       server secret exponent
 *
 * returns: B (buffer)      the server public message
 */
function getB(
  params: { N?: any; g: BigInteger; N_length_bits: number },
  k: BigInteger,
  v: any,
  b: any
) {
  assertIsBignum(v);
  assertIsBignum(k);
  assertIsBignum(b);

  const N = params.N;
  const r = k.mul(v).add(params.g.powm(b, N)).mod(N);

  return padToN(r, params);
}

/*
 * The client key exchange message carries the client's public value
 * (A).  The client calculates this value as A = g^a % N, where a is a
 * random number that SHOULD be at least 256 bits in length.
 *
 * Note: for this implementation, we take that to mean 256/8 bytes.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         a (bignum)       client secret exponent
 *
 * returns A (bignum)       the client public message
 */
function getA(
  params: { g?: any; N?: any; N_length_bits: number },
  a_num: { bitLength: () => number }
) {
  assertIsBignum(a_num);
  if (Math.ceil(a_num.bitLength() / 8) < 256 / 8) {
    console.warn(
      "getA: client key length",
      a_num.bitLength(),
      "is less than the recommended 256"
    );
  }
  return padToN(params.g.powm(a_num, params.N), params);
}

/*
 * getu() hashes the two public messages together, to obtain a scrambling
 * parameter "u" which cannot be predicted by either party ahead of time.
 * This makes it safe to use the message ordering defined in the SRP-6a
 * paper, in which the server reveals their "B" value before the client
 * commits to their "A" value.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         A (Buffer)       client ephemeral public key
 *         B (Buffer)       server ephemeral public key
 *
 * returns: u (bignum)      shared scrambling parameter
 */
function getu(
  params: { hash: string; N_length_bits: number },
  A: crypto.BinaryLike,
  B: crypto.BinaryLike
) {
  assertIsNBuffer(A, params, "A");
  assertIsNBuffer(B, params, "B");
  const u_buf = crypto.createHash(params.hash).update(A).update(B).digest();

  return BigInteger.fromBuffer(u_buf);
}

/*
 * The TLS premaster secret as calculated by the client
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt (read from server)
 *         I (buffer)       user identity (read from user)
 *         P (buffer)       user password (read from user)
 *         a (bignum)       ephemeral private key (generated for session)
 *         B (bignum)       server ephemeral public key (read from server)
 *
 * returns: buffer
 */

function client_getS(
  params: { g?: any; N?: any; N_length_bits: number },
  k_num: { mul: (arg0: any) => any },
  x_num: any,
  a_num: { add: (arg0: any) => any },
  B_num: BigInteger,
  u_num: { mul: (arg0: any) => any }
) {
  assertIsBignum(k_num);
  assertIsBignum(x_num);
  assertIsBignum(a_num);
  assertIsBignum(B_num);
  assertIsBignum(u_num);
  var g = params.g;
  var N = params.N;
  if (zero.ge(B_num) || N.le(B_num))
    throw new Error("invalid server-supplied 'B', must be 1..N-1");
  var S_num = B_num.sub(k_num.mul(g.powm(x_num, N)))
    .powm(a_num.add(u_num.mul(x_num)), N)
    .mod(N);
  return padToN(S_num, params);
}

/*
 * The TLS premastersecret as calculated by the server
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         v (bignum)       verifier (stored on server)
 *         A (bignum)       ephemeral client public key (read from client)
 *         b (bignum)       server ephemeral private key (generated for session)
 *
 * returns: bignum
 */

function server_getS(
  params: { N?: any; N_length_bits: number },
  v_num: { powm: (arg0: any, arg1: any) => any },
  A_num: BigInteger,
  b_num: any,
  u_num: any
) {
  assertIsBignum(v_num);
  assertIsBignum(A_num);
  assertIsBignum(b_num);
  assertIsBignum(u_num);
  var N = params.N;
  if (zero.ge(A_num) || N.le(A_num))
    throw new Error("invalid client-supplied 'A', must be 1..N-1");
  var S_num = A_num.mul(v_num.powm(u_num, N)).powm(b_num, N).mod(N);
  return padToN(S_num, params);
}

/*
 * Compute the shared session key K from S
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         S (buffer)       Session key
 *
 * returns: buffer
 */
function getK(
  params: { hash: string; N_length_bits: number },
  S_buf: Buffer | crypto.BinaryLike
) {
  assertIsNBuffer(S_buf, params, "S");
  return Buffer.from(crypto.createHash(params.hash).update(S_buf).digest());
}

function getM1(
  params: { hash: string; N_length_bits: number },
  A_buf: crypto.BinaryLike,
  B_buf: crypto.BinaryLike,
  S_buf: Buffer | crypto.BinaryLike
) {
  assertIsNBuffer(A_buf, params, "A");
  assertIsNBuffer(B_buf, params, "B");
  assertIsNBuffer(S_buf, params, "S");
  return Buffer.from(
    crypto
      .createHash(params.hash)
      .update(A_buf)
      .update(B_buf)
      .update(S_buf)
      .digest()
  );
}

function getM2(
  params: { hash: string; N_length_bits: number },
  A_buf: crypto.BinaryLike,
  M_buf: crypto.BinaryLike,
  K_buf: crypto.BinaryLike
) {
  assertIsNBuffer(A_buf, params, "A");
  assertIsBuffer(M_buf, "M");
  assertIsBuffer(K_buf, "K");
  return Buffer.from(
    crypto
      .createHash(params.hash)
      .update(A_buf)
      .update(M_buf)
      .update(K_buf)
      .digest()
  );
}

function equal(buf1: Buffer, buf2: Buffer) {
  // constant-time comparison. A drop in the ocean compared to our
  // non-constant-time modexp operations, but still good practice.
  let mismatch = buf1.length - buf2.length;
  if (mismatch) {
    return false;
  }
  for (var i = 0; i < buf1.length; i++) {
    mismatch |= buf1[i] ^ buf2[i];
  }
  return mismatch === 0;
}

export class Client {
  _private: {
    params: Params;
    k_num: BigInteger;
    x_num: BigInteger;
    a_num: BigInteger;
    A_buf: Buffer;
    K_buf?: Buffer;
    M1_buf?: Buffer;
    M2_buf?: Buffer;
    u_num?: BigInteger;
  };

  constructor(
    params: Params,
    salt_buf: Buffer,
    identity_buf: Buffer,
    password_buf: Buffer,
    secret1_buf: Buffer
  ) {
    assertIsBuffer(salt_buf, "salt (salt)");
    assertIsBuffer(identity_buf, "identity (I)");
    assertIsBuffer(password_buf, "password (P)");
    assertIsBuffer(secret1_buf, "secret1");

    const a_num = BigInteger.fromBuffer(secret1_buf);
    this._private = {
      params,
      k_num: getk(params),
      x_num: getx(params, salt_buf, identity_buf, password_buf),
      a_num,
      A_buf: getA(params, a_num)
    };
  }

  computeA() {
    return this._private.A_buf;
  }

  setB(B_buf: any) {
    const p = this._private;
    const B_num = BigInteger.fromBuffer(B_buf);
    const u_num = getu(p.params, p.A_buf, B_buf);
    const S_buf = client_getS(
      p.params,
      p.k_num,
      p.x_num,
      p.a_num,
      B_num,
      u_num
    );
    p.K_buf = getK(p.params, S_buf);
    p.M1_buf = getM1(p.params, p.A_buf, B_buf, S_buf);
    p.M2_buf = getM2(p.params, p.A_buf, p.M1_buf, p.K_buf);
    p.u_num = u_num;
  }

  computeM1() {
    invariant(
      typeof this._private.M1_buf !== "undefined",
      "Incomplete protocol"
    );
    return this._private.M1_buf;
  }

  checkM2(M2_buf: Buffer) {
    invariant(
      typeof this._private.M2_buf !== "undefined",
      "Incomplete protocol"
    );
    invariant(equal(this._private.M2_buf, M2_buf), "Server is not authentic");
  }

  computeK() {
    invariant(
      typeof this._private.K_buf !== "undefined",
      "Incomplete protocol"
    );
    return this._private.K_buf;
  }
}

export class Server {
  _private: {
    params: Params;
    k_num: BigInteger;
    b_num: BigInteger;
    v_num: BigInteger;
    B_buf: Buffer;
    K_buf?: Buffer;
    M1_buf?: Buffer;
    M2_buf?: Buffer;
    u_num?: BigInteger;
    S_buf?: Buffer;
  };

  constructor(params: Params, verifier_buf: Buffer, secret2_buf: Buffer) {
    assertIsBuffer(verifier_buf, "verifier");
    assertIsBuffer(secret2_buf, "secret2");
    assertIsBuffer(verifier_buf, "verifier");
    assertIsBuffer(secret2_buf, "secret2");

    const nums = {
      k_num: getk(params),
      b_num: BigInteger.fromBuffer(secret2_buf),
      v_num: BigInteger.fromBuffer(verifier_buf)
    };

    this._private = {
      params: params,
      ...nums,
      B_buf: getB(params, nums.k_num, nums.v_num, nums.b_num)
    };
  }

  computeB() {
    return this._private.B_buf;
  }

  setA(A_buf: Buffer) {
    const p = this._private;
    const A_num = BigInteger.fromBuffer(A_buf);
    const u_num = getu(p.params, A_buf, p.B_buf);
    const S_buf = server_getS(p.params, p.v_num, A_num, p.b_num, u_num);

    p.K_buf = getK(p.params, S_buf);
    p.M1_buf = getM1(p.params, A_buf, p.B_buf, S_buf);
    p.M2_buf = getM2(p.params, A_buf, p.M1_buf, p.K_buf);
    p.u_num = u_num; // only for tests
    p.S_buf = S_buf; // only for tests
  }

  checkM1(clientM1_buf: Buffer) {
    invariant(
      typeof this._private.M1_buf !== "undefined",
      "Incomplete protocol"
    );

    invariant(
      equal(this._private.M1_buf, clientM1_buf),
      "Client did not use the same password"
    );

    return this._private.M2_buf;
  }

  computeK() {
    invariant(
      typeof this._private.K_buf !== "undefined",
      "Incomplete protocol"
    );

    return this._private.K_buf;
  }
}

export { params } from "./params";
