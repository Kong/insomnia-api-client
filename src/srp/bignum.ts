import { Buffer } from "buffer";
import { BigInteger as _BigInteger } from "jsbn";

/**
 * A wrapper around jsbn's BigInteger that adds some convenience methods
 * and makes it easier to work with Buffers.
 * It uses ensureBI to ensure that the passed in value is a BigInteger.
 * It also adds a `bigNum` property to the object so that we can tell if it's a BigInteger.
 */
export class BigInteger extends _BigInteger {
  bigNum = true;

  toBuffer() {
    let h = this.toString(16);

    // Fix odd-length hex values from BigInteger
    if (h.length % 2 === 1) {
      h = "0" + h;
    }

    return Buffer.from(h, "hex");
  }

  ensureBI(n: any) {
    if (!("bigNum" in n)) {
      n = new BigInteger(n);
    }

    return n;
  }

  add(n: BigInteger): BigInteger {
    return this.ensureBI(new _BigInteger(this).add(this.ensureBI(n)));
  }

  mul(n: BigInteger) {
    return this.ensureBI(this.multiply(this.ensureBI(n)));
  }

  sub(n: BigInteger) {
    return this.ensureBI(this.subtract(this.ensureBI(n)));
  }

  powm(n: BigInteger, m: BigInteger) {
    return this.ensureBI(this.modPow(this.ensureBI(n), this.ensureBI(m)));
  }

  eq(n: BigInteger) {
    return this.ensureBI(this.equals(this.ensureBI(n)));
  }

  ge(n: BigInteger) {
    return this.compareTo(n) >= 0;
  }

  le(n: BigInteger) {
    return this.compareTo(n) <= 0;
  }

  static fromBuffer(buffer: Buffer) {
    return new BigInteger(buffer.toString("hex"), 16);
  }
}
