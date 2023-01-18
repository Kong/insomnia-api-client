/**
 * This is a simple in-memory database for storing and retrieving data.
 * It is used by the SRP plugin to store and retrieve the salt and verifier
 * for a given username.
 */

const data: Record<string, any> = {};

export function store(key: string, value: any, callback: (err: Error | null, success: boolean) => void) {
  data[key] = value;
  return callback(null, true);
};

exports.fetch = function fetch(key: string, callback: (err: Error | null, value: any) => void) {
  return callback(null, data[key]);
};