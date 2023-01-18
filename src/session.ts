import { Client, computeVerifier, params } from "./srp/srp";
import type * as schema from "@getinsomnia/api-client/schema";
import * as unorm from "unorm";
import * as crypt from "./crypt";
import * as util from "./fetch";
import { Buffer } from "buffer";

export interface BillingDetails {
  planId: string;
  description: string;
  isPaymentRequired: boolean;
  isBillingAdmin: boolean;
  subTrialing: boolean;
  subTrialEnd: string;
  subCancelled: boolean;
  subPeriodEnd: string;
  subPercentOff: number;
  customerId: string;
  subQuantity: number;
  subMemo: string;
  hasCard: boolean;
  lastFour: string;
}

export interface Team {
  id: string;
  name: string;
  ownerAccountId: string;
  isPersonal: boolean;
  accounts: {
    isAdmin: boolean;
    firstName: string;
    lastName: string;
    email: string;
    id: string;
  }[];
}

export interface Invoice {
  id: string;
  date: string;
  paid: boolean;
  total: number;
}

export interface InvoiceLink {
  downloadLink: string;
}

interface AuthSalts {
  saltKey: string;
  saltAuth: string;
}

interface Account {
  email: string;
  firstName: string;
  lastName: string;
  id: string;
  saltEnc: string;
  saltAuth: string;
  saltKey: string;
  verifier?: string;
  publicKey?: string;
  encPrivateKey?: string;
  encSymmetricKey?: string;
}

/** Create a new Account for the user */
export async function signup(
  firstName: string,
  lastName: string,
  rawEmail: string,
  rawPassphrase: string,
  loginAfter = false
) {
  const email = _sanitizeEmail(rawEmail);
  const passphrase = _sanitizePassphrase(rawPassphrase);

  // Get a fancy new Account object
  const account = await _initAccount(firstName, lastName, email);

  // Generate some secrets for the user base'd on password
  const authSecret = await crypt.deriveKey(
    passphrase,
    account.email,
    account.saltKey
  );
  const derivedSymmetricKey = await crypt.deriveKey(
    passphrase,
    account.email,
    account.saltEnc
  );

  // Generate public/private keypair and symmetric key for Account
  const { publicKey, privateKey } = await crypt.generateKeyPairJWK();
  const symmetricKeyJWK = await crypt.generateAES256Key();

  // Compute the verifier key and add it to the Account object
  account.verifier = computeVerifier(
    _getSrpParams(),
    Buffer.from(account.saltAuth, "hex"),
    Buffer.from(account.email, "utf8"),
    Buffer.from(authSecret, "hex")
  ).toString("hex");

  // Encode keypair
  const encSymmetricJWKMessage = crypt.encryptAES(
    derivedSymmetricKey,
    JSON.stringify(symmetricKeyJWK)
  );
  const encPrivateJWKMessage = crypt.encryptAES(
    symmetricKeyJWK,
    JSON.stringify(privateKey)
  );

  // Add keys to account
  account.publicKey = JSON.stringify(publicKey);
  account.encPrivateKey = JSON.stringify(encPrivateJWKMessage);
  account.encSymmetricKey = JSON.stringify(encSymmetricJWKMessage);

  const signupData = await util.post("/auth/signup", account);

  if (loginAfter) {
    await login(rawEmail, rawPassphrase, authSecret);
  }

  return signupData;
}

export function deleteAccount() {
  return util.del("/auth/delete-account");
}

export function signupAndLogin(
  firstName: string,
  lastName: string,
  rawEmail: string,
  rawPassphrase: string
) {
  return signup(firstName, lastName, rawEmail, rawPassphrase, true);
}

/**
 * Performs an SRP login. When useCookies is set to false, the server uses the
 * negotiated SRP K value to create a valid session token. When useCookies is
 * set to true, the SRP K value is discarded and a pseudo-random session cookie
 * is created upon login instead, using HTTP-only mode.
 *
 * authSecret never needs to be passed; it is only passed by other auth
 * functions when the authSecret value has already been computed for another
 * reason (such as during signup.)
 *
 * useCookies needs to be set to false if the client needs access to a valid
 * session token.
 *
 * @param rawEmail The raw e-mail identity.
 * @param rawPassphrase The raw passphrase.
 * @param authSecret If already calculated, the derived passphrase key.
 * @param useCookies If true, the server creates a psuedo-random session cookie.
 * @returns The SRP K value.
 */
export async function login(
  rawEmail: string,
  rawPassphrase: string,
  authSecret: string | null = null,
  useCookies = true
): Promise<string> {
  // ~~~~~~~~~~~~~~~ //
  // Sanitize Inputs //
  // ~~~~~~~~~~~~~~~ //

  const email = _sanitizeEmail(rawEmail);
  const passphrase = _sanitizePassphrase(rawPassphrase);

  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ //
  // Fetch Salt and Submit A To Server //
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ //

  const { saltKey, saltAuth } = await getAuthSalts(email);
  authSecret =
    authSecret || (await crypt.deriveKey(passphrase, email, saltKey));
  const secret1 = await crypt.srpGenKey();
  const c = new Client(
    _getSrpParams(),
    Buffer.from(saltAuth, "hex"),
    Buffer.from(email, "utf8"),
    Buffer.from(authSecret, "hex"),
    Buffer.from(secret1, "hex")
  );
  const srpA = c.computeA().toString("hex");
  const { sessionStarterId, srpB } = await util.post<{
    sessionStarterId: string;
    srpB: string;
  }>("/auth/login-a", { srpA, email });

  // ~~~~~~~~~~~~~~~~~~~~~ //
  // Compute and Submit M1 //
  // ~~~~~~~~~~~~~~~~~~~~~ //

  c.setB(Buffer.from(srpB, "hex"));
  const srpM1 = c.computeM1().toString("hex");
  const { srpM2 } = await util.post<{
    srpM2: string;
  }>("/auth/login-m1", {
    srpM1,
    sessionStarterId,
    useCookies
  });

  // ~~~~~~~~~~~~~~~~~~~~~~~~~ //
  // Verify Server Identity M2 //
  // ~~~~~~~~~~~~~~~~~~~~~~~~~ //

  c.checkM2(Buffer.from(srpM2, "hex"));

  // Return K
  return c.computeK().toString("hex");
}

export function subscribe(
  tokenId: string,
  planId: string,
  quantity: number,
  memo: string
) {
  return util.post("/api/billing/subscriptions", {
    token: tokenId,
    quantity: quantity,
    plan: planId,
    memo: memo
  });
}

export async function logout() {
  try {
    await util.post("/auth/logout");
  } catch (e) {
    // Not a huge deal if this fails, but we don't want it to prevent the
    // user from signing out.
    console.warn("Failed to logout", e);
  }
}

export async function cancelAccount() {
  await util.del("/api/billing/subscriptions");
}

export async function whoami() {
  return util.get<schema.WhoamiResponse>("/auth/whoami");
}

export async function keys() {
  return util.get<schema.APIKeysResponse>("/v1/keys");
}

export async function invoices() {
  return util.get<Invoice[]>("/api/billing/invoices");
}

export async function getInvoice(invoiceId: string) {
  return util.get<InvoiceLink>("/api/billing/invoices/" + invoiceId);
}

export async function verify() {
  return util.post("/auth/verify");
}

export async function billingDetails() {
  try {
    return await util.get<BillingDetails>("/api/billing/details");
  } catch (e) {
    return null;
  }
}

export function getAuthSalts(email: string) {
  return util.post<AuthSalts>("/auth/login-s", { email });
}

export async function changePasswordAndEmail(
  rawOldPassphrase: string,
  rawNewPassphrase: string,
  rawNewEmail: string,
  newFirstName: string,
  newLastName: string
) {
  // Sanitize inputs
  const oldPassphrase = _sanitizePassphrase(rawOldPassphrase);
  const newPassphrase = _sanitizePassphrase(rawNewPassphrase);
  const newEmail = _sanitizeEmail(rawNewEmail);

  // Fetch some things
  const { email: oldEmail, saltEnc, encSymmetricKey } = await whoami();
  const { saltKey, saltAuth } = await getAuthSalts(oldEmail);

  // Generate some secrets for the user base'd on password
  const oldSecret = await crypt.deriveKey(oldPassphrase, oldEmail, saltEnc);
  const newSecret = await crypt.deriveKey(newPassphrase, newEmail, saltEnc);
  const oldAuthSecret = await crypt.deriveKey(oldPassphrase, oldEmail, saltKey);
  const newAuthSecret = await crypt.deriveKey(newPassphrase, newEmail, saltKey);

  // Compute the verifier key and add it to the Account object
  const oldVerifier = oldPassphrase
    ? computeVerifier(
        _getSrpParams(),
        Buffer.from(saltAuth, "hex"),
        Buffer.from(oldEmail, "utf8"),
        Buffer.from(oldAuthSecret, "hex")
      ).toString("hex")
    : "";

  const newVerifier = newPassphrase
    ? computeVerifier(
        _getSrpParams(),
        Buffer.from(saltAuth, "hex"),
        Buffer.from(newEmail, "utf8"),
        Buffer.from(newAuthSecret, "hex")
      ).toString("hex")
    : "";

  // Re-encrypt existing keys with new secret
  const newEncSymmetricKeyJSON = crypt.recryptAES(
    oldSecret,
    newSecret,
    JSON.parse(encSymmetricKey)
  );
  const newEncSymmetricKey = JSON.stringify(newEncSymmetricKeyJSON);

  return util.post(`/auth/change-password`, {
    verifier: oldVerifier,
    newEmail,
    newFirstName,
    newLastName,
    encSymmetricKey: encSymmetricKey,
    newVerifier,
    newEncSymmetricKey
  });
}

export class NeedPassphraseError extends Error {
  constructor() {
    super("Passphrase required");

    // This trick is necessary to extend a native type from a transpiled ES6 class.
    Object.setPrototypeOf(this, NeedPassphraseError.prototype);
  }
}

export async function deriveSymmetricKey(
  whoami: Pick<schema.WhoamiResponse, "email" | "saltEnc">,
  rawPassphrase: string
): Promise<string> {
  const passPhrase = _sanitizePassphrase(rawPassphrase);
  const { email, saltEnc } = whoami;
  return await crypt.deriveKey(passPhrase, email, saltEnc);
}

async function getCachedPrivateKey(
  whoami: Pick<
    schema.WhoamiResponse,
    "email" | "saltEnc" | "encPrivateKey" | "encSymmetricKey"
  >,
  rawPassphrase: string | null
): Promise<JsonWebKey> {
  let privateKey: string | null = null;

  if (rawPassphrase !== null) {
    // We have a raw passphrase? Derive it from the passphrase.
    const secret = await deriveSymmetricKey(whoami, rawPassphrase);
    const { encPrivateKey, encSymmetricKey } = whoami;

    let symmetricKey: string;
    try {
      symmetricKey = crypt.decryptAES(secret, JSON.parse(encSymmetricKey));
    } catch (err) {
      console.log("Failed to decrypt wrapped private key", err);
      throw new Error("Invalid password");
    }

    privateKey = crypt.decryptAES(
      JSON.parse(symmetricKey),
      JSON.parse(encPrivateKey)
    );
    try {
      window.sessionStorage.setItem("privateKey", privateKey);
    } catch (err) {
      console.log("Failed to store private key into cache", err);
    }
  } else {
    // Otherwise, try to get it from the cache.
    try {
      privateKey = window.sessionStorage.getItem("privateKey");
    } catch (err) {
      console.log("Failed to fetch private key from cache", err);
    }

    if (privateKey === null) {
      throw new NeedPassphraseError();
    }
  }

  return JSON.parse(privateKey) as JsonWebKey;
}

export async function inviteToTeam(
  teamId: string,
  emailToInvite: string,
  rawPassphrase: string | null
) {
  // Ask the server what we need to do to invite the member
  const { data, errors } = await util.post<{
    data: {
      teamAddInstructions: {
        accountId: string;
        publicKey: string;
        projectKeys: {
          projectId: string;
          encSymmetricKey: string;
        }[];
      };
    };
    errors: Error[];
  }>(`/graphql?teamAddInstructions`, {
    variables: {
      teamId,
      email: emailToInvite
    },
    query: `
      query ($email: String!, $teamId: ID!) {
         teamAddInstructions(email: $email, teamId: $teamId) {
            accountId
            publicKey

            projectKeys {
              projectId
              encSymmetricKey
            }
         }
      }
    `
  });

  if (errors && errors.length) {
    console.error("Failed to get instructions for adding to team", errors);
    throw new Error(errors[0].message);
  }

  const { accountId, publicKey, projectKeys } = data.teamAddInstructions;

  // Compute keys necessary to invite the member
  const privateKeyJWK = await getCachedPrivateKey(
    await whoami(),
    rawPassphrase
  );

  // Build the invite data request
  const nextKeys = [];
  for (const instruction of projectKeys) {
    const publicKeyJWK = JSON.parse(publicKey);
    const encSymmetricKey = crypt.recryptRSAWithJWK(
      privateKeyJWK,
      publicKeyJWK,
      instruction.encSymmetricKey
    );
    nextKeys.push({
      encSymmetricKey,
      projectId: instruction.projectId
    });
  }

  // Actually invite the member
  // Ask the server what we need to do to invite the member
  const { errors: errorsMutation } = await util.post<{
    errors: Error[];
  }>(`/graphql?teamAdd`, {
    variables: {
      accountId,
      teamId,
      keys: nextKeys
    },
    query: `
      mutation ($accountId: ID!, $teamId: ID!, $keys: [TeamAddKeyInput!]!) {
        teamAdd(accountId: $accountId, teamId: $teamId, keys: $keys)
      }
    `
  });

  if (errorsMutation && errorsMutation.length) {
    console.error("Failed adding user to team", errorsMutation);
    throw new Error(errorsMutation[0].message);
  }
}

export async function createTeam() {
  return util.post(`/api/teams`);
}

export async function leaveTeam(teamId: string) {
  const { errors } = await util.post<{
    errors: Error[];
  }>(`/graphql?teamLeave`, {
    variables: {
      teamId
    },
    query: `
      mutation ($teamId: ID!) {
        teamLeave(teamId: $teamId)
      }
    `
  });

  if (errors && errors.length) {
    console.error("Failed to leave team", errors);
    throw new Error(errors[0].message);
  }
}

export async function changeTeamAdminStatus(
  teamId: string,
  accountId: string,
  isAdmin: boolean
) {
  await util.patch(`/api/teams/${teamId}/admin-status`, {
    isAdmin,
    accountId
  });
}

export async function removeFromTeam(teamId: string, accountId: string) {
  const { errors } = await util.post<{
    errors: Error[];
  }>(`/graphql?teamRemove`, {
    variables: {
      accountIdToRemove: accountId,
      teamId
    },
    query: `
      mutation ($accountIdToRemove: ID!, $teamId: ID!) {
        teamRemove(accountIdToRemove: $accountIdToRemove, teamId: $teamId)
      }
    `
  });

  if (errors && errors.length) {
    console.error("Failed to remove member", errors);
    throw new Error(errors[0].message);
  }
}

export async function changeTeamName(teamId: string, name: string) {
  return util.patch(`/api/teams/${teamId}`, { name });
}

export async function listTeams() {
  return util.get<Team[]>("/api/teams");
}

export async function githubOauthConfig() {
  return util.get<schema.GithubOAuthConfigResponse>(
    "/v1/oauth/github/config",
    false
  );
}

export async function updateEmailSubscription(unsubscribed: boolean) {
  if (unsubscribed) {
    return util.post(`/v1/email/unsubscribe`);
  } else {
    return util.post(`/v1/email/subscribe`);
  }
}

// ~~~~~~~~~~~~~~~~ //
// Helper Functions //
// ~~~~~~~~~~~~~~~~ //

async function _initAccount(
  firstName: string,
  lastName: string,
  email: string
): Promise<Account> {
  return {
    email,
    firstName,
    lastName,
    id: await crypt.generateAccountId(),
    saltEnc: await crypt.getRandomHex(),
    saltAuth: await crypt.getRandomHex(),
    saltKey: await crypt.getRandomHex()
  };
}

function _getSrpParams() {
  return params[2048];
}

function _sanitizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function _sanitizePassphrase(passphrase: string) {
  return unorm.nfkd(passphrase.trim());
}
