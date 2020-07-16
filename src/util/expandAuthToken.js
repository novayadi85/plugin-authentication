import claimsCognito from "./decode-verify-jwt.js";
/**
 * Given an Authorization Bearer token it returns a JSON object with user
 * properties and claims found
 *
 * @name cognitoAuthToken
 * @method
 * @summary Expands an Auth token
 * @param {String} token Auth token
 * @returns {Object} JSON object
 */
export default async function cognitoAuthToken(token) {
  const payloads = await claimsCognito({token});

  if (!payloads.isValid) throw new Error("Error introspecting token");

  return payloads;
}
