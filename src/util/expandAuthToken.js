import claimsJWT from "./decode-verify-jwt.js";

/**
 * Given an Authorization Bearer token it returns a JSON object with user
 * properties and claims found
 *
 * @name expandAuthToken
 * @method
 * @summary Expands an Auth token
 * @param {String} token Auth token
 * @returns {Object} JSON object
 */
export default async function expandAuthToken(token) {
  const response = await claimsJWT(token);

  if (!response.ok) throw new Error("Error introspecting token");

  return response.json();
}
