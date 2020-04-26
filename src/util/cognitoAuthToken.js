import claimsJWT from "./decode-verify-jwt.js";
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
  /*
  const response = await fetch(HYDRA_OAUTH2_INTROSPECT_URL, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    method: "POST",
    body: `token=${encodeURIComponent(token)}`
  });
  */

  const { ok, payloads } = await claimsJWT(token);
  if (!ok) throw new Error("Error introspecting token");

  return {
    ...payloads,
    ok
  };
}
