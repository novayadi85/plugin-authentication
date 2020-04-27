import { promisify } from 'util';
import Axios from 'axios';
import jsonwebtoken from 'jsonwebtoken';
import config from "../config.js";

const {
  AWS_POOL_ID,
  AWS_REGION
} = config;

import jwkToPem from 'jwk-to-pem';

const cognitoPoolId = AWS_POOL_ID || '';
if (!cognitoPoolId) {
  throw new Error('env var required for cognito pool');
}
const cognitoIssuer = `https://cognito-idp.${AWS_REGION}.amazonaws.com/${cognitoPoolId}`;
let cacheKeys;
const getPublicKeys = async () => {
  if (!cacheKeys) {
    const url = `${cognitoIssuer}/.well-known/jwks.json`;
    const publicKeys = await Axios.default.get(url);
    cacheKeys = publicKeys.data.keys.reduce((agg, current) => {
      const pem = jwkToPem(current);
      agg[current.kid] = { instance: current, pem };
      return agg;
    }, {});
    return cacheKeys;
  }
  else {
    return cacheKeys;
  }
};
const verifyPromised = promisify(jsonwebtoken.verify.bind(jsonwebtoken));

export default async (request) => {
  let result;
  try {
    console.log(`user claim verfiy invoked for ${JSON.stringify(request)}`);
    const token = request.token;
    const tokenSections = (token || '').split('.');
    if (tokenSections.length < 2) {
      throw new Error('requested token is invalid');
    }
    const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
    const header = JSON.parse(headerJSON);
    const keys = await getPublicKeys();
    const key = keys[header.kid];
    if (key === undefined) {
      throw new Error('claim made for unknown kid');
    }
    const claim = await verifyPromised(token, key.pem);
    const currentSeconds = Math.floor((new Date()).valueOf() / 1000);
    if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
      throw new Error('claim is expired or invalid');
    }
    if (claim.iss !== cognitoIssuer) {
      throw new Error('claim issuer is invalid');
    }
    if (claim.token_use !== 'access') {
      throw new Error('claim use is not access');
    }
    console.log(`claim confirmed for ${claim.username}`);
    result = { ...claim, isValid: true };
  }
  catch (error) {
    result = { userName: '', clientId: '', error, isValid: false };
  }
  return result;
};

