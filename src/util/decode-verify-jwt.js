
import jwksRsa from "jwks-rsa";
import jsonwebtoken from "jsonwebtoken";
import config from "../config.js";

const {
  AWS_POOL_IDENTITY_POOL,
  AWS_CLIENT_ID,
  AWS_POOL_ID,
  AWS_REGION
} = config;


const decodeTokenHeader = (token) => {
  const [headerEncoded] = token.split(".");
  // const buff = new Buffer(headerEncoded, 'base64');
  let buff; const encoding = "base64";
  if (Buffer.from && Buffer.from !== Uint8Array.from) {
    buff = Buffer.from(headerEncoded, encoding);
  } else {
    if (typeof headerEncoded === "number") {
      throw new Error('The "size" argument must be not of type number.');
    }
    buff = Buffer.from(headerEncoded, encoding);
  }
  const text = buff.toString("ascii");
  return JSON.parse(text);
};

const verifyJsonWebTokenSignature = (token, jsonWebKey, clbk) => {
  jsonwebtoken.verify(token, jsonWebKey, { algorithms: ["RS256"] }, (err, decodedToken) => clbk(err, decodedToken));
};

const verifyCognitoToken = async (token, decoded) => {
  try {
    const decode = new Promise((resolve, reject) => {
      const header = decodeTokenHeader(token);
      const client = jwksRsa({
        jwksUri: `https://cognito-idp.${decoded.AWS_REGION}.amazonaws.com/${decoded.AWS_POOL_ID}/.well-known/jwks.json`
      });

      client.getSigningKey(header.kid, async (error, key) => {
        if (error) {
          resolve({
            error: true,
            message: error.message
          });
        }
        if (typeof key === "undefined" || key === undefined) {
          reject(new Error("fail"));
        } else {
          const signingKey = key.publicKey || key.rsaPublicKey;
          verifyJsonWebTokenSignature(token, signingKey, (err, decodedToken) => {
            if (err) {
              resolve({
                error: true,
                message: err.message
              });
            } else {
              resolve({ error: false, payloads: decodedToken });
            }
          });
        }
      });
    });

    return await decode.then(async (value) =>
    // console.log(value)
      value);
  } catch (error) {
    return { error: true };
  }
};


const claimRace = async (token) => {
  const configs = [
    {
      AWS_POOL_ID,
      AWS_CLIENT_ID,
      AWS_POOL_IDENTITY_POOL,
      AWS_REGION
    }
  ];

  return Promise.race(configs.map((item) => verifyCognitoToken(token, item))).then((value) =>
    value);
};

export default async (token) => {
  let tokenize = {};
  let isAuthenticated = false;
  if (token) {
    tokenize = await claimRace(token);
    const { error } = tokenize;
    if (error !== true) {
      // console.log(error)
      isAuthenticated = true;
    }
  }

  return {
    ...tokenize,
    ok: isAuthenticated
  };
};

