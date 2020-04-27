/* eslint-disable require-jsdoc */
/* eslint-disable no-console */
import Logger from "@reactioncommerce/logger";
import AWS from "aws-sdk";
import config from "../config.js";
import expandAuthToken from "./expandAuthToken.js";

const {
  AWS_POOL_IDENTITY_POOL,
  AWS_REGION
} = config;

AWS.config.update({
  region: AWS_REGION
});

AWS.config.credentials = new AWS.CognitoIdentityCredentials({
  IdentityPoolId: `${AWS_POOL_IDENTITY_POOL}`,
  region: AWS_REGION
});

/**
 * Given an Authorization Bearer token and the current context, returns the user document
 * for that token after performing token checks.
 *
 * If the provided token is not associated with any user or is associated but is
 * expired, this function throws an "access-denied" ReactionError.
 *
 * @name getUserFromAuthToken
 * @method
 * @memberof GraphQL
 * @summary Looks up a user by token
 * @param {String} loginToken Auth token
 * @param {Object} context An object with request-specific state
 * @returns {Object} The user associated with the token
 */

async function getCurrentUser(token) {
  const cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider();
  const params = {
    AccessToken: token
  };

  return cognitoidentityserviceprovider.getUser(params).promise();
}

const attributesToObject = (attributes) => {
  const obj = {};
  if (attributes) {
    attributes.map(attribute => {
      if (attribute.Value === 'true') {
        obj[attribute.Name] = true;
      } else if (attribute.Value === 'false') {
        obj[attribute.Name] = false;
      } else {
        obj[attribute.Name] = attribute.Value;
      }
    });
  }
  return obj;
}

async function getUserFromAuthToken(loginToken) {
  const token = loginToken.replace(/bearer\s/gi, "");

  const tokenObj = await expandAuthToken(token);

  if (!tokenObj) {
    Logger.debug("No token object");
    throw new Error("No token object");
  }

  console.log(tokenObj);

  const { isValid: active, token_use: tokenType } = tokenObj;

  if (!active) {
    Logger.debug("Bearer token is expired");
    throw new Error("Bearer token is expired");
  }

  if (tokenType !== "access") {
    Logger.error("Bearer token is not an access token");
    throw new Error("Bearer token is not an access token");
  }

  // const currentUser = await context.collections.users.findOne({ _id });

  const activeUser = await getCurrentUser(token);

  if (!activeUser) {
    Logger.error("Bearer token specifies a user ID that does not exist");
    throw new Error("Bearer token specifies a user ID that does not exist");
  }


  const { UserAttributes } = activeUser;

  let user = attributesToObject(UserAttributes);

  user = {
    ...user,
    emails: [
      {
        address: user.email,
        verified: (user.email_verified === "true"),
        provides: "cognito"
      }
    ],
    name: `${user.given_name} ${user.family_name}`,
    profile: {
      firstName: user.given_name,
      lastName: user.family_name
    },
    _id: activeUser.Username
  };

  return user;
}

export default getUserFromAuthToken;
