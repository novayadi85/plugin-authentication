import envalid from "envalid";

const { str } = envalid;

export default envalid.cleanEnv(process.env, {
  HYDRA_OAUTH2_INTROSPECT_URL: str({ devDefault: "http://hydra:4445/oauth2/introspect" }),
  AWS_POOL_IDENTITY_POOL: str({
    desc: "AWS Pool Identity",
    devDefault: ""
  }),
  AWS_ACCESS_KEY_ID: str({
    desc: "AWS ACESS key id",
    devDefault: ""
  }),
  AWS_SECRET_KEY: str({
    desc: "AWS Secret key",
    devDefault: ""
  }),
  AWS_REGION: str({
    desc: "Region Id",
    devDefault: ""
  }),
  AWS_POOL_ID: str({
    desc: "A private Pool ID",
    devDefault: ""
  }),
  AWS_CLIENT_ID: str({
    desc: "AWS Client ID",
    devDefault: ""
  })
}, {
  dotEnvPath: "./.env"
});
