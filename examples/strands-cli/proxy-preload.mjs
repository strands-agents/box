// Send the AWS SDK's requests through the box's egress gateway. Load with `node --import`.
import { createRequire } from "node:module";

// Find modules the way the CLI does, from the CLI's own script.
const require = createRequire(process.argv[1]);

if (process.env.HTTPS_PROXY) {
  // Make every Node connection use the proxy settings from the environment.
  const http = require("node:http");
  const https = require("node:https");
  const proxyEnv = process.env;
  const HttpAgent = http.Agent;
  const HttpsAgent = https.Agent;
  http.Agent = class extends HttpAgent {
    constructor(options) {
      super({ proxyEnv, ...options });
    }
  };
  https.Agent = class extends HttpsAgent {
    constructor(options) {
      super({ proxyEnv, ...options });
    }
  };

  // Bedrock calls use HTTP/2, which ignores these proxy settings. Use HTTP/1.1.
  const handlers = require("@smithy/node-http-handler");
  handlers.NodeHttp2Handler = handlers.NodeHttpHandler;
}
