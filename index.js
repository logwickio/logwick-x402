const express = require("express");
const { paymentMiddleware, x402ResourceServer } = require("@x402/express");
const { ExactEvmScheme } = require("@x402/evm/exact/server");
const { HTTPFacilitatorClient } = require("@x402/core/server");
const { bazaarResourceServerExtension, declareDiscoveryExtension } = require("@x402/extensions");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const PAYTO = process.env.PAYTO_ADDRESS || "0x19f50adb4a5b41802594814f9ad51f26324ee90e";
const PORT = process.env.PORT || 4021;

async function makeJWT(method, urlPath) {
  const { SignJWT, importPKCS8 } = await import("jose");
  const keyName = process.env.CDP_API_KEY_NAME;
  const rawKey = process.env.CDP_API_KEY_PRIVATE_KEY;
  if (!keyName || !rawKey) throw new Error("Missing CDP credentials");

  const keyBuffer = Buffer.from(rawKey, "base64");
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const pkcs8Key = Buffer.concat([prefix, keyBuffer]);
  const pemKey = "-----BEGIN PRIVATE KEY-----\n" + pkcs8Key.toString("base64") + "\n-----END PRIVATE KEY-----";
  const signingKey = await importPKCS8(pemKey, "EdDSA");

  const uri = `${method} api.cdp.coinbase.com${urlPath}`;
  return await new SignJWT({ iss: "cdp", nbf: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 120, sub: keyName, uri })
    .setProtectedHeader({ alg: "EdDSA", kid: keyName, nonce: crypto.randomBytes(16).toString("hex") })
    .sign(signingKey);
}

const facilitatorClient = new HTTPFacilitatorClient({
  url: "https://api.cdp.coinbase.com/platform/v2/x402",
  createAuthHeaders: async () => ({
    verify: { Authorization: `Bearer ${await makeJWT("POST", "/platform/v2/x402/verify")}` },
    settle: { Authorization: `Bearer ${await makeJWT("POST", "/platform/v2/x402/settle")}` },
    supported: { Authorization: `Bearer ${await makeJWT("GET", "/platform/v2/x402/supported")}` },
  })
});

const resourceServer = new x402ResourceServer(facilitatorClient);
resourceServer.register("eip155:8453", new ExactEvmScheme());
resourceServer.registerExtension(bazaarResourceServerExtension);

const bazaarExtension = {
  info: {
    input: {
      type: "http",
      method: "POST",
      body: {},
      bodyType: "json",
    },
    output: {
      type: "json",
      example: {
        id: "550e8400-e29b-41d4-a716-446655440000",
        timestamp: "2026-05-04T12:00:00.000Z",
        status: "ingested",
      },
    },
  },
  schema: {
    properties: {
      input: {
        properties: {
          method: {
            type: "string",
            enum: ["POST"],
          },
        },
        required: ["method"],
      },
    },
  },
};

// Debug middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path} - payment header: ${!!req.headers['payment-signature']}`);
  next();
});

app.use(
  paymentMiddleware(
    {
      "POST /agent-log": {
        accepts: [{
          scheme: "exact",
          price: "$0.001",
          network: "eip155:8453",
          payTo: PAYTO,
        }],
        description: "Ingest one AI agent audit log entry to Logwick.",
        mimeType: "application/json",
        extensions: { bazaar: bazaarExtension },
      },
    },
    resourceServer,
  ),
);

app.post("/agent-log", async (req, res) => {
  const { agent, action, status = "success", input, output, tokens, latency_ms, cost_usd, user, tags = [], metadata = {} } = req.body || {};
  if (!agent || !action) return res.status(400).json({ error: "agent and action are required" });

  try {
    const response = await fetch(`${process.env.LOGWICK_API_URL || "https://logwick.io"}/api/v1/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.LOGWICK_X402_API_KEY}`,
      },
      body: JSON.stringify({ agent, action, status, input, output, tokens, latency_ms, cost_usd, user, tags, metadata }),
    });
    const data = await response.json();
    return res.status(200).json({ id: data.id, timestamp: data.timestamp || new Date().toISOString(), status: "ingested" });
  } catch (err) {
    console.error("Forward error:", err);
    return res.status(500).json({ error: "Failed to store log" });
  }
});

app.get("/health", (req, res) => res.json({ status: "ok" }));
app.listen(PORT, () => console.log(`x402 server running on port ${PORT}`));
