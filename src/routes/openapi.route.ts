import { Router, Request, Response } from 'express';
import { config } from '../utils/config';
export const openapiRouter = Router();
export const docsRouter = Router();

const docsHtml = `<!DOCTYPE html>
<html>
<head>
  <title>Token Trust API — Docs</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; color: #333; }
    h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
    h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #eee; padding-bottom: 0.5rem; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 8px; }
    .get { background: #e3f2fd; color: #1565c0; }
    .post { background: #e8f5e9; color: #2e7d32; }
    .endpoint { background: #f5f5f5; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
    .path { font-family: monospace; font-size: 1rem; font-weight: bold; }
    .desc { color: #666; font-size: 0.9rem; margin-top: 0.25rem; }
    pre { background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 13px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 8px; }
    th, td { text-align: left; padding: 8px; border: 1px solid #ddd; }
    th { background: #f5f5f5; }
  </style>
</head>
<body>
  <h1>Token Trust API</h1>
  <p>Check any token or smart contract for honeypots, scam patterns and security risks — Ethereum, BSC and Solana.</p>
  <p><strong>Base URL:</strong> <code>https://token-trust-api.onrender.com</code></p>

  <h2>Quick start</h2>
  <pre>const res = await fetch("https://token-trust-api.onrender.com/v1/check?contract=0x...");
const { decision, trust_score, flags } = await res.json();
if (decision === "avoid") warnUser("High risk token detected");
else if (decision === "caution") warnUser("Some risk signals — research before investing");</pre>

  <h2>Endpoints</h2>
  <div class="endpoint">
    <div><span class="badge get">GET</span><span class="path">/v1/check</span></div>
    <div class="desc">Check a single token via query parameter</div>
    <pre>curl "https://token-trust-api.onrender.com/v1/check?contract=0x..."</pre>
  </div>
  <div class="endpoint">
    <div><span class="badge post">POST</span><span class="path">/v1/check</span></div>
    <div class="desc">Check a single token via request body</div>
    <pre>curl -X POST https://token-trust-api.onrender.com/v1/check \\
  -H "Content-Type: application/json" \\
  -d '{"contract": "0x...", "chain": "ethereum"}'</pre>
  </div>
  <div class="endpoint">
    <div><span class="badge post">POST</span><span class="path">/v1/check/batch</span></div>
    <div class="desc">Check up to 10 tokens in one request</div>
    <pre>curl -X POST https://token-trust-api.onrender.com/v1/check/batch \\
  -H "Content-Type: application/json" \\
  -d '{"tokens": [{"contract": "0x..."}, {"contract": "0x..."}]}'</pre>
  </div>

  <h2>Risk flags</h2>
  <table>
    <tr><th>Flag</th><th>Meaning</th></tr>
    <tr><td>honeypot</td><td>You can buy but cannot sell — classic scam</td></tr>
    <tr><td>owner_can_mint</td><td>Owner can create unlimited new tokens</td></tr>
    <tr><td>owner_can_blacklist</td><td>Owner can prevent you from selling</td></tr>
    <tr><td>slippage_modifiable</td><td>Owner can change buy/sell tax at any time</td></tr>
    <tr><td>high_sell_tax</td><td>Sell tax over 10% — likely a trap</td></tr>
    <tr><td>not_open_source</td><td>Contract code is hidden — cannot be audited</td></tr>
    <tr><td>low_liquidity</td><td>Under $10,000 liquidity — high price impact</td></tr>
    <tr><td>creator_holds_majority</td><td>Creator holds over 50% of supply</td></tr>
  </table>

  <h2>OpenAPI Spec</h2>
  <p><a href="/openapi.json">Download openapi.json</a></p>
</body>
</html>`;

docsRouter.get('/', (_req: Request, res: Response) => { res.setHeader('Content-Type', 'text/html'); res.send(docsHtml); });

openapiRouter.get('/', (_req: Request, res: Response) => {
  res.status(200).json({
    openapi: '3.0.3',
    info: { title: 'Token Trust API', version: '1.0.0', description: 'Check any token or smart contract for honeypots, scam patterns and security risks.' },
    servers: [{ url: 'https://token-trust-api.onrender.com', description: 'Production' }, { url: `http://localhost:${config.server.port}`, description: 'Local' }],
    paths: {
      '/v1/health': { get: { summary: 'Health check', operationId: 'getHealth', responses: { '200': { description: 'OK' } } } },
      '/v1/check': {
        get: { summary: 'Check a token via GET', operationId: 'checkGet', parameters: [{ name: 'contract', in: 'query', required: true, schema: { type: 'string' } }, { name: 'chain', in: 'query', schema: { type: 'string', enum: ['ethereum', 'bsc', 'solana'] } }], responses: { '200': { description: 'Token trust result' } } },
        post: { summary: 'Check a token via POST', operationId: 'checkPost', requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/CheckRequest' } } } }, responses: { '200': { description: 'Token trust result' } } },
      },
      '/v1/check/batch': { post: { summary: 'Check up to 10 tokens', operationId: 'checkBatch', requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/BatchRequest' } } } }, responses: { '200': { description: 'Batch results' } } } },
    },
    components: {
      schemas: {
        CheckRequest: { type: 'object', required: ['contract'], properties: { contract: { type: 'string', example: '0x...' }, chain: { type: 'string', enum: ['ethereum', 'bsc', 'solana'], default: 'ethereum' } } },
        BatchRequest: { type: 'object', required: ['tokens'], properties: { tokens: { type: 'array', items: { $ref: '#/components/schemas/CheckRequest' }, minItems: 1, maxItems: 10 } } },
      },
    },
  });
});
