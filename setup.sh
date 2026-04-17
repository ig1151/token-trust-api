#!/bin/bash
set -e

echo "🚀 Building Token Trust API..."

cat > src/types/index.ts << 'HEREDOC'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type TokenDecision = 'safe' | 'caution' | 'avoid';
export type Chain = 'ethereum' | 'bsc' | 'solana';

export interface CheckRequest {
  contract: string;
  chain?: Chain;
}

export interface BatchRequest {
  tokens: CheckRequest[];
}

export interface TokenSecurity {
  is_honeypot: boolean;
  honeypot_with_same_creator: boolean;
  owner_can_mint: boolean;
  owner_can_pause: boolean;
  owner_can_blacklist: boolean;
  has_proxy_contract: boolean;
  is_open_source: boolean;
  is_verified: boolean;
  buy_tax: number;
  sell_tax: number;
  transfer_pausable: boolean;
  slippage_modifiable: boolean;
  is_anti_whale: boolean;
}

export interface LiquidityInfo {
  total_liquidity_usd?: number;
  liquidity_locked: boolean;
  lock_percentage?: number;
  dex_list: string[];
}

export interface TokenInfo {
  name?: string;
  symbol?: string;
  total_supply?: string;
  holder_count?: number;
  creator_address?: string;
  creator_percent?: number;
  owner_address?: string;
  owner_percent?: number;
  top_10_holders_percent?: number;
}

export interface TokenTrustResponse {
  id: string;
  contract: string;
  chain: Chain;
  trust_score: number;
  risk_level: RiskLevel;
  decision: TokenDecision;
  flags: string[];
  recommendation: string;
  security: TokenSecurity;
  liquidity?: LiquidityInfo;
  token_info?: TokenInfo;
  summary: string;
  latency_ms: number;
  created_at: string;
}
HEREDOC

cat > src/utils/config.ts << 'HEREDOC'
import 'dotenv/config';
function required(key: string): string { const val = process.env[key]; if (!val) throw new Error(`Missing required env var: ${key}`); return val; }
function optional(key: string, fallback: string): string { return process.env[key] ?? fallback; }
export const config = {
  anthropic: { apiKey: required('ANTHROPIC_API_KEY'), model: optional('ANTHROPIC_MODEL', 'claude-sonnet-4-20250514') },
  etherscan: { apiKey: required('ETHERSCAN_API_KEY') },
  server: { port: parseInt(optional('PORT', '3000'), 10), nodeEnv: optional('NODE_ENV', 'development'), apiVersion: optional('API_VERSION', 'v1') },
  rateLimit: { windowMs: parseInt(optional('RATE_LIMIT_WINDOW_MS', '60000'), 10), maxFree: parseInt(optional('RATE_LIMIT_MAX_FREE', '10'), 10), maxPro: parseInt(optional('RATE_LIMIT_MAX_PRO', '500'), 10) },
  logging: { level: optional('LOG_LEVEL', 'info') },
} as const;
HEREDOC

cat > src/utils/logger.ts << 'HEREDOC'
export const logger = {
  info: (obj: unknown, msg?: string) => console.log(JSON.stringify({ level: 'info', ...(typeof obj === 'object' ? obj : { data: obj }), msg })),
  warn: (obj: unknown, msg?: string) => console.warn(JSON.stringify({ level: 'warn', ...(typeof obj === 'object' ? obj : { data: obj }), msg })),
  error: (obj: unknown, msg?: string) => console.error(JSON.stringify({ level: 'error', ...(typeof obj === 'object' ? obj : { data: obj }), msg })),
};
HEREDOC

cat > src/utils/validation.ts << 'HEREDOC'
import Joi from 'joi';

export function detectChain(contract: string): 'ethereum' | 'bsc' | 'solana' | 'unknown' {
  if (/^0x[a-fA-F0-9]{40}$/.test(contract)) return 'ethereum';
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(contract)) return 'solana';
  return 'unknown';
}

export const checkSchema = Joi.object({
  contract: Joi.string().required().messages({ 'any.required': 'contract address is required' }),
  chain: Joi.string().valid('ethereum', 'bsc', 'solana').optional(),
});

export const batchSchema = Joi.object({
  tokens: Joi.array().items(checkSchema).min(1).max(10).required().messages({ 'array.max': 'Batch accepts a maximum of 10 tokens per request' }),
});
HEREDOC

cat > src/utils/goplus.ts << 'HEREDOC'
import https from 'https';
import { logger } from './logger';

const GOPLUS_BASE = 'api.gopluslabs.io';

function get(path: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    https.get(`https://${GOPLUS_BASE}${path}`, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { reject(new Error('Invalid JSON')); } });
    }).on('error', reject);
  });
}

// Chain IDs for GoPlus
const CHAIN_IDS: Record<string, string> = {
  ethereum: '1',
  bsc: '56',
  solana: 'solana',
};

export async function getTokenSecurity(contract: string, chain: string) {
  const chainId = CHAIN_IDS[chain] ?? '1';
  try {
    const endpoint = chain === 'solana'
      ? `/api/v1/solana/token_security?contract_addresses=${contract}`
      : `/api/v1/token_security/${chainId}?contract_addresses=${contract}`;
    const data = await get(endpoint);
    if (data.code !== 1) { logger.warn({ contract, chain, code: data.code }, 'GoPlus returned non-success'); return null; }
    const result = data.result as Record<string, unknown>;
    return result[contract.toLowerCase()] ?? result[contract] ?? null;
  } catch (err) { logger.warn({ contract, chain, err }, 'GoPlus request failed'); return null; }
}

export async function getDexInfo(contract: string, chain: string) {
  if (chain === 'solana') return null;
  const chainId = CHAIN_IDS[chain] ?? '1';
  try {
    const data = await get(`/api/v1/dex_check/${chainId}?contract_addresses=${contract}`);
    if (data.code !== 1) return null;
    const result = data.result as Record<string, unknown>;
    return result[contract.toLowerCase()] ?? result[contract] ?? null;
  } catch (err) { logger.warn({ contract, chain, err }, 'GoPlus DEX request failed'); return null; }
}
HEREDOC

cat > src/services/token.service.ts << 'HEREDOC'
import Anthropic from '@anthropic-ai/sdk';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../utils/config';
import { logger } from '../utils/logger';
import { getTokenSecurity, getDexInfo } from '../utils/goplus';
import { detectChain } from '../utils/validation';
import type { CheckRequest, TokenTrustResponse, RiskLevel, TokenDecision, Chain } from '../types/index';

const client = new Anthropic({ apiKey: config.anthropic.apiKey });

function getRiskLevel(score: number): RiskLevel { return score >= 80 ? 'critical' : score >= 50 ? 'high' : score >= 20 ? 'medium' : 'low'; }
function getDecision(score: number): TokenDecision { return score >= 60 ? 'avoid' : score >= 30 ? 'caution' : 'safe'; }

function safeNum(val: unknown, fallback = 0): number {
  const n = parseFloat(String(val ?? fallback));
  return isNaN(n) ? fallback : n;
}

function safeBool(val: unknown): boolean {
  if (typeof val === 'boolean') return val;
  if (typeof val === 'string') return val === '1' || val.toLowerCase() === 'true';
  if (typeof val === 'number') return val === 1;
  return false;
}

export async function checkToken(req: CheckRequest): Promise<TokenTrustResponse> {
  const id = `token_${uuidv4().replace(/-/g, '').slice(0, 12)}`;
  const t0 = Date.now();
  const contract = req.contract.trim();

  // Auto-detect chain
  let chain: Chain;
  if (req.chain) {
    chain = req.chain;
  } else {
    const detected = detectChain(contract);
    chain = detected === 'unknown' ? 'ethereum' : detected as Chain;
  }

  logger.info({ id, contract, chain }, 'Starting token trust check');

  const [securityData, dexData] = await Promise.all([
    getTokenSecurity(contract, chain),
    getDexInfo(contract, chain),
  ]);

  const flags: string[] = [];
  let riskScore = 0;

  // Parse security data
  const sec = securityData as Record<string, unknown> | null;
  const dex = dexData as Record<string, unknown> | null;

  const isHoneypot = safeBool(sec?.is_honeypot);
  const honeypotSameCreator = safeBool(sec?.honeypot_with_same_creator);
  const ownerCanMint = safeBool(sec?.is_mintable);
  const ownerCanPause = safeBool(sec?.transfer_pausable);
  const ownerCanBlacklist = safeBool(sec?.is_blacklisted);
  const hasProxy = safeBool(sec?.is_proxy);
  const isOpenSource = safeBool(sec?.is_open_source);
  const isVerified = isOpenSource;
  const buyTax = safeNum(sec?.buy_tax) * 100;
  const sellTax = safeNum(sec?.sell_tax) * 100;
  const slippageModifiable = safeBool(sec?.slippage_modifiable);
  const isAntiWhale = safeBool(sec?.is_anti_whale);
  const transferPausable = safeBool(sec?.transfer_pausable);

  // Risk scoring
  if (isHoneypot) { riskScore += 90; flags.push('honeypot'); }
  if (honeypotSameCreator) { riskScore += 40; flags.push('honeypot_creator_pattern'); }
  if (ownerCanMint) { riskScore += 30; flags.push('owner_can_mint'); }
  if (ownerCanBlacklist) { riskScore += 25; flags.push('owner_can_blacklist'); }
  if (ownerCanPause) { riskScore += 20; flags.push('owner_can_pause'); }
  if (slippageModifiable) { riskScore += 30; flags.push('slippage_modifiable'); }
  if (hasProxy) { riskScore += 15; flags.push('proxy_contract'); }
  if (!isOpenSource) { riskScore += 20; flags.push('not_open_source'); }
  if (sellTax > 10) { riskScore += 25; flags.push(`high_sell_tax_${Math.round(sellTax)}pct`); }
  else if (sellTax > 5) { riskScore += 10; flags.push(`elevated_sell_tax_${Math.round(sellTax)}pct`); }
  if (buyTax > 10) { riskScore += 15; flags.push(`high_buy_tax_${Math.round(buyTax)}pct`); }

  // Holder concentration
  const top10Percent = safeNum(sec?.holder_count ? (sec?.top10_holder_rate ?? 0) : 0) * 100;
  const creatorPercent = safeNum(sec?.creator_percent) * 100;
  const ownerPercent = safeNum(sec?.owner_percent) * 100;

  if (creatorPercent > 50) { riskScore += 30; flags.push('creator_holds_majority'); }
  else if (creatorPercent > 20) { riskScore += 15; flags.push('creator_high_concentration'); }
  if (top10Percent > 80) { riskScore += 20; flags.push('top10_holders_dominant'); }

  // Liquidity
  const dexList = (dex?.dex as { name: string }[] ?? []).map(d => d.name).filter(Boolean);
  const totalLiquidity = safeNum(dex?.liquidity);
  const liquidityLocked = safeBool(dex?.is_locked);

  if (dexList.length === 0 && chain !== 'solana') { riskScore += 20; flags.push('no_dex_liquidity'); }
  if (totalLiquidity > 0 && totalLiquidity < 10000) { riskScore += 15; flags.push('low_liquidity'); }
  if (!liquidityLocked && dexList.length > 0) { riskScore += 10; flags.push('liquidity_not_locked'); }

  if (flags.length === 0) flags.push('no_risk_flags_detected');

  riskScore = Math.min(100, riskScore);
  const riskLevel = getRiskLevel(riskScore);
  const decision = getDecision(riskScore);

  const recommendation = decision === 'avoid'
    ? 'Avoid — high risk of scam or rug pull detected'
    : decision === 'caution'
    ? 'Caution — some risk signals present, research before investing'
    : 'Safe — no significant risk flags detected';

  // Claude summary
  let summary = '';
  try {
    const prompt = `Summarize this token security analysis in 2-3 sentences for a crypto user.

Contract: ${contract}
Chain: ${chain}
Risk score: ${riskScore}/100
Decision: ${decision}
Flags: ${flags.join(', ')}
Is honeypot: ${isHoneypot}
Owner can mint: ${ownerCanMint}
Sell tax: ${sellTax}%
Open source: ${isOpenSource}

Return ONLY a plain English summary string, no JSON.`;

    const response = await client.messages.create({
      model: config.anthropic.model,
      max_tokens: 150,
      messages: [{ role: 'user', content: prompt }],
    });
    summary = response.content.find(b => b.type === 'text')?.text?.trim() ?? '';
  } catch (err) {
    logger.warn({ id, err }, 'Claude summary failed');
    summary = `Token ${contract} on ${chain} has a risk score of ${riskScore}/100 with decision: ${decision}. ${flags.length > 0 ? `Risk flags: ${flags.slice(0, 3).join(', ')}.` : 'No significant risk flags detected.'}`;
  }

  logger.info({ id, contract, chain, riskScore, decision }, 'Token trust check complete');

  return {
    id, contract, chain,
    trust_score: Math.max(0, 100 - riskScore),
    risk_level: riskLevel,
    decision, flags, recommendation,
    security: {
      is_honeypot: isHoneypot,
      honeypot_with_same_creator: honeypotSameCreator,
      owner_can_mint: ownerCanMint,
      owner_can_pause: ownerCanPause,
      owner_can_blacklist: ownerCanBlacklist,
      has_proxy_contract: hasProxy,
      is_open_source: isOpenSource,
      is_verified: isVerified,
      buy_tax: buyTax,
      sell_tax: sellTax,
      transfer_pausable: transferPausable,
      slippage_modifiable: slippageModifiable,
      is_anti_whale: isAntiWhale,
    },
    ...(dexList.length > 0 || totalLiquidity > 0 ? {
      liquidity: {
        total_liquidity_usd: totalLiquidity > 0 ? totalLiquidity : undefined,
        liquidity_locked: liquidityLocked,
        dex_list: dexList,
      }
    } : {}),
    ...(sec ? {
      token_info: {
        name: String(sec.token_name ?? ''),
        symbol: String(sec.token_symbol ?? ''),
        total_supply: String(sec.total_supply ?? ''),
        holder_count: safeNum(sec.holder_count),
        creator_address: String(sec.creator_address ?? ''),
        creator_percent: creatorPercent,
        owner_address: String(sec.owner_address ?? ''),
        owner_percent: ownerPercent,
        top_10_holders_percent: top10Percent,
      }
    } : {}),
    summary,
    latency_ms: Date.now() - t0,
    created_at: new Date().toISOString(),
  };
}
HEREDOC

cat > src/middleware/error.middleware.ts << 'HEREDOC'
import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
export function errorHandler(err: Error, req: Request, res: Response, _next: NextFunction): void {
  logger.error({ err, path: req.path }, 'Unhandled error');
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } });
}
export function notFound(req: Request, res: Response): void { res.status(404).json({ error: { code: 'NOT_FOUND', message: `Route ${req.method} ${req.path} not found` } }); }
HEREDOC

cat > src/middleware/ratelimit.middleware.ts << 'HEREDOC'
import rateLimit from 'express-rate-limit';
import { config } from '../utils/config';
export const rateLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs, max: config.rateLimit.maxFree,
  standardHeaders: 'draft-7', legacyHeaders: false,
  keyGenerator: (req) => req.headers['authorization']?.replace('Bearer ', '') ?? req.ip ?? 'unknown',
  handler: (_req, res) => { res.status(429).json({ error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests.' } }); },
});
HEREDOC

cat > src/routes/health.route.ts << 'HEREDOC'
import { Router, Request, Response } from 'express';
export const healthRouter = Router();
const startTime = Date.now();
healthRouter.get('/', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'ok', version: '1.0.0', uptime_seconds: Math.floor((Date.now() - startTime) / 1000), timestamp: new Date().toISOString() });
});
HEREDOC

cat > src/routes/token.route.ts << 'HEREDOC'
import { Router, Request, Response, NextFunction } from 'express';
import { checkSchema, batchSchema } from '../utils/validation';
import { checkToken } from '../services/token.service';
import type { CheckRequest, BatchRequest } from '../types/index';
export const tokenRouter = Router();

tokenRouter.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { error, value } = checkSchema.validate(req.body, { abortEarly: false });
    if (error) { res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.details.map(d => d.message) } }); return; }
    res.status(200).json(await checkToken(value as CheckRequest));
  } catch (err) { next(err); }
});

tokenRouter.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { error, value } = checkSchema.validate({ contract: req.query.contract, chain: req.query.chain }, { abortEarly: false });
    if (error) { res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.details.map(d => d.message) } }); return; }
    res.status(200).json(await checkToken(value as CheckRequest));
  } catch (err) { next(err); }
});

tokenRouter.post('/batch', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { error, value } = batchSchema.validate(req.body, { abortEarly: false });
    if (error) { res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.details.map(d => d.message) } }); return; }
    const t0 = Date.now();
    const results = await Promise.allSettled((value as BatchRequest).tokens.map((t: CheckRequest) => checkToken(t)));
    const out = results.map(r => r.status === 'fulfilled' ? r.value : { error: r.reason instanceof Error ? r.reason.message : 'Unknown' });
    res.status(200).json({ batch_id: `batch_${Date.now()}`, total: (value as BatchRequest).tokens.length, results: out, latency_ms: Date.now() - t0 });
  } catch (err) { next(err); }
});
HEREDOC

cat > src/routes/openapi.route.ts << 'HEREDOC'
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
HEREDOC

cat > src/app.ts << 'HEREDOC'
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { tokenRouter } from './routes/token.route';
import { healthRouter } from './routes/health.route';
import { openapiRouter, docsRouter } from './routes/openapi.route';
import { errorHandler, notFound } from './middleware/error.middleware';
import { rateLimiter } from './middleware/ratelimit.middleware';
import { config } from './utils/config';
const app = express();
app.use(helmet()); app.use(cors()); app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(`/${config.server.apiVersion}/check`, rateLimiter);
app.use(`/${config.server.apiVersion}/check`, tokenRouter);
app.use(`/${config.server.apiVersion}/health`, healthRouter);
app.use('/openapi.json', openapiRouter);
app.use('/docs', docsRouter);
app.get('/', (_req, res) => res.redirect(`/${config.server.apiVersion}/health`));
app.use(notFound);
app.use(errorHandler);
export { app };
HEREDOC

cat > src/index.ts << 'HEREDOC'
import { app } from './app';
import { config } from './utils/config';

const server = app.listen(config.server.port, () => {
  console.log(`🚀 Token Trust API started on port ${config.server.port}`);
});

const shutdown = (signal: string) => {
  console.log(`Shutting down (${signal})`);
  server.close(() => { console.log('Closed'); process.exit(0); });
  setTimeout(() => process.exit(1), 10_000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => console.error('Unhandled rejection:', reason));
process.on('uncaughtException', (err) => { console.error('Uncaught exception:', err); process.exit(1); });
HEREDOC

cat > jest.config.js << 'HEREDOC'
module.exports = { preset: 'ts-jest', testEnvironment: 'node', rootDir: '.', testMatch: ['**/tests/**/*.test.ts'], collectCoverageFrom: ['src/**/*.ts', '!src/index.ts'], setupFiles: ['<rootDir>/tests/setup.ts'] };
HEREDOC

cat > tests/setup.ts << 'HEREDOC'
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-key';
process.env.ETHERSCAN_API_KEY = 'test-key';
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent';
HEREDOC

cat > .gitignore << 'HEREDOC'
node_modules/
dist/
.env
coverage/
*.log
.DS_Store
HEREDOC

cat > render.yaml << 'HEREDOC'
services:
  - type: web
    name: token-trust-api
    runtime: node
    buildCommand: npm install && npm run build
    startCommand: node dist/index.js
    healthCheckPath: /v1/health
    envVars:
      - key: NODE_ENV
        value: production
      - key: LOG_LEVEL
        value: info
      - key: ANTHROPIC_API_KEY
        sync: false
      - key: ETHERSCAN_API_KEY
        sync: false
HEREDOC

echo ""
echo "✅ All files created! Run: npm install"