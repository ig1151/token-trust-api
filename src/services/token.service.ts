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
