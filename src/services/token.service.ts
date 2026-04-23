import { v4 as uuidv4 } from 'uuid';
import { config } from '../utils/config';
import { logger } from '../utils/logger';
import { getTokenSecurity, getDexInfo } from '../utils/goplus';
import { detectChain } from '../utils/validation';
import type { CheckRequest, TokenTrustResponse, RiskLevel, TokenDecision, Chain, UseCase } from '../types/index';

const OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/chat/completions';
const MODEL = 'anthropic/claude-sonnet-4-5';

const USE_CASE_THRESHOLDS: Record<UseCase, { avoidAt: number; cautionAt: number }> = {
  trading:       { avoidAt: 50, cautionAt: 20 },
  bot_filtering: { avoidAt: 40, cautionAt: 15 },
  token_listing: { avoidAt: 60, cautionAt: 30 },
  wallet_display:{ avoidAt: 70, cautionAt: 35 },
};

function getRiskLevel(score: number): RiskLevel { return score >= 80 ? 'critical' : score >= 50 ? 'high' : score >= 20 ? 'medium' : 'low'; }

function getDecision(score: number, useCase: UseCase): TokenDecision {
  const t = USE_CASE_THRESHOLDS[useCase];
  if (score >= t.avoidAt) return 'avoid';
  if (score >= t.cautionAt) return 'caution';
  return 'safe';
}

function getConfidence(hasSecurityData: boolean, hasLiquidityData: boolean, holderCount: number): number {
  let confidence = 0.5;
  if (hasSecurityData) confidence += 0.3;
  if (hasLiquidityData) confidence += 0.1;
  if (holderCount > 1000) confidence += 0.1;
  return parseFloat(Math.min(0.95, confidence).toFixed(2));
}

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

function buildReasons(flags: string[], decision: TokenDecision): string[] {
  const reasonMap: Record<string, string> = {
    honeypot: 'Cannot sell after buying — confirmed honeypot',
    honeypot_creator_pattern: 'Creator has deployed other honeypots',
    owner_can_mint: 'Owner can create unlimited tokens — dilution risk',
    owner_can_blacklist: 'Owner can prevent you from selling',
    slippage_modifiable: 'Owner can change taxes at any time',
    high_sell_tax: 'High sell tax makes profitable exit difficult',
    not_open_source: 'Contract code is hidden — cannot be audited',
    low_liquidity: 'Low liquidity — high price impact on trades',
    no_dex_liquidity: 'No DEX liquidity detected',
    creator_holds_majority: 'Creator holds majority of supply — rug pull risk',
    proxy_contract: 'Upgradeable proxy — contract logic can be changed',
    liquidity_not_locked: 'Liquidity not locked — can be removed anytime',
  };

  if (decision === 'safe' && flags.includes('no_risk_flags_detected')) {
    return ['No significant risk flags detected'];
  }

  return flags
    .filter(f => !f.includes('no_risk'))
    .map(f => {
      const baseFlag = f.replace(/_\d+pct$/, '').replace(/^elevated_/, '').replace(/^high_/, 'high_');
      return reasonMap[baseFlag] ?? f.replace(/_/g, ' ');
    })
    .slice(0, 5);
}

export async function checkToken(req: CheckRequest): Promise<TokenTrustResponse> {
  const id = `token_${uuidv4().replace(/-/g, '').slice(0, 12)}`;
  const t0 = Date.now();
  const contract = req.contract.trim();
  const useCase = req.use_case ?? 'trading';

  let chain: Chain;
  if (req.chain) {
    chain = req.chain;
  } else {
    const detected = detectChain(contract);
    chain = detected === 'unknown' ? 'ethereum' : detected as Chain;
  }

  logger.info({ id, contract, chain, useCase }, 'Starting token trust check');

  const [securityData, dexData] = await Promise.all([
    getTokenSecurity(contract, chain),
    getDexInfo(contract, chain),
  ]);

  const flags: string[] = [];
  let riskScore = 0;

  const sec = securityData as Record<string, unknown> | null;
  const dex = dexData as Record<string, unknown> | null;

  const isHoneypot = safeBool(sec?.is_honeypot);
  const honeypotSameCreator = safeBool(sec?.honeypot_with_same_creator);
  const ownerCanMint = safeBool(sec?.is_mintable);
  const ownerCanPause = safeBool(sec?.transfer_pausable);
  const ownerCanBlacklist = safeBool(sec?.is_blacklisted);
  const hasProxy = safeBool(sec?.is_proxy);
  const isOpenSource = safeBool(sec?.is_open_source);
  const buyTax = safeNum(sec?.buy_tax) * 100;
  const sellTax = safeNum(sec?.sell_tax) * 100;
  const slippageModifiable = safeBool(sec?.slippage_modifiable);
  const isAntiWhale = safeBool(sec?.is_anti_whale);
  const transferPausable = safeBool(sec?.transfer_pausable);

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

  const top10Percent = safeNum(sec?.top10_holder_rate) * 100;
  const creatorPercent = safeNum(sec?.creator_percent) * 100;
  const ownerPercent = safeNum(sec?.owner_percent) * 100;
  const holderCount = safeNum(sec?.holder_count);

  if (creatorPercent > 50) { riskScore += 30; flags.push('creator_holds_majority'); }
  else if (creatorPercent > 20) { riskScore += 15; flags.push('creator_high_concentration'); }
  if (top10Percent > 80) { riskScore += 20; flags.push('top10_holders_dominant'); }

  const dexList = (dex?.dex as { name: string }[] ?? []).map(d => d.name).filter(Boolean);
  const totalLiquidity = safeNum(dex?.liquidity);
  const liquidityLocked = safeBool(dex?.is_locked);

  if (dexList.length === 0 && chain !== 'solana') { riskScore += 20; flags.push('no_dex_liquidity'); }
  if (totalLiquidity > 0 && totalLiquidity < 10000) { riskScore += 15; flags.push('low_liquidity'); }
  if (!liquidityLocked && dexList.length > 0) { riskScore += 10; flags.push('liquidity_not_locked'); }

  if (flags.length === 0) flags.push('no_risk_flags_detected');

  riskScore = Math.min(100, riskScore);
  const riskLevel = getRiskLevel(riskScore);
  const decision = getDecision(riskScore, useCase);
  const confidence = getConfidence(!!sec, !!dex, holderCount);
  const reasons = buildReasons(flags, decision);

  const recommendation = decision === 'avoid'
    ? 'Avoid — high risk of scam or rug pull detected'
    : decision === 'caution'
    ? 'Caution — some risk signals present, research before investing'
    : 'Safe — no significant risk flags detected';

  let summary = '';
  try {
    const apiKey = process.env.OPENROUTER_API_KEY;
    if (!apiKey) throw new Error('OPENROUTER_API_KEY not set');

    const prompt = `Summarize this token security analysis in 2-3 sentences for a crypto user.

Contract: ${contract}
Chain: ${chain}
Use case: ${useCase}
Risk score: ${riskScore}/100
Decision: ${decision}
Confidence: ${confidence}
Flags: ${flags.join(', ')}

Return ONLY a plain English summary, no JSON.`;

    const response = await fetch(OPENROUTER_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 150,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!response.ok) throw new Error(`OpenRouter error: ${response.status}`);
    const data = await response.json() as { choices: { message: { content: string } }[] };
    summary = data.choices[0].message.content.trim();
  } catch (err) {
    logger.warn({ id, err }, 'OpenRouter summary failed');
    summary = `Token ${contract} on ${chain} scored ${riskScore}/100 risk with decision: ${decision} (confidence: ${confidence}). ${reasons.slice(0, 2).join('. ')}.`;
  }

  logger.info({ id, contract, chain, useCase, riskScore, decision, confidence }, 'Token trust check complete');

  return {
    id, contract, chain, use_case: useCase,
    trust_score: Math.max(0, 100 - riskScore),
    risk_level: riskLevel,
    decision, confidence, flags, reasons, recommendation,
    security: {
      is_honeypot: isHoneypot,
      honeypot_with_same_creator: honeypotSameCreator,
      owner_can_mint: ownerCanMint,
      owner_can_pause: ownerCanPause,
      owner_can_blacklist: ownerCanBlacklist,
      has_proxy_contract: hasProxy,
      is_open_source: isOpenSource,
      is_verified: isOpenSource,
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
        holder_count: holderCount,
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
