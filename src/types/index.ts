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
