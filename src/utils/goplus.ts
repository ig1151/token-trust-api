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
