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
