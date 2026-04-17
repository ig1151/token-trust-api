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
