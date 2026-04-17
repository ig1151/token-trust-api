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
