import { createApp } from './app.js';

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1';
const isBeEfEnabled = process.env.BROWSER_EXPLOITATION_LAB_ENABLED === 'true';
const beefApiUrl = process.env.BEEF_API_URL || 'http://127.0.0.1:3001';

const app = createApp();

const server = app.listen(PORT, HOST, () => {
  const localUrl = `http://${HOST}:${PORT}`;
  const localLine = `║  Local  : ${localUrl.padEnd(51)}║`;

  const banner = [
    '╔══════════════════════════════════════════════════════════════╗',
    '║                                                              ║',
    '║   ██╗  ██╗███████╗███████╗       ██╗      █████╗ ██████╗     ║',
    '║   ╚██╗██╔╝██╔════╝██╔════╝       ██║     ██╔══██╗██╔══██╗    ║',
    '║    ╚███╔╝ ███████╗███████╗       ██║     ███████║██████╔╝    ║',
    '║    ██╔██╗ ╚════██║╚════██║       ██║     ██╔══██║██╔══██╗    ║',
    '║   ██╔╝ ██╗███████║███████║       ███████╗██║  ██║██████╔╝    ║',
    '║   ╚═╝  ╚═╝╚══════╝╚══════╝       ╚══════╝╚═╝  ╚═╝╚═════╝     ║',
    '║                                                              ║',
    '║                         XSS-LAB                              ║',
    '║                                                              ║',
    '║                      Created by                              ║',
    '║                      ALIF MORTAZA                            ║',
    '║                                                              ║',
    '╠══════════════════════════════════════════════════════════════╣',
    '║  Status : RUNNING                                            ║',
    localLine,
    '║                                                              ║',
    '║  For local educational use only.                             ║',
    '║  Press Ctrl+C to stop.                                       ║',
    '╚══════════════════════════════════════════════════════════════╝'
  ].join('\n');

  console.log(banner);
  console.log('\nXSS-Lab is ready.\n');
  console.log('Open:');
  console.log(`  ${localUrl}\n`);
  console.log('Development mode:');
  console.log('  npm run dev\n');
  if (isBeEfEnabled) {
    console.log('BeEF:');
    console.log(`  ${beefApiUrl}/ui/panel\n`);
  }
  console.log('Stop:');
  console.log('  Ctrl+C\n');
});

// Handle graceful shutdown
function handleShutdown() {
  console.log('\nShutting down XSS Lab server...');
  server.close(() => {
    console.log('Server closed successfully.');
    process.exit(0);
  });
}

process.on('SIGINT', handleShutdown);
process.on('SIGTERM', handleShutdown);
