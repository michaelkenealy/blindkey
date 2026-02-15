import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

/**
 * Start the MCP stdio server by spawning @blindkey/openclaw-skill.
 * Used when `bk serve --mcp` is invoked (or from .mcp.json).
 */
function startMcpServer(): void {
  const require = createRequire(import.meta.url);
  let skillEntry: string;

  try {
    skillEntry = require.resolve('@blindkey/openclaw-skill');
  } catch {
    console.error('\x1b[31m\u2715\x1b[0m Could not find @blindkey/openclaw-skill package.');
    console.error('  Make sure it is installed: npm install @blindkey/openclaw-skill');
    process.exit(1);
  }

  console.error('Starting BlindKey MCP server on stdio...');
  console.error(`Entry: ${skillEntry}`);

  const child = spawn('node', [skillEntry], {
    stdio: 'inherit',
    env: { ...process.env },
  });

  child.on('error', (err) => {
    console.error(`\x1b[31m\u2715\x1b[0m Failed to start MCP server: ${err.message}`);
    console.error('Run \x1b[1mnpx turbo build\x1b[0m first to compile the skill package.');
    process.exit(1);
  });

  child.on('exit', (code) => {
    process.exit(code ?? 0);
  });
}

/**
 * Start the local HTTP API server by spawning @blindkey/local-api.
 * The dashboard connects to this in local mode.
 */
function startLocalApiServer(port: number): void {
  const require = createRequire(import.meta.url);
  let apiEntry: string;

  try {
    apiEntry = require.resolve('@blindkey/local-api');
  } catch {
    console.error('\x1b[31m\u2715\x1b[0m Could not find @blindkey/local-api package.');
    console.error('  Make sure it is installed: npm install @blindkey/local-api');
    process.exit(1);
  }

  const child = spawn('node', [apiEntry], {
    stdio: 'inherit',
    env: { ...process.env, LOCAL_API_PORT: String(port) },
  });

  child.on('error', (err) => {
    console.error(`\x1b[31m\u2715\x1b[0m Failed to start local API server: ${err.message}`);
    console.error('Run \x1b[1mnpx turbo build\x1b[0m first to compile the local-api package.');
    process.exit(1);
  });

  child.on('exit', (code) => {
    process.exit(code ?? 0);
  });
}

export function registerServeCommand(program: Command, _getVault: () => Promise<LocalVault>) {
  program
    .command('serve')
    .description('Start the BlindKey local HTTP API server (or MCP server with --mcp)')
    .option('-p, --port <port>', 'Port for the HTTP API server', '3200')
    .option('--mcp', 'Start the MCP stdio server instead of the HTTP API')
    .action(async (options: { port: string; mcp?: boolean }) => {
      if (options.mcp) {
        startMcpServer();
        return;
      }

      const port = parseInt(options.port, 10);
      startLocalApiServer(port);
    });
}
