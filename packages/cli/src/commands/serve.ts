import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';
import { spawn } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export function registerServeCommand(program: Command, _getVault: () => Promise<LocalVault>) {
  program
    .command('serve')
    .description('Start the BlindKey MCP server (stdio transport)')
    .option('-p, --port <port>', 'Port for HTTP proxy (not yet implemented)')
    .action(async () => {
      // Resolve the openclaw-skill entry point relative to this CLI package
      const __dirname = dirname(fileURLToPath(import.meta.url));
      const skillEntry = resolve(__dirname, '../../openclaw-skill/dist/index.js');

      console.error('Starting BlindKey MCP server on stdio...');
      console.error(`Entry: ${skillEntry}`);

      const child = spawn('node', [skillEntry], {
        stdio: 'inherit',
        env: { ...process.env },
      });

      child.on('error', (err) => {
        console.error(`\x1b[31m✕\x1b[0m Failed to start MCP server: ${err.message}`);
        console.error('Run \x1b[1mnpx turbo build\x1b[0m first to compile the skill package.');
        process.exit(1);
      });

      child.on('exit', (code) => {
        process.exit(code ?? 0);
      });
    });
}
