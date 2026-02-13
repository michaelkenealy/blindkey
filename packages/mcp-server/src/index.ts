#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { handleProxyRequest, handleListSecrets, handleFsOperation, handleFsListGrants } from './handlers.js';

const server = new McpServer({
  name: 'blindkey',
  version: '0.1.0',
});

// Tool: Make an authenticated API request through BlindKey
server.tool(
  'bk_proxy',
  'Make an authenticated API request through BlindKey. The real credential is never exposed — BlindKey injects it server-side.',
  {
    vault_ref: z.string().describe('Secret reference, e.g. bk://stripe-prod-abc123'),
    method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).describe('HTTP method'),
    url: z.string().describe('Full target API URL'),
    headers: z.record(z.string(), z.string()).optional().describe('Additional request headers'),
    body: z.unknown().optional().describe('Request body (for POST/PUT/PATCH)'),
  },
  async ({ vault_ref, method, url, headers, body }) => {
    try {
      const result = await handleProxyRequest({
        vault_ref,
        method,
        url,
        headers: headers as Record<string, string> | undefined,
        body,
      });

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              { status: result.status, body: result.body },
              null,
              2
            ),
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: 'text' as const,
            text: `Error: ${(err as Error).message}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// Tool: List available secret references for this session
server.tool(
  'bk_list_secrets',
  'List available secret references for the current BlindKey session.',
  async () => {
    try {
      const result = await handleListSecrets();

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: 'text' as const,
            text: `Error: ${(err as Error).message}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// ── Filesystem Tools ──

// Helper for fs tool responses
function fsToolResponse(result: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(result, null, 2),
      },
    ],
  };
}

function fsToolError(err: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: `Error: ${(err as Error).message}`,
      },
    ],
    isError: true,
  };
}

// Tool: Read a file through the filesystem proxy
server.tool(
  'bk_fs_read',
  'Read a file through BlindKey filesystem proxy. Access is controlled by session grants and policies.',
  {
    path: z.string().describe('Absolute path to the file to read'),
    encoding: z.string().optional().describe('File encoding (default: utf-8)'),
  },
  async ({ path, encoding }) => {
    try {
      const result = await handleFsOperation({ operation: 'read', path, encoding });
      return fsToolResponse(result);
    } catch (err) {
      return fsToolError(err);
    }
  }
);

// Tool: Write to a file through the filesystem proxy
server.tool(
  'bk_fs_write',
  'Write content to a file through BlindKey filesystem proxy. Use mode "append" to add to existing file.',
  {
    path: z.string().describe('Absolute path to the file to write'),
    content: z.string().describe('Content to write to the file'),
    mode: z.enum(['overwrite', 'append']).optional().describe('Write mode (default: overwrite)'),
  },
  async ({ path, content, mode }) => {
    try {
      const result = await handleFsOperation({ operation: 'write', path, content, mode });
      return fsToolResponse(result);
    } catch (err) {
      return fsToolError(err);
    }
  }
);

// Tool: List directory contents through the filesystem proxy
server.tool(
  'bk_fs_list',
  'List directory contents through BlindKey filesystem proxy.',
  {
    path: z.string().describe('Absolute path to the directory to list'),
  },
  async ({ path }) => {
    try {
      const result = await handleFsOperation({ operation: 'list', path });
      return fsToolResponse(result);
    } catch (err) {
      return fsToolError(err);
    }
  }
);

// Tool: Delete a file through the filesystem proxy
server.tool(
  'bk_fs_delete',
  'Delete a file through BlindKey filesystem proxy. Requires delete permission in session grants.',
  {
    path: z.string().describe('Absolute path to the file to delete'),
  },
  async ({ path }) => {
    try {
      const result = await handleFsOperation({ operation: 'delete', path });
      return fsToolResponse(result);
    } catch (err) {
      return fsToolError(err);
    }
  }
);

// Tool: Get file/directory info through the filesystem proxy
server.tool(
  'bk_fs_info',
  'Get metadata about a file or directory through BlindKey filesystem proxy.',
  {
    path: z.string().describe('Absolute path to the file or directory'),
  },
  async ({ path }) => {
    try {
      const result = await handleFsOperation({ operation: 'info', path });
      return fsToolResponse(result);
    } catch (err) {
      return fsToolError(err);
    }
  }
);

// Tool: List filesystem grants for the current session
server.tool(
  'bk_fs_grants',
  'List the filesystem grants (allowed paths and permissions) for the current session.',
  async () => {
    try {
      const result = await handleFsListGrants();
      return fsToolResponse(result);
    } catch (err) {
      return fsToolError(err);
    }
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('BlindKey MCP server running on stdio');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
