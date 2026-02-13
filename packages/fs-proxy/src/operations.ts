import { readFile, writeFile, appendFile, stat, readdir, unlink, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import type { FsRequest } from '@blindkey/core';

export interface FsReadResult {
  content: string;
  size: number;
}

export interface FsWriteResult {
  bytes_written: number;
}

export interface FsListEntry {
  name: string;
  type: 'file' | 'directory';
  size: number;
  modified_at: string;
}

export interface FsInfoResult {
  name: string;
  type: 'file' | 'directory';
  size: number;
  created_at: string;
  modified_at: string;
  permissions: string;
}

export async function executeRead(request: FsRequest): Promise<FsReadResult> {
  const fullPath = resolve(request.path);
  const encoding = (request.encoding ?? 'utf-8') as BufferEncoding;
  const content = await readFile(fullPath, { encoding });
  const info = await stat(fullPath);
  return { content, size: info.size };
}

export async function executeWrite(request: FsRequest): Promise<FsWriteResult> {
  const fullPath = resolve(request.path);
  const content = request.content ?? '';

  if (request.operation === 'create') {
    await mkdir(dirname(fullPath), { recursive: true });
  }

  if (request.mode === 'append') {
    await appendFile(fullPath, content, 'utf-8');
  } else {
    await writeFile(fullPath, content, 'utf-8');
  }

  return { bytes_written: Buffer.byteLength(content, 'utf-8') };
}

export async function executeList(request: FsRequest): Promise<FsListEntry[]> {
  const fullPath = resolve(request.path);
  const entries = await readdir(fullPath, { withFileTypes: true });

  const results: FsListEntry[] = [];
  for (const entry of entries) {
    const entryPath = resolve(fullPath, entry.name);
    try {
      const info = await stat(entryPath);
      results.push({
        name: entry.name,
        type: entry.isDirectory() ? 'directory' : 'file',
        size: info.size,
        modified_at: info.mtime.toISOString(),
      });
    } catch {
      results.push({
        name: entry.name,
        type: entry.isDirectory() ? 'directory' : 'file',
        size: 0,
        modified_at: new Date().toISOString(),
      });
    }
  }

  return results;
}

export async function executeDelete(request: FsRequest): Promise<void> {
  const fullPath = resolve(request.path);
  await unlink(fullPath);
}

export async function executeInfo(request: FsRequest): Promise<FsInfoResult> {
  const fullPath = resolve(request.path);
  const info = await stat(fullPath);
  const name = fullPath.split(/[/\\]/).pop() ?? '';

  return {
    name,
    type: info.isDirectory() ? 'directory' : 'file',
    size: info.size,
    created_at: info.birthtime.toISOString(),
    modified_at: info.mtime.toISOString(),
    permissions: (info.mode & 0o777).toString(8),
  };
}
