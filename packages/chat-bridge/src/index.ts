#!/usr/bin/env node

import Fastify from 'fastify';
import crypto from 'node:crypto';

interface BridgeConfig {
  host: string;
  port: number;
  sharedSecret: string;
  localLlmUrl: string;
  localLlmModel: string;
  localLlmApiKey?: string;
  llmProvider: 'openai' | 'ollama';
  llmTimeoutMs: number;
  maxPromptChars: number;
  maxResponseChars: number;
  minRequestIntervalMs: number;
  systemPrompt?: string;
  slackSigningSecret?: string;
  allowedChannels: Set<string>;
}

interface ParsedBody<T> {
  rawBody: string;
  data: T;
}

interface SlackCommandPayload {
  text?: string;
  user_id?: string;
  channel_id?: string;
  channel_name?: string;
}

type ChatSource = 'api' | 'slack';

const TIMESTAMP_TOLERANCE_SECONDS = 300;

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function parseCsvSet(value: string | undefined): Set<string> {
  return new Set(
    (value ?? '')
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
  );
}

function readConfig(): BridgeConfig {
  const sharedSecret = process.env.CHAT_BRIDGE_SHARED_SECRET?.trim();
  if (!sharedSecret) {
    throw new Error('CHAT_BRIDGE_SHARED_SECRET is required');
  }

  const localLlmUrl = process.env.LOCAL_LLM_URL?.trim();
  if (!localLlmUrl) {
    throw new Error('LOCAL_LLM_URL is required');
  }

  const llmProviderRaw = (process.env.LLM_PROVIDER ?? 'openai').trim().toLowerCase();
  const llmProvider = llmProviderRaw === 'ollama' ? 'ollama' : 'openai';

  return {
    host: process.env.CHAT_BRIDGE_HOST?.trim() || '127.0.0.1',
    port: parsePositiveInt(process.env.CHAT_BRIDGE_PORT, 3601),
    sharedSecret,
    localLlmUrl,
    localLlmModel: process.env.LOCAL_LLM_MODEL?.trim() || 'llama3.1',
    localLlmApiKey: process.env.LOCAL_LLM_API_KEY?.trim() || undefined,
    llmProvider,
    llmTimeoutMs: parsePositiveInt(process.env.LOCAL_LLM_TIMEOUT_MS, 20_000),
    maxPromptChars: parsePositiveInt(process.env.CHAT_BRIDGE_MAX_PROMPT_CHARS, 2_000),
    maxResponseChars: parsePositiveInt(process.env.CHAT_BRIDGE_MAX_RESPONSE_CHARS, 4_000),
    minRequestIntervalMs: parsePositiveInt(process.env.CHAT_BRIDGE_MIN_REQUEST_INTERVAL_MS, 1_000),
    systemPrompt: process.env.CHAT_BRIDGE_SYSTEM_PROMPT?.trim() || undefined,
    slackSigningSecret: process.env.SLACK_SIGNING_SECRET?.trim() || undefined,
    allowedChannels: parseCsvSet(process.env.CHAT_BRIDGE_ALLOWED_CHANNELS),
  };
}

function safeCompare(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a, 'utf8');
  const bBuffer = Buffer.from(b, 'utf8');
  if (aBuffer.length !== bBuffer.length) return false;
  return crypto.timingSafeEqual(aBuffer, bBuffer);
}

function isSlackRequestValid(rawBody: string, headers: Record<string, string | undefined>, signingSecret: string): boolean {
  const timestamp = headers['x-slack-request-timestamp'];
  const signature = headers['x-slack-signature'];
  if (!timestamp || !signature) return false;

  const timestampInt = Number.parseInt(timestamp, 10);
  if (!Number.isInteger(timestampInt)) return false;

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestampInt) > TIMESTAMP_TOLERANCE_SECONDS) return false;

  const base = `v0:${timestamp}:${rawBody}`;
  const expected = `v0=${crypto.createHmac('sha256', signingSecret).update(base).digest('hex')}`;
  return safeCompare(expected, signature);
}

function getHeaderMap(headers: Record<string, unknown>): Record<string, string | undefined> {
  const mapped: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(headers)) {
    mapped[key.toLowerCase()] = typeof value === 'string' ? value : undefined;
  }
  return mapped;
}

function normalizePrompt(input: string, maxPromptChars: number): string {
  const withoutMentions = input.replace(/<@!?\d+>/g, '').trim();
  if (withoutMentions.length === 0) {
    throw new Error('Prompt is empty');
  }

  if (withoutMentions.length > maxPromptChars) {
    throw new Error(`Prompt exceeds ${maxPromptChars} characters`);
  }

  return withoutMentions;
}

function assertAuthorized(requestAuthHeader: string | undefined, sharedSecret: string): void {
  if (!requestAuthHeader?.startsWith('Bearer ')) {
    throw new Error('Missing bearer token');
  }

  const token = requestAuthHeader.slice('Bearer '.length).trim();
  if (!safeCompare(token, sharedSecret)) {
    throw new Error('Invalid bearer token');
  }
}

function assertChannelAllowed(channelId: string | undefined, channelName: string | undefined, allowedChannels: Set<string>): void {
  if (allowedChannels.size === 0) return;
  const candidates = [channelId?.trim(), channelName?.trim()].filter((v): v is string => Boolean(v));
  const allowed = candidates.some((value) => allowedChannels.has(value));
  if (!allowed) {
    throw new Error('Channel is not allowlisted');
  }
}

async function queryLocalLlm(prompt: string, config: BridgeConfig): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.llmTimeoutMs);

  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (config.localLlmApiKey) {
      headers.Authorization = `Bearer ${config.localLlmApiKey}`;
    }

    const body =
      config.llmProvider === 'ollama'
        ? {
            model: config.localLlmModel,
            stream: false,
            messages: [
              ...(config.systemPrompt ? [{ role: 'system', content: config.systemPrompt }] : []),
              { role: 'user', content: prompt },
            ],
          }
        : {
            model: config.localLlmModel,
            temperature: 0.2,
            messages: [
              ...(config.systemPrompt ? [{ role: 'system', content: config.systemPrompt }] : []),
              { role: 'user', content: prompt },
            ],
          };

    const response = await fetch(config.localLlmUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`Local LLM returned HTTP ${response.status}`);
    }

    const json = (await response.json()) as Record<string, unknown>;

    const content =
      config.llmProvider === 'ollama'
        ? ((json.message as Record<string, unknown> | undefined)?.content as string | undefined)
        : ((((json.choices as Array<Record<string, unknown>> | undefined)?.[0]?.message as Record<string, unknown> | undefined)
            ?.content as string | undefined));

    if (!content || typeof content !== 'string') {
      throw new Error('Local LLM response did not contain text content');
    }

    return content.length > config.maxResponseChars ? `${content.slice(0, config.maxResponseChars)}...` : content;
  } finally {
    clearTimeout(timeout);
  }
}

async function start() {
  const config = readConfig();
  const app = Fastify({
    bodyLimit: 128 * 1024,
    requestTimeout: 30_000,
    logger: true,
  });

  const lastRequestByActor = new Map<string, number>();

  app.addHook('onSend', async (_request, reply) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('Cache-Control', 'no-store');
  });

  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_request, body, done) => {
    try {
      const params = new URLSearchParams(body as string);
      const data: Record<string, string> = {};
      for (const [key, value] of params.entries()) {
        data[key] = value;
      }
      done(null, { rawBody: body as string, data });
    } catch (error) {
      done(error as Error);
    }
  });

  app.addContentTypeParser('application/json', { parseAs: 'string' }, (_request, body, done) => {
    try {
      const parsed = JSON.parse(body as string) as Record<string, unknown>;
      done(null, { rawBody: body as string, data: parsed });
    } catch {
      done(new Error('Invalid JSON body'));
    }
  });

  function enforceRateLimit(actorId: string): void {
    const now = Date.now();
    const last = lastRequestByActor.get(actorId) ?? 0;
    if (now - last < config.minRequestIntervalMs) {
      throw new Error('Rate limited');
    }
    lastRequestByActor.set(actorId, now);
  }

  async function runChat(source: ChatSource, actorId: string, channelId: string | undefined, channelName: string | undefined, text: string): Promise<string> {
    assertChannelAllowed(channelId, channelName, config.allowedChannels);
    enforceRateLimit(`${source}:${actorId}`);

    const prompt = normalizePrompt(text, config.maxPromptChars);
    app.log.info({ source, actor: actorId, channel: channelId ?? channelName ?? 'unknown' }, 'Accepted chat request');
    return queryLocalLlm(prompt, config);
  }

  app.get('/health', async () => ({
    status: 'ok',
    service: 'blindkey-chat-bridge',
    slack_enabled: Boolean(config.slackSigningSecret),
  }));

  app.post<{ Body: ParsedBody<{ prompt?: string; actor_id?: string; channel?: string }> }>('/v1/chat', async (request, reply) => {
    try {
      assertAuthorized(request.headers.authorization, config.sharedSecret);
      const actorId = request.body.data.actor_id?.trim() || 'api-user';
      const prompt = request.body.data.prompt ?? '';
      const response = await runChat('api', actorId, request.body.data.channel, undefined, prompt);
      return reply.send({ response });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Request failed';
      const statusCode = message === 'Rate limited' ? 429 : message.includes('bearer') || message.includes('token') ? 401 : 400;
      return reply.code(statusCode).send({ error: message });
    }
  });

  app.post<{ Body: ParsedBody<SlackCommandPayload> }>('/integrations/slack/command', async (request, reply) => {
    if (!config.slackSigningSecret) {
      return reply.code(404).send({ error: 'Slack integration is disabled' });
    }

    const headerMap = getHeaderMap(request.headers as Record<string, unknown>);
    if (!isSlackRequestValid(request.body.rawBody, headerMap, config.slackSigningSecret)) {
      return reply.code(401).send({ error: 'Invalid Slack signature' });
    }

    const payload = request.body.data;

    try {
      const response = await runChat(
        'slack',
        payload.user_id?.trim() || 'slack-user',
        payload.channel_id,
        payload.channel_name,
        payload.text ?? ''
      );

      return reply.send({ response_type: 'ephemeral', text: response });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Request failed';
      const statusCode = message === 'Rate limited' ? 429 : 400;
      return reply.code(statusCode).send({ response_type: 'ephemeral', text: `Error: ${message}` });
    }
  });

  await app.listen({ host: config.host, port: config.port });
}

start().catch((error) => {
  console.error(error);
  process.exit(1);
});
