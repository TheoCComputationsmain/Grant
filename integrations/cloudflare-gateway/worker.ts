/**
 * Grant approval proxy for Cloudflare AI Gateway / tool routers.
 *
 * Zero dependencies: fetch, Request, Response, AbortController, Web Crypto.
 * Zero custody: Grant only receives tool names, call ids, argument key names,
 * and a correlation hash. Never argument values, credentials, or payment data.
 */

const DEFAULT_GRANT_BASE_URL = 'https://grant-approve.vercel.app';
const DEFAULT_PROTECTED_TOOLS = [
  'send_email',
  'send_message',
  'issue_refund',
  'create_charge',
  'transfer_funds',
  'publish_content',
  'write_record',
  'delete_record',
  'execute_payment',
];

export interface Env {
  GRANT_BASE_URL?: string;
  GRANT_API_KEY?: string;
  UPSTREAM_URL?: string;
  PROTECTED_TOOLS?: string;
  GRANT_MODE?: string;
  POLL_INTERVAL_MS?: string;
  POLL_TIMEOUT_MS?: string;
}

type ToolCall = { id?: string; name?: string; function?: { name?: string; arguments?: unknown }; arguments?: unknown };
type Body = Record<string, unknown>;

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

function baseUrl(env: Env): string {
  return String(env.GRANT_BASE_URL || DEFAULT_GRANT_BASE_URL).replace(/\/+$/, '');
}

function protectedTools(env: Env): string[] {
  const raw = env.PROTECTED_TOOLS;
  const list = raw ? raw.split(',').map((item) => item.trim()).filter(Boolean) : DEFAULT_PROTECTED_TOOLS;
  return list.length ? list : DEFAULT_PROTECTED_TOOLS;
}

function record(value: unknown): Body | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Body) : null;
}

function toolCalls(body: Body): ToolCall[] {
  const calls: ToolCall[] = [];
  const candidates = [
    ...(Array.isArray(body.tool_calls) ? body.tool_calls : []),
    ...(Array.isArray(body.tools) ? body.tools : []),
  ];
  if (record(body.tool)) candidates.push(body.tool);
  for (const raw of candidates) {
    const item = record(raw);
    if (!item) continue;
    const fn = record(item.function);
    const name = String(fn?.name ?? item.name ?? '');
    if (!name) continue;
    calls.push(raw as ToolCall);
  }
  if (!calls.length && typeof body.tool_name === 'string') {
    calls.push({ id: String(body.call_id ?? ''), name: body.tool_name, arguments: body.arguments ?? {} });
  }
  return calls;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const object = record(value);
  if (!object) return JSON.stringify(value ?? null);
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(',')}}`;
}

function hash(value: unknown): string {
  const text = canonical(value);
  let result = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) {
    result ^= text.charCodeAt(index);
    result = Math.imul(result, 0x01000193) >>> 0;
  }
  return result.toString(16).padStart(8, '0');
}

function redactedScope(call: ToolCall, id: string): Body {
  let args: unknown = call.function?.arguments ?? call.arguments ?? {};
  if (typeof args === 'string') {
    try {
      args = JSON.parse(args);
    } catch {
      args = { unparsed: true };
    }
  }
  return {
    tool_call_id: id.slice(0, 120),
    argument_keys: Object.keys(record(args) ?? {}).sort().slice(0, 50),
    arguments_sha256: hash(args),
  };
}

async function grantFetch(path: string, options: RequestInit, env: Env): Promise<{ status: number; body: Body }> {
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');
  if (env.GRANT_API_KEY) headers.set('Authorization', `Bearer ${env.GRANT_API_KEY}`);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(`${baseUrl(env)}${path}`, { ...options, headers, signal: controller.signal });
    let body: Body = {};
    try {
      body = record(await response.json()) ?? {};
    } catch {
      body = {};
    }
    return { status: response.status, body };
  } finally {
    clearTimeout(timer);
  }
}

async function verifyReceipt(signedReceipt: string, requestId: string, env: Env): Promise<boolean> {
  if (!signedReceipt) return false;
  const result = await grantFetch(
    '/v1/receipts/verify',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ signed_receipt: signedReceipt, request_id: requestId }),
    },
    env
  );
  return result.status < 400 && result.body.valid === true;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForDecision(requestId: string, env: Env): Promise<{ approved: boolean; receipt: string }> {
  const interval = Math.max(100, Number(env.POLL_INTERVAL_MS) || 1000);
  const deadline = Date.now() + Math.max(1000, Number(env.POLL_TIMEOUT_MS) || 60_000);
  while (Date.now() < deadline) {
    await sleep(interval);
    const result = await grantFetch(`/v1/approvals/${encodeURIComponent(requestId)}`, { method: 'GET' }, env);
    if (result.status >= 400) continue;
    const decision = String(result.body.decision ?? '').toLowerCase();
    const status = String(result.body.status ?? '').toLowerCase();
    if (['approve', 'always', 'auto_rule'].includes(decision) || status === 'approved') {
      return { approved: true, receipt: String(result.body.signed_receipt ?? '') };
    }
    if (['reject', 'cancelled', 'expired', 'denied'].includes(decision) || status === 'cancelled') {
      return { approved: false, receipt: '' };
    }
  }
  return { approved: false, receipt: '' };
}

function forward(request: Request, body: Body, env: Env, receipt: string, requestId: string): Promise<Response> {
  const upstream = String(env.UPSTREAM_URL || '').trim();
  if (!upstream) return Promise.resolve(json({ error: 'UPSTREAM_URL is not configured' }, 500));
  const headers = new Headers(request.headers);
  headers.delete('x-grant-receipt');
  headers.delete('x-grant-request-id');
  headers.set('Content-Type', 'application/json');
  if (receipt) headers.set('X-Grant-Receipt', receipt);
  if (requestId) headers.set('X-Grant-Request-Id', requestId);
  return fetch(upstream, {
    method: request.method === 'GET' || request.method === 'HEAD' ? 'GET' : 'POST',
    headers,
    body: request.method === 'GET' || request.method === 'HEAD' ? undefined : JSON.stringify(body),
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'GET' && new URL(request.url).pathname === '/health') {
      return json({ status: 'ok', grant_base_url: baseUrl(env), watermark: '● Protected by Grant · Zero-custody consent infrastructure' });
    }

    let body: Body;
    try {
      body = record(await request.json()) ?? {};
    } catch {
      return json({ error: 'Request body must be JSON.' }, 400);
    }

    const suppliedReceipt = request.headers.get('X-Grant-Receipt') || '';
    const suppliedRequestId = request.headers.get('X-Grant-Request-Id') || '';
    if (suppliedReceipt) {
      const valid = await verifyReceipt(suppliedReceipt, suppliedRequestId, env);
      if (!valid) {
        return json({ error: 'Grant receipt is invalid. Protected action not executed.' }, 403);
      }
      return forward(request, body, env, suppliedReceipt, suppliedRequestId);
    }

    const calls = toolCalls(body).filter((call) => {
      const name = String(call.function?.name ?? call.name ?? '').toLowerCase();
      return protectedTools(env).some((tool) => tool.toLowerCase() === name || tool === '*');
    });

    if (!calls.length) {
      return forward(request, body, env, '', '');
    }

    const call = calls[0];
    const name = String(call.function?.name ?? call.name ?? '').slice(0, 120);
    const id = String(call.id ?? '').slice(0, 120);
    const checkpoint = await grantFetch(
      '/v1/approvals',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent_name: 'cloudflare-ai-gateway',
          tool_name: name,
          summary: `Allow the assistant to call ${name}?`,
          scope: redactedScope(call, id),
          workspace: 'public',
          channel: 'cloudflare_worker',
        }),
      },
      env
    );
    if (checkpoint.status >= 400) {
      return json({ error: 'Grant checkpoint failed', status: checkpoint.status }, 502);
    }

    const requestId = String(checkpoint.body.request_id ?? checkpoint.body.id ?? '');
    let receipt = String(checkpoint.body.signed_receipt ?? '');
    let approved = String(checkpoint.body.status ?? '').toLowerCase() === 'approved' || receipt.length > 0;

    if (!approved && String(env.GRANT_MODE || '').toLowerCase() === 'blocking') {
      const waited = await waitForDecision(requestId, env);
      approved = waited.approved;
      receipt = waited.receipt;
    }

    if (!approved) {
      return json(
        {
          status: 'approval_required',
          request_id: requestId,
          approval_url: checkpoint.body.approval_url ?? '',
          receipt_url: checkpoint.body.receipt_url ?? '',
          expires_at: checkpoint.body.expires_at ?? '',
          message: 'Open the Grant pop-up, approve, then retry with X-Grant-Receipt.',
        },
        202
      );
    }

    if (!(await verifyReceipt(receipt, requestId, env))) {
      return json({ error: 'Grant receipt could not be verified. Protected action not executed.' }, 403);
    }
    return forward(request, body, env, receipt, requestId);
  },
};
