import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { execFileSync, spawn } from 'node:child_process';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import {
  feedFilePlaceholder,
  generatePresignedUploadScript,
  type PresignedUploadScriptOptions,
} from '@/utils/generatePresignedUploadScript';

const base: PresignedUploadScriptOptions = {
  apiURL: 'https://api.example.com/',
  appName: 'app',
  channel: 'stable',
  platform: 'linux',
  arch: 'amd64',
  updater: 'manual',
  publish: true,
  critical: false,
  tuf: false,
};

const hostTools = ['bash', 'jq', 'curl', 'openssl'].every((tool) => {
  try {
    execFileSync('sh', ['-c', `command -v ${tool}`]);
    return true;
  } catch {
    return false;
  }
});

describe('feedFilePlaceholder', () => {
  it.each([
    ['velopack', 'beta', 'releases.beta.json'],
    ['velopack', '', 'releases.CHANNEL.json'],
    ['sparkle', 'x', 'appcast.xml'],
    ['squirrel_windows', 'x', 'RELEASES'],
    ['electron-builder', 'x', 'latest.yml'],
    ['manual', 'x', null],
    ['tauri', 'x', null],
  ])('%s/%s -> %s', (updater, channel, expected) => {
    expect(feedFilePlaceholder(updater, channel)).toBe(expected);
  });
});

describe('generatePresignedUploadScript', () => {
  it('trims the API url and falls back to a placeholder', () => {
    expect(generatePresignedUploadScript(base)).toContain("API='https://api.example.com'\n");
    expect(generatePresignedUploadScript({ ...base, apiURL: '  ' })).toContain(
      "API='https://faynosync.example.com'\n",
    );
  });

  it('documents the picked defaults', () => {
    const script = generatePresignedUploadScript({ ...base, publish: false, critical: true, channel: 'my channel' });
    expect(script).toContain("#   --channel 'my channel' --platform linux --arch amd64 --updater manual --no-publish --critical");
  });

  it('shows feed and signature usage per updater', () => {
    expect(generatePresignedUploadScript({ ...base, updater: 'velopack' })).toContain(
      '--feed path/to/releases.stable.json',
    );
    expect(generatePresignedUploadScript({ ...base, updater: 'tauri' })).toContain(
      '--signature "$(cat path/to/artifact.sig)"',
    );
  });

  it('adds sha256/sha512/length to the manifest only for TUF apps', () => {
    expect(generatePresignedUploadScript(base)).not.toContain('sha256');
    const tuf = generatePresignedUploadScript({ ...base, tuf: true });
    expect(tuf).toContain('(TUF: sends sha256/sha512)');
    expect(tuf).toContain('{name:$n, md5:$md5, sha256:$sha256, sha512:$sha512, length:$length}');
  });

  it.runIf(hostTools).each([
    ['plain', base],
    ['tuf + velopack', { ...base, tuf: true, updater: 'velopack' }],
    ['tauri, no defaults', { ...base, updater: 'tauri', channel: '', platform: '', arch: '' }],
    ['hostile names', { ...base, appName: `it's "$(touch /tmp/pwned)" \`x\``, channel: "a'b c" }],
  ])('is valid bash: %s', (_, options) => {
    const script = generatePresignedUploadScript(options as PresignedUploadScriptOptions);
    execFileSync('bash', ['-n'], { input: script });
  });
});

type Recorded = { method: string; url: string; headers: IncomingMessage['headers']; body: Buffer };

describe.runIf(hostTools)('generated script against a fake faynoSync', () => {
  let dir: string;
  let srv: Server;
  let api: string;
  let requests: Recorded[];
  let initStatus: number;
  let presignedHeaders: Record<string, string>;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'fs-presigned-'));
    requests = [];
    initStatus = 200;
    presignedHeaders = { 'Content-Type': 'application/octet-stream', 'x-amz-meta-test': 'yes' };
    srv = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        requests.push({ method: req.method!, url: req.url!, headers: req.headers, body: Buffer.concat(chunks) });
        if (req.url === '/upload/init') {
          if (initStatus !== 200) {
            res.writeHead(initStatus, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'nope' }));
            return;
          }
          const files = ['a.bin', 'b.bin'].map((name) => ({
            name,
            url: `${api}/storage/${name}?sig=1`,
            headers: presignedHeaders,
          }));
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ upload_id: 'up-1', files }));
        } else if (req.url?.startsWith('/storage/')) {
          res.writeHead(200);
          res.end();
        } else if (req.url === '/upload/complete') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"uploadResult":{"Uploaded":"ok"}}');
        } else {
          res.writeHead(404);
          res.end();
        }
      });
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    const address = srv.address();
    api = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
  });

  afterEach(async () => {
    await new Promise((r) => srv.close(r));
    rmSync(dir, { recursive: true, force: true });
  });

  const run = (options: Partial<PresignedUploadScriptOptions>, args: string[], token: string | null = 'tok') => {
    const script = join(dir, 'upload.sh');
    writeFileSync(script, generatePresignedUploadScript({ ...base, apiURL: api, ...options }));
    chmodSync(script, 0o755);
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH };
    if (token !== null) env.FAYNOSYNC_TOKEN = token;
    return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
      const child = spawn('bash', [script, ...args], { cwd: dir, env });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      child.on('close', (code) => resolve({ code, stdout, stderr }));
    });
  };

  const formField = (body: Buffer, field: string): string => {
    const text = body.toString('utf8');
    const match = text.match(new RegExp(`name="${field}"\\r\\n\\r\\n([\\s\\S]*?)\\r\\n--`));
    if (!match) throw new Error(`field ${field} not in form: ${text}`);
    return match[1];
  };

  const writeArtifacts = () => {
    writeFileSync(join(dir, 'a.bin'), 'alpha');
    writeFileSync(join(dir, 'b.bin'), 'bravo-bytes');
  };

  const md5 = (s: string) => createHash('md5').update(s).digest('hex');
  const sha = (alg: string, s: string) => createHash(alg).update(s).digest('hex');

  it('runs init -> PUT -> complete with the dashboard defaults', async () => {
    writeArtifacts();
    const result = await run({ appName: "it's app", channel: 'nightly' }, ['--version', '1.4.0', 'a.bin', 'b.bin']);
    expect(result.stderr).toContain('Uploading a.bin');
    expect(result.code).toBe(0);

    expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      'POST /upload/init',
      'PUT /storage/a.bin?sig=1',
      'PUT /storage/b.bin?sig=1',
      'POST /upload/complete',
    ]);

    const [init, putA, putB, complete] = requests;
    expect(init.headers.authorization).toBe('Bearer tok');
    expect(JSON.parse(formField(init.body, 'data'))).toEqual({
      app_name: "it's app",
      version: '1.4.0',
      channel: 'nightly',
      platform: 'linux',
      arch: 'amd64',
      updater: 'manual',
      publish: true,
      critical: false,
    });
    expect(JSON.parse(formField(init.body, 'files'))).toEqual([
      { name: 'a.bin', md5: md5('alpha') },
      { name: 'b.bin', md5: md5('bravo-bytes') },
    ]);

    expect(putA.body.toString()).toBe('alpha');
    expect(putB.body.toString()).toBe('bravo-bytes');
    expect(putA.headers['x-amz-meta-test']).toBe('yes');
    expect(putA.headers['content-type']).toBe('application/octet-stream');
    expect(putA.headers.authorization).toBeUndefined();

    expect(complete.headers.authorization).toBe('Bearer tok');
    expect(JSON.parse(complete.body.toString())).toEqual({ upload_id: 'up-1' });
  });

  it('lets per-run flags override the defaults and sends TUF digests', async () => {
    writeArtifacts();
    writeFileSync(join(dir, 'RELEASES'), 'feed');
    const result = await run({ tuf: true, updater: 'squirrel_windows' }, [
      '--version', '2.0.0', '--channel', 'beta', '--no-publish', '--critical',
      '--changelog', '## notes', '--feed', 'RELEASES', 'a.bin', 'b.bin',
    ]);
    expect(result.code).toBe(0);
    const init = requests[0];
    expect(JSON.parse(formField(init.body, 'data'))).toMatchObject({
      channel: 'beta',
      publish: false,
      critical: true,
      changelog: '## notes',
      updater: 'squirrel_windows',
    });
    expect(JSON.parse(formField(init.body, 'files'))[0]).toEqual({
      name: 'a.bin',
      md5: md5('alpha'),
      sha256: sha('sha256', 'alpha'),
      sha512: sha('sha512', 'alpha'),
      length: 5,
    });
    expect(init.body.toString()).toMatch(/name="file"; filename="RELEASES"/);
  });

  it.each([
    [[], null, 'FAYNOSYNC_TOKEN'],
    [['a.bin'], 'tok', '--version is required'],
    [['--version', '1'], 'tok', 'no files to upload'],
    [['--version', '1', 'missing.bin'], 'tok', 'not a file: missing.bin'],
    [['--bogus'], 'tok', 'unknown option: --bogus'],
  ])('fails before any request: %j', async (args, token, message) => {
    writeArtifacts();
    const result = await run({}, args as string[], token as string | null);
    expect(result.code).not.toBe(0);
    expect(result.stderr).toContain(message);
    expect(requests).toHaveLength(0);
  });

  it.each([
    ['velopack', '--updater velopack needs --feed'],
    ['tauri', '--updater tauri needs --signature'],
  ])('requires the %s companion file', async (updater, message) => {
    writeArtifacts();
    const result = await run({ updater }, ['--version', '1', 'a.bin']);
    expect(result.code).not.toBe(0);
    expect(result.stderr).toContain(message);
    expect(requests).toHaveLength(0);
  });

  it('reports init failures without uploading', async () => {
    writeArtifacts();
    initStatus = 400;
    const result = await run({}, ['--version', '1', 'a.bin']);
    expect(result.code).not.toBe(0);
    expect(result.stderr).toContain('upload/init failed (HTTP 400)');
    expect(requests).toHaveLength(1);
  });

  it('explains 501 from storage drivers without presigned support', async () => {
    writeArtifacts();
    initStatus = 501;
    const result = await run({}, ['--version', '1', 'a.bin']);
    expect(result.code).not.toBe(0);
    expect(result.stderr).toContain('does not support presigned uploads');
  });
});
