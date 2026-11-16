import { http, HttpResponse, type DefaultBodyType, type HttpResponseResolver } from 'msw';
import { API, server } from './msw';

export type Call = {
  method: string;
  path: string;
  query: URLSearchParams;
  json?: unknown;
  form?: Record<string, unknown>;
  files?: string[];
};

export const calls: Call[] = [];

const readBody = async (request: Request): Promise<Pick<Call, 'json' | 'form' | 'files'>> => {
  const type = request.headers.get('content-type') || '';
  if (type.includes('multipart/form-data')) {
    const data = await request.formData();
    const form: Record<string, unknown> = {};
    const files: string[] = [];
    data.forEach((value, key) => {
      if (typeof value === 'string') {
        try {
          form[key] = JSON.parse(value);
        } catch {
          form[key] = value;
        }
      } else {
        files.push(`${key}:${(value as File).name}`);
      }
    });
    return { form, files };
  }
  const text = await request.text();
  if (!text) return {};
  try {
    return { json: JSON.parse(text) };
  } catch {
    return { json: text };
  }
};

type Method = 'get' | 'post' | 'delete' | 'patch' | 'put';

export const route = (method: Method, path: string, resolver: HttpResponseResolver<never, DefaultBodyType>) =>
  http[method](`${API}${path}`, async (info) => {
    const url = new URL(info.request.url);
    const body = await readBody(info.request.clone());
    calls.push({ method: method.toUpperCase(), path: url.pathname, query: url.searchParams, ...body });
    return resolver(info as never);
  });

export const callsTo = (method: string, path: string) =>
  calls.filter((c) => c.method === method && c.path === path);

export const lastCall = (method: string, path: string) => {
  const matching = callsTo(method, path);
  return matching[matching.length - 1];
};

export const now = '2026-03-01T10:20:00Z';

type Row = Record<string, unknown>;
type App = Row & { ID: string; AppName: string };

export const fixtures = () => ({
  apps: [
    { ID: 'app-1', AppName: 'alpha', Description: 'First app', Logo: '', Updated_at: now, Tuf: false },
    {
      ID: 'app-2',
      AppName: 'beta',
      Description: 'Second app with a description that is longer than fifty characters',
      Logo: '',
      Updated_at: now,
      Private: true,
      DownloadMode: 'strict',
      Tuf: true,
      Reports: true,
      CdnEdge: true,
    },
  ] as App[],
  channels: [
    { ID: 'ch-1', ChannelName: 'stable', Updated_at: now },
    { ID: 'ch-2', ChannelName: 'nightly', Updated_at: now },
  ] as Row[],
  platforms: [
    { ID: 'pl-1', PlatformName: 'linux', Updated_at: now, Updaters: [{ type: 'manual', default: true }] },
    {
      ID: 'pl-2',
      PlatformName: 'windows',
      Updated_at: now,
      Updaters: [
        { type: 'manual', default: false },
        { type: 'squirrel_windows', default: true },
      ],
    },
  ] as Row[],
  archs: [
    { ID: 'ar-1', ArchID: 'amd64', Updated_at: now },
    { ID: 'ar-2', ArchID: 'arm64', Updated_at: now },
  ] as Row[],
  versions: [] as Row[],
  user: {
    id: 'u-1',
    username: 'admin',
    is_admin: true,
  } as Record<string, unknown>,
});

export let db = fixtures();

export const version = (id: string, overrides: Record<string, unknown> = {}) => ({
  ID: id,
  AppName: 'alpha',
  Version: `1.0.${id}`,
  Channel: 'stable',
  Published: true,
  Critical: false,
  Intermediate: false,
  Artifacts: [
    { ID: `${id}-a`, link: `${API}/download/${id}.bin`, platform: 'linux', arch: 'amd64', package: '.bin' },
  ],
  Changelog: [{ Version: `1.0.${id}`, Changes: `Changes for ${id}`, Date: now }],
  Updated_at: now,
  ...overrides,
});

export const resetFakeApi = () => {
  db = fixtures();
  calls.length = 0;
};

export const defaultHandlers = () => [
  route('get', '/app/list', () => HttpResponse.json({ apps: db.apps })),
  route('get', '/search', ({ request }) => {
    const url = new URL(request.url);
    const page = Number(url.searchParams.get('page') || 1);
    const limit = Number(url.searchParams.get('limit') || 9);
    const appName = url.searchParams.get('app_name');
    const filtered = db.versions.filter((v) => v.AppName === appName);
    return HttpResponse.json({
      items: filtered.slice((page - 1) * limit, page * limit),
      total: filtered.length,
      page,
      limit,
    });
  }),
  route('get', '/channel/list', () => HttpResponse.json({ channels: db.channels })),
  route('get', '/platform/list', () => HttpResponse.json({ platforms: db.platforms })),
  route('get', '/arch/list', () => HttpResponse.json({ archs: db.archs })),
  route('get', '/whoami', () => HttpResponse.json(db.user)),
  route('get', '/report-keys/list', () => HttpResponse.json({ report_keys: [] })),
  route('get', '/download-tokens/list', () => HttpResponse.json({ download_tokens: [] })),
];

export const useFakeApi = () => {
  resetFakeApi();
  server.use(...defaultHandlers());
};
