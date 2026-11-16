import '@testing-library/jest-dom/vitest';
import { afterAll, afterEach, beforeAll, vi } from 'vitest';
import { cleanup, configure } from '@testing-library/react';
import { Blob as NodeBlob, File as NodeFile } from 'node:buffer';
import { server } from './msw';
import { clearQueryClients } from './render';

// jsdom's FormData/File reach MSW's XHR interceptor as "[object FormData]"; Node's natives serialize as multipart.
const NodeFormData = (await new Response('a=1', { headers: { 'content-type': 'application/x-www-form-urlencoded' } }).formData()).constructor as typeof FormData;
globalThis.FormData = NodeFormData;
globalThis.File = NodeFile as unknown as typeof File;
globalThis.Blob = NodeBlob as unknown as typeof Blob;

configure({ asyncUtilTimeout: 3000 });

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;

if (!window.matchMedia) {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList;
}

window.scrollTo = vi.fn() as unknown as typeof window.scrollTo;
Element.prototype.scrollIntoView = vi.fn();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  cleanup();
  clearQueryClients();
  server.resetHandlers();
  localStorage.clear();
  sessionStorage.clear();
});
afterAll(() => server.close());
