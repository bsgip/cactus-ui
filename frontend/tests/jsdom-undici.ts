import { builtinEnvironments, type Environment } from 'vitest/environments';

// jsdom installs its own AbortController/AbortSignal/URLSearchParams on the global. Node's fetch
// (undici) — which msw, react-router, and apiDownload's Request bodies route through — validates
// constructs like `signal instanceof AbortSignal` and `body instanceof URLSearchParams` against
// the *native* classes, so a jsdom instance makes `new Request(url, { signal / body })` throw
// "Expected [...] to be an instance of [...]". We run jsdom as normal, then put the native
// classes back so the two realms agree.
const NativeAbortController = globalThis.AbortController;
const NativeAbortSignal = globalThis.AbortSignal;
const NativeURLSearchParams = globalThis.URLSearchParams;

const jsdom = builtinEnvironments.jsdom;

export default <Environment>{
  name: 'jsdom-undici',
  transformMode: 'web',
  async setup(global, options) {
    const { teardown } = await jsdom.setup(global, options);
    global.AbortController = NativeAbortController;
    global.AbortSignal = NativeAbortSignal;
    global.URLSearchParams = NativeURLSearchParams;
    return { teardown };
  },
};
