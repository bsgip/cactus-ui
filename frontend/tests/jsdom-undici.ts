import { builtinEnvironments, type Environment } from 'vitest/environments';

// jsdom installs its own AbortController/AbortSignal on the global. Node's fetch (undici) — which
// msw and react-router route Requests through — validates `signal instanceof AbortSignal` against
// the *native* class, so a jsdom signal makes `new Request(url, { signal })` throw
// "Expected signal to be an instance of AbortSignal". We run jsdom as normal, then put the native
// AbortController/AbortSignal back so the two realms agree.
const NativeAbortController = globalThis.AbortController;
const NativeAbortSignal = globalThis.AbortSignal;

const jsdom = builtinEnvironments.jsdom;

export default <Environment>{
  name: 'jsdom-undici',
  transformMode: 'web',
  async setup(global, options) {
    const { teardown } = await jsdom.setup(global, options);
    global.AbortController = NativeAbortController;
    global.AbortSignal = NativeAbortSignal;
    return { teardown };
  },
};
