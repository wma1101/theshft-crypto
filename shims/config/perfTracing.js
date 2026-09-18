// Test-runner stub for config/perfTracing.js (app-only performance tracing).
// The shipped app records trace spans for profiling; none of that affects
// the cryptography, so this module is a set of no-ops.
// config/encryption.js calls traces.<name>() for many different span names
// (naclEncrypt, mlkemKeygen, pbkdf2, ...). A Proxy answers every one of them
// with a no-op rather than hardcoding the list, which would drift from the
// real config/perfTracing.js as spans are added there.
export const traces = new Proxy({}, { get: () => () => null });
export const startTrace = () => null;
export const endTrace = () => 0;
export const measure = () => {};
export const measureSync = (fn) => (typeof fn === 'function' ? fn() : undefined);
