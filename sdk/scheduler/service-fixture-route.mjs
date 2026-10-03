// SPDX-License-Identifier: AGPL-3.0-only
// Controlled TLS fixture transport; never accepts a caller-selected destination.
export function fixtureRequest(upstream, method, target) {
  const source = new URL(upstream);
  const port = Number(source.port);
  if (source.protocol !== 'http:' || source.hostname !== '127.0.0.1' ||
      source.pathname !== '/' || source.search || source.hash || source.username || source.password ||
      !Number.isInteger(port) || port < 1 || port > 65535 ||
      !['GET', 'POST'].includes(method) || target !== '/v1/workflow/tools') {
    throw new Error('fixture route refused');
  }
  return { hostname: '127.0.0.1', port, method, path: '/v1/workflow/tools' };
}
