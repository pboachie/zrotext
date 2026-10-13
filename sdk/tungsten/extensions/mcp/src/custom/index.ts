// Hand-written extensions of this MCP server. tungsten creates this file once
// and never overwrites or deletes it; src/server.ts calls `customize` before
// the server starts.

import type { ServerOptions } from "@elysra/tungsten-mcp";

/** Adjust the server options: wrap `createCore` to add middleware, enable
 * the sandbox, change the name. Return them unchanged to keep the defaults. */
export function customize(options: ServerOptions): ServerOptions {
  return options;
}
