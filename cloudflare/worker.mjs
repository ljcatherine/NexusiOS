// Cloudflare Access authenticates the request before this Worker is invoked.
// The private gateway independently validates the forwarded OIDC bearer token.
const fixedRoutes = new Map([
  ["/v1/models", new Set(["GET"])],
  ["/v1/context", new Set(["GET"])],
  ["/v1/chat/completions", new Set(["POST"])],
  ["/v1/chat/completions/input_tokens", new Set(["POST"])],
  ["/v1/search", new Set(["POST"])],
  ["/v1/research", new Set(["POST"])],
  ["/v1/conversations", new Set(["GET"])],
  ["/v1/nexus/workspaces", new Set(["GET"])],
  ["/v1/nexus/agent-runs", new Set(["GET", "POST"])],
  ["/v1/nexus/agent-runs/active", new Set(["GET"])],
  ["/v1/nexus/models", new Set(["GET"])],
  ["/v1/nexus/status", new Set(["GET"])],
  ["/v1/nexus/models/status", new Set(["GET"])],
  ["/v1/nexus/models/unload", new Set(["POST"])],
]);
const conversationPath = /^\/v1\/conversations\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const conversationMethods = new Set(["GET", "PUT", "DELETE"]);
const nexusModelLoadPath = /^\/v1\/nexus\/models\/[0-9a-f]{16}\/load$/;
const nexusModelLoadMethods = new Set(["POST"]);
const nexusAgentRunPath = /^\/v1\/nexus\/agent-runs\/[0-9a-f]{32}$/;
const nexusAgentRunCancelPath = /^\/v1\/nexus\/agent-runs\/[0-9a-f]{32}\/cancel$/;
const nexusSubagentCancelPath = /^\/v1\/nexus\/agent-runs\/[0-9a-f]{32}\/subagents\/[0-9a-f]{32}\/cancel$/;
const nexusWorkspaceListPath = /^\/v1\/nexus\/workspaces\/(debian|nixos)$/;
const nexusWorkspaceFilesPath = /^\/v1\/nexus\/workspaces\/(debian|nixos)\/[a-z][a-z0-9_-]{0,31}\/files$/;
const nexusWorkspaceContextPath = /^\/v1\/nexus\/workspaces\/(debian|nixos)\/[a-z][a-z0-9_-]{0,31}\/context$/;
const nexusWorkspaceTaskPath = /^\/v1\/nexus\/workspaces\/(debian|nixos)\/[a-z][a-z0-9_-]{0,31}\/tasks$/;
const nexusPatchPath = /^\/v1\/nexus\/workspaces\/(debian|nixos)\/[a-z][a-z0-9_-]{0,31}\/patches(?:\/([0-9a-f]{32})(?:\/(decision|apply|reconcile))?)?$/;
const nexusCommandPath = /^\/v1\/nexus\/workspaces\/(debian|nixos)\/[a-z][a-z0-9_-]{0,31}\/commands(?:\/([0-9a-f]{32})(?:\/(decision|execute|reconcile|cancel))?)?$/;
const nexusCommandProfilesPath = /^\/v1\/nexus\/workspaces\/(debian|nixos)\/[a-z][a-z0-9_-]{0,31}\/commands\/profiles$/;
const sshTargetPath = /^\/v1\/ssh\/(nixos|debian)$/;
const maxRequestBytes = 8 * 1024 * 1024;
const maxOrchestratorRequestBytes = 2 * 1024 * 1024;
const maxPanelRequestBytes = 64 * 1024 * 1024;

async function readBoundedBody(body, limit) {
  if (!body) return null;
  const reader = body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function deny(status, message) {
  return new Response(JSON.stringify({ error: message }), {
    status, headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

async function forwardPanel(request, env, ctx, url, assertion) {
  if (url.pathname === "/v1" || url.pathname.startsWith("/v1/") ||
      url.pathname === "/healthz" || url.pathname.startsWith("/cdn-cgi/")) return deny(404, "not found");
  const allowedMethods = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
  const websocket = request.headers.get("Upgrade")?.toLowerCase() === "websocket";
  if (!allowedMethods.has(request.method) || (websocket && request.method !== "GET")) {
    return deny(405, "method not allowed");
  }
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxPanelRequestBytes)) {
    return deny(413, "request too large");
  }
  if (!env.NEXUS_GATEWAY || typeof env.NEXUS_GATEWAY.fetch !== "function") {
    return deny(503, "gateway unavailable");
  }
  const gatewayPath = `/v1/minecraft/panel${url.pathname === "/" ? "" : url.pathname}${url.search}`;
  const headers = new Headers({ authorization: `Bearer ${assertion}` });
  for (const name of [
    "accept", "content-type", "cookie", "origin", "referer", "range", "if-match",
    "if-none-match", "if-modified-since", "if-range", "cache-control", "upgrade",
    "sec-websocket-protocol", "sec-websocket-extensions",
  ]) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  try {
    const init = { method: request.method, headers, redirect: "manual", signal: request.signal };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
      init.duplex = "half";
    }
    const upstream = await env.NEXUS_GATEWAY.fetch(new Request(
      `http://nexus-gateway.internal${gatewayPath}`, init,
    ));
    if (upstream.status === 101 && upstream.webSocket) {
      return new Response(null, { status: 101, webSocket: upstream.webSocket,
        headers: { "cache-control": "no-store" } });
    }
    const responseHeaders = new Headers({ "cache-control": "no-store" });
    for (const name of [
      "content-type", "content-length", "content-disposition", "location", "etag", "last-modified",
      "accept-ranges", "content-range", "retry-after",
    ]) {
      const value = upstream.headers.get(name);
      if (value !== null) responseHeaders.set(name, value);
    }
    for (const cookie of upstream.headers.getSetCookie()) responseHeaders.append("set-cookie", cookie);
    return new Response(request.method === "HEAD" || upstream.status === 204 || upstream.status === 304
      ? null : upstream.body, { status: upstream.status, headers: responseHeaders });
  } catch {
    return deny(502, "Minecraft panel unavailable");
  }
}

export default {
  async fetch(request, env, ctx) {
    const audience = typeof env.ACCESS_AUDIENCE === "string" ? env.ACCESS_AUDIENCE.trim() : "";
    const owner = typeof env.OWNER_EMAIL === "string" ? env.OWNER_EMAIL.trim().toLowerCase() : "";
    const accessContextPresent = Boolean(ctx?.access);
    const audienceMatches = accessContextPresent && ctx.access.aud === audience;
    if (!audience || !owner || !accessContextPresent || !audienceMatches) {
      console.warn("Access validation denied", {
        audienceConfigured: Boolean(audience),
        ownerConfigured: Boolean(owner),
        accessContextPresent,
        audienceMatches,
      });
      return deny(403, "access denied");
    }
    let identity;
    try {
      identity = await ctx.access.getIdentity();
    } catch {
      console.warn("Access identity lookup failed");
      return deny(403, "access denied");
    }
    const identityEmailPresent = typeof identity?.email === "string";
    const identityEmailMatches = identityEmailPresent && identity.email.trim().toLowerCase() === owner;
    if (!identityEmailMatches) {
      const accessEmailHeader = request.headers.get("cf-access-authenticated-user-email");
      const accessEmailPresent = typeof accessEmailHeader === "string" && accessEmailHeader.length > 0;
      const normalizedAccessEmail = accessEmailPresent ? accessEmailHeader.trim().toLowerCase() : "";
      console.warn("Access identity rejected", {
        identityEmailPresent,
        identityEmailMatches,
        accessEmailPresent,
        accessEmailMatchesOwner: accessEmailPresent && normalizedAccessEmail === owner,
        identityMatchesAccessEmail: identityEmailPresent && accessEmailPresent &&
          identity.email.trim().toLowerCase() === normalizedAccessEmail,
      });
      return deny(403, "access denied");
    }

    const url = new URL(request.url);
    if (url.pathname === "/oauth2redirect") {
      if (request.method !== "GET") return deny(405, "method not allowed");
      const codes = url.searchParams.getAll("code");
      const states = url.searchParams.getAll("state");
      const errors = url.searchParams.getAll("error");
      const parameterNames = [...url.searchParams.keys()];
      const allowedParameters = new Set(["code", "state", "error", "iss", "error_description"]);
      const hasDuplicateParameters = new Set(parameterNames).size !== parameterNames.length;
      if (states.length !== 1 || !states[0] || states[0].length > 256 ||
          hasDuplicateParameters || parameterNames.length > 4 ||
          parameterNames.some((name) => !allowedParameters.has(name)) ||
          (url.searchParams.get("iss")?.length ?? 0) > 2048 ||
          (url.searchParams.get("error_description")?.length ?? 0) > 1024) {
        return deny(400, "invalid OAuth callback");
      }
      const callback = new URL("com.ljcatherine.Nexus:/oauth2redirect");
      callback.searchParams.set("state", states[0]);
      if (codes.length === 1 && codes[0] && codes[0].length <= 8192 && errors.length === 0) {
        callback.searchParams.set("code", codes[0]);
      } else if (errors.length === 1 && /^[A-Za-z0-9_-]{1,128}$/.test(errors[0]) && codes.length === 0) {
        callback.searchParams.set("error", errors[0]);
      } else {
        return deny(400, "invalid OAuth callback");
      }
      return new Response(null, { status: 302, headers: {
        location: callback.toString(),
        "cache-control": "no-store",
        "referrer-policy": "no-referrer",
      } });
    }
    const sshTarget = sshTargetPath.exec(url.pathname);
    if (sshTarget) {
      if (url.search || url.hash || request.method !== "GET" ||
          request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return deny(426, "websocket upgrade required");
      }
      // The iOS client and the Debian gateway both require this exact
      // subprotocol. Returning a 101 without echoing it makes NIO reject the
      // upgrade even when the WebSocket itself was established successfully.
      const sshProtocol = "nexus-ssh-v1";
      if (request.headers.get("sec-websocket-protocol") !== sshProtocol) {
        return deny(426, "SSH websocket subprotocol required");
      }
      const assertion = request.headers.get("cf-access-jwt-assertion") ?? "";
      if (assertion.length > 16_384 || assertion.split(".").length !== 3 ||
          !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(assertion)) {
        return deny(401, "verified Access assertion required");
      }
      if (!env.NEXUS_GATEWAY || typeof env.NEXUS_GATEWAY.fetch !== "function") {
        return deny(503, "gateway unavailable");
      }
      try {
        const headers = new Headers({
          authorization: `Bearer ${assertion}`,
          upgrade: "websocket",
        });
        headers.set("sec-websocket-protocol", sshProtocol);
        const upstream = await env.NEXUS_GATEWAY.fetch(new Request(
          `http://nexus-gateway.internal/v1/ssh/${sshTarget[1]}`,
          { method: "GET", headers, redirect: "manual", signal: request.signal },
        ));
        if (upstream.status !== 101 || !upstream.webSocket) {
          console.warn("SSH relay upstream upgrade failed", { upstreamStatus: upstream.status });
          return deny(502, "SSH relay unavailable");
        }
        const selectedProtocol = upstream.headers.get("sec-websocket-protocol");
        if (selectedProtocol !== null && selectedProtocol !== sshProtocol) {
          console.warn("SSH relay upstream subprotocol mismatch");
          return deny(502, "SSH relay unavailable");
        }
        return new Response(null, {
          status: 101,
          webSocket: upstream.webSocket,
          headers: { "cache-control": "no-store", "sec-websocket-protocol": sshProtocol },
        });
      } catch {
        console.warn("SSH relay upstream request failed");
        return deny(502, "SSH relay unavailable");
      }
    }
    const patch = nexusPatchPath.exec(url.pathname);
    const patchMethods = patch ? new Set(patch[3] ? ["POST"] : patch[2] ? ["GET"] : ["GET", "POST"]) : null;
    const command = nexusCommandPath.exec(url.pathname);
    const commandMethods = command ? new Set(command[3] ? ["POST"] : command[2] ? ["GET"] : ["GET", "POST"]) : null;
    const methods = fixedRoutes.get(url.pathname) ?? patchMethods ?? commandMethods ??
      (nexusCommandProfilesPath.test(url.pathname) ? new Set(["GET"]) : null) ??
      (conversationPath.test(url.pathname) ? conversationMethods :
        nexusModelLoadPath.test(url.pathname) ? nexusModelLoadMethods :
          nexusAgentRunPath.test(url.pathname) ? new Set(["GET"]) :
            nexusAgentRunCancelPath.test(url.pathname) || nexusSubagentCancelPath.test(url.pathname)
              ? new Set(["POST"]) :
              nexusWorkspaceListPath.test(url.pathname) || nexusWorkspaceFilesPath.test(url.pathname) ||
                nexusWorkspaceContextPath.test(url.pathname) ? new Set(["GET"]) :
                nexusWorkspaceTaskPath.test(url.pathname) ? new Set(["POST"]) : null);
    // Managed OAuth access tokens are opaque and must never be forwarded to the
    // private gateway as JWTs. Access resolves them before invocation and adds its
    // signed application assertion for the origin.
    const assertion = request.headers.get("cf-access-jwt-assertion") ?? "";
    if (assertion.length > 16_384 || assertion.split(".").length !== 3 ||
        !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(assertion)) {
      return deny(401, "verified Access assertion required");
    }
    if (!methods) return forwardPanel(request, env, ctx, url, assertion);
    const workspaceFiles = nexusWorkspaceFilesPath.test(url.pathname);
    const workspaceContext = nexusWorkspaceContextPath.test(url.pathname);
    const workspaceTask = nexusWorkspaceTaskPath.test(url.pathname);
    const patchPost = patch !== null && request.method === "POST";
    const commandPost = command !== null && request.method === "POST";
    if (!methods.has(request.method) || url.hash || (!workspaceFiles && !workspaceContext && url.search)) {
      return deny(404, "not found");
    }
    if (workspaceFiles || workspaceContext) {
      if (url.search.length > 2048) return deny(400, "invalid workspace path");
      const pathValues = url.searchParams.getAll("path");
      if ([...url.searchParams.keys()].some((key) => key !== "path") || pathValues.length > 1) {
        return deny(400, "invalid workspace path");
      }
      const workspacePath = pathValues[0] ?? "";
      if (workspacePath.length > 512 || workspacePath.startsWith("/") ||
          workspacePath.includes("\\") || workspacePath.includes("\0") ||
          (workspaceContext && workspacePath.length === 0) ||
          (workspacePath.length > 0 && workspacePath.split("/").some((part) => !part || part === "." || part === ".."))) {
        return deny(400, "invalid workspace path");
      }
      url.search = pathValues.length ? `?path=${encodeURIComponent(workspacePath)}` : "";
    }
    const isOrchestrator = url.pathname.startsWith("/v1/nexus/");
    const isAgentRun = request.method === "POST" && url.pathname === "/v1/nexus/agent-runs";
    const length = request.headers.get("content-length");
    const maxBody = commandPost ? 4096 : patchPost ? 512 * 1024 : workspaceTask ? 4096 : (isOrchestrator ? maxOrchestratorRequestBytes : maxRequestBytes);
    if (length !== null && (!/^\d+$/.test(length) ||
        Number(length) > maxBody)) {
      return deny(413, "request too large");
    }
    const bodylessOrchestrator = isOrchestrator && !isAgentRun && !workspaceTask && !patchPost && !commandPost;
    if (bodylessOrchestrator) {
      // An empty HTTP POST can arrive with a non-null, zero-byte stream.
      // Check actual bytes (never trust Content-Length alone), then discard
      // that consumed empty stream instead of forwarding it as chunked data.
      if (length !== null && Number(length) !== 0) return deny(400, "request body not permitted");
      if (request.body !== null) {
        try {
          if (await readBoundedBody(request.body, 0) === null) return deny(400, "request body not permitted");
        } catch {
          return deny(400, "invalid request body");
        }
      }
    }
    if ((isAgentRun || workspaceTask || patchPost || commandPost) && request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !== "application/json") {
      return deny(415, "application/json required");
    }
    if (!env.NEXUS_GATEWAY || typeof env.NEXUS_GATEWAY.fetch !== "function") {
      return deny(503, "gateway unavailable");
    }

    // Do not forward the Access cookie, caller-controlled proxy headers, or arbitrary destinations.
    const headers = new Headers({ authorization: `Bearer ${assertion}` });
    for (const name of ["accept", "content-type", "if-match"]) {
      const value = request.headers.get(name);
      if (value !== null) headers.set(name, value);
    }
    // Agent submissions are quick; subsequent status polling is separately
    // bounded by the request timeout and the gateway's response-size limit.
    const signal = isOrchestrator
      ? AbortSignal.any([request.signal, AbortSignal.timeout(150_000)])
      : request.signal;
    const init = { method: request.method, headers, redirect: "manual", signal };
    if (request.method === "POST" || request.method === "PUT") {
      if (isAgentRun || workspaceTask || patchPost || commandPost) {
        try {
          init.body = await readBoundedBody(request.body, maxBody);
        } catch {
          return deny(400, "invalid request body");
        }
        if (init.body === null) return deny(413, "request too large");
      } else {
        init.body = bodylessOrchestrator ? null : request.body;
      }
      if (init.body !== null) init.duplex = "half";
    }
    try {
      const upstream = await env.NEXUS_GATEWAY.fetch(new Request(`http://nexus-gateway.internal${url.pathname}${url.search}`, init));
      if (upstream.status >= 300 && upstream.status < 400) return deny(502, "gateway unavailable");
      const responseHeaders = new Headers({ "cache-control": "no-store" });
      for (const name of ["content-type", "etag", "retry-after"]) {
        const value = upstream.headers.get(name);
        if (value !== null) responseHeaders.set(name, value);
      }
      return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
    } catch {
      return deny(502, "gateway unavailable");
    }
  },
};
