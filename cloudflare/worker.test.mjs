import test from "node:test";
import assert from "node:assert/strict";
import worker from "./worker.mjs";

const owner = { access: { aud: "expected-audience", getIdentity: async () => ({ email: "owner@example.test" }) } };
const environment = (fetch) => ({ ACCESS_AUDIENCE: "expected-audience", OWNER_EMAIL: "owner@example.test", NEXUS_GATEWAY: { fetch } });
const assertion = "header.payload.signature";
const request = (path, options = {}) => {
  const { headers, ...init } = options;
  return new Request(`https://nexus.example.workers.dev${path}`, {
    ...init, headers: { "cf-access-jwt-assertion": assertion, ...headers },
  });
};

test("command review routes keep owner identity at gateway, bound bodies and strict methods", async () => {
  const scope = "/v1/nexus/workspaces/debian/code/commands";
  const id = "a".repeat(32);
  const seen = [];
  const env = environment(async (req) => {
    seen.push({path:new URL(req.url).pathname, method:req.method, body:await req.text(),
      principal:req.headers.get("x-nexus-principal"), cookie:req.headers.get("cookie"), auth:req.headers.get("authorization")});
    return Response.json({execution_enabled:false});
  });
  for (const [path, method, body] of [
    [scope,"GET",null], [scope+"/profiles","GET",null], [scope,"POST",{profile_id:"tests",submission_id:id}],
    [scope+"/"+id,"GET",null],
    [scope+"/"+id+"/decision","POST",{digest:"b".repeat(64),decision:"approve"}],
    [scope+"/"+id+"/execute","POST",{digest:"b".repeat(64)}],
    [scope+"/"+id+"/reconcile","POST",{digest:"b".repeat(64)}],
    [scope+"/"+id+"/cancel","POST",{digest:"b".repeat(64)}],
  ]) {
    const res = await worker.fetch(request(path,{method, headers:{"content-type":"application/json",
      "x-nexus-principal":"forged", cookie:"private", authorization:"Bearer injected"},
      ...(body ? {body:JSON.stringify(body)} : {})}),env,owner);
    assert.equal(res.status,200,`${method} ${path}`);
  }
  assert.equal(seen.length,8);
  assert.ok(seen.every(c=>c.principal===null && c.cookie===null && c.auth===`Bearer ${assertion}`));
  for (const [path,method] of [[scope+"/"+id,"POST"],[scope+"/"+id+"/decision","GET"],
    [scope+"/"+id+"/execute","GET"],[scope+"/"+id+"/cancel","GET"],[scope+"/profiles","POST"],[scope+"?x=1","GET"],
    [scope.replace("/debian/","/any/"),"GET"]]) {
    assert.equal((await worker.fetch(request(path,{method}),env,owner)).status,404);
  }
  assert.equal((await worker.fetch(request(scope,{method:"POST",headers:{"content-type":"application/json"},body:"a".repeat(4097)}),env,owner)).status,413);
  assert.equal((await worker.fetch(request(scope,{method:"POST",headers:{"content-type":"text/plain"},body:"{}"}),env,owner)).status,415);
  assert.equal(seen.length,8);
});

test("patch review routes stay scoped, bounded and free of caller identity headers", async () => {
  const scope = "/v1/nexus/workspaces/debian/code/patches";
  const id = "a".repeat(32);
  const seen = [];
  const env = environment(async (req) => {
    seen.push({ path: new URL(req.url).pathname, method: req.method, body: await req.text(), principal: req.headers.get("x-nexus-principal") });
    assert.equal(req.headers.get("authorization"), `Bearer ${assertion}`);
    return Response.json({ execution_enabled: false });
  });
  for (const [path, method, body] of [[scope,"GET",null],[scope,"POST",{ path:"main.py",replacement:"x",submission_id:id }],
    [scope+"/"+id,"GET",null],[scope+"/"+id+"/decision","POST",{digest:"b".repeat(64),decision:"approve"}],
    [scope+"/"+id+"/apply","POST",{digest:"b".repeat(64)}],
    [scope+"/"+id+"/reconcile","POST",{digest:"b".repeat(64)}]]) {
    const response = await worker.fetch(request(path, { method, headers:{"content-type":"application/json","x-nexus-principal":"forged"},
      ...(body ? {body:JSON.stringify(body)} : {}) }),env,owner);
    assert.equal(response.status,200);
  }
  assert.equal(seen.length,6);
  assert.ok(seen.every((call)=>call.principal===null));
  assert.equal(JSON.parse(seen[3].body).decision,"approve");
  for (const [path,method] of [[scope+"/"+id,"POST"],[scope+"/"+id+"/decision","GET"],
    [scope+"/"+id+"/apply","GET"],[scope+"/"+id+"/reconcile","GET"],
    [scope+"?extra=1","GET"],[scope.replace("/debian/","/unknown/"),"GET"]]) {
    assert.equal((await worker.fetch(request(path,{method}),env,owner)).status,404);
  }
  assert.equal((await worker.fetch(request(scope,{method:"POST",headers:{"content-type":"application/json"},
    body:"x".repeat(512*1024+1)}),env,owner)).status,413);
  assert.equal(seen.length,6);
});

test("fails closed before contacting the gateway without an authorized Access identity", async () => {
  let called = false;
  const env = environment(async () => { called = true; return new Response("unexpected"); });
  for (const ctx of [{}, { access: { ...owner.access, aud: "other" } },
    { access: { ...owner.access, getIdentity: async () => ({ email: "other@example.test" }) } },
    { access: { ...owner.access, getIdentity: async () => { throw new Error("failure"); } } }]) {
    assert.equal((await worker.fetch(request("/v1/models"), env, ctx)).status, 403);
  }
  assert.equal((await worker.fetch(request("/v1/models"), { ...env, OWNER_EMAIL: "" }, owner)).status, 403);
  assert.equal(called, false);
});

test("only forwards approved routes and the verified Access assertion, never cookies or proxy headers", async () => {
  let seen;
  const env = environment(async (req) => { seen = req; return new Response("ok", { headers: { "content-type": "text/plain", "set-cookie": "secret=bad" } }); });
  const req = new Request("https://nexus.example.workers.dev/v1/models", { headers: {
    "cf-access-jwt-assertion": assertion, authorization: "Bearer oauth:opaque-token", cookie: "CF_Authorization=private", "x-forwarded-host": "evil.test", accept: "application/json",
  } });
  const result = await worker.fetch(req, env, owner);
  assert.equal(result.status, 200);
  assert.equal(seen.url, "http://nexus-gateway.internal/v1/models");
  assert.equal(seen.headers.get("authorization"), `Bearer ${assertion}`);
  assert.equal(seen.headers.get("cookie"), null);
  assert.equal(seen.headers.get("x-forwarded-host"), null);
  assert.equal(result.headers.get("set-cookie"), null);
  assert.equal(result.headers.get("cache-control"), "no-store");
  for (const path of ["/healthz", "/v1/models?extra=1", "/v1/other", "/v1/conversations/not-a-uuid"]) {
    assert.equal((await worker.fetch(request(path), env, owner)).status, 404);
  }
  assert.equal((await worker.fetch(request("/v1/models", { method: "POST" }), env, owner)).status, 404);
});

test("forwards authenticated tokenizer preflight to the private gateway", async () => {
  let upstream;
  const env = environment(async (req) => { upstream = req; return Response.json({ input_tokens: 321 }); });
  const response = await worker.fetch(request("/v1/chat/completions/input_tokens", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "installed-model", messages: [{ role: "user", content: "hello" }], stream: false }),
  }), env, owner);
  assert.equal(response.status, 200);
  assert.equal(upstream.url, "http://nexus-gateway.internal/v1/chat/completions/input_tokens");
  assert.equal(upstream.headers.get("authorization"), `Bearer ${assertion}`);
  assert.equal((await response.json()).input_tokens, 321);
});

test("requires the verified Access assertion, enforces declared limits and denies redirects", async () => {
  let calls = 0;
  const env = environment(async () => { calls++; return new Response(null, { status: 302, headers: { location: "https://evil.test" } }); });
  assert.equal((await worker.fetch(new Request("https://nexus.example.workers.dev/v1/models"), env, owner)).status, 401);
  assert.equal((await worker.fetch(request("/v1/chat/completions", { method: "POST", headers: {
    "content-length": "9000000",
  } }), env, owner)).status, 413);
  assert.equal((await worker.fetch(request("/v1/models"), env, owner)).status, 502);
  assert.equal(calls, 1);
});

test("relays streamed chat data without waiting for the upstream stream to close", async () => {
  let streamController;
  const stream = new ReadableStream({ start(controller) { streamController = controller; controller.enqueue(new TextEncoder().encode("data: first\n\n")); } });
  const env = environment(async (req) => {
    assert.equal(req.method, "POST");
    assert.equal(await req.text(), '{"stream":true}');
    return new Response(stream, { headers: { "content-type": "text/event-stream" } });
  });
  const req = request("/v1/chat/completions", { method: "POST", headers: { "content-type": "application/json" }, body: '{"stream":true}' });
  const result = await worker.fetch(req, env, owner);
  const reader = result.body.getReader();
  assert.equal(new TextDecoder().decode((await reader.read()).value), "data: first\n\n");
  streamController.close();
  assert.equal((await reader.read()).done, true);
});

test("passes conversation revision headers only on allowed UUID routes", async () => {
  const env = environment(async (req) => {
    assert.equal(req.headers.get("if-match"), '"4"');
    return new Response(null, { status: 204 });
  });
  const req = request("/v1/conversations/01234567-89ab-cdef-0123-456789abcdef", {
    method: "DELETE", headers: { "if-match": '"4"' },
  });
  assert.equal((await worker.fetch(req, env, owner)).status, 204);
});

test("SSH upgrade requires the fixed subprotocol before reaching the private gateway", async () => {
  let calls = 0;
  const env = environment(async () => { calls++; return new Response("unexpected"); });
  const makeRequest = (protocol) => request("/v1/ssh/nixos", { headers: {
    Upgrade: "websocket", ...(protocol ? { "sec-websocket-protocol": protocol } : {}),
  } });
  assert.equal((await worker.fetch(makeRequest(null), env, owner)).status, 426);
  assert.equal((await worker.fetch(makeRequest("other-protocol"), env, owner)).status, 426);
  assert.equal(calls, 0);
});

test("SSH upstream WebSocket 101 echoes the selected subprotocol to the iOS client", async () => {
  const socket = { marker: "gateway-websocket" };
  let upstreamRequest;
  const env = environment(async (req) => {
    upstreamRequest = req;
    return { status: 101, webSocket: socket,
      headers: new Headers({ "sec-websocket-protocol": "nexus-ssh-v1" }) };
  });
  // Node's native Response disallows 101. Mock only the response constructor
  // for this fixture; production uses Cloudflare's WebSocket Response support.
  const OriginalResponse = globalThis.Response;
  globalThis.Response = class WebSocketResponse {
    constructor(body, init) {
      this.body = body;
      this.status = init.status;
      this.headers = new Headers(init.headers);
      this.webSocket = init.webSocket;
    }
  };
  try {
    const response = await worker.fetch(request("/v1/ssh/nixos", { headers: {
      Upgrade: "websocket", "sec-websocket-protocol": "nexus-ssh-v1",
      authorization: "Bearer never-forward-this-token",
    } }), env, owner);
    assert.equal(upstreamRequest.url, "http://nexus-gateway.internal/v1/ssh/nixos");
    assert.equal(upstreamRequest.headers.get("authorization"), `Bearer ${assertion}`);
    assert.equal(upstreamRequest.headers.get("sec-websocket-protocol"), "nexus-ssh-v1");
    assert.equal(response.status, 101);
    assert.equal(response.webSocket, socket);
    assert.equal(response.headers.get("sec-websocket-protocol"), "nexus-ssh-v1");
  } finally {
    globalThis.Response = OriginalResponse;
  }
});

test("orchestrator routes allow only documented methods, normalized IDs, and verified assertion", async () => {
  const seen = [];
  const env = environment(async (req) => {
    seen.push({ method: req.method, path: new URL(req.url).pathname, search: new URL(req.url).search, auth: req.headers.get("authorization"),
      cookie: req.headers.get("cookie"), host: req.headers.get("x-forwarded-host"),
      content: req.method === "POST" && req.body ? await req.text() : "" });
    const path = new URL(req.url).pathname;
    const status = req.method === "POST" && (path.includes("models/") || path === "/v1/nexus/agent-runs")
      ? 202 : 200;
    const payload = path.endsWith("/active") ? { active: 0 }
      : path === "/v1/nexus/agent-runs" && req.method === "POST"
        ? { id: "0123456789abcdef0123456789abcdef", status: "queued" }
        : { id: "0123456789abcdef0123456789abcdef", status: "running", phase: "working", subagents: [] };
    return new Response(JSON.stringify(payload), {
      status,
      headers: { "set-cookie": "bad=value", "content-type": "application/json" },
    });
  });
  const cases = [
    ["GET", "/v1/nexus/workspaces", null],
    ["GET", "/v1/nexus/workspaces/debian", null],
    ["GET", "/v1/nexus/workspaces/debian/code/files?path=src%2Fmain.swift", null],
    ["GET", "/v1/nexus/workspaces/debian/code/context?path=src%2Fmain.swift", null],
    ["POST", "/v1/nexus/agent-runs", JSON.stringify({ prompt: "summarize", workspace: { host: "debian", workspace_id: "code", path: "" } })],
    ["POST", "/v1/nexus/workspaces/debian/code/tasks", JSON.stringify({ host: "debian", workspace_id: "code", operation: "inventory", path: "", query: "" })],
    ["GET", "/v1/nexus/agent-runs", null],
    ["GET", "/v1/nexus/agent-runs/active", null],
    ["GET", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef", null],
    ["POST", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef/cancel", null],
    ["POST", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef/subagents/abcdef0123456789abcdef0123456789/cancel", null],
    ["GET", "/v1/nexus/models", null],
    ["GET", "/v1/nexus/status", null],
    ["GET", "/v1/nexus/models/status", null],
    ["POST", "/v1/nexus/models/unload", null],
    ["POST", "/v1/nexus/models/0123456789abcdef/load", null],
  ];
  for (const [method, path, body] of cases) {
    const result = await worker.fetch(request(path, {
      method, body, headers: {
        authorization: "Bearer caller-oauth-credential",
        cookie: "session=private", "x-forwarded-host": "evil.test",
        ...(body === null ? {} : { "content-type": "application/json" }),
      },
    }), env, owner);
    assert.equal(result.status, method === "POST" && (path.includes("/models/") || path === "/v1/nexus/agent-runs") ? 202 : 200, path);
    assert.equal(result.headers.get("set-cookie"), null);
    assert.equal(result.headers.get("cache-control"), "no-store");
  }
  assert.deepEqual(seen.map((entry) => [entry.method, entry.path, entry.search]),
    cases.map(([method, path]) => {
      const url = new URL(path, "https://worker.example");
      return [method, url.pathname, url.search];
    }));
  for (const entry of seen) {
    assert.equal(entry.auth, "Bearer " + assertion);
    assert.equal(entry.cookie, null);
    assert.equal(entry.host, null);
  }
  assert.equal(seen.find((entry) => entry.path === "/v1/nexus/agent-runs").content,
    cases.find(([, path]) => path === "/v1/nexus/agent-runs")[2]);
  const before = seen.length;
  for (const [method, path] of [
    ["GET", "/v1/nexus/models/0123456789abcdef/load"],
    ["POST", "/v1/nexus/models/0123456789abcdeG/load"],
    ["POST", "/v1/nexus/models/0123456789abcdef/load?token=bad"],
    ["GET", "/v1/nexus/workspaces?host=other"],
    ["GET", "/v1/nexus/workspaces/debian/code/files?path=../secret"],
    ["GET", "/v1/nexus/workspaces/debian/code/files?path=src%2F..%2Fsecret"],
    ["GET", "/v1/nexus/workspaces/debian/code/files?path=src&path=other"],
    ["POST", "/v1/nexus/workspaces/debian/code/tasks"],
    ["GET", "/v1/nexus/agent-runs/ABCDEF0123456789ABCDEF0123456789"],
    ["POST", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef/cancel?token=bad"],
    ["POST", "/v1/nexus/models/status"],
    ["GET", "/v1/nexus/models/anything/load"],
  ]) {
    const expected = path.includes("/files?path=") ? 400
      : path.endsWith("/tasks") && method === "POST" ? 415 : 404;
    assert.equal((await worker.fetch(request(path, { method }), env, owner)).status, expected, path);
  }
  assert.equal(seen.length, before);
});

test("bodyless actions accept empty POST streams and forward no body", async () => {
  const seen = [];
  const env = environment(async (req) => {
    seen.push({ path: new URL(req.url).pathname, body: req.body });
    return new Response(null, { status: 202 });
  });
  const paths = ["/v1/nexus/models/0123456789abcdef/load", "/v1/nexus/models/unload",
    "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef/cancel"];
  for (const path of paths) {
    for (const headers of [{}, { "content-length": "0" }]) {
      const req = request(path, { method: "POST", headers, body: "" });
      assert.notEqual(req.body, null); // zero bytes, but a real stream object
      assert.equal((await worker.fetch(req, env, owner)).status, 202);
    }
  }
  assert.equal(seen.length, 6);
  assert.ok(seen.every((entry) => entry.body === null));
  for (const headers of [{}, { "content-length": "0" }]) {
    assert.equal((await worker.fetch(request(paths[0], {
      method: "POST", headers, body: "x",
    }), env, owner)).status, 400);
  }
  assert.equal((await worker.fetch(request(paths[0], {
    method: "POST", headers: { "content-length": "1" }, body: "",
  }), env, owner)).status, 400);
  const broken = new ReadableStream({ start(controller) { controller.error(new Error("fixture")); } });
  assert.equal((await worker.fetch(request(paths[0], {
    method: "POST", body: broken, duplex: "half",
  }), env, owner)).status, 400);
  assert.equal(seen.length, 6); // dishonest length must not reach the gateway
});

test("orchestrator enforces bounded request bodies without content-length and returns disabled 503", async () => {
  let calls = 0;
  const env = environment(async () => {
    calls++;
    return new Response(JSON.stringify({ error: "native control off" }), {
      status: 503, headers: { "content-type": "application/json" },
    });
  });
  const endpoint = "/v1/nexus/agent-runs";
  assert.equal((await worker.fetch(request(endpoint, { method: "POST",
    headers: { "content-type": "text/plain" }, body: "{}" }), env, owner)).status, 415);
  assert.equal((await worker.fetch(request(endpoint, { method: "POST",
    headers: { "content-type": "application/json" }, body: "x".repeat(2 * 1024 * 1024 + 1) }), env, owner)).status, 413);
  assert.equal((await worker.fetch(request("/v1/nexus/models/unload", { method: "POST",
    body: "{}", headers: { "content-type": "application/json" } }), env, owner)).status, 400);
  assert.equal(calls, 0);
  const largerHistory = JSON.stringify({ prompt: "continue", history: Array.from({ length: 16 },
    () => ({ role: "assistant", content: "x".repeat(40 * 1024) })) });
  assert.ok(largerHistory.length > 512 * 1024);
  assert.equal((await worker.fetch(request(endpoint, { method: "POST",
    headers: { "content-type": "application/json" }, body: largerHistory }), env, owner)).status, 503);
  for (const path of ["/v1/nexus/models", "/v1/nexus/status", "/v1/nexus/models/status"]) {
    assert.equal((await worker.fetch(request(path), env, owner)).status, 503);
  }
  assert.equal(calls, 4);
});

test("the existing Minecraft panel relay still forwards its dedicated prefix", async () => {
  let upstreamRequest;
  const env = environment(async (req) => {
    upstreamRequest = req;
    return new Response("panel-ok", { headers: { "content-type": "text/plain" } });
  });
  const response = await worker.fetch(request("/?page=1", { method: "GET" }), env, owner);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "panel-ok");
  assert.equal(upstreamRequest.url, "http://nexus-gateway.internal/v1/minecraft/panel?page=1");
  assert.equal(upstreamRequest.headers.get("authorization"), "Bearer " + assertion);
});
