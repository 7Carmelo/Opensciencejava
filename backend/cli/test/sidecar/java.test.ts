import { afterEach, describe, expect, test } from "bun:test"
import path from "path"
import { JavaSidecar } from "../../src/sidecar/java"

const original = process.env.OPENSCIENCE_JAVA_SIDECAR_URL
const http = process.env.HTTP_PROXY
const https = process.env.HTTPS_PROXY
const bypass = process.env.NO_PROXY
const servers = new Set<ReturnType<typeof Bun.serve>>()
const sockets = new Set<{ stop(closeActiveConnections?: boolean): void }>()
const input = {
  permission: "bash",
  pattern: "ls",
  rules: [{ permission: "bash", pattern: "ls *", action: "allow" as const }],
  local: { permission: "bash", pattern: "ls *", action: "allow" as const },
}

afterEach(() => {
  for (const server of servers) server.stop(true)
  servers.clear()
  for (const socket of sockets) socket.stop(true)
  sockets.clear()
  if (original === undefined) delete process.env.OPENSCIENCE_JAVA_SIDECAR_URL
  if (original !== undefined) process.env.OPENSCIENCE_JAVA_SIDECAR_URL = original
  if (http === undefined) delete process.env.HTTP_PROXY
  if (http !== undefined) process.env.HTTP_PROXY = http
  if (https === undefined) delete process.env.HTTPS_PROXY
  if (https !== undefined) process.env.HTTPS_PROXY = https
  if (bypass === undefined) delete process.env.NO_PROXY
  if (bypass !== undefined) process.env.NO_PROXY = bypass
})

describe("JavaSidecar.compare", () => {
  test("is disabled when no sidecar URL is configured", async () => {
    delete process.env.OPENSCIENCE_JAVA_SIDECAR_URL

    expect(await JavaSidecar.compare(input)).toEqual({ status: "disabled" })
  })

  test("sends the versioned policy contract to a real loopback server", async () => {
    const received = Promise.withResolvers<unknown>()
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(request) {
        received.resolve(await request.json())
        return Response.json({
          protocolVersion: "1",
          decision: { permission: "bash", pattern: "ls *", action: "allow" },
        })
      },
    })
    servers.add(server)
    process.env.OPENSCIENCE_JAVA_SIDECAR_URL = server.url.origin

    expect(await JavaSidecar.compare(input)).toEqual({ status: "matched" })
    expect(await received.promise).toEqual({
      protocolVersion: "1",
      permission: "bash",
      pattern: "ls",
      rules: [{ permission: "bash", pattern: "ls *", action: "allow" }],
    })
  })

  test("reports an opposing Java decision without changing the local object", async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        return Response.json({
          protocolVersion: "1",
          decision: { permission: "bash", pattern: "ls *", action: "deny" },
        })
      },
    })
    servers.add(server)
    process.env.OPENSCIENCE_JAVA_SIDECAR_URL = server.url.origin

    expect(await JavaSidecar.compare(input)).toEqual({ status: "mismatched" })
    expect(input.local).toEqual({ permission: "bash", pattern: "ls *", action: "allow" })
  })

  test("contains malformed responses and connection failures", async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        return Response.json({ protocolVersion: "2", decision: { action: "grant" } })
      },
    })
    servers.add(server)
    process.env.OPENSCIENCE_JAVA_SIDECAR_URL = server.url.origin

    expect(await JavaSidecar.compare(input)).toEqual({ status: "unavailable" })

    process.env.OPENSCIENCE_JAVA_SIDECAR_URL = "http://127.0.0.1:1"
    expect(await JavaSidecar.compare(input)).toEqual({ status: "unavailable" })
  })

  test("contains a malformed negative HTTP chunk size", async () => {
    const server = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data(socket) {
          socket.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n-6\r\n")
          socket.end()
        },
      },
    })
    sockets.add(server)
    process.env.OPENSCIENCE_JAVA_SIDECAR_URL = `http://127.0.0.1:${server.port}`

    expect(await JavaSidecar.compare(input)).toEqual({ status: "unavailable" })
  })

  test("rejects a chunked response without the final trailer terminator", async () => {
    const body = JSON.stringify({
      protocolVersion: "1",
      decision: { permission: "bash", pattern: "ls *", action: "allow" },
    })
    const server = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data(socket) {
          socket.write(
            `HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${body.length.toString(16)}\r\n${body}\r\n0\r\n`,
          )
          socket.end()
        },
      },
    })
    sockets.add(server)
    process.env.OPENSCIENCE_JAVA_SIDECAR_URL = `http://127.0.0.1:${server.port}`

    expect(await JavaSidecar.compare(input)).toEqual({ status: "unavailable" })
  })

  test("accepts a valid multi-chunk response", async () => {
    const body = JSON.stringify({
      protocolVersion: "1",
      decision: { permission: "bash", pattern: "ls *", action: "allow" },
    })
    const first = body.slice(0, 23)
    const second = body.slice(23)
    const server = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data(socket) {
          socket.write(
            [
              "HTTP/1.1 200 OK",
              "Transfer-Encoding: chunked",
              "Connection: close",
              "",
              `${Buffer.byteLength(first).toString(16)}\r\n${first}`,
              `${Buffer.byteLength(second).toString(16)}\r\n${second}`,
              "0",
              "",
              "",
            ].join("\r\n"),
          )
          socket.end()
        },
      },
    })
    sockets.add(server)
    process.env.OPENSCIENCE_JAVA_SIDECAR_URL = `http://127.0.0.1:${server.port}`

    expect(await JavaSidecar.compare(input)).toEqual({ status: "matched" })
  })

  test("times out a slow sidecar", async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch() {
        await Bun.sleep(2_000)
        return Response.json({
          protocolVersion: "1",
          decision: { permission: "bash", pattern: "ls *", action: "allow" },
        })
      },
    })
    servers.add(server)
    process.env.OPENSCIENCE_JAVA_SIDECAR_URL = server.url.origin

    const started = performance.now()
    expect(await JavaSidecar.compare(input)).toEqual({ status: "unavailable" })
    expect(performance.now() - started).toBeLessThan(1_500)
  })

  test("does not follow a redirect away from the configured endpoint", async () => {
    const calls = { value: 0 }
    const sink = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        calls.value++
        return Response.json({
          protocolVersion: "1",
          decision: { permission: "bash", pattern: "ls *", action: "allow" },
        })
      },
    })
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        return new Response(null, { status: 307, headers: { location: sink.url.origin + "/leak" } })
      },
    })
    servers.add(sink)
    servers.add(server)
    process.env.OPENSCIENCE_JAVA_SIDECAR_URL = server.url.origin

    expect(await JavaSidecar.compare(input)).toEqual({ status: "unavailable" })
    await Bun.sleep(20)
    expect(calls.value).toBe(0)
  })

  test("bypasses HTTP proxy environment variables for loopback traffic", async () => {
    const direct = { value: 0 }
    const routed = { value: 0 }
    const response = {
      protocolVersion: "1",
      decision: { permission: "bash", pattern: "ls *", action: "allow" },
    }
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        direct.value++
        return Response.json(response)
      },
    })
    const proxy = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        routed.value++
        return Response.json(response)
      },
    })
    servers.add(server)
    servers.add(proxy)
    const script = `
      import { JavaSidecar } from "./src/sidecar/java.ts"
      const result = await JavaSidecar.compare({
        permission: "bash",
        pattern: "ls",
        rules: [{ permission: "bash", pattern: "ls *", action: "allow" }],
        local: { permission: "bash", pattern: "ls *", action: "allow" },
      })
      console.log(JSON.stringify(result))
    `
    const proc = Bun.spawn([process.execPath, "-e", script], {
      cwd: path.resolve(import.meta.dir, "../.."),
      env: {
        ...process.env,
        OPENSCIENCE_JAVA_SIDECAR_URL: server.url.origin,
        HTTP_PROXY: proxy.url.origin,
        HTTPS_PROXY: proxy.url.origin,
        NO_PROXY: "",
      },
      stdout: "pipe",
      stderr: "pipe",
    })
    const [stdout, stderr, exit] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ])

    expect({ exit, stderr }).toEqual({ exit: 0, stderr: "" })
    expect(JSON.parse(stdout)).toEqual({ status: "matched" })
    expect(direct.value).toBe(1)
    expect(routed.value).toBe(0)
  })

  test("rejects bare query and fragment delimiters without making a request", async () => {
    const calls = { value: 0 }
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        calls.value++
        return Response.json({
          protocolVersion: "1",
          decision: { permission: "bash", pattern: "ls *", action: "allow" },
        })
      },
    })
    servers.add(server)

    for (const marker of ["?", "#"]) {
      process.env.OPENSCIENCE_JAVA_SIDECAR_URL = server.url.origin + "/" + marker
      expect(await JavaSidecar.compare(input)).toEqual({ status: "unavailable" })
    }
    expect(calls.value).toBe(0)
  })

  test("rejects URLs that are not strict loopback HTTP roots", async () => {
    for (const url of [
      "https://127.0.0.1:8088",
      "http://example.com:8088",
      "http://user:pass@127.0.0.1:8088",
      "http://127.0.0.1:8088/base",
      "http://127.0.0.1:8088/?token=secret",
    ]) {
      process.env.OPENSCIENCE_JAVA_SIDECAR_URL = url
      expect(await JavaSidecar.compare(input)).toEqual({ status: "unavailable" })
    }
  })
})
