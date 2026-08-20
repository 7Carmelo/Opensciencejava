import { Log } from "@/util/log"
import { connect } from "node:net"
import z from "zod"

export namespace JavaSidecar {
  const log = Log.create({ service: "java-sidecar" })
  const Rule = z.object({
    permission: z.string(),
    pattern: z.string(),
    action: z.enum(["allow", "deny", "ask"]),
  })
  const Payload = z.object({
    protocolVersion: z.literal("1"),
    decision: Rule,
  })

  export type Rule = z.infer<typeof Rule>
  export type Input = {
    permission: string
    pattern: string
    rules: Rule[]
    local: Rule
  }
  export type Result = {
    status: "disabled" | "matched" | "mismatched" | "unavailable"
  }

  function endpoint() {
    const raw = process.env.OPENSCIENCE_JAVA_SIDECAR_URL
    if (!raw) return
    if (raw.includes("?") || raw.includes("#")) return false
    if (!URL.canParse(raw)) return false

    const url = new URL(raw)
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "")
    if (url.protocol !== "http:") return false
    if (!["localhost", "127.0.0.1", "::1"].includes(host)) return false
    if (url.username || url.password) return false
    if (url.pathname !== "/" || url.search || url.hash) return false
    return new URL("/v1/policy/evaluate", url)
  }

  function decode(body: Buffer): string | undefined {
    const chunks: Buffer[] = []
    const state = { offset: 0 }

    while (state.offset < body.length) {
      const line = body.indexOf("\r\n", state.offset)
      if (line === -1) return

      const token = body.subarray(state.offset, line).toString("ascii").split(";", 1)[0]
      if (!/^[0-9a-f]+$/i.test(token)) return

      const size = Number.parseInt(token, 16)
      if (!Number.isSafeInteger(size)) return
      if (size === 0) {
        const end = body.indexOf("\r\n\r\n", line)
        if (end === -1 || end + 4 !== body.length) return
        return Buffer.concat(chunks).toString("utf8")
      }

      const start = line + 2
      const end = start + size
      if (end < start || end + 2 > body.length) return
      if (body.subarray(end, end + 2).toString("ascii") !== "\r\n") return
      chunks.push(body.subarray(start, end))
      state.offset = end + 2
    }
  }

  function parse(input: Buffer) {
    const boundary = input.indexOf("\r\n\r\n")
    if (boundary === -1) return
    const lines = input.subarray(0, boundary).toString("latin1").split("\r\n")
    const status = /^HTTP\/1\.[01] (\d{3})/.exec(lines[0])
    if (!status) return

    const raw = input.subarray(boundary + 4)
    const chunked = lines.some((line) => /^transfer-encoding:\s*chunked\s*$/i.test(line))
    const body = chunked ? decode(raw) : raw.toString("utf8")
    if (body === undefined) return
    return { status: Number(status[1]), body }
  }

  function post(url: URL, body: string) {
    return new Promise<{ status: number; body: string } | undefined>((resolve) => {
      const chunks: Buffer[] = []
      const size = { value: 0 }
      const host = url.hostname.replace(/^\[|\]$/g, "")
      const socket = connect({ host, port: Number(url.port || "80") })
      const timer = setTimeout(() => socket.destroy(new Error("sidecar request timed out")), 500)

      socket.on("connect", () => {
        socket.write(
          [
            `POST ${url.pathname} HTTP/1.1`,
            `Host: ${url.host}`,
            "Content-Type: application/json",
            `Content-Length: ${Buffer.byteLength(body)}`,
            "Connection: close",
            "",
            body,
          ].join("\r\n"),
        )
      })
      socket.on("data", (chunk) => {
        size.value += chunk.length
        if (size.value > 65_536) {
          socket.destroy(new Error("sidecar response exceeded 64 KiB"))
          return
        }
        chunks.push(chunk)
      })
      socket.on("end", () => {
        clearTimeout(timer)
        try {
          const response = parse(Buffer.concat(chunks))
          if (!response) log.warn("sidecar returned an invalid HTTP response")
          resolve(response)
        } catch (error) {
          log.warn("sidecar response parsing failed", { error })
          resolve(undefined)
        }
      })
      socket.on("error", (error) => {
        clearTimeout(timer)
        log.warn("sidecar request unavailable", { error })
        resolve(undefined)
      })
    })
  }

  export async function compare(input: Input): Promise<Result> {
    const url = endpoint()
    if (url === undefined) return { status: "disabled" }
    if (url === false) {
      log.warn("rejected invalid sidecar URL")
      return { status: "unavailable" }
    }

    const response = await post(
      url,
      JSON.stringify({
        protocolVersion: "1",
        permission: input.permission,
        pattern: input.pattern,
        rules: input.rules,
      }),
    )
    if (!response) return { status: "unavailable" }
    if (response.status < 200 || response.status >= 300) {
      log.warn("sidecar returned an unsuccessful response", { status: response.status })
      return { status: "unavailable" }
    }

    const body: unknown = await new Response(response.body).json().catch((error) => {
      log.warn("sidecar returned invalid JSON", { error })
      return undefined
    })
    const parsed = Payload.safeParse(body)
    if (!parsed.success) {
      log.warn("sidecar response failed validation", { issues: parsed.error.issues })
      return { status: "unavailable" }
    }

    const remote = parsed.data.decision
    const matched =
      remote.permission === input.local.permission &&
      remote.pattern === input.local.pattern &&
      remote.action === input.local.action
    if (matched) {
      log.debug("sidecar policy matched", { permission: input.permission, pattern: input.pattern })
      return { status: "matched" }
    }

    log.warn("sidecar policy mismatched", {
      permission: input.permission,
      pattern: input.pattern,
      local: input.local,
      remote,
    })
    return { status: "mismatched" }
  }
}
