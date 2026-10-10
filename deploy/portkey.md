# proteus behind Portkey

This note registers `proteus mcp --http` as an MCP server in the Portkey MCP
gateway. The stack in `deploy/docker/` runs proteus behind Caddy, which terminates
TLS. Replace `proteus.example.org` with the server's DNS name.

Portkey documents its MCP gateway at <https://portkey.ai/docs/product/mcp-gateway>.
The pages below were checked on 2026-10-10. Check them again: the settings can
change.

## 1. Register the server

Add the server to the MCP Registry
(<https://portkey.ai/docs/product/mcp-gateway/mcp-registry>). This needs the
organisation admin or owner role.

| Field | Value |
| --- | --- |
| URL | `https://proteus.example.org/mcp` |
| Auth type | Headers (static headers) |
| Header | `Authorization: Bearer <token>` |

`<token>` is the content of `deploy/docker/secrets/proteus-mcp-token`. proteus
needs a token of 32 bytes or more; `openssl rand -hex 32` makes one of 64.

Portkey sends the static headers with every request to the server
(<https://portkey.ai/docs/product/mcp-gateway/authentication/custom-auth>). All
users share this token: it proves that the request comes through the gateway, not
who the user is.

proteus answers MCP on every path except `/healthz`. The path `/mcp` is a
convention.

## 2. Forward the user's identity

proteus writes one audit line per call. The line records the claims of the header
`X-User-Claims` that `audit_claims` names (default: `sub`). Set this in the
server's Advanced Configuration JSON
(<https://portkey.ai/docs/product/mcp-gateway/advanced-configuration>):

```json
{
  "user_identity_forwarding": {
    "method": "claims_header",
    "include_claims": ["sub"]
  }
}
```

The `claims_header` method sends the claims as a JSON object in `X-User-Claims`,
the default header name
(<https://portkey.ai/docs/product/mcp-gateway/authentication/identity-forwarding>).
proteus reads that header by default (`identity_header: X-User-Claims`). Without
`include_claims`, Portkey sends a larger default set of claims; proteus audits
only the claims in `audit_claims`.

Portkey strips a client's own `X-User-Claims` header before it forwards a request
(same page). So a user of the gateway cannot claim another identity.

## 3. Trust

**Warning: a token holder can forge the identity.** proteus does not verify the
identity header. Anyone who holds the token can send any `X-User-Claims` value. The
audit line records the identity as the gateway claimed it. Keep the token secret,
or the audit is not reliable.

- proteus does no authorisation. Portkey decides which users and workspaces can
  use the server.
- The audit lines hold identities, and the addresses in the tools' inputs. Treat
  the container's log, or the audit file, as sensitive.
- proteus does not audit a refused request (401 or 403). Its process log counts
  them by status once a minute. Portkey's logs hold the refused attempts at the
  gateway, and Caddy's logs the requests that bypass it. Behind the proxy every
  request has the proxy's address; proteus does not read `X-Forwarded-For`, and
  it must not trust it.
- Rotate the token in the secret file and in Portkey together, then restart
  `proteus-mcp`.

## 4. Allow only Portkey at the proxy

The Portkey documentation checked above does not publish egress addresses for the
SaaS gateway. Ask Portkey for them. When you have them, allow only those addresses
in `deploy/docker/Caddyfile`:

```caddyfile
@outside not remote_ip 203.0.113.10 203.0.113.11
respond @outside 403
```

The addresses above are documentation placeholders. Without an address filter,
the token is the only check.

## 5. Check the setup

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://proteus.example.org/healthz      # 200
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://proteus.example.org/mcp  # 401
```

Then call a tool from a Portkey client. The audit line in the container's log
(`docker compose logs proteus-mcp`; the sample sets `audit_log: -`) shows
`"identity_source":"header"` and the user's `sub`.
