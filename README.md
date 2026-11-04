<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-export-webhook

First-party signed kind:export plugin cdylib: the request-log WEBHOOK sink (module: request-log-webhook), packaged as a droppable busbar plugin. Drop the signed tarball into plugins/ and name it from an export.<name>.module: request-log-webhook block.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `export` | `request-log-webhook` | `busbar-export-webhook-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-export-webhook/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-export-webhook/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-export-webhook` is a `kind: export` busbar plugin.

## Config

Configured under the `request-log-webhook` module name (`export.<name>.module: request-log-webhook`), with these `settings:` (unknown keys are refused):

| key | default | meaning |
|---|---|---|
| `url` | required | The webhook target. `https://` only; refused by the host when it names a loopback, link-local, private, CGNAT or cloud-metadata host. |
| `auth_header` | none | `{ name, value }`: one header sent on every delivery. Prefer a secret reference (`{env:}`, `{file:}`, `{module:}`) for `value`; the export host also preserves existing literal header values. |
| `max_inflight_deliveries` | 64 | Concurrent deliveries for this instance; at least 1 (the largest instance's bound is validated, and must not exceed `usize::MAX >> 3`). |
| `delivery_timeout_secs` | 2 | Per-delivery deadline in seconds, from 1 up to 30 years (946080000). |

Security notes:

- Only `https://` targets are dialled, to public destinations.
- A `user:pass@` in the url is not sent in the url: it becomes an `Authorization: Basic` header.
- An ambiguous url is refused: an `@` after the host (a credential holding an unescaped `/`, `?` or `#`) would be dialled as a host. Percent-encode the credential.
- An `auth_header` that cannot be sent (an invalid name or value) is refused, as is one named for a framing or connection field (`content-length`, `transfer-encoding`, `host`, `connection`, `te`, `upgrade`, `trailer`, `keep-alive`, `proxy-connection`); `validate` and `open` refuse alike.
- Log lines name the target by scheme, a masked userinfo marker (`***@`), host and port, with a path shown as `/***` and a query as `?***`, and cut the url's parts and the request's credentials from the host's failure text.

## Differences from 1.5.5

- A mistyped `auth_header` (a string where `{ name, value }` belongs) or an unknown key under it is
  refused without quoting the text: the refusal reads `invalid type: string "***"` or
  ``unknown field `***` ``. 1.5.5 (serde's derived reader, `crates/busbar/src/config/mod.rs:3499`)
  quoted it, and that text is most often the credential.
- An `auth_header` whose name or value cannot be built as an HTTP header is refused at validation
  and open (and removed by the migration from 1.5.5). 1.5.5 (`crates/busbar/src/export/webhook.rs:148`)
  left such a header out and POSTed every line without it, unauthenticated.
- An `auth_header` named for a framing or connection field (`content-length`, `host`,
  `connection`, ...) is refused at validation and open (and removed by the migration from 1.5.5): the
  sink's framer states those fields itself. 1.5.5 (`crates/busbar/src/export/webhook.rs:148`) passed
  such a name to its HTTP client.

## Build

```bash
cargo build --release -p busbar-export-webhook-plugin --features dropped-in
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
