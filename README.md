<!-- fleet:header:begin (rendered by `cargo xtask fleet render` from GetBusbar/busbar's plugins.yaml; edit it there) -->
# busbar-export-webhook

First-party signed kind:export plugin cdylib: the request-log WEBHOOK sink (module: request-log-webhook), packaged as a droppable busbar plugin. Drop the signed tarball into plugins/ and name it from an export.<name>.module: request-log-webhook block.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `export` | `webhook` | `busbar-export-webhook-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-export-webhook/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-export-webhook/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-export-webhook` is a `kind: export` busbar plugin.

## Config

Configured under the `webhook` module name.

## Build

```bash
cargo build --release -p busbar-export-webhook-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
