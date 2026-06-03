# Release {{ version }}

## Changes

{{ changelog }}

## Build Targets

- `x86_64-unknown-linux-musl`
- `x86_64-pc-windows-gnu`

## Assets

- `brute-{{ version }}-x86_64-unknown-linux-musl.tar.gz`
- `brute-{{ version }}-x86_64-pc-windows-gnu.zip`
- `SHA256SUMS.txt`

## Verify Downloads

Download the release archives and `SHA256SUMS.txt`, then run:

```bash
sha256sum --check SHA256SUMS.txt
```

## Notes

- Authorized use only: Run brute only against systems you own or have explicit
  permission to assess. Respect applicable policies, laws, and traffic limits.
- Tag format must be `v*`, for example `v0.1.0`.
- Release artifacts are published automatically by GitHub Actions after the tag is pushed.
