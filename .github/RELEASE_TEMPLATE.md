# Release {{ version }}

## Changes

{{ changelog }}

## Build Targets

- `x86_64-unknown-linux-musl` (`ubuntu-latest`)
- `x86_64-pc-windows-msvc` (`windows-latest`)
- `aarch64-apple-darwin` (`macos-latest`, Apple Silicon)

## Assets

- `brute-{{ version }}-x86_64-unknown-linux-musl.tar.gz`
- `brute-{{ version }}-x86_64-pc-windows-msvc.zip`
- `brute-{{ version }}-aarch64-apple-darwin.tar.gz`
- `SHA256SUMS.txt`

## Verify Downloads

Download the release archives and `SHA256SUMS.txt`, then run:

```bash
sha256sum --check SHA256SUMS.txt
```

On macOS, `shasum` can be used instead:

```bash
shasum -a 256 -c SHA256SUMS.txt
```

## Notes

- Authorized use only: Run brute only against systems you own or have explicit
  permission to assess. Respect applicable policies, laws, and traffic limits.
- Tag format must be `v*`, for example `v0.1.0`.
- Release artifacts are published automatically by GitHub Actions after the tag is pushed.
