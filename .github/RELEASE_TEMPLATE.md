# Release {{ version }}

## Changes

{{ changelog }}

## Build Targets

- `x86_64-unknown-linux-musl`
- `x86_64-pc-windows-gnu`

## Assets

- `brute-{{ version }}-x86_64-unknown-linux-musl.tar.gz`
- `brute-{{ version }}-x86_64-pc-windows-gnu.zip`

## Notes

- Authorized use only: Run proxlet only against systems you own or have explicit
 permission to assess. Respect applicable policies, laws, and traffic limits.
- Tag format must be `v*`, for example `v0.1.0`.
- Release artifacts are published automatically by GitHub Actions after the tag is pushed.
