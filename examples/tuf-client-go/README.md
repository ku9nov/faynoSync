# TUF Client Example (faynoSync Adaptation)

This directory contains a local adaptation of the upstream `go-tuf` client example.

## What was adapted for faynoSync

- `metadataURL` points to faynoSync metadata storage.
- `targetsURL` points to faynoSync target storage.
- `targetName` is set to a faynoSync target path.
- `cfg.PrefixTargetsWithHash` is set to `false` to match faynoSync target URL layout.

## License note

The source file `client.go` is based on code from The Update Framework `go-tuf` examples and keeps its original Apache-2.0 license header and SPDX identifier.
