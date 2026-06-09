# Roadmap

- ~~Add polymorphism for working with S3~~
- ~~Add DO Spaces, GCP s3, Azure Blob Storage~~
- ~~Add jwt support~~
- Add encryption for uploads to S3 (?)
- ~~Implement an application example with auto-updating~~
- ~~Implement gathering of statistics on the number of clients, versions used, and the number of downloads~~
- Add application code signing functionality for avoiding "Unknown Publisher" warnings (?)
- Add "Forgot password" feature
- Add email support
- ~~Add slack notifications~~

## Updaters to Implement

- ~~**Squirrel**~~
- ~~**Electron Builder**~~
- **Sparkle** 
- ~~**Tauri**~~
- ~~**[go-tuf](https://github.com/theupdateframework/go-tuf)**~~ (Partially implemented - pilot version)
- **etc...**

## TUF (The Update Framework) Implementation

### Current Status
- ✅ **Pilot version implemented** - Core functionality is operational but requires additional work before production deployment

### Testing & Quality
- [x] Add comprehensive unit tests for TUF functionality

### Delegations Management
- [ ] **Delegated role add/revoke workflow, with policy validations and migration rules**
- [ ] **POST /tuf/v1/delegations** - Create new delegation (?)
- [ ] **PUT /tuf/v1/delegations** - Update existing delegation (?)
- [ ] **POST /tuf/v1/delegations/delete** - Delete delegation (?)
- [ ] Evaluate if delegations make sense for faynoSync use case (?)

### Metadata Management Enhancements
- [x] **POST /tuf/v1/metadata/sign/delete** - Delete metadata in signing process
- [x] **POST /tuf/v1/metadata/online** - Force new version of online metadata

### Documentation & Tooling
- [x] Update Postman template with TUF endpoints
- [x] Update API documentation for TUF functionality
- [x] Add TUF usage examples and guides
- [x] Document TUF configuration and setup process

### Security & Key Management
- [x] Add support for key types other than ed25519 (e.g., RSA, ECDSA)

### Future Improvements
- [ ] Performance optimizations for large repositories
- [x] Enhanced error handling and recovery mechanisms
- [ ] Metadata versioning and rollback capabilities
- [ ] Support for additional hash algorithms
- [x] Refactor or remove unused endpoints (e.g., `/tuf/v1/bootstrap/locks`, `/tuf/v1/bootstrap/generate`) 
- [ ] **Offline-targets posture** (`bootstrap/settings.go:146`) — bootstrap hardcodes `TargetsOnlineKey: true`, while recovery derives online-ness by probing `ONLINE_KEY_DIR` (`recovery.go:607-617`), so the two flows can disagree. First reconcile both flows behind one shared online-ness helper (cheap, worth doing regardless). Then, if a true offline-targets repo is wanted, stage targets changes through the existing async pending-signing flow (as `root` already does) and bind snapshot/timestamp only after the offline signature lands. Low priority — current online-targets posture is acceptable, just make it a deliberate, documented choice.
- [ ] **Spec-compliant delegation path matching** (`artifacts/add.go:333-355`) — `matchDelegatedPathPattern` treats `prefix/*` as a recursive prefix, but TUF glob `*` does not cross `/`. A spec-compliant client can therefore disagree with the server about which delegated role is authoritative for a target (relevant for terminating delegations and which signatures a client trusts). Align on `**` / `pathHashPrefixes`, or document that clients must use the same non-standard matcher. Low priority.
- [ ] **Multi-level (nested) delegation** (`metadata/metadata.go`) — `PostMetadataDelegatedRotate`/`PostMetadataSign` only verify delegated roles directly against `targets` (`targets.VerifyDelegate(role, …)`), so a delegated role delegating further is unsupported. Not a vulnerability — a spec-capability gap. Implement a delegator resolver that walks the delegation graph from `targets`, or document the single-level limitation. Low priority.
