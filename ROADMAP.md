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
- [ ] Add TUF usage examples and guides
- [ ] Document TUF configuration and setup process

### Security & Key Management
- [x] Add support for key types other than ed25519 (e.g., RSA, ECDSA)

### Future Improvements
- [ ] Performance optimizations for large repositories
- [x] Enhanced error handling and recovery mechanisms
- [ ] Metadata versioning and rollback capabilities
- [ ] Support for additional hash algorithms
- [x] Refactor or remove unused endpoints (e.g., `/tuf/v1/bootstrap/locks`, `/tuf/v1/bootstrap/generate`) 
