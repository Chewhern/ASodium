# ASodium
This is a libsodium binding that forked from Sodium.Core

Without any pre-contributors in .Net, this binding wouldn't exist.

These contributors include
```
tabrath (Sodium.Core previous author), adamcaudill (libsodium-net) 
```

Read changelog for more details.

This repository wiki will be used as a documentation but the quality won't be as good as official libsodium's.

The information on wiki may not be up to date.

This is a new binding, there'll be unforeseen bugs please report to me and I'll see what I can do.

## Design Goals and Scope Comparison
| Trait | ASodium | Geralt | NSec |
|------|--------|--------|------|
| Design goal | Security engineering & memory control | Managed safety with some low-level control | High-level, safe cryptography |
| libsodium feature coverage | Broad /aims for near-complete coverage | Core primitives only | Core primitives only |
| libsodium memory API exposure | Extensive (mlock, noaccess, unmanaged) | Partial | Minimal |
| Managed memory abstraction | Optional | Primary | Primary |
| Intended audience | Security engineers | Advanced users | Application developers |

These libraries target different audiences and threat models.

ASodium focuses on exposing low-level memory control and broader libsodium coverage for security-engineering use cases, while Geralt and NSec prioritize safer, higher-level abstractions suitable for most application development.
