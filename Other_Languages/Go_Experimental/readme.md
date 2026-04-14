# Go translation of ASodium (experimental / reference)

This directory contains an **experimental** Go translation of ASodium's cryptographic logic.

**⚠️ Status: EXPERIMENTAL – NOT FOR PRODUCTION USE**

- This is a **1:1 functional translation** of ASodium (C#) into Go, generated with AI assistance.
- It is **not actively maintained** and **requires thorough testing** by anyone who considers using it.
- It is intended **only as a reference** for how ASodium's logic can be expressed in Go.

**What does "1:1 functional translation" mean?**

All ASodium features that are **feasible in Go** have been translated. However, some features are limited by Go's own language structural constraints.

For example, ASodium has `SodiumSecureMemory.SecureClearString` which helps to remove the last copy of a string in memory securely. This **cannot be replicated in Go at all** because Go lacks the equivalent of C# `GCHandle`. Go does have `unsafe.Pointer` (similar to C# `IntPtr`), but without `GCHandle`, there is no way to pin a string object in memory and prevent the garbage collector from moving it. This makes secure string clearing impossible.

The same limitation applies to Node.js / TypeScript, which lacks both `GCHandle` and `IntPtr` equivalents. As confirmed by Node.js core maintainers ([#59965](https://github.com/nodejs/node/issues/59965)), there is no way to forcibly destroy a string handle or guarantee memory cleanup.

**Why does this exist?**

To explore cross‑language crypto patterns and provide a **reference** for anyone who wants to understand how ASodium's logic could look in Go.

**What should Go developers use instead?**

Go's standard library (`crypto/ed25519`, `crypto/ecdh`) and `golang.org/x/crypto` are usable. However, from a **security engineering** perspective, libsodium + a proper Go binding would be the **best choice** — offering a wider range of modern algorithms (XChaCha20, Argon2, secretstream, etc.) and better memory safety guarantees.

The problem is that currently there is **no production‑ready, actively maintained Go binding for libsodium**. Existing options like `github.com/jamesruan/sodium` can serve as a **reference** for how to compile and bind libsodium, but they are not officially maintained.

The best path forward is to first understand the underlying memory safety concepts:
- `GCHandle` (pinning GC objects)
- `IntPtr` / `unsafe.Pointer`
- Mutable vs. immutable data types
- Why secure string clearing matters

Once you understand these, you can use this **experimental** translation as a starting point to build your own Go binding for libsodium.

**Will this be updated?**

No. This code is provided as‑is for reference only. It is not a production solution.

**License**

Same as ASodium (MIT/ISC).
