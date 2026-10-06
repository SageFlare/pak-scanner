# pak-scanner

A read-only **security scanner for Chivalry 2 mod `.pak` files**. Point it at an untrusted mod;
it reports a verdict — **benign**, **attempted** (tried a breach that would not take effect, but
still hostile), or **malicious** (a breach that would take effect) — plus findings and a report.
It never mounts or executes the pak.

Part of a 3-repo system: [pak-corpus](https://github.com/SageFlare/pak-corpus) (labeled dataset)
· **pak-scanner** (this, the detector) · pak-benchmark (grades this scanner on the corpus).

## What it detects (Phase 1)

Grounded in how Chivalry 2 mods actually work (a pak carries assets + Blueprints, never native
code):

- **Asset replacement** — a pak entry that shadows a trusted game asset (a path under
  `TBL/Content/<game dir>` rather than the mod's own `Mods/` namespace). The primary real threat.
- **LaunchURL** — a Blueprint referencing the stock `LaunchURL` node (opens a browser URL).

## Build & run

Requires the **.NET 8 SDK**.

```
dotnet test
dotnet run --project src/PakScanner -- path/to/mod.pak
```

Parsing is done via CUE4Parse through Chivalry 2 Unchained's UnrealModScanner.

## License

GPLv3 (see [LICENSE](LICENSE)) — it links the GPLv3 UnchainedLauncher. See [NOTICE](NOTICE).
