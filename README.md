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

## Known limitations

This is a pre-load **intent/behavior flagger**, not a guarantee. Treat a flag as "do not load
until a human judges it," and absence of a flag as "no *known* vector found," not "proven safe."

- **Verdicts describe behavior, not intent.** A `launch_url` finding could be a legit
  server-rules link or a malicious redirect — the scanner cannot tell; a human decides.
- **Cross-mod shadowing isn't flagged.** Entries under `TBL/Content/Mods/<Other>/` could shadow
  another installed mod's assets, but aren't distinguishable from a mod's own namespace without
  the pak's declared mod identity. Game-asset replacement (outside `Mods/`) *is* flagged.
- **Replacement delivery is uncertain.** A replacement is flagged-latent, not flagged-active —
  whether it actually overrides the game asset depends on cook-fidelity and mount precedence,
  which can't be confirmed statically.
- **Detection is signature-based** (LaunchURL node, game-dir paths). Novel vectors or heavy
  obfuscation beyond the covered forms may evade it. The rule set grows with the pen-test corpus.
- **zlib-ng native lib** is downloaded on first run to read compressed paks; if it can't be
  obtained the scan is Indeterminate (never a silent pass).

The benchmark's headline metrics are over a small, self-authored corpus — evidence the covered
vectors are caught, not proof of real-world completeness.

## License

GPLv3 (see [LICENSE](LICENSE)) — it links the GPLv3 UnchainedLauncher. See [NOTICE](NOTICE).
