# btcx

Shared Rust wallet stack for **BTCX (Bitcoin PoCX)** applications — extracted
from [satchel](https://github.com/PoC-Consortium/satchel)'s `libswap` so that
Satchel, Phoenix (desktop + mobile), and headless tools maintain one wallet
implementation. Companion workspace to
[pocx](https://github.com/PoC-Consortium/pocx), which bundles the coin-agnostic
consensus-framework crates the same way.

Naming: bare *PoCX* names the consensus framework (`pocx_miner`,
`pocx_plotter`, …); the `-btcx` suffix marks Bitcoin-family infrastructure for
the BTCX chain, like [electrs-btcx](https://github.com/PoC-Consortium/electrs-btcx)
and [bindex-btcx](https://github.com/PoC-Consortium/bindex-btcx). Those two
stay separate repos (they track upstream romanz remotes); this workspace is
greenfield crates only.

## Crates

| Crate | Contents |
|---|---|
| `params-btcx` | Chain parameters (BTCX mainnet/testnet/regtest + BTC), coin registry, 286-byte Bitcoin PoCX header hashing, bech32/bech32m address encode/parse (`pocx` HRP) |
| `keys-btcx` | BIP39 seed → BIP-86 descriptors, coin type `0x504F4358` (SLIP-44 1347371864) |
| `seedstore` | Seed-at-rest: scrypt + ChaCha20Poly1305 (passphrase), OS keyring behind a desktop-only feature |
| `electrum-btcx` | Electrum connection manager: server list/failover/health, scripthash subscriptions, raw-header fetch with PoCX hashing, background sync worker producing BDK updates |
| `wallet-btcx` | BDK v2 wallet: create/restore, send/receive, history, RBF/sweep/CPFP, fee estimation, sqlite persistence; swap-funding primitives behind the `swap-support` feature |

`wallet-btcx` is multi-coin via the registry (it also speaks vanilla BTC as the
swap counterparty). All crates build on **stock, unforked** BDK v2 /
rust-bitcoin — the 286-byte header rule lives in `params-btcx` and is applied
at the Electrum boundary.

## Consumers

- **satchel / pactd** — swap engine (`libswap`) builds on `wallet-btcx` with
  `swap-support`
- **phoenix-pocx** — Tauri commands over `wallet-btcx` for the mobile wallet
  and desktop nodeless mode

Extracted at satchel `fa169fc` (post v0.1.0-rc12). See
`../MIGRATION-PLAN.md` (local) for the full migration plan.
