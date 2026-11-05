# Contract Hunter Plugin for Hermes

Scout-powered EVM contract vulnerability hunting. Bring the full bounty-hunting pipeline (radar → surface → prove → report) into Hermes as native tools, hooks, and slash commands.

## Installation

```bash
hermes plugins install NathanOyewole/hermes-contract-hunter
```

## Setup

Scout is auto-detected from common paths (`~/.cargo/bin/scout`, `/usr/local/bin/scout`). No `SCOUT_PATH` needed. Or install Scout first:

```bash
git clone https://github.com/NathanOyewole/scout.git
cd scout && cargo install --path .
```

## Usage

### Slash Command
```
/hunt setup               # Verify Scout is installed
/hunt demo                # Quick demo radar pull
/hunt radar immunefi 5    # Pull 5 new bounty targets
/hunt surface 42          # Surface target #42
/hunt prove 42 "reentrancy in withdraw"  # Prove hypothesis
/hunt report 42           # Generate vulnerability report
/hunt status              # Check hunting status
```

### Web Dashboard
Scout includes a built-in web dashboard accessible from any device:
```bash
scout serve --port 8080
# Access at http://localhost:8080 or http://<your-ip>:8080
# For public access: cloudflared tunnel --url http://localhost:8080
```

### Tools (for agent use)
- `scout_radar` — Pull bounty targets from Immunefi/Sourcify/DexScreener
- `scout_surface` — Fetch contract source, ABI, metadata
- `scout_prove` — Prove vulnerability on local Anvil fork
- `scout_report` — Generate professional vulnerability report
- `scout_status` — Check hunting status

### Hooks
- `on_session_start` — Optionally checks for new Immunefi targets (off by default; controlled by `auto_pull_immunefi` setting)

## How It Works

1. **Radar** — Pulls bounty programs from Immunefi, Sourcify, and DexScreener
2. **Surface** — Fetches contract source code, ABI, and metadata
3. **Prove** — Tests vulnerability hypotheses on a local Anvil fork
4. **Report** — Generates professional vulnerability reports ready for submission

## Disclosures

This plugin wraps the external `scout` CLI (source: https://github.com/NathanOyewole/scout). When tools are invoked:

- **Network calls**: `radar` contacts Immunefi, Sourcify, and/or DexScreener (depending on source).
- **Local Anvil fork**: `prove` executes exploit transactions against a local Anvil fork. The fork RPC is determined by Scout (typically a public Ethereum mainnet endpoint or the one configured in Scout).
- **Session-start pull**: An optional Immunefi radar pull can run on session start. It is **off by default** and controlled by the `auto_pull_immunefi` plugin setting. When enabled it blocks briefly and makes a network call.

The Scout binary itself must be installed separately and is the component that performs the actual network and fork work. Review the Scout source before use.

## License

MIT
