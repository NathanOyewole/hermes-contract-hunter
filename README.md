# Contract Hunter Plugin for Hermes

Scout-powered EVM contract vulnerability hunting. Bring the full bounty-hunting pipeline (radar → surface → prove → report) into Hermes as native tools, hooks, and slash commands.

## Installation

```bash
hermes plugins install NathanOyewole/hermes-contract-hunter
```

## Setup

Scout is auto-detected from common paths (`~/.cargo/bin/scout`, `/usr/local/bin/scout`). No `SCOUT_PATH` needed. Or install Scout first:

```bash
cargo install --path /path/to/scout
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
- `on_session_start` — Auto-checks for new bounty targets when a session starts

## How It Works

1. **Radar** — Pulls bounty programs from Immunefi, Sourcify, and DexScreener
2. **Surface** — Fetches contract source code, ABI, and metadata
3. **Prove** — Tests vulnerability hypotheses on a local Anvil fork
4. **Report** — Generates professional vulnerability reports ready for submission

## License

MIT