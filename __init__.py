"""Contract Hunter plugin — Scout-powered EVM vulnerability hunting for Hermes.

Brings the Scout contract-hunting engine (radar → surface → prove → report)
into Hermes as native tools, hooks, and slash commands.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_SCOUT_BIN: Optional[str] = None


def _find_scout() -> Optional[str]:
    """Auto-detect Scout binary from common install paths."""
    env_path = os.getenv("SCOUT_PATH")
    if env_path and os.path.isfile(env_path) and os.access(env_path, os.X_OK):
        return env_path

    common_paths = [
        os.path.expanduser("~/.cargo/bin/scout"),
        "/usr/local/bin/scout",
        "/usr/bin/scout",
        os.path.expanduser("~/.local/bin/scout"),
    ]
    for p in common_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p

    found = shutil.which("scout")
    if found:
        return found

    return None


def _get_scout() -> Optional[str]:
    global _SCOUT_BIN
    if _SCOUT_BIN is None:
        _SCOUT_BIN = _find_scout()
    return _SCOUT_BIN


def _run_scout(args: list[str], timeout: int = 120) -> dict[str, Any]:
    """Run a scout CLI command and return parsed output."""
    scout = _get_scout()
    if scout is None:
        return {
            "success": False,
            "error": (
                "Scout binary not found. Install it with:\n"
                "  cargo install --path /path/to/scout\n"
                "Or set SCOUT_PATH env var to the binary location.\n"
                "Or run: /hunt setup"
            ),
        }
    try:
        result = subprocess.run(
            [scout] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0,
        }
    except FileNotFoundError:
        return {"success": False, "error": f"Scout binary not found at {scout}. Run: /hunt setup"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Scout command timed out after {timeout}s."}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _scout_radar(source: str = "immunefi", limit: int = 10) -> str:
    result = _run_scout(["pull", "--source", source, "--limit", str(limit)])
    if result["success"]:
        return f"Radar pull complete.\n{result['stdout']}"
    return f"Radar pull failed: {result.get('error', result.get('stderr', 'unknown'))}"


def _scout_surface(target_id: str) -> str:
    result = _run_scout(["source", target_id])
    if result["success"]:
        return f"Surface complete for target {target_id}.\n{result['stdout']}"
    return f"Surface failed: {result.get('error', result.get('stderr', 'unknown'))}"


def _scout_prove(target_id: str, hypothesis: str = "") -> str:
    args = ["prove", target_id]
    if hypothesis:
        args += ["--hypothesis", hypothesis]
    result = _run_scout(args, timeout=300)
    if result["success"]:
        return f"Proof complete for target {target_id}.\n{result['stdout']}"
    return f"Proof failed: {result.get('error', result.get('stderr', 'unknown'))}"


def _scout_report(target_id: str) -> str:
    result = _run_scout(["report", target_id])
    if result["success"]:
        return f"Report generated for target {target_id}.\n{result['stdout']}"
    return f"Report failed: {result.get('error', result.get('stderr', 'unknown'))}"


def _scout_status() -> str:
    result = _run_scout(["list"])
    if result["success"]:
        return f"Hunting status:\n{result['stdout']}"
    return f"Status check failed: {result.get('error', result.get('stderr', 'unknown'))}"


def _hunt_setup() -> str:
    """Check if Scout is installed and provide install instructions."""
    scout = _get_scout()
    if scout:
        return f"Scout found at: {scout}\n\nYou're ready to hunt! Use /hunt radar to get started."
    return (
        "Scout not found. Install it:\n\n"
        "1. Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh\n"
        "2. Clone Scout: git clone https://github.com/NathanOyewole/scout.git\n"
        "3. Build: cd scout && cargo install --path .\n"
        "4. Verify: scout --version\n\n"
        "Or set SCOUT_PATH=/path/to/scout binary.\n"
        "Then restart Hermes."
    )


def _hunt_demo() -> str:
    """Run a demo on a known vulnerable contract."""
    scout = _get_scout()
    if not scout:
        return "Scout not found. Run /hunt setup first."
    result = _run_scout(["pull", "--source", "immunefi", "--limit", "1"], timeout=30)
    if result["success"]:
        return f"Demo radar pull:\n{result['stdout']}\n\nNow use /hunt surface <id> to analyze a target."
    return f"Demo failed: {result.get('error', result.get('stderr', 'unknown'))}"


def _on_session_start(**kwargs) -> None:
    """On session start, check for new bounty targets."""
    logger.info("Contract Hunter: checking for new bounty targets on session start")
    try:
        result = _run_scout(["pull", "--source", "immunefi", "--limit", "5"], timeout=30)
        if result["success"]:
            logger.info("Contract Hunter: radar pull on session start completed")
    except Exception as e:
        logger.debug("Contract Hunter: session start radar check failed: %s", e)


def _handle_hunt(raw_args: str) -> Optional[str]:
    parts = raw_args.strip().split()
    if not parts or parts[0] in {"help", "-h", "--help"}:
        return """\
/hunt — Contract Hunter powered by Scout

Subcommands:
  setup                      Check/install Scout
  demo                       Run a demo radar pull
  radar [source] [limit]     Pull bounty targets (default: immunefi, 10)
  surface <id>               Surface a target contract
  prove <id> [hypothesis]    Prove a vulnerability on local fork
  report <id>                Generate vulnerability report
  status                     Check hunting status

Examples:
  /hunt setup
  /hunt demo
  /hunt radar immunefi 5
  /hunt surface 42
  /hunt prove 42 "reentrancy in withdraw"
  /hunt report 42
  /hunt status
"""
    sub = parts[0]
    if sub == "setup":
        return _hunt_setup()
    elif sub == "demo":
        return _hunt_demo()
    elif sub == "radar":
        source = parts[1] if len(parts) > 1 else "immunefi"
        limit = int(parts[2]) if len(parts) > 2 else 10
        return _scout_radar(source, limit)
    elif sub == "surface":
        if len(parts) < 2:
            return "Usage: /hunt surface <target_id>"
        return _scout_surface(parts[1])
    elif sub == "prove":
        if len(parts) < 2:
            return "Usage: /hunt prove <target_id> [hypothesis]"
        hyp = " ".join(parts[2:]) if len(parts) > 2 else ""
        return _scout_prove(parts[1], hyp)
    elif sub == "report":
        if len(parts) < 2:
            return "Usage: /hunt report <target_id>"
        return _scout_report(parts[1])
    elif sub == "status":
        return _scout_status()
    else:
        return f"Unknown subcommand: {sub}\n\nType /hunt help for usage."


def register(ctx) -> None:
    ctx.register_tool(
        "scout_radar",
        description="Pull bounty targets from a radar source (immunefi, sourcify, dexscreener).",
        parameters={
            "type": "object",
            "properties": {
                "source": {"type": "string", "default": "immunefi", "description": "Radar source"},
                "limit": {"type": "integer", "default": 10, "description": "Max targets to pull"},
            },
        },
        handler=lambda args, **kw: _scout_radar(args.get("source", "immunefi"), args.get("limit", 10)),
    )
    ctx.register_tool(
        "scout_surface",
        description="Surface a target contract — fetch source, ABI, metadata.",
        parameters={
            "type": "object",
            "properties": {
                "target_id": {"type": "string", "description": "Target ID from radar"},
            },
            "required": ["target_id"],
        },
        handler=lambda args, **kw: _scout_surface(args["target_id"]),
    )
    ctx.register_tool(
        "scout_prove",
        description="Prove a vulnerability hypothesis on a local Anvil fork.",
        parameters={
            "type": "object",
            "properties": {
                "target_id": {"type": "string", "description": "Target ID"},
                "hypothesis": {"type": "string", "description": "Vulnerability hypothesis to test"},
            },
            "required": ["target_id"],
        },
        handler=lambda args, **kw: _scout_prove(args["target_id"], args.get("hypothesis", "")),
    )
    ctx.register_tool(
        "scout_report",
        description="Generate a professional vulnerability report for a proven finding.",
        parameters={
            "type": "object",
            "properties": {
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target_id"],
        },
        handler=lambda args, **kw: _scout_report(args["target_id"]),
    )
    ctx.register_tool(
        "scout_status",
        description="Check current hunting status and recent findings.",
        parameters={"type": "object", "properties": {}},
        handler=lambda args, **kw: _scout_status(),
    )

    ctx.register_hook("on_session_start", _on_session_start)

    ctx.register_command("hunt", handler=_handle_hunt,
                         description="Contract hunting: radar → surface → prove → report.")