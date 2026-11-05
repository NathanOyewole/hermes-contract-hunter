"""Contract Hunter plugin — Scout-powered EVM vulnerability hunting for Hermes.

Brings the Scout contract-hunting engine (radar → surface → prove → report)
into Hermes as native tools, hooks, and slash commands.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sqlite3
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

SCOUT_BIN = os.getenv("SCOUT_PATH", "scout")
DB_PATH = None


def _run_scout(args: list[str], timeout: int = 120) -> dict[str, Any]:
    """Run a scout CLI command and return parsed output."""
    try:
        result = subprocess.run(
            [SCOUT_BIN] + args,
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
        return {"success": False, "error": f"Scout binary not found at {SCOUT_BIN}. Set SCOUT_PATH env var."}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Scout command timed out after {timeout}s."}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _scout_radar(source: str = "immunefi", limit: int = 10) -> str:
    """Pull bounty targets from a radar source."""
    result = _run_scout(["pull", "--source", source, "--limit", str(limit)])
    if result["success"]:
        return f"Radar pull complete.\n{result['stdout']}"
    return f"Radar pull failed: {result.get('error', result.get('stderr', 'unknown'))}"


def _scout_surface(target_id: str) -> str:
    """Surface a target contract."""
    result = _run_scout(["source", target_id])
    if result["success"]:
        return f"Surface complete for target {target_id}.\n{result['stdout']}"
    return f"Surface failed: {result.get('error', result.get('stderr', 'unknown'))}"


def _scout_prove(target_id: str, hypothesis: str = "") -> str:
    """Prove a vulnerability hypothesis on a local fork."""
    args = ["prove", target_id]
    if hypothesis:
        args += ["--hypothesis", hypothesis]
    result = _run_scout(args, timeout=300)
    if result["success"]:
        return f"Proof complete for target {target_id}.\n{result['stdout']}"
    return f"Proof failed: {result.get('error', result.get('stderr', 'unknown'))}"


def _scout_report(target_id: str) -> str:
    """Generate a vulnerability report."""
    result = _run_scout(["report", target_id])
    if result["success"]:
        return f"Report generated for target {target_id}.\n{result['stdout']}"
    return f"Report failed: {result.get('error', result.get('stderr', 'unknown'))}"


def _scout_status() -> str:
    """Check hunting status and recent findings."""
    result = _run_scout(["status"])
    if result["success"]:
        return f"Hunting status:\n{result['stdout']}"
    return f"Status check failed: {result.get('error', result.get('stderr', 'unknown'))}"


def _on_session_start(**kwargs) -> None:
    """On session start, check for new bounty targets."""
    logger.info("Contract Hunter: checking for new bounty targets on session start")
    # Non-blocking: just log, don't block session
    try:
        result = _run_scout(["pull", "--source", "immunefi", "--limit", "5"], timeout=30)
        if result["success"]:
            logger.info("Contract Hunter: radar pull on session start completed")
    except Exception as e:
        logger.debug("Contract Hunter: session start radar check failed: %s", e)


def _handle_hunt(raw_args: str) -> Optional[str]:
    """Slash command: /hunt <subcommand> [args]"""
    parts = raw_args.strip().split()
    if not parts or parts[0] in {"help", "-h", "--help"}:
        return """\
/hunt — Contract Hunter powered by Scout

Subcommands:
  radar [source] [limit]   Pull bounty targets (default: immunefi, 10)
  surface <id>             Surface a target contract
  prove <id> [hypothesis]  Prove a vulnerability on local fork
  report <id>              Generate vulnerability report
  status                   Check hunting status

Examples:
  /hunt radar immunefi 5
  /hunt surface 42
  /hunt prove 42 "reentrancy in withdraw"
  /hunt report 42
  /hunt status
"""
    sub = parts[0]
    if sub == "radar":
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
    # Register tools
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
        description="Surface a target contract — fetch source, ABI, and metadata.",
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

    # Register hooks
    ctx.register_hook("on_session_start", _on_session_start)

    # Register slash command
    ctx.register_command("hunt", handler=_handle_hunt,
                         description="Contract hunting: radar → surface → prove → report.")
