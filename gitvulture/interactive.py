"""Interactive TUI for GitVulture.

Lets the user navigate the workflow step-by-step instead of one-shot:
- Each phase becomes a "node" in a tree of possible actions
- User picks options by typing a number or short keyword
- Built-in commands: back, forward, skip, redo, status, save, help, quit
- Maintains a history stack so the user can rewind/replay any phase
- AI is OPT-IN at every node ("[a]sk AI?") — never fires unprompted
- Authenticated residential proxy can be set/changed at any time
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .core.http_client import HttpClient
from .core.recon import run_recon
from .core.ref_discovery import discover_refs
from .core.object_engine import ObjectEngine
from .core.index_parser import parse_index
from .core.aggressive import AggressiveRetriever
from .logger import init_logger, get_logger
from .storage import new_scan_dir


# ---------------------------------------------------------------------------#
@dataclass
class Node:
    name: str
    description: str
    run: Callable             # async () -> Any
    options: list[tuple[str, str, str]] = field(default_factory=list)
    # options: list of (key, label, next_node_name)
    can_skip: bool = True


@dataclass
class State:
    target_url: str = ""
    out_dir: Path = Path("./gitvulture_loot")
    client: Optional[HttpClient] = None
    recon: Any = None
    refs: Any = None
    engine: Optional[ObjectEngine] = None
    aggressive_result: Any = None
    history: list[str] = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)
    proxy: Optional[str] = None
    use_ai_for_step: bool = False


# ---------------------------------------------------------------------------#
class InteractiveRunner:
    def __init__(self, console: Console) -> None:
        self.console = console
        self.log = get_logger()
        self.state = State()
        self.nodes: dict[str, Node] = {}
        self._register_nodes()

    # ------------- node registry ------------------------------------------ #
    def _register_nodes(self) -> None:
        self.nodes["start"] = Node(
            name="start",
            description="Configure target and connection",
            run=self._do_configure,
            options=[("1", "Run recon", "recon")],
            can_skip=False,
        )
        self.nodes["recon"] = Node(
            name="recon",
            description="Probe target for .git/ exposure",
            run=self._do_recon,
            options=[
                ("1", "Discover refs (Phase 2)", "refs"),
                ("2", "Probe extras only (.env, .DS_Store…)", "extras"),
                ("a", "Ask AI for next step", "ai_guide"),
            ],
        )
        self.nodes["refs"] = Node(
            name="refs",
            description="Discover branches/tags/refs",
            run=self._do_refs,
            options=[
                ("1", "Acquire objects + packs (Phase 3)", "objects"),
                ("2", "Parse .git/index (file map)", "index"),
                ("a", "Ask AI for next step", "ai_guide"),
            ],
        )
        self.nodes["objects"] = Node(
            name="objects",
            description="Download loose objects + pack files",
            run=self._do_objects,
            options=[
                ("1", "Reconstruct repository (Phase 4)", "rebuild"),
                ("2", "Try aggressive blob retrieval", "aggressive"),
                ("a", "Ask AI for next step", "ai_guide"),
            ],
        )
        self.nodes["index"] = Node(
            name="index",
            description="Parse .git/index → file list with blob SHAs",
            run=self._do_index,
            options=[
                ("1", "Aggressive blob retrieval (L9)", "aggressive"),
                ("2", "Endpoint synthesis (L3)", "endpoints"),
            ],
        )
        self.nodes["aggressive"] = Node(
            name="aggressive",
            description="Try every bypass to retrieve every blob",
            run=self._do_aggressive,
            options=[
                ("1", "Secret hunt on recovered content", "secrets"),
                ("2", "Generate AI exploit roadmap", "roadmap"),
            ],
        )
        self.nodes["secrets"] = Node(
            name="secrets",
            description="Scan recovered files for hard-coded secrets",
            run=self._do_secrets,
            options=[
                ("1", "Generate AI exploit roadmap", "roadmap"),
                ("2", "Print final report and exit", "report"),
            ],
        )
        self.nodes["endpoints"] = Node(
            name="endpoints",
            description="Probe live endpoints inferred from index file paths",
            run=self._do_endpoints,
            options=[
                ("1", "Aggressive blob retrieval", "aggressive"),
                ("2", "Secret hunt", "secrets"),
            ],
        )
        self.nodes["rebuild"] = Node(
            name="rebuild",
            description="git fsck + reconstruct working tree",
            run=self._do_rebuild,
            options=[
                ("1", "Secret hunt", "secrets"),
            ],
        )
        self.nodes["extras"] = Node(
            name="extras",
            description="Probe .env, .DS_Store, backup files",
            run=self._do_extras,
            options=[
                ("1", "Back to recon", "recon"),
            ],
        )
        self.nodes["roadmap"] = Node(
            name="roadmap",
            description="AI exploit roadmap (strict-mode, evidence-cited)",
            run=self._do_roadmap,
            options=[("1", "Final report", "report")],
        )
        self.nodes["ai_guide"] = Node(
            name="ai_guide",
            description="Ask AI: 'given current state, what should I do next?'",
            run=self._do_ai_guide,
            options=[
                ("1", "Back to previous node", "back"),
            ],
        )
        self.nodes["report"] = Node(
            name="report",
            description="Save final report and exit",
            run=self._do_report,
            options=[],
            can_skip=False,
        )

    # ------------- main loop ---------------------------------------------- #
    async def run(self) -> int:
        self.console.print(Panel.fit(
            "[bold cyan]GitVulture Interactive Mode[/bold cyan]\n"
            "Navigate the workflow with [yellow]numbered choices[/yellow]\n"
            "Commands at any prompt: "
            "[white]back · forward · skip · redo · status · proxy · ai · quit · help[/white]",
            border_style="cyan",
        ))
        current = "start"
        forward_stack: list[str] = []

        while current:
            node = self.nodes.get(current)
            if not node:
                self.console.print(f"[red]Unknown node: {current}[/red]")
                return 1

            self.console.rule(f"[bold magenta]{node.name.upper()}[/bold magenta]",
                              style="magenta")
            self.console.print(f"  [dim]{node.description}[/dim]\n")

            # Run the node's action
            try:
                await node.run()
            except KeyboardInterrupt:
                self.console.print("[yellow]Interrupted.[/yellow]")
                break
            except Exception as e:
                self.console.print(f"[red]Error in {node.name}: {e}[/red]")

            # Push history
            self.state.history.append(current)

            # Terminal node?
            if not node.options:
                if node.name == "report":
                    return 0
                self.console.print("[yellow]No further options. Use 'back' or 'quit'.[/yellow]")

            # Build prompt
            self.console.print()
            for k, label, _nxt in node.options:
                self.console.print(f"  [bold cyan]{k}[/bold cyan]  {label}")
            self.console.print("  [dim]Commands: back · forward · skip · "
                                "status · proxy · ai · quit · help[/dim]")
            choice = (await asyncio.to_thread(input, "\n  > ")).strip().lower()

            # Built-in commands
            if choice in ("q", "quit", "exit"):
                self.console.print("[yellow]Bye.[/yellow]")
                return 0
            if choice in ("h", "help", "?"):
                self._print_help()
                continue
            if choice == "status":
                self._print_status()
                continue
            if choice == "back":
                if len(self.state.history) >= 2:
                    forward_stack.append(self.state.history.pop())
                    current = self.state.history.pop()
                    self.console.print(f"[yellow]← {current}[/yellow]")
                else:
                    self.console.print("[yellow]No history.[/yellow]")
                continue
            if choice in ("forward", "fw"):
                if forward_stack:
                    current = forward_stack.pop()
                    self.console.print(f"[yellow]→ {current}[/yellow]")
                else:
                    self.console.print("[yellow]Nothing forward.[/yellow]")
                continue
            if choice == "proxy":
                self._configure_proxy()
                continue
            if choice == "skip":
                if node.can_skip and node.options:
                    current = node.options[0][2]
                    forward_stack.clear()
                    continue
                self.console.print("[yellow]Cannot skip this node.[/yellow]")
                continue
            if choice == "redo":
                continue  # re-execute the same node
            if choice == "ai":
                self.state.use_ai_for_step = True
                current = "ai_guide"
                continue

            # Numeric / keyword option
            nxt = None
            for k, _label, dest in node.options:
                if choice == k or choice == _label.lower():
                    nxt = dest
                    break
            if nxt:
                current = nxt
                forward_stack.clear()
            else:
                self.console.print(f"[yellow]Unknown choice: {choice}[/yellow]")

        return 0

    # ------------- helpers ------------------------------------------------ #
    def _print_help(self) -> None:
        self.console.print(Panel(
            "[bold]Available commands[/bold]\n"
            "  [cyan]N[/cyan]         pick numbered option\n"
            "  [cyan]back[/cyan]      return to previous node\n"
            "  [cyan]forward[/cyan]   redo the next step you came back from\n"
            "  [cyan]skip[/cyan]      jump to the first follow-up of this node\n"
            "  [cyan]redo[/cyan]      re-run current node\n"
            "  [cyan]status[/cyan]    show what data has been collected\n"
            "  [cyan]proxy[/cyan]     configure / change residential proxy\n"
            "  [cyan]ai[/cyan]        consult AI for next-step recommendation\n"
            "  [cyan]quit[/cyan]      exit",
            border_style="dim",
        ))

    def _print_status(self) -> None:
        t = Table(title="session state", show_header=False)
        t.add_column("key", style="cyan")
        t.add_column("value")
        t.add_row("target", self.state.target_url or "-")
        t.add_row("output", str(self.state.out_dir))
        t.add_row("proxy", self.state.proxy or "(none)")
        t.add_row("recon", "✓" if self.state.recon else "·")
        t.add_row("refs", "✓" if self.state.refs else "·")
        t.add_row("aggressive", "✓" if self.state.aggressive_result else "·")
        t.add_row("history", " → ".join(self.state.history[-6:]) or "(empty)")
        self.console.print(t)

    def _configure_proxy(self) -> None:
        self.console.print(
            "[bold]Enter proxy URL (user:pass@host:port supported)[/bold]\n"
            "[dim]Examples:[/dim]\n"
            "[dim]  http://user:pass@residential.example.com:8000[/dim]\n"
            "[dim]  socks5://user:pass@proxy.local:1080[/dim]\n"
            "[dim]  (blank to clear)[/dim]"
        )
        val = input("  proxy > ").strip()
        if not val:
            self.state.proxy = None
            self.console.print("[yellow]proxy cleared[/yellow]")
            return
        # Validate format
        if not re.match(r"^(http|https|socks4|socks5)://", val):
            self.console.print("[red]Invalid: must start with http(s)://"
                                " or socks5://[/red]")
            return
        self.state.proxy = val
        self.console.print(f"[green]proxy set:[/green] "
                            f"{val.split('@')[-1]}  (creds masked)")

    # ------------- node implementations ----------------------------------- #
    async def _do_configure(self) -> None:
        if not self.state.target_url:
            t = input("  target URL > ").strip()
            if not t:
                raise RuntimeError("target required")
            self.state.target_url = t.rstrip("/")
        if not self.state.out_dir.exists():
            self.state.out_dir = new_scan_dir(self.state.target_url)
        self._configure_proxy_optional()
        self.console.print(f"  [green]→ target: {self.state.target_url}[/green]")
        self.console.print(f"  [green]→ output: {self.state.out_dir}[/green]")

    def _configure_proxy_optional(self) -> None:
        if self.state.proxy is None:
            ans = input("  use proxy? [y/N] > ").strip().lower()
            if ans == "y":
                self._configure_proxy()

    async def _ensure_client(self) -> None:
        if self.state.client is None:
            insecure = (input("  insecure TLS (--insecure)? [Y/n] > ")
                        .strip().lower() != "n")
            self.state.client = HttpClient(
                self.state.target_url,
                insecure=insecure,
                proxy=self.state.proxy,
                bypass_403=True,
                ua_rotate=True,
            )

    async def _do_recon(self) -> None:
        await self._ensure_client()
        await self.state.client.calibrate_soft_404()
        self.state.recon = await run_recon(self.state.client)

    async def _do_refs(self) -> None:
        await self._ensure_client()
        self.state.refs = await discover_refs(self.state.client)

    async def _do_objects(self) -> None:
        await self._ensure_client()
        git_dir = self.state.out_dir / ".git"
        git_dir.mkdir(parents=True, exist_ok=True)
        self.state.engine = ObjectEngine(self.state.client, git_dir)
        await self.state.engine.fetch_packs()

    async def _do_index(self) -> None:
        if not self.state.refs or "index" not in (self.state.refs.raw_files or {}):
            self.console.print("[yellow]No index file fetched yet.[/yellow]")
            return
        entries = parse_index(self.state.refs.raw_files["index"])
        self.state.artifacts["index_entries"] = entries
        t = Table(title=f"index entries ({len(entries)})")
        t.add_column("mode")
        t.add_column("sha")
        t.add_column("path")
        for e in entries[:30]:
            t.add_row(oct(e.mode), e.sha1[:10], e.path)
        self.console.print(t)
        if len(entries) > 30:
            self.console.print(f"[dim]…and {len(entries)-30} more[/dim]")

    async def _do_aggressive(self) -> None:
        await self._ensure_client()
        entries = self.state.artifacts.get("index_entries") or []
        if not entries:
            if self.state.refs and "index" in (self.state.refs.raw_files or {}):
                entries = parse_index(self.state.refs.raw_files["index"])
        if not entries:
            self.console.print("[yellow]No index entries — run 'index' first.[/yellow]")
            return
        agg = AggressiveRetriever(self.state.client, self.state.target_url,
                                    self.state.out_dir)
        blobs = [(e.sha1, e.path) for e in entries]
        res = await agg.run(blobs)
        self.state.aggressive_result = res
        self.console.print(
            f"  [green]recovered {len(res.hits)} blob(s); "
            f"{len(res.failed_shas)} failed[/green]"
        )

    async def _do_rebuild(self) -> None:
        from .core.reconstructor import init_repo, reconstruct
        init_repo(self.state.out_dir, self.state.out_dir / ".git")
        rebuild = reconstruct(self.state.out_dir / ".git")
        self.state.artifacts["rebuild"] = rebuild
        self.console.print(
            f"  [green]reconstructed:[/green] {len(rebuild.commits)} commits, "
            f"{len(rebuild.dangling_commits)} dangling, "
            f"{len(rebuild.files_on_head)} files on HEAD"
        )

    async def _do_secrets(self) -> None:
        from .secrets.git_walker import walk_repository
        rebuild = self.state.artifacts.get("rebuild")
        if not rebuild:
            self.console.print("[yellow]Run 'rebuild' first.[/yellow]")
            return
        findings = walk_repository(self.state.out_dir, rebuild.commits,
                                    rebuild.dangling_commits, rebuild.dangling_blobs)
        self.state.artifacts["findings"] = findings
        for f in findings:
            self.log.secret_hit(f.rule_id, f.file_path, f.redacted, f.severity)

    async def _do_endpoints(self) -> None:
        entries = self.state.artifacts.get("index_entries") or []
        candidate_paths = sorted({"/" + e.path for e in entries
                                   if e.path.endswith((".php", ".html", ".js"))})[:60]
        await self._ensure_client()
        live: list[tuple[str, int, int]] = []
        for path in candidate_paths:
            url = self.state.target_url + path
            r = await self.state.client._request(url)
            if 200 <= r.status < 300 and len(r.content) > 32:
                live.append((url, r.status, len(r.content)))
                self.log.success(f"endpoint LIVE  {r.status}  {url}  ({len(r.content)}B)")
        self.state.artifacts["live_endpoints"] = live

    async def _do_extras(self) -> None:
        from .config import SENSITIVE_EXTRAS
        await self._ensure_client()
        for name in SENSITIVE_EXTRAS:
            url = f"{self.state.target_url}/{name}"
            r = await self.state.client._request(url)
            if r.ok:
                self.log.success(f"extra: {name} ({len(r.content)}B)")

    async def _do_roadmap(self) -> None:
        if not os.environ.get("EMERGENT_LLM_KEY"):
            self.console.print("[yellow]EMERGENT_LLM_KEY not set. Cannot ask AI.[/yellow]")
            return
        from .ai.exploit_roadmap import generate_roadmap
        rebuild = self.state.artifacts.get("rebuild")
        rebuild_d = {}
        if rebuild:
            rebuild_d = {
                "branches": list(rebuild.branches or []),
                "tags":     list(rebuild.tags or []),
                "commits":  [c.__dict__ for c in (rebuild.commits or [])[:10]],
                "dangling_commits": list(rebuild.dangling_commits or []),
                "dangling_blobs":   list(rebuild.dangling_blobs or []),
            }
        roadmap = await generate_roadmap(
            target_url=self.state.target_url,
            out_dir=self.state.out_dir,
            recon=(self.state.recon.__dict__ if self.state.recon else {}),
            rebuild=rebuild_d,
            findings=[f.__dict__ for f in self.state.artifacts.get("findings", [])],
            escalation=None,
            session_id=f"gitvulture-interactive-{os.getpid()}",
        )
        self.state.artifacts["roadmap"] = roadmap
        if "error" in roadmap:
            self.console.print(f"[red]AI error:[/red] {roadmap['error']}")
            return
        for s in roadmap.get("scenarios", []):
            self.console.print(Panel(
                f"[bold]{s.get('title', '?')}[/bold]\n"
                f"impact: {s.get('impact', '-')}\n"
                f"confidence: {s.get('confidence', '-')}\n"
                f"effort: ~{s.get('effort_minutes', '?')} min\n"
                f"evidence: {', '.join(s.get('evidence_citations', []) or [])}\n"
                f"rationale: {s.get('rationale', '')}",
                border_style="red",
            ))
            for cmd in s.get("ready_commands", [])[:5]:
                self.console.print(f"  [green]$[/green] {cmd}")

    async def _do_ai_guide(self) -> None:
        if not os.environ.get("EMERGENT_LLM_KEY"):
            self.console.print("[yellow]No LLM key. AI guidance unavailable.[/yellow]")
            return
        # Lightweight one-shot: ask "given current state, what next?"
        self.console.print("[bold cyan]Consulting AI for next-step recommendation…[/bold cyan]")
        # Reuse the roadmap generator with truncated bundle
        await self._do_roadmap()

    async def _do_report(self) -> None:
        report_path = self.state.out_dir / "gitvulture-interactive-report.json"
        rep = {
            "target": self.state.target_url,
            "history": self.state.history,
            "recon": self.state.recon.__dict__ if self.state.recon else None,
            "artifacts": {k: str(type(v)) for k, v in self.state.artifacts.items()},
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(rep, default=str, indent=2))
        self.console.print(f"[green]Report saved → {report_path}[/green]")
        if self.state.client:
            await self.state.client.close()
