"""ASCII banner for GitExpose."""
from rich.console import Console
from rich.text import Text

BANNER = r"""
   ____ _ _   _____                          
  / ___(_) |_| ____|_  ___ __   ___  ___  ___ 
 | |  _| | __|  _| \ \/ / '_ \ / _ \/ __|/ _ \
 | |_| | | |_| |___ >  <| |_) | (_) \__ \  __/
  \____|_|\__|_____/_/\_\ .__/ \___/|___/\___|
                        |_|                   
"""

TAGLINE = "  Advanced Git Directory Exposure Exploitation Framework"
META = "  v1.0.0  |  Live verbose  |  Pack/Index/Refs recovery  |  Secret scanner"


def print_banner(console: Console, version: str = "1.0.0") -> None:
    text = Text(BANNER, style="bold cyan")
    console.print(text)
    console.print(TAGLINE, style="bold white")
    console.print(
        f"  v{version}  |  Live verbose  |  Pack/Index/Refs recovery  |  Secret scanner",
        style="dim",
    )
    console.print()


def legal_warning(console: Console) -> None:
    console.print(
        "  [yellow]![/yellow] [bold]Legal notice:[/bold] Use only on targets you are "
        "[bold green]explicitly authorized[/bold green] to test "
        "(bug-bounty scope, CTF, own assets).",
        style="white",
    )
    console.print(
        "  [yellow]![/yellow] The developer assumes [bold]no liability[/bold] for misuse.\n",
        style="white",
    )
