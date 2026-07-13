# cloudsecure/cli.py
import click
import datetime
import os
import sys
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from cloudsecure.utils.reporting import export_to_csv, export_to_pdf
from cloudsecure import __version__  # Ensure this exists in your __init__.py

from cloudsecure.scanners.terraform import run_local_scan

console = Console()

# --- Ascii Art Banner ---
CLOUDSECURE_BANNER = r"""
   ________                _______                               
  / ____/ /___  __  ______/ / ___/___  ________  __________      
 / /   / / __ \/ / / / __  /\__ \/ _ \/ ___/ / / / ___/ _ \     
/ /___/ / /_/ / /_/ / /_/ /___/ /  __/ /__/ /_/ / /  /  __/     
\____/_/\____/\__,_/\__,_//____/\___/\___/\__,_/_/   \___/      
                                                                 
    
"""


# --- 1. THE MAIN GROUP ---
@click.group()
# This adds the global --version and -V flags
@click.version_option(__version__, '--version', '-V', prog_name="CloudSecure CLI")
def cli():
    """🛡️ CloudSecure: Intelligent Auditing for Modern Infrastructure [Kaali Topi].
    
    Commands:
    - iac: Run a scan. Use --csv-export or --pdf-export for reports.
    - version: Show team and version info.
    """
    pass

# --- 2. THE VERSION SUB-COMMAND ---
@cli.command()
def version():
    """Display the CloudSecure version and Team info."""
    version_text = Text()
    version_text.append("CloudSecure CLI ", style="bold magenta")
    version_text.append(f"v{__version__}\n", style="bold cyan")
    version_text.append("Developed by ", style="dim white")
    version_text.append("Team Kaali Topi", style="bold yellow")
    
    console.print(Panel(version_text, border_style="dim white", expand=False))

# --- HELPER FUNCTIONS ---
def print_banner():
    """Prints the CloudSecure ASCII art banner."""
    styled_banner = Text(CLOUDSECURE_BANNER, style="bold magenta")
    console.print(styled_banner)

def get_config_summary(scan_path):
    """Returns a table summarizing the scan configuration."""
    table = Table(show_header=False, show_lines=False, box=None, padding=(0, 2))
    table.add_row(Text("→ Scanning local IaC directory:", style="bold white"))
    table.add_row(Text("  • Directory:", style="dim white"), Text(scan_path, style="bold yellow"))
    table.add_row(Text("  • Scanners:", style="dim white"), Text("misconfig, secret", style="bold yellow"))
    table.add_row(Text("  • Authentication method:", style="dim white"), Text("No auth", style="bold yellow"))
    return table

def format_findings_table(title, items, color_theme):
    """Generic helper to create a styled table for results."""
    table = Table(title=f"[bold {color_theme}]{title}[/]", box=None, padding=(0, 1))
    table.title_align = "left"
    
    table.add_column("Severity", justify="center", width=12)
    table.add_column("ID", style="dim cyan", width=15)
    table.add_column("Resource", style="bold magenta", width=25)
    table.add_column("Description", style="white")

    if not items:
        return Text(f"\n✔ No items found in this category.", style="dim green")

    severity_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items.sort(key=lambda x: severity_map.get(x.get('severity', 'LOW'), 99))

    for issue in items:
        severity = str(issue.get('severity', 'LOW')).upper()
        if severity == "CRITICAL":
            sev_style = "white on red"
        elif severity == "HIGH":
            sev_style = "red"
        elif severity == "MEDIUM":
            sev_style = "yellow"
        else:
            sev_style = "blue"
            
        desc = issue.get('rule_description') or issue.get('description') or "No description"
        table.add_row(
            Text(f" {severity} ", style=f"bold {sev_style}"),
            issue.get('rule_id', 'N/A'),
            issue.get('resource', 'unknown'),
            Text(desc, style="white", overflow="fold")
        )
    return table

def format_overview_results(results_list):
    """Generates the Rich overview results panel based on scan status."""
    total_cases = len(results_list)
    failed = len([r for r in results_list if r.get('status') == 'failed'])
    passed = len([r for r in results_list if r.get('status') == 'passed'])
    muted = len([r for r in results_list if r.get('status') == 'muted'])
    
    if total_cases > 0:
        failed_percent = (failed / total_cases) * 100
        passed_percent = (passed / total_cases) * 100
        muted_percent = (muted / total_cases) * 100
    else:
        failed_percent = passed_percent = muted_percent = 0

    colored_table = Table(show_header=False, show_lines=False, box=None, padding=(0, 1))
    colored_table.add_row(
        Panel(Text(f"{failed_percent:.2f}% ({failed}) Failed", style="white"), style="red", padding=(0, 1)),
        Panel(Text(f"{passed_percent:.2f}% ({passed}) Passed", style="white"), style="green", padding=(0, 1)),
        Panel(Text(f"{muted_percent:.2f}% ({muted}) Muted", style="white"), style="blue", padding=(0, 1))
    )
    return Panel(colored_table, border_style="dim white", padding=(0, 0), title="Overview Results:", title_align="left")

# --- 3. THE IAC COMMAND ---

@cli.command()
@click.argument('scan-path', default=".", type=click.Path(exists=True))
@click.option('--scanners', default="misconfig, secret", help="Comma-separated list of scanners to use.")
@click.option('--format', default="json", help="Output format for the full report (e.g., json, sarif).")
@click.option('--csv-export', is_flag=True, help="Generate a professional CSV report (scan_report.csv).")
@click.option('--pdf-export', is_flag=True, help="Generate a branded PDF audit report (scan_report.pdf).")
def iac(scan_path, scanners, format, csv_export, pdf_export):
    """Scans local infrastructure files (Terraform) for security issues."""
    
    if os.path.isfile(scan_path) and not scan_path.endswith('.tf'):
         console.print(f"[bold red]Error:[/] '{scan_path}' is a file but not a Terraform (.tf) file.")
         return

    console.print(Align(Text("Initializing CloudSecure Deep Ingestion Engine...", style="bold cyan"), align="center"))
    print_banner()
    console.print(Align(Text("Intelligent Auditing for Modern Infrastructure [Kaali Topi]", style="bold magenta"), align="center"))
    console.print(Align(Text("Developed by Team Kaali Topi", style="dim cyan"), align="center"))
    console.print("\n")

    now = datetime.datetime.now()
    rprint(f"[dim white]Date:[/] [bold yellow]{now.strftime('%Y-%m-%d %H:%M:%S')}[/]")
    console.print("\n")
    console.print(get_config_summary(scan_path))
    console.print("\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[bold white]{task.completed}/{task.total} in {task.elapsed:.1f}s"),
        console=console
    ) as progress:
        task1 = progress.add_task("[bold white]Scanning files...", total=100)
        findings_report = run_local_scan(scan_path, format)

        if isinstance(findings_report, dict) and "error" in findings_report:
            progress.update(task1, description=Text("Scan Error", style="bold red"))
            console.print(f"\n[bold red]Error:[/] {findings_report['error']}")
            return 
        
        while not progress.finished:
            progress.update(task1, advance=5)
            time.sleep(0.02)
        progress.update(task1, description=Text("Scan completed!", style="bold white"))

    if findings_report:
        raw_results = findings_report.get("results", [])
        critical_failures = [res for res in raw_results if str(res.get('status')) == '1']
        best_practices = [
            res for res in raw_results 
            if str(res.get('status')) == '0' and res.get('severity') in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        ]

        processed_list = []
        for res in raw_results:
            if str(res.get('status')) == '1':
                res['status'] = 'failed'
            elif res in best_practices:
                res['status'] = 'muted'
            else:
                res['status'] = 'passed'
            processed_list.append(res)

        summary_panel = format_overview_results(processed_list)
        console.print("\n")
        console.print(summary_panel)

        console.print("\n" + "━" * 50)
        console.print(format_findings_table("CRITICAL SECURITY VIOLATIONS (FAILURES)", critical_failures, "red"))

        console.print("\n" + "━" * 50)
        console.print(format_findings_table("SECURITY BEST PRACTICES & WARNINGS", best_practices, "yellow"))
        console.print("\n")
        
        if csv_export:
            path = export_to_csv(raw_results)
            console.print(f"[bold green]✔ CSV Report generated:[/] {path}")

        if pdf_export:
            path = export_to_pdf(raw_results)
            console.print(f"[bold green]✔ PDF Report generated:[/] {path}")
    else:
        console.print("\n[bold red]Scan failed: No report generated.[/]")

def main():
    cli()

if __name__ == "__main__":
    main()