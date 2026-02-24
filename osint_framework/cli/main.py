import os
import typer
import httpx
import json
import time

app = typer.Typer(help="Professional OSINT Framework CLI")
API_BASE = os.getenv("OSINT_API_BASE", "http://localhost:8000/api/v1").rstrip("/")

@app.command()
def scan(target_type: str, target: str):
    """
    Launch a new OSINT scan.
    Example: osint scan domain example.com
    """
    typer.secho(f"[*] Starting scan on {target} ({target_type})...", fg=typer.colors.CYAN)
    
    try:
        response = httpx.post(f"{API_BASE}/scan", json={"target": target, "target_type": target_type})
        response.raise_for_status()
        data = response.json()
        job_id = data["job_id"]
        typer.secho(f"[+] Scan queued! Job ID: {job_id}", fg=typer.colors.GREEN)
        
        # Optionally, wait and poll for completion
        typer.echo("[*] Waiting for results...")
        while True:
            status_resp = httpx.get(f"{API_BASE}/scan/{job_id}")
            status_data = status_resp.json()
            if status_data["status"] in ["completed", "error"]:
                typer.secho(f"\n[+] Scan {status_data['status']}!", fg=typer.colors.GREEN)
                break
            typer.echo(f"\rProgress: {status_data['modules_done']}/{status_data['modules_total']} modules complete", nl=False)
            time.sleep(2)
            
    except httpx.RequestError as e:
        typer.secho(f"[-] API connection failed: {e}", fg=typer.colors.RED)

@app.command()
def results(job_id: str, format: str = "json"):
    """
    Fetch results of a scan.
    """
    try:
        response = httpx.get(f"{API_BASE}/result/{job_id}")
        response.raise_for_status()
        data = response.json()
        
        if format == "json":
            typer.echo(json.dumps(data, indent=2))
        else:
            typer.secho(f"[-] Format {format} not fully supported in CLI yet. Showing JSON.", fg=typer.colors.YELLOW)
            typer.echo(json.dumps(data, indent=2))
            
    except httpx.RequestError as e:
        typer.secho(f"[-] API connection failed: {e}", fg=typer.colors.RED)
    except httpx.HTTPStatusError as e:
         typer.secho(f"[-] Error: {e.response.json()}", fg=typer.colors.RED)
         
@app.command()
def modules():
    """
    List active modules.
    """
    try:
        response = httpx.get(f"{API_BASE}/modules")
        response.raise_for_status()
        mods = response.json()
        
        typer.secho(f"\nActive Modules ({len(mods)}):", fg=typer.colors.CYAN)
        for m in mods:
            typer.echo(f"- {m['name']} v{m['version']} [{','.join(m['target_types'])}]")
    except httpx.RequestError as e:
        typer.secho(f"[-] API connection failed: {e}", fg=typer.colors.RED)

if __name__ == "__main__":
    app()
