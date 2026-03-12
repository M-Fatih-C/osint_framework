import os
import typer
import httpx
import json
import time
from pathlib import Path

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


@app.command("vision-calibrate")
def vision_calibrate(
    manifest: str,
    output: str = typer.Argument("osint_framework/data/vision/calibration_report.json"),
    min_threshold: float = typer.Argument(0.6),
    max_threshold: float = typer.Argument(0.98),
    step: float = typer.Argument(0.01),
    max_pairs_per_class: int = typer.Argument(25000),
):
    """
    Calibrate face similarity threshold from a labeled local face dataset.
    """
    try:
        from osint_framework.plugins.vision.calibration import VisionThresholdCalibrator
    except Exception as exc:
        typer.secho(f"[-] Could not load calibration module: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.secho(f"[*] Loading manifest: {manifest}", fg=typer.colors.CYAN)
    calibrator = VisionThresholdCalibrator(
        min_threshold=min_threshold,
        max_threshold=max_threshold,
        step=step,
        max_pairs_per_class=max_pairs_per_class,
    )
    report = calibrator.calibrate_from_manifest(manifest)
    if report.get("status") == "error":
        typer.secho(f"[-] Calibration failed: {report.get('reason')}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    report_path = calibrator.save_report(report, output)
    status = str(report.get("status") or "")
    recommended = report.get("recommended_similarity_min_score")
    metrics = report.get("best_threshold_metrics") or {}
    quality = report.get("quality_assessment") or {}

    typer.secho("\n[+] Calibration completed", fg=typer.colors.GREEN)
    typer.echo(f"  Status: {status}")
    typer.echo(f"  Samples: {report.get('samples_total')} (embeddings={report.get('embeddings_total')})")
    typer.echo(
        f"  Pairs: positive={report.get('positive_pairs_total')} negative={report.get('negative_pairs_total')}"
    )
    typer.echo(f"  Recommended OSINT_VISION_SIMILARITY_MIN_SCORE={recommended}")
    typer.echo(
        f"  Metrics: precision={metrics.get('precision')} recall={metrics.get('recall')} f1={metrics.get('f1')}"
    )
    typer.echo(f"  Report: {Path(report_path)}")
    if status == "warning":
        typer.secho("  Dataset quality is low; threshold is not auto-recommended.", fg=typer.colors.YELLOW)
        reasons = quality.get("reasons") or []
        if reasons:
            typer.echo(f"  Quality reasons: {', '.join(reasons)}")


@app.command("vision-build-manifest")
def vision_build_manifest(
    dataset_dir: str,
    output_manifest: str = typer.Argument("osint_framework/data/vision/calibration_manifest.json"),
    mode: str = typer.Argument("auto"),
    min_samples_per_identity: int = typer.Argument(2),
):
    """
    Build calibration manifest from a dataset directory.
    """
    try:
        from osint_framework.plugins.vision.dataset_manifest import VisionCalibrationManifestBuilder
    except Exception as exc:
        typer.secho(f"[-] Could not load manifest builder: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.secho(f"[*] Scanning dataset: {dataset_dir}", fg=typer.colors.CYAN)
    builder = VisionCalibrationManifestBuilder()
    try:
        report = builder.build(
            dataset_dir=dataset_dir,
            output_path=output_manifest,
            mode=mode,
            min_samples_per_identity=min_samples_per_identity,
        )
    except Exception as exc:
        typer.secho(f"[-] Manifest build failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.secho("\n[+] Manifest generated", fg=typer.colors.GREEN)
    typer.echo(f"  Mode: {report.get('mode')}")
    typer.echo(f"  Identities: {report.get('identities_total')}")
    typer.echo(f"  Samples: {report.get('samples_total')}")
    typer.echo(f"  Output: {report.get('output_path')}")
    dropped = report.get("dropped_identities") or {}
    if dropped:
        typer.echo(f"  Dropped (min_samples<{min_samples_per_identity}): {len(dropped)} identities")


@app.command("vision-create-review")
def vision_create_review(
    image_path: str,
    review_dir: str = typer.Argument("osint_framework/data/vision/review"),
    min_size_px: int = typer.Argument(120),
    max_faces: int = typer.Argument(20),
):
    """
    Detect faces and create a review package (crops + review.json).
    """
    try:
        from osint_framework.plugins.vision.face_review import VisionFaceReviewSession
    except Exception as exc:
        typer.secho(f"[-] Could not load face review module: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    session = VisionFaceReviewSession(min_size_px=min_size_px, max_faces=max_faces)
    try:
        result = session.create_review(image_path=image_path, review_dir=review_dir)
    except Exception as exc:
        typer.secho(f"[-] Review creation failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if result.get("status") != "ok":
        typer.secho(f"[-] Review creation failed: {result.get('reason')}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.secho("\n[+] Review package created", fg=typer.colors.GREEN)
    typer.echo(f"  Provider: {result.get('provider')}")
    typer.echo(f"  Faces: {result.get('faces_total')}")
    typer.echo(f"  Review file: {result.get('review_path')}")
    typer.echo("  Next: edit review.json and set approved=true + identity for valid faces.")


@app.command("vision-export-approved")
def vision_export_approved(
    review_json_path: str,
    dataset_dir: str = typer.Argument("osint_framework/data/vision/datasets/approved_faces"),
    min_samples_per_identity: int = typer.Argument(2),
):
    """
    Export approved faces from review.json into dataset folders by identity.
    """
    try:
        from osint_framework.plugins.vision.face_review import VisionFaceReviewSession
    except Exception as exc:
        typer.secho(f"[-] Could not load face review module: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    session = VisionFaceReviewSession()
    try:
        result = session.export_approved_dataset(
            review_json_path=review_json_path,
            dataset_dir=dataset_dir,
            min_samples_per_identity=min_samples_per_identity,
        )
    except Exception as exc:
        typer.secho(f"[-] Export failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if result.get("status") != "ok":
        typer.secho("[-] Export failed: no approved faces written", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.secho("\n[+] Approved faces exported", fg=typer.colors.GREEN)
    typer.echo(f"  Dataset: {result.get('dataset_dir')}")
    typer.echo(f"  Written: {result.get('written_total')}")
    typer.echo(f"  Identities: {result.get('identities_total')}")
    below_min = result.get("below_min_samples") or {}
    if below_min:
        typer.secho("  Warning: some identities are below recommended sample count.", fg=typer.colors.YELLOW)
        typer.echo(f"  Below min: {below_min}")


@app.command("vision-apply-calibration")
def vision_apply_calibration(
    report_path: str,
    config_path: str = typer.Argument("osint_framework/config.yaml"),
    env_example_path: str = typer.Argument(".env.example"),
):
    """
    Apply recommended similarity threshold from calibration report into config files.
    """
    try:
        from osint_framework.plugins.vision.calibration_apply import apply_calibration_report
    except Exception as exc:
        typer.secho(f"[-] Could not load calibration apply module: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    try:
        result = apply_calibration_report(
            report_path=report_path,
            config_path=config_path,
            env_example_path=env_example_path,
        )
    except Exception as exc:
        typer.secho(f"[-] Apply failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if result.get("status") != "ok":
        typer.secho(f"[-] Apply skipped: {result.get('reason')}", fg=typer.colors.YELLOW)
        typer.echo(
            f"  report_status={result.get('report_status')} recommended={result.get('recommended_similarity_min_score')}"
        )
        raise typer.Exit(code=1)

    typer.secho("\n[+] Calibration applied", fg=typer.colors.GREEN)
    typer.echo(f"  Applied OSINT_VISION_SIMILARITY_MIN_SCORE={result.get('applied_similarity_min_score')}")
    typer.echo(
        f"  config: {result.get('config', {}).get('status')} ({result.get('config', {}).get('path')})"
    )
    typer.echo(
        f"  env_example: {result.get('env_example', {}).get('status')} ({result.get('env_example', {}).get('path')})"
    )

if __name__ == "__main__":
    app()
