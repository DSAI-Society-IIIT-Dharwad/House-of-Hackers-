from fastapi import FastAPI, HTTPException, Body
from typing import Optional

app = FastAPI(title="Decepticon Execution API")


import subprocess

@app.post("/execute/recon")
def execute_recon(target: Optional[str] = Body(None, embed=True)):
    """Proper reconnaissance using Docker attacker container for lab targets"""
    try:
        target = target or "localhost"
        
        # Security check
        if any(char in target for char in [';', '&', '|', '>', '<', '`', '$']):
             raise HTTPException(status_code=400, detail="Invalid target")

        # Check if we should use Docker (for lab targets)
        is_lab = target.lower() in ["victim", "decepticon-victim", "juice-shop", "decepticon-juice-shop", "dvwa", "decepticon-dvwa", "attacker"]
        
        if is_lab:
            # Check if attacker container is running
            try:
                check_cmd = ["docker", "inspect", "-f", "{{.State.Running}}", "attacker"]
                check_res = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
                
                if check_res.returncode == 0 and "true" in check_res.stdout.lower():
                    cmd = ["docker", "exec", "attacker", "nmap", "-sV", "-Pn", "--script", "http-enum", "-T4", target]
                    output_prefix = f"🛡️ [LAB EXECUTION] Routing scan through 'attacker' container to {target}...\n"
                else:
                    return {
                        "type": "terminal",
                        "output": "❌ ERROR: Lab 'attacker' container is not running.\n\n"
                                  "Please go to the '🧪 Lab Monitor' page and click '🚀 Start Lab Environment' first.",
                    }
            except Exception as e:
                return {
                    "type": "terminal",
                    "output": f"❌ ERROR: Docker command failed: {str(e)}\nMake sure Docker Desktop is running.",
                }
        else:
            cmd = ["nmap", "-sV", "-Pn", "--script", "http-enum", "-T4", target]
            output_prefix = f"Starting Nmap recon scan on {target}...\n"
        
        output = output_prefix + f"Command: {' '.join(cmd)}\n\n"
        result = subprocess.run(cmd, capture_output=True, timeout=300)
        
        stdout_str = result.stdout.decode('utf-8', errors='replace') if result.stdout else ""
        stderr_str = result.stderr.decode('utf-8', errors='replace') if result.stderr else ""
        
        output += stdout_str
        if stderr_str:
            output += "\nErrors:\n" + stderr_str
            
        return {"type": "terminal", "output": output}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/execute/vuln")
def execute_vuln(
    target: Optional[str] = Body(None, embed=True),
    scripts: Optional[str] = Body("vuln", embed=True)
):
    """Proper vulnerability scanning using Docker attacker container for lab targets"""
    try:
        target = target or "localhost"
        scripts = scripts or "vuln"

        if any(char in target for char in [';', '&', '|', '>', '<', '`', '$']):
             raise HTTPException(status_code=400, detail="Invalid target")

        is_lab = target.lower() in ["victim", "decepticon-victim", "juice-shop", "decepticon-juice-shop", "dvwa", "decepticon-dvwa", "attacker"]
        
        if is_lab:
            # Check if attacker container is running
            try:
                check_cmd = ["docker", "inspect", "-f", "{{.State.Running}}", "attacker"]
                check_res = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
                
                if check_res.returncode == 0 and "true" in check_res.stdout.lower():
                    cmd = ["docker", "exec", "attacker", "nmap", "-sV", "-Pn", "--script", scripts, "-T4", target]
                    output_prefix = f"🛡️ [LAB EXECUTION] Routing vuln scan through 'attacker' container to {target}...\n"
                else:
                    return {
                        "type": "terminal",
                        "output": "❌ ERROR: Lab 'attacker' container is not running.\n\n"
                                  "Please go to the '🧪 Lab Monitor' page and click '🚀 Start Lab Environment' first.",
                    }
            except Exception as e:
                return {
                    "type": "terminal",
                    "output": f"❌ ERROR: Docker command failed: {str(e)}\nMake sure Docker Desktop is running.",
                }
        else:
            cmd = ["nmap", "-sV", "-Pn", "--script", scripts, "-T4", target]
            output_prefix = f"Starting Nmap vulnerability scan on {target}...\n"
        
        output = output_prefix + f"Command: {' '.join(cmd)}\n\n"
        result = subprocess.run(cmd, capture_output=True, timeout=300)
        
        stdout_str = result.stdout.decode('utf-8', errors='replace') if result.stdout else ""
        stderr_str = result.stderr.decode('utf-8', errors='replace') if result.stderr else ""
        
        output += stdout_str
        if stderr_str:
            output += "\nErrors:\n" + stderr_str
            
        return {"type": "terminal", "output": output}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/run-recon")
def run_recon_compat():
    """Compatibility endpoint - redirects to execute_recon"""
    return execute_recon()


@app.post("/execute/lateral")
def execute_lateral():
    """Fast lateral movement analysis simulation"""
    try:
        from src.security_services.core_services import analyze_lateral_movement
        
        target = "compromised_host"
        
        # Analyze lateral paths (instant with fast_mode)
        lateral_result = analyze_lateral_movement(target, fast_mode=True)
        
        output = f"""Starting Lateral Movement Analysis from {target}...

Current Network Segment: {lateral_result.network_segment}

TRUST RELATIONSHIPS FOUND:
{chr(10).join(f"- {t.trust_type}: {t.source} -> {t.target} [{t.risk_level.value.upper()}] (Perms: {', '.join(t.permissions)})" for t in lateral_result.trusts)}

HARVESTED CREDENTIALS:
{chr(10).join(f"- {c.cred_type} for '{c.username}' (Valid on: {', '.join(c.target_systems)})" for c in lateral_result.credentials)}

VIABLE LATERAL PATHS:
{chr(10).join(f"- {p.technique} ({p.mitre_id}) to {p.destination} [Difficulty: {p.difficulty}, Success rate: {int(p.success_probability * 100)}%]" for p in lateral_result.lateral_paths)}

Analysis complete.
"""
        return {
            "type": "terminal",
            "output": output,
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
