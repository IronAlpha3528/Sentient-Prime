import subprocess
import os

def run_playbook(action_name: str, target: str):
    """
    Maps an action name to a playbook script and executes it as a subprocess.
    """
    playbook_map = {
        "Isolate Host": "isolate_host.py",
        "Revoke Credential": "revoke_credential.py",
        "Block IP": "block_ip.py"
    }
    
    script_name = playbook_map.get(action_name)
    if not script_name:
        print(f"❌ Executor Error: No playbook mapped for action '{action_name}'.")
        return False
        
    script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "playbooks", script_name)
    
    if not os.path.exists(script_path):
        print(f"❌ Executor Error: Playbook script '{script_path}' not found.")
        return False
        
    print(f"⚡ EXECUTING PLAYBOOK: {script_name} against {target}...")
    try:
        # Run the playbook as a subprocess
        result = subprocess.run(
            ["python", script_path, "--target", target],
            capture_output=True,
            text=True,
            check=True
        )
        print(f"✅ Execution Success:\n{result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Playbook Execution Failed:\n{e.stderr}")
        return False
