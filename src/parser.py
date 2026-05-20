
from yaml import yaml
from fastapi import Request, BackgroundTasks, HTTPException, Response, status as Status

def audit_mainifest(raw_yaml_text: str, filename: str) -> list:
    # Placeholder for the actual audit logic
    # This function would perform the necessary checks and audits on the YAML content
    print(f"Auditing manifest from file: {filename}")
    violations = []
    # Simulate some audit checks and add any violations to the list
    if "kind: Pod" in raw_yaml_text:
        violations.append(f"Violation in {filename}: Pods are not allowed.")
    return violations


def validate_pr_files(yaml_files: list, github_token: str):
    """Downloads each manifest and checks for security vulnerabilities."""
    headers = {"Authorization": f"token {github_token}"}
    all_violations = []

    for file_info in yaml_files:
        filename = file_info["filename"]
        raw_url = file_info["raw_url"]

        # Download the actual raw manifest text
        file_response = Request.get(raw_url, headers=headers)
        if file_response.status_code != 200:
            continue
            
        raw_yaml_content = file_response.text

        # Use safe_load_all to parse multi-document manifests safely (--- separated)
        try:
            manifests = yaml.safe_load_all(raw_yaml_content)
            
            for doc in manifests:
                if not doc or "kind" not in doc:
                    continue
                
                # Execute your parameters validation loop here
                violations = audit_single_document(doc, filename)
                all_violations.extend(violations)
                
        except yaml.YAMLError as err:
            all_violations.append({
                "file": filename,
                "policy": "YAML Syntax",
                "severity": "CRITICAL",
                "message": f"Invalid YAML formatting: {str(err)}"
            })

    return all_violations

def audit_single_document(doc: dict, filename: str) -> list:
    """Core parameters checklist validation."""
    violations = []
    kind = doc.get("kind")
    name = doc.get("metadata", {}).get("name", "unknown")

    if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
        containers = doc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        
        for c in containers:
            c_name = c.get("name", "unknown")
            
            # 1. Validate parameter: runAsNonRoot
            run_as_non_root = c.get("securityContext", {}).get("runAsNonRoot")
            if run_as_non_root is not True:
                violations.append({
                    "file": filename,
                    "policy": "Pod Security",
                    "severity": "CRITICAL",
                    "message": f"Container `{c_name}` in {kind}/{name} must have `securityContext.runAsNonRoot` set to true."
                })

            # 2. Validate parameter: memory limit boundaries
            memory_limit = c.get("resources", {}).get("limits", {}).get("memory")
            if not memory_limit:
                violations.append({
                    "file": filename,
                    "policy": "Resource Management",
                    "severity": "HIGH",
                    "message": f"Container `{c_name}` in {kind}/{name} is missing explicit memory limits."
                })
                
    return violations    