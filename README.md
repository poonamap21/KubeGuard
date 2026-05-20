# KubeGuard
An event-driven Python microservice that automatically audits Kubernetes manifests and Helm charts for security misconfigurations and CVEs before they hit production.

Building your **`gitops-governance-engine`** (codenamed *KubeGuard*) requires a clear, layered development approach. By breaking it down step-by-step, you ensure that you write clean Python code while implementing strong DevSecOps practices.

---

## 🛠️ Complete System Architecture: Input & Output

To understand how data flows through your microservice, let's map out the boundary inputs and outputs.

* **Input Source:** * **GitHub Webhook payload:** A JSON object triggered by a `pull_request` event. It contains metadata about the repository, branch, commit SHA, and target pull request ID.
* **Raw Configuration Manifests:** YAML files containing Kubernetes resource definitions (e.g., `Deployment`, `Pod`, `StatefulSet`) pulled programmatically using the GitHub REST API based on the webhook payload.


* **Output Destination:**
* **GitHub PR Review Comment:** A dynamically constructed Markdown table posted back to the specific pull request thread via the GitHub API.
* **Pipeline Status Check:** A `success` or `failure` commit status API flag to enforce branch protection and physically prevent the merging of risky code.



---

## 📋 What Parameters to Validate (Security Policy Schema)

When your engine processes a Kubernetes manifest, it should parse the YAML into Python dictionaries and look for specific fields within the `spec` definitions. Here is an enterprise baseline of parameters to validate:

### 1. Pod Security Context Restrictions

* **`securityContext.runAsNonRoot`**: Must be explicitly set to `true`. Ensures the application doesn't run with root uid permissions.
* **`securityContext.allowPrivilegeEscalation`**: Must be explicitly set to `false`. Prevents a process from gaining more privileges than its parent process.
* **`securityContext.privileged`**: Must not exist or be set to `false`. Running a privileged container breaks all container isolation barriers.

### 2. Resource Management (Guardrails against DoS)

* **`resources.limits.cpu` & `resources.limits.memory**`: Must be defined. Without limits, a compromised or runaway container can consume all available node resources, starving critical system components.
* **`resources.requests.cpu` & `resources.requests.memory**`: Must be defined. Essential for the Kubernetes scheduler to correctly place workloads across nodes.

### 3. Supply Chain Security

* **`image` tag**: Must not use `:latest` or be missing a tag entirely. Images must point to a specific semantic version (e.g., `:1.2.3`) or an immutable SHA-256 digest to prevent unauthorized runtime mutations.

---

## 🚀 Step-by-Step Implementation Guide

Follow this logical pipeline to build your service on your own from scratch.

### Step 1: Establish the Python Project Structure

Start with a modern, clean Python project directory layout. Initialize a virtual environment and structure your source directories cleanly.

```text
gitops-governance-engine/
├── src/
│   ├── __init__.py
│   ├── main.py            # FastAPI Application Entrypoint
│   ├── parser.py          # YAML Validation & Policy Logic
│   └── github_client.py   # GitHub REST API Interaction Layer
├── tests/
│   └── test_parser.py     # Unit Tests for validation policies
├── Dockerfile             # Multi-stage hardened production container
├── requirements.txt       # Project dependencies
└── README.md

```

### Step 2: Build the Core Policy Engine (`src/parser.py`)

Write a pure Python utility module that focuses purely on dictionary traversal and rule matching.

```python
import yaml
from typing import Dict, List, Tuple

def audit_manifest(yaml_content: str) -> List[Dict[str, str]]:
    """
    Parses a Kubernetes manifest string and evaluates security rules.
    Returns a list of discovered violations.
    """
    violations = []
    try:
        # Load multi-document YAML strings safely
        documents = yaml.safe_load_all(yaml_content)
        for doc in documents:
            if not doc or "kind" not in doc:
                continue
                
            kind = doc.get("kind")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", "unknown")
            
            # Focus checks on workload structures containing pod templates
            if kind in ["Deployment", "StatefulSet", "Job"]:
                pod_template = doc.get("spec", {}).get("template", {})
                pod_spec = pod_template.get("spec", {})
                containers = pod_spec.get("containers", [])
                
                for container in containers:
                    c_name = container.get("name", "unknown")
                    sec_ctx = container.get("securityContext", {})
                    resources = container.get("resources", {})
                    image = container.get("image", "")
                    
                    # Rule 1: Check Non-Root Execution Status
                    if sec_ctx.get("runAsNonRoot") is not True:
                        violations.append({
                            "resource": f"{kind}/{name}",
                            "container": c_name,
                            "severity": "CRITICAL",
                            "policy": "runAsNonRoot restriction",
                            "message": "container securityContext.runAsNonRoot must be set to true."
                        })
                        
                    # Rule 2: Check Resource Limit Thresholds
                    if "limits" not in resources or "memory" not in resources.get("limits", {}):
                        violations.append({
                            "resource": f"{kind}/{name}",
                            "container": c_name,
                            "severity": "HIGH",
                            "policy": "Resource Limit Enforcement",
                            "message": "Container resource limits are missing or fail to define memory boundaries."
                        })
                        
                    # Rule 3: Enforce Secure Image Tag Management
                    if ":" not in image or image.endswith(":latest"):
                        violations.append({
                            "resource": f"{kind}/{name}",
                            "container": c_name,
                            "severity": "MEDIUM",
                            "policy": "Immutable Image Requirement",
                            "message": "Image reference uses a fluid tag. Immutable versions or digests required."
                        })
    except Exception as e:
        # Append parsing error anomalies
        violations.append({"resource": "YAML Parser", "container": "N/A", "severity": "CRITICAL", "policy": "Syntax Validation", "message": str(e)})
        
    return violations

```

### Step 3: Implement the FastAPI Server Gateway (`src/main.py`)

Set up an asynchronous web api wrapper using FastAPI to expose a functional listener interface ready to accept webhook data payloads.

```python
from fastapi import FastAPI, Request, Response, status
from .parser import audit_manifest
from .github_client import post_pr_comment, update_commit_status
import asyncio

app = FastAPI(title="GitOps Governance Engine", version="1.0.0")

@app.post("/v1/gatekeeper/validate")
async def handle_github_webhook(request: Request):
    payload = await request.json()
    
    # Verify that the webhook action targets a pull request change sequence
    if "pull_request" in payload:
        action = payload.get("action")
        # Process context only during creation or subsequent patch updates
        if action in ["opened", "synchronize"]:
            pr_data = payload["pull_request"]
            repo_full_name = payload["repository"]["full_name"]
            sha = pr_data["head"]["sha"]
            pr_number = payload["number"]
            
            # Asynchronously hand off parsing tasks so the webhook returns immediately
            asyncio.create_task(process_pipeline_audit(repo_full_name, sha, pr_number))
            
    return Response(status_code=status.HTTP_202_ACCEPTED)

async def process_pipeline_audit(repo_name: str, sha: str, pr_number: int):
    """
    Simulated workflow handling manifest acquisition, calling 
    the engine validation layer, and communicating results back to GitHub.
    """
    # 1. Update target commit milestone status to 'pending'
    update_commit_status(repo_name, sha, "pending", "KubeGuard evaluation running...")
    
    # 2. Mock asset loading (In practice, fetch file changes using PyGithub SDK)
    sample_insecure_manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dynamic-web-frontend
spec:
  template:
    spec:
      containers:
      - name: web-app
        image: nginx:latest
        securityContext:
          runAsNonRoot: false
    """
    
    # 3. Process the file contents via your parsing logic
    findings = audit_manifest(sample_insecure_manifest)
    
    # 4. Determine final policy gate pass/fail state
    if findings:
        update_commit_status(repo_name, sha, "failure", "Security policy violations discovered.")
        post_pr_comment(repo_name, pr_number, findings)
    else:
        update_commit_status(repo_name, sha, "success", "All governance checks passed.")

```

### Step 4: Add Communication Capabilities (`src/github_client.py`)

Write helper functions using standard Python `requests` modules to connect to the external GitHub API endpoints.

```python
import requests
import os

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "mock_token")

def update_commit_status(repo: str, sha: str, state: str, description: str):
    """Updates the status circle icon directly on the commit hash inside GitHub"""
    url = f"https://api.github.com/v3/repos/{repo}/statuses/{sha}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    payload = {"state": state, "context": "KubeGuard-Engine", "description": description}
    # In live scenarios: requests.post(url, json=payload, headers=headers)
    print(f"[STATUS UPDATE] {repo} @ {sha} -> {state}: {description}")

def post_pr_comment(repo: str, pr_number: int, violations: list):
    """Formats findings list into a markdown summary and posts a PR thread response"""
    url = f"https://api.github.com/v3/repos/{repo}/issues/{pr_number}/comments"
    
    # Build a clean Markdown layout dynamically
    markdown_body = "### ⚠️ KubeGuard Security Audit: FAILED\n\n"
    markdown_body += "| Workload Target | Policy Block | Risk Rating | Remediation Requirement |\n"
    markdown_body += "| :--- | :--- | :--- | :--- |\n"
    
    for v in violations:
        markdown_body += f"| `{v['resource']}` | {v['policy']} | **{v['severity']}** | {v['message']} |\n"
        
    print(f"[GITHUB COMMENT POSTED ON PR #{pr_number}]:\n{markdown_body}")

```

### Step 5: Secure the Execution Context (`Dockerfile`)

Finish up the lifecycle pipeline by writing a multi-stage Docker build config that locks down your operational runtime environment.

```dockerfile
# Stage 1: Build dependencies cleanly
FROM python:3.11-alpine AS builder
WORKDIR /app
RUN apk add --no-cache gcc musl-dev libffi-dev
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Hardened runtime environment 
FROM python:3.11-alpine
WORKDIR /app

# Create a non-privileged system service user context
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Retrieve installed library wheels from the builder environment
COPY --from=builder /root/.local /home/appuser/.local
COPY ./src ./src

# Apply absolute ownership access control structures 
RUN chown -R appuser:appgroup /app
USER appuser
ENV PATH=/home/appuser/.local/bin:$PATH

EXPOSE 8080
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]

```

---

## 🚀 Scenarios to Test Your Project Locally

Once you assemble the source scripts, you don't need a public domain or cloud cluster immediately to verify the service logic. Test your work locally using these simulation steps:

1. **Verify Engine Core Logic:** Execute your unit tests via your terminal interface using `pytest tests/` to confirm that the dictionary filters successfully isolate bad manifest definitions from secure ones.
2. **Simulate Live Network Requests:** Fire up your local web server by running `uvicorn src.main:app --port 8080`.
3. **Trigger Ingestion Hooks:** Use a standard API client tool (like `curl` or Postman) to send a sample mock GitHub JSON structure directly to your active endpoint (`http://localhost:8080/v1/gatekeeper/validate`). Look at your terminal logs to verify that the app caught the request asynchronously and that the markdown processing logic compiled perfectly.
