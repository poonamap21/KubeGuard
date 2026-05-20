from fastapi import FastAPI, HTTPException, Request, Response, Status, BackgroundTasks
from . import github_client
from . import parser

app = FastAPI(
    title ="KubeGuard API",
    description="API for KubeGuard, a Kubernetes security tool",
    version="1.0.0",
)
@app.get("/health")
async def health_check():
    
    return {"status": "healthy"}   

@app.post("/gatekeeper/validate")
async def validate(request: Request, background_tasks: BackgroundTasks):
    try:
        payload = await request.json()
        # Placeholder for validation logic
        # In a real implementation, this would involve complex logic to validate the Kubernetes resource
        
        if "pull_request" in payload:
            action = payload["pull_request"]["action"]
            if action not in ["opened", "synchronize", "reopened"]:
                return {"status": "skipped", "reason": f"Action '{action}' does not trigger audit"}
            else:
                repo_name = payload["repository"]["full_name"]
                pr_number = payload["pull_request"]["number"]
                pull_request_sha = payload["pull_request"]["head"]["sha"]
                git_token = request.headers.get("X-Git-Token") 
    
                if not git_token:
                    return Response(
                        content="Missing authentication token mapping", 
                        status_code=Status.HTTP_401_UNAUTHORIZED
                    )
                background_tasks.add_task(
                    process_pipeline_audit, 
                    git_token, 
                    repo_name, 
                    pr_number, 
                    pull_request_sha
                )
                # get the data
        return Response(content="Validation request received", status_code=Status.HTTP_202_ACCEPTED)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) 


async def process_pipeline_audit(git_token: str, repo_name: str, pr_number: int, pull_request_sha: str):
    # Placeholder for the actual audit logic
    # This function would perform the necessary checks and audits on the pull request
    print(f"Processing pipeline audit for {repo_name} PR #{pr_number} with SHA {pull_request_sha}")
    all_findings = []
    # Simulate time-consuming audit process
    yaml_files = github_client.get_modified_yaml_files(repo_name, pr_number, git_token)
    for file_info in yaml_files:
        raw_yaml_text = github_client.download_raw_content(file_info["raw_url"], git_token)
        # Pass the text to your rule engine
        file_violations = parser.audit_manifest(raw_yaml_text, file_info["filename"])
        all_findings.extend(file_violations)
    
    if all_findings:
        github_client.update_commit_status(repo_name, pull_request_sha, "failure", "Violations found", git_token)
        github_client.post_pr_comment(repo_name, pr_number, all_findings, git_token)
    else:
        github_client.update_commit_status(repo_name, pull_request_sha, "success", "All governance checks passed", git_token)


