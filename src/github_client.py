from fastapi import Request, BackgroundTasks, HTTPException, Response
from typing import List, Dict, Any  


def get_modified_yaml_files(self, repo_name: str, pr_number: int, git_token: str) -> List[Dict[str, Any]]:
    url = f"{self.api_url}/repos/{repo_name}/pulls/{pr_number}/files"
    headers = {"Authorization": f"token {git_token}"}
    response = Request.get(url, headers=headers)
    if response.status_code == 200:
        files = response.json()
        yaml_files = [file for file in files if file["filename"].endswith((".yaml", ".yml"))]
        return yaml_files
    else:
        raise Exception(f"Failed to fetch modified files: {response.status_code} - {response.text}")
    


def download_raw_content(self, raw_url: str, git_token: str) -> str:
    headers = {"Authorization": f"token {git_token}"}
    response = Request.get(raw_url, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        raise Exception(f"Failed to download raw content: {response.status_code} - {response.text}")
    

def update_commit_status(self, repo_name: str, pr_number: int, state: str, description: str, git_token: str):
    url = f"{self.api_url}/repos/{repo_name}/statuses/{pr_number}"
    headers = {"Authorization": f"token {git_token}"}
    data = {
        "state": state,
        "description": description,
        "context": "KubeGuard Audit"
    }
    response = Request.post(url, headers=headers, json=data)
    if response.status_code != 201:
        raise Exception(f"Failed to update commit status: {response.status_code} - {response.text}")
    
    return response 

    
def post_pr_comment(self, repo_name: str, pr_number: int, comment: str, git_token: str):
    url = f"{self.api_url}/repos/{repo_name}/issues/{pr_number}/comments"
    headers = {"Authorization": f"token {git_token}"}
    data = {"body": comment}
    response = Request.post(url, headers=headers, json=data)
    if response.status_code != 201:
        raise Exception(f"Failed to post PR comment: {response.status_code} - {response.text}")
    
    return response
