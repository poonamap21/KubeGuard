# KubeGuard
An event-driven Python microservice that automatically audits Kubernetes manifests and Helm charts for security misconfigurations and CVEs before they hit production.

## Features
- **Automated Auditing**: KubeGuard continuously monitors your Git repositories for new Kubernetes manifests and Helm charts, automatically auditing them for security issues.

- **Comprehensive Security Checks**: KubeGuard checks for common misconfigurations such as running containers as root, missing resource limits, and exposed secrets. It also integrates with vulnerability databases to identify CVEs in container images.
- **Real-time Notifications**: If KubeGuard detects any security issues, it sends real-time notifications to your team via email or Slack, allowing you to address them before deployment.
- **Customizable Rules**: You can customize the security rules and policies that KubeGuard
uses for auditing, tailoring it to your organization's specific security requirements.
- **Integration with CI/CD**: KubeGuard can be integrated into your CI/CD pipeline, ensuring that all Kubernetes manifests and Helm charts are audited as part of your deployment process.
## Installation

docker build -t kubeguard:latest .  
docker run -d -p 8081:8000 --name kubeguard kubeguard:latest

Now open the browser and navigate to http://localhost:8081/docs to access the interactive API documentation provided by FastAPI.

## Usage
Once KubeGuard is running, you can access the API at `http://localhost:8081`. You can use the following endpoints:
- `POST /audit/manifest`: Audit a Kubernetes manifest for security issues.  
- `POST /audit/helm`: Audit a Helm chart for security issues.
- `GET /reports`: Retrieve audit reports for previously scanned manifests and charts.

## Contributing
Contributions to KubeGuard are welcome! Please fork the repository and submit a pull request with
your changes. Make sure to include tests for any new features or bug fixes.

## License
KubeGuard is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

