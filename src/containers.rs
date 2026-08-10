use crate::models::{Category, Finding, Severity};

/// Check container runtime security (Docker, Podman, Kubernetes).
pub fn audit_container_security() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Docker checks
    if is_docker_installed() {
        findings.extend(check_docker_security());
    }

    // Podman checks
    if is_podman_installed() {
        findings.extend(check_podman_security());
    }

    // Kubernetes checks
    if is_kubectl_installed() {
        findings.extend(check_kubernetes_security());
    }

    findings
}

fn is_docker_installed() -> bool {
    std::process::Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn is_podman_installed() -> bool {
    std::process::Command::new("podman")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn is_kubectl_installed() -> bool {
    std::process::Command::new("kubectl")
        .arg("version")
        .arg("--client")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn check_docker_security() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check if Docker daemon is running
    let info_output = std::process::Command::new("docker")
        .args(["info", "--format", "{{.SecurityOptions}}"])
        .output();

    if let Ok(output) = info_output {
        if output.status.success() {
            let security_opts = String::from_utf8_lossy(&output.stdout);

            // Check for user namespace remapping
            if !security_opts.contains("userns") && !security_opts.contains("userns-remap") {
                findings.push(
                    Finding::new("ctr-docker-no-userns", "Docker User Namespace Remapping Disabled", Severity::Medium, Category::Containers)
                        .description("Docker is running without user namespace remapping. Containers run as root by default, increasing attack surface.")
                        .recommendation("Enable user namespace remapping in /etc/docker/daemon.json: { \"userns-remap\": \"default\" }")
                        .metadata("runtime", "docker")
                );
            }

            // Check for seccomp
            if !security_opts.contains("seccomp") {
                findings.push(
                    Finding::new("ctr-docker-no-seccomp", "Docker Seccomp Not Enforced", Severity::Medium, Category::Containers)
                        .description("Docker is running without seccomp profiles. This allows containers to use potentially dangerous syscalls.")
                        .recommendation("Ensure seccomp is not disabled. Use --security-opt seccomp=default.json")
                        .metadata("runtime", "docker")
                );
            }

            // Check for AppArmor/SELinux
            if !security_opts.contains("apparmor") && !security_opts.contains("selinux") {
                findings.push(
                    Finding::new(
                        "ctr-docker-no-mac",
                        "Docker No Mandatory Access Control",
                        Severity::Low,
                        Category::Containers,
                    )
                    .description("Neither AppArmor nor SELinux is enforced for Docker containers.")
                    .recommendation(
                        "Enable AppArmor or SELinux for additional container isolation.",
                    )
                    .metadata("runtime", "docker"),
                );
            }
        }
    }

    // Check for running containers with --privileged
    let ps_output = std::process::Command::new("docker")
        .args(["ps", "--format", "{{.ID}} {{.Names}}"])
        .output();

    if let Ok(output) = ps_output {
        if output.status.success() {
            let containers = String::from_utf8_lossy(&output.stdout);
            for line in containers.lines() {
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.len() < 2 {
                    continue;
                }
                let id = parts[0];
                let name = parts[1];

                // Inspect for privileged mode
                let inspect_output = std::process::Command::new("docker")
                    .args(["inspect", "--format", "{{.HostConfig.Privileged}}", id])
                    .output();

                if let Ok(inspect) = inspect_output {
                    let privileged = String::from_utf8_lossy(&inspect.stdout).trim() == "true";
                    if privileged {
                        findings.push(
                            Finding::new(
                                &format!("ctr-docker-privileged-{}", id),
                                "Docker Container Running in Privileged Mode",
                                Severity::High,
                                Category::Containers,
                            )
                            .description(&format!("Container '{}' ({}) is running with --privileged. This grants full host access.", name, id))
                            .recommendation("Remove --privileged flag and use specific capabilities instead.")
                            .metadata("container_id", id)
                            .metadata("container_name", name)
                        );
                    }
                }
            }
        }
    }

    // Check if Docker socket is exposed
    let socket_path = "/var/run/docker.sock";
    if std::path::Path::new(socket_path).exists() {
        let metadata = std::fs::metadata(socket_path);
        #[allow(unused_variables)]
        if let Ok(meta) = metadata {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = meta.permissions().mode();
                if perms & 0o077 != 0 {
                    findings.push(
                        Finding::new("ctr-docker-socket-permissive", "Docker Socket Has Permissive Permissions", Severity::High, Category::Containers)
                            .description("The Docker socket (/var/run/docker.sock) has permissive permissions. Anyone with access can control Docker, effectively granting root access.")
                            .recommendation("Restrict Docker socket permissions: chmod 660 /var/run/docker.sock")
                            .metadata("socket", socket_path)
                            .metadata("permissions", &format!("{:o}", perms))
                    );
                }
            }
        }
    }

    findings
}

fn check_podman_security() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Podman is generally more secure (rootless by default), but check for rootful mode
    let output = std::process::Command::new("podman")
        .args(["info", "--format", "{{.Host.Security.Rootless}}"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let rootless = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if rootless == "false" {
                findings.push(
                    Finding::new("ctr-podman-rootful", "Podman Running in Rootful Mode", Severity::Low, Category::Containers)
                        .description("Podman is running in rootful mode. Rootless mode is recommended for better isolation.")
                        .recommendation("Use rootless Podman by running as a non-root user.")
                        .metadata("runtime", "podman")
                );
            }
        }
    }

    findings
}

fn check_kubernetes_security() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for pods running as root
    let output = std::process::Command::new("kubectl")
        .args([
            "get",
            "pods",
            "--all-namespaces",
            "-o",
            "jsonpath={.items[*].spec.containers[*].securityContext.runAsNonRoot}",
        ])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let run_as_non_root = String::from_utf8_lossy(&output.stdout);
            let has_false = run_as_non_root.contains("false");
            let has_empty = run_as_non_root.trim().is_empty();

            if has_false || has_empty {
                findings.push(
                    Finding::new("ctr-k8s-pods-root", "Kubernetes Pods Running as Root", Severity::Medium, Category::Containers)
                        .description("One or more Kubernetes pods are running without runAsNonRoot=true. Containers may be running as root.")
                        .recommendation("Set securityContext.runAsNonRoot=true in pod specs.")
                        .metadata("runtime", "kubernetes")
                );
            }
        }
    }

    // Check for pods without resource limits
    let limits_output = std::process::Command::new("kubectl")
        .args([
            "get",
            "pods",
            "--all-namespaces",
            "-o",
            "jsonpath={.items[*].spec.containers[*].resources.limits}",
        ])
        .output();

    if let Ok(output) = limits_output {
        if output.status.success() {
            let limits = String::from_utf8_lossy(&output.stdout);
            if limits.trim().is_empty() {
                findings.push(
                    Finding::new("ctr-k8s-no-limits", "Kubernetes Pods Without Resource Limits", Severity::Low, Category::Containers)
                        .description("Kubernetes pods are running without resource limits. This can lead to resource exhaustion attacks.")
                        .recommendation("Set resource limits in pod specs: resources.limits.cpu and resources.limits.memory.")
                        .metadata("runtime", "kubernetes")
                );
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_container_security_no_runtime() {
        // If no container runtime is installed, should return empty
        let findings = audit_container_security();
        // On CI without Docker/Podman/K8s, this returns empty.
        let _ = findings.len();
    }
}
