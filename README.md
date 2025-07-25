
# Kubernetes The Hard Way Setup

This project demonstrates the manual setup of a Kubernetes cluster using the "Kubernetes The Hard Way" guide by Kelsey Hightower. The repository documents the process of configuring a Kubernetes cluster from scratch on Ubuntu 24.10 servers, highlighting hands-on experience with Kubernetes components, networking, and SSH key-based authentication for secure access.

## Project Overview

The goal of this project was to set up a Kubernetes cluster manually, without relying on automated tools like kubeadm, to gain a deep understanding of Kubernetes architecture and components. The setup includes one control plane node and two worker nodes, configured on DigitalOcean droplets running Ubuntu 24.10.

## Prerequisites

- **Operating System**: Ubuntu 24.10 (GNU/Linux 6.11.0-9-generic x86_64)
- **Nodes**:
  - Control Plane: `165.227.200.17` (server.kubernetes.local)
  - Worker Node 0: `143.244.144.193` (node-0.kubernetes.local, subnet: 10.200.0.0/24)
  - Worker Node 1: `159.223.186.53` (node-1.kubernetes.local, subnet: 10.200.1.0/24)
- **Tools**: `wget`, `curl`, `vim`, `openssl`, `git`
- **SSH Key**: RSA key (`id_rsa_personal`) for secure access
- **Repository**: Cloned from `https://github.com/kelseyhightower/kubernetes-the-hard-way`

## Setup Steps

### 1. Environment Setup

- Connected to a DigitalOcean droplet (`157.245.204.83`) via SSH using a personal RSA key.
- Updated the package list and installed required tools:
  ```bash
  apt-get update
  apt-get -y install wget curl vim openssl git
  ```
- Cloned the "Kubernetes The Hard Way" repository:
  ```bash
  git clone --depth 1 https://github.com/kelseyhightower/kubernetes-the-hard-way.git
  ```

### 2. Downloading Kubernetes Binaries

- Retrieved Kubernetes binaries and dependencies for `amd64` architecture using `wget`:
  ```bash
  wget -q --show-progress --https-only --timestamping -P downloads -i downloads-amd64.txt
  ```
- Downloaded components:
  - `kubectl`, `kube-apiserver`, `kube-controller-manager`, `kube-scheduler`, `kube-proxy`, `kubelet`
  - `crictl-v1.32.0`, `runc.amd64`, `cni-plugins-linux-amd64-v1.6.2`, `containerd-2.1.0-beta.0`, `etcd-v3.6.0-rc.3`

### 3. Organizing Binaries

- Created directories for organizing binaries:
  ```bash
  mkdir -p downloads/{client,cni-plugins,controller,worker}
  ```
- Extracted and moved binaries to appropriate directories:
  ```bash
  tar -xvf downloads/crictl-v1.32.0-linux-amd64.tar.gz -C downloads/worker/
  tar -xvf downloads/containerd-2.1.0-beta.0-linux-amd64.tar.gz --strip-components 1 -C downloads/worker/
  tar -xvf downloads/cni-plugins-linux-amd64-v1.6.2.tgz -C downloads/cni-plugins/
  tar -xvf downloads/etcd-v3.6.0-rc.3-linux-amd64.tar.gz -C downloads/ --strip-components 1 etcd-v3.6.0-rc.3-linux-amd64/etcdctl etcd-v3.6.0-rc.3-linux-amd64/etcd
  mv downloads/{etcdctl,kubectl} downloads/client/
  mv downloads/{etcd,kube-apiserver,kube-controller-manager,kube-scheduler} downloads/controller/
  mv downloads/{kubelet,kube-proxy} downloads/worker/
  mv downloads/runc.amd64 downloads/worker/runc
  ```
- Set executable permissions and copied `kubectl` to `/usr/local/bin/`:
  ```bash
  chmod +x downloads/{client,cni-plugins,controller,worker}/*
  cp downloads/client/kubectl /usr/local/bin/
  ```
- Verified `kubectl` installation:
  ```bash
  kubectl version --client
  ```

### 4. Node Configuration

- Created a `machine.txt` file to define the cluster nodes:
  ```bash
  165.227.200.17 server.kubernetes.local server
  143.244.144.193 node-0.kubernetes.local node-0 10.200.0.0/24
  159.223.186.53 node-1.kubernetes.local node-1 10.200.1.0/24
  ```
- Enabled root login on each node by modifying SSH configurations:
  ```bash
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
  systemctl restart ssh
  ```
- Configured password authentication on worker nodes (`143.244.144.193`, `159.223.186.53`) by editing `/etc/ssh/sshd_config.d/50-cloud-init.conf` and restarting the SSH service:
  ```bash
  sudo nano /etc/ssh/sshd_config.d/50-cloud-init.conf
  sudo systemctl daemon-reload
  sudo systemctl restart ssh.socket
  ```

### 5. SSH Key Distribution

- Generated an ED25519 key pair on the control node (`157.245.204.83`):
  ```bash
  ssh-keygen
  ```
- Copied the public key to all nodes:
  ```bash
  while read IP FQDN HOST SUBNET; do
    ssh-copy-id root@${IP}
  done < machine.txt
  ```
- Verified SSH connectivity:
  ```bash
  while read IP FQDN HOST SUBNET; do
    ssh -n root@${IP} hostname
  done < machine.txt
  ```
- Output:
  ```bash
  k8s-server
  k8s-node-0
  k8s-node-1
  ```

### 6. Hostname and Hosts File Configuration

- Configured hostnames and updated `/etc/hosts` on each node:
  ```bash
  while read IP FQDN HOST SUBNET; do
    CMD="sed -i 's/^127.0.1.1.*/127.0.1.1\t${FQDN} ${HOST}/' /etc/hosts"
    ssh -n root@${IP} "$CMD"
    ssh -n root@${IP} hostnamectl set-hostname ${HOST}
    ssh -n root@${IP} systemctl restart systemd-hostnamed
  done < machine.txt
  ```
- Verified fully qualified domain names (FQDNs):
  ```bash
  while read IP FQDN HOST SUBNET; do
    ssh -n root@${IP} hostname --fqdn
  done < machine.txt
  ```
- Output:
  ```bash
  server.kubernetes.local
  node-0.kubernetes.local
  node-1.kubernetes.local
  ```
- Created a `hosts` file for cluster nodes:
  ```bash
  echo "" > hosts
  echo "# Kubernetes The Hard Way" >> hosts
  while read IP FQDN HOST SUBNET; do
    ENTRY="${IP} ${FQDN} ${HOST}"
    echo $ENTRY >> hosts
  done < machine.txt
  ```
- Contents of `hosts` file:
  ```bash
  # Kubernetes The Hard Way
  165.227.200.17 server.kubernetes.local server
  143.244.144.193 node-0.kubernetes.local node-0
  159.223.186.53 node-1.kubernetes.local node-1
  ```
- Appended `hosts` file to local `/etc/hosts`:
  ```bash
  cat hosts >> /etc/hosts
  ```
- Distributed `hosts` file to all nodes and appended to their `/etc/hosts`:
  ```bash
  while read IP FQDN HOST SUBNET; do
    scp hosts root@${HOST}:~/
    ssh -n root@${HOST} "cat hosts >> /etc/hosts"
  done < machine.txt
  ```
- Verified hostname resolution on each node:
  ```bash
  for host in server node-0 node-1; do
    ssh root@${host} hostname
  done
  ```
- Output:
  ```bash
  server
  node-0
  node-1
  ```

### 7. Certificate Authority and Certificate Generation

- Created a Certificate Authority (CA) configuration file `ca.conf` for generating certificates:
  ```bash
  [req]
  distinguished_name = req_distinguished_name
  prompt             = no
  x509_extensions    = ca_x509_extensions

  [ca_x509_extensions]
  basicConstraints = CA:TRUE
  keyUsage         = cRLSign, keyCertSign

  [req_distinguished_name]
  C   = US
  ST  = Washington
  L   = Seattle
  CN  = CA

  [admin]
  distinguished_name = admin_distinguished_name
  prompt             = no
  req_extensions     = default_req_extensions

  [admin_distinguished_name]
  CN = admin
  O  = system:masters

  [service-accounts]
  distinguished_name = service-accounts_distinguished_name
  prompt             = no
  req_extensions     = default_req_extensions

  [service-accounts_distinguished_name]
  CN = service-accounts

  [node-0]
  distinguished_name = node-0_distinguished_name
  prompt             = no
  req_extensions     = node-0_req_extensions

  [node-0_req_extensions]
  basicConstraints     = CA:FALSE
  extendedKeyUsage     = clientAuth, serverAuth
  keyUsage             = critical, digitalSignature, keyEncipherment
  nsCertType           = client
  nsComment            = "Node-0 Certificate"
  subjectAltName       = DNS:node-0, IP:127.0.0.1
  subjectKeyIdentifier = hash

  [node-0_distinguished_name]
  CN = system:node:node-0
  O  = system:nodes
  C  = US
  ST = Washington
  L  = Seattle

  [node-1]
  distinguished_name = node-1_distinguished_name
  prompt             = no
  req_extensions     = node-1_req_extensions

  [node-1_req_extensions]
  basicConstraints     = CA:FALSE
  extendedKeyUsage     = clientAuth, serverAuth
  keyUsage             = critical, digitalSignature, keyEncipherment
  nsCertType           = client
  nsComment            = "Node-1 Certificate"
  subjectAltName       = DNS:node-1, IP:127.0.0.1
  subjectKeyIdentifier = hash

  [node-1_distinguished_name]
  CN = system:node:node-1
  O  = system:nodes
  C  = US
  ST = Washington
  L  = Seattle

  [kube-proxy]
  distinguished_name = kube-proxy_distinguished_name
  prompt             = no
  req_extensions     = kube-proxy_req_extensions

  [kube-proxy_req_extensions]
  basicConstraints     = CA:FALSE
  extendedKeyUsage     = clientAuth, serverAuth
  keyUsage             = critical, digitalSignature, keyEncipherment
  nsCertType           = client
  nsComment            = "Kube Proxy Certificate"
  subjectAltName       = DNS:kube-proxy, IP:127.0.0.1
  subjectKeyIdentifier = hash

  [kube-proxy_distinguished_name]
  CN = system:kube-proxy
  O  = system:node-proxier
  C  = US
  ST = Washington
  L  = Seattle

  [kube-controller-manager]
  distinguished_name = kube-controller-manager_distinguished_name
  prompt             = no
  req_extensions     = kube-controller-manager_req_extensions

  [kube-controller-manager_req_extensions]
  basicConstraints     = CA:FALSE
  extendedKeyUsage     = clientAuth, serverAuth
  keyUsage             = critical, digitalSignature, keyEncipherment
  nsCertType           = client
  nsComment            = "Kube Controller Manager Certificate"
  subjectAltName       = DNS:kube-controller-manager, IP:127.0.0.1
  subjectKeyIdentifier = hash

  [kube-controller-manager_distinguished_name]
  CN = system:kube-controller-manager
  O  = system:kube-controller-manager
  C  = US
  ST = Washington
  L  = Seattle

  [kube-scheduler]
  distinguished_name = kube-scheduler_distinguished_name
  prompt             = no
  req_extensions     = kube-scheduler_req_extensions

  [kube-scheduler_req_extensions]
  basicConstraints     = CA:FALSE
  extendedKeyUsage     = clientAuth, serverAuth
  keyUsage             = critical, digitalSignature, keyEncipherment
  nsCertType           = client
  nsComment            = "Kube Scheduler Certificate"
  subjectAltName       = DNS:kube-scheduler, IP:127.0.0.1
  subjectKeyIdentifier = hash

  [kube-scheduler_distinguished_name]
  CN = system:kube-scheduler
  O  = system:system:kube-scheduler
  C  = US
  ST = Washington
  L  = Seattle

  [kube-api-server]
  distinguished_name = kube-api-server_distinguished_name
  prompt             = no
  req_extensions     = kube-api-server_req_extensions

  [kube-api-server_req_extensions]
  basicConstraints     = CA:FALSE
  extendedKeyUsage     = clientAuth, serverAuth
  keyUsage             = critical, digitalSignature, keyEncipherment
  nsCertType           = client, server
  nsComment            = "Kube API Server Certificate"
  subjectAltName       = @kube-api-server_alt_names
  subjectKeyIdentifier = hash

  [kube-api-server_alt_names]
  IP.0  = 127.0.0.1
  IP.1  = 10.32.0.1
  DNS.0 = kubernetes
  DNS.1 = kubernetes.default
  DNS.2 = kubernetes.default.svc
  DNS.3 = kubernetes.default.svc.cluster
  DNS.4 = kubernetes.svc.cluster.local
  DNS.5 = server.kubernetes.local
  DNS.6 = api-server.kubernetes.local

  [kube-api-server_distinguished_name]
  CN = kubernetes
  C  = US
  ST = Washington
  L  = Seattle

  [default_req_extensions]
  basicConstraints     = CA:FALSE
  extendedKeyUsage     = clientAuth
  keyUsage             = critical, digitalSignature, keyEncipherment
  nsCertType           = client
  nsComment            = "Admin Client Certificate"
  subjectKeyIdentifier = hash
  ```
- Generated CA key and certificate:
  ```bash
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -sha512 -noenc -key ca.key -days 3653 -config ca.conf -out ca.crt
  ```
- Generated certificates for cluster components:
  ```bash
  certs=("admin" "node-0" "node-1" "kube-proxy" "kube-scheduler" "kube-controller-manager" "kube-api-server" "service-accounts")
  for i in ${certs[*]}; do
    openssl genrsa -out "${i}.key" 4096
    openssl req -new -key "${i}.key" -sha256 -config "ca.conf" -section ${i} -out "${i}.csr"
    openssl x509 -req -days 3653 -in "${i}.csr" -copy_extensions copyall -sha256 -CA "ca.crt" -CAkey "ca.key" -CAcreateserial -out "${i}.crt"
  done
  ```

### 8. Troubleshooting

- Encountered `Permission denied (publickey)` errors during SSH key distribution.
- Resolved by:
  - Enabling password authentication temporarily on worker nodes.
  - Setting root passwords on worker nodes:
    ```bash
    sudo passwd root
    ```
  - Re-running `ssh-copy-id` to install the public key.
- Verified SSH service status and configuration:
  ```bash
  sudo systemctl status ssh.service
  sudo sshd -t
  ```
- Experienced `client_loop: send disconnect: Broken pipe` during SSH session.
  - Likely caused by network instability or idle timeout. Re-established connection using:
    ```bash
    ssh -i ~/.ssh/id_rsa_personal root@157.245.204.83
    ```
- Encountered `nginx: invalid option: "-"` when checking NGINX version.
  - Corrected by using `nginx -version` instead of `nginx --version`.
  - Confirmed NGINX version: `nginx/1.26.0 (Ubuntu)`.
- Encountered `ca.crt: command not found` after generating CA certificate.
  - This was due to attempting to execute `ca.crt ca.key` as a command. Resolved by verifying file creation with:
    ```bash
    ls
    ```
  - Confirmed presence of `ca.crt` and `ca.key`.

## Challenges Faced

- **SSH Authentication Issues**: Initial attempts to copy SSH keys failed due to `publickey` authentication restrictions. Resolved by enabling `PermitRootLogin` and temporarily enabling password authentication.
- **File Not Found Errors**: Incorrect file name (`machines.txt` vs. `machine.txt`) caused script failures, fixed by correcting the file name in commands.
- **Service Restart Issues**: Attempted to restart `sshd` service but found it was managed by `ssh.socket`. Used `systemctl restart ssh.socket` to apply changes.
- **Network Instability**: Broken pipe errors during SSH sessions were resolved by reconnecting.
- **Command Syntax Errors**: Incorrect NGINX version command syntax was fixed by using the correct flag.
- **Certificate Generation Error**: Attempting to run `ca.crt ca.key` as a command caused an error. Resolved by recognizing it was not a command but a file listing issue.

## Next Steps

- Complete the remaining steps of the "Kubernetes The Hard Way" guide, including:
  - Configuring the control plane components (`kube-apiserver`, `kube-controller-manager`, `kube-scheduler`, `etcd`).
  - Setting up worker nodes with `kubelet`, `kube-proxy`, and `containerd`.
  - Configuring networking with CNI plugins.
  - Deploying a sample application to verify cluster functionality.
- Push the repository to GitHub for inclusion in the CV.
- Update this README with additional setup details and outcomes.

## Repository

This project is hosted on GitHub: [Insert GitHub Repository URL]

## Skills Demonstrated

- Kubernetes cluster setup and configuration
- Linux system administration (Ubuntu 24.10)
- SSH key management and secure access configuration
- Package management and binary installation
- Hostname and network configuration
- Certificate Authority setup and certificate generation for Kubernetes components
- Troubleshooting SSH connectivity, command syntax, and certificate generation issues
- Scripting for automation (e.g., `while` loops for SSH key distribution, hosts file management, and certificate generation)
