

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
- **Tools**: `wget`, `curl`, `vim`, `openssl`, `git`, `socat`, `conntrack`, `ipset`, `kmod`
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
  mv downloads/{etcd,kube-apiserver,kue-controller-manager,kube-scheduler} downloads/controller/
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

### 8. Kubeconfig and Certificate Distribution

- Distributed certificates to worker nodes (`node-0` and `node-1`):
  ```bash
  for host in node-0 node-1; do
    ssh root@${host} mkdir /var/lib/kubelet/
    scp ca.crt root@${host}:/var/lib/kubelet/
    scp ${host}.crt root@${host}:/var/lib/kubelet/kubelet.crt
    scp ${host}.key root@${host}:/var/lib/kubelet/kubelet.key
  done
  ```
- Distributed certificates to the control plane node (`server`):
  ```bash
  scp ca.key ca.crt kube-api-server.key kube-api-server.crt service-accounts.key service-accounts.crt root@server:~/
  ```
- Configured kubeconfig files for worker nodes (`node-0`, `node-1`):
  ```bash
  for host in node-0 node-1; do
    kubectl config set-cluster kubernetes-the-hard-way \
      --certificate-authority=ca.crt \
      --embed-certs=true \
      --server=https://server.kubernetes.local:6443 \
      --kubeconfig=${host}.kubeconfig
    kubectl config set-credentials system:node:${host} \
      --client-certificate=${host}.crt \
      --client-key=${host}.key \
      --embed-certs=true \
      --kubeconfig=${host}.kubeconfig
    kubectl config set-context default \
      --cluster=kubernetes-the-hard-way \
      --user=system:node:${host} \
      --kubeconfig=${host}.kubeconfig
    kubectl config use-context default \
      --kubeconfig=${host}.kubeconfig
  done
  ```
- Configured kubeconfig for `kube-proxy`:
  ```bash
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=https://server.kubernetes.local:6443 \
    --kubeconfig=kube-proxy.kubeconfig
  kubectl config set-credentials system:kube-proxy \
    --client-certificate=kube-proxy.crt \
    --client-key=kube-proxy.key \
    --embed-certs=true \
    --kubeconfig=kube-proxy.kubeconfig
  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-proxy \
    --kubeconfig=kube-proxy.kubeconfig
  kubectl config use-context default \
    --kubeconfig=kube-proxy.kubeconfig
  ```
- Configured kubeconfig for `kube-controller-manager`:
  ```bash
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=https://server.kubernetes.local:6443 \
    --kubeconfig=kube-controller-manager.kubeconfig
  kubectl config set-credentials system:kube-controller-manager \
    --client-certificate=kube-controller-manager.crt \
    --client-key=kube-controller-manager.key \
    --embed-certs=true \
    --kubeconfig=kube-controller-manager.kubeconfig
  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-controller-manager \
    --kubeconfig=kube-controller-manager.kubeconfig
  kubectl config use-context default \
    --kubeconfig=kube-controller-manager.kubeconfig
  ```
- Configured kubeconfig for `kube-scheduler`:
  ```bash
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=https://server.kubernetes.local:6443 \
    --kubeconfig=kube-scheduler.kubeconfig
  kubectl config set-credentials system:kube-scheduler \
    --client-certificate=kube-scheduler.crt \
    --client-key=kube-scheduler.key \
    --embed-certs=true \
    --kubeconfig=kube-scheduler.kubeconfig
  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-scheduler \
    --kubeconfig=kube-scheduler.kubeconfig
  kubectl config use-context default \
    --kubeconfig=kube-scheduler.kubeconfig
  ```
- Configured kubeconfig for `admin`:
  ```bash
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=https://127.0.0.1:6443 \
    --kubeconfig=admin.kubeconfig
  kubectl config set-credentials admin \
    --client-certificate=admin.crt \
    --client-key=admin.key \
    --embed-certs=true \
    --kubeconfig=admin.kubeconfig
  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=admin \
    --kubeconfig=admin.kubeconfig
  kubectl config use-context default \
    --kubeconfig=admin.kubeconfig
  ```
- Created directories and distributed kubeconfig files to worker nodes:
  ```bash
  for host in node-0 node-1; do
    ssh root@${host} "mkdir -p /var/lib/{kube-proxy,kubelet}"
    scp kube-proxy.kubeconfig root@${host}:/var/lib/kube-proxy/kubeconfig
    scp ${host}.kubeconfig root@${host}:/var/lib/kubelet/kubeconfig
  done
  ```
- Distributed kubeconfig files to the control plane node:
  ```bash
  scp admin.kubeconfig kube-controller-manager.kubeconfig kube-scheduler.kubeconfig root@server:~/
  ```

### 9. Encryption Configuration and etcd Setup

- Generated an encryption key for Kubernetes secrets:
  ```bash
  export ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)
  ```
- Created an encryption configuration file from a template:
  ```bash
  envsubst < configs/encryption-config.yaml > encryption-config.yaml
  ```
- Contents of `encryption-config.yaml`:
  ```bash
  kind: EncryptionConfiguration
  apiVersion: apiserver.config.k8s.io/v1
  resources:
    - resources:
        - secrets
      providers:
        - aescbc:
            keys:
              - name: key1
                secret: TlbGBevzNRzsREuMeSpX8wZs1JBnUWHmy55s9G1hZAU=
        - identity: {}
  ```
- Copied the encryption configuration to the control plane node:
  ```bash
  scp encryption-config.yaml root@server:~/
  ```
- Copied `etcd` binary, `etcdctl` binary, and `etcd` service file to the control plane node:
  ```bash
  scp downloads/controller/etcd downloads/client/etcdctl units/etcd.service root@server:~/
  ```
- On the control plane node (`server`), moved `etcd` and `etcdctl` binaries to `/usr/local/bin/`:
  ```bash
  mv etcd etcdctl /usr/local/bin/
  ```
- Created directories for `etcd` and set permissions:
  ```bash
  mkdir -p /etc/etcd /var/lib/etcd
  chmod 700 /var/lib/etcd
  ```
- Copied certificates to the `etcd` configuration directory:
  ```bash
  cp ca.crt kube-api-server.key kube-api-server.crt /etc/etcd/
  ```
- Moved `etcd` service file to the systemd directory and started the service:
  ```bash
  mv etcd.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable etcd
  systemctl start etcd
  ```
- Verified `etcd` status:
  ```bash
  etcdctl member list
  ```
- Output:
  ```bash
  6702b0a34e2cfd39, started, controller, http://127.0.0.1:2380, http://127.0.0.1:2379, false
  ```

### 10. Control Plane Setup

- Copied control plane binaries and configuration files to the control plane node:
  ```bash
  scp downloads/controller/kube-apiserver \
    downloads/controller/kube-controller-manager \
    downloads/controller/kube-scheduler \
    downloads/client/kubectl \
    units/kube-apiserver.service \
    units/kube-controller-manager.service \
    units/kube-scheduler.service \
    configs/kube-scheduler.yaml \
    configs/kube-apiserver-to-kubelet.yaml \
    root@server:~/
  ```
- On the control plane node (`server`), moved binaries to `/usr/local/bin/`:
  ```bash
  mv kube-apiserver kube-controller-manager kube-scheduler kubectl /usr/local/bin/
  ```
- Created directories and moved certificates and encryption configuration:
  ```bash
  mkdir -p /var/lib/kubernetes/
  mv ca.crt ca.key kube-api-server.key kube-api-server.crt service-accounts.key service-accounts.crt encryption-config.yaml /var/lib/kubernetes/
  ```
- Moved service and configuration files to appropriate directories:
  ```bash
  mv kube-apiserver.service /etc/systemd/system/
  mv kube-controller-manager.kubeconfig /var/lib/kubernetes/
  mv kube-controller-manager.service /etc/systemd/system/
  mv kube-scheduler.kubeconfig /var/lib/kubernetes/
  mv kube-scheduler.yaml /etc/kubernetes/config/
  mv kube-scheduler.service /etc/systemd/system/
  ```
- Created configuration directory:
  ```bash
  mkdir -p /etc/kubernetes/config
  ```
- Enabled and started control plane services:
  ```bash
  systemctl daemon-reload
  systemctl enable kube-apiserver kube-controller-manager kube-scheduler
  systemctl start kube-apiserver kube-controller-manager kube-scheduler
  ```
- Verified `kube-apiserver` status:
  ```bash
  systemctl is-active kube-apiserver
  systemctl status kube-apiserver
  ```
- Output:
  ```bash
  active
  ● kube-apiserver.service - Kubernetes API Server
       Loaded: loaded (/etc/systemd/system/kube-apiserver.service; enabled; preset: enabled)
       Active: active (running) since Sun 2025-08-03 15:02:59 UTC; 34s ago
     Invocation: 97297f349bfd4bd9b894fa77fcfb6ec0
         Docs: https://github.com/kubernetes/kubernetes
     Main PID: 2535696 (kube-apiserver)
        Tasks: 6 (limit: 506)
       Memory: 223.3M (peak: 238.9M)
          CPU: 10.201s
       CGroup: /system.slice/kube-apiserver.service
               └─2535696 /usr/local/bin/kube-apiserver --allow-privileged=true --audit-log-maxage=30 --audit-log-maxbacku>
  ```
- Checked control plane status:
  ```bash
  kubectl cluster-info --kubeconfig admin.kubeconfig
  ```
- Output:
  ```bash
  Kubernetes control plane is running at https://127.0.0.1:6443
  ```
- Applied RBAC permissions for kube-apiserver to kubelet communication:
  ```bash
  kubectl apply -f kube-apiserver-to-kubelet.yaml --kubeconfig admin.kubeconfig
  ```
- Output:
  ```bash
  clusterrole.rbac.authorization.k8s.io/system:kube-apiserver-to-kubelet created
  clusterrolebinding.rbac.authorization.k8s.io/system:kube-apiserver created
  ```
- Verified Kubernetes version:
  ```bash
  curl --cacert ca.crt https://server.kubernetes.local:6443/version
  ```
- Output:
  ```bash
  {
    "major": "1",
    "minor": "32",
    "gitVersion": "v1.32.3",
    "gitCommit": "32cc146f75aad04beaaa245a7157eb35063a9f99",
    "gitTreeState": "clean",
    "buildDate": "2025-03-11T19:52:21Z",
    "goVersion": "go1.23.6",
    "compiler": "gc",
    "platform": "linux/amd64"
  }
  ```

### 11. Worker Node Setup

- For each worker node (`node-0`, `node-1`), generated and distributed CNI and kubelet configuration files:
  ```bash
  for HOST in node-0 node-1; do
    SUBNET=$(grep ${HOST} machine.txt | cut -d " " -f 4)
    sed "s|SUBNET|$SUBNET|g" configs/10-bridge.conf > 10-bridge.conf
    sed "s|SUBNET|$SUBNET|g" configs/kubelet-config.yaml > kubelet-config.yaml
    scp 10-bridge.conf kubelet-config.yaml root@${HOST}:~/
  done
  ```
- Distributed worker node binaries and configuration files:
  ```bash
  for HOST in node-0 node-1; do
    scp downloads/worker/* \
        downloads/client/kubectl \
        configs/99-loopback.conf \
        configs/containerd-config.toml \
        configs/kube-proxy-config.yaml \
        units/containerd.service \
        units/kubelet.service \
        units/kube-proxy.service \
        root@${HOST}:~/
    scp downloads/cni-plugins/* root@${HOST}:~/cni-plugins/
  done
  ```
- On each worker node (`node-0`, `node-1`), installed required packages:
  ```bash
  apt-get update
  apt-get -y install socat conntrack ipset kmod
  ```
- Created necessary directories:
  ```bash
  mkdir -p /etc/cni/net.d /opt/cni/bin /var/lib/kubelet /var/lib/kube-proxy /var/lib/kubernetes /var/run/kubernetes
  ```
- Moved binaries to appropriate locations:
  ```bash
  mv crictl kube-proxy kubelet runc /usr/local/bin/
  mv containerd containerd-shim-runc-v2 containerd-stress /bin/
  mv cni-plugins/* /opt/cni/bin/
  ```
- Configured CNI networking:
  ```bash
  mv 10-bridge.conf 99-loopback.conf /etc/cni/net.d/
  modprobe br-netfilter
  echo "br-netfilter" >> /etc/modules-load.d/modules.conf
  echo "net.bridge.bridge-nf-call-iptables = 1" >> /etc/sysctl.d/kubernetes.conf
  echo "net.bridge.bridge-nf-call-ip6tables = 1" >> /etc/sysctl.d/kubernetes.conf
  sysctl -p /etc/sysctl.d/kubernetes.conf
  ```
- Configured containerd:
  ```bash
  mkdir -p /etc/containerd/
  mv containerd-config.toml /etc/containerd/config.toml
  mv containerd.service /etc/systemd/system/
  ```
- Configured kubelet and kube-proxy:
  ```bash
  mv kubelet-config.yaml /var/lib/kubelet/
  mv kubelet.service /etc/systemd/system/
  mv kube-proxy-config.yaml /var/lib/kube-proxy/
  mv kube-proxy.service /etc/systemd/system/
  ```
- Enabled and started services:
  ```bash
  systemctl daemon-reload
  systemctl enable containerd kubelet kube-proxy
  systemctl start containerd kubelet kube-proxy
  ```
- Verified kubelet status:
  ```bash
  systemctl is-active kubelet
  ```
- Output:
  ```bash
  active
  ```

### 12. Cluster Verification

- Configured local `kubectl` to interact with the cluster:
  ```bash
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=https://server.kubernetes.local:6443
  kubectl config set-credentials admin \
    --client-certificate=admin.crt \
    --client-key=admin.key
  kubectl config set-context kubernetes-the-hard-way \
    --cluster=kubernetes-the-hard-way \
    --user=admin
  kubectl config use-context kubernetes-the-hard-way
  ```
- Verified `kubectl` version and cluster nodes:
  ```bash
  kubectl version
  kubectl get nodes
  ```
- Output:
  ```bash
  Client Version: v1.32.3
  Kustomize Version: v5.5.0
  Server Version: v1.32.3
  NAME     STATUS   ROLES    AGE   VERSION
  node-0   Ready    <none>   68m   v1.32.3
  node-1   Ready    <none>   56m   v1.32.3
  ```
- Verified node status from the control plane:
  ```bash
  ssh root@server "kubectl get nodes --kubeconfig admin.kubeconfig"
  ```
- Output:
  ```bash
  NAME     STATUS   ROLES    AGE   VERSION
  node-0   Ready    <none>   12m   v1.32.3
  node-1   Ready    <none>   33s   v1.32.3
  ```
- Extracted IP addresses and subnets for scripting:
  ```bash
  SERVER_IP=$(grep server machine.txt | cut -d " " -f 1)
  NODE_0_IP=$(grep node-0 machine.txt | cut -d " " -f 1)
  NODE_0_SUBNET=$(grep node-0 machine.txt | cut -d " " -f 4)
  NODE_1_IP=$(grep node-1 machine.txt | cut -d " " -f 1)
  NODE_1_SUBNET=$(grep node-1 machine.txt | cut -d " " -f 4)
  ```

### 13. Troubleshooting

- **SSH Authentication Issues**:
  - Encountered `Permission denied (publickey)` errors during SSH key distribution to `node-1`. Resolved by enabling password authentication temporarily and re-running `ssh-copy-id`.
  - Verified SSH service status and configuration:
    ```bash
    sudo systemctl status ssh.service
    sudo sshd -t
    ```
  - Experienced `client_loop: send disconnect: Broken pipe` during SSH sessions, likely due to network instability or idle timeout. Re-established connection using:
    ```bash
    ssh -i ~/.ssh/id_rsa_personal root@157.245.204.83
    ```
- **File Not Found Errors**:
  - Incorrect file name (`machines.txt` vs. `machine.txt`) caused script failures. Fixed by correcting the file name in commands.
  - Attempted to access `etch.service` instead of `etcd.service`. Corrected by using the proper file name.
- **Service Restart Issues**:
  - Attempted to restart `sshd` service but found it was managed by `ssh.socket`. Used `systemctl restart ssh.socket` to apply changes.
- **Command Syntax Errors**:
  - Encountered `nginx: invalid option: "-"` when checking NGINX version. Corrected by using `nginx -version` instead of `nginx --version`. Confirmed NGINX version: `nginx/1.26.0 (Ubuntu)`.
  - Encountered `ca.crt: command not found` after generating CA certificate. Resolved by verifying file creation with `ls`.
- **Curl Certificate Error**:
  - Initial `curl --cacert ca.crt https://server.kubernetes.local:6443/version` failed with `curl: (77) error setting certificate file: ca.crt`. Resolved by ensuring the command was run from the correct directory containing `ca.crt`.
- **CNI Plugin Distribution**:
  - Failed to move CNI plugins due to incorrect path (`cni-plugins/*`). Fixed by copying plugins to a temporary directory (`~/cni-plugins/`) and then moving them to `/opt/cni/bin/`.
- **RBAC Bootstrap Issues**:
  - Observed `poststarthook/rbac/bootstrap-roles failed: not finished` in `kube-apiserver` logs. This is expected during initial setup as RBAC roles are created incrementally. Verified successful rolebinding creation in logs.

## Challenges Faced

- **SSH Authentication Issues**: Initial attempts to copy SSH keys failed due to `publickey` authentication restrictions. Resolved by enabling `PermitRootLogin` and temporarily enabling password authentication.
- **File Not Found Errors**: Incorrect file names (`machines.txt` vs. `machine.txt`, `etch.service` vs. `etcd.service`) caused script failures, fixed by correcting file references.
- **Service Restart Issues**: Managed by `ssh.socket` instead of `sshd`. Used `systemctl restart ssh.socket` to apply changes.
- **Network Instability**: Broken pipe errors during SSH sessions were resolved by reconnecting.
- **Command Syntax Errors**: Fixed incorrect NGINX version command and certificate file execution errors.
- **Curl Certificate Path Issue**: Resolved by running `curl` from the correct directory.
- **CNI Plugin Distribution**: Corrected path issues for CNI plugins to ensure proper installation.

## Next Steps

- Deploy a sample application to verify cluster functionality.
- Configure DNS for the cluster using CoreDNS or another DNS solution.
- Set up pod networking with a CNI plugin (e.g., Calico or Flannel) to enable pod-to-pod communication.
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
- Kubeconfig file creation and distribution for cluster authentication
- Encryption configuration for Kubernetes secrets
- etcd setup and configuration
- Control plane setup (`kube-apiserver`, `kube-controller-manager`, `kube-scheduler`)
- Worker node setup (`kubelet`, `kube-proxy`, `containerd`)
- CNI networking configuration
- Troubleshooting SSH connectivity, command syntax, certificate issues, and RBAC bootstrap errors
- Scripting for automation (e.g., `while` loops for SSH key distribution, hosts file management, certificate generation, kubeconfig distribution, and configuration file generation)

