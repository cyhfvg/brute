#!/usr/bin/env bash
set -euo pipefail

# Create a kube-system default SA token and write tests/docker/42-kubelet/pass.txt.
token="$(docker exec kubelet-brute-lab sh -c \
  'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl create token default -n kube-system --duration=87600h')"
dir="$(cd "$(dirname "$0")" && pwd)"
printf 'wrong\n%s\n' "$token" > "${dir}/pass.txt"
echo "wrote kubelet token to pass.txt"
