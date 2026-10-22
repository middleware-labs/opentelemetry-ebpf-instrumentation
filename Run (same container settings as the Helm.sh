Run (same container settings as the Helm chart: privileged, host network, cgroup and tracefs mounts):
  docker run -d --name obi --restart unless-stopped \
    --privileged --network host \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v /sys/kernel/tracing:/sys/kernel/tracing \
    -v "$PWD/obi-host.yaml:/etc/obi/obi-host.yaml:ro" \
    -e OTEL_EBPF_CONFIG_PATH=/etc/obi/obi-host.yaml \
    ghcr.io/middleware-labs/ruby-app:ntest2