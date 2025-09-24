# Kubernetes manifest

You can deploy bpfmeter in a Kubernetes cluster using the provided manifest file. The agent configuration can be adjusted by manually editing this manifest.

The bpfmeter release container image is specified in the `image` field. You can update this value to use a custom registry, image proxy or adjust bpfmeter version if needed.

Command-line options for bpfmeter are passed through the `args` section of the bpfmeter container specification.

The container requires a privileged `securityContext` in order to collect kernel-level performance metrics.

By default, the agent starts a Prometheus client on port 9100. To make this endpoint available to other services or scrapers, container `ports` and corresponding Kubernetes `Service` are configured.
