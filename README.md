# Amazon Managed Prometheus Prometheus Remote Write Exporter Sample

This is a version of some [example code](https://github.com/open-telemetry/opentelemetry-python-contrib/tree/main/exporter/opentelemetry-exporter-prometheus-remote-write/example) provided for the `opentelemetry-exporter-prometheus-remote-write` Python package that's been modified to be run in Amazon EKS and write to an AMP workspace.

To deploy it to EKS you'll need to set up a role with the required permissions and associate a k8s SA with that role and the deployment. It's also necessary to provide the AMP remote write endpoint url as an env var to the container (`PROMETHEUS_REMOTE_WRITE_ENDPOINT`).

