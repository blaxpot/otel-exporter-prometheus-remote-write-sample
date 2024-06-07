# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import boto3
import logging
import os
import psutil
import random
import requests
import sys
import time

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from logging import INFO, ERROR
from opentelemetry import metrics
from opentelemetry.exporter.prometheus_remote_write import (
    PrometheusRemoteWriteMetricsExporter,
)
from opentelemetry.metrics import Observation
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    MetricExportResult,
    PeriodicExportingMetricReader,
)
from typing import Dict

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)

if "PROMETHEUS_REMOTE_WRITE_ENDPOINT" not in os.environ:
    logger.log(
        level=ERROR,
        msg="Error: The environment variable 'PROMETHEUS_REMOTE_WRITE_ENDPOINT' is not set.",
    )

    sys.exit(1)


class SigV4PrometheusRemoteWriteMetricsExporter(PrometheusRemoteWriteMetricsExporter):
    def _send_message(self, message: bytes, headers: Dict) -> MetricExportResult:
        cert = None
        verify = True
        if self.tls_config:
            if "ca_file" in self.tls_config:
                verify = self.tls_config["ca_file"]
            elif "insecure_skip_verify" in self.tls_config:
                verify = self.tls_config["insecure_skip_verify"]

            if "cert_file" in self.tls_config and "key_file" in self.tls_config:
                cert = (
                    self.tls_config["cert_file"],
                    self.tls_config["key_file"],
                )
        try:
            session = boto3.Session()
            credentials = session.get_credentials()
            credentials = credentials.get_frozen_credentials()
            request = AWSRequest(
                method="POST", url=self.endpoint, headers=headers, data=message
            )
            SigV4Auth(credentials, "aps", session.region_name).add_auth(request)

            response = requests.post(
                self.endpoint,
                data=message,
                headers=dict(request.headers),
                timeout=self.timeout,
                proxies=self.proxies,
                cert=cert,
                verify=verify,
            )
            if not response.ok:
                response.raise_for_status()
        except requests.exceptions.RequestException as err:
            logger.error("Export POST request failed with reason: %s", err)
            return MetricExportResult.FAILURE
        return MetricExportResult.SUCCESS


exporter = SigV4PrometheusRemoteWriteMetricsExporter(
    endpoint=os.getenv("PROMETHEUS_REMOTE_WRITE_ENDPOINT"), timeout=10
)

reader = PeriodicExportingMetricReader(exporter, 1000)
provider = MeterProvider(metric_readers=[reader])
metrics.set_meter_provider(provider)
meter = metrics.get_meter(__name__)


# Callback to gather cpu usage
def get_cpu_usage_callback(observer):
    for number, percent in enumerate(psutil.cpu_percent(percpu=True)):
        labels = {"cpu_number": str(number)}
        yield Observation(percent, labels)


# Callback to gather RAM usage
def get_ram_usage_callback(observer):
    ram_percent = psutil.virtual_memory().percent
    yield Observation(ram_percent, {})


requests_counter = meter.create_counter(
    name="requests",
    description="number of requests",
    unit="1",
)

request_min_max = meter.create_counter(
    name="requests_min_max",
    description="min max sum count of requests",
    unit="1",
)

request_last_value = meter.create_counter(
    name="requests_last_value",
    description="last value number of requests",
    unit="1",
)

requests_active = meter.create_up_down_counter(
    name="requests_active",
    description="number of active requests",
    unit="1",
)

meter.create_observable_counter(
    callbacks=[get_ram_usage_callback],
    name="ram_usage",
    description="ram usage",
    unit="1",
)

meter.create_observable_up_down_counter(
    callbacks=[get_cpu_usage_callback],
    name="cpu_percent",
    description="per-cpu usage",
    unit="1",
)

request_latency = meter.create_histogram("request_latency")
testing_labels = {"environment": "testing"}

# Load generator
num = random.randint(0, 1000)
while True:
    # counters
    requests_counter.add(num % 131 + 200, testing_labels)
    request_min_max.add(num % 181 + 200, testing_labels)
    request_last_value.add(num % 101 + 200, testing_labels)

    # updown counter
    requests_active.add(num % 7231 + 200, testing_labels)

    request_latency.record(num % 92, testing_labels)
    logger.log(level=INFO, msg="completed metrics collection cycle")
    time.sleep(1)
    num += 9791
