"""
Comprehensive Test Suite for Universal Container and Workload Support in KubeGuard.

Verifies:
1. Universal image reference handling (Docker Hub, private registries, tags, digests).
2. Universal Kubernetes workload discovery & ownerReferences resolution:
   - Deployments (via ReplicaSet)
   - CronJobs (via Job)
   - StatefulSets
   - DaemonSets
   - Jobs
   - Standalone Pods
3. Multi-container pod support (regular containers, initContainers, ephemeralContainers).
4. Universal Docker runtime support (discovery, revalidation, backup, evidence).
5. M10 Multi-Workload Evidence and Baseline Isolation:
   - Separate run IDs and incident folders.
   - Tampering in Workload A's evidence must NOT affect Workload B's integrity status.
6. Dynamic privileged-mode detection (inspected dynamically, never inferred from image name).
"""

import unittest
import os
import sys
import json
import shutil
import tempfile
from unittest.mock import patch, MagicMock

from runtime_target import (
    RuntimeTarget,
    matches_image_name,
    normalize_image_name,
    resolve_owning_workload_from_metadata,
    discover_docker_workloads,
    discover_runtime_workloads,
    revalidate_runtime_target,
    prompt_or_select_runtime_target
)
from module7_backup import create_backup
from module8_evidence import collect_evidence
from module10_integrity import (
    initialize_baseline,
    verify_hashes,
    load_tamper_log,
    INTEGRITY_DIR
)


class TestUniversalImageReferenceHandling(unittest.TestCase):
    """Verifies arbitrary valid container image references and matching."""

    def test_standard_docker_hub_images(self):
        self.assertTrue(matches_image_name("redis:7", "redis:7"))
        self.assertTrue(matches_image_name("docker.io/library/redis:7", "redis:7"))
        self.assertTrue(matches_image_name("library/ubuntu:24.04", "ubuntu:24.04"))
        self.assertTrue(matches_image_name("alpine:latest", "alpine"))
        self.assertTrue(matches_image_name("alpine", "alpine:latest"))

    def test_private_registry_with_port(self):
        self.assertTrue(matches_image_name(
            "registry.internal.corp:5000/security/agent:v2.1",
            "registry.internal.corp:5000/security/agent:v2.1"
        ))
        self.assertTrue(matches_image_name(
            "myregistry.azurecr.io/apps/payments:release-42",
            "myregistry.azurecr.io/apps/payments:release-42"
        ))
        # Container running with full registry prefix matches short target if repository matches
        self.assertTrue(matches_image_name(
            "registry.internal.corp:5000/security/agent:v2.1",
            "agent:v2.1"
        ))

    def test_immutable_sha256_digests(self):
        digest = "sha256:7115236b23e20e5883a48e7e17409419cf5b62b1b38f8cfd90161a0397cc9f68"
        img_with_digest = f"redis@{digest}"
        self.assertTrue(matches_image_name(img_with_digest, "redis:latest"))
        self.assertTrue(matches_image_name(img_with_digest, f"docker.io/library/redis@{digest}"))

    def test_different_images_do_not_match(self):
        self.assertFalse(matches_image_name("redis:7", "postgres:15"))
        self.assertFalse(matches_image_name("nginx:1.24", "nginx:1.25"))
        self.assertFalse(matches_image_name("myapp:v1", "otherapp:v1"))


class TestWorkloadOwnerReferencesResolution(unittest.TestCase):
    """Verifies dynamic resolution of ownerReferences across all Kubernetes workload types."""

    def test_standalone_pod_resolution(self):
        meta = {
            "name": "standalone-worker",
            "uid": "uid-pod-123",
            "ownerReferences": []
        }
        res = resolve_owning_workload_from_metadata(meta, namespace="prod")
        self.assertEqual(res["kind"], "Pod")
        self.assertEqual(res["name"], "standalone-worker")
        self.assertEqual(res["uid"], "uid-pod-123")

    @patch("subprocess.run")
    def test_replicaset_to_deployment_resolution(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "metadata": {
                    "name": "payment-api-6b79878d6b",
                    "ownerReferences": [{"kind": "Deployment", "name": "payment-api", "uid": "uid-deploy-456"}]
                }
            })
        )
        meta = {
            "name": "payment-api-6b79878d6b-x9z2w",
            "uid": "uid-pod-789",
            "ownerReferences": [{"kind": "ReplicaSet", "name": "payment-api-6b79878d6b"}]
        }
        res = resolve_owning_workload_from_metadata(meta, namespace="default")
        self.assertEqual(res["kind"], "Deployment")
        self.assertEqual(res["name"], "payment-api")
        self.assertEqual(res["uid"], "uid-deploy-456")

    @patch("subprocess.run")
    def test_job_to_cronjob_resolution(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "metadata": {
                    "name": "backup-sync-2891234",
                    "ownerReferences": [{"kind": "CronJob", "name": "backup-sync", "uid": "uid-cron-111"}]
                }
            })
        )
        meta = {
            "name": "backup-sync-2891234-podq7",
            "uid": "uid-pod-999",
            "ownerReferences": [{"kind": "Job", "name": "backup-sync-2891234"}]
        }
        res = resolve_owning_workload_from_metadata(meta, namespace="ops")
        self.assertEqual(res["kind"], "CronJob")
        self.assertEqual(res["name"], "backup-sync")
        self.assertEqual(res["uid"], "uid-cron-111")

    def test_statefulset_resolution(self):
        meta = {
            "name": "cassandra-0",
            "uid": "uid-pod-cas",
            "ownerReferences": [{"kind": "StatefulSet", "name": "cassandra", "uid": "uid-ss-222"}]
        }
        res = resolve_owning_workload_from_metadata(meta, namespace="db")
        self.assertEqual(res["kind"], "StatefulSet")
        self.assertEqual(res["name"], "cassandra")

    def test_daemonset_resolution(self):
        meta = {
            "name": "fluentd-node-k8s-01",
            "uid": "uid-pod-fl",
            "ownerReferences": [{"kind": "DaemonSet", "name": "fluentd-logger", "uid": "uid-ds-333"}]
        }
        res = resolve_owning_workload_from_metadata(meta, namespace="logging")
        self.assertEqual(res["kind"], "DaemonSet")
        self.assertEqual(res["name"], "fluentd-logger")


class TestMultiContainerAndPrivilegeDiscovery(unittest.TestCase):
    """Verifies multi-container pod handling (regular, init, ephemeral) and dynamic privilege checks."""

    @patch("subprocess.run")
    def test_discover_target_in_multi_container_pod(self, mock_run):
        cluster_pods = {
            "items": [
                {
                    "metadata": {
                        "name": "order-service-98fbc-k911p",
                        "namespace": "production",
                        "uid": "uid-order-pod",
                        "creationTimestamp": "2026-10-30T10:00:00Z",
                        "ownerReferences": [{"kind": "StatefulSet", "name": "order-service"}]
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {"name": "istio-proxy", "containerID": "containerd://istio123"},
                            {"name": "order-app", "containerID": "containerd://app456"}
                        ]
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "istio-proxy",
                                "image": "istio/proxyv2:1.20",
                                "securityContext": {"privileged": False}
                            },
                            {
                                "name": "order-app",
                                "image": "internal.corp/order-app:v3.2",
                                "securityContext": {"privileged": True}
                            }
                        ]
                    }
                }
            ]
        }
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(cluster_pods))

        targets = discover_runtime_workloads(
            target_image="internal.corp/order-app:v3.2",
            namespace="production"
        )
        self.assertEqual(len(targets), 1)
        t = targets[0]
        self.assertEqual(t.workload_kind, "StatefulSet")
        self.assertEqual(t.workload_name, "order-service")
        self.assertEqual(t.container_name, "order-app")
        self.assertTrue(t.privileged)
        self.assertEqual(t.container_id, "containerd://app456")

    @patch("subprocess.run")
    def test_discover_init_container_target(self, mock_run):
        cluster_pods = {
            "items": [
                {
                    "metadata": {
                        "name": "migration-runner-pod",
                        "namespace": "db",
                        "creationTimestamp": "2026-10-30T10:00:00Z"
                    },
                    "status": {
                        "phase": "Running",
                        "initContainerStatuses": [
                            {"name": "flyway-init", "containerID": "containerd://flyway999"}
                        ]
                    },
                    "spec": {
                        "containers": [],
                        "initContainers": [
                            {
                                "name": "flyway-init",
                                "image": "flyway/flyway:9-alpine",
                                "securityContext": {"privileged": False}
                            }
                        ]
                    }
                }
            ]
        }
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(cluster_pods))

        targets = discover_runtime_workloads(
            target_image="flyway/flyway:9-alpine",
            namespace="db"
        )
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].container_name, "flyway-init")
        self.assertFalse(targets[0].privileged)


class TestDockerRuntimeUniversalSupport(unittest.TestCase):
    """Verifies Docker container discovery, revalidation, backup, and evidence collection."""

    @patch("shutil.which", return_value="/usr/bin/docker")
    @patch("subprocess.run")
    def test_discover_docker_workloads(self, mock_run, mock_which):
        ps_output = json.dumps({
            "ID": "c71a80d52b31",
            "Names": "/custom-db-instance",
            "Image": "postgres:15-alpine"
        })
        inspect_output = json.dumps([{
            "Id": "c71a80d52b31c4f5e8",
            "Image": "sha256:d84f2910ba",
            "State": {"Status": "running", "Running": True},
            "HostConfig": {"Privileged": True},
            "Config": {"Image": "postgres:15-alpine", "Labels": {"environment": "test"}}
        }])

        def run_side_effect(cmd, *args, **kwargs):
            if cmd[1] == "ps":
                return MagicMock(returncode=0, stdout=ps_output)
            elif cmd[1] == "inspect":
                return MagicMock(returncode=0, stdout=inspect_output)
            return MagicMock(returncode=1, stderr="Unknown cmd")

        mock_run.side_effect = run_side_effect

        targets = discover_docker_workloads(target_image="postgres:15-alpine")
        self.assertEqual(len(targets), 1)
        t = targets[0]
        self.assertEqual(t.namespace, "docker")
        self.assertEqual(t.workload_kind, "DockerContainer")
        self.assertEqual(t.workload_name, "custom-db-instance")
        self.assertEqual(t.container_id, "c71a80d52b31")
        self.assertTrue(t.privileged)

    @patch("shutil.which", return_value="/usr/bin/docker")
    @patch("subprocess.run")
    def test_revalidate_docker_target(self, mock_run, mock_which):
        target = RuntimeTarget(
            namespace="docker",
            workload_kind="DockerContainer",
            workload_name="redis-prod",
            pod_name="redis-prod",
            container_id="a1b2c3d4e5f6",
            runtime_image="redis:7-alpine",
            privileged=False
        )

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps([{
                "State": {"Status": "running", "Running": True},
                "HostConfig": {"Privileged": False},
                "Config": {"Image": "redis:7-alpine", "Labels": {}}
            }])
        )

        ok, err = revalidate_runtime_target(target)
        self.assertTrue(ok)
        self.assertIsNone(err)

    @patch("subprocess.run")
    def test_docker_backup_and_evidence(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="simulated_docker_output\n")

        temp_dir = tempfile.mkdtemp(prefix="kg_test_docker_")
        try:
            target = RuntimeTarget(
                namespace="docker",
                workload_kind="DockerContainer",
                workload_name="my-container-123",
                pod_name="my-container-123",
                container_id="my-container-123"
            )

            # Test Docker backup
            bak_path = create_backup(run_id="test_run", namespace="docker", target=target)
            self.assertIsNotNone(bak_path)
            self.assertTrue(os.path.exists(bak_path))
            files = os.listdir(bak_path)
            self.assertIn("docker_ps.json", files)
            self.assertIn("docker_inspect.json", files)

            # Test Docker evidence
            ev_path = collect_evidence("my-container-123", namespace="docker", run_id="test_run", target=target)
            self.assertIsNotNone(ev_path)
            self.assertTrue(os.path.exists(ev_path))
            ev_files = os.listdir(ev_path)
            self.assertIn("docker_inspect.json", ev_files)
            self.assertIn("docker_logs.txt", ev_files)
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)


class TestM10MultiWorkloadEvidenceIsolation(unittest.TestCase):
    """
    Verifies that M10 isolates evidence baselines, manifests, and tamper logs by incident directory.
    Tampering with evidence in Workload A must NEVER trigger a tamper alarm on Workload B.
    """

    def setUp(self):
        self.test_root = tempfile.mkdtemp(prefix="kg_test_isolation_")
        self.ev_dir_a = os.path.join(self.test_root, "incident_run001_20261030_workloadA")
        self.ev_dir_b = os.path.join(self.test_root, "incident_run002_20261030_workloadB")
        os.makedirs(self.ev_dir_a, exist_ok=True)
        os.makedirs(self.ev_dir_b, exist_ok=True)

        with open(os.path.join(self.ev_dir_a, "pod.yaml"), "w") as f:
            f.write("kind: Pod\nmetadata:\n  name: pod-workload-a\n")
        with open(os.path.join(self.ev_dir_a, "logs.txt"), "w") as f:
            f.write("Log line from workload A\n")

        with open(os.path.join(self.ev_dir_b, "pod.yaml"), "w") as f:
            f.write("kind: Pod\nmetadata:\n  name: pod-workload-b\n")
        with open(os.path.join(self.ev_dir_b, "logs.txt"), "w") as f:
            f.write("Log line from workload B\n")

    def tearDown(self):
        if os.path.exists(self.test_root):
            shutil.rmtree(self.test_root, ignore_errors=True)
        # Clean up created test baselines in integrity directory
        for item in ["incident_run001_20261030_workloadA", "incident_run002_20261030_workloadB"]:
            p = os.path.join(INTEGRITY_DIR, item)
            if os.path.exists(p):
                shutil.rmtree(p, ignore_errors=True)

    def test_independent_tamper_isolation(self):
        # 1. Establish baseline for Workload A
        hash_file_a = initialize_baseline(self.ev_dir_a, authorized_by="AdminA", reason="Test baseline A", force=True)
        self.assertTrue(os.path.exists(hash_file_a))

        # 2. Establish baseline for Workload B
        hash_file_b = initialize_baseline(self.ev_dir_b, authorized_by="AdminB", reason="Test baseline B", force=True)
        self.assertTrue(os.path.exists(hash_file_b))

        # 3. Verify both initially verified
        ok_a_init, ver_a_init, tamp_a_init, miss_a_init, _ = verify_hashes(self.ev_dir_a)
        ok_b_init, ver_b_init, tamp_b_init, miss_b_init, _ = verify_hashes(self.ev_dir_b)
        self.assertTrue(ok_a_init)
        self.assertTrue(ok_b_init)
        self.assertEqual(tamp_a_init, 0)
        self.assertEqual(tamp_b_init, 0)

        # 4. Tamper Workload A only
        with open(os.path.join(self.ev_dir_a, "pod.yaml"), "a") as f:
            f.write("# INJECTED MALICIOUS TAMPERING IN WORKLOAD A\n")

        # 5. Re-verify Workload A -> must be TAMPERED
        ok_a_after, ver_a_after, tamp_a_after, miss_a_after, _ = verify_hashes(self.ev_dir_a)
        self.assertFalse(ok_a_after)
        self.assertGreater(tamp_a_after, 0)

        # 6. Re-verify Workload B -> must REMAIN VERIFIED and UNTOUCHED
        ok_b_after, ver_b_after, tamp_b_after, miss_b_after, _ = verify_hashes(self.ev_dir_b)
        self.assertTrue(ok_b_after)
        self.assertEqual(tamp_b_after, 0)
        self.assertEqual(miss_b_after, 0)

        # 7. Check tamper log isolation
        log_a = load_tamper_log(self.ev_dir_a)
        log_b = load_tamper_log(self.ev_dir_b)
        self.assertIsNotNone(log_a)
        self.assertTrue(log_a.get("tampered"))
        self.assertIsNone(log_b)  # Workload B was never tampered


if __name__ == "__main__":
    unittest.main()
