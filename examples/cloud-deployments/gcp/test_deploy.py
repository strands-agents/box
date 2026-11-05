"""Offline checks for deployment ownership and saved evidence."""

import argparse
import base64
import contextlib
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("gcp_deploy", Path(__file__).with_name("deploy.py"))
deploy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deploy)


def serial(value):
    encoded = base64.b64encode(gzip.compress(json.dumps(value).encode())).decode()
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    chunks = [encoded[start:start + 1000] for start in range(0, len(encoded), 1000)]
    return "\n".join(f"BOX_GCP_RECEIPT_CHUNK={digest}:{index}:{len(chunks)}:{chunk}"
                     for index, chunk in enumerate(chunks))


class SerialTests(unittest.TestCase):
    def test_large_receipt_survives_prefixed_duplicate_and_reordered_lines(self):
        value = {"decisions": [hashlib.sha256(str(index).encode()).hexdigest() for index in range(1000)]}
        lines = serial(value).splitlines()
        self.assertGreater(len(lines), 10)
        self.assertLess(max(map(len, lines)), 1200)
        output = "\n".join("log prefix: " + line for line in list(reversed(lines)) + lines)
        self.assertTrue(all(result == value for result in deploy.serial_receipts(output)))
        self.assertEqual(list(deploy.serial_receipts(output))[-1], value)

    def test_incomplete_or_corrupt_receipts_cannot_report_success(self):
        lines = serial({"values": [hashlib.sha256(str(index).encode()).hexdigest() for index in range(100)]}).splitlines()
        self.assertGreater(len(lines), 1)
        for output in ("\n".join(lines[:-1]), "\n".join(lines)[:-1], "\n".join(lines).replace("CHUNK=", "CHUNK=bad")):
            with self.subTest(output_length=len(output)):
                self.assertEqual(list(deploy.serial_receipts(output)), [])


class Cloud:
    """An in-memory cloud that can lose a create response."""

    PREFIXES = {
        ("compute", "networks", "subnets"): "subnet",
        ("compute", "networks"): "network",
        ("iam", "service-accounts"): "service_account",
        ("iam", "roles"): "role",
        ("compute", "disks"): "disk",
        ("compute", "instances"): "instance",
    }

    def __init__(self):
        self.resources, self.bindings, self.calls, self.deleted = {}, [], [], []
        self.fail_create, self.accept_before_failure, self.serial = None, False, ""
        self.deleted_account_lookup_denied = False

    def __call__(self, project, *args, optional=False, raw=False):
        self.calls.append((project, args))
        if args[:2] == ("services", "enable"):
            return None
        if args[:2] == ("compute", "images"):
            return {"name": "debian-unit-image"}
        if args[:3] == ("compute", "instances", "get-serial-port-output"):
            return self.serial
        if args[:2] == ("projects", "get-iam-policy"):
            return {"bindings": copy.deepcopy(self.bindings)}
        if args[:2] == ("projects", "add-iam-policy-binding"):
            self.bindings.append({
                "role": next(arg.split("=", 1)[1] for arg in args if arg.startswith("--role=")),
                "members": [next(arg.split("=", 1)[1] for arg in args if arg.startswith("--member="))],
            })
            return None
        if args[:2] == ("projects", "remove-iam-policy-binding"):
            for binding in self.bindings:
                if binding["role"] == args[args.index("--role") + 1]:
                    binding["members"].remove(args[args.index("--member") + 1])
            self.bindings = [binding for binding in self.bindings if binding["members"]]
            return None
        for prefix, kind in self.PREFIXES.items():
            if args[:len(prefix)] != prefix:
                continue
            action, name = args[len(prefix):len(prefix) + 2]
            key = kind, name + "@" + project + ".iam.gserviceaccount.com" if kind == "service_account" and action == "create" else name
            if action == "list" and kind == "service_account":
                email = name.removeprefix("--filter=email=")
                value = self.resources.get((kind, email))
                return [copy.deepcopy(value)] if value is not None else []
            if action == "describe":
                if kind == "service_account" and key not in self.resources and self.deleted_account_lookup_denied:
                    raise RuntimeError("PERMISSION_DENIED: resource may not exist")
                return copy.deepcopy(self.resources.get(key))
            if action == "create":
                if kind != self.fail_create or self.accept_before_failure:
                    self.resources[key] = {"description": args[args.index("--description") + 1], "status": "RUNNING"}
                if kind == self.fail_create:
                    raise RuntimeError("create response unavailable")
                return None
            if action == "delete":
                self.deleted.append((key, args))
                del self.resources[key]
                return None
        raise AssertionError((project, args))


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="box-gcp-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.receipt = self.directory / "state" / "deployment.json"
        self.example = self.directory / "example"
        self.example.mkdir()
        for name in ("run-demo.py", "agent.py", "requirements.txt", "setup-vm.sh"):
            (self.example / name).write_text("fixture\n")
        self.cloud = Cloud()
        for manager in (patch.object(deploy, "EXAMPLE", self.example),
                        patch.object(deploy, "gcloud", self.cloud), contextlib.redirect_stdout(io.StringIO())):
            manager.__enter__()
            self.addCleanup(manager.__exit__, None, None, None)
        self.args = argparse.Namespace(
            project="demo-project", name="box-demo", zone="us-central1-a", machine_type="t2a-standard-4",
            source_revision="a" * 40, image="debian-unit-image", location="global", model=None, probe_only=True,
        )

    def create(self):
        deploy.deploy(self.args, self.receipt)
        return json.loads(self.receipt.read_text())

    def test_cleanup_refuses_every_foreign_resource(self):
        state = self.create()
        for key in list(self.cloud.resources):
            with self.subTest(kind=key[0]):
                original = self.cloud.resources[key]["description"]
                self.cloud.resources[key]["description"] = "another deployment"
                selected = dict(state, created=[key[0]])
                with self.assertRaisesRegex(RuntimeError, "ownership marker"):
                    deploy.cleanup(selected, self.receipt)
                self.assertEqual(self.cloud.deleted, [])
                self.cloud.resources[key]["description"] = original

    def test_partial_creation_is_cleaned_even_when_the_response_is_lost(self):
        for accepted in (False, True):
            with self.subTest(accepted_before_failure=accepted):
                self.cloud.fail_create = "disk"
                self.cloud.accept_before_failure = accepted
                receipt = self.directory / str(accepted) / "deployment.json"
                with self.assertRaisesRegex(RuntimeError, "create response unavailable"):
                    deploy.deploy(self.args, receipt)
                state = json.loads(receipt.read_text())
                deploy.cleanup(state, receipt)
                self.assertEqual(self.cloud.resources, {})
                self.assertEqual(self.cloud.bindings, [])
                self.assertTrue(json.loads(receipt.read_text())["cleaned_up"])

    def test_cleanup_survives_unavailable_serial_output_and_still_checks_ownership(self):
        state = self.create()
        self.cloud.resources[("instance", state["name"])]["status"] = "TERMINATED"

        def unavailable_serial(project, *args, **kwargs):
            if args[:3] == ("compute", "instances", "get-serial-port-output"):
                raise RuntimeError("Serial output is unavailable for this stopped VM")
            return self.cloud(project, *args, **kwargs)

        with patch.object(deploy, "gcloud", unavailable_serial):
            original = self.cloud.resources[("instance", state["name"])]["description"]
            self.cloud.resources[("instance", state["name"])]["description"] = "another deployment"
            with self.assertRaisesRegex(RuntimeError, "ownership marker"):
                deploy.cleanup(state, self.receipt)
            self.assertEqual(self.cloud.deleted, [])
            self.cloud.resources[("instance", state["name"])]["description"] = original
            deploy.cleanup(state, self.receipt)

        self.assertEqual(len(self.cloud.deleted), 6)
        self.assertEqual(self.cloud.resources, {})
        self.assertEqual(self.cloud.bindings, [])
        self.assertTrue(json.loads(self.receipt.read_text())["cleaned_up"])

    def test_concurrent_deployment_cannot_replace_the_owners_receipt(self):
        both_preflight = threading.Barrier(2)
        first_finished = threading.Event()
        outcomes, create_attempts = {}, []

        def concurrent_cloud(project, *args, **kwargs):
            if args[:2] == ("compute", "images"):
                both_preflight.wait(timeout=5)
                if threading.current_thread().name == "second":
                    if not first_finished.wait(timeout=5):
                        raise RuntimeError("The first deployment did not finish")
            for prefix in Cloud.PREFIXES:
                if args[:len(prefix)] == prefix and args[len(prefix)] == "create":
                    create_attempts.append(threading.current_thread().name)
                    break
            if args[:3] == ("compute", "networks", "create") and ("network", args[3]) in self.cloud.resources:
                raise RuntimeError("The network already exists")
            return self.cloud(project, *args, **kwargs)

        def attempt():
            name = threading.current_thread().name
            try:
                deploy.deploy(self.args, self.receipt)
                outcomes[name] = None
            except Exception as error:
                outcomes[name] = error
            finally:
                if name == "first":
                    first_finished.set()

        with patch.object(deploy, "gcloud", concurrent_cloud):
            threads = [threading.Thread(target=attempt, name=name) for name in ("first", "second")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertFalse(any(thread.is_alive() for thread in threads))

        self.assertIsNone(outcomes["first"])
        self.assertIsInstance(outcomes["second"], (FileExistsError, RuntimeError))
        self.assertEqual(create_attempts, ["first"] * 6)
        state = json.loads(self.receipt.read_text())
        self.assertEqual(set(state["created"]), set(Cloud.PREFIXES.values()))
        self.assertTrue(all(resource["description"] == state["marker"] for resource in self.cloud.resources.values()))
        deploy.cleanup(state, self.receipt)
        self.assertEqual(self.cloud.resources, {})
        self.assertEqual(self.cloud.bindings, [])

    def test_cleanup_preserves_other_role_members(self):
        state = self.create()
        other = "serviceAccount:other@demo-project.iam.gserviceaccount.com"
        self.cloud.bindings[0]["members"].append(other)
        with self.assertRaisesRegex(RuntimeError, "another member"):
            deploy.cleanup(state, self.receipt)
        self.assertEqual(self.cloud.bindings[0]["members"], [other])
        self.assertIn(("role", state["role"]), self.cloud.resources)

    def test_serial_receipts_require_owner_revision_and_payload(self):
        state = self.create()
        trusted = {key: state[key] for key in ("owner", "source_revision", "payload_sha256")}
        trusted["proof"] = "trusted"
        receipts = [[], trusted] + [dict(trusted, **{key: "foreign", "proof": "foreign"})
                                   for key in ("owner", "source_revision", "payload_sha256")]
        self.cloud.serial = "BOX_GCP_RECEIPT_CHUNK=invalid!\n" + "\n".join(serial(value) for value in receipts)
        deploy.status(state, self.receipt)
        saved = self.receipt.parent / "results.json"
        self.assertEqual(json.loads(saved.read_text()), trusted)
        self.assertEqual((self.receipt.parent / "serial.log").read_text(), self.cloud.serial)
        self.cloud.serial = serial(receipts[-1])
        deploy.status(state, self.receipt)
        self.assertEqual(json.loads(saved.read_text()), trusted)
        self.assertEqual(len(list(self.receipt.parent.glob("serial-*.log"))), 2)

    def test_cleanup_resumes_when_a_deleted_account_cannot_be_described(self):
        state = self.create()
        del self.cloud.resources[("service_account", state["service_account"])]
        self.cloud.deleted_account_lookup_denied = True
        deploy.cleanup(state, self.receipt)
        self.assertEqual(self.cloud.resources, {})
        self.assertEqual(self.cloud.bindings, [])
        self.assertTrue(json.loads(self.receipt.read_text())["cleaned_up"])

    def test_account_list_failure_does_not_imply_the_account_is_absent(self):
        state = self.create()
        for result in (RuntimeError("PERMISSION_DENIED"), {}, [None], ["invalid"],
                       [{"description": state["marker"]}, {"description": state["marker"]}]):
            with self.subTest(result=result), patch.object(deploy, "gcloud") as cloud:
                if isinstance(result, Exception):
                    cloud.side_effect = result
                else:
                    cloud.return_value = result
                with self.assertRaises(RuntimeError):
                    deploy.owned_resource(state, "service_account")
        self.assertEqual(self.cloud.deleted, [])

    def test_cleanup_is_repeatable_and_keeps_vm_disks_until_ownership_check(self):
        state = self.create()
        deploy.cleanup(state, self.receipt)
        first_deletions = list(self.cloud.deleted)
        deploy.cleanup(json.loads(self.receipt.read_text()), self.receipt)
        self.assertEqual(self.cloud.deleted, first_deletions)
        self.assertEqual(self.cloud.resources, {})
        self.assertEqual(len(first_deletions), 6)
        vm_delete = next(args for (kind, _), args in first_deletions if kind == "instance")
        self.assertIn("--keep-disks=all", vm_delete)
        self.assertTrue(self.receipt.exists())
        for project, args in self.cloud.calls:
            self.assertEqual(project, "debian-cloud" if args[:2] == ("compute", "images") else "demo-project")
        self.assertFalse(any("firewall-rules" in args or "disable" in args for _, args in self.cloud.calls))


class CommandTests(unittest.TestCase):
    def test_gcloud_always_names_the_project(self):
        for raw in (False, True):
            with self.subTest(raw=raw), patch.object(deploy.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, "serial" if raw else "{}", "")
                deploy.gcloud("explicit-project", "compute", "instances", "list", raw=raw)
                command = run.call_args.args[0]
                self.assertEqual(command[command.index("--project") + 1], "explicit-project")
                self.assertIn("--quiet", command)

    def test_optional_lookup_does_not_hide_permission_failure(self):
        with patch.object(deploy.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, "", "PERMISSION_DENIED")
            with self.assertRaisesRegex(RuntimeError, "PERMISSION_DENIED"):
                deploy.gcloud("explicit-project", "compute", "instances", "describe", "demo", optional=True)

    def test_project_is_required_before_any_cloud_call(self):
        with patch.object(deploy.sys, "argv", ["deploy.py", "deploy"]), \
                patch.object(deploy, "gcloud") as cloud, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_status:
                deploy.main()
            self.assertEqual(exit_status.exception.code, 2)
            cloud.assert_not_called()


if __name__ == "__main__":
    unittest.main()
