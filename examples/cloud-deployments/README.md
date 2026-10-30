# Cloud deployment profiles

Cloud deployment profiles describe the surrounding environment for Box on three cloud targets.

> **Status.** Reference configurations only. Runnable deployment examples and package installation remain pending.

For managed Python code, use the
[AgentCore Runtime managed code profile](../../docs/user/cloud-deployments.md#runtime-managed-code).
It records the service runtime, bundled files, application endpoint, and operator identity.

For your own container image, use the
[AgentCore Runtime container profile](../../docs/user/cloud-deployments.md#runtime-container).
It records the image dependencies, non-root identity, and application endpoint.

For lifecycle-controlled execution, use the
[Lambda MicroVM profile](../../docs/user/cloud-deployments.md#lambda-microvm).
Its tested configuration requires root and the service's `ALL` capability setting.
Treat it as a qualification configuration.
Normal completion passed, but cancellation and timeout left task processes running.
The guide records the explicit library grants used by the tests.

Read the guide's [shared requirements](../../docs/user/cloud-deployments.md#shared-requirements)
and [qualification results](../../docs/user/cloud-deployments.md#qualification-results) before choosing a profile.
