"""Dogwood policy for the synthetic deployment service."""

import json


def deployment_policy(host, port, failure_window=300, cooldown=600):
    """Count failed deployment replies and preserve diagnostics during cooldown."""
    if not isinstance(host, str) or not host or any(char.isspace() for char in host):
        raise ValueError("host must be a nonempty hostname without whitespace")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    if type(failure_window) is not int or failure_window <= 0:
        raise ValueError("failure_window must be a positive integer number of seconds")
    if type(cooldown) is not int or cooldown <= 0:
        raise ValueError("cooldown must be a positive integer number of seconds")
    quoted_host = json.dumps(host)
    return f'''@id("deployment_connection")
permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)
when {{ context.input.host == {quoted_host} && context.input.port == {port} }};

@id("deployment_requests")
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when {{
    context.input.host == {quoted_host} && context.input.port == {port} &&
    ((context.input.method == "POST" && context.input.path == "/deployments/checkout") ||
     (context.input.method == "GET" && context.input.path == "/deployments/checkout/status"))
}};

@id("deployment_cooldown")
forbid(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when {{
    context.input.host == {quoted_host} && context.input.port == {port} &&
    context.input.method == "POST" && context.input.path == "/deployments/checkout"
}}
when temporal {{
    formerly within {cooldown}s (
        exists (trigger_status: Long). (
            Box::Action::"http:request"::response{{
                input.host: {quoted_host}, input.port: {port},
                input.method: "POST", input.path: "/deployments/checkout",
                output.status: trigger_status
            }}
            && trigger_status >= 400 && trigger_status < 600
            && exists (failures: Long). (
                (count for (t: Timepoint). where (
                    formerly within {failure_window}s (
                        exists (status: Long). (
                            Box::Action::"http:request"::response{{
                                input.host: {quoted_host}, input.port: {port},
                                input.method: "POST", input.path: "/deployments/checkout",
                                output.status: status
                            }}
                            && status >= 400 && status < 600 && tp(t)
                        )
                    )
                )) == failures
                && failures == 3
            )
        )
    )
}};
'''
