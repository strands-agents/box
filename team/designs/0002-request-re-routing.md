# Supporting request re-routing on Box

## **Overview**

The goal of this document is to align on key decisions for supporting routing egress HTTP calls to a different destinations.

## Key Decisions

### **KD 1: Feature Name**

The feature we're building is the ability to re-route an outbound request to a different destination.

We have two candidates for defining this "destination" i.e. (1) **backend** (2) **target**.

**Backend:** In the load balancer/proxy world, this word is popular to represent the destination path. It's used in several open source projects \[[HAProxy](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/proxying-essentials/configuration-basics/backends/)**,** [Traefik](https://doc.traefik.io/traefik/v1.4/basics/#backends), [Kubernetes Gateway API, ](https://kubernetes.io/docs/concepts/services-networking/gateway/)​[agentgateway](https://agentgateway.dev/docs/standalone/latest/documentation/configuration/backends/)]

**Target (Target Groups)**: This word is popular inside AWS. \[[ALB](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html)**,** [NLB](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html)**,**  [AgentCore Gateway,](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-core-concepts.html) [VPC Lattice](https://docs.aws.amazon.com/vpc-lattice/latest/ug/target-groups.html) ]

**Recommendation:** We will prefer the word "backend" because (1) This aligns more closely with the terms used by open-source projects (2) Box internally uses the term "target" to represent the destinations that the agent wants to use. This can be confusing, especially if we decide to launch Box SDK.

**​**

### **KD 2: API Shape**

The proposal is to support named list of backends, per egress table. Each backend table will support

1. a name for the backend
2. the backend URL
3. the auth required to reach the backend. Will support all supported credential injection mechanisms on Box.

At launch, we will validate that there can be only a single backend defined. In the future, we can extend this to support multiple backends with the ability to define routing-rules to control how to forward requests to backends.

```
[egress.github]
destinations = ["api.github.com"]

[[egress.github.backends]]
name = "primary"
url  = "https://gateway-1.example.com"
auth.ref = "env://BOX_GW_TOKEN"

## At launch support a single backend. 
```

**Future Extensions**

The same shape can be easily extended to support the following features

1. Support multiple backends
2. Routing Rules to define how requests should be routed
3. Support URL re-writing (e.g. define values for headers, query params, path etc for the outbound request)

```
## In future, extend to multiple backends + ability to configure routing rules.

[egress.github]
destinations = ["api.github.com"]
﻿
[[egress.github.backends]]
name = "control"
url  = "https://gateway-1.example.com"
auth.ref = "env://BOX_GW_TOKEN"

[[egress.github.backends]]
name = "experiment"
url  = "https://gateway-2.example.com"
auth.ref = "env://BOX_GW_TOKEN"

[[egress.github.route-rules]]
backends = [ { name = "control", weight = 90 }, { name = "experiment", weight = 10 } ] # example rule types
```

### KD 3: Policy Evaluation

Today policies get applied on requests that agents make. Now, we're introducing the ability to route requests to a different destination. The main question is -- which request do we run policy on?

**Option 1:** Policy authorizes the original destination only.

**Rationale:** The policy we have today, authorizes only the agent/workload's action (a.k.a "Agent Action"). Box re-routing the request to another backend is a "Box action". Today, we don't have policies on "Box action". We have some precedence of not creating policy on box actions e.g. fetching credentials for credential injection. 

If the Box operator does not want the agent to reach the backend directly, no action should be required (given the default-deny nature of Box). If the Box operator has a wild-card policy in place, then they can add an explicit deny on the backend URL.  


**Option 2:** Policy authorizes on original destination + backend with a new action type

**Rationale:** The security posture here is that we're authorizing both the agent's action and the consequent effect it had. In this case, the consequent action must be defined as a new action, to prevent the scenario where the agent directly invokes the backend (instead of the destination)

```
## Option 2

@id("github_connect")
permit (principal, action == Box::Action::"net:connect", resource)
when {
  context.input.host == "api.github.com" &&
  context.input.port == 443
};

@id("backend_connect")
permit (principal, action == Box::Action::"backend:connect", resource) #example action name
when {
  context.input.host == "gateway-1.example.com" &&
  context.input.port == 443
};

```

Other alternatives like (1) authorizing only the backend (2) authorizing on original destination + new backend using same action types are rejected because of poor security posture. With (1) the risk is that policy information be lost, if the backend url is the same across multiple destinations. With (2) if the agent discovers the backend URL, it can reach them directly and avoid any policy configured on the original destination.

**Recommendation:** The recommendation is to go with Option 1. We can introduce policies on Box Actions in the future, if the need arises.

### KD 4: Address-Level Check of the Backend Connection
**Background:** Box decides `net:connect` two times for a direct request. (1) It decides on the host first, before DNS. If this denies, Box does not resolve the host. (2) It decides on each resolved address next, after DNS and before it opens the socket. The address check does two jobs. It pins the result, so Box dials only the address that it
decided. It is also the only check for metadata addresses and private addresses, because the rule reads `context.input.ip`, and the IP is known only at this step.

**Decision:** For a destination that has a backend, Box runs the host check on the original destination, and Box skips the IP check i.e. Box does not run `net:connect` on the backend IP address. Neither does Box try to connect to the original destination.

**Rationale:** The connection to the backend is a Box action, not an agent action. KD 3 states that policy does not apply on Box actions. So the backend address needs no permission, and the address check does not apply to it. The host check still covers the agent's intent, because it runs on the original destination.

This decision keeps the premise "Validate once, then act on the identity you approved". In this case, we validate the agent's intent to connect to a destination, and then Box deterministically re-routes the call to a pre-approved destination, because it's defined in `box.toml` and not derived from the agent's request. The redirect is not a second identity that needs validation.

**Residual risk:** No rule fires on the backend address. If the backend resolves to a metadata address or a private address, no `forbid` stops the connection. This is okay because (1) the backend is trusted by the Box operator (2) The backend cannot be overridden by the agent/workload.