import {
  AgentCoreApplication,
  AgentCoreMcp,
  type AgentCoreProjectSpec,
  type AgentCoreMcpSpec,
} from '@aws/agentcore-cdk';
import { Aspects, CfnOutput, CfnResource, RemovalPolicy, Stack, aws_iam as iam, type StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface AgentCoreStackProps extends StackProps {
  /**
   * The AgentCore project specification containing agents, memories, and credentials.
   */
  spec: AgentCoreProjectSpec;
  /**
   * The MCP specification containing gateways and servers.
   */
  mcpSpec?: AgentCoreMcpSpec;
  /**
   * Credential provider ARNs from deployed state, keyed by credential name.
   */
  credentials?: Record<string, { credentialProviderArn: string; clientSecretArn?: string }>;
}

/**
 * CDK Stack that deploys AgentCore infrastructure.
 *
 * This is a thin wrapper that instantiates L3 constructs.
 * All resource logic and outputs are contained within the L3 constructs.
 */
export class AgentCoreStack extends Stack {
  /** The AgentCore application containing all agent environments */
  public readonly application: AgentCoreApplication;

  constructor(scope: Construct, id: string, props: AgentCoreStackProps) {
    super(scope, id, props);

    const { spec, mcpSpec, credentials } = props;

    // Create AgentCoreApplication with all agents
    this.application = new AgentCoreApplication(this, 'Application', {
      spec,
    });

    Aspects.of(this).add({
      visit(node) {
        if (node instanceof iam.Policy) {
          if (node.node.path.includes('/Runtime/')) {
            node.addStatements(new iam.PolicyStatement({
              actions: ['bedrock:CallWithBearerToken'], resources: ['*'],
              conditions: { StringEquals: { 'bedrock:bearerTokenType': 'SHORT_TERM' } },
            }));
          }

        }
        if (!(node instanceof CfnResource)) return;
        node.applyRemovalPolicy(RemovalPolicy.RETAIN);
        if (node.cfnResourceType === 'AWS::BedrockAgentCore::Runtime') {
          node.addPropertyOverride('PlatformVersion', 'V2');
        }
        if (node.cfnResourceType === 'AWS::ECR::Repository') {
          node.addPropertyOverride('EmptyOnDelete', false);
          node.addPropertyDeletionOverride('LifecyclePolicy');
        }
      },
    });

    // Create AgentCoreMcp if there are gateways configured
    if (mcpSpec?.agentCoreGateways && mcpSpec.agentCoreGateways.length > 0) {
      new AgentCoreMcp(this, 'Mcp', {
        projectName: spec.name,
        mcpSpec,
        agentCoreApplication: this.application,
        credentials,
        projectTags: spec.tags,
      });
    }

    // Stack-level output
    new CfnOutput(this, 'StackNameOutput', {
      description: 'Name of the CloudFormation Stack',
      value: this.stackName,
    });
  }
}
