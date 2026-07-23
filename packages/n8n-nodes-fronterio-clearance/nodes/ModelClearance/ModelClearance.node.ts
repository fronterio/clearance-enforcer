import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from "n8n-workflow";
import { NodeOperationError } from "n8n-workflow";

/**
 * Fronterio Model Clearance node: ask "may this workflow send these data
 * classes to this model?" BEFORE the model node runs. Returns the
 * green/yellow/red verdict + reasons + recommended alternatives; optionally
 * stops the workflow on red. Fronterio decides — your workflow enforces.
 */
export class ModelClearance implements INodeType {
  description: INodeTypeDescription = {
    displayName: "Fronterio Model Clearance",
    name: "fronterioModelClearance",
    icon: "file:fronterio.svg",
    group: ["transform"],
    version: 1,
    subtitle: '={{$parameter["model"]}}',
    description:
      "Check a model use against your Fronterio routing policy (green/yellow/red) before calling the model",
    defaults: { name: "Model Clearance" },
    inputs: ["main"],
    outputs: ["main"],
    credentials: [{ name: "fronterioApi", required: true }],
    properties: [
      {
        displayName: "Model",
        name: "model",
        type: "string",
        default: "",
        required: true,
        placeholder: "DeepSeek V4 Flash",
        description: "Register model ID or model name",
      },
      {
        displayName: "Data Classes",
        name: "dataClasses",
        type: "multiOptions",
        options: [
          { name: "Public", value: "public" },
          { name: "Internal", value: "internal" },
          { name: "Customer Data", value: "customer_data" },
          { name: "Personal Data", value: "personal_data" },
          { name: "Special Category", value: "special_category" },
          { name: "Financial", value: "financial" },
          { name: "Credentials", value: "credentials" },
        ],
        default: ["internal"],
        required: true,
        description: "Data classes present in the payload about to be sent",
      },
      {
        displayName: "Agent Reference",
        name: "agentRef",
        type: "string",
        default: "",
        description:
          "Optional agent reference — a Fronterio agent UUID scopes agent-specific rules",
      },
      {
        displayName: "Stop Workflow on Red",
        name: "blockOnRed",
        type: "boolean",
        default: true,
        description: "Whether to fail this execution when the verdict is red",
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const returnData: INodeExecutionData[] = [];

    for (let i = 0; i < items.length; i += 1) {
      const model = this.getNodeParameter("model", i) as string;
      const dataClasses = this.getNodeParameter("dataClasses", i) as string[];
      const agentRef = this.getNodeParameter("agentRef", i) as string;
      const blockOnRed = this.getNodeParameter("blockOnRed", i) as boolean;

      const decision = (await this.helpers.httpRequestWithAuthentication.call(
        this,
        "fronterioApi",
        {
          method: "POST",
          url: "/api/v1/model-use/check",
          body: {
            model,
            dataClasses,
            agentRef: agentRef || undefined,
          },
          json: true,
        },
      )) as {
        verdict: string;
        decisionId: string | null;
        reasons: unknown[];
        unmetConditions: string[];
        recommendedAlternatives: unknown[];
      };

      if (decision.verdict === "red" && blockOnRed) {
        throw new NodeOperationError(
          this.getNode(),
          `Blocked by model routing policy (decision ${decision.decisionId ?? "n/a"})`,
          { itemIndex: i },
        );
      }

      returnData.push({
        json: { ...items[i].json, fronterioClearance: decision },
        pairedItem: { item: i },
      });
    }

    return [returnData];
  }
}
