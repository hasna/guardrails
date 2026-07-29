import { describe, expect, test } from "bun:test";
import { collectSearchText, collectTextFields, defaultSecretRedactionRules, detectRedactions, sha256 } from "../src";
import type { GuardrailInput } from "../src";

describe("redaction", () => {
  test("collects searchable text across every supported context", () => {
    const circular: Record<string, unknown> = { label: "placeholder-circular" };
    circular.self = circular;
    const input: GuardrailInput = {
      operationType: "prompt",
      subject: "subject",
      prompt: {
        text: "prompt",
        messages: [
          { role: "user", content: "message" },
          { role: "assistant", content: [{ type: "text", text: "structured" }] },
          { role: "tool", content: null },
        ],
      },
      action: { id: "action-id", name: "action-name", kind: "action-kind", input: circular, preview: { ok: true } },
      shell: { command: "placeholder-command", args: ["first", "second"] },
      mcp: {
        serverId: "server-id",
        serverName: "server-name",
        toolName: "tool-name",
        arguments: { placeholder: true },
      },
      browser: { url: "https://example.invalid", domain: "example.invalid", action: "navigate" },
      computer: { app: "app", action: "click", screenText: "screen" },
      runtime: { path: "/tmp/placeholder", host: "localhost", packageName: "placeholder-package" },
      modelRouting: { requestedModel: "requested", selectedModel: "selected", provider: "provider" },
      secretAccess: { secretName: "PLACEHOLDER_SECRET", source: "placeholder-source" },
      sourceAccess: { uri: "file:///tmp/placeholder", license: "Apache-2.0" },
      business: { operation: "refund", resource: "invoice" },
      content: { text: "content", json: { placeholder: "json" } },
    };

    const fields = collectTextFields(input);
    expect(fields.map((field) => field.path)).toContain("prompt.messages.1.content");
    expect(fields.find((field) => field.path === "action.input")?.value).toBe("[object Object]");
    expect(fields.some((field) => field.value.includes("placeholder"))).toBe(true);
    expect(collectSearchText(input)).toContain("structured");
  });

  test("honors exact, parent, and wildcard paths and records safe hashes", () => {
    const input: GuardrailInput = {
      operationType: "prompt",
      prompt: {
        text: "PLACEHOLDER_TOKEN and placeholder_token",
        messages: [{ role: "user", content: "PLACEHOLDER_TOKEN" }],
      },
      content: { text: "PLACEHOLDER_TOKEN" },
    };
    const redactions = detectRedactions(input, "redaction-policy", [
      { id: "prompt-only", pattern: "(?i)placeholder_token", replacement: "[masked]", paths: ["prompt"] },
      { pattern: "PLACEHOLDER_TOKEN", paths: ["content.text"] },
      { id: "wildcard", pattern: "does-not-match", paths: ["*"] },
    ]);

    expect(redactions).toHaveLength(4);
    expect(redactions[0]).toEqual({
      policyId: "redaction-policy",
      path: "prompt.text",
      replacement: "[masked]",
      originalSha256: sha256("PLACEHOLDER_TOKEN"),
      start: 0,
      end: 17,
      ruleId: "prompt-only",
    });
    expect(redactions.at(-1)).toMatchObject({ path: "content.text", replacement: "[redacted]" });
    expect(JSON.stringify(redactions)).not.toContain("PLACEHOLDER_TOKEN");
  });

  test("default rule pack detects representative placeholder secret formats", () => {
    const placeholderValues = [
      "sk-PLACEHOLDER0000",
      "sk_test_PLACEHOLDER0000",
      "ghp_PLACEHOLDER000000000000",
      "github_pat_PLACEHOLDER000000000000",
      "xoxb-PLACEHOLDER-0000",
      "AIzaPLACEHOLDER000000000000",
      "eyJPLACEHOLDER.eyJPLACEHOLDER.SIGNATUREPLACEHOLDER",
      "Bearer PLACEHOLDER_TOKEN_0000",
    ];
    const input: GuardrailInput = { operationType: "prompt", prompt: { text: placeholderValues.join("\n") } };
    const rules = defaultSecretRedactionRules();
    const redactions = detectRedactions(input, "default-secrets", rules);

    expect(rules).toHaveLength(8);
    expect(redactions.map((redaction) => redaction.ruleId)).toEqual(rules.map((rule) => rule.id));
    expect(redactions.every((redaction) => redaction.replacement === "[redacted-secret]")).toBe(true);
  });
});
