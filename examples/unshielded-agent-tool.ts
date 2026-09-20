/**
 * Example AI Agent Tool implementation for AgentGuard-CI demonstration.
 * This demonstrates how AgentGuard-CI detects common security oversights
 * in AI Agent tooling and Prompt construction.
 */

// 1. Unshielded SSRF in Agent Tool Execution (AIS-007)
// The model supplies an arbitrary target URL without loopback or private network shielding.
export async function executeFetchWebpage(toolArgs: { url: string }): Promise<string> {
  const response = await fetch(toolArgs.url);
  return response.text();
}

// 2. Benign Prompt with Safe Identifier (No False Positive)
export function buildWelcomeMessage(user_id: string, role: string) {
  return {
    role: 'system',
    content: `User session ID: ${user_id}, role: ${role}. Assist politely.`
  };
}

// 3. Inline Suppression Demo (agentguard-ignore)
// Suppressing a known safe evaluation for demonstration:
const dummyData = "eval(modelResponse)"; // agentguard-ignore: AIS-002
