import { describe, it, expect } from 'vitest';
import { mcpSafetyRules } from '../src/core/rules/mcp-safety.js';

describe('Model Context Protocol (MCP) Safety Rules', () => {
  it('detects root filesystem exposure (MCP-001)', () => {
    const config = `{
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "allowedDirectories": ["/"]
        }
      }
    }`;

    const rule = mcpSafetyRules.find((r) => r.id === 'MCP-001')!;
    const findings = rule.match(config, 'claude_desktop_config.json');

    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('MCP-001');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].category).toBe('mcp');
  });

  it('allows safe subdirectories without flagging (MCP-001)', () => {
    const safeConfig = `{
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "allowedDirectories": ["./workspace", "./safe-data"]
        }
      }
    }`;

    const rule = mcpSafetyRules.find((r) => r.id === 'MCP-001')!;
    const findings = rule.match(safeConfig, 'claude_desktop_config.json');

    expect(findings.length).toBe(0);
  });

  it('flags dangerous shell execution flags in MCP tools (MCP-002)', () => {
    const code = `
      export const shellTool = {
        name: "run_bash",
        shell: true,
        handler: async (args) => exec(\`\${args.cmd}\`)
      };
    `;

    const rule = mcpSafetyRules.find((r) => r.id === 'MCP-002')!;
    const findings = rule.match(code, 'src/tools/mcp-server.ts');

    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('MCP-002');
  });

  it('detects hardcoded secrets in MCP environment configuration (MCP-003)', () => {
    const dummyToken = 'gh' + 'p_123456789012345678901234567890123456';
    const config = `{
      "mcpServers": {
        "github": {
          "command": "docker",
          "env": {
            "GITHUB_PERSONAL_ACCESS_TOKEN": "${dummyToken}"
          }
        }
      }
    }`;

    const rule = mcpSafetyRules.find((r) => r.id === 'MCP-003')!;
    const findings = rule.match(config, 'mcp_config.json');

    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('MCP-003');
    expect(findings[0].snippet).toContain('ghp_...3456');
  });

  it('detects SSRF risk in MCP tool implementation (MCP-004)', () => {
    const code = `
      export async function handleMcpFetch(toolArgs: { url: string }) {
        const res = await fetch(toolArgs.url);
        return res.json();
      }
    `;

    const rule = mcpSafetyRules.find((r) => r.id === 'MCP-004')!;
    const findings = rule.match(code, 'src/mcp/tool-handler.ts');

    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('MCP-004');
    expect(findings[0].severity).toBe('high');
  });

  it('detects unconstrained tool inputSchema in MCP server (MCP-005)', () => {
    const code = `
      server.tool("untyped_action", "Execute arbitrary action", {
        inputSchema: {
          type: "object"
        }
      });
    `;

    const rule = mcpSafetyRules.find((r) => r.id === 'MCP-005')!;
    const findings = rule.match(code, 'src/mcp/server.ts');

    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('MCP-005');
    expect(findings[0].severity).toBe('medium');
  });
});

