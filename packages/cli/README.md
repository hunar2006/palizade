# Palizade

MCP-native prompt-injection firewall and security proxy for agent/tool pipelines.

```bash
npx palizade init
npx palizade install-config --all
npx palizade doctor
npx palizade wrap <serverName>
```

`install-config --all` wraps configured MCP servers in the target client config. It does not protect native client tools such as Claude Code's built-in Read, Write, or Bash tools.

Full docs and source: https://github.com/hunar2006/palizade
