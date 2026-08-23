# Security Hub Gateway MCP

One stdio MCP endpoint that manages the registered security-hub MCP images.
It starts a child container only when a tool is first used or when the agent
explicitly calls `gateway_prewarm`. `gateway_shutdown` releases an idle child;
the gateway refuses to interrupt active work and removes all children on exit.

## Build and run

```powershell
docker compose build
docker build -t security-hub-gateway:latest ./gateway-mcp
docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock security-hub-gateway:latest
```

Build the child images you plan to use before starting the gateway; `docker
compose build` builds the full registered collection. The Docker socket lets
this trusted local gateway create the isolated child containers. Do not expose
this gateway or its Docker socket to a network.

## MCP client configuration

```json
{
  "mcpServers": {
    "security-hub": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "security-hub-gateway:latest"
      ]
    }
  }
}
```

Use `gateway_list_component_tools` to retrieve the child tool schema, then
call it through `gateway_call`. Lifecycle inputs are fixed registry IDs; Docker
images, commands, and container identifiers are never accepted from the agent.
