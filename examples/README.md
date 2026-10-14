# MCP client examples

Build the single image with `docker compose build`, then use one of the JSON
examples as the client configuration. Replace `example.com` with the authorized
target scope. Keep the gateway container attached to stdin for the session.

To disable a reviewed component or tool, edit `tool_setting.ini`, rebuild the
image, and restart the client. A deployment can instead mount a reviewed copy
of the file read-only at `/opt/security-hub/tool_setting.ini`.

Local file review requires an explicit read-only host mount for the approved
input path. Do not mount a broad host directory or a Docker socket.
