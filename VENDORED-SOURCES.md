# Vendored MCP Sources

Every MCP implementation used by this repository is stored locally. Dockerfiles must build from the corresponding `vendor/` directory and must not clone or install an upstream MCP server at build or runtime.

| MCP | Upstream repository | Commit |
| --- | --- | --- |
| `tools/reconnaissance/shodan-mcp` | `BurtTheCoder/mcp-shodan` | `59c70b91647a22b338bad04ac6269650af5a6f0f` |
| `tools/reconnaissance/networksdb-mcp` | `MorDavid/NetworksDB-MCP` | `812513953129afefdb9646f9fe4999ee25f7e6b8` |
| `tools/reconnaissance/zoomeye-mcp` | `zoomeye-ai/mcp_zoomeye` | `f82ca2da19597b54bb5658a23cd4f5644736c89e` |
| `tools/osint/dnstwist-mcp` | `BurtTheCoder/mcp-dnstwist` | `af62d09328f762a3581cd354997299ed0a758c11` |
| `tools/osint/maigret-mcp` | `BurtTheCoder/mcp-maigret` | `1a7c9a4b1e4e8ffd12ac03058aee3e90161f1846` |
| `tools/threat-intel/otx-mcp` | `mrwadams/otx-mcp` | `ca9f76616867a1881c174ae2906b57f87a7b617d` |
| `tools/threat-intel/virustotal-mcp` | `BurtTheCoder/mcp-virustotal` | `364ce0d0fb505644c52ed1a83c4f3d5f10abee1f` |
| `tools/web-security/burp-mcp` | `PortSwigger/mcp-server` | `642e6fa31c63db3886a353fcd7ed62037e0ceed5` |
| `tools/web-security/nikto-mcp` | `weldpua2008/nikto-mcp` | `7ff8fe072debd6a7431f9f3701a0ab2e4ab35acc` |
| `tools/meta/mcp-scan` | `invariantlabs-ai/mcp-scan` | `a59b55af25196cefbad754cf1281b6cc6a11a722` |

`tools/web-security/nikto-mcp/vendor/nikto` also vendors Nikto scanner source from `sullo/nikto` at `312645d873478a77986627ab1fc8cffe595e85d4`.
