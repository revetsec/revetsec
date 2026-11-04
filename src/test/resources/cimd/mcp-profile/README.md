# MCP/CIMD profile fixtures

`mcp-reference.json` is the JSON example from the pinned MCP 2026-07-28 client-registration page: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration . It was extracted from the project's October 2 archival read. The example omits `application_type` and contains both an IP-literal and a localhost HTTP callback.

The Claude Code and VS Code JSON files are byte-preserved October 29 captures already used for the adopted SR-1 planning review. Tests distinguish unmodified documents from explicitly constructed variants. The VS Code capture lists an extra device-code grant; the metadata profile ignores that declaration while keeping issuance restricted to supported grants. Document tests do not establish interoperability with a running released client.

Fixture SHA-256 values:

- `claude-code-client-metadata.json`: `844b69e632732c325e3bae21ab324fa3d5353ba2e15890a384e8885e9837e5a4`
- `mcp-reference.json`: `efd088bdc9bdc37abbdc289b7cb218797124cc122827aa376b03ddfc14e5a0cd`
- `vscode-client-metadata.json`: `ef2f099373c6417e4e7753e38d3832489ca2e3797a0a60cc4ae82a4095442ad2`
