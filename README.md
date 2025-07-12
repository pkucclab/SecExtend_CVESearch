# SecExtend CVESearch
Fscan component of the SecExtend project

# Quick Start

First, build the image and start the container

```shell
git clone https://github.com/pkucclab/SecExtend_CVESearch.git
cd SecExtend_CVESearch
docker compose up -d
```

Then configure the configuration file of the MCP server, as shown below

```json
{
  "mcpServers": {
    "SecExtend_CVESearch": {
      "url": "http://127.0.0.1:8000/sse",
      "disabled": false,
      "autoApprove": [],
      "timeout": 1800
    }
  }
}
```
Port 8000 is exposed by default