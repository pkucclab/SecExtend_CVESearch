# SecExtend Fscan
Fscan component of the SecExtend project

# Quick Start

First, build the image and start the container

```shell
git clone https://github.com/pkucclab/SecExtend_Fscan.git
cd SecExtend_Fscan
docker -t secextend_fscan .
docker run -p 8000:8000 secextend_fscan
```

Then configure the configuration file of the MCP server, as shown below

```json
{
  "mcpServers": {
    "SecExtend_Fscan": {
      "url": "http://127.0.0.1:8000/sse",
      "disabled": false,
      "autoApprove": [],
      "timeout": 1800
    }
  }
}
```
Port 8000 is exposed by default