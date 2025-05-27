from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl
from .tool_registry import tool_registry
import mcp.server.stdio
import mcp.server.sse
import argparse
import uvicorn
import logging
from starlette.applications import Starlette
from starlette.routing import Route, Mount

# Store notes as a simple key-value dict to demonstrate state management
notes: dict[str, str] = {}
logger = logging.getLogger(__name__)
server = Server("SecExtend_Fscan")

@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """
    List available note resources.
    Each note is exposed as a resource with a custom note:// URI scheme.
    """
    return [
        types.Resource(
            uri=AnyUrl(f"note://internal/{name}"),
            name=f"Note: {name}",
            description=f"A simple note named {name}",
            mimeType="text/plain",
        )
        for name in notes
    ]

@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """
    Read a specific note's content by its URI.
    The note name is extracted from the URI host component.
    """
    if uri.scheme != "note":
        raise ValueError(f"Unsupported URI scheme: {uri.scheme}")

    name = uri.path
    if name is not None:
        name = name.lstrip("/")
        return notes[name]
    raise ValueError(f"Note not found: {name}")

@server.list_prompts()
async def handle_list_prompts() -> list[types.Prompt]:
    """
    List available prompts.
    Each prompt can have optional arguments to customize its behavior.
    """
    return [
        types.Prompt(
            name="summarize-notes",
            description="Creates a summary of all notes",
            arguments=[
                types.PromptArgument(
                    name="style",
                    description="Style of the summary (brief/detailed)",
                    required=False,
                )
            ],
        )
    ]

@server.get_prompt()
async def handle_get_prompt(
    name: str, arguments: dict[str, str] | None
) -> types.GetPromptResult:
    """
    Generate a prompt by combining arguments with server state.
    The prompt includes all current notes and can be customized via arguments.
    """
    if name != "summarize-notes":
        raise ValueError(f"Unknown prompt: {name}")

    style = (arguments or {}).get("style", "brief")
    detail_prompt = " Give extensive details." if style == "detailed" else ""

    return types.GetPromptResult(
        description="Summarize the current notes",
        messages=[
            types.PromptMessage(
                role="user",
                content=types.TextContent(
                    type="text",
                    text=f"Here are the current notes to summarize:{detail_prompt}\n\n"
                    + "\n".join(
                        f"- {name}: {content}"
                        for name, content in notes.items()
                    ),
                ),
            )
        ],
    )


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """
    List available tools.
    Each tool specifies its arguments using JSON Schema validation.
    """
    return [
        types.Tool(
            name=tool_info['name'],
            description=tool_info['description'],
            inputSchema=tool_info['input_schema'],
        )
        for tool_info in tool_registry.list_tools()
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """
    Handle tool execution requests.
    Tools can modify server state and notify clients of changes.
    """
    try:
        tool = tool_registry.get_tool(name)
        result = await tool.execute(arguments or {})
        
        # Notify clients that resources have changed
        await server.request_context.session.send_resource_list_changed()
        
        return result
    except ValueError as e:
        raise ValueError(f"Tool error: {str(e)}")


async def run_stdio_server():
    """basic local stdio server, default"""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="SecExtend_Fscan",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


async def run_sse_server():
    """remote mcp server, use http+sse"""
    sse = mcp.server.sse.SseServerTransport("/messages/")
    
    async def handle_sse(request):
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await server.run(
                streams[0], streams[1], 
                InitializationOptions(
                    server_name="SecExtend_Fscan",
                    server_version="0.1.0",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    )
                )
            )

    routes = [
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse.handle_post_message),
    ]

    starlette_app = Starlette(routes=routes)

    config = uvicorn.Config(
        starlette_app,
        host="0.0.0.0",
        port=8000,
        log_config=None,
    )

    app = uvicorn.Server(config)
    logger.info("SSE server is starting on port 8000...")
    await app.serve()



async def main():
    parser = argparse.ArgumentParser(description='SecExtend Server')
    parser.add_argument('--mode', choices=['sse', 'stdio'], default='stdio',
                        help='Server running mode (default: stdio)')
    
    args = parser.parse_args()
    
    if args.mode == 'sse':
        await run_sse_server()
    else:
        await run_stdio_server()