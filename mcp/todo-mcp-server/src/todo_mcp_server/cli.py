#!/usr/bin/env python3
import argparse
import os
from .server import create_server
from .utils.logger import get_logger

logger = get_logger()


def parse_args():
    parser = argparse.ArgumentParser(description="Todo MCP Server")
    parser.add_argument(
        "--api-url", help="Todo API URL", default="http://localhost:8000"
    )
    parser.add_argument("--env-file", help="Path to .env file")
    parser.add_argument(
        "--log-level",
        help="Log level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    parser.add_argument(
        "--transport",
        help="Transport type",
        choices=["stdio", "streamable-http"],
        default="streamable-http",
    )
    parser.add_argument(
        "--port", help="Port for streamable-http", type=int, default=8080
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Set environment variables
    os.environ["TODO_API_URL"] = args.api_url
    os.environ["LOG_LEVEL"] = args.log_level

    logger.info(f"Starting Todo MCP Server with {args.transport} transport")

    # Create and run server with port configuration
    server = create_server(
        env_file_path=args.env_file, host="127.0.0.1", port=args.port
    )

    if args.transport == "streamable-http":
        server.run(transport="streamable-http")
    else:
        server.run(transport="stdio")


if __name__ == "__main__":
    main()
