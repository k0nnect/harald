# runs harald's mcp server over stdio, which is how glama checks that it starts and
# lists its tools. a container has no bluetooth radio, so the tools that scan or
# connect report an error there.
FROM python:3.13-slim

# pinned to the uv that wrote uv.lock, like ci
COPY --from=ghcr.io/astral-sh/uv:0.12.9 /uv /bin/uv

WORKDIR /app
COPY . .
RUN uv sync --locked --no-dev --no-editable --no-cache

ENV PATH="/app/.venv/bin:$PATH"
CMD ["harald", "mcp"]
