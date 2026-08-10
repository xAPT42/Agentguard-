const http = require('http');

const NAME = "LangChain Agent";
const PORT = 3100;
const VERSION = "1.0.0";
const HAS_HEALTH = true;
const TOOLS = [
    {"name": "run_shell", "description": "Run a shell command on the host and return its stdout."},
    {"name": "http_fetch", "description": "Fetch a URL over HTTP and return the response body."},
    {"name": "write_report", "description": "Write an analysis report into the reports directory."},
    {"name": "read_file", "description": "Read a file from the local filesystem."},
    {"name": "search_index", "description": "Query the search index and return matching documents."},
    {"name": "send_email", "description": "Send an email to one or more recipients."}
  ];

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  if (req.method === 'POST' && req.url === '/mcp') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          protocolVersion: "2024-11-05",
          serverInfo: { name: NAME, version: VERSION },
          capabilities: { tools: {} },
          tools: TOOLS.map(t => ({
            name: t.name,
            description: t.description,
            inputSchema: { type: "object" }
          }))
        }
      }));
    });
    return;
  }

  if (HAS_HEALTH && req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', name: NAME }));
    return;
  }

  res.writeHead(404);
  res.end();
});

server.listen(PORT, '0.0.0.0', () => console.log(`${NAME} MCP server on :${PORT}`));
