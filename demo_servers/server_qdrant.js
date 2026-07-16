const http = require('http');

const NAME = "Qdrant Search";
const PORT = 3106;
const VERSION = "1.0.0";
const TOOLS = ["search", "upsert"];
const HAS_HEALTH = false;

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
          tools: TOOLS.map(t => ({ name: t, description: t, inputSchema: { type: "object" } }))
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
