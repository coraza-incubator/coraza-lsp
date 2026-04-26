# Monaco Editor Integration

This guide explains how to connect Monaco Editor to `coraza-lsp` over a WebSocket.

## 1. Start the server

```bash
coraza-lsp --ws :7999
```

The server listens for WebSocket connections on port 7999.

## 2. Install client libraries

```bash
npm install monaco-editor vscode-ws-jsonrpc monaco-languageclient
```

## 3. Wire up the language client

```typescript
import * as monaco from 'monaco-editor';
import { CloseAction, ErrorAction, MessageTransports } from 'monaco-languageclient';
import { toSocket, WebSocketMessageReader, WebSocketMessageWriter } from 'vscode-ws-jsonrpc';
import { MonacoLanguageClient } from 'monaco-languageclient';

// Register the SecLang language with Monaco.
monaco.languages.register({
  id: 'seclang',
  extensions: ['.conf'],
  aliases: ['SecLang', 'Coraza Rules'],
});

// Create the editor.
const editor = monaco.editor.create(document.getElementById('container')!, {
  language: 'seclang',
  value: '# Paste or type your SecLang rules here\nSecRuleEngine On\n',
});

// Connect to the language server.
const webSocket = new WebSocket('ws://localhost:7999');
webSocket.onopen = () => {
  const socket = toSocket(webSocket);
  const reader = new WebSocketMessageReader(socket);
  const writer = new WebSocketMessageWriter(socket);
  const languageClient = createLanguageClient({ reader, writer });
  languageClient.start();
  reader.onClose(() => languageClient.stop());
};

function createLanguageClient(transports: MessageTransports): MonacoLanguageClient {
  return new MonacoLanguageClient({
    name: 'Coraza SecLang Language Client',
    clientOptions: {
      documentSelector: ['seclang'],
      errorHandler: {
        error: () => ({ action: ErrorAction.Continue }),
        closed: () => ({ action: CloseAction.DoNotRestart }),
      },
    },
    connectionProvider: {
      get: () => Promise.resolve(transports),
    },
  });
}
```

## 4. Self-contained HTML example

See [`example/index.html`](example/index.html) for a complete, bundler-free example using
a CDN build of Monaco and the language client.

## Architecture

```
Browser (Monaco)                     coraza-lsp
     |                                    |
     |-- WebSocket JSON-RPC ----------->  |
     |                                    |  Hand-written parser
     |<- completions, hover, diags -----  |  Knowledge base
                                          |  Coraza WAF oracle
```

The server uses the same protocol handler as the stdio/TCP transports — only the
transport layer changes. Feature parity is guaranteed across all transports.

## CORS / Security

When running in a web browser, ensure the server's WebSocket endpoint is accessible
from the page's origin. For local development, starting on `localhost:7999` with no
TLS is sufficient. For production, proxy via nginx/Caddy with appropriate CORS headers
and TLS termination.

## Embedding the language server in a Go application

The setup above runs `coraza-lsp` as a separate process. If your application is
already a Go HTTP server (typical for web tools that serve SecLang rules from a
database), you can skip the subprocess and embed the language server in-process.
This gives you authenticated WebSocket upgrade in your own handlers, full
control over filesystem access, and no second binary to ship or supervise.

```go
import (
    "net/http"

    "github.com/gorilla/websocket"
    "github.com/coraza-incubator/coraza-lsp/pkg/lsp"
)

func lspHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Authenticate the upgrade in your normal middleware chain — JWT,
    //    session cookie, API key, whatever you already use. Reject before
    //    upgrading so unauthorised clients never see a WebSocket.

    upgrader := websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool { /* same-origin check */ return true },
    }
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        return
    }
    defer conn.Close()

    // 2. Build a per-connection FileSystem snapshot from your data source
    //    (database, object storage, etc). The LSP cannot reach beyond it.
    files := loadFilesForCurrentSession(r) // map[string][]byte
    srv := lsp.New("my-app/1.0", lsp.WithFileSystem(lsp.NewMemFS(files)))

    // 3. Drive the LSP over the upgraded connection. Blocks until the
    //    client disconnects, then the per-session Server is GC'd.
    srv.ServeWebSocket(conn)
}
```

Key points:

- `lsp.WithFileSystem` is **mandatory** for multi-tenant deployments. Without
  it the server reads directly from the host's disk — fine for a CLI, dangerous
  for a web app where one tenant's `Include` directive could read another
  tenant's files.
- One `*lsp.Server` per WebSocket connection is the recommended model. The
  constructor is cheap, and per-connection isolation makes cross-tenant
  leakage impossible by construction.
- `lsp.NewMemFS(map[string][]byte)` is the easiest sandboxed FileSystem; for
  custom storage backends, implement `lsp.FileSystem` directly.
- See `pkg/lsp/embed_test.go` for an executable example that exercises the
  full embedding API.
