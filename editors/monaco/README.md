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
