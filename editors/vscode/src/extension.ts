import * as path from 'path';
import * as vscode from 'vscode';
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
// Persistent across restarts so the output channel history is preserved.
let outputChannel: vscode.OutputChannel | undefined;
let traceOutputChannel: vscode.OutputChannel | undefined;

function createClient(): LanguageClient {
  const config = vscode.workspace.getConfiguration('coraza-lsp');
  const serverPath: string = config.get('serverPath') ?? 'coraza-lsp';

  // Resolve relative paths against the workspace root.
  const resolvedPath = path.isAbsolute(serverPath)
    ? serverPath
    : serverPath; // Let the OS resolve via $PATH.

  const serverOptions: ServerOptions = {
    command: resolvedPath,
    args: ['--stdio'],
    transport: TransportKind.stdio,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: 'file', language: 'seclang' }],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher('**/*.conf'),
    },
    outputChannel,
    traceOutputChannel,
  };

  return new LanguageClient('coraza-lsp', 'Coraza SecLang', serverOptions, clientOptions);
}

export function activate(context: vscode.ExtensionContext): { client: LanguageClient } {
  outputChannel = vscode.window.createOutputChannel('Coraza SecLang');
  traceOutputChannel = vscode.window.createOutputChannel('Coraza SecLang (trace)');

  client = createClient();
  client.start();
  context.subscriptions.push(client);

  context.subscriptions.push(
    vscode.commands.registerCommand('coraza-lsp.restartServer', async () => {
      if (client) {
        await client.stop();
        client.dispose();
      }
      client = createClient();
      client.start();
      context.subscriptions.push(client);
      vscode.window.showInformationMessage('Coraza language server restarted.');
    }),

    vscode.commands.registerCommand('coraza-lsp.showOutputChannel', () => {
      outputChannel?.show();
    }),
  );

  return { client };
}

export async function deactivate(): Promise<void> {
  if (client) {
    await client.stop();
    client = undefined;
  }
}
