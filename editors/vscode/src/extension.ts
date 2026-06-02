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
        await stopClient(client);
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

    vscode.commands.registerCommand('coraza-lsp.gotoRule', gotoRuleById),
  );

  return { client };
}

// gotoRuleById prompts for a rule id and jumps to the matching SecRule, reusing
// the language server's workspace-symbol index (rules are indexed by id). No
// custom LSP request is needed — this drives the standard workspace symbol
// provider the server already implements.
async function gotoRuleById(preset?: string): Promise<void> {
  const id =
    preset ??
    (await vscode.window.showInputBox({
      title: 'Coraza: Go to Rule by ID',
      prompt: 'Enter a SecRule id',
      placeHolder: 'e.g. 942100',
      validateInput: (v) => (/^\d+$/.test(v.trim()) ? undefined : 'Enter a numeric rule id'),
    }));
  if (!id) {
    return;
  }
  const ruleId = id.trim();

  const symbols =
    (await vscode.commands.executeCommand<vscode.SymbolInformation[]>(
      'vscode.executeWorkspaceSymbolProvider',
      ruleId,
    )) ?? [];

  // The server labels rules as "<Directive> <id>" or "<Directive> <id>: <msg>".
  // Match on the id token so a query like "42" doesn't jump to rule 9942100.
  const matches = symbols.filter((s) => {
    const parts = s.name.split(/\s+/);
    const idTok = parts[1]?.replace(/:$/, '');
    return idTok === ruleId;
  });

  if (matches.length === 0) {
    vscode.window.showWarningMessage(
      `No rule with id ${ruleId} found. Open the rule files (or set "global": true in .coraza.json) so they are indexed.`,
    );
    return;
  }

  const target =
    matches.length === 1
      ? matches[0]
      : (
          await vscode.window.showQuickPick(
            matches.map((s) => ({
              label: s.name,
              description: vscode.workspace.asRelativePath(s.location.uri),
              symbol: s,
            })),
            { title: `Multiple rules with id ${ruleId}` },
          )
        )?.symbol;
  if (!target) {
    return;
  }

  const doc = await vscode.workspace.openTextDocument(target.location.uri);
  const editor = await vscode.window.showTextDocument(doc);
  editor.selection = new vscode.Selection(target.location.range.start, target.location.range.start);
  editor.revealRange(target.location.range, vscode.TextEditorRevealType.InCenter);
}

// stopClient stops a LanguageClient tolerantly. LanguageClient.stop() rejects
// when the client is still in the Starting state ("Client is not running and
// can't be stopped"); a user hitting "restart" right after activation, or
// deactivate firing mid-startup, would otherwise throw. We swallow that case —
// the subsequent dispose()/replacement handles cleanup.
async function stopClient(c: LanguageClient): Promise<void> {
  try {
    await c.stop();
  } catch {
    // client was still starting or already stopped — nothing to do.
  }
}

export async function deactivate(): Promise<void> {
  if (client) {
    await stopClient(client);
    client = undefined;
  }
}
