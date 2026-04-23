# Publishing the Coraza SecLang VS Code extension

The extension publishes automatically when you push a tag of the form
`vscode-v<semver>` (e.g. `vscode-v0.1.0`). The
[`.github/workflows/release-vscode.yml`](../../.github/workflows/release-vscode.yml)
workflow then:

1. Verifies the tag's semver matches `editors/vscode/package.json` → `version`.
2. Compiles TypeScript, packages a `.vsix`.
3. Publishes to the **VS Code Marketplace** (if `VSCE_PAT` is configured).
4. Publishes to **Open VSX** (if `OVSX_PAT` is configured) — reaches VSCodium,
   Gitpod, code-server, Eclipse Theia, etc.
5. Attaches the `.vsix` to the GitHub release for manual install.

Missing secrets cause a warning, not a failure — you always get a GitHub
release with the `.vsix` you can publish later.

## One-time setup

### 1. VS Code Marketplace publisher

Reference: <https://code.visualstudio.com/api/working-with-extensions/publishing-extension>

1. Sign in to an Azure DevOps account at <https://dev.azure.com>.
   Any Microsoft account works; no organization subscription needed.
2. Create a Personal Access Token:
   - Top-right user menu → **Personal access tokens** → **New Token**.
   - **Organization**: *All accessible organizations* (required).
   - **Scopes**: *Custom defined* → expand **Marketplace** → tick **Manage**.
   - **Expiration**: 1 year is fine; set a calendar reminder to rotate.
3. Copy the token (you won't see it again).
4. If the publisher `corazawaf` doesn't exist yet (or you want a different
   one), create it at <https://marketplace.visualstudio.com/manage> →
   **Create publisher**. Update `editors/vscode/package.json` → `publisher`
   if you use a different name.
5. Save the token as a repo secret:

   ```bash
   gh secret set VSCE_PAT --repo coraza-incubator/coraza-lsp --body '<PAT>'
   ```

### 2. Open VSX registry (recommended for OSS reach)

Open VSX is the Eclipse Foundation's open registry — it's what VSCodium,
Gitpod, and similar VS Code forks pull from.

1. Sign in at <https://open-vsx.org> with your GitHub account.
2. Settings → **Access Tokens** → **Generate new token**.
3. Before the first publish, claim the `corazawaf` namespace:

   ```bash
   npx ovsx create-namespace corazawaf --pat <OVSX_TOKEN>
   ```

4. Save the token:

   ```bash
   gh secret set OVSX_PAT --repo coraza-incubator/coraza-lsp --body '<PAT>'
   ```

### 3. Verify

```bash
gh secret list --repo coraza-incubator/coraza-lsp
# Should list VSCE_PAT and (optionally) OVSX_PAT
```

## Releasing

```bash
# 1. Bump version in editors/vscode/package.json (e.g. 0.1.0 → 0.2.0)
# 2. Commit + push to develop, merge to main
# 3. Tag and push:
git tag -a vscode-v0.2.0 -m "VS Code extension v0.2.0"
git push origin vscode-v0.2.0
```

The workflow runs in ~2 minutes. Watch it with:

```bash
gh run watch --repo coraza-incubator/coraza-lsp
```

## Verifying a release locally before tagging

```bash
cd editors/vscode
npm ci
npm run compile
npx --yes @vscode/vsce package          # produces a .vsix without publishing
code --install-extension *.vsix         # sanity-install into your own VS Code
```

If `vsce package` complains about LICENSE, README, or missing repo metadata,
fix those before tagging — the Marketplace is strict about manifest hygiene.

## Unpublishing

Rarely needed. Marketplace:

```bash
npx --yes @vscode/vsce unpublish corazawaf.coraza-lsp --pat <VSCE_PAT>
```

Prefer bumping the version with a fix over unpublishing — Marketplace users
get the update automatically.

## Troubleshooting

- **"Publisher 'corazawaf' not found"**: create the publisher at
  <https://marketplace.visualstudio.com/manage>, or update the `publisher`
  field in `package.json` to match a publisher you own.
- **Tag/version mismatch**: the workflow fails fast. Fix the version in
  `package.json`, commit, delete the bad tag (`git push --delete origin
  vscode-vX.Y.Z`) and re-tag.
- **"error TS..." during compile**: run `npm run compile` locally to
  reproduce before tagging.
