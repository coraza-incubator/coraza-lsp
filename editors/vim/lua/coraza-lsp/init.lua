-- coraza-lsp: Neovim plugin for OWASP Coraza / ModSecurity SecLang files.
--
-- Requires Neovim 0.8+. For classic Vim, use the ALE linter at:
--   ale_linters/seclang/coraza_lsp.vim
--
-- Quick start (add to your init.lua):
--   require('coraza-lsp').setup()
--
-- With options:
--   require('coraza-lsp').setup({
--     server_path = '/usr/local/bin/coraza-lsp',
--     on_attach   = function(client, bufnr)
--       vim.keymap.set('n', 'K',  vim.lsp.buf.hover,          { buffer = bufnr })
--       vim.keymap.set('n', 'gd', vim.lsp.buf.definition,     { buffer = bufnr })
--       vim.keymap.set('n', '<leader>ca', vim.lsp.buf.code_action, { buffer = bufnr })
--     end,
--   })
--
-- Users with nvim-lspconfig can alternatively call:
--   require('coraza-lsp').setup()          -- registers the server config
--   require('lspconfig').coraza_lsp.setup({})  -- then let lspconfig manage it

local M = {}
local lsp = require('coraza-lsp.lsp')

--- Default configuration — mirrors the VS Code extension's settings schema.
local defaults = {
  -- Path to the coraza-lsp binary. Resolved via $PATH when a plain name is given.
  server_path = 'coraza-lsp',
  -- Extra CLI arguments appended after '--stdio', e.g. { '-v' } for verbose logs.
  cmd_extra_args = {},
  -- Callback invoked when the LSP client attaches: function(client, bufnr)
  on_attach = nil,
  -- LSP capabilities override. Defaults to vim.lsp.protocol.make_client_capabilities().
  capabilities = nil,
  -- Filetypes the server should attach to.
  filetypes = { 'seclang' },
  -- Workspace root directory. nil = parent directory of the opened file.
  root_dir = nil,
  -- Arbitrary settings forwarded via workspace/didChangeConfiguration.
  settings = {},
}

local _initialized = false
local _opts = {}

--- Set up the coraza-lsp plugin. Call once in your Neovim config.
---@param opts? table Configuration overrides (see defaults above).
function M.setup(opts)
  if vim.fn.has('nvim-0.8') ~= 1 then
    vim.notify(
      'coraza-lsp: Neovim 0.8+ is required. '
        .. 'For classic Vim use the ALE linter (ale_linters/seclang/coraza_lsp.vim).',
      vim.log.levels.WARN
    )
    return
  end

  _opts = vim.tbl_deep_extend('force', defaults, opts or {})
  _initialized = true

  lsp.setup_autocmd(_opts)
  lsp.register_lspconfig(_opts)
end

--- Restart the coraza-lsp server for all open seclang buffers.
--- Stops any running coraza_lsp clients then re-triggers the FileType autocmd.
function M.restart()
  if not _initialized then
    vim.notify('coraza-lsp: call setup() before restart()', vim.log.levels.WARN)
    return
  end

  lsp.stop()

  -- Re-trigger the FileType autocommand on every loaded seclang buffer.
  for _, buf in ipairs(vim.api.nvim_list_bufs()) do
    if vim.api.nvim_buf_is_loaded(buf) then
      local ft = vim.bo[buf].filetype
      if ft == 'seclang' then
        vim.api.nvim_buf_call(buf, function()
          vim.api.nvim_exec_autocmds('FileType', {
            group = 'coraza_lsp',
            pattern = 'seclang',
            buffer = buf,
          })
        end)
      end
    end
  end

  vim.notify('coraza-lsp: server restarted', vim.log.levels.INFO)
end

--- Return a human-readable status string for the current buffer.
---@return string
function M.status()
  return lsp.status()
end

return M
