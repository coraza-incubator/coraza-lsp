-- lsp.lua: LSP client configuration and lifecycle management.
-- Uses Neovim's built-in vim.lsp.start() (Neovim 0.8+).

local M = {}

-- Compatibility: get_clients was renamed from get_active_clients in Neovim 0.10.
local _get_clients = vim.lsp.get_clients or vim.lsp.get_active_clients

--- Build the vim.lsp.start() config table from the merged user options.
---@param opts table
---@return table
function M.make_config(opts)
  local cmd = { opts.server_path, '--stdio' }
  for _, arg in ipairs(opts.cmd_extra_args or {}) do
    table.insert(cmd, arg)
  end

  return {
    name = 'coraza_lsp',
    cmd = cmd,
    filetypes = opts.filetypes,
    -- root_dir: use the explicit override, or fall back to the buffer's directory.
    -- We capture it at setup time so the value is stable across buffer opens.
    root_dir = opts.root_dir,
    capabilities = opts.capabilities or vim.lsp.protocol.make_client_capabilities(),
    on_attach = opts.on_attach,
    settings = opts.settings or {},
    single_file_support = true,
  }
end

--- Register this server with nvim-lspconfig (if installed), enabling:
---   require('lspconfig').coraza_lsp.setup({})
---@param opts table
function M.register_lspconfig(opts)
  local ok_cfg, lspconfig_configs = pcall(require, 'lspconfig.configs')
  if not ok_cfg then return end
  local ok_util, util = pcall(require, 'lspconfig.util')
  if not ok_util then return end

  if not lspconfig_configs.coraza_lsp then
    lspconfig_configs.coraza_lsp = {
      default_config = {
        cmd = { opts.server_path, '--stdio' },
        filetypes = opts.filetypes,
        root_dir = util.find_git_ancestor,
        single_file_support = true,
        settings = opts.settings or {},
      },
      docs = {
        description = 'Coraza SecLang Language Server (https://github.com/coraza-incubator/coraza-lsp)\n'
          .. 'Provides completions, diagnostics, hover, go-to-definition, symbols,\n'
          .. 'formatting, and code actions for OWASP Coraza / ModSecurity rule files.',
      },
    }
  end
end

--- Set up the FileType autocommand that starts the LSP client.
---@param opts table
function M.setup_autocmd(opts)
  local group = vim.api.nvim_create_augroup('coraza_lsp', { clear = true })
  local config = M.make_config(opts)

  vim.api.nvim_create_autocmd('FileType', {
    group = group,
    pattern = table.concat(opts.filetypes, ','),
    desc = 'Start coraza-lsp language server',
    callback = function(ev)
      -- Resolve root_dir per-buffer when not explicitly set.
      local buf_config = vim.tbl_extend('force', config, {
        root_dir = opts.root_dir or vim.fn.fnamemodify(
          vim.api.nvim_buf_get_name(ev.buf), ':p:h'
        ),
      })
      vim.lsp.start(buf_config)
    end,
  })
end

--- Stop all active coraza_lsp clients (globally, not just current buffer).
function M.stop()
  for _, client in ipairs(_get_clients({ name = 'coraza_lsp' })) do
    client.stop()
  end
end

--- Return a human-readable status string for the current buffer.
---@return string
function M.status()
  local clients = _get_clients({ name = 'coraza_lsp', bufnr = 0 })
  if #clients == 0 then
    return 'coraza-lsp: not attached to current buffer'
  end
  local c = clients[1]
  return string.format(
    'coraza-lsp: running  id=%d  root=%s',
    c.id,
    c.config.root_dir or '(none)'
  )
end

return M
