-- lsp_spec.lua: Tests for the Neovim LSP setup.
-- Unit tests run without the binary. Integration tests are skipped when
-- the coraza-lsp binary is not on PATH or CORAZA_LSP_PATH is unset.

local coraza_lsp = require('coraza-lsp')
local lsp_mod    = require('coraza-lsp.lsp')

-- Path to the VS Code testdata fixtures (shared across editor integrations).
local this_file   = debug.getinfo(1, 'S').source:sub(2)
local project_root = vim.fn.fnamemodify(this_file, ':h:h:h:h:h')  -- coraza-lsp/
local fixture_missing_id = project_root .. '/editors/vscode/testdata/missing-id.conf'

local function can_run_integration()
  local path = os.getenv('CORAZA_LSP_PATH') or 'coraza-lsp'
  return vim.fn.executable(path) == 1
end

local function server_path()
  return os.getenv('CORAZA_LSP_PATH') or 'coraza-lsp'
end

local function teardown()
  -- Stop any running clients and clear the autocmd group so setups don't stack.
  lsp_mod.stop()
  pcall(vim.api.nvim_del_augroup_by_name, 'coraza_lsp')
  for _, buf in ipairs(vim.api.nvim_list_bufs()) do
    if vim.api.nvim_buf_is_valid(buf) then
      vim.api.nvim_buf_delete(buf, { force = true })
    end
  end
end

-- ── Unit tests (no binary required) ──────────────────────────────────────────

describe('coraza-lsp unit', function()
  after_each(teardown)

  it('setup() with no arguments executes without error', function()
    assert.has_no.errors(function()
      coraza_lsp.setup({})
    end)
  end)

  it('setup() with a custom server_path executes without error', function()
    assert.has_no.errors(function()
      coraza_lsp.setup({ server_path = '/usr/bin/coraza-lsp' })
    end)
  end)

  it('make_config() produces correct name and cmd', function()
    local cfg = lsp_mod.make_config({
      server_path    = 'coraza-lsp',
      cmd_extra_args = {},
      filetypes      = { 'seclang' },
      settings       = {},
    })
    assert.equals('coraza_lsp', cfg.name)
    assert.same({ 'coraza-lsp', '--stdio' }, cfg.cmd)
    assert.same({ 'seclang' }, cfg.filetypes)
    assert.is_true(cfg.single_file_support)
  end)

  it('make_config() appends cmd_extra_args after --stdio', function()
    local cfg = lsp_mod.make_config({
      server_path    = 'coraza-lsp',
      cmd_extra_args = { '-v' },
      filetypes      = { 'seclang' },
      settings       = {},
    })
    assert.same({ 'coraza-lsp', '--stdio', '-v' }, cfg.cmd)
  end)

  it('make_config() uses provided capabilities', function()
    local caps = { textDocument = { hover = { dynamicRegistration = false } } }
    local cfg = lsp_mod.make_config({
      server_path    = 'coraza-lsp',
      cmd_extra_args = {},
      filetypes      = { 'seclang' },
      settings       = {},
      capabilities   = caps,
    })
    assert.same(caps, cfg.capabilities)
  end)

  it('setup() registers a FileType autocmd for seclang', function()
    coraza_lsp.setup({})
    local autocmds = vim.api.nvim_get_autocmds({ group = 'coraza_lsp', event = 'FileType' })
    assert.is_true(#autocmds > 0, 'expected at least one FileType autocmd')
    local patterns = vim.tbl_map(function(a) return a.pattern end, autocmds)
    assert.is_true(
      vim.tbl_contains(patterns, 'seclang'),
      'expected pattern "seclang" in autocmd list'
    )
  end)

  it('status() returns a string before any client is attached', function()
    coraza_lsp.setup({})
    local s = coraza_lsp.status()
    assert.is_string(s)
    assert.is_true(#s > 0)
  end)

  it('restart() warns when setup() has not been called', function()
    local warnings = {}
    local orig = vim.notify
    vim.notify = function(msg, level)
      if level == vim.log.levels.WARN then
        table.insert(warnings, msg)
      end
    end
    coraza_lsp.restart()
    vim.notify = orig
    assert.is_true(#warnings > 0, 'expected a warning when restarting without setup()')
  end)

  it('stop() is a no-op when no server is running', function()
    assert.has_no.errors(function()
      lsp_mod.stop()
    end)
  end)
end)

-- ── Integration tests (require coraza-lsp binary) ────────────────────────────

describe('coraza-lsp integration', function()
  after_each(teardown)

  it('attaches LSP client to a seclang buffer', function()
    if not can_run_integration() then
      pending('coraza-lsp binary not found — run `make build` and add ./bin to $PATH')
      return
    end

    coraza_lsp.setup({ server_path = server_path() })
    vim.cmd('edit ' .. vim.fn.fnameescape(fixture_missing_id))

    local attached = vim.wait(8000, function()
      local get = vim.lsp.get_clients or vim.lsp.get_active_clients
      return #get({ name = 'coraza_lsp', bufnr = 0 }) > 0
    end, 100)

    assert.is_true(attached, 'coraza_lsp client did not attach within 8 s')
  end)

  it('publishes diagnostics for a rule missing an id', function()
    if not can_run_integration() then
      pending('coraza-lsp binary not found')
      return
    end

    coraza_lsp.setup({ server_path = server_path() })
    vim.cmd('edit ' .. vim.fn.fnameescape(fixture_missing_id))

    -- Wait for the LSP to attach first.
    local attached = vim.wait(8000, function()
      local get = vim.lsp.get_clients or vim.lsp.get_active_clients
      return #get({ name = 'coraza_lsp', bufnr = 0 }) > 0
    end, 100)
    assert.is_true(attached, 'client did not attach')

    -- Then wait for diagnostics to arrive (server debounces at 300 ms).
    local bufnr = vim.api.nvim_get_current_buf()
    local got_diag = vim.wait(10000, function()
      return #vim.diagnostic.get(bufnr) > 0
    end, 200)

    assert.is_true(got_diag, 'no diagnostics received within 10 s')

    local diags = vim.diagnostic.get(bufnr)
    local messages = vim.tbl_map(function(d) return d.message end, diags)
    local has_id_diag = vim.tbl_filter(function(m)
      return m:lower():find('id') ~= nil
    end, messages)
    assert.is_true(
      #has_id_diag > 0,
      'expected a diagnostic mentioning "id"; got: ' .. table.concat(messages, ', ')
    )
  end)

  it('status() reports running after attachment', function()
    if not can_run_integration() then
      pending('coraza-lsp binary not found')
      return
    end

    coraza_lsp.setup({ server_path = server_path() })
    vim.cmd('edit ' .. vim.fn.fnameescape(fixture_missing_id))

    vim.wait(8000, function()
      local get = vim.lsp.get_clients or vim.lsp.get_active_clients
      return #get({ name = 'coraza_lsp', bufnr = 0 }) > 0
    end, 100)

    local s = coraza_lsp.status()
    assert.is_true(s:find('running') ~= nil, 'expected "running" in status: ' .. s)
  end)
end)
