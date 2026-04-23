-- ale_spec.lua: Tests for the ALE linter definition.
-- ALE-dependent tests are skipped when ALE is not installed.

local this_file  = debug.getinfo(1, 'S').source:sub(2)
local spec_dir   = vim.fn.fnamemodify(this_file, ':p:h')
local plugin_dir = vim.fn.fnamemodify(spec_dir, ':h:h')   -- editors/vim/
local linter_file = plugin_dir .. '/ale_linters/seclang/coraza_lsp.vim'

local function ale_available()
  return vim.fn.exists('*ale#linter#Define') == 1
end

local function load_linter()
  vim.cmd('source ' .. vim.fn.fnameescape(linter_file))
end

-- ── File existence ────────────────────────────────────────────────────────────

describe('ALE linter file', function()
  it('exists at ale_linters/seclang/coraza_lsp.vim', function()
    assert.is_true(
      vim.fn.filereadable(linter_file) == 1,
      'ALE linter file not found: ' .. linter_file
    )
  end)

  it('can be sourced without errors when ALE is not installed', function()
    -- The file guards itself with `if !exists('g:loaded_ale')` so it should
    -- always be safe to source regardless of whether ALE is present.
    assert.has_no.errors(function()
      vim.cmd('source ' .. vim.fn.fnameescape(linter_file))
    end)
  end)
end)

-- ── ALE integration (requires ALE) ───────────────────────────────────────────

describe('ALE linter definition', function()
  before_each(function()
    if ale_available() then
      -- Clear any previously registered linters for a clean slate.
      pcall(vim.fn['ale#linter#Reset'])
      load_linter()
    end
  end)

  it('registers coraza_lsp for the seclang filetype', function()
    if not ale_available() then
      pending('ALE not installed — install dense-analysis/ale to enable ALE tests')
      return
    end

    local linters = vim.fn['ale#linter#Get']('seclang')
    local names   = vim.tbl_map(function(l) return l.name end, linters)
    assert.is_true(
      vim.tbl_contains(names, 'coraza_lsp'),
      'coraza_lsp not in ALE linter list; found: ' .. table.concat(names, ', ')
    )
  end)

  it('linter uses stdio LSP transport', function()
    if not ale_available() then
      pending('ALE not installed')
      return
    end

    local linters = vim.fn['ale#linter#Get']('seclang')
    for _, l in ipairs(linters) do
      if l.name == 'coraza_lsp' then
        assert.equals('stdio',   l.lsp,      'expected lsp = "stdio"')
        assert.equals('seclang', l.language, 'expected language = "seclang"')
        return
      end
    end
    assert.fail('coraza_lsp linter entry not found')
  end)

  it('default executable is "coraza-lsp"', function()
    if not ale_available() then
      pending('ALE not installed')
      return
    end

    local bufnr = vim.api.nvim_get_current_buf()
    local exe   = vim.fn['ale#Var'](bufnr, 'seclang_coraza_lsp_executable')
    assert.equals('coraza-lsp', exe)
  end)

  it('respects g:ale_seclang_coraza_lsp_executable override', function()
    if not ale_available() then
      pending('ALE not installed')
      return
    end

    vim.g.ale_seclang_coraza_lsp_executable = '/custom/path/coraza-lsp'
    load_linter()

    local bufnr = vim.api.nvim_get_current_buf()
    local exe   = vim.fn['ale#Var'](bufnr, 'seclang_coraza_lsp_executable')
    assert.equals('/custom/path/coraza-lsp', exe)

    -- Clean up.
    vim.g.ale_seclang_coraza_lsp_executable = nil
  end)
end)
