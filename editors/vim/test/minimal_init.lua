-- minimal_init.lua: Minimal Neovim configuration for coraza-lsp test suite.
--
-- Usage (from project root):
--   nvim --headless -u editors/vim/test/minimal_init.lua \
--       -c "PlenaryBustedDirectory editors/vim/test/spec {minimal_init='editors/vim/test/minimal_init.lua'}" \
--       +qa

-- Resolve paths relative to this file's location.
local this_file = debug.getinfo(1, 'S').source:sub(2)           -- strip leading '@'
local test_dir  = vim.fn.fnamemodify(this_file, ':p:h')         -- .../editors/vim/test
local plugin_dir = vim.fn.fnamemodify(test_dir, ':h')            -- .../editors/vim

-- Add the plugin itself to runtimepath so ftdetect/, syntax/, lua/, etc. are found.
vim.opt.rtp:prepend(plugin_dir)

-- Bootstrap plenary.nvim into a temporary location so tests can use describe/it/assert.
local plenary_path = vim.fn.stdpath('data') .. '/site/pack/coraza-lsp-test/start/plenary.nvim'
if vim.fn.isdirectory(plenary_path) == 0 then
  vim.notify('minimal_init: cloning plenary.nvim …', vim.log.levels.INFO)
  local result = vim.fn.system({
    'git', 'clone', '--depth', '1',
    'https://github.com/nvim-lua/plenary.nvim',
    plenary_path,
  })
  if vim.v.shell_error ~= 0 then
    error('Failed to clone plenary.nvim:\n' .. result)
  end
end
vim.opt.rtp:prepend(plenary_path)

-- Minimal editor settings.
vim.opt.swapfile    = false
vim.opt.backup      = false
vim.opt.writebackup = false
vim.opt.termguicolors = false

-- Enable filetype detection and syntax so ftdetect/ and syntax/ files are sourced.
vim.cmd('filetype plugin indent on')
vim.cmd('syntax on')
