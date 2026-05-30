-- syntax_spec.lua: Tests for SecLang syntax highlighting (syntax/seclang.vim).
--
-- These lock in the vim-side analogue of the TextMate grammar fixes: the vim
-- region model handles escaped quotes (skip=/\\"/) and column-0 continuations,
-- so a multi-line rule whose msg value embeds \" must NOT break highlighting of
-- the rest of the rule (the bug that broke the TextMate grammar). They also
-- assert the core token classes (directive, variable, operator, transformation).

local function open_conf(content)
  local path = os.tmpname() .. '.conf'
  local f = assert(io.open(path, 'w'))
  f:write(content)
  f:close()
  vim.cmd('edit ' .. vim.fn.fnameescape(path))
  -- Force the filetype so syntax/seclang.vim is sourced. We force (not rely on
  -- ftdetect) because this is a SYNTAX test, not a detection test — ftdetect is
  -- covered by filetype_spec. `syntax sync fromstart` makes synID() resolve the
  -- multi-line action-string region from the top of the buffer rather than from
  -- a limited sync window, so positions inside a continuation line report the
  -- region's group correctly.
  vim.cmd('set filetype=seclang')
  vim.cmd('syntax sync fromstart')
  assert.equals('seclang', vim.bo.filetype)
  return path
end

-- syn_name returns the syntax group name at 1-indexed (lnum, col).
local function syn_name(lnum, col)
  return vim.fn.synIDattr(vim.fn.synID(lnum, col, 1), 'name')
end

-- first_col finds the 1-indexed column where `needle` starts on line `lnum`.
local function first_col(lnum, needle)
  local line = vim.fn.getline(lnum)
  local s = line:find(needle, 1, true)
  return s
end

local function close_all_bufs()
  for _, buf in ipairs(vim.api.nvim_list_bufs()) do
    if vim.api.nvim_buf_is_valid(buf) then
      vim.api.nvim_buf_delete(buf, { force = true })
    end
  end
end

describe('syntax/seclang', function()
  after_each(close_all_bufs)

  it('classifies directive, variable and operator on a SecRule line', function()
    local p = open_conf('SecRule ARGS "@rx attack" "id:1,phase:2,deny"\n')
    assert.equals('seclangDirective', syn_name(1, first_col(1, 'SecRule')))
    assert.equals('seclangVariable', syn_name(1, first_col(1, 'ARGS')))
    assert.equals('seclangOperator', syn_name(1, first_col(1, '@rx')))
    os.remove(p)
  end)

  it('colors t: transformations distinctly', function()
    local p = open_conf('SecRule ARGS "@rx x" "id:1,phase:2,t:lowercase,deny"\n')
    -- the transformation name (after t:) is its own group, not a bare string
    local col = first_col(1, 'lowercase')
    assert.equals('seclangTransformation', syn_name(1, col))
    os.remove(p)
  end)

  it('does not break on an escaped double quote inside a single-quoted msg', function()
    -- Regression: \" inside a msg:'...' value must not terminate the action
    -- string region. Everything after it must stay highlighted (seclangString),
    -- never fall through to an empty/None group.
    local content = table.concat({
      'SecRule ARGS "@rx foo" \\',
      '    "id:1,phase:2,\\',
      "    msg:'is the \\\"magic number\\\" crash',\\",
      '    severity:2,\\',
      "    setvar:'tx.score=+1'\"",
    }, '\n') .. '\n'
    local p = open_conf(content)
    -- The continuation lines (3,4,5) are inside the action string region.
    for _, lnum in ipairs({ 3, 4, 5 }) do
      local line = vim.fn.getline(lnum)
      for c = (line:find('%S')), #line do
        local name = syn_name(lnum, c)
        assert.is_true(
          name ~= '',
          string.format('L%d col %d (%q) fell through to no syntax group', lnum, c, line:sub(c, c))
        )
      end
    end
    os.remove(p)
  end)

  it('handles a column-0 (unindented) continuation line', function()
    -- ModSecurity-style rules often put the continuation quote at column 0.
    local content = 'SecRule REQBODY_ERROR "!@eq 0" \\\n"id:200002,phase:2,deny,severity:2"\n'
    local p = open_conf(content)
    -- The action string on line 2 must be highlighted, not plain text.
    assert.equals('seclangString', syn_name(2, 1))
    os.remove(p)
  end)
end)
