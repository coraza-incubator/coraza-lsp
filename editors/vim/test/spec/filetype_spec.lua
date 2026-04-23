-- filetype_spec.lua: Tests for SecLang filetype detection.
-- Verifies that .conf files are typed as 'seclang' iff they contain SecLang directives.

local function write_temp_conf(content)
  local path = os.tmpname() .. '.conf'
  local f = assert(io.open(path, 'w'))
  f:write(content)
  f:close()
  return path
end

local function open_and_get_ft(path)
  vim.cmd('edit ' .. vim.fn.fnameescape(path))
  -- Ensure ftdetect autocmds have fired.
  vim.cmd('doautocmd BufRead ' .. vim.fn.fnameescape(path))
  return vim.bo.filetype
end

local function close_all_bufs()
  for _, buf in ipairs(vim.api.nvim_list_bufs()) do
    if vim.api.nvim_buf_is_valid(buf) then
      vim.api.nvim_buf_delete(buf, { force = true })
    end
  end
end

describe('ftdetect/seclang', function()
  after_each(function()
    close_all_bufs()
  end)

  -- ── Positive cases ────────────────────────────────────────────────────────

  it('detects seclang for a file starting with SecRule', function()
    local path = write_temp_conf('SecRule ARGS "@rx sql" "id:1001,phase:2,deny"\n')
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.equals('seclang', ft)
  end)

  it('detects seclang for SecRuleEngine directive', function()
    local path = write_temp_conf('SecRuleEngine On\n')
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.equals('seclang', ft)
  end)

  it('detects seclang for SecAction directive', function()
    local path = write_temp_conf('SecAction "id:900001,phase:1,pass,nolog"\n')
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.equals('seclang', ft)
  end)

  it('detects seclang for SecDefaultAction directive', function()
    local path = write_temp_conf('SecDefaultAction "phase:1,log,deny,status:403"\n')
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.equals('seclang', ft)
  end)

  it('detects seclang for SecMarker directive', function()
    local path = write_temp_conf('SecMarker BEGIN_HOST_CHECK\n')
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.equals('seclang', ft)
  end)

  it('detects seclang for Include directive', function()
    local path = write_temp_conf('Include /etc/modsecurity/*.conf\n')
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.equals('seclang', ft)
  end)

  it('detects seclang when directive follows comment lines', function()
    local content = '# OWASP CRS\n# version 3.3\nSecRuleEngine DetectionOnly\n'
    local path = write_temp_conf(content)
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.equals('seclang', ft)
  end)

  it('detects seclang when directive is on line 15 (within 20-line scan window)', function()
    local lines = {}
    for _ = 1, 14 do table.insert(lines, '# comment') end
    table.insert(lines, 'SecAction "id:1002,phase:1,pass"')
    local path = write_temp_conf(table.concat(lines, '\n') .. '\n')
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.equals('seclang', ft)
  end)

  -- ── Negative cases ────────────────────────────────────────────────────────

  it('does not assign seclang to an nginx .conf file', function()
    local content = 'server {\n  listen 80;\n  location / {\n    root /var/www;\n  }\n}\n'
    local path = write_temp_conf(content)
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.not_equal('seclang', ft)
  end)

  it('does not assign seclang to an empty .conf file', function()
    local path = write_temp_conf('')
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.not_equal('seclang', ft)
  end)

  it('does not assign seclang to a comment-only .conf file', function()
    local path = write_temp_conf('# just a comment\n# another comment\n')
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.not_equal('seclang', ft)
  end)

  it('does not detect seclang when directive is past line 20', function()
    local lines = {}
    for _ = 1, 21 do table.insert(lines, '# comment') end
    table.insert(lines, 'SecRule ARGS "@rx test" "id:1003,phase:2,pass"')
    local path = write_temp_conf(table.concat(lines, '\n') .. '\n')
    local ft = open_and_get_ft(path)
    os.remove(path)
    assert.not_equal('seclang', ft)
  end)

  it('does not match a word that only starts with "Sec" but is not a directive', function()
    local path = write_temp_conf('SecretKey = abc123\n')
    local ft = open_and_get_ft(path)
    os.remove(path)
    -- "SecretKey" should NOT trigger seclang detection (word-boundary check).
    assert.not_equal('seclang', ft)
  end)
end)
