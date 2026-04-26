-- AMSI-P01: Script execution detection
-- Invoked by rasp_mod_amsi.dll for every AMSI scan in registered processes.
--
-- Context fields (AmsiProvider sensor):
--   context.contentName = scanned item name  (e.g. "script.ps1", "inline script")
--   context.appName     = calling host       (e.g. "PowerShell", "JScript", "cscript")
--   context.body        = script sample (first 512 bytes of scanned content, UTF-8)
--
-- Return { match=true, desc="...", payload="..." } to flag the scan.
-- Return nil (or nothing) to pass the scan through.
--
-- Uses regex_match() (PCRE2 global) for all pattern checks.
-- Each detection group is one alternation — case-insensitive via (?i).

function rule(sensor, context)
  if bail_unless(sensor, SENSOR_AMSI) then return nil end

  local body = context.body        or ""
  local name = context.contentName or ""
  local app  = context.appName     or ""

  dbg("AMSI-P01: scan  app=" .. app .. "  name=" .. name
      .. "  bodyLen=" .. #body
      .. "  body=" .. body:sub(1, 80))

  -- AMSI bypass / self-patching attempts
  if regex_match("(?i)(amsiutils|amsiinitfailed|amsiscanbuffer|amsi\\.dll|amsicontext)", body) then
    dbg("AMSI-P01: MATCH bypass  app=" .. app .. "  name=" .. name)
    return { match=true,
             desc="AMSI bypass attempt detected",
             payload=body:sub(1, 200) }
  end

  -- Encoded / obfuscated PowerShell
  if regex_match("(?i)(-encodedcommand|-enc\\s|frombase64string|system\\.convert)", body) then
    dbg("AMSI-P01: MATCH obfuscated  app=" .. app .. "  name=" .. name)
    return { match=true,
             desc="Encoded/obfuscated PowerShell command",
             payload=body:sub(1, 200) }
  end

  -- Remote download and execution
  if regex_match("(?i)(downloadstring|downloadfile|invoke-webrequest|net\\.webclient)", body) then
    dbg("AMSI-P01: MATCH download  app=" .. app .. "  name=" .. name)
    return { match=true,
             desc="Remote code download pattern",
             payload=body:sub(1, 200) }
  end

  -- Dynamic eval / reflective execution
  if regex_match("(?i)(iex[\\s(]|invoke-expression|invoke-command)", body) then
    dbg("AMSI-P01: MATCH invoke-expression  app=" .. app .. "  name=" .. name)
    return { match=true,
             desc="Dynamic eval / Invoke-Expression pattern",
             payload=body:sub(1, 200) }
  end

  -- Reflective DLL / shellcode loading
  if regex_match("(?i)(virtualalloc|writeprocessmemory|createthread|loadlibrary)", body) then
    dbg("AMSI-P01: MATCH shellcode  app=" .. app .. "  name=" .. name)
    return { match=true,
             desc="Reflective memory/shellcode pattern",
             payload=body:sub(1, 200) }
  end

  -- Red team / post-exploitation tools
  if regex_match("(?i)(invoke-mimikatz|invoke-bloodhound|invoke-kerberoast|invoke-dcsync|invoke-wmiexec|invoke-smbexec|invoke-psexec|invoke-reflectivepeinJection|powersploit|powerview|\\bempire\\b|cobalt.strike|sekurlsa|lsadump|kerberos::ptt|mimikatz)", body) then
    dbg("AMSI-P01: MATCH redteam  app=" .. app .. "  name=" .. name)
    return { match=true,
             desc="Red team / post-exploitation tool detected",
             payload=body:sub(1, 200) }
  end

  dbg("AMSI-P01: no match  app=" .. app .. "  name=" .. name)
  return { match=false,
           desc="Lua script did not find threats",
           payload=body:sub(1, 200) }
end
