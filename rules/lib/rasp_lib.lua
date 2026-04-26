-- rasp_lib.lua — shared utility library for all RASP Lua rule scripts
--
-- This file is concatenated BEFORE each rule script at precompile time.
-- It is NOT loaded via require() — that global is nil in the sandbox.
-- All definitions are local; they are visible to the rule script below
-- because both are compiled as one Lua chunk (same lexical scope).
--
-- Usage in a rule script:
--   function rule(sensor, context)
--       if bail_unless(sensor, SENSOR_DESER) then return nil end
--       local m = scan(context.body, GADGET_TYPES)
--       if m then
--           return { match=true, desc="Gadget type: " .. m, payload=truncate(context.body, 200) }
--       end
--       return nil
--   end

-- ── Debug helper ─────────────────────────────────────────────────────────────
-- Safe in both production (print=nil) and RunWithCapture/RunWithDebugLog
-- (print is wired to capture buffer). The if-guard short-circuits silently
-- in production with zero overhead.
local function dbg(s) if print then print(s) end end

-- ── Sensor name constants ────────────────────────────────────────────────────
-- Use these in bail guards to avoid silent typos.
local SENSOR_DESER      = "Deserialization"
local SENSOR_ASM        = "AssemblyLoad"
local SENSOR_SQLI       = "SqlInjection"
local SENSOR_AUTH       = "AuthBypass"
local SENSOR_METHOD     = "MethodHook"
local SENSOR_CLASS      = "ClassLoad"
local SENSOR_REQFILTER  = "RequestFilter"
local SENSOR_PATH       = "PathTraversal"
local SENSOR_AMSI       = "AmsiProvider"

-- ── Per-sensor context fields ────────────────────────────────────────────────
-- Each module pushes only the fields it owns.  Scripts see only the keys
-- that were pushed — accessing a field from another sensor returns nil.
--
-- AmsiProvider (rasp_mod_amsi):
--   context.contentName  — scanned item name  (e.g. "script.ps1", "MemoryStream")
--   context.appName      — calling host       (e.g. "PowerShell_ISE", "w3wp")
--   context.body         — scanned bytes      (binary-safe string, variable length)
--
-- RequestFilter / PathTraversal (rasp_mod_iis7):
--   context.url          — HTTP.sys cooked (normalized) path
--   context.rawUrl       — raw wire URL before HTTP.sys normalization
--   context.method       — HTTP verb           (e.g. "GET", "POST")
--   context.ip           — client IP address   (e.g. "10.0.0.1")
--   context.ua           — User-Agent header   (may be absent)
--   context.patterns     — 1-indexed Lua array of config patterns (rule-specific)
--
-- Deserialization / AssemblyLoad (rasp_mod_dot_net, via managed bridge):
--   context.body         — serialized payload or assembly bytes (binary-safe)
--   context.url          — request path at interception time
--   context.method       — HTTP verb

-- ── Bail helper ──────────────────────────────────────────────────────────────
-- Returns true when sensor does NOT match expected, so the caller can
-- return nil immediately.
--
-- Usage:
--   if bail_unless(sensor, SENSOR_DESER) then return nil end
local function bail_unless(sensor, expected)
    return sensor ~= expected
end

-- ── String utilities ─────────────────────────────────────────────────────────

-- Truncate string s to at most n characters, appending "..." if cut.
local function truncate(s, n)
    if not s then return "" end
    if #s <= n then return s end
    return string.sub(s, 1, n) .. "..."
end

-- Scan haystack for any needle in the array needles.
-- Returns the first matched needle string, or nil if none matched.
-- Uses literal (non-regex) matching — safe for type names containing dots.
local function scan(haystack, needles)
    if not haystack or not needles then return nil end
    for _, needle in ipairs(needles) do
        if string.find(haystack, needle, 1, true) then
            return needle
        end
    end
    return nil
end

-- Scan haystack against an array of PCRE2 regex patterns.
-- Returns the first pattern that matches, or nil.
-- Use when patterns need alternation (|), word boundaries (\b), or capture groups
-- that plain scan() cannot express with literal matching.
-- Requires: regex_match() global (registered by RaspLuaEngine).
local function regex_scan(haystack, patterns)
    if not haystack or not patterns then return nil end
    for _, pat in ipairs(patterns) do
        if regex_match(pat, haystack) then return pat end
    end
    return nil
end

-- ── JSON helpers ─────────────────────────────────────────────────────────────

-- Returns true when body contains a "$type" or "__type" JSON key.
local function has_json_type_key(body)
    if not body then return false end
    return string.find(body, '"$type"',  1, true) ~= nil
        or string.find(body, '"__type"', 1, true) ~= nil
end

-- ── Binary / PE helpers ──────────────────────────────────────────────────────

-- Returns true when the hex-encoded bytes begin with the MZ (4D 5A) PE signature.
local function has_mz_header(hex)
    if not hex or #hex < 4 then return false end
    return string.sub(string.lower(hex), 1, 4) == "4d5a"
end

-- Returns true when the hex-encoded bytes contain the BSJB CLI metadata root
-- signature (42 53 4A 42 = "BSJB") found in all valid .NET PE images.
local function has_bsjb_signature(hex)
    if not hex then return false end
    return string.find(string.lower(hex), "42534a42", 1, true) ~= nil
end

-- ── Known-dangerous type lists ───────────────────────────────────────────────
-- Sync these with rasp_rules.json GadgetChainTypes when adding new gadgets.

-- Gadget chain types used in JSON deserialization attacks ($type / __type).
local GADGET_TYPES = {
    -- Core compiled-in list (DESER-001/002/003/010 in rasp_rules.json)
    "System.Workflow.ComponentModel",
    "System.Windows.Forms.AxHost+State",
    "System.Data.DataSet",
    "System.Windows.Data.ObjectDataProvider",
    "System.Diagnostics.Process",
    "System.Runtime.Remoting",
    "Microsoft.VisualStudio.Text",
    "System.Security.Claims.ClaimsPrincipal",
    "System.Windows.Markup.XamlReader",
    -- Extended types (Lua-only — not in compiled-in list)
    "Microsoft.Build.Tasks.Windows",
    "System.Drawing.Imaging.ImageCodecInfo",
    "System.Data.DataTable",
    "System.Data.DataView",
    "Newtonsoft.Json.Linq.JObject",
    "System.Web.UI.ObjectStateFormatter"
}

-- Assembly references that indicate high-risk in-memory loaded DLLs.
local DANGEROUS_REFS = {
    "System.Diagnostics",   -- Process.Start / command execution
    "System.Net.Sockets",   -- reverse shell / bind shell
    "Microsoft.Win32",      -- registry manipulation
    "System.Management"     -- WMI command execution
}

-- Suspicious type name fragments found in webshell assemblies.
local SUSPICIOUS_TYPES = {
    "WebShell", "Webshell", "webshell",
    "Backdoor", "backdoor",
    "CmdExec",  "cmdexec",
    "Payload",  "Stager",   "Loader",
    "Injector", "Dropper",
    "ReverseShell", "BindShell"
}

-- Suspicious method name fragments found in webshell assemblies.
local SUSPICIOUS_METHODS = {
    "RunCommand",    "ExecCommand",   "ExecuteCmd",  "ExecuteCommand",
    "ShellExec",     "InvokeCmd",     "CmdShell",
    "RunShell",      "SpawnProcess",  "LaunchProcess",
    "RunCode",       "ExecCode",      "InjectCode"
}
