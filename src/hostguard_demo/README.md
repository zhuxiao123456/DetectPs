# HostGuard Demo

Minimal standalone HostGuard-style IPC demo.

```powershell
cmake -S . -B build-hostguard-demo -G "Visual Studio 17 2022" -A x64
cmake --build build-hostguard-demo --config Release
.\build-hostguard-demo\Release\hostguard_demo.exe .\config\rasp_rules.json .\logs --demo-pipes
```

Commands:

- `status`
- `reload`
- `unload`
- `quit`

Production pipe mode is explicit and strict:

```powershell
.\build-hostguard-demo\Release\hostguard_demo.exe .\config\rasp_rules.json .\logs --production-pipes
```

If a formal pipe is already served, startup fails instead of falling back to `_demo` pipes.

Pipe client usage is also explicit:

```powershell
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --demo-pipes rules GET_RULES
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes rules GET_RULES
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes event "{\"test\":1}"
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes status "{\"msgType\":\"RULE_LOAD_RESULT\"}"
```
