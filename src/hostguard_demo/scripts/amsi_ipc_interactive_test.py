# -*- coding: utf-8 -*-
import ctypes
import json
import sys
import time
from ctypes import wintypes


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

ERROR_FILE_NOT_FOUND = 2
ERROR_PIPE_BUSY = 231
ERROR_BROKEN_PIPE = 109
ERROR_NO_DATA = 232
ERROR_PIPE_NOT_CONNECTED = 233
ERROR_MORE_DATA = 234

PIPE_RULES = "amsi_detect_rules"
PIPE_EVENTS = "amsi_detect_events"
PIPE_STATUS = "amsi_detect_control_status"
PIPE_CONFIG = "amsi_detect_config"


CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
CreateFileW.restype = wintypes.HANDLE

WaitNamedPipeW = kernel32.WaitNamedPipeW
WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
WaitNamedPipeW.restype = wintypes.BOOL

WriteFile = kernel32.WriteFile
WriteFile.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
WriteFile.restype = wintypes.BOOL

ReadFile = kernel32.ReadFile
ReadFile.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
ReadFile.restype = wintypes.BOOL

PeekNamedPipe = kernel32.PeekNamedPipe
PeekNamedPipe.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
]
PeekNamedPipe.restype = wintypes.BOOL

FlushFileBuffers = kernel32.FlushFileBuffers
FlushFileBuffers.argtypes = [wintypes.HANDLE]
FlushFileBuffers.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


def last_error_text(prefix):
    err = ctypes.get_last_error()
    return f"{prefix}: error={err}, {ctypes.FormatError(err)}"


def open_pipe(pipe_name, desired_access, timeout_ms=3000):
    pipe_path = r"\\.\pipe\{}".format(pipe_name)
    deadline = time.monotonic() + timeout_ms / 1000.0

    while True:
        handle = CreateFileW(
            pipe_path,
            desired_access,
            0,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )

        if handle and handle != INVALID_HANDLE_VALUE:
            return handle

        err = ctypes.get_last_error()
        remaining_ms = int((deadline - time.monotonic()) * 1000)

        if remaining_ms <= 0:
            raise OSError(
                err,
                f"Connect pipe timeout: {pipe_path}, last_error={err}, {ctypes.FormatError(err)}",
            )

        if err == ERROR_PIPE_BUSY:
            ok = WaitNamedPipeW(pipe_path, remaining_ms)
            if not ok:
                raise OSError(ctypes.get_last_error(), last_error_text(f"WaitNamedPipe failed: {pipe_path}"))
        elif err == ERROR_FILE_NOT_FOUND:
            time.sleep(0.05)
        else:
            raise OSError(err, last_error_text(f"CreateFileW failed: {pipe_path}"))


def write_pipe(handle, pipe_name, payload):
    data = payload.encode("utf-8")
    buf = ctypes.create_string_buffer(data)
    written = wintypes.DWORD(0)

    ok = WriteFile(handle, buf, len(data), ctypes.byref(written), None)
    if not ok:
        raise OSError(ctypes.get_last_error(), last_error_text(f"WriteFile failed, pipe={pipe_name}"))

    FlushFileBuffers(handle)
    return written.value


def send_pipe_payload(pipe_name, payload, timeout_ms=3000):
    handle = open_pipe(pipe_name, GENERIC_WRITE, timeout_ms)
    try:
        written = write_pipe(handle, pipe_name, payload)
        print(f"[OK] pipe={pipe_name}, bytes={written}")
        print(payload)
    finally:
        CloseHandle(handle)


def read_available_pipe(handle, timeout_ms=3000, idle_ms=200):
    deadline = time.monotonic() + timeout_ms / 1000.0
    idle_deadline = None
    chunks = []

    while True:
        available = wintypes.DWORD(0)
        bytes_left = wintypes.DWORD(0)
        total = wintypes.DWORD(0)

        ok = PeekNamedPipe(
            handle,
            None,
            0,
            ctypes.byref(total),
            ctypes.byref(available),
            ctypes.byref(bytes_left),
        )

        if not ok:
            err = ctypes.get_last_error()
            if err in (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED):
                break
            raise OSError(err, last_error_text("PeekNamedPipe failed"))

        if available.value > 0:
            idle_deadline = None
            to_read = min(available.value, 65536)
            buf = ctypes.create_string_buffer(to_read)
            read = wintypes.DWORD(0)

            ok = ReadFile(handle, buf, to_read, ctypes.byref(read), None)
            if not ok:
                err = ctypes.get_last_error()
                if err in (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED):
                    break
                raise OSError(err, last_error_text("ReadFile failed"))

            if read.value > 0:
                chunks.append(buf.raw[:read.value])
            continue

        now = time.monotonic()
        if idle_deadline is None:
            idle_deadline = now + idle_ms / 1000.0

        if now >= idle_deadline:
            break

        if now >= deadline:
            break

        time.sleep(0.02)

    return b"".join(chunks).decode("utf-8", errors="replace")


def read_rule_response(handle):
    # AmsiRuleChannel writes one response and then the server side disconnects.
    # Read directly like the DLL/minimal C++ pipe client; PeekNamedPipe can race
    # with server disconnect and return ERROR_PIPE_NOT_CONNECTED (233).
    chunks = []

    while True:
        buf = ctypes.create_string_buffer(65536)
        read = wintypes.DWORD(0)
        ok = ReadFile(handle, buf, len(buf) - 1, ctypes.byref(read), None)

        if ok:
            if read.value > 0:
                chunks.append(buf.raw[:read.value])
            if read.value < len(buf) - 1:
                break
            continue

        err = ctypes.get_last_error()
        if err == ERROR_MORE_DATA:
            if read.value > 0:
                chunks.append(buf.raw[:read.value])
            continue
        if err in (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED):
            break
        raise OSError(err, last_error_text("ReadFile failed"))

    return b"".join(chunks).decode("utf-8", errors="replace")


def request_rules(command, timeout_ms=3000):
    if command not in ("GET_RULES", "GET_ALL_RULES"):
        raise ValueError("unsupported rule command")

    handle = open_pipe(PIPE_RULES, GENERIC_READ | GENERIC_WRITE, timeout_ms)
    try:
        payload = command + "\n"
        written = write_pipe(handle, PIPE_RULES, payload)
        response = read_rule_response(handle)
        print(
            f"[OK] pipe={PIPE_RULES}, command={command}, "
            f"requestBytes={written}, responseBytes={len(response.encode('utf-8'))}"
        )
        print_response(response)
    finally:
        CloseHandle(handle)


def wait_pipe_available(pipe_name, timeout_ms=1000):
    pipe_path = r"\\.\pipe\{}".format(pipe_name)
    ok = WaitNamedPipeW(pipe_path, timeout_ms)
    if ok:
        return True, 0, "available"
    err = ctypes.get_last_error()
    return False, err, ctypes.FormatError(err).strip()


def health_check():
    print("[HEALTH] probing production AMSI IPC pipes")
    pipes = [
        (PIPE_RULES, "rules"),
        (PIPE_EVENTS, "events"),
        (PIPE_STATUS, "control_status"),
        (PIPE_CONFIG, "config_host_owned"),
    ]

    all_ok = True
    for pipe_name, label in pipes:
        ok, err, message = wait_pipe_available(pipe_name)
        state = "OK" if ok else "FAIL"
        print(f"[{state}] {label}: \\\\.\\pipe\\{pipe_name} ({message}, error={err})")
        all_ok = all_ok and ok

    if not all_ok:
        print("[HEALTH] one or more pipes are missing. Check hostguard_demo startup and stale old DLL processes.")
        return False

    print("[HEALTH] requesting GET_RULES to verify rule channel response")
    request_rules("GET_RULES")
    print("[HEALTH] config pipe is Host-owned; this script intentionally does not connect/read it.")
    return True


def print_response(response):
    if not response:
        print("[WARN] empty response")
        return

    try:
        obj = json.loads(response)
        print(json.dumps(obj, ensure_ascii=False, indent=2))
    except Exception:
        print(response)


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def compact_json(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def send_detection():
    payload = compact_json({
        "id": "manual-detection-001",
        "ts": now_iso(),
        "sev": "high",
        "act": "detect",
        "cat": "Detection",
        "mod": "rasp_mod_amsi",
        "sensor": "ManualPipeTest",
        "rule": "manual-test-rule",
        "desc": "manual detection event test",
        "pattern": "manual-test",
        "payload": "powershell suspicious command",
    })
    send_pipe_payload(PIPE_EVENTS, payload)


def send_diag():
    payload = compact_json({
        "id": "manual-diag-001",
        "ts": now_iso(),
        "sev": "info",
        "act": "audit",
        "cat": "diag",
        "mod": "rasp_mod_amsi",
        "sensor": "RaspLog",
        "rule": "",
        "desc": "[manual] diagnostic log test",
        "pattern": "amsi-log",
        "payload": "",
    })
    send_pipe_payload(PIPE_EVENTS, payload)


def send_diag_repeat():
    try:
        count = int(input("重复次数，默认 20: ").strip() or "20")
    except ValueError:
        count = 20

    payload = compact_json({
        "id": "manual-diag-repeat",
        "ts": now_iso(),
        "sev": "info",
        "act": "audit",
        "cat": "diag",
        "mod": "rasp_mod_amsi",
        "sensor": "RaspLog",
        "rule": "",
        "desc": "[manual] repeated diagnostic log test",
        "pattern": "amsi-log",
        "payload": "",
    })

    for _ in range(count):
        send_pipe_payload(PIPE_EVENTS, payload)
        time.sleep(0.05)

    print(f"[OK] repeated diag sent, count={count}")


def send_drain_ack():
    payload = compact_json({
        "id": "manual-drain-ack-001",
        "ts": now_iso(),
        "cat": "drain-ack",
        "sensor": "RaspLog",
        "broadcastId": "manual-broadcast-id",
        "status": "ok",
    })
    send_pipe_payload(PIPE_EVENTS, payload)


def send_unknown_event():
    payload = compact_json({
        "id": "manual-unknown-001",
        "ts": now_iso(),
        "cat": "unknown-manual",
        "sensor": "ManualPipeTest",
        "payload": "unknown event test",
    })
    send_pipe_payload(PIPE_EVENTS, payload)


def send_oversized_event():
    payload = compact_json({
        "cat": "Detection",
        "sensor": "ManualPipeTest",
        "desc": "oversized event test",
        "payload": "A" * (70 * 1024),
    })
    send_pipe_payload(PIPE_EVENTS, payload)


def send_dll_loaded():
    payload = compact_json({
        "msgType": "DLL_LOADED",
        "module": "amsi_detect",
        "dllInstanceId": "manual-test-instance",
        "pid": 1234,
        "processPath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "parentPid": 1000,
        "parentProcessPath": r"C:\Windows\explorer.exe",
        "timestamp": now_iso(),
    })
    send_pipe_payload(PIPE_STATUS, payload)


def send_rule_load_success():
    payload = compact_json({
        "msgType": "RULE_LOAD_RESULT",
        "module": "amsi_detect",
        "dllInstanceId": "manual-test-instance",
        "pid": 1234,
        "timestamp": now_iso(),
        "requestedVersion": "manual-version",
        "requestedHash": "manual-hash",
        "activeVersion": "manual-version",
        "activeHash": "manual-hash",
        "success": True,
        "ruleCount": 1,
        "errorCode": 0,
        "errorMessage": "",
    })
    send_pipe_payload(PIPE_STATUS, payload)


def send_rule_load_failed():
    payload = compact_json({
        "msgType": "RULE_LOAD_RESULT",
        "module": "amsi_detect",
        "dllInstanceId": "manual-test-instance",
        "pid": 1234,
        "timestamp": now_iso(),
        "requestedVersion": "manual-version",
        "requestedHash": "manual-hash",
        "activeVersion": "",
        "activeHash": "",
        "success": False,
        "ruleCount": 0,
        "errorCode": 1001,
        "errorMessage": "manual rule load failed",
    })
    send_pipe_payload(PIPE_STATUS, payload)


def send_control_status():
    payload = compact_json({
        "msgType": "CONTROL_STATUS",
        "module": "amsi_detect",
        "dllInstanceId": "manual-test-instance",
        "pid": 1234,
        "timestamp": now_iso(),
        "command": "pause",
        "success": True,
        "errorCode": 0,
        "errorMessage": "",
    })
    send_pipe_payload(PIPE_STATUS, payload)


def send_oversized_status():
    payload = compact_json({
        "msgType": "DLL_LOADED",
        "module": "amsi_detect",
        "dllInstanceId": "manual-oversized-status",
        "pid": 1234,
        "timestamp": now_iso(),
        "padding": "S" * (70 * 1024),
    })
    send_pipe_payload(PIPE_STATUS, payload)


def show_menu():
    print("")
    print("========== AMSI IPC 交互测试 ==========")
    print("1. GET_RULES")
    print("2. GET_ALL_RULES")
    print("3. 发送 Detection event")
    print("4. 发送 DLL diagnostic log")
    print("5. 发送重复 DLL diagnostic log")
    print("6. 发送 drain-ack event")
    print("7. 发送 unknown event")
    print("8. 发送 oversized event")
    print("9. 发送 DLL_LOADED status")
    print("10. 发送 RULE_LOAD_RESULT success")
    print("11. 发送 RULE_LOAD_RESULT failed")
    print("12. 发送 CONTROL_STATUS")
    print("13. 发送 oversized status")
    print("14. 全部基础用例")
    print("15. Health check Host-owned production pipes")
    print("0. 退出")
    print("======================================")


def run_basic_all():
    request_rules("GET_RULES")
    request_rules("GET_ALL_RULES")
    send_detection()
    send_diag()
    send_drain_ack()
    send_unknown_event()
    send_dll_loaded()
    send_rule_load_success()
    send_rule_load_failed()
    send_control_status()


def main():
    print("AMSI detect named pipe interactive test")
    print("请确认 hostguard_demo.exe / hostguard.exe 已启动，并且 production pipe 已创建。")

    while True:
        show_menu()
        choice = input("请选择: ").strip()

        try:
            if choice == "1":
                request_rules("GET_RULES")
            elif choice == "2":
                request_rules("GET_ALL_RULES")
            elif choice == "3":
                send_detection()
            elif choice == "4":
                send_diag()
            elif choice == "5":
                send_diag_repeat()
            elif choice == "6":
                send_drain_ack()
            elif choice == "7":
                send_unknown_event()
            elif choice == "8":
                send_oversized_event()
            elif choice == "9":
                send_dll_loaded()
            elif choice == "10":
                send_rule_load_success()
            elif choice == "11":
                send_rule_load_failed()
            elif choice == "12":
                send_control_status()
            elif choice == "13":
                send_oversized_status()
            elif choice == "14":
                run_basic_all()
            elif choice == "15":
                health_check()
            elif choice == "0":
                print("退出")
                break
            else:
                print("无效选择")
        except Exception as exc:
            print(f"[ERROR] {exc}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--health":
        sys.exit(0 if health_check() else 1)
    main()
