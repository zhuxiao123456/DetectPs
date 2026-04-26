#pragma once
// sentry_log.h — structured logger matching the C# SentryLog format exactly.
// Log line format: [YYYY-MM-DD HH:mm:ss.fff UTC] LEVEL [COMPONENT] message
// Output: console (stdout) + daily rasp-sentry-diag-YYYY-MM-DD.log file.

#include <cstdarg>

void SentryLog_Initialize(const char* logDir);
void SentryLog_Info (const char* component, const char* fmt, ...);
void SentryLog_Warn (const char* component, const char* fmt, ...);
void SentryLog_Error(const char* component, const char* fmt, ...);
