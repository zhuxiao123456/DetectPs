#pragma once
// pipe_security.h — Named pipe security descriptor helpers.
// Mirrors C# PipeHelper.PublicSecurity(): grants Authenticated Users
// (S-1-5-11) read+write+create-instance access on server pipes.
//
// Usage:
//   SECURITY_ATTRIBUTES sa; PACL acl;
//   if (MakeAuthenticatedUsersSecurity(&sa, &acl)) {
//       HANDLE h = CreateNamedPipeW(..., &sa);
//       FreePipeSecurity(&sa, acl);
//   }

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

// Builds a SECURITY_ATTRIBUTES and ACL granting Authenticated Users
// GENERIC_READ | GENERIC_WRITE | FILE_CREATE_PIPE_INSTANCE.
// Returns true on success. On failure returns false; caller should fall back
// to a NULL DACL (pass nullptr as lpSecurityAttributes to CreateNamedPipeW).
bool MakeAuthenticatedUsersSecurity(SECURITY_ATTRIBUTES* pSa, PACL* pAcl);

// Frees the ACL and SECURITY_DESCRIPTOR allocated by MakeAuthenticatedUsersSecurity.
void FreePipeSecurity(SECURITY_ATTRIBUTES* pSa, PACL acl);
