#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

bool MakeAuthenticatedUsersSecurity(SECURITY_ATTRIBUTES* pSa, PACL* pAcl);
void FreePipeSecurity(SECURITY_ATTRIBUTES* pSa, PACL acl);
