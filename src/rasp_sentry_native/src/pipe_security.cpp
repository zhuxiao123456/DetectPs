#include "pipe_security.h"
#include <aclapi.h>

bool MakeAuthenticatedUsersSecurity(SECURITY_ATTRIBUTES* pSa, PACL* pAcl)
{
    *pAcl = nullptr;
    if (!pSa) return false;

    // S-1-5-11 = Authenticated Users
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID authUsersSid = nullptr;
    if (!AllocateAndInitializeSid(&ntAuth, 1,
            SECURITY_AUTHENTICATED_USER_RID,
            0, 0, 0, 0, 0, 0, 0,
            &authUsersSid))
        return false;

    EXPLICIT_ACCESS ea = {};
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | FILE_CREATE_PIPE_INSTANCE;
    ea.grfAccessMode        = SET_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName    = static_cast<LPTSTR>(authUsersSid);

    PACL acl = nullptr;
    DWORD r = SetEntriesInAcl(1, &ea, nullptr, &acl);
    FreeSid(authUsersSid);
    if (r != ERROR_SUCCESS) return false;

    PSECURITY_DESCRIPTOR pSd = static_cast<PSECURITY_DESCRIPTOR>(
        LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH));
    if (!pSd) { LocalFree(acl); return false; }

    InitializeSecurityDescriptor(pSd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(pSd, TRUE, acl, FALSE);

    pSa->nLength              = sizeof(SECURITY_ATTRIBUTES);
    pSa->lpSecurityDescriptor = pSd;
    pSa->bInheritHandle       = FALSE;
    *pAcl = acl;
    return true;
}

void FreePipeSecurity(SECURITY_ATTRIBUTES* pSa, PACL acl)
{
    if (pSa && pSa->lpSecurityDescriptor)
    {
        LocalFree(pSa->lpSecurityDescriptor);
        pSa->lpSecurityDescriptor = nullptr;
    }
    if (acl)
        LocalFree(acl);
}
