#include "PipeSecurity.h"

#include <aclapi.h>

bool MakeAuthenticatedUsersSecurity(SECURITY_ATTRIBUTES* pSa, PACL* pAcl)
{
    if (pAcl) {
        *pAcl = nullptr;
    }
    if (!pSa || !pAcl) {
        return false;
    }

    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID authUsersSid = nullptr;
    if (!AllocateAndInitializeSid(&ntAuth,
                                  1,
                                  SECURITY_AUTHENTICATED_USER_RID,
                                  0,
                                  0,
                                  0,
                                  0,
                                  0,
                                  0,
                                  0,
                                  &authUsersSid)) {
        return false;
    }

    EXPLICIT_ACCESS ea = {};
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | FILE_CREATE_PIPE_INSTANCE;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = static_cast<LPTSTR>(authUsersSid);

    PACL acl = nullptr;
    DWORD result = SetEntriesInAcl(1, &ea, nullptr, &acl);
    FreeSid(authUsersSid);
    if (result != ERROR_SUCCESS) {
        return false;
    }

    PSECURITY_DESCRIPTOR sd = static_cast<PSECURITY_DESCRIPTOR>(
        LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH));
    if (!sd) {
        LocalFree(acl);
        return false;
    }

    if (!InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE)) {
        LocalFree(sd);
        LocalFree(acl);
        return false;
    }

    pSa->nLength = sizeof(SECURITY_ATTRIBUTES);
    pSa->lpSecurityDescriptor = sd;
    pSa->bInheritHandle = FALSE;
    *pAcl = acl;
    return true;
}

void FreePipeSecurity(SECURITY_ATTRIBUTES* pSa, PACL acl)
{
    if (pSa && pSa->lpSecurityDescriptor) {
        LocalFree(pSa->lpSecurityDescriptor);
        pSa->lpSecurityDescriptor = nullptr;
    }
    if (acl) {
        LocalFree(acl);
    }
}
