#include "pipe_security.h"

bool MakeAuthenticatedUsersSecurity(SECURITY_ATTRIBUTES* pSa, PACL* pAcl)
{
    if (pAcl) {
        *pAcl = nullptr;
    }
    if (pSa) {
        pSa->nLength = sizeof(SECURITY_ATTRIBUTES);
        pSa->lpSecurityDescriptor = nullptr;
        pSa->bInheritHandle = FALSE;
    }
    return false;
}

void FreePipeSecurity(SECURITY_ATTRIBUTES* pSa, PACL)
{
    if (pSa) {
        pSa->lpSecurityDescriptor = nullptr;
    }
}
