#include <windows.h>
#include <winsvc.h>
#include <aclapi.h>
#include <sddl.h>
#include <algorithm>
#include <string>
#include <vector>
#include "services.h"

namespace
{
    void addUniqueUser(std::vector<std::string> &users, const std::string &user)
    {
        if(user.empty())
            return;

        if(std::find(users.begin(), users.end(), user) == users.end())
            users.push_back(user);
    }

    std::string sidToAccountName(PSID sid)
    {
        if(sid == NULL)
            return "";

        DWORD nameSize = 0;
        DWORD domainSize = 0;
        SID_NAME_USE sidType;

        LookupAccountSidA(NULL, sid, NULL, &nameSize, NULL, &domainSize, &sidType);

        if(nameSize > 0)
        {
            std::vector<char> nameBuffer(nameSize + 1, '\0');
            std::vector<char> domainBuffer(domainSize + 1, '\0');

            if(LookupAccountSidA(NULL,
                                 sid,
                                 nameBuffer.data(),
                                 &nameSize,
                                 domainBuffer.data(),
                                 &domainSize,
                                 &sidType) != 0)
            {
                if(domainSize > 0 && domainBuffer[0] != '\0')
                    return std::string(domainBuffer.data()) + "\\" + nameBuffer.data();

                return nameBuffer.data();
            }
        }

        LPSTR sidString = NULL;
        if(ConvertSidToStringSidA(sid, &sidString) != 0 && sidString != NULL)
        {
            std::string fallback = sidString;
            LocalFree(sidString);
            return fallback;
        }

        return "";
    }

    void applyMaskToPermissions(ServicePermission &permissions, DWORD mask, const std::string &accountName)
    {
        if((mask & SERVICE_START) == SERVICE_START)
            addUniqueUser(permissions.userCanStart, accountName);

        if((mask & SERVICE_STOP) == SERVICE_STOP)
            addUniqueUser(permissions.userCanStop, accountName);

        if((mask & SERVICE_PAUSE_CONTINUE) == SERVICE_PAUSE_CONTINUE)
            addUniqueUser(permissions.userCanPause, accountName);

        if((mask & SERVICE_QUERY_STATUS) == SERVICE_QUERY_STATUS)
            addUniqueUser(permissions.userCanQuery, accountName);

        if((mask & (SERVICE_START | SERVICE_STOP)) == (SERVICE_START | SERVICE_STOP))
            addUniqueUser(permissions.userCanRestart, accountName);
    }

    ServicePermission queryServicePermissions(SC_HANDLE scmHandle, const char *serviceName)
    {
        ServicePermission permissions;

        if(scmHandle == NULL || serviceName == NULL)
            return permissions;

        SC_HANDLE serviceHandle = OpenServiceA(scmHandle, serviceName, READ_CONTROL);
        if(serviceHandle == NULL)
            return permissions;

        DWORD requiredBytes = 0;
        QueryServiceObjectSecurity(serviceHandle,
                                   DACL_SECURITY_INFORMATION,
                                   NULL,
                                   0,
                                   &requiredBytes);

        if(requiredBytes == 0)
        {
            CloseServiceHandle(serviceHandle);
            return permissions;
        }

        std::vector<BYTE> securityDescriptorBuffer(requiredBytes);

        if(QueryServiceObjectSecurity(serviceHandle,
                                      DACL_SECURITY_INFORMATION,
                                      (PSECURITY_DESCRIPTOR)securityDescriptorBuffer.data(),
                                      requiredBytes,
                                      &requiredBytes) == 0)
        {
            CloseServiceHandle(serviceHandle);
            return permissions;
        }

        BOOL daclPresent = FALSE;
        BOOL daclDefaulted = FALSE;
        PACL dacl = NULL;

        if(GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)securityDescriptorBuffer.data(),
                                     &daclPresent,
                                     &dacl,
                                     &daclDefaulted) == 0 ||
           daclPresent == FALSE ||
           dacl == NULL)
        {
            CloseServiceHandle(serviceHandle);
            return permissions;
        }

        for(DWORD i = 0; i < dacl->AceCount; ++i)
        {
            LPVOID ace = NULL;
            if(GetAce(dacl, i, &ace) == 0 || ace == NULL)
                continue;

            ACE_HEADER *header = (ACE_HEADER*)ace;
            DWORD accessMask = 0;
            PSID sid = NULL;

            if(header->AceType == ACCESS_ALLOWED_ACE_TYPE)
            {
                ACCESS_ALLOWED_ACE *allowedAce = (ACCESS_ALLOWED_ACE*)ace;
                accessMask = allowedAce->Mask;
                sid = (PSID)&allowedAce->SidStart;
            }
            else
                continue;

            applyMaskToPermissions(permissions, accessMask, sidToAccountName(sid));
        }

        CloseServiceHandle(serviceHandle);
        return permissions;
    }

    std::string serviceStateToString(DWORD currentState)
    {
        switch(currentState)
        {
            case SERVICE_STOPPED:
                return "STOPPED";
            case SERVICE_START_PENDING:
                return "START_PENDING";
            case SERVICE_STOP_PENDING:
                return "STOP_PENDING";
            case SERVICE_RUNNING:
                return "RUNNING";
            case SERVICE_CONTINUE_PENDING:
                return "CONTINUE_PENDING";
            case SERVICE_PAUSE_PENDING:
                return "PAUSE_PENDING";
            case SERVICE_PAUSED:
                return "PAUSED";
            default:
                return "UNKNOWN";
        }
    }

    std::string queryBinaryPath(SC_HANDLE scmHandle, const char *serviceName)
    {
        if(scmHandle == NULL || serviceName == NULL)
            return "";

        SC_HANDLE serviceHandle = OpenServiceA(scmHandle, serviceName, SERVICE_QUERY_CONFIG);
        if(serviceHandle == NULL)
            return "";

        DWORD requiredBytes = 0;
        QueryServiceConfigA(serviceHandle, NULL, 0, &requiredBytes);

        if(requiredBytes == 0)
        {
            CloseServiceHandle(serviceHandle);
            return "";
        }

        std::vector<char> configBuffer(requiredBytes);
        LPQUERY_SERVICE_CONFIGA config =
            reinterpret_cast<LPQUERY_SERVICE_CONFIGA>(configBuffer.data());

        std::string binaryPath;
        if(QueryServiceConfigA(serviceHandle, config, requiredBytes, &requiredBytes) != 0 &&
           config->lpBinaryPathName != NULL)
        {
            binaryPath = config->lpBinaryPathName;
        }

        CloseServiceHandle(serviceHandle);
        return binaryPath;
    }
}

WinServices::WinServices()
{
}

std::vector<ServiceSpec> WinServices::getEnumService()
{
    std::vector<ServiceSpec> services;

    SC_HANDLE scmHandle = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if(scmHandle == NULL)
        return services;

    DWORD bytesNeeded = 0;
    DWORD serviceCount = 0;
    DWORD resumeHandle = 0;
    DWORD lastError = ERROR_MORE_DATA;

    while(lastError == ERROR_MORE_DATA || resumeHandle != 0 || services.empty())
    {
        bytesNeeded = 0;
        serviceCount = 0;

        EnumServicesStatusExA(scmHandle,
                              SC_ENUM_PROCESS_INFO,
                              SERVICE_WIN32,
                              SERVICE_STATE_ALL,
                              NULL,
                              0,
                              &bytesNeeded,
                              &serviceCount,
                              &resumeHandle,
                              NULL);

        lastError = GetLastError();
        if(lastError != ERROR_MORE_DATA && bytesNeeded == 0)
            break;

        std::vector<BYTE> buffer(bytesNeeded);
        DWORD currentResumeHandle = resumeHandle;

        if(EnumServicesStatusExA(scmHandle,
                                 SC_ENUM_PROCESS_INFO,
                                 SERVICE_WIN32,
                                 SERVICE_STATE_ALL,
                                 buffer.data(),
                                 bytesNeeded,
                                 &bytesNeeded,
                                 &serviceCount,
                                 &currentResumeHandle,
                                 NULL) == 0)
        {
            if(GetLastError() != ERROR_MORE_DATA)
                break;

            resumeHandle = currentResumeHandle;
            lastError = ERROR_MORE_DATA;
            continue;
        }

        ENUM_SERVICE_STATUS_PROCESSA *entries =
            reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buffer.data());

        for(DWORD i = 0; i < serviceCount; ++i)
        {
            ServiceSpec spec;
            spec.serviceName = entries[i].lpServiceName != NULL ? entries[i].lpServiceName : "";
            spec.status = serviceStateToString(entries[i].ServiceStatusProcess.dwCurrentState);
            spec.path = queryBinaryPath(scmHandle, spec.serviceName.c_str());
            spec.permissions = queryServicePermissions(scmHandle, spec.serviceName.c_str());
            services.push_back(spec);
        }

        resumeHandle = currentResumeHandle;
        lastError = resumeHandle == 0 ? ERROR_SUCCESS : ERROR_MORE_DATA;
    }

    CloseServiceHandle(scmHandle);
    return services;
}
