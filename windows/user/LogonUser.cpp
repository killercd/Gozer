#include <windows.h>
#include <lm.h>
#include <algorithm>
#include <cctype>
#include <sddl.h>
#include <string>
#include <vector>
#include "LogonUser.h"

namespace
{
    std::string wideToString(const wchar_t *value)
    {
        if(value == NULL)
            return "";

        int needed = WideCharToMultiByte(CP_ACP, 0, value, -1, NULL, 0, NULL, NULL);
        if(needed <= 0)
            return "";

        std::vector<char> buffer(needed);
        if(WideCharToMultiByte(CP_ACP, 0, value, -1, buffer.data(), needed, NULL, NULL) == 0)
            return "";

        return buffer.data();
    }

    std::wstring stringToWide(const std::string &value)
    {
        if(value.empty())
            return std::wstring();

        int needed = MultiByteToWideChar(CP_ACP, 0, value.c_str(), -1, NULL, 0);
        if(needed <= 0)
            return std::wstring();

        std::vector<wchar_t> buffer(needed);
        if(MultiByteToWideChar(CP_ACP, 0, value.c_str(), -1, buffer.data(), needed) == 0)
            return std::wstring();

        return buffer.data();
    }

    std::string toLowerCopy(const std::string &value)
    {
        std::string lowered = value;
        std::transform(lowered.begin(),
                       lowered.end(),
                       lowered.begin(),
                       [](unsigned char ch) { return (char)std::tolower(ch); });
        return lowered;
    }

    void addUniqueGroup(std::vector<std::string> &groups, const std::string &groupName)
    {
        if(groupName.empty())
            return;

        if(std::find(groups.begin(), groups.end(), groupName) == groups.end())
            groups.push_back(groupName);
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

    std::string getAdministratorsGroupName()
    {
        BYTE adminSidBuffer[SECURITY_MAX_SID_SIZE];
        DWORD sidSize = sizeof(adminSidBuffer);
        PSID adminSid = (PSID)adminSidBuffer;

        if(CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, adminSid, &sidSize) == 0)
            return "Administrators";

        DWORD nameSize = 0;
        DWORD domainSize = 0;
        SID_NAME_USE sidType;

        LookupAccountSidA(NULL, adminSid, NULL, &nameSize, NULL, &domainSize, &sidType);
        if(nameSize == 0)
            return "Administrators";

        std::vector<char> nameBuffer(nameSize + 1, '\0');
        std::vector<char> domainBuffer(domainSize + 1, '\0');

        if(LookupAccountSidA(NULL,
                             adminSid,
                             nameBuffer.data(),
                             &nameSize,
                             domainBuffer.data(),
                             &domainSize,
                             &sidType) != 0)
        {
            return nameBuffer.data();
        }

        return "Administrators";
    }

    bool isSystemAccount(const std::string &userName)
    {
        const std::string normalized = toLowerCopy(userName);
        return normalized == "system" ||
               normalized == "localsystem" ||
               normalized == "nt authority\\system";
    }

    void loadLocalGroups(const std::string &userName, std::vector<std::string> &groups)
    {
        const std::wstring wideUserName = stringToWide(userName);
        if(wideUserName.empty())
            return;

        LOCALGROUP_USERS_INFO_0 *groupBuffer = NULL;
        DWORD entriesRead = 0;
        DWORD totalEntries = 0;

        NET_API_STATUS status = NetUserGetLocalGroups(NULL,
                                                      (LPWSTR)wideUserName.c_str(),
                                                      0,
                                                      LG_INCLUDE_INDIRECT,
                                                      (LPBYTE*)&groupBuffer,
                                                      MAX_PREFERRED_LENGTH,
                                                      &entriesRead,
                                                      &totalEntries);

        if(status == NERR_Success && groupBuffer != NULL)
        {
            for(DWORD i = 0; i < entriesRead; ++i)
                addUniqueGroup(groups, wideToString(groupBuffer[i].lgrui0_name));
        }

        if(groupBuffer != NULL)
            NetApiBufferFree(groupBuffer);
    }

    void loadGlobalGroups(const std::string &userName, std::vector<std::string> &groups)
    {
        const std::wstring wideUserName = stringToWide(userName);
        if(wideUserName.empty())
            return;

        GROUP_USERS_INFO_0 *groupBuffer = NULL;
        DWORD entriesRead = 0;
        DWORD totalEntries = 0;

        NET_API_STATUS status = NetUserGetGroups(NULL,
                                                 (LPWSTR)wideUserName.c_str(),
                                                 0,
                                                 (LPBYTE*)&groupBuffer,
                                                 MAX_PREFERRED_LENGTH,
                                                 &entriesRead,
                                                 &totalEntries);

        if(status == NERR_Success && groupBuffer != NULL)
        {
            for(DWORD i = 0; i < entriesRead; ++i)
                addUniqueGroup(groups, wideToString(groupBuffer[i].grui0_name));
        }

        if(groupBuffer != NULL)
            NetApiBufferFree(groupBuffer);
    }

    bool belongsToAdministrators(const std::vector<std::string> &groups, const std::string &administratorsGroup)
    {
        const std::string normalizedAdmin = toLowerCopy(administratorsGroup);

        for(std::vector<std::string>::const_iterator it = groups.begin(); it != groups.end(); ++it)
        {
            const std::string current = toLowerCopy(*it);
            if(current == normalizedAdmin)
                return true;

            const std::string::size_type slashPos = current.find('\\');
            if(slashPos != std::string::npos)
            {
                const std::string bareGroup = current.substr(slashPos + 1);
                if(bareGroup == normalizedAdmin)
                    return true;
            }
        }

        return false;
    }

    std::string privilegeLuidToName(const LUID &luid)
    {
        DWORD nameSize = 0;
        LookupPrivilegeNameW(NULL, const_cast<LUID*>(&luid), NULL, &nameSize);
        if(nameSize == 0)
            return "";

        std::vector<wchar_t> buffer(nameSize + 1, L'\0');
        if(LookupPrivilegeNameW(NULL, const_cast<LUID*>(&luid), buffer.data(), &nameSize) == 0)
            return "";

        return wideToString(buffer.data());
    }

    std::string privilegeNameToDisplayName(const std::string &privilegeName)
    {
        const std::wstring widePrivilegeName = stringToWide(privilegeName);
        if(widePrivilegeName.empty())
            return "";

        DWORD displayNameSize = 0;
        DWORD languageId = 0;
        LookupPrivilegeDisplayNameW(NULL,
                                    (LPWSTR)widePrivilegeName.c_str(),
                                    NULL,
                                    &displayNameSize,
                                    &languageId);

        if(displayNameSize == 0)
            return "";

        std::vector<wchar_t> buffer(displayNameSize + 1, L'\0');
        if(LookupPrivilegeDisplayNameW(NULL,
                                       (LPWSTR)widePrivilegeName.c_str(),
                                       buffer.data(),
                                       &displayNameSize,
                                       &languageId) == 0)
        {
            return "";
        }

        return wideToString(buffer.data());
    }
}

WinLogonUser::WinLogonUser()
{
}

std::vector<UserInfo> WinLogonUser::getUserList()
{
    std::vector<UserInfo> users;

    USER_INFO_0 *userBuffer = NULL;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;
    const std::string administratorsGroup = getAdministratorsGroupName();

    do
    {
        NET_API_STATUS status = NetUserEnum(NULL,
                                            0,
                                            FILTER_NORMAL_ACCOUNT,
                                            (LPBYTE*)&userBuffer,
                                            MAX_PREFERRED_LENGTH,
                                            &entriesRead,
                                            &totalEntries,
                                            &resumeHandle);

        if(status != NERR_Success && status != ERROR_MORE_DATA)
        {
            if(userBuffer != NULL)
                NetApiBufferFree(userBuffer);
            break;
        }

        for(DWORD i = 0; i < entriesRead; ++i)
        {
            UserInfo info;
            info.user = wideToString(userBuffer[i].usri0_name);

            loadLocalGroups(info.user, info.groups);
            loadGlobalGroups(info.user, info.groups);

            info.isAdministrator = isSystemAccount(info.user) ||
                                   belongsToAdministrators(info.groups, administratorsGroup);

            users.push_back(info);
        }

        if(userBuffer != NULL)
        {
            NetApiBufferFree(userBuffer);
            userBuffer = NULL;
        }

    } while(resumeHandle != 0);

    return users;
}

std::string WinLogonUser::getCurrentUser()
{
    HANDLE tokenHandle = NULL;
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == 0)
        return "";

    DWORD requiredBytes = 0;
    GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &requiredBytes);
    if(requiredBytes == 0)
    {
        CloseHandle(tokenHandle);
        return "";
    }

    std::vector<BYTE> tokenBuffer(requiredBytes);
    if(GetTokenInformation(tokenHandle,
                           TokenUser,
                           tokenBuffer.data(),
                           requiredBytes,
                           &requiredBytes) == 0)
    {
        CloseHandle(tokenHandle);
        return "";
    }

    TOKEN_USER *tokenUser = reinterpret_cast<TOKEN_USER*>(tokenBuffer.data());
    const std::string currentUser = sidToAccountName(tokenUser->User.Sid);

    CloseHandle(tokenHandle);
    return currentUser;
}

std::vector<std::string> WinLogonUser::getCurrentGroups()
{
    std::vector<std::string> groups;

    HANDLE tokenHandle = NULL;
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == 0)
        return groups;

    DWORD requiredBytes = 0;
    GetTokenInformation(tokenHandle, TokenGroups, NULL, 0, &requiredBytes);
    if(requiredBytes == 0)
    {
        CloseHandle(tokenHandle);
        return groups;
    }

    std::vector<BYTE> tokenBuffer(requiredBytes);
    if(GetTokenInformation(tokenHandle,
                           TokenGroups,
                           tokenBuffer.data(),
                           requiredBytes,
                           &requiredBytes) == 0)
    {
        CloseHandle(tokenHandle);
        return groups;
    }

    TOKEN_GROUPS *tokenGroups = reinterpret_cast<TOKEN_GROUPS*>(tokenBuffer.data());
    for(DWORD i = 0; i < tokenGroups->GroupCount; ++i)
        addUniqueGroup(groups, sidToAccountName(tokenGroups->Groups[i].Sid));

    CloseHandle(tokenHandle);
    return groups;
}

std::vector<UserPrivilege> WinLogonUser::getCurrentPrivileges()
{
    std::vector<UserPrivilege> privileges;

    HANDLE tokenHandle = NULL;
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == 0)
        return privileges;

    DWORD requiredBytes = 0;
    GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &requiredBytes);
    if(requiredBytes == 0)
    {
        CloseHandle(tokenHandle);
        return privileges;
    }

    std::vector<BYTE> tokenBuffer(requiredBytes);
    if(GetTokenInformation(tokenHandle,
                           TokenPrivileges,
                           tokenBuffer.data(),
                           requiredBytes,
                           &requiredBytes) == 0)
    {
        CloseHandle(tokenHandle);
        return privileges;
    }

    TOKEN_PRIVILEGES *tokenPrivileges = reinterpret_cast<TOKEN_PRIVILEGES*>(tokenBuffer.data());
    for(DWORD i = 0; i < tokenPrivileges->PrivilegeCount; ++i)
    {
        const LUID_AND_ATTRIBUTES &entry = tokenPrivileges->Privileges[i];

        UserPrivilege privilege;
        privilege.priv = privilegeLuidToName(entry.Luid);
        privilege.description = privilegeNameToDisplayName(privilege.priv);
        privilege.enabled = (entry.Attributes & SE_PRIVILEGE_ENABLED) != 0;

        privileges.push_back(privilege);
    }

    CloseHandle(tokenHandle);
    return privileges;
}
