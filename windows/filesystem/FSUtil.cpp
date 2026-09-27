#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <algorithm>
#include <string>
#include <vector>
#include "FSUtil.h"

namespace
{
    struct CurrentTokenInfo
    {
        std::vector<std::string> sidStrings;
        HANDLE impersonationToken = NULL;
    };

    std::string joinPath(const std::string &base, const std::string &name)
    {
        if(base.empty())
            return name;

        const char lastChar = base[base.size() - 1];
        if(lastChar == '\\' || lastChar == '/')
            return base + name;

        return base + "\\" + name;
    }

    std::string normalizePath(const std::string &path)
    {
        if(path.empty())
            return path;

        char fullPath[MAX_PATH];
        DWORD result = GetFullPathNameA(path.c_str(), MAX_PATH, fullPath, NULL);
        if(result == 0 || result >= MAX_PATH)
            return path;

        return fullPath;
    }

    void addUniqueString(std::vector<std::string> &values, const std::string &value)
    {
        if(value.empty())
            return;

        if(std::find(values.begin(), values.end(), value) == values.end())
            values.push_back(value);
    }

    std::string sidToString(PSID sid)
    {
        if(sid == NULL)
            return "";

        LPSTR sidString = NULL;
        if(ConvertSidToStringSidA(sid, &sidString) == 0 || sidString == NULL)
            return "";

        std::string result = sidString;
        LocalFree(sidString);
        return result;
    }

    std::string sidToAccountName(PSID sid, SID_NAME_USE *sidTypeOut = NULL)
    {
        if(sid == NULL)
            return "";

        DWORD nameSize = 0;
        DWORD domainSize = 0;
        SID_NAME_USE sidType = SidTypeUnknown;

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
                if(sidTypeOut != NULL)
                    *sidTypeOut = sidType;

                if(domainSize > 0 && domainBuffer[0] != '\0')
                    return std::string(domainBuffer.data()) + "\\" + nameBuffer.data();

                return nameBuffer.data();
            }
        }

        if(sidTypeOut != NULL)
            *sidTypeOut = sidType;

        return sidToString(sid);
    }

    bool isWritableMask(DWORD mask)
    {
        const DWORD writeMask =
            GENERIC_WRITE |
            GENERIC_ALL |
            FILE_GENERIC_WRITE |
            FILE_ALL_ACCESS |
            FILE_WRITE_DATA |
            FILE_APPEND_DATA |
            FILE_ADD_FILE |
            FILE_ADD_SUBDIRECTORY |
            FILE_WRITE_ATTRIBUTES |
            FILE_WRITE_EA |
            DELETE |
            WRITE_DAC |
            WRITE_OWNER;

        return (mask & writeMask) != 0;
    }

    bool isGroupType(SID_NAME_USE sidType)
    {
        return sidType == SidTypeGroup ||
               sidType == SidTypeWellKnownGroup ||
               sidType == SidTypeAlias;
    }

    bool hasEffectiveAccess(const CurrentTokenInfo &currentToken,
                            PSECURITY_DESCRIPTOR securityDescriptor,
                            DWORD desiredAccess)
    {
        if(currentToken.impersonationToken == NULL || securityDescriptor == NULL)
            return false;

        GENERIC_MAPPING genericMapping;
        genericMapping.GenericRead = FILE_GENERIC_READ;
        genericMapping.GenericWrite = FILE_GENERIC_WRITE;
        genericMapping.GenericExecute = FILE_GENERIC_EXECUTE;
        genericMapping.GenericAll = FILE_ALL_ACCESS;

        DWORD mappedAccess = desiredAccess;
        MapGenericMask(&mappedAccess, &genericMapping);

        BYTE privilegeBuffer[sizeof(PRIVILEGE_SET) + (sizeof(LUID_AND_ATTRIBUTES) * 16)];
        PRIVILEGE_SET *privilegeSet = reinterpret_cast<PRIVILEGE_SET*>(privilegeBuffer);
        DWORD privilegeSetLength = sizeof(privilegeBuffer);
        DWORD grantedAccess = 0;
        BOOL accessStatus = FALSE;

        if(AccessCheck(securityDescriptor,
                       currentToken.impersonationToken,
                       mappedAccess,
                       &genericMapping,
                       privilegeSet,
                       &privilegeSetLength,
                       &grantedAccess,
                       &accessStatus) == 0)
        {
            return false;
        }

        return accessStatus != FALSE;
    }

    bool isEffectivelyWritable(const CurrentTokenInfo &currentToken,
                               PSECURITY_DESCRIPTOR securityDescriptor,
                               bool isDirectory)
    {
        const DWORD commonWriteRights[] =
        {
            FILE_WRITE_EA,
            FILE_WRITE_ATTRIBUTES,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER
        };

        if(isDirectory)
        {
            if(hasEffectiveAccess(currentToken, securityDescriptor, FILE_ADD_FILE) ||
               hasEffectiveAccess(currentToken, securityDescriptor, FILE_ADD_SUBDIRECTORY))
            {
                return true;
            }
        }
        else
        {
            if(hasEffectiveAccess(currentToken, securityDescriptor, FILE_WRITE_DATA) ||
               hasEffectiveAccess(currentToken, securityDescriptor, FILE_APPEND_DATA))
            {
                return true;
            }
        }

        for(size_t i = 0; i < (sizeof(commonWriteRights) / sizeof(commonWriteRights[0])); ++i)
        {
            if(hasEffectiveAccess(currentToken, securityDescriptor, commonWriteRights[i]))
                return true;
        }

        return false;
    }

    void closeCurrentTokenInfo(CurrentTokenInfo &info)
    {
        if(info.impersonationToken != NULL)
        {
            CloseHandle(info.impersonationToken);
            info.impersonationToken = NULL;
        }
    }

    CurrentTokenInfo getCurrentTokenInfo()
    {
        CurrentTokenInfo info;

        HANDLE tokenHandle = NULL;
        if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &tokenHandle) == 0)
            return info;

        DWORD requiredBytes = 0;
        GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &requiredBytes);
        if(requiredBytes > 0)
        {
            std::vector<BYTE> userBuffer(requiredBytes);
            if(GetTokenInformation(tokenHandle,
                                   TokenUser,
                                   userBuffer.data(),
                                   requiredBytes,
                                   &requiredBytes) != 0)
            {
                TOKEN_USER *tokenUser = reinterpret_cast<TOKEN_USER*>(userBuffer.data());
                addUniqueString(info.sidStrings, sidToString(tokenUser->User.Sid));
            }
        }

        requiredBytes = 0;
        GetTokenInformation(tokenHandle, TokenGroups, NULL, 0, &requiredBytes);
        if(requiredBytes > 0)
        {
            std::vector<BYTE> groupsBuffer(requiredBytes);
            if(GetTokenInformation(tokenHandle,
                                   TokenGroups,
                                   groupsBuffer.data(),
                                   requiredBytes,
                                   &requiredBytes) != 0)
            {
                TOKEN_GROUPS *tokenGroups = reinterpret_cast<TOKEN_GROUPS*>(groupsBuffer.data());
                for(DWORD i = 0; i < tokenGroups->GroupCount; ++i)
                    addUniqueString(info.sidStrings, sidToString(tokenGroups->Groups[i].Sid));
            }
        }

        DuplicateToken(tokenHandle, SecurityImpersonation, &info.impersonationToken);
        CloseHandle(tokenHandle);
        return info;
    }

    void inspectWritePermissions(const std::string &path, FindFilesResult &result, const CurrentTokenInfo &currentToken)
    {
        PSECURITY_DESCRIPTOR securityDescriptor = NULL;
        PSID ownerSid = NULL;
        PSID groupSid = NULL;
        PACL dacl = NULL;

        DWORD secInfoResult = GetNamedSecurityInfoA((LPSTR)path.c_str(),
                                                    SE_FILE_OBJECT,
                                                    OWNER_SECURITY_INFORMATION |
                                                    GROUP_SECURITY_INFORMATION |
                                                    DACL_SECURITY_INFORMATION,
                                                    &ownerSid,
                                                    &groupSid,
                                                    &dacl,
                                                    NULL,
                                                    &securityDescriptor);
        if(secInfoResult != ERROR_SUCCESS || dacl == NULL)
        {
            if(securityDescriptor != NULL)
                LocalFree(securityDescriptor);
            return;
        }

        ACL_SIZE_INFORMATION aclInfo;
        aclInfo.AceCount = 0;
        aclInfo.AclBytesFree = 0;
        aclInfo.AclBytesInUse = 0;

        if(GetAclInformation(dacl, &aclInfo, sizeof(aclInfo), AclSizeInformation) == 0)
        {
            LocalFree(securityDescriptor);
            return;
        }

        for(DWORD i = 0; i < aclInfo.AceCount; ++i)
        {
            LPVOID ace = NULL;
            if(GetAce(dacl, i, &ace) == 0 || ace == NULL)
                continue;

            ACE_HEADER *aceHeader = reinterpret_cast<ACE_HEADER*>(ace);
            if(aceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
                continue;

            ACCESS_ALLOWED_ACE *allowedAce = reinterpret_cast<ACCESS_ALLOWED_ACE*>(ace);
            if(!isWritableMask(allowedAce->Mask))
                continue;

            PSID sid = reinterpret_cast<PSID>(&allowedAce->SidStart);
            SID_NAME_USE sidType = SidTypeUnknown;
            const std::string accountName = sidToAccountName(sid, &sidType);
            const std::string sidString = sidToString(sid);

            if(isGroupType(sidType))
                addUniqueString(result.groupsCanWrite, accountName);
            else
                addUniqueString(result.usersCanWrite, accountName);

            if(std::find(currentToken.sidStrings.begin(),
                         currentToken.sidStrings.end(),
                         sidString) != currentToken.sidStrings.end())
            {
                result.isWritableByUser = true;
            }
        }

        result.isWritableByUser = isEffectivelyWritable(currentToken, securityDescriptor, result.isDirectory);
        LocalFree(securityDescriptor);
    }

    FindFilesResult buildFileInfo(const std::string &path,
                                  const WIN32_FIND_DATAA *findData,
                                  const CurrentTokenInfo &currentToken)
    {
        FindFilesResult result;
        result.filePath = normalizePath(path);

        if(findData != NULL)
        {
            result.fileName = findData->cFileName;
            result.isDirectory = (findData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        }
        else
        {
            result.fileName = result.filePath;

            DWORD attributes = GetFileAttributesA(path.c_str());
            if(attributes != INVALID_FILE_ATTRIBUTES)
                result.isDirectory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        }

        inspectWritePermissions(result.filePath, result, currentToken);
        return result;
    }

    void enumerateFiles(const std::string &baseDir,
                        const std::string &searchMask,
                        bool recursive,
                        const CurrentTokenInfo &currentToken,
                        std::vector<FindFilesResult> &results)
    {
        WIN32_FIND_DATAA findData;
        HANDLE findHandle = FindFirstFileA(joinPath(baseDir, searchMask).c_str(), &findData);
        if(findHandle != INVALID_HANDLE_VALUE)
        {
            do
            {
                if(strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
                    continue;

                results.push_back(buildFileInfo(joinPath(baseDir, findData.cFileName), &findData, currentToken));
            }
            while(FindNextFileA(findHandle, &findData) != 0);

            FindClose(findHandle);
        }

        if(!recursive)
            return;

        HANDLE dirHandle = FindFirstFileA(joinPath(baseDir, "*").c_str(), &findData);
        if(dirHandle == INVALID_HANDLE_VALUE)
            return;

        do
        {
            if(strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
                continue;

            const bool isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const bool isReparsePoint = (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
            if(isDirectory && !isReparsePoint)
                enumerateFiles(joinPath(baseDir, findData.cFileName), searchMask, true, currentToken, results);
        }
        while(FindNextFileA(dirHandle, &findData) != 0);

        FindClose(dirHandle);
    }
}

FSUtil::FSUtil()
{
}

std::vector<FindFilesResult> FSUtil::findFiles(std::string baseDir, std::string searchMask, bool recursive)
{
    std::vector<FindFilesResult> results;

    if(baseDir.empty() || searchMask.empty())
        return results;

    const std::string normalizedBaseDir = normalizePath(baseDir);
    CurrentTokenInfo currentToken = getCurrentTokenInfo();

    enumerateFiles(normalizedBaseDir, searchMask, recursive, currentToken, results);
    closeCurrentTokenInfo(currentToken);
    return results;
}

FindFilesResult FSUtil::getFileInfo(std::string path)
{
    CurrentTokenInfo currentToken = getCurrentTokenInfo();
    FindFilesResult result = buildFileInfo(path, NULL, currentToken);
    closeCurrentTokenInfo(currentToken);
    return result;
}
