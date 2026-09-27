#include <algorithm>
#include <cctype>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include "windows/services/services.h"
#include "windows/user/LogonUser.h"
#include "windows/filesystem/FSUtil.h"
#include "windows/tasks/TaskUtil.h"


using namespace std;
#define RED "\033[31m"
#define YELLOW "\033[33m"
#define RED_ON_YELLOW "\033[31;43m"
#define GREEN "\033[32m"
#define RESET "\033[0m"
namespace
{
    void enableAnsiColorMode()
    {
        HANDLE outputHandles[] = { GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle(STD_ERROR_HANDLE) };
        for(size_t i = 0; i < (sizeof(outputHandles) / sizeof(outputHandles[0])); ++i)
        {
            HANDLE handle = outputHandles[i];
            if(handle == INVALID_HANDLE_VALUE || handle == NULL)
                continue;

            DWORD consoleMode = 0;
            if(GetConsoleMode(handle, &consoleMode) == 0)
                continue;

            consoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            consoleMode |= DISABLE_NEWLINE_AUTO_RETURN;
            SetConsoleMode(handle, consoleMode);
        }
    }

    struct PrivilegeRiskInfo
    {
        const char *privilegeName;
        const char *severity;
        const char *abuseDescription;
    };

    wstring stringToWide(const string &value)
    {
        if(value.empty())
            return L"";

        int needed = MultiByteToWideChar(CP_ACP, 0, value.c_str(), -1, NULL, 0);
        if(needed <= 0)
            return L"";

        vector<wchar_t> buffer((size_t)needed);
        if(MultiByteToWideChar(CP_ACP, 0, value.c_str(), -1, buffer.data(), needed) == 0)
            return L"";

        return buffer.data();
    }

    string wideToString(const wstring &value)
    {
        if(value.empty())
            return "";

        int needed = WideCharToMultiByte(CP_ACP, 0, value.c_str(), -1, NULL, 0, NULL, NULL);
        if(needed <= 0)
            return "";

        vector<char> buffer((size_t)needed);
        if(WideCharToMultiByte(CP_ACP, 0, value.c_str(), -1, buffer.data(), needed, NULL, NULL) == 0)
            return "";

        return buffer.data();
    }

    string toLowerCopy(const string &value)
    {
        string lowered = value;
        transform(lowered.begin(),
                  lowered.end(),
                  lowered.begin(),
                  [](unsigned char ch) { return (char)tolower(ch); });
        return lowered;
    }

    wstring toLowerWideCopy(const wstring &value)
    {
        wstring lowered = value;
        transform(lowered.begin(),
                  lowered.end(),
                  lowered.begin(),
                  [](wchar_t ch) { return (wchar_t)towlower(ch); });
        return lowered;
    }

    wstring trimWide(const wstring &value)
    {
        size_t start = 0;
        while(start < value.size() && iswspace(value[start]) != 0)
            ++start;

        size_t end = value.size();
        while(end > start && iswspace(value[end - 1]) != 0)
            --end;

        return value.substr(start, end - start);
    }

    wstring stripQuotes(const wstring &value)
    {
        wstring result = trimWide(value);
        while(result.size() >= 2 && result.front() == L'"' && result.back() == L'"')
            result = trimWide(result.substr(1, result.size() - 2));
        return result;
    }

    wstring expandEnvironmentStringsValue(const wstring &value)
    {
        const wstring trimmed = trimWide(value);
        if(trimmed.empty())
            return L"";

        DWORD needed = ExpandEnvironmentStringsW(trimmed.c_str(), NULL, 0);
        if(needed == 0)
            return trimmed;

        vector<wchar_t> buffer((size_t)needed);
        DWORD written = ExpandEnvironmentStringsW(trimmed.c_str(), buffer.data(), needed);
        if(written == 0 || written > needed)
            return trimmed;

        return buffer.data();
    }

    wstring trimTrailingPathPunctuation(const wstring &value)
    {
        wstring result = value;
        while(!result.empty())
        {
            const wchar_t lastChar = result[result.size() - 1];
            if(lastChar == L',' || lastChar == L';')
            {
                result.erase(result.size() - 1);
                continue;
            }

            break;
        }

        return result;
    }

    wstring normalizePathCandidate(const wstring &value)
    {
        wstring expanded = stripQuotes(expandEnvironmentStringsValue(value));
        expanded = trimTrailingPathPunctuation(expanded);
        if(expanded.empty())
            return L"";

        DWORD needed = GetFullPathNameW(expanded.c_str(), 0, NULL, NULL);
        if(needed == 0)
            return expanded;

        vector<wchar_t> buffer((size_t)needed);
        DWORD written = GetFullPathNameW(expanded.c_str(), needed, buffer.data(), NULL);
        if(written == 0 || written >= needed)
            return expanded;

        return buffer.data();
    }

    wstring getFileNameFromPath(const wstring &path)
    {
        const size_t pos = path.find_last_of(L"\\/");
        if(pos == wstring::npos)
            return path;

        return path.substr(pos + 1);
    }

    bool isFilePathExisting(const wstring &path)
    {
        if(path.empty())
            return false;

        DWORD attributes = GetFileAttributesW(path.c_str());
        if(attributes == INVALID_FILE_ATTRIBUTES)
            return false;

        return (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    wstring getParentDirectory(const wstring &path)
    {
        const size_t pos = path.find_last_of(L"\\/");
        if(pos == wstring::npos)
            return L"";

        return path.substr(0, pos);
    }

    bool hasInterestingExtension(const wstring &path)
    {
        const wstring lowerPath = toLowerWideCopy(path);
        static const wchar_t *extensions[] =
        {
            L".exe", L".dll", L".sys", L".com", L".bat", L".cmd",
            L".ps1", L".psm1", L".vbs", L".vbe", L".js", L".jse",
            L".wsf", L".wsh", L".hta", L".msc", L".jar", L".msi",
            L".ocx", L".scr"
        };

        for(size_t i = 0; i < (sizeof(extensions) / sizeof(extensions[0])); ++i)
        {
            const wstring extension = extensions[i];
            if(lowerPath.size() >= extension.size() &&
               lowerPath.compare(lowerPath.size() - extension.size(), extension.size(), extension) == 0)
            {
                return true;
            }
        }

        return false;
    }

    bool looksLikePathToken(const wstring &token)
    {
        const wstring cleaned = trimTrailingPathPunctuation(stripQuotes(token));
        if(cleaned.empty())
            return false;

        if(cleaned.find(L'\\') != wstring::npos || cleaned.find(L'/') != wstring::npos)
            return true;

        if(cleaned.find(L':') != wstring::npos)
            return true;

        if(cleaned.find(L'%') != wstring::npos)
            return true;

        if(cleaned[0] == L'.')
            return true;

        return hasInterestingExtension(cleaned);
    }

    string extractFirstExePath(const string &value)
    {
        const string lowerValue = toLowerCopy(value);
        const size_t exePos = lowerValue.find(".exe");
        if(exePos == string::npos)
            return "";

        size_t start = 0;
        while(start < value.size() && isspace((unsigned char)value[start]) != 0)
            ++start;

        if(start < value.size() && value[start] == '"')
            ++start;

        string result = value.substr(start, (exePos + 4) - start);

        while(!result.empty() &&
              (result[0] == '"' || isspace((unsigned char)result[0]) != 0))
        {
            result.erase(result.begin());
        }

        while(!result.empty() &&
              (result[result.size() - 1] == '"' ||
               isspace((unsigned char)result[result.size() - 1]) != 0))
        {
            result.erase(result.size() - 1);
        }

        return result;
    }

    vector<wstring> tokenizeCommandLine(const wstring &value)
    {
        vector<wstring> tokens;
        wstring current;
        bool inQuotes = false;

        for(size_t i = 0; i < value.size(); ++i)
        {
            const wchar_t ch = value[i];
            if(ch == L'"')
            {
                inQuotes = !inQuotes;
                continue;
            }

            if(iswspace(ch) != 0 && !inQuotes)
            {
                if(!current.empty())
                {
                    tokens.push_back(current);
                    current.clear();
                }

                continue;
            }

            current += ch;
        }

        if(!current.empty())
            tokens.push_back(current);

        return tokens;
    }

    void addUniquePathTarget(const wstring &rawPath, vector<string> &targets, vector<wstring> &seenKeys)
    {
        const wstring normalizedPath = normalizePathCandidate(rawPath);
        if(normalizedPath.empty())
            return;

        if(!isFilePathExisting(normalizedPath))
            return;

        const wstring loweredPath = toLowerWideCopy(normalizedPath);
        if(find(seenKeys.begin(), seenKeys.end(), loweredPath) != seenKeys.end())
            return;

        seenKeys.push_back(loweredPath);
        targets.push_back(wideToString(normalizedPath));
    }

    void addArgumentPathTarget(const wstring &token, vector<string> &targets, vector<wstring> &seenKeys)
    {
        if(!looksLikePathToken(token))
            return;

        addUniquePathTarget(token, targets, seenKeys);
    }

    bool isInterpreterOrLoaderExecutable(const wstring &path)
    {
        const wstring exeName = toLowerWideCopy(getFileNameFromPath(path));
        static const wchar_t *interpreters[] =
        {
            L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"wscript.exe", L"cscript.exe",
            L"mshta.exe", L"rundll32.exe", L"regsvr32.exe", L"python.exe", L"pythonw.exe",
            L"py.exe", L"java.exe", L"javaw.exe", L"node.exe", L"msiexec.exe"
        };

        for(size_t i = 0; i < (sizeof(interpreters) / sizeof(interpreters[0])); ++i)
        {
            if(exeName == interpreters[i])
                return true;
        }

        return false;
    }

    void collectInterpreterTargets(const wstring &executePath,
                                   const vector<wstring> &tokens,
                                   vector<string> &targets,
                                   vector<wstring> &seenKeys)
    {
        const wstring exeName = toLowerWideCopy(getFileNameFromPath(executePath));

        if(exeName == L"cmd.exe")
        {
            for(size_t i = 0; i + 1 < tokens.size(); ++i)
            {
                const wstring current = toLowerWideCopy(tokens[i]);
                if(current == L"/c" || current == L"/k")
                    addUniquePathTarget(tokens[i + 1], targets, seenKeys);
            }
        }
        else if(exeName == L"powershell.exe" || exeName == L"pwsh.exe")
        {
            for(size_t i = 0; i < tokens.size(); ++i)
            {
                const wstring current = toLowerWideCopy(tokens[i]);
                if((current == L"-file" || current == L"-f") && i + 1 < tokens.size())
                    addUniquePathTarget(tokens[i + 1], targets, seenKeys);
                else if(current.find(L"-file:") == 0)
                    addUniquePathTarget(tokens[i].substr(6), targets, seenKeys);
            }
        }
        else if(exeName == L"wscript.exe" || exeName == L"cscript.exe" ||
                exeName == L"python.exe" || exeName == L"pythonw.exe" ||
                exeName == L"py.exe" || exeName == L"node.exe" ||
                exeName == L"mshta.exe")
        {
            for(size_t i = 0; i < tokens.size(); ++i)
            {
                if(!tokens[i].empty() && tokens[i][0] == L'-')
                    continue;

                if(!tokens[i].empty() && tokens[i][0] == L'/')
                    continue;

                addUniquePathTarget(tokens[i], targets, seenKeys);
                break;
            }
        }
        else if(exeName == L"java.exe" || exeName == L"javaw.exe")
        {
            for(size_t i = 0; i + 1 < tokens.size(); ++i)
            {
                if(toLowerWideCopy(tokens[i]) == L"-jar")
                    addUniquePathTarget(tokens[i + 1], targets, seenKeys);
            }
        }
        else if(exeName == L"rundll32.exe")
        {
            for(size_t i = 0; i < tokens.size(); ++i)
            {
                const size_t commaPos = tokens[i].find(L',');
                if(commaPos != wstring::npos)
                    addUniquePathTarget(tokens[i].substr(0, commaPos), targets, seenKeys);
                else
                    addUniquePathTarget(tokens[i], targets, seenKeys);
            }
        }
        else if(exeName == L"regsvr32.exe")
        {
            for(size_t i = 0; i < tokens.size(); ++i)
            {
                if(!tokens[i].empty() && (tokens[i][0] == L'/' || tokens[i][0] == L'-'))
                    continue;

                addUniquePathTarget(tokens[i], targets, seenKeys);
            }
        }
        else if(exeName == L"msiexec.exe")
        {
            for(size_t i = 0; i < tokens.size(); ++i)
            {
                const wstring current = toLowerWideCopy(tokens[i]);
                if((current == L"/i" || current == L"/package" || current == L"/a") && i + 1 < tokens.size())
                    addUniquePathTarget(tokens[i + 1], targets, seenKeys);
                else if(current.find(L"/i") == 0 && tokens[i].size() > 2)
                    addUniquePathTarget(tokens[i].substr(2), targets, seenKeys);
            }
        }
    }

    vector<string> collectTaskTargetPaths(const SchTaskInfo &taskInfo)
    {
        vector<string> targets;
        vector<wstring> seenKeys;

        const wstring executePath = normalizePathCandidate(stringToWide(taskInfo.taskPath));
        if(executePath.empty())
            return targets;

        addUniquePathTarget(executePath, targets, seenKeys);

        const vector<wstring> argumentTokens = tokenizeCommandLine(stringToWide(taskInfo.taskArguments));

        if(isInterpreterOrLoaderExecutable(executePath))
            collectInterpreterTargets(executePath, argumentTokens, targets, seenKeys);

        for(size_t i = 0; i < argumentTokens.size(); ++i)
        {
            const wstring &token = argumentTokens[i];
            addArgumentPathTarget(token, targets, seenKeys);

            const size_t separatorPos = token.find(L'=');
            if(separatorPos != wstring::npos && separatorPos + 1 < token.size())
                addArgumentPathTarget(token.substr(separatorPos + 1), targets, seenKeys);

            const size_t colonPos = token.find(L':');
            if(colonPos != wstring::npos && colonPos + 1 < token.size() && colonPos != 1)
                addArgumentPathTarget(token.substr(colonPos + 1), targets, seenKeys);
        }

        return targets;
    }

    void printWritableIdentities(const FindFilesResult &info)
    {
        if(!info.isWritableByUser)
            return;

        for(size_t i = 0; i < info.usersCanWrite.size(); ++i)
            cout << "      user: " << info.usersCanWrite[i] << endl;

        for(size_t i = 0; i < info.groupsCanWrite.size(); ++i)
            cout << "      group: " << info.groupsCanWrite[i] << endl;
    }

    bool parentDirectoriesContainTask(const string &filePath)
    {
        const string parentDirectory = wideToString(getParentDirectory(stringToWide(filePath)));
        return toLowerCopy(parentDirectory).find("task") != string::npos;
    }

    void printPathWithHighlightedTask(const string &path)
    {
        const string loweredPath = toLowerCopy(path);
        size_t currentPos = 0;
        size_t taskPos = loweredPath.find("task");

        while(taskPos != string::npos)
        {
            cout << path.substr(currentPos, taskPos - currentPos);
            cout << RED << path.substr(taskPos, 4) << RESET;
            currentPos = taskPos + 4;
            taskPos = loweredPath.find("task", currentPos);
        }

        cout << path.substr(currentPos);
    }

    bool accountMatchesCurrentPrincipal(const string &accountName,
                                        const string &currentUser,
                                        const vector<string> &currentGroups)
    {
        const string normalizedAccount = toLowerCopy(accountName);
        const string normalizedCurrentUser = toLowerCopy(currentUser);

        if(!normalizedCurrentUser.empty() &&
           normalizedAccount.find(normalizedCurrentUser) != string::npos)
        {
            return true;
        }

        for(size_t i = 0; i < currentGroups.size(); ++i)
        {
            const string normalizedGroup = toLowerCopy(currentGroups[i]);
            if(!normalizedGroup.empty() && normalizedAccount == normalizedGroup)
                return true;
        }

        return false;
    }

    bool currentPrincipalHasServicePermission(const vector<string> &permissionAccounts,
                                              const string &currentUser,
                                              const vector<string> &currentGroups)
    {
        for(size_t i = 0; i < permissionAccounts.size(); ++i)
        {
            if(accountMatchesCurrentPrincipal(permissionAccounts[i], currentUser, currentGroups))
                return true;
        }

        return false;
    }

    vector<string> getCurrentServicePrivileges(const ServiceSpec &service,
                                               const string &currentUser,
                                               const vector<string> &currentGroups)
    {
        vector<string> privileges;

        if(currentPrincipalHasServicePermission(service.permissions.userCanStop, currentUser, currentGroups))
            privileges.push_back("stop");

        if(currentPrincipalHasServicePermission(service.permissions.userCanRestart, currentUser, currentGroups))
            privileges.push_back("restart");

        if(currentPrincipalHasServicePermission(service.permissions.userCanStart, currentUser, currentGroups))
            privileges.push_back("start");

        return privileges;
    }

    void printServicePrivileges(const vector<string> &privileges)
    {
        if(privileges.empty())
            return;

        cout << " " << RED << "priv: ";
        for(size_t i = 0; i < privileges.size(); ++i)
        {
            if(i > 0)
                cout << ",";

            cout << privileges[i];
        }
        cout << RESET;
    }

    bool groupNameMatches(const string &groupName, const string &targetGroupName)
    {
        const string normalizedGroup = toLowerCopy(groupName);
        const string normalizedTarget = toLowerCopy(targetGroupName);

        if(normalizedGroup == normalizedTarget)
            return true;

        const string::size_type slashPos = normalizedGroup.find('\\');
        if(slashPos != string::npos && normalizedGroup.substr(slashPos + 1) == normalizedTarget)
            return true;

        return false;
    }

    bool isSensitiveGroupMembership(const string &groupName)
    {
        return groupNameMatches(groupName, "Administrators") ||
               groupNameMatches(groupName, "Domain Admins") ||
               groupNameMatches(groupName, "Backup Operators");
    }

    const PrivilegeRiskInfo* findPrivilegeRiskInfo(const string &privilegeName)
    {
        static const PrivilegeRiskInfo privilegeRisks[] =
        {
            {"SeDebugPrivilege", "HIGH", "Open any process, token stealing, LSASS dump"},
            {"SeImpersonatePrivilege", "HIGH", "Impersonate tokens (Potato attacks -> SYSTEM)"},
            {"SeAssignPrimaryTokenPrivilege", "HIGH", "Assign primary token to process (used with impersonation)"},
            {"SeBackupPrivilege", "HIGH", "Read any file ignoring ACL (dump SAM/SYSTEM)"},
            {"SeRestorePrivilege", "HIGH", "Write any file ignoring ACL (overwrite system files)"},
            {"SeTakeOwnershipPrivilege", "HIGH", "Take ownership of objects -> modify ACL"},
            {"SeTcbPrivilege", "HIGH", "Act as OS, create/modify tokens (full control)"},
            {"SeCreateTokenPrivilege", "HIGH", "Create arbitrary tokens (direct escalation)"},
            {"SeLoadDriverPrivilege", "HIGH", "Load kernel drivers (kernel execution)"},
            {"SeManageVolumePrivilege", "HIGH", "Raw disk access, bypass file ACLs"},
            {"SeRelabelPrivilege", "MEDIUM", "Modify integrity levels"},
            {"SeIncreaseQuotaPrivilege", "MEDIUM", "Adjust process quotas (used in token abuse chains)"}
        };

        for(size_t i = 0; i < (sizeof(privilegeRisks) / sizeof(privilegeRisks[0])); ++i)
        {
            if(privilegeName == privilegeRisks[i].privilegeName)
                return &privilegeRisks[i];
        }

        return NULL;
    }
}
bool vectorContains(const std::string& s, const std::vector<std::string>& v) {
    return std::find(v.begin(), v.end(), s) != v.end();
}
void checkUnquotedPath()
{

    cout << "[*] Searching for services with unquoted paths" << endl << endl;

    WinServices wservice = WinServices();
    vector<ServiceSpec> serviceList = wservice.getEnumService();
    for(size_t i = 0; i < serviceList.size(); ++i)
    {
        const string &currentService = serviceList[i].path;
        const string normalizedService = toLowerCopy(currentService);

        const string separator = ".exe ";
        const size_t separatorPos = currentService.find(separator);
        if(separatorPos == string::npos)
            continue;

        const string prePath = currentService.substr(0, separatorPos);
        if(prePath.find(' ') != string::npos && normalizedService.find("system32") == string::npos)
            cout << currentService << endl;
    }
}


void showServicePermission(const vector<string>& svPerm, const string& currentUser, const vector<string>& currentGroups){
    for(size_t j = 0; j < svPerm.size(); ++j)
    {
        string in_user = svPerm[j];
        if(in_user.find(currentUser)!=string::npos || vectorContains(in_user, currentGroups))
            cout << "    " << RED << in_user << RESET << endl;
        else
            cout << "    " << in_user << endl;
    }

}
void checkServicePermission()
{
    cout << "[*] Searching for weak service permissions" << endl << endl;

    WinServices wservice = WinServices();
    vector<ServiceSpec> serviceList = wservice.getEnumService();
    WinLogonUser logonUser;
    string currentUser = logonUser.getCurrentUser();
    vector<string> currentGroups = logonUser.getCurrentGroups();

    for(size_t i = 0; i < serviceList.size(); ++i)
    {
        ServiceSpec &service = serviceList[i];
        const string normalizedName = toLowerCopy(service.path);

        if(normalizedName.find("system32") != string::npos)
            continue;

        cout << endl << "Service: " << service.serviceName << " Path: " << service.path << endl;
        
        cout << endl <<  "  - Users with "<< GREEN << "start " << RESET << "permissions" << endl;
        showServicePermission(service.permissions.userCanStart, currentUser, currentGroups);
        cout << endl <<  "  - Users with "<< GREEN << "stop " << RESET << "permissions" << endl;
        showServicePermission(service.permissions.userCanStop, currentUser, currentGroups);
        cout << endl <<  "  - Users with "<< GREEN << "restart " << RESET << "permissions" << endl;
        showServicePermission(service.permissions.userCanRestart, currentUser, currentGroups);
        
        
    }
}
void checkFilePermission(){
    WinServices wservice = WinServices();
    FSUtil fsUtil;
    vector<ServiceSpec> serviceList = wservice.getEnumService();
    TaskUtil taskUtil;
    WinLogonUser logonUser;
    const string currentUser = logonUser.getCurrentUser();
    const vector<string> currentGroups = logonUser.getCurrentGroups();

    cout << "[*] Checking file permissions on service paths" << endl << endl;
    for(size_t i = 0; i < serviceList.size(); ++i)
    {
        ServiceSpec &service = serviceList[i];
        const string executablePath = extractFirstExePath(service.path);
        const string normalizedName = toLowerCopy(executablePath);

        if(normalizedName.find("system32") != string::npos)
            continue;

        FindFilesResult fPerm = fsUtil.getFileInfo(executablePath);
        const vector<string> servicePrivileges = getCurrentServicePrivileges(service, currentUser, currentGroups);
        const bool highlightEntireLine = fPerm.isWritableByUser && !servicePrivileges.empty();

        if(highlightEntireLine)
            cout << RED_ON_YELLOW;

        cout << "(";
        if(!highlightEntireLine)
            cout << GREEN;
        cout << service.serviceName;
        if(!highlightEntireLine)
            cout << RESET;
        cout << ") " << executablePath;

        if(fPerm.isWritableByUser)
        {
            if(!highlightEntireLine)
                cout << RED;
            cout << " [WRITABLE]";
            if(!highlightEntireLine)
                cout << RESET;
        }

        if(highlightEntireLine)
        {
            cout << " priv: ";
            for(size_t j = 0; j < servicePrivileges.size(); ++j)
            {
                if(j > 0)
                    cout << ",";

                cout << servicePrivileges[j];
            }
        }
        else
            printServicePrivileges(servicePrivileges);

        if(highlightEntireLine)
            cout << RESET;
        cout << endl;
    }

    cout << endl << "[*] Querying Windows tasks" << endl << endl;
    vector<SchTaskInfo> taskList = taskUtil.getScheduledTask();
    for(size_t i = 0; i < taskList.size(); ++i)
    {
        const SchTaskInfo &taskInfo = taskList[i];
        if(taskInfo.taskPath.empty())
            continue;

        const vector<string> targetPaths = collectTaskTargetPaths(taskInfo);
        if(targetPaths.empty())
            continue;

        cout << "Task: " << taskInfo.taskName << endl;
        cout << "  Execute: " << taskInfo.taskPath << endl;
        if(!taskInfo.taskArguments.empty())
            cout << "  Arguments: " << taskInfo.taskArguments << endl;

        for(size_t j = 0; j < targetPaths.size(); ++j)
        {
            const string &targetPath = targetPaths[j];
            const FindFilesResult fileInfo = fsUtil.getFileInfo(targetPath);
            const wstring parentDirectoryWide = getParentDirectory(stringToWide(targetPath));
            const string parentDirectory = wideToString(parentDirectoryWide);
            const FindFilesResult parentInfo = parentDirectory.empty()
                                             ? FindFilesResult()
                                             : fsUtil.getFileInfo(parentDirectory);

            cout << "    Target: " << targetPath;
            if(fileInfo.isWritableByUser)
                cout << RED << " [WRITABLE FILE]" << RESET;
            cout << endl;
            printWritableIdentities(fileInfo);

            if(!parentDirectory.empty())
            {
                cout << "    Parent: " << parentDirectory;
                if(parentInfo.isWritableByUser)
                    cout << RED << " [WRITABLE DIR]" << RESET;
                cout << endl;
                printWritableIdentities(parentInfo);
            }
        }

        cout << endl;
    }
}
void userList()
{
    WinLogonUser logonUser;
    vector<UserInfo> users = logonUser.getUserList();

    for(size_t i = 0; i < users.size(); ++i)
        cout << "User: " << users[i].user << endl;
}
void checkWeakPrivileges()
{

    WinLogonUser logonUser;
    vector<string> currentGroups = logonUser.getCurrentGroups();
    vector<UserPrivilege> userPrivileges = logonUser.getCurrentPrivileges();
    cout << "[*] Checking weak privileges" << endl << endl;
    cout << "Current group memberships:" << endl;
    for(size_t i = 0; i < currentGroups.size(); ++i)
    {
        if(isSensitiveGroupMembership(currentGroups[i]))
            cout << RED << "  " << currentGroups[i] << RESET << endl;
        else
            cout << "  " << currentGroups[i] << endl;
    }

    cout << endl;
    cout << left
         << setw(30) << "Privilege"
         << setw(12) << "Risk"
         << setw(12) << "State"
         << "Description" << endl;

    for(size_t i = 0; i < userPrivileges.size(); ++i){
        const UserPrivilege &privilege = userPrivileges[i];
        if(!privilege.enabled)
            continue;

        const PrivilegeRiskInfo *riskInfo = findPrivilegeRiskInfo(privilege.priv);
        const string severity = riskInfo != NULL ? riskInfo->severity : "INFO";
        const string description = riskInfo != NULL ? riskInfo->abuseDescription
                                                    : privilege.description;

        const char *color = RESET;
        if(severity == "HIGH")
            color = RED;
        else if(severity == "MEDIUM")
            color = YELLOW;

        cout << color
             << left
             << setw(30) << privilege.priv
             << setw(12) << severity
             << setw(12) << "Enabled"
             << description
             << RESET << endl;
            
    }

   
}

void checkHiddenTaskFiles()
{
    FSUtil fsUtil;
    const string searchRoot = "C:\\";
    const string searchMasks[] =
    {
        "*.exe", "*.ps1", "*.bat", "*.cmd", "*.vbs",
        "*.js", "*.jse", "*.wsf", "*.hta", "*.dll", "*.lnk"
    };

    cout << "[*] Searching for writable executable/script files under C:\\" << endl << endl;

    for(size_t i = 0; i < (sizeof(searchMasks) / sizeof(searchMasks[0])); ++i)
    {
        vector<FindFilesResult> files = fsUtil.findFiles(searchRoot, searchMasks[i], true);
        for(size_t j = 0; j < files.size(); ++j)
        {
            const FindFilesResult &fileInfo = files[j];
            if(!fileInfo.isWritableByUser)
                continue;

            if(parentDirectoriesContainTask(fileInfo.filePath))
            {
                cout << RED_ON_YELLOW << fileInfo.filePath << " [WRITABLE]" << RESET << endl;
                continue;
            }
            else
                cout << fileInfo.filePath;

            cout << RED << " [WRITABLE]" << RESET << endl;
        }
    }
}

void usage(){
    const int moduleWidth = 16;

    cout << "Gozer Windows privilege escalation tool v1.0 by KillerCD" << endl;
    cout << "Usage: " << endl;
    cout << "Gozer.exe" << " [MODULE]" << endl << endl;
    cout << "Available modules:" << endl << endl;
    cout << "  " << left << setw(moduleWidth) << "all" << "(all modules)" << endl;
    cout << "  " << left << setw(moduleWidth) << "srv-perm" << "(Check service permissions)" << endl;
    cout << "  " << left << setw(moduleWidth) << "srv-unquoted" << "(Check for unquoted service paths)" << endl;
    cout << "  " << left << setw(moduleWidth) << "file-perm" << "(Check for weak file permissions)" << endl;
    cout << "  " << left << setw(moduleWidth) << "hidden-task" << "(Find writable task-related executables/scripts)" << endl;
    cout << "  " << left << setw(moduleWidth) << "priv" << "(Check for weak privileges)" << endl;

}


int main(int argc, char *argv[])
{
    enableAnsiColorMode();

    if(argc<2){
        usage();
        return -1;
    }
    string module = argv[1];
    
  

    if(module=="srv-perm")
        checkServicePermission();
    else if(module=="srv-unquoted")
        checkUnquotedPath();
    else if(module=="file-perm")
        checkFilePermission();
    else if(module=="hidden-task")
        checkHiddenTaskFiles();
    else if(module=="priv")
        checkWeakPrivileges();
    
    else if(module=="all"){
        checkServicePermission();
        checkUnquotedPath();
        checkFilePermission();
        checkHiddenTaskFiles();
        checkWeakPrivileges();
    }
    
    //userList();
    return 0;
}
