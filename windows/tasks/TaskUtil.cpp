#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <oleauto.h>
#include <string>
#include <vector>
#include "TaskUtil.h"

namespace
{
    struct TaskExecInfo
    {
        std::string path;
        std::string arguments;
    };

    std::wstring expandEnvironmentStrings(const wchar_t *value)
    {
        if(value == NULL || value[0] == L'\0')
            return L"";

        DWORD needed = ExpandEnvironmentStringsW(value, NULL, 0);
        if(needed == 0)
            return value;

        std::vector<wchar_t> buffer(needed);
        DWORD written = ExpandEnvironmentStringsW(value, buffer.data(), needed);
        if(written == 0 || written > needed)
            return value;

        return buffer.data();
    }

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

    std::string formatTaskDate(DATE taskDate)
    {
        if(taskDate <= 0.0)
            return "";

        SYSTEMTIME systemTime;
        ZeroMemory(&systemTime, sizeof(systemTime));
        if(VariantTimeToSystemTime(taskDate, &systemTime) == 0)
            return "";

        char buffer[32];
        wsprintfA(buffer,
                  "%02d/%02d/%04d %02d:%02d:%02d",
                  systemTime.wDay,
                  systemTime.wMonth,
                  systemTime.wYear,
                  systemTime.wHour,
                  systemTime.wMinute,
                  systemTime.wSecond);
        return buffer;
    }

    TaskExecInfo getTaskExecInfo(IRegisteredTask *task)
    {
        TaskExecInfo execInfo;
        if(task == NULL)
            return execInfo;

        ITaskDefinition *definition = NULL;
        IActionCollection *actions = NULL;
        LONG actionCount = 0;

        if(FAILED(task->get_Definition(&definition)) || definition == NULL)
            return execInfo;

        if(FAILED(definition->get_Actions(&actions)) || actions == NULL)
        {
            definition->Release();
            return execInfo;
        }

        if(FAILED(actions->get_Count(&actionCount)))
        {
            actions->Release();
            definition->Release();
            return execInfo;
        }

        for(LONG i = 1; i <= actionCount; ++i)
        {
            IAction *action = NULL;
            TASK_ACTION_TYPE actionType = TASK_ACTION_EXEC;

            if(FAILED(actions->get_Item(_variant_t(i), &action)) || action == NULL)
                continue;

            if(SUCCEEDED(action->get_Type(&actionType)) && actionType == TASK_ACTION_EXEC)
            {
                IExecAction *execAction = NULL;
                if(SUCCEEDED(action->QueryInterface(IID_IExecAction, (void**)&execAction)) && execAction != NULL)
                {
                    BSTR execPath = NULL;
                    if(SUCCEEDED(execAction->get_Path(&execPath)) && execPath != NULL)
                    {
                        const std::wstring expandedPath = expandEnvironmentStrings(execPath);
                        execInfo.path = wideToString(expandedPath.c_str());
                        SysFreeString(execPath);
                    }

                    BSTR execArguments = NULL;
                    if(SUCCEEDED(execAction->get_Arguments(&execArguments)) && execArguments != NULL)
                    {
                        execInfo.arguments = wideToString(execArguments);
                        SysFreeString(execArguments);
                    }

                    execAction->Release();
                }
            }

            action->Release();

            if(!execInfo.path.empty() || !execInfo.arguments.empty())
                break;
        }

        actions->Release();
        definition->Release();
        return execInfo;
    }

    void collectTasksFromFolder(ITaskFolder *folder, std::vector<SchTaskInfo> &results)
    {
        if(folder == NULL)
            return;

        IRegisteredTaskCollection *tasks = NULL;
        LONG taskCount = 0;

        if(SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks != NULL)
        {
            if(SUCCEEDED(tasks->get_Count(&taskCount)))
            {
                for(LONG i = 1; i <= taskCount; ++i)
                {
                    IRegisteredTask *task = NULL;
                    VARIANT taskIndex;
                    VariantInit(&taskIndex);
                    taskIndex.vt = VT_I4;
                    taskIndex.lVal = i;

                    if(FAILED(tasks->get_Item(taskIndex, &task)) || task == NULL)
                        continue;

                    SchTaskInfo info;
                    BSTR taskName = NULL;
                    DATE nextRunTime = 0.0;
                    DATE lastRunTime = 0.0;

                    if(SUCCEEDED(task->get_Name(&taskName)) && taskName != NULL)
                    {
                        info.taskName = wideToString(taskName);
                        SysFreeString(taskName);
                    }

                    if(SUCCEEDED(task->get_NextRunTime(&nextRunTime)))
                        info.nextRunTime = formatTaskDate(nextRunTime);

                    if(SUCCEEDED(task->get_LastRunTime(&lastRunTime)))
                        info.lastRunTime = formatTaskDate(lastRunTime);

                    const TaskExecInfo execInfo = getTaskExecInfo(task);
                    info.taskPath = execInfo.path;
                    info.taskArguments = execInfo.arguments;
                    results.push_back(info);
                    task->Release();
                }
            }

            tasks->Release();
        }

        ITaskFolderCollection *folders = NULL;
        LONG folderCount = 0;

        if(SUCCEEDED(folder->GetFolders(0, &folders)) && folders != NULL)
        {
            if(SUCCEEDED(folders->get_Count(&folderCount)))
            {
                for(LONG i = 1; i <= folderCount; ++i)
                {
                    ITaskFolder *childFolder = NULL;
                    VARIANT folderIndex;
                    VariantInit(&folderIndex);
                    folderIndex.vt = VT_I4;
                    folderIndex.lVal = i;

                    if(SUCCEEDED(folders->get_Item(folderIndex, &childFolder)) && childFolder != NULL)
                    {
                        collectTasksFromFolder(childFolder, results);
                        childFolder->Release();
                    }
                }
            }

            folders->Release();
        }
    }
}

TaskUtil::TaskUtil()
{
}

std::vector<SchTaskInfo> TaskUtil::getScheduledTask()
{
    std::vector<SchTaskInfo> tasks;

    HRESULT initResult = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if(FAILED(initResult) && initResult != RPC_E_CHANGED_MODE)
        return tasks;

    HRESULT securityResult = CoInitializeSecurity(NULL,
                                                  -1,
                                                  NULL,
                                                  NULL,
                                                  RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                                                  RPC_C_IMP_LEVEL_IMPERSONATE,
                                                  NULL,
                                                  0,
                                                  NULL);

    if(FAILED(securityResult) && securityResult != RPC_E_TOO_LATE)
    {
        if(initResult != RPC_E_CHANGED_MODE)
            CoUninitialize();
        return tasks;
    }

    ITaskService *taskService = NULL;
    HRESULT createResult = CoCreateInstance(CLSID_TaskScheduler,
                                            NULL,
                                            CLSCTX_INPROC_SERVER,
                                            IID_ITaskService,
                                            (void**)&taskService);
    if(FAILED(createResult) || taskService == NULL)
    {
        if(initResult != RPC_E_CHANGED_MODE)
            CoUninitialize();
        return tasks;
    }

    VARIANT empty;
    VariantInit(&empty);

    HRESULT connectResult = taskService->Connect(empty,
                                                 empty,
                                                 empty,
                                                 empty);
    if(FAILED(connectResult))
    {
        taskService->Release();
        if(initResult != RPC_E_CHANGED_MODE)
            CoUninitialize();
        return tasks;
    }

    ITaskFolder *rootFolder = NULL;
    BSTR rootPath = SysAllocString(L"\\");
    HRESULT rootResult = taskService->GetFolder(rootPath, &rootFolder);
    SysFreeString(rootPath);
    if(SUCCEEDED(rootResult) && rootFolder != NULL)
    {
        collectTasksFromFolder(rootFolder, tasks);
        rootFolder->Release();
    }

    taskService->Release();

    if(initResult != RPC_E_CHANGED_MODE)
        CoUninitialize();

    return tasks;
}
