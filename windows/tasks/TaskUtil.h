#ifndef _LIB_TASK_UTIL_
#define _LIB_TASK_UTIL_


#include <string>
#include <vector>

struct SchTaskInfo{
    std::string taskName;
    std::string taskPath;
    std::string taskArguments;
    std::string nextRunTime;
    std::string lastRunTime;
};

class TaskUtil{
    public:
        TaskUtil();
        std::vector<SchTaskInfo> getScheduledTask(); 

};
#endif
