#ifndef _WIN_SERVICES_
#define _WIN_SERVICES_

#include <string>
#include <vector>

struct ServicePermission{
    std::vector<std::string> userCanStart;
    std::vector<std::string> userCanStop;
    std::vector<std::string> userCanPause;
    std::vector<std::string> userCanQuery;
    std::vector<std::string> userCanRestart;

};
struct ServiceSpec{

    std::string serviceName;
    std::string path;
    std::string status;
    ServicePermission permissions;
};
class WinServices{
  
    public:
        WinServices();
        std::vector<ServiceSpec> getEnumService();

};




#endif
