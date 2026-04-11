#ifndef _LOGONUSER_
#define _LOGONUSER_

#include <string>
#include <vector>


struct UserInfo{
    std::string user;
    std::vector<std::string> groups;
    bool isAdministrator=false;
};
struct UserPrivilege{
    std::string priv;
    std::string description;
    bool enabled;
};
class WinLogonUser{
    public:
        WinLogonUser();
        std::vector<UserInfo> getUserList();
        std::string getCurrentUser();
        std::vector<std::string> getCurrentGroups();
        std::vector<UserPrivilege> getCurrentPrivileges();

};
#endif
