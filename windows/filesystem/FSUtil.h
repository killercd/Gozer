#ifndef _LIB_FSUTIL_
#define _LIB_FSUTIL_

#include <string>
#include <vector>

struct FindFilesResult{
    std::string fileName;
    std::string filePath;
    bool isDirectory = false;
    bool isWritableByUser=false;
    std::vector<std::string> usersCanWrite;
    std::vector<std::string> groupsCanWrite;

};
class FSUtil{
    public:
        FSUtil();
        std::vector<FindFilesResult> findFiles(std::string baseDir, std::string searchMask, bool recursive);
        FindFilesResult getFileInfo(std::string path);

};

#endif