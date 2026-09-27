if not exist bin mkdir bin

g++ -c main.cpp -o bin/main.o
g++ -c windows/services/services.cpp -o bin/services.o
g++ -c windows/user/LogonUser.cpp -o bin/LogonUser.o
g++ -c windows/filesystem/FSUtil.cpp -o bin/FSUtil.o
g++ -c windows/tasks/TaskUtil.cpp -o bin/TaskUtil.o

g++ bin/main.o bin/services.o bin/LogonUser.o bin/FSUtil.o bin/TaskUtil.o -o bin/gozer.exe -static -static-libgcc -static-libstdc++ -ladvapi32 -lnetapi32 -ltaskschd -lole32 -loleaut32 -luuid
