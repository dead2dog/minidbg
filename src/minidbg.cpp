#include <string.h>
#include <sys/personality.h>
#include "debugger.hpp"

// 执行被调试程序
void execute_debugee(const std::string& prog_name) { 
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        std::cerr << "Error in ptrace\n";
        return;
    }
    execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

// 附加到目标进程
void attach_target(pid_t pid) { 
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        std::cerr << "Error in ptrace\n";
        return;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <mode> <target>\n", argv[0]);
        fprintf(stderr, "mode: -p <pid> to attach to a process, -t <program> to execute a program\n");
        return -1;
    }
    if (strcmp(argv[1], "-t") == 0) { // 执行目标程序
        pid_t pid = fork();
        if (pid == 0) {
            personality(ADDR_NO_RANDOMIZE); // 关闭地址空间随机加载
            execute_debugee(argv[2]);
        } else if (pid > 0) {
            std::cout << "Started debugging process " << pid << '\n';
            debugger dbg{argv[2], pid};
            dbg.run();
        } else {
            perror("fork");
            return -1;
        }
    } else if (strcmp(argv[1], "-p") == 0) { // 附加到目标进程
        pid_t pid = atoi(argv[2]);
        attach_target(pid);
        debugger dbg{get_executable_path(pid), pid};
        dbg.run();
    } else {
        fprintf(stderr, "Invalid mode. Use -p to attach or -t to execute.\n");
        return -1;
    }

    return 0;
}