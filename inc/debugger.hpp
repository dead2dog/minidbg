#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <unordered_map>
#include <iomanip>
#include <utility>
#include <fcntl.h>
#include <linux/types.h>
#include <iostream>
#include <fstream>
#include <string>

#include "breakpoint.hpp"
#include "registers.hpp"
#include "linenoise.h"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

// 字符串拆分
std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> out{};
    std::stringstream ss {s};
    std::string item;

    while (std::getline(ss,item,delimiter)) {
        out.push_back(item);
    }

    return out;
}
// 前缀匹配
bool is_prefix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) return false;
    return std::equal(s.begin(), s.end(), of.begin());
}



class debugger {
public:
    debugger (std::string prog_name, pid_t pid)
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {
        auto fd = open(m_prog_name.c_str(), O_RDONLY);

        m_elf = elf::elf{elf::create_mmap_loader(fd)};
        m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
    }

    void run(); // 调试loop
    void set_breakpoint_at_address(std::intptr_t addr); // 通过地址设置断点
    void dump_registers(); // 打印全部寄存器的值
    void single_step_instruction(); // 单步执行
    void set_breakpoint_at_function(const std::string& name); // 通过函数名设置断点
    void print_line(); // 打印下一条指令的行号

private:
    void handle_command(const std::string& line);  // 命令控制器
    void cont_execution(); // 完成
    auto get_pc() -> uint64_t; 
    void set_pc(uint64_t pc);
    void step_over_breakpoint();
    void wait_for_signal();
    auto read_memory(uint64_t address) -> uint64_t ;
    void write_memory(uint64_t address, uint64_t value);
    auto get_line_entry_from_pc(uint64_t pc) -> dwarf::line_table::iterator;
    void initialise_load_address(); // 初始化加载地址
    uint64_t offset_load_address(uint64_t addr); // 获得偏移量
    uint64_t offset_dwarf_address(uint64_t addr); // 获得运行地址
    
    std::string m_prog_name; // 被调试路径
    pid_t m_pid; // 被调试pid
    std::unordered_map<std::intptr_t,breakpoint> m_breakpoints; // 断点列表
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
    uint64_t m_load_address = 0x555555554000; // 加载地址
};

void debugger::initialise_load_address() {

    std::string maps_file = "/proc/" + std::to_string(m_pid) + "/maps";

    std::ifstream map(maps_file);
    if (!map.is_open()) {
        std::cerr << "failed open file" << maps_file << std::endl;
        return;
    }
    // 从文件中读取第一行数据
    std::string addr;
    std::getline(map, addr, '-');
    std::cout<<"load address:"<<addr<<std::endl;
    // 将地址转换为十六进制整数
    m_load_address = std::stol(addr, 0, 16);
}

void debugger::set_breakpoint_at_function(const std::string& name) {
    for (const auto& cu : m_dwarf.compilation_units()) {
        for (const auto& die : cu.root()) {
            // 检查die中是否有dwarf::DW_AT::name，并且名称与函数名匹配
            if (die.has(dwarf::DW_AT::name) && at_name(die) == name) {
                auto low_pc = at_low_pc(die); // 获取起始地址
                auto entry = get_line_entry_from_pc(low_pc);
                // at_low_pc指向的不是函数代码的起始地址
                // 而是指向prologue，用于执行保存和恢复堆栈、操作堆栈指针
                ++entry; 
                set_breakpoint_at_address(offset_dwarf_address(entry->address));
            }
        }
    }
}


void debugger::print_line(){
    auto offset_pc = offset_load_address(get_pc()); //通过偏移量去查
    auto line_entry = get_line_entry_from_pc(offset_pc);
    printf("0x%016lx %s:%d\n", line_entry->address, line_entry->file->path.c_str(), line_entry->line);
    return;
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) { // 遍历dwarf中的所有编译单元
        if (die_pc_range(cu.root()).contains(pc)) { // 检查pc是否在地址范围内
            auto &lt = cu.get_line_table(); // 获取行表
            auto it = lt.find_address(pc); // 查找行表中pc对应的行条目
            if (it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            }
            else {
                return it; // 返回行条目迭代器
            }
        }
    }
    throw std::out_of_range{"Cannot find line entry"};
}

uint64_t debugger::offset_load_address(uint64_t addr) {
   return addr - m_load_address;
}

uint64_t debugger::offset_dwarf_address(uint64_t addr) {
   return addr + m_load_address;
}

void debugger::single_step_instruction() {
    // 检查是否遇见断点
    if (m_breakpoints.count(get_pc()-1)) {
        step_over_breakpoint();
    }
    else { //没遇见
        ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
        wait_for_signal();
    }
}

uint64_t debugger::get_pc() {
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) {
    set_register_value(m_pid, reg::rip, pc);
}
void debugger::step_over_breakpoint() {
    auto possible_breakpoint_location = get_pc() - 1; // pc指的是下一条指令，我们需要断点的指令

    if (m_breakpoints.count(possible_breakpoint_location)) {
        auto& bp = m_breakpoints[possible_breakpoint_location];

        if (bp.is_enabled()) {
            auto previous_instruction_address = possible_breakpoint_location;
            set_pc(previous_instruction_address);

            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

void debugger::wait_for_signal() {
    int wait_status;
    waitpid(m_pid, &wait_status, 0);
}
void debugger::dump_registers() {
    for (int i = 0; i <= static_cast<int>(reg::gs_base); ++i) {
        reg r = static_cast<reg>(i);
        std::cout << get_register_name(r) << ": " << std::hex << get_register_value(m_pid, r) << std::dec << std::endl;
    }
}

uint64_t debugger::read_memory(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}
void debugger::write_memory(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

void debugger::cont_execution() {
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}


void debugger::handle_command(const std::string& line) {
    auto args = split(line,' ');
    auto command = args[0];

    if (is_prefix(command, "cont")) { // 恢复运行
        cont_execution();
    }
    else if(is_prefix(command, "go")) { // 开始执行
        ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
        wait_for_signal();
    }
    else if(is_prefix(command, "break")) {
        if (args[1][0] == '0' && args[1][1] == 'x') {
            std::string addr {args[1], 2};
            set_breakpoint_at_address(std::stol(addr, 0, 16));// 去掉前面的"0x"
        }
        else {
            set_breakpoint_at_function(args[1]);
        }
    }
    else if (is_prefix(command, "register")) {
        if (is_prefix(args[1], "all")) {
            dump_registers();
        }
        else if (is_prefix(args[1], "read")) {
            std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
        }
        else if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2}; //去掉前面的"0x"
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
    }
    else if(is_prefix(command, "memory")) {
        std::string addr {args[2], 2}; 

        if (is_prefix(args[1], "read")) {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        }
        if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2};
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else if(is_prefix(command, "next")) {
        single_step_instruction();
    }
    else if(is_prefix(command, "show")){
        print_line();
    }
    else {
        std::cerr << "Unknown command\n";
    }
}
void debugger::run() {
    wait_for_signal();
    initialise_load_address();

    char* line = nullptr;
    while((line = linenoise("(Debugger) > ")) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    breakpoint bp {m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}
    
// 获取目标进程的执行路径
std::string get_executable_path(pid_t pid) {
    char exe_path[1024];

    // 构造 /proc/<pid>/exe 路径
    std::string link = "/proc/" + std::to_string(pid) + "/exe";

    // 读取符号链接内容
    ssize_t len = readlink(link.c_str(), exe_path, sizeof(exe_path) - 1);
    if (len != -1) {
        exe_path[len] = '\0'; // 添加字符串结束符
        std::cout<<"executable path:"<<std::string(exe_path)<<std::endl;
        return std::string(exe_path);
    } else {
        perror("readlink");
        return ""; 
    }
}