#include <sys/user.h>
#include <algorithm>
#include <string>
#include <sys/ptrace.h>


enum class reg {
    rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp,
    r8, r9, r10, r11, r12, r13, r14, r15,
    rip, cs, rflags, ss, ds, es, fs, gs,
    orig_rax, fs_base, gs_base
};
// 获取寄存器值
uint64_t get_register_value(pid_t pid, reg r) {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    switch (r) {
        case reg::rax:     return regs.rax;
        case reg::rbx:     return regs.rbx;
        case reg::rcx:     return regs.rcx;
        case reg::rdx:     return regs.rdx;
        case reg::rsi:     return regs.rsi;
        case reg::rdi:     return regs.rdi;
        case reg::rbp:     return regs.rbp;
        case reg::rsp:     return regs.rsp;
        case reg::r8:      return regs.r8;
        case reg::r9:      return regs.r9;
        case reg::r10:     return regs.r10;
        case reg::r11:     return regs.r11;
        case reg::r12:     return regs.r12;
        case reg::r13:     return regs.r13;
        case reg::r14:     return regs.r14;
        case reg::r15:     return regs.r15;
        case reg::rip:     return regs.rip;
        case reg::cs:      return regs.cs;
        case reg::rflags:  return regs.eflags;
        case reg::ss:      return regs.ss;
        case reg::ds:      return regs.ds;
        case reg::es:      return regs.es;
        case reg::fs:      return regs.fs;
        case reg::gs:      return regs.gs;
        case reg::orig_rax:return regs.orig_rax;
        case reg::fs_base: return regs.fs_base;
        case reg::gs_base: return regs.gs_base;
    }
}

// 设置寄存器值
void set_register_value(pid_t pid, reg r, uint64_t value) {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    switch (r) {
        case reg::rax:     regs.rax = value; break;
        case reg::rbx:     regs.rbx = value; break;
        case reg::rcx:     regs.rcx = value; break;
        case reg::rdx:     regs.rdx = value; break;
        case reg::rsi:     regs.rsi = value; break;
        case reg::rdi:     regs.rdi = value; break;
        case reg::rbp:     regs.rbp = value; break;
        case reg::rsp:     regs.rsp = value; break;
        case reg::r8:      regs.r8 = value; break;
        case reg::r9:      regs.r9 = value; break;
        case reg::r10:     regs.r10 = value; break;
        case reg::r11:     regs.r11 = value; break;
        case reg::r12:     regs.r12 = value; break;
        case reg::r13:     regs.r13 = value; break;
        case reg::r14:     regs.r14 = value; break;
        case reg::r15:     regs.r15 = value; break;
        case reg::rip:     regs.rip = value; break;
        case reg::cs:      regs.cs = value; break;
        case reg::rflags:  regs.eflags = value; break;
        case reg::ss:      regs.ss = value; break;
        case reg::ds:      regs.ds = value; break;
        case reg::es:      regs.es = value; break;
        case reg::fs:      regs.fs = value; break;
        case reg::gs:      regs.gs = value; break;
        case reg::orig_rax:regs.orig_rax = value; break;
        case reg::fs_base: regs.fs_base = value; break;
        case reg::gs_base: regs.gs_base = value; break;
    }

    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}
// name->enum
reg get_register_from_name(const std::string& name) {
    if (name == "r15")        return reg::r15;
    else if (name == "r14")   return reg::r14;
    else if (name == "r13")   return reg::r13;
    else if (name == "r12")   return reg::r12;
    else if (name == "rbp")   return reg::rbp;
    else if (name == "rbx")   return reg::rbx;
    else if (name == "r11")   return reg::r11;
    else if (name == "r10")   return reg::r10;
    else if (name == "r9")    return reg::r9;
    else if (name == "r8")    return reg::r8;
    else if (name == "rax")   return reg::rax;
    else if (name == "rcx")   return reg::rcx;
    else if (name == "rdx")   return reg::rdx;
    else if (name == "rsi")   return reg::rsi;
    else if (name == "rdi")   return reg::rdi;
    else if (name == "orig_rax") return reg::orig_rax;
    else if (name == "rip")   return reg::rip;
    else if (name == "cs")    return reg::cs;
    else if (name == "rflags") return reg::rflags;
    else if (name == "rsp")   return reg::rsp;
    else if (name == "ss")    return reg::ss;
    else if (name == "fs_base") return reg::fs_base;
    else if (name == "gs_base") return reg::gs_base;
    else if (name == "ds")    return reg::ds;
    else if (name == "es")    return reg::es;
    else if (name == "fs")    return reg::fs;
    else if (name == "gs")    return reg::gs;
}

// enum->name
std::string get_register_name(reg r) {
    switch (r) {
        case reg::rax:     return "rax";
        case reg::rbx:     return "rbx";
        case reg::rcx:     return "rcx";
        case reg::rdx:     return "rdx";
        case reg::rsi:     return "rsi";
        case reg::rdi:     return "rdi";
        case reg::rbp:     return "rbp";
        case reg::rsp:     return "rsp";
        case reg::r8:      return "r8";
        case reg::r9:      return "r9";
        case reg::r10:     return "r10";
        case reg::r11:     return "r11";
        case reg::r12:     return "r12";
        case reg::r13:     return "r13";
        case reg::r14:     return "r14";
        case reg::r15:     return "r15";
        case reg::rip:     return "rip";
        case reg::cs:      return "cs";
        case reg::rflags:  return "rflags";
        case reg::ss:      return "ss";
        case reg::ds:      return "ds";
        case reg::es:      return "es";
        case reg::fs:      return "fs";
        case reg::gs:      return "gs";
        case reg::orig_rax:return "orig_rax";
        case reg::fs_base: return "fs_base";
        case reg::gs_base: return "gs_base";
    }
    return "";
}