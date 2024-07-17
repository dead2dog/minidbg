#include <cstdint>
#include <sys/wait.h>
#include <sys/ptrace.h>

class breakpoint {
    public:
        breakpoint() = default;
        breakpoint(pid_t pid, std::intptr_t addr) : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{} {}

        void enable() {
            auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
            m_saved_data = static_cast<uint8_t>(data & 0xff); //保存底部1字节的数据
            uint64_t int3 = 0xcc;
            uint64_t data_with_int3 = ((data & ~0xff) | int3); //将底部1字节置为0，并替换成int3
            ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3); 
            m_enabled = true;
        }

        void disable() {
            auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
            auto restored_data = ((data & ~0xff) | m_saved_data);
            ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);

            m_enabled = false;
        }

        bool is_enabled() const { return m_enabled; }

        auto get_address() const -> std::intptr_t { return m_addr; }
    private:
        pid_t m_pid;
        std::intptr_t m_addr;
        bool m_enabled;
        uint8_t m_saved_data;
    };