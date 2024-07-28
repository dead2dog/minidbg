#include <unistd.h>
#include <stdio.h>

int main() {
    int iteration = 0;
    char buffer[50];
    
    while (1) {
        // 构建输出字符串
        int length = snprintf(buffer, sizeof(buffer), "当前迭代次数: %d\n", iteration);
        write(STDOUT_FILENO, buffer, length);
        
        // 递增迭代次数
        iteration++;
        
        // 每秒暂停一次
        sleep(1);
    }

    return 0;
}

