#include <iostream>
void e() {
    std::cout<<"call d()\n";
}
void d() {
    std::cout<<"call d()\n";
}
void c() {
    std::cout<<"call c()\n";
}
void b() {
    std::cout<<"call b()\n";
}
void a() {
    std::cout<<"call a()\n";

}

int main() {
    std::cout<<"demo1 start\n";
    int f = 16;
    int g = 16;
    int h = f+g;
    a();
    b();
    c();
    d();
    std::cout<<"byby\n";
    return 0;
}