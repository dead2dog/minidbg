void a() {
    int foo = 1;
}

void b() {
    int foo = 2;
    a();
}

void c() {
    int foo = 3;
    b();
}

int main() {
    int d = 12;
    int e = 20;
    int f = d+e;
    c();
    return 0;
}
