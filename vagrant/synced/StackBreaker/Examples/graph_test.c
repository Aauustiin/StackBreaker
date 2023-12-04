int c() {
    a();
    return 0;
}

int e() {
    return 0;
}

int b() {
    c();
    return 0;
}

int d() {
    e();
    return 0;
}

int a() {
    b();
    d();
    a();
    return 0;
}

int main() {
    a();
    return 0;
}