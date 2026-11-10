// framework.h - Micro-framework de teste executado no HOST - v5.1.0
//
// Usado pelos testes unitarios em tests/*.cpp. Nao tem dependencia de
// Arduino/ESP: compila com g++ puro.
//
//   g++ -std=c++11 -Wall -Wextra -I tests/stub -I tests -I lib/src
//       tests/<arquivo>.cpp -o /tmp/<teste>
#ifndef HEF_TEST_FRAMEWORK_H
#define HEF_TEST_FRAMEWORK_H

#include <cstdio>

namespace heftest {

inline int& totalChecks() {
    static int c = 0;
    return c;
}

inline int& totalFailures() {
    static int f = 0;
    return f;
}

inline void section(const char* name) {
    printf("\n-- %s --\n", name);
}

inline bool check(bool cond, const char* msg) {
    totalChecks()++;
    if (cond) {
        printf("  [PASS] %s\n", msg);
        return true;
    }
    printf("  [FAIL] %s\n", msg);
    totalFailures()++;
    return false;
}

// Retorna o codigo de saida do processo (0 = tudo passou).
inline int summary(const char* suite) {
    printf("\n  %s: %d verificacoes, %d falha(s)\n",
           suite, totalChecks(), totalFailures());
    return totalFailures() == 0 ? 0 : 1;
}

}  // namespace heftest

#define CHECK(cond, msg) ::heftest::check((cond), (msg))
#define SECTION(name)  ::heftest::section(name)

#endif  // HEF_TEST_FRAMEWORK_H
