#ifndef MYDOCKER_SPEC_APP_H
#define MYDOCKER_SPEC_APP_H

#include <functional>
#include <string>

class SpecApp {
  public:
    typedef struct {
        std::string bundle;
        bool rootless;
    } spec_args;

    static std::function<void()> spec_callback(const spec_args &arg);
};

#endif // MYDOCKER_SPEC_APP_H
