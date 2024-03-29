#ifndef MYDOCKER_RUN_H
#define MYDOCKER_RUN_H

#include <string>

class RunApp {
  public:
    typedef struct {
        std::string command;
    } run_args;
    static std::function<void()> run_callback(const run_args &arg);
};

#endif // MYDOCKER_RUN_H
