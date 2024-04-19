#ifndef MYDOCKER_RUN_H
#define MYDOCKER_RUN_H

#include <string>

#include "spec.h"

class RunApp {
  private:
    typedef std::pair<std::vector<const char *>, std::vector<const char *>> exec_arg_t;

    static int run_child(void *);
    static exec_arg_t create_exec_arg(const spec::Spec& config);

  public:
    typedef struct {
        std::string bundle_dir;
    } run_args;

    constexpr static const std::string DEFAULT_BUNDLE_DIR = ".";

    static std::function<void()> run_callback(const run_args &arg);
};

#endif // MYDOCKER_RUN_H
