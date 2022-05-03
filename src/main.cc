#include <iostream>
#include <CLI/App.hpp>
#include <CLI/Formatter.hpp>
#include <CLI/Config.hpp>

int main(int argc, char **argv)
{
    CLI::App app{"My own container runtime written in C++"};

    CLI11_PARSE(app, argc, argv);
    return 0;
}
