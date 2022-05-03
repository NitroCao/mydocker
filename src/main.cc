#include "application.h"

int main(int argc, char **argv)
{
    mydocker::app::application app;

    return app.run(argc, argv);
}
