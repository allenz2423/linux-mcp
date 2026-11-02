#include <QCoreApplication>
#include <QTimer>

#ifndef TEST_PROMPT_EXIT_CODE
#define TEST_PROMPT_EXIT_CODE 0
#endif
#ifndef TEST_PROMPT_DELAY_MS
#define TEST_PROMPT_DELAY_MS 10
#endif

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QTimer::singleShot(TEST_PROMPT_DELAY_MS, &app, [&app]() {
        app.exit(TEST_PROMPT_EXIT_CODE);
    });
    return app.exec();
}
