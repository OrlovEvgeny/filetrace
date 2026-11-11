#include "unit/test.h"

int ft_test_failures;
int ft_test_checks;

int main(void)
{
    static const struct {
        const char *name;
        void (*run)(void);
    } suites[] = {
        {"format", test_format}, {"model", test_model}, {"table", test_table},
        {"state", test_state},   {"agent", test_agent}, {"views", test_views},
        {"config", test_config},
    };

    for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
        int before = ft_test_failures;
        suites[i].run();
        printf("%-8s %s\n", suites[i].name, ft_test_failures == before ? "ok" : "FAILED");
    }
    printf("%d checks, %d failed\n", ft_test_checks, ft_test_failures);
    return ft_test_failures ? 1 : 0;
}
