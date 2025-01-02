#include "config.h" 
#include "unity_fixture.h"

struct instance_config_t instance_config = {
	.send_raw_packet = NULL,
	.send_delayed_packet = NULL,
};

static void RunAllTests(void)
{
	RUN_TEST_GROUP(QuicTest);
}

int main(int argc, const char * argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}
