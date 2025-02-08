#include "unity.h"
#include "unity_fixture.h"

#include "trie.h"

TEST_GROUP(TrieTest);

TEST_SETUP(TrieTest)
{
}

TEST_TEAR_DOWN(TrieTest)
{
}

const char ASTR[] = "abacaba";
const char BSTR[] = "BABABABA";
const char CSTR[] = "abracadabra";

const char tstr[] = "aBABABABDADAabacabracadabraabbbabacabaaaaaabacaba";


TEST(TrieTest, Trie_string_adds)
{
	int ret;
	size_t offset;
	size_t offlen;
	struct trie_container trie;

	ret = trie_init(&trie);
	TEST_ASSERT_EQUAL(0, ret);
	ret = trie_add_string(&trie, (uint8_t *)ASTR, sizeof(ASTR) - 1);
	TEST_ASSERT_EQUAL(0, ret);
	ret = trie_add_string(&trie, (uint8_t *)BSTR, sizeof(BSTR) - 1);
	TEST_ASSERT_EQUAL(0, ret);
	ret = trie_add_string(&trie, (uint8_t *)CSTR, sizeof(CSTR) - 1);
	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL(25, trie.sz);

	trie_destroy(&trie);
}

TEST(TrieTest, Trie_string_finds)
{
	int ret;
	size_t offset;
	size_t offlen;
	struct trie_container trie;

	ret = trie_init(&trie);
	ret = trie_add_string(&trie, (uint8_t *)ASTR, sizeof(ASTR) - 1);
	ret = trie_add_string(&trie, (uint8_t *)BSTR, sizeof(BSTR) - 1);
	ret = trie_add_string(&trie, (uint8_t *)CSTR, sizeof(CSTR) - 1);

	ret = trie_process_str(&trie, 
			(uint8_t *)tstr, sizeof(tstr) - 1,
			0, &offset, &offlen
	);
	TEST_ASSERT_EQUAL(1, ret);
	TEST_ASSERT_EQUAL(11, offlen);
	TEST_ASSERT_EQUAL_STRING_LEN("abracadabra", tstr + offset, offlen);

	trie_destroy(&trie);
}

TEST(TrieTest, Trie_string_finds_opt_end)
{
	int ret;
	size_t offset;
	size_t offlen;
	struct trie_container trie;

	ret = trie_init(&trie);
	ret = trie_add_string(&trie, (uint8_t *)ASTR, sizeof(ASTR) - 1);
	ret = trie_add_string(&trie, (uint8_t *)BSTR, sizeof(BSTR) - 1);
	ret = trie_add_string(&trie, (uint8_t *)CSTR, sizeof(CSTR) - 1);

	ret = trie_process_str(&trie, 
			(uint8_t *)tstr, sizeof(tstr) - 1,
			TRIE_OPT_MAP_TO_END, 
			&offset, &offlen
	);
	TEST_ASSERT_EQUAL(1, ret);
	TEST_ASSERT_EQUAL(7, offlen);
	TEST_ASSERT_EQUAL_STRING_LEN("abacaba", tstr + offset, offlen);

	ret = trie_process_str(&trie, 
			(uint8_t *)tstr, sizeof(tstr),
			TRIE_OPT_MAP_TO_END, 
			&offset, &offlen
	);
	TEST_ASSERT_EQUAL(0, ret);

	trie_destroy(&trie);
}

TEST(TrieTest, Trie_single_vertex)
{
	int ret;
	size_t offset;
	size_t offlen;
	struct trie_container trie;

	ret = trie_init(&trie);

	ret = trie_process_str(&trie, 
			(uint8_t *)tstr, sizeof(tstr) - 1,
			0, 
			&offset, &offlen
	);
	TEST_ASSERT_EQUAL(0, ret);

	trie_destroy(&trie);

}

TEST(TrieTest, Trie_uninitialized)
{
	int ret;
	size_t offset;
	size_t offlen;
	struct trie_container trie = {0};

	// ret = trie_init(&trie);

	ret = trie_add_string(&trie, (uint8_t *)ASTR, sizeof(ASTR) - 1);
	TEST_ASSERT_EQUAL(-EINVAL, ret);

	ret = trie_process_str(&trie, 
			(uint8_t *)tstr, sizeof(tstr) - 1,
			0, 
			&offset, &offlen
	);
	TEST_ASSERT_EQUAL(0, ret);

}


TEST_GROUP_RUNNER(TrieTest)
{
	RUN_TEST_CASE(TrieTest, Trie_string_adds);
	RUN_TEST_CASE(TrieTest, Trie_string_finds);
	RUN_TEST_CASE(TrieTest, Trie_string_finds_opt_end);
	RUN_TEST_CASE(TrieTest, Trie_single_vertex);
	RUN_TEST_CASE(TrieTest, Trie_uninitialized);
}
