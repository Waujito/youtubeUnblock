/*
  Copyright 2005-2014 Rich Felker, et al.
  
  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:
  
  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#include "types.h"
#include "logging.h"
#include "getopt.h"

char *optarg;
int optind=1, opterr=1, optopt, __optpos, optreset=0;

#define optpos __optpos

static void __getopt_msg(const char *b, const char *c, size_t l)
{
	lgerr("%s %.*s", b, (int)l, c);
}

int getopt(int argc, char * const argv[], const char *optstring)
{
	int i, c, d;
	int k, l;
	char *optchar;

	if (!optind || optreset) {
		optreset = 0;
		__optpos = 0;
		optind = 1;
	}

	if (optind >= argc || !argv[optind])
		return -1;

	if (argv[optind][0] != '-') {
		if (optstring[0] == '-') {
			optarg = argv[optind++];
			return 1;
		}
		return -1;
	}

	if (!argv[optind][1])
		return -1;

	if (argv[optind][1] == '-' && !argv[optind][2])
		return optind++, -1;

	if (!optpos) optpos++;
	c = argv[optind][optpos], k = 1;
	optchar = argv[optind]+optpos;
	optopt = c;
	optpos += k;

	if (!argv[optind][optpos]) {
		optind++;
		optpos = 0;
	}

	if (optstring[0] == '-' || optstring[0] == '+')
		optstring++;

	i = 0;
	d = 0;
	do {
		d = optstring[i], l = 1;
		if (l>0) i+=l; else i++;
	} while (l && d != c);

	if (d != c) {
		if (optstring[0] != ':' && opterr)
			__getopt_msg("Unrecognized option: ", optchar, k);
		return '?';
	}
	if (optstring[i] == ':') {
		if (optstring[i+1] == ':') optarg = 0;
		else if (optind >= argc) {
			if (optstring[0] == ':') return ':';
			if (opterr) __getopt_msg("Option requires an argument: ",
				optchar, k);
			return '?';
		}
		if (optstring[i+1] != ':' || optpos) {
			optarg = argv[optind++] + optpos;
			optpos = 0;
		}
	}
	return c;
}

static void permute(char *const *argv, int dest, int src)
{
	char **av = (char **)argv;
	char *tmp = av[src];
	int i;
	for (i=src; i>dest; i--)
		av[i] = av[i-1];
	av[dest] = tmp;
}

static int __getopt_long_core(int argc, char *const *argv, const char *optstring, const struct option *longopts, int *idx, int longonly)
{
	optarg = 0;
	if (longopts && argv[optind][0] == '-' &&
		((longonly && argv[optind][1] && argv[optind][1] != '-') ||
		 (argv[optind][1] == '-' && argv[optind][2])))
	{
		int colon = optstring[optstring[0]=='+'||optstring[0]=='-']==':';
		int i, cnt, match = -1;
		char *opt;
		for (cnt=i=0; longopts[i].name; i++) {
			const char *name = longopts[i].name;
			opt = argv[optind]+1;
			if (*opt == '-') opt++;
			for (; *name && *name == *opt; name++, opt++);
			if (*opt && *opt != '=') continue;
			match = i;
			if (!*name) {
				cnt = 1;
				break;
			}
			cnt++;
		}
		if (cnt==1) {
			i = match;
			optind++;
			optopt = longopts[i].val;
			if (*opt == '=') {
				if (!longopts[i].has_arg) {
					if (colon || !opterr)
						return '?';
					__getopt_msg(
						"Option does not take an argument: ",
						longopts[i].name,
						strlen(longopts[i].name));
					return '?';
				}
				optarg = opt+1;
			} else if (longopts[i].has_arg == required_argument) {
				if (!(optarg = argv[optind])) {
					if (colon) return ':';
					if (!opterr) return '?';
					__getopt_msg(
						"Option requires an argument: ",
						longopts[i].name,
						strlen(longopts[i].name));
					return '?';
				}
				optind++;
			}
			if (idx) *idx = i;
			if (longopts[i].flag) {
				*longopts[i].flag = longopts[i].val;
				return 0;
			}
			return longopts[i].val;
		}
		if (argv[optind][1] == '-') {
			if (!colon && opterr)
				__getopt_msg(cnt ?
					"Option is ambiguous: " :
					"Unrecognized option: ",
					argv[optind]+2,
					strlen(argv[optind]+2));
			optind++;
			return '?';
		}
	}
	return getopt(argc, argv, optstring);
}

static int __getopt_long(int argc, char *const *argv, const char *optstring, const struct option *longopts, int *idx, int longonly)
{
	int ret, skipped, resumed;
	if (!optind || optreset) {
		optreset = 0;
		__optpos = 0;
		optind = 1;
	}
	if (optind >= argc || !argv[optind]) return -1;
	skipped = optind;
	if (optstring[0] != '+' && optstring[0] != '-') {
		int i;
		for (i=optind; ; i++) {
			if (i >= argc || !argv[i]) return -1;
			if (argv[i][0] == '-' && argv[i][1]) break;
		}
		optind = i;
	}
	resumed = optind;
	ret = __getopt_long_core(argc, argv, optstring, longopts, idx, longonly);
	if (resumed > skipped) {
		int i, cnt = optind-resumed;
		for (i=0; i<cnt; i++)
			permute(argv, skipped, optind-1);
		optind = skipped + cnt;
	}
	return ret;
}

int getopt_long(int argc, char *const *argv, const char *optstring, const struct option *longopts, int *idx)
{
	return __getopt_long(argc, argv, optstring, longopts, idx, 0);
}

int getopt_long_only(int argc, char *const *argv, const char *optstring, const struct option *longopts, int *idx)
{
	return __getopt_long(argc, argv, optstring, longopts, idx, 1);
}
