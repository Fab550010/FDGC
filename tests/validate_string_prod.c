#include "fdgc.h"

#include <stdio.h>
#include <time.h>

#define BUFLEN 1500

int main(int argc, char **argv) {
	int err_code;
	struct fdgc_context plib;
	if (!fdgc_init_pass_lib(&plib, NULL, NULL, &err_code)) {
		fprintf(stderr, "Erreur à l'init : %i\n", err_code);
		return 1;
	}

	unsigned char buf[BUFLEN];

	while (fgets(buf, BUFLEN, stdin) ) {
		if (buf[strlen(buf)-1] == '\n')
			buf[strlen(buf)-1] = '\0';
		struct fdgc_info_pass *p = fdgc_get_pass_string(&plib, buf, &err_code);
		if (p) {
			char iat[50];
			char exp[50];
			strftime(iat, 50, "%Y-%m-%d %H-%M-%S", localtime(&(p->iat)));
			strftime(exp, 50, "%Y-%m-%d %H-%M-%S", localtime(&(p->exp)));
			printf("string has been decoded and its signature checked. Type : %s, emitted at %s and expiring %s\n", fdgc_pass_cat_to_str[p->cat_type], iat, exp);
			printf("Can the holder travel inside the EU ? %s\n", fdgc_valid_pass_eu(p) ? "Yes !" : "No !");
			fdgc_free_info_pass(p);
		} else
			printf("string not decoded because %i\n", err_code);
	}

	fdgc_free_pass_lib(&plib);
	
	return 0;
}



