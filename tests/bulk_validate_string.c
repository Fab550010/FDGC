#include "fdgc.h"

#include <stdio.h>
#include <time.h>

#define BUFLEN 1500

int main(int argc, char **argv) {
	int err_code;
	struct fdgc_context plib;
	if (!fdgc_init_pass_lib(&plib, NULL, "https://de.qa.dscg.ubirch.com/trustList/DSC/", &err_code)) {
		fprintf(stderr, "Erreur à l'init : %i\n", err_code);
		return 1;
	}

	unsigned char buf[BUFLEN];
	int i=1;

	while (fgets(buf, BUFLEN, stdin) ) {
		if (buf[strlen(buf)-1] == '\n')
			buf[strlen(buf)-1] = '\0';
		struct fdgc_info_pass *p = fdgc_get_pass_string(&plib, buf, &err_code);
		if (p) {
			char iat[50];
			char exp[50];
			strftime(iat, 50, "%Y-%m-%d %H-%M-%S", localtime(&(p->iat)));
			strftime(exp, 50, "%Y-%m-%d %H-%M-%S", localtime(&(p->exp)));
			printf("string %i has been decoded and its signature checked. Type : %s, emitted at %s and expiring %s\n", i, fdgc_pass_cat_to_str[p->cat_type], iat, exp);
			free(p);
		} else
			printf("string %i not decoded because %i\n", i, err_code);
		i++;
	}

	fdgc_free_pass_lib(&plib);
	
	return 0;
}



