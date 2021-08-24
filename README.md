FDGC library
============

Intro
-----

Purpose of this library is to provide the means to decode and verify European's Digital Green Certificates, ie covid sanitary pass. See here for full specs : https://ec.europa.eu/health/ehealth/covid-19

Digital Green Certificates are encoded as QR-Codes that are meant to be presented when doing certain activities (dependig on countries) or travaling inside the UE.
A certificate is digitally signed and can expire, which are checked by the library.
It will then provide informations on either :
- the vaccination status of its bearer
- the testing status of its bearer (NOTE THAT IT CAN BE POSITIVE, see cat.t.tr)
- the recovery status of its bearer

Note that interpreting these status inside a country is country dependant, as, for example, the time limit of a negative test varies from country to country.

At this moment the library will NOT interpret the results but present them back to the calling application.

The UE provides tests certicates here : https://github.com/eu-digital-green-certificates/dgc-testdata that is used to validate fdgc's correcness. Note that some of these tests certificates are expired or used keys that are no longer available.

Signing is done against public keys that are provided in different ways and formats from country to country, including countries that do not make them fully and openly available.
Right now FDGC uses and undertands Germany's servers and formats for public keys. Since all countries share their keys and make them available, using german servers still provide the full list of each country's public keys.

Contact info and website
------------------------

You can contact me at fab550010 gmail com
Git adress :


FDGC Usage
----------

Here is a description of each public function call provided by the library.

     _int fdgc_init_pass_lib(struct fdgc_context *plib, char *certs_file, char *certs_url, int *err_code);_
First call to be made, it will initialize some internals.
Parameters :
* plib is a pointer to a soon to be allocated struct pdgc_context structure to hold internal informations and public keys
* certs_file is a file path to be used to both read a previously cached public keys list and to update it with online informations. Providing a NULL parameter bypass both mechanisms
* certs_url is a url to the german formated public keys. If NULL, the default production url will be used.
* err_code is an integer that will be used to store error codes if anything fails
Return value :
* boolean flag, with 1 being a success and 0 a failure
    Notes :
This function will try to download the lastest public keys available from certs_url (or default german url if NULL) in a blocking way so might take some time.
Also, either a successful download or a cache read is needed.


     _void fdgc_free_pass_lib(struct fdgc_context *plib);_
Last call to be made, it will free the plib structure
Parameter :
* plib, the previously allocated struct fdgc_context


     _struct fdgc_info_pass *fdgc_get_pass_string(struct fdgc_context *plib, char *qr_code, int *err_code);_
Will decode, signature check and expiration check a qr_code
Parameters :
* plib is the struct fdgc_context initialized at fdgc_init_pass_lib() time
* qr_code is qr_code to be decoded, as a string
* err_code is an integer that will be used to store error codes if anything fails
Return value :
* struct fdgc_info_pass * allocated and filled with the proper informations (see struct details) or NULL in case of error


     _void fdgc_free_info_pass(struct fdgc_info_pass *pass);_
Frees a previously allocated struct fdgc_info_pass as created by fdgc_get_pass_string()
Parameter :
* pass as returned by a previous fdgc_get_pass_string() call


FDGC Example
------------

Here is the minimal code needed to fully decode a Digital Green Certificate :

.................
```
#include <fdgc.h>

int main() {

	char qr_code="HC1:AAAAAAAAAAAAAAAAAAAAAA"; // a real qr_code is needed
  int err_code;

  struct fdgc_context plib;
  if (!fdgc_init_pass_lib(&plib, NULL, NULL, &err_code)) {
  	fprintf(stderr, "FDGC initialization error : %i\n", err_code);
    return 1;
  }

  struct fdgc_info_pass *p = fdgc_get_pass_string(&plib, qr_code, &err_code);
  if (!p) {
  	fprintf(stderr, "FDGC decoding error : %i\n", err_code);
    return 2;
  }

  printf("The pass of %s %s born on %s has been decoded and validated\n", p->nam.fn, p->nam.gn, p->dob);

  fdgc_free_info_pass(p);

  fdgc_free_pass_lib(&plib);

  return 0;
}
```
.................


