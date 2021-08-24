/*
 * Copyright 2021 Fabrice PREMEL. All Rights Reserved.
 *
 This file is part of FDGC.

    FDGC is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    FDGC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with FDGC.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _FDGC_H_
#define _FDGC_H_

#include <stdlib.h>
#include <qcbor/UsefulBuf.h>

/*
 * FDGC library
 *
 * Purpose of this library is to provide the means to decode and verify European's Digital Green Certificates, ie covid sanitary pass. See here for full specs : https://ec.europa.eu/health/ehealth/covid-19
 *
 * Digitcal Green Certificates are encoded as QR-Codes that are meant to be presented when doing certain activities (dependig on countries) or travaling inside the UE.
 * A certificate is digitally signed and can expire, which are checked by the library.
 * It will then provide informations on either :
 * - the vaccination status of its bearer
 * - the testing status of its bearer (NOTE THAT IT CAN BE POSITIVE, see cat.t.tr)
 * - the recovery status of its bearer
 *
 * Note that interpreting these status inside a country is country dependant, as, for example, the time limit of a negative test varies from country to country.
 *
 * At this moment the library will NOT interpret the results but present them back to the calling application.
 *
 * The UE provides tests certicates here : https://github.com/eu-digital-green-certificates/dgc-testdata that is used to validate fdgc's correcness. Note that some of these tests certificates are expired or used keys that are no longer available.
 *
 * Signing is done against public keys that are provided in different ways and formats from country to country, including countries that do not make them fully and openly available.
 * Right now FDGC uses and undertands Germany's servers and formats for public keys. Since all countries share their keys and make them available, using german servers still provide the full list of each country's public keys.
 */

/* FDGC Usage
 *
 * Here is a description of each public function call provided by the library.
 *
 *	int fdgc_init_pass_lib(struct fdgc_context *plib, char *certs_file, char *certs_url, int *err_code);
 *   First call to be made, it will initialize some internals.
 *   Parameters :
 *   - plib is a pointer to a soon to be allocated struct pdgc_context structure to hold internal informations and public keys
 *   - certs_file is a file path to be used to both read a previously cached public keys list and to update it with online informations. Providing a NULL parameter bypass both mechanisms
 *   - certs_url is a url to the german formated public keys. If NULL, the default production url will be used.
 *   - err_code is an integer that will be used to store error codes if anything fails
 *   Return value :
 *   - boolean flag, with 1 being a success and 0 a failure
 *	 Notes :
 *	 This function will try to download the lastest public keys available from certs_url (or default german url if NULL) in a blocking way so might take some time.
 *	 Also, either a successful download or a cache read is needed
 *
 *
 *	void fdgc_free_pass_lib(struct fdgc_context *plib);
 *	 Last call to be made, it will free the plib structure
 *	 Parameter :
 *	 - plib, the previously allocated struct fdgc_context
 *
 *
 *	struct fdgc_info_pass *fdgc_get_pass_string(struct fdgc_context *plib, char *qr_code, int *err_code);
 *   Will decode, signature check and expiration check a qr_code
 *   Parameters :
 *   - plib is the struct fdgc_context initialized at fdgc_init_pass_lib() time
 *   - qr_code is qr_code to be decoded, as a string
 *   - err_code is an integer that will be used to store error codes if anything fails
 *   Return value :
 *   - struct fdgc_info_pass * allocated and filled with the proper informations (see struct details) or NULL in case of error
 *
 *
 *	void fdgc_free_info_pass(struct fdgc_info_pass *pass);
 *	 Frees a previously allocated struct fdgc_info_pass as created by fdgc_get_pass_string()
 *	 Parameter :
 *	 - pass as returned by a previous fdgc_get_pass_string() call
 */

/* FDGC Example
 *
 * Here is the minimal code needed to fully decode a Digital Green Certificate :
 *
 * #include <fdgc.h>
 *
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
 
 *
 */

#define FDGC_CAT_V 1
#define FDGC_CAT_T 2
#define FDGC_CAT_R 3

char *fdgc_pass_cat_to_str[] = { "", "vaccine", "test", "recovery" };


/* fdgc_info_pass structure
 *
 * Details of each field are descibed here : https://ec.europa.eu/health/sites/default/files/ehealth/docs/covid-certificate_json_specification_en.pdf
 *
 * struct fdgc_info_pass will basically holds all informations present in the certificate
 *
 */

struct fdgc_info_pass {
        char *ver;                      //Schema version. Currently version 1.3.0 is supported - mandatory
        struct nam {
                char *fn;               //Surname of holder - mandatory
                char *fnt;              //Standardised surname of holder - mandatory
                char *gn;               //Forename of holder - mandatory
                char *gnt;              //Stardardised forename of holder - mandatory
        } nam;
        char *dob;                      //Holder's date of birth. Format can be YYYY-MM-DD, YYYY-MM, YYYY - mandatory
        int64_t cat_type;               //Type of certificate : FDGC_CAT_V for vaccine, FDGC_CAT_T for test, FDGC_CAT_R for recovery. Used to interpret cat union. - mandatory
        union cat {
                struct v {
                        char *tg;       //targeted disease, 840539006 for COVID-19 - mandatory
                        char *vp;       //Type of vaccine used, see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/valuesets/vaccine-prophylaxis.json. Note that some countries will badly fill that field, so it shouldn't be trusted (ex : France) - mandatory
                        char *mp;       //Brand of vaccine used, see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/valuesets/vaccine-medicinal-product.json - mandatory
                        char *ma;       //Vaccine manufacturer, see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/valuesets/vaccine-mah-manf.json - mandatory
                        int64_t dn;     //Dose number of this certificate - mandatory
                        int64_t sd;     //Total dose number for this vaccine - mandatory
                        char *dt;       //Date of this injection, in YYYY-MM-DD format - mandatory
                        char *co;       //Country where injection took place, see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/valuesets/country-2-codes.json - mandatory
                        char *is;       //Name of the organisation that issued the certiticate - mandatory
                        char *ci;       //Unique Certificate Identifier - mandatory
                } v;
                struct t {
                        char *tg;       //targeted disease, 840539006 for COVID-19 - mandatory
                        char *tt;       //Type of test, see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/valuesets/test-type.json - mandatory
                        char *nm;       //Commercial name of the test - optionnal
                        char *ma;       //Rapid antigen test device identifier, see https://covid-19-diagnostics.jrc.ec.europa.eu/devices?manufacturer&text_name&marking&rapid_diag&format&target_type&field-1=HSC%20common%20list%20%28RAT%29&value-1=1&search_method=AND#form_content and https://covid-19-diagnostics.jrc.ec.europa.eu/devices/hsc-common-recognition-rat - mandatory for RAT tests, never present for other tests
                        char *sc;       //Date and time of test sample collection. Some certificates seem to instead have test results date ... Formats can be YYYY-MM-DDThh:mm:ssZ YYYY-MM-DDThh:mm:ss[+-]hh YYYY-MM-DDThh:mm:ss[+-]hhmm YYYY-MM-DDThh:mm:ss[+-]hh:mm - mandatory
                        char *tr;       //Test result, see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/valuesets/test-result.json - mandatory
                        char *tc;       //Name of testing center - mandatory for NAAT tests, optionnal for RAT tests
                        char *co;       //Country where test took place, see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/valuesets/country-2-codes.json - mandatory
                        char *is;       //Name of the organisation that issued the certiticate - mandatory
                        char *ci;       //Unique Certificate Identifier - mandatory
                } t;
                struct r {
                        char *tg;       //targeted disease, 840539006 for COVID-19 - mandatory
                        char *fr;       //Date of first positive NAAT test, format YYYY-MM-DD - mandatory
                        char *co;       //Country where test took place, see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/valuesets/country-2-codes.json - mandatory
                        char *is;       //Name of the organisation that issued the certiticate - mandatory
                        char *df;       //First date of validity of certificate, format YYYY-MM-DD - mandatory
                        char *du;       //Last date of validity of certificate, format YYYY-MM-DD - mandatory
                        char *ci;       //Unique Certificate Identifier - mandatory
                } r;
        } cat;
  time_t iat;                           //Issuing date of certificate - mandatory
  time_t exp;                           //Expering date of certificate, this is checked by fdgc and will result in an error if certificate is expired - mandatory

  /*Internal informations*/

	struct sign_header {
		int64_t alg;
		char kid[8];
	} sign_header;
	UsefulBufC signature;
	UsefulBufC payload;
};

struct certificate_unit {
        char *certificateType;
        char *country;
        char kid[8];
        UsefulBufC rawdata;
        char *timestamp;
};

typedef struct fdgc_certificates {
   struct certificate_unit  *certs;
   size_t len;
} fdgc_certificates;

struct fdgc_context {
	fdgc_certificates *certs;
	char *certs_url;
	char *certs_file;
	time_t certs_last_update;
};

#define FDGC_BASE45_NULL_INPUT 1
#define FDGC_BASE45_INVALID_INPUT 2
#define FDGC_BASE45_MEM_ERR 3
#define FDGC_CBOR_HIGH_LEVEL_ERROR 4
#define FDGC_CBOR_LOW_LEVEL_ERROR 5
#define FDGC_CBOR_BUILDPAYLOAD_ERROR 9
#define FDGC_CERT_PARSE 6
#define FDGC_CERT_PARSE_NO_CERTIFICATES 7
#define FDGC_CERT_MEM_ERR 8
#define FDGC_QR_HEADER_VER 10
#define FDGC_ZLIB_ERR 11
#define FDGC_CURL_INIT_ERR 12
#define FDGC_CURL_FETCH_ERR 13
#define FDGC_NO_CERTS 14
#define FDGC_SIGN_NOKEY_FOUND 15
#define FDGC_SIGN_INVALID_KEY 16
#define FDGC_SIGN_DIGEST_ERR 17
#define FDGC_SIGN_BN_ERR 18
#define FDGC_SIGN_SIG 19
#define FDGC_SIGN_INVALID_ALG 20
#define FDGC_EXPIRED 21
#ifdef ZBAR_SUPPORT
#define FDGC_ZBAR_FILE_ERR 22
#define FDGC_ZBAR_PNG_ERR 23
#define FDGC_ZBAR_NO_QR 24
#endif


void fdgc_free_info_pass(struct fdgc_info_pass *pass);

struct fdgc_info_pass *fdgc_get_pass_string(struct fdgc_context *plib, char *qr_code, int *err_code);

#ifdef ZBAR_SUPPORT
struct fdgc_info_pass *fdgc_get_pass_img(struct fdgc_context *plib, char *filename, int *err_code);
#endif

int fdgc_init_pass_lib(struct fdgc_context *plib, char *certs_file, char *certs_url, int *err_code);

void fdgc_free_pass_lib(struct fdgc_context *plib);

#endif
