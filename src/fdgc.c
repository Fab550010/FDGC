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

#define _GNU_SOURCE
#include <time.h>

#include "fdgc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <zlib.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include <cjson/cJSON.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <curl/curl.h>

#ifdef ZBAR_SUPPORT
#include <zbar.h>
#include <png.h>
#endif

//#define FDGC_DEBUG 1

void destroy_certificates(fdgc_certificates *c) {
	for (int i=0;i<c->len;i++) {
		free(c->certs[i].certificateType);
		free(c->certs[i].country);
		free((void *)c->certs[i].rawdata.ptr);
		free(c->certs[i].timestamp);
	}
	free(c->certs);
	c->certs=NULL;
	c->len=0;
}

int base64_decode_len(char *input) {
	if (!input)
		return 0;
	int len = strlen(input);
	if (len<3)
		return 0;
	int padding;

	if ( (input[len-1] == '=') && (input[len-2] == '=') ) {
		padding = 2;
	} else if ( input[len-1] == '=' ) {
		padding = 1;
	} else {
		padding=0;
	}

	return len * 3 / 4 - padding;
}

UsefulBufC base64_decode(char *input) {
	UsefulBufC res;
	res.ptr=NULL;
	res.len = base64_decode_len(input);
	if (!res.len)
		return res;
	res.ptr = calloc(1, res.len);

	FILE *s = fmemopen(input, strlen(input), "r");
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *bio = BIO_new_fp(s, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_read(bio, (void *)res.ptr, strlen(input));
	BIO_free_all(bio);
	fclose(s);

	return res;
}
	

fdgc_certificates *parse_certificates_json(char *input, int *err_code) {
	fdgc_certificates *res = malloc(sizeof(fdgc_certificates));
	res->certs = NULL;
	*err_code = 0;
	cJSON *json = cJSON_Parse(input);

	if ( json == NULL ) {
		*err_code = FDGC_CERT_PARSE;
		goto end;
	}
	cJSON *certificates = cJSON_GetObjectItemCaseSensitive(json, "certificates");
	if ( certificates == NULL ) {
		*err_code = FDGC_CERT_PARSE_NO_CERTIFICATES;
		goto end;
	}
	res->len = cJSON_GetArraySize(certificates);
	res->certs = calloc((*res).len, sizeof(struct certificate_unit));
	if ( (*res).certs == NULL ) {
		*err_code = FDGC_CERT_MEM_ERR;
		goto end;
	}

	for (int i=0;i<(*res).len;i++) {
		cJSON *cert_json = cJSON_GetArrayItem(certificates, i);
		res->certs[i].certificateType = strdup(cJSON_GetObjectItemCaseSensitive(cert_json, "certificateType")->valuestring);
		res->certs[i].country = strdup(cJSON_GetObjectItemCaseSensitive(cert_json, "country")->valuestring);
		if ( base64_decode_len(cJSON_GetObjectItemCaseSensitive(cert_json, "kid")->valuestring) != 8 )
			goto end;
		UsefulBufC buf = base64_decode(cJSON_GetObjectItemCaseSensitive(cert_json, "kid")->valuestring);
		memcpy(res->certs[i].kid, buf.ptr, 8);
		free((void *)buf.ptr);

		res->certs[i].rawdata = base64_decode(cJSON_GetObjectItemCaseSensitive(cert_json, "rawData")->valuestring);

		res->certs[i].timestamp = strdup(cJSON_GetObjectItemCaseSensitive(cert_json, "timestamp")->valuestring);
	}

	end: 
		cJSON_Delete(json);
		if ( *err_code ) {
			if ( res->certs ) 
				destroy_certificates(res);				
			free(res);
			return NULL;
		} else {
			return res;
		}
}

static char tab[256] = {
	255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255,
	255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255,
	36, 255,255,255,  37, 38,255,255, 255,255, 39, 40, 255, 41, 42, 43,
         0,   1,  2,  3,   4,  5,  6,  7,   8,  9, 44,255, 255,255,255,255, 

        255, 10, 11, 12,  13, 14, 15, 16,  17, 18, 19, 20,  21, 22, 23, 24, /* uppercase */
         25, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 35, 255,255,255,255,
        255, 10, 11, 12,  13, 14, 15, 16,  17, 18, 19, 20,  21, 22, 23, 24, /* lowercase */
         25, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 35, 255,255,255,255,

	255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255, 
	255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255,
	255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255,
	255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255,

	255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255,
	255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255,
	255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255,
	255,255,255,255, 255,255,255,255, 255,255,255,255, 255,255,255,255,
};

static const char BASE45_CHARSET[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

UsefulBufC *base45_decode(char *input, int *err_code) {
	UsefulBufC res;
	res.len=0;
	res.ptr=NULL;

	if ( input == NULL ) {
		*err_code = FDGC_BASE45_NULL_INPUT;
		return NULL;
	}

	int len = strlen(input);
	if ( len < 3 ) {
		*err_code = FDGC_BASE45_INVALID_INPUT;
		return NULL;
	}

	res.ptr = malloc(len / 3 * 2 + ( (len % 3) ? 1 : 0 ) );
	if ( res.ptr == NULL ) {
		*err_code = FDGC_BASE45_MEM_ERR;
		return NULL;
	}

	char *p = input;
	char *r = (char *)res.ptr;
	res.len = 0;
	while ( p < input + len ) {
		if ( p + 3 <= input + len ) {
			if ( (tab[(int)*p] == 255) || (tab[(int)*p+1] == 255) || (tab[(int)*p+2] == 255) ) {
				free((char *)res.ptr);
				*err_code = FDGC_BASE45_INVALID_INPUT;
				return NULL;
			}
			unsigned int n = tab[(int)*p] + tab[(int)*(p+1)]*45 + tab[(int)*(p+2)]*45*45;
			*r = n/256;
			r++;
			*r = n%256;
			r++;
			res.len += 2;
			p+=3;
		} else {
			if ( (tab[(int)*p] == 255) || (tab[(int)*p+1] == 255) ) {
				free((char *)res.ptr);
				*err_code = FDGC_BASE45_INVALID_INPUT;
			}
			*r = tab[(int)*p] + tab[(int)*(p+1)]*45;
			r++;
			p+=2;
			res.len += 1;
		}
	}

	UsefulBufC *res2 = malloc(sizeof(UsefulBufC));
	(*res2).len = res.len;
	(*res2).ptr = res.ptr;
	return res2;
}

char *base45_encode(UsefulBufC *input, int *err_code) {
	if ( input == NULL ) {
		*err_code = FDGC_BASE45_NULL_INPUT;
		return NULL;
	}

	char *res = calloc(input->len*4, 1);
	unsigned char *inp = (unsigned char *)input->ptr;
	int j=0;
	for(int i = 0;i<input->len;i+=2) {
		if ( input->len -i > 1 ) {
			int x = inp[i]*256 + inp[i+1];
			unsigned char e, d, c;
			e = x / (45*45);
			x %= 45*45;
			d = x / 45;
			c = x % 45;
			res[j++] = BASE45_CHARSET[c];
			res[j++] = BASE45_CHARSET[d];
			res[j++] = BASE45_CHARSET[e];
		} else {
			int x = inp[i];
			unsigned char c, d;
			d = x /45;
			c = x % 45;
			res[j++] = BASE45_CHARSET[c];
			res[j++] = BASE45_CHARSET[d];
		}
	}

	return res;
}

void fdgc_destroy_info_pass(struct fdgc_info_pass pass) {
	free(pass.ver);
	free(pass.nam.fn);
	free(pass.nam.fnt);
	free(pass.nam.gn);
	free(pass.nam.gnt);
	free(pass.dob);
	if ( pass.cat_type == FDGC_CAT_V ) {
		free(pass.cat.v.tg);
		free(pass.cat.v.vp);
		free(pass.cat.v.mp);
		free(pass.cat.v.ma);
		free(pass.cat.v.dt);
		free(pass.cat.v.co);
		free(pass.cat.v.is);
		free(pass.cat.v.ci);
	} else if ( pass.cat_type == FDGC_CAT_T ) {
		free(pass.cat.t.tg);
		free(pass.cat.t.tt);
		free(pass.cat.t.nm);
		free(pass.cat.t.ma);
		free(pass.cat.t.sc);
		free(pass.cat.t.tr);
		free(pass.cat.t.tc);
		free(pass.cat.t.co);
		free(pass.cat.t.is);
		free(pass.cat.t.ci);
	} else if ( pass.cat_type == FDGC_CAT_R ) {
		free(pass.cat.r.tg);
		free(pass.cat.r.fr);
		free(pass.cat.r.co);
		free(pass.cat.r.is);
		free(pass.cat.r.df);
		free(pass.cat.r.du);
		free(pass.cat.r.ci);
	}
	free((void *)pass.signature.ptr);
	pass.signature.len=0;
	free((void *)pass.payload.ptr);
}

void fdgc_free_info_pass(struct fdgc_info_pass *pass) {
	fdgc_destroy_info_pass(*pass);
	free(pass);
}

void buftostr(UsefulBufC *txt, char **s) {
	if ( txt->len == 0 )
		return ;
	*s = calloc(1, txt->len+1);
	memcpy(*s, txt->ptr, txt->len);
}

/*
void debug_peek_next(QCBORDecodeContext *DecodeCtx) {
	QCBORItem item;
	QCBORDecode_VPeekNext(DecodeCtx, &item);
	printf("type : %i, nextinglevel : %i; nextnesting : %i; label : %i\n", item.uDataType, item.uNestingLevel, item.uNextNestLevel, item.uLabelType);
	QCBORError uErr;
	uErr = QCBORDecode_GetError(DecodeCtx);
	if(uErr != QCBOR_SUCCESS) {
		printf("err : %i\n", uErr);
		return;
	}
}
*/

int build_payload(struct fdgc_info_pass *pass, UsefulBufC header, UsefulBufC data, int *err_code) {
	QCBOREncodeContext EncodeCtx;
	UsefulBuf out;
	UsefulBufC outres;
	outres.ptr = NULL;outres.len = 0;
	out.ptr = NULL; out.len = UINT32_MAX;
	UsefulBufC nulstr; nulstr.len=0;
        QCBOREncode_Init(&EncodeCtx, out);
                QCBOREncode_OpenArray(&EncodeCtx);
                        QCBOREncode_AddSZString(&EncodeCtx, "Signature1");
                        QCBOREncode_AddBytes(&EncodeCtx, header);
                        QCBOREncode_AddBytes(&EncodeCtx, nulstr);
                        QCBOREncode_AddBytes(&EncodeCtx, data);
                QCBOREncode_CloseArray(&EncodeCtx);
        QCBOREncode_Finish(&EncodeCtx, &outres);
        out.ptr = malloc(out.len);
        QCBOREncode_Init(&EncodeCtx, out);
                QCBOREncode_OpenArray(&EncodeCtx);
                        QCBOREncode_AddSZString(&EncodeCtx, "Signature1");
                        QCBOREncode_AddBytes(&EncodeCtx, header);
                        QCBOREncode_AddBytes(&EncodeCtx, nulstr);
                        QCBOREncode_AddBytes(&EncodeCtx, data);
                QCBOREncode_CloseArray(&EncodeCtx);
        QCBORError uerr = QCBOREncode_Finish(&EncodeCtx, &pass->payload);
        if ( uerr != QCBOR_SUCCESS ) {
#ifdef FDGC_DEBUG
		printf("err build_payload : %s\n", qcbor_err_to_str(QCBOREncode_GetErrorState(&EncodeCtx)));
#endif
                *err_code = FDGC_CBOR_BUILDPAYLOAD_ERROR;
                return 0;
        }
	return 1;
}


struct fdgc_info_pass *fdgc_decode_info_pass(UsefulBufC buf, int *err_code) {

	QCBORDecodeContext DecodeCtx;
	QCBORDecode_Init(&DecodeCtx, buf, QCBOR_DECODE_MODE_NORMAL);
	QCBORError uerr;
	
	UsefulBufC high_level_strings[3];
	UsefulBufC kid;
	kid.len=0;

	QCBORDecode_EnterArray(&DecodeCtx, NULL);
        	QCBORDecode_GetByteString(&DecodeCtx, &(high_level_strings[0]));
		if ( QCBORDecode_GetError(&DecodeCtx) != QCBOR_SUCCESS )
                	*err_code = FDGC_CBOR_LOW_LEVEL_ERROR;

		QCBORDecode_EnterMap(&DecodeCtx, NULL);
			QCBORDecode_GetByteStringInMapN(&DecodeCtx, 4, &kid);
			QCBORDecode_GetAndResetError(&DecodeCtx); //Previous call can be an error to ignore as kid can be either in protected header or here
		QCBORDecode_ExitMap(&DecodeCtx);

		QCBORDecode_GetByteString(&DecodeCtx, &(high_level_strings[1]));
		QCBORDecode_GetByteString(&DecodeCtx, &(high_level_strings[2]));
	QCBORDecode_ExitArray(&DecodeCtx);
	uerr = QCBORDecode_Finish(&DecodeCtx);
	if ( uerr != QCBOR_SUCCESS ) {
		*err_code = FDGC_CBOR_HIGH_LEVEL_ERROR;
		return NULL;
	}

#ifdef FDGC_DEBUG       
	FILE *f = fopen("/tmp/firststr", "w");
	fwrite(high_level_strings[0].ptr, high_level_strings[0].len, 1, f);
	fclose(f);
	FILE *f3 = fopen("/tmp/secondstr", "w");
	fwrite(high_level_strings[1].ptr, high_level_strings[1].len, 1, f3);
	fclose(f3);
	FILE *f2 = fopen("/tmp/thirdstr", "w");
	fwrite(high_level_strings[2].ptr, high_level_strings[2].len, 1, f2);
	fclose(f2);
	FILE *f4 = fopen("/tmp/completecbor", "w");
	fwrite(buf.ptr, buf.len, 1, f4);
	fclose(f4);
	int tmp;
	char *fst_45 = base45_encode(&high_level_strings[0], &tmp);
	printf("First str en 45 : %s\n", fst_45);
#endif

        struct fdgc_info_pass *pass;
        pass = calloc(1, sizeof(struct fdgc_info_pass));
        *err_code=0;

	if ( build_payload(pass, high_level_strings[0], high_level_strings[1], err_code) == 0 ) {
#ifdef FDGC_DEBUG
		printf("err payload\n");
#endif
		fdgc_free_info_pass(pass);
		return NULL;
	}

#ifdef FDGC_DEBUG
	FILE *f5 = fopen("/tmp/sign_payload", "w"); fwrite(pass->payload.ptr, pass->payload.len, 1, f5);fclose(f5);
	printf("l\n");
#endif

	QCBORDecode_Init(&DecodeCtx, high_level_strings[1], QCBOR_DECODE_MODE_NORMAL);

	QCBORDecode_EnterMap(&DecodeCtx, NULL);
		// some countries have wierd formats ...
		QCBORDecode_GetInt64ConvertAllInMapN(&DecodeCtx, 4, QCBOR_CONVERT_TYPE_XINT64 | QCBOR_CONVERT_TYPE_FLOAT | QCBOR_CONVERT_TYPE_BIG_NUM | QCBOR_CONVERT_TYPE_DECIMAL_FRACTION | QCBOR_CONVERT_TYPE_BIGFLOAT, &pass->exp);
		QCBORDecode_GetInt64ConvertAllInMapN(&DecodeCtx, 6, QCBOR_CONVERT_TYPE_XINT64 | QCBOR_CONVERT_TYPE_FLOAT | QCBOR_CONVERT_TYPE_BIG_NUM | QCBOR_CONVERT_TYPE_DECIMAL_FRACTION | QCBOR_CONVERT_TYPE_BIGFLOAT, &pass->iat);
		QCBORDecode_EnterMapFromMapN(&DecodeCtx, -260);
			QCBORDecode_EnterMapFromMapN(&DecodeCtx, 1);
				UsefulBufC txt;
				txt.len=0; //in case of previous error
				QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "dob", &txt);
				buftostr(&txt, &pass->dob);
				QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "ver", &txt);
				buftostr(&txt, &pass->ver);
				QCBORDecode_EnterMapFromMapSZ(&DecodeCtx, "nam");
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "fn", &txt);
					buftostr(&txt, &pass->nam.fn);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "fnt", &txt);
					buftostr(&txt, &pass->nam.fnt);
					if ( QCBORDecode_GetError(&DecodeCtx) != QCBOR_SUCCESS )
						*err_code = FDGC_CBOR_LOW_LEVEL_ERROR;

					//Optional parameters
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "gn", &txt);
                                        buftostr(&txt, &pass->nam.gn);
                                        QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "gnt", &txt);
                                        buftostr(&txt, &pass->nam.gnt);

					QCBORDecode_GetAndResetError(&DecodeCtx);
				QCBORDecode_ExitMap(&DecodeCtx);
			
				QCBORDecode_EnterArrayFromMapSZ(&DecodeCtx, "v");
				if (QCBORDecode_GetAndResetError(&DecodeCtx) == QCBOR_SUCCESS ) {
					QCBORDecode_EnterMap(&DecodeCtx, NULL);
					pass->cat_type = FDGC_CAT_V;
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "tg", &txt);
					buftostr(&txt, &pass->cat.v.tg);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "vp", &txt);
					buftostr(&txt, &pass->cat.v.vp);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "mp", &txt);
					buftostr(&txt, &pass->cat.v.mp);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "ma", &txt);
					buftostr(&txt, &pass->cat.v.ma);
					QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "dn", &(*pass).cat.v.dn);
					QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "sd", &(*pass).cat.v.sd);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "dt", &txt);
					buftostr(&txt, &pass->cat.v.dt);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "co", &txt);
					buftostr(&txt, &pass->cat.v.co);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "is", &txt);
					buftostr(&txt, &pass->cat.v.is);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "ci", &txt);
					buftostr(&txt, &pass->cat.v.ci);
					QCBORDecode_ExitMap(&DecodeCtx);
					QCBORDecode_ExitArray(&DecodeCtx);
				}
				QCBORDecode_EnterArrayFromMapSZ(&DecodeCtx, "t");
				if (QCBORDecode_GetAndResetError(&DecodeCtx) == QCBOR_SUCCESS ) {
					QCBORDecode_EnterMap(&DecodeCtx, NULL);
					(*pass).cat_type = FDGC_CAT_T;
					//Some countries encode as string, some as a tagged date. This should work for all
					QCBORDecode_GetDateStringInMapSZ(&DecodeCtx, "sc", QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG , &txt);
                                        buftostr(&txt, &pass->cat.t.sc);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "tg", &txt);
					buftostr(&txt, &pass->cat.t.tg);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "tt", &txt);
					buftostr(&txt, &pass->cat.t.tt);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "tr", &txt);
					buftostr(&txt, &pass->cat.t.tr);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "co", &txt);
					buftostr(&txt, &pass->cat.t.co);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "is", &txt);
					buftostr(&txt, &pass->cat.t.is);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "ci", &txt);
					buftostr(&txt, &pass->cat.t.ci);
					if ( QCBORDecode_GetError(&DecodeCtx) != QCBOR_SUCCESS ) 
						*err_code = FDGC_CBOR_LOW_LEVEL_ERROR;
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "nm", &txt);
					buftostr(&txt, &pass->cat.t.nm);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "ma", &txt);
					buftostr(&txt, &pass->cat.t.ma);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "tc", &txt);
					buftostr(&txt, &pass->cat.t.tc);
					QCBORDecode_GetAndResetError(&DecodeCtx);
					QCBORDecode_ExitMap(&DecodeCtx);
					QCBORDecode_ExitArray(&DecodeCtx);
				}
				QCBORDecode_EnterArrayFromMapSZ(&DecodeCtx, "r");
				if (QCBORDecode_GetAndResetError(&DecodeCtx) == QCBOR_SUCCESS ) {
					QCBORDecode_EnterMap(&DecodeCtx, NULL);
					(*pass).cat_type = FDGC_CAT_R;
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "tg", &txt);
					buftostr(&txt, &pass->cat.r.tg);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "fr", &txt);
					buftostr(&txt, &pass->cat.r.fr);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "co", &txt);
					buftostr(&txt, &pass->cat.r.co);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "is", &txt);
					buftostr(&txt, &pass->cat.r.is);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "df", &txt);
					buftostr(&txt, &pass->cat.r.df);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "du", &txt);
					buftostr(&txt, &pass->cat.r.du);
					QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "ci", &txt);
					buftostr(&txt, &pass->cat.r.ci);
					QCBORDecode_ExitMap(&DecodeCtx);
					QCBORDecode_ExitArray(&DecodeCtx);
				}
			QCBORDecode_ExitMap(&DecodeCtx);
		QCBORDecode_ExitMap(&DecodeCtx);
	QCBORDecode_ExitMap(&DecodeCtx);

	if ( ( QCBORDecode_GetError(&DecodeCtx) != QCBOR_SUCCESS ) || ( *err_code ) ) {
#ifdef FDGC_DEBUG
		printf("err dec : %s\n", qcbor_err_to_str(QCBORDecode_GetError(&DecodeCtx)));
#endif
		*err_code = FDGC_CBOR_LOW_LEVEL_ERROR;
		fdgc_free_info_pass(pass);
		return NULL;
	}

	// signature header
	QCBORDecode_Init(&DecodeCtx, high_level_strings[0], QCBOR_DECODE_MODE_NORMAL);
        QCBORDecode_EnterMap(&DecodeCtx, NULL);
		//kid can be either in the protected header OR outside it
		QCBORDecode_GetByteStringInMapN(&DecodeCtx, 4, &txt);
		if (QCBORDecode_GetAndResetError(&DecodeCtx) == QCBOR_SUCCESS ) {
			if ( txt.len == 8 ) {
				memcpy(pass->sign_header.kid, txt.ptr, 8);
			} else {
				*err_code = FDGC_CBOR_LOW_LEVEL_ERROR;
			}
		} else {
			if ( kid.len == 8 ) {
				memcpy(pass->sign_header.kid, kid.ptr, 8);
			} else {
				*err_code = FDGC_CBOR_LOW_LEVEL_ERROR;
			}
		}
		QCBORDecode_GetInt64InMapN(&DecodeCtx, 1, &(*pass).sign_header.alg);
	QCBORDecode_ExitMap(&DecodeCtx);
	if ( ( QCBORDecode_GetError(&DecodeCtx) != QCBOR_SUCCESS ) || ( *err_code ) ) {
#ifdef FDGC_DEBUG
		printf("err dec sign header (%i)\n", QCBORDecode_GetError(&DecodeCtx));
#endif
		*err_code = FDGC_CBOR_LOW_LEVEL_ERROR;
		fdgc_free_info_pass(pass);
		return NULL;
	}

	// key
	pass->signature.ptr = calloc(1, high_level_strings[2].len);
	memcpy((void *)pass->signature.ptr, high_level_strings[2].ptr, high_level_strings[2].len);
	pass->signature.len = high_level_strings[2].len;

	return pass;
}

struct fdgc_info_pass *decode_pass(char *qr_code, int *err_code) {

	if ( (qr_code[0]!='H') || (qr_code[1]!='C') || (qr_code[2]!='1') || (qr_code[3]!=':') ) {
		*err_code = FDGC_QR_HEADER_VER;
		return NULL;
	}

        UsefulBufC *dec;
        dec = base45_decode(qr_code+4, err_code);
        if ( dec == NULL ) 
                return NULL;
     
        UsefulBufC dec2;
        char buf[4096];
        if ( ((char *)(*dec).ptr)[0] == 120 ) {
                uLongf dlen = 4096;
                int zerr = uncompress((Bytef *)buf, &dlen, (*dec).ptr, (*dec).len);
                if ( zerr != Z_OK ) {
			*err_code = FDGC_ZLIB_ERR;
			return NULL;
                }
                dec2.ptr = buf;
                dec2.len = dlen;
		free((void *)dec->ptr);
		free((void *)dec);
        } else {
                dec2.ptr = (*dec).ptr;
                dec2.len = (*dec).len;
        }
	
	return fdgc_decode_info_pass(dec2, err_code);
}

EC_KEY *get_pkey_de(fdgc_certificates *certs, int i, int *err_code) {
	BIO *bio;
	X509 *x509_cert;
	bio = BIO_new(BIO_s_mem());
	int res;
	res = BIO_write(bio, certs->certs[i].rawdata.ptr, certs->certs[i].rawdata.len);
	x509_cert = d2i_X509_bio(bio, NULL);
	if ( x509_cert == NULL ) {
		*err_code = FDGC_SIGN_INVALID_KEY;
		BIO_free_all(bio);
		return NULL;
	}
	EVP_PKEY *evp_key = X509_get_pubkey(x509_cert);
	if ( evp_key == NULL ) {
		*err_code = FDGC_SIGN_INVALID_KEY;
		BIO_free_all(bio);
		X509_free(x509_cert);
		return NULL;
	}
	EC_KEY *key = EVP_PKEY_get1_EC_KEY(evp_key);
	if (!key) {
		*err_code = FDGC_SIGN_INVALID_KEY;
		BIO_free_all(bio);
		X509_free(x509_cert);
		return NULL;
	}
	EVP_PKEY_free(evp_key);
	BIO_free_all(bio);
	X509_free(x509_cert);
	return key;
}

RSA *get_rsa_de(fdgc_certificates *certs, int i, int *err_code) {
	BIO *bio;
        X509 *x509_cert;
        bio = BIO_new(BIO_s_mem());
        int res;
        res = BIO_write(bio, certs->certs[i].rawdata.ptr, certs->certs[i].rawdata.len);
        x509_cert = d2i_X509_bio(bio, NULL);
        if ( x509_cert == NULL ) {
                *err_code = FDGC_SIGN_INVALID_KEY;
                BIO_free_all(bio);
                return NULL;
        }
        EVP_PKEY *evp_key = X509_get_pubkey(x509_cert);
        if ( evp_key == NULL ) {
                *err_code = FDGC_SIGN_INVALID_KEY;
                BIO_free_all(bio);
                X509_free(x509_cert);
                return NULL;
        }
	RSA *rsa = EVP_PKEY_get1_RSA(evp_key);
	if (!rsa) {
                *err_code = FDGC_SIGN_INVALID_KEY;
                BIO_free_all(bio);
                X509_free(x509_cert);
                return NULL;
        }
        EVP_PKEY_free(evp_key);
        BIO_free_all(bio);
        X509_free(x509_cert);
        return rsa;
}


int check_signature(struct fdgc_info_pass *pass, fdgc_certificates *certs, int *err_code) {
	for (int i=0;i<certs->len;i++ ) {
		if ( memcmp(certs->certs[i].kid, pass->sign_header.kid, 8) == 0 ) {
#ifdef FDGC_DEBUG
			printf("kid trouve : %i\n", i);
#endif
			if ( pass->sign_header.alg == -7 ) { //ECDSA
#ifdef FDGC_DEBUG
				FILE *f = fopen("/tmp/cert.der", "w");
				fwrite(certs->certs[i].rawdata.ptr, certs->certs[i].rawdata.len, 1, f);
				fclose(f);
#endif
				int res;
#ifdef FDGC_DEBUG
				printf("Algo ECDSA\n");
#endif
				EC_KEY *key = get_pkey_de(certs, i, err_code);
				if (!key) 
					continue;

				unsigned char digest[EVP_MAX_MD_SIZE];
				unsigned int digest_len = sizeof(digest);
				res = EVP_Digest((void *)pass->payload.ptr, pass->payload.len, digest, &digest_len, EVP_sha256(), NULL);
				if ( ! res ) {
					*err_code = FDGC_SIGN_DIGEST_ERR;
					EC_KEY_free(key);
					continue;
				}

				BIGNUM *r, *s;
				r = BN_bin2bn(pass->signature.ptr, pass->signature.len/2, NULL);
				if ( !r ) {
					*err_code = FDGC_SIGN_BN_ERR;
					EC_KEY_free(key);
					continue;
				}
				s = BN_bin2bn(pass->signature.ptr+pass->signature.len/2, pass->signature.len/2, NULL);
				if ( !s ) {
					*err_code = FDGC_SIGN_BN_ERR;
					EC_KEY_free(key);
					continue;
				}

				ECDSA_SIG *sig = ECDSA_SIG_new();
				res = ECDSA_SIG_set0(sig, r, s);
				if ( ! res ) {
					*err_code = FDGC_SIGN_SIG;
					EC_KEY_free(key);
					continue;
				}

				res = ECDSA_do_verify(digest, digest_len, sig, key);
				//res = ECDSA_verify(0, digest, digest_len, pass->signature.ptr, pass->signature.len, key);
#ifdef FDGC_DEBUG
				printf("res : %i\n", res);
				if (res == 1)
					printf("crypto verifiee : ok !\n");
				if ( res == -1 )
					ERR_print_errors_fp(stdout);
#endif

				ECDSA_SIG_free(sig);
				EC_KEY_free(key);
				if ( res == 1 )
					return true;
			} else if ( pass->sign_header.alg == -37 ) { // RSASSA-PSS
#ifdef FDGC_DEBUG
				printf("RSA\n");
				                                FILE *f = fopen("/tmp/cert.der", "w");
                                fwrite(certs->certs[i].rawdata.ptr, certs->certs[i].rawdata.len, 1, f);
                                fclose(f);
#endif

				int res;
				RSA *rsa = get_rsa_de(certs, i, err_code);
#ifdef FDGC_DEBUG
				RSA_print_fp(stdout, rsa, 0);
#endif

				unsigned char digest[EVP_MAX_MD_SIZE];
				unsigned int digest_len = sizeof(digest);
				res = EVP_Digest((void *)pass->payload.ptr, pass->payload.len, digest, &digest_len, EVP_sha256(), NULL);
				if ( ! res ) {
					*err_code = FDGC_SIGN_DIGEST_ERR;
					RSA_free(rsa);
					continue;
				}

				int em_len = RSA_size(rsa);
				char *em = calloc(1, em_len);

				res = RSA_public_decrypt(pass->signature.len, pass->signature.ptr, em, rsa, RSA_NO_PADDING);
				if ( res != em_len ) {
					*err_code = FDGC_SIGN_SIG;
					RSA_free(rsa);
					continue;
				}

				res = RSA_verify_PKCS1_PSS(rsa, digest, EVP_sha256(), em, -1);
				RSA_free(rsa);
				if ( res == 1 )
					return true;

			} else {
				*err_code = FDGC_SIGN_INVALID_ALG;
				return false;
			}
		}
	}
	if (!*err_code)
		*err_code = FDGC_SIGN_NOKEY_FOUND;
	return false;
}


struct fdgc_info_pass *fdgc_get_pass_string(struct fdgc_context *plib, char *qr_code, int *err_code) {
	struct fdgc_info_pass *res = decode_pass(qr_code, err_code);
	if (!res)
		return NULL;
	if ( res->exp < time(NULL) ) {
		*err_code = FDGC_EXPIRED;
		fdgc_free_info_pass(res);
		return NULL;
	}
	if (!check_signature(res, plib->certs, err_code)) {
		fdgc_free_info_pass(res);
		return NULL;
	}
	return res;
}


int check_vaccine(struct fdgc_info_pass *pass, int min_days) {
	struct tm tm;
	memset(&tm, 0, sizeof(tm));
	if ( strptime(pass->cat.v.dt, "%Y-%m-%d", &tm) == NULL )
		return 0;
	if ( (strcmp(pass->cat.v.mp, "EU/1/20/1528")!=0) && (strcmp(pass->cat.v.mp, "EU/1/20/1507")!=0) && (strcmp(pass->cat.v.mp, "EU/1/21/1529")!=0) && (strcmp(pass->cat.v.mp, "EU/1/20/1525")!=0) )
		return 0;
	if ( ( strcmp(pass->cat.v.tg, "840539006") == 0 ) && ( pass->cat.v.dn == pass->cat.v.sd ) && ( time(NULL) - mktime(&tm) > min_days*24*60*60 ) ) 
		return 1;
	
	return 0;
}

int check_test(struct fdgc_info_pass *pass, int max_hours) {
	struct tm tm;
	memset(&tm, 0, sizeof(tm));
	if ( strptime(pass->cat.t.sc, "%Y-%m-%dT%H:%M:%S%z", &tm) == NULL )
		return 0;
	if ( ( strcmp(pass->cat.t.tg, "840539006") == 0 ) && ( strcmp(pass->cat.t.tr, "260415000")==0 ) && ( time(NULL) - mktime(&tm) < max_hours*60*60 ) )
		return 1;
	return 0;
}

int check_recovery(struct fdgc_info_pass *pass, int max_days) {
	struct tm tmmin, tmmax, tmtest;
	memset(&tmmin, 0, sizeof(tmmin));
	memset(&tmmax, 0, sizeof(tmmax));
	memset(&tmtest, 0, sizeof(tmtest));
	if ( ( strptime(pass->cat.r.df, "%Y-%m-%d", &tmmin) == NULL ) || ( strptime(pass->cat.r.du, "%Y-%m-%d", &tmmax) == NULL ) || ( strptime(pass->cat.r.fr, "%Y-%m-%d", &tmtest) == NULL ) )
		return 0;
	if ( ( strcmp(pass->cat.r.tg, "840539006") == 0 ) && ( mktime(&tmmin) < time(NULL) ) && ( mktime(&tmmax) > time(NULL) ) && ( mktime(&tmtest) + max_days*24*60*60 > time(NULL) ) ) 
		return 1;
	return 0;
}
	

int fdgc_valid_pass_eu(struct fdgc_info_pass *pass) {	//last dose + 14 days OR tests < 48h OR recovery < 6 months
	if (!pass)
		return 0;
	if ( pass->cat_type == FDGC_CAT_V ) {
		return check_vaccine(pass, 14);
	} else if ( pass->cat_type == FDGC_CAT_T ) {
		return check_test(pass, 48);
	} else if ( pass->cat_type == FDGC_CAT_R ) {
		return check_recovery(pass, 182);
	} else {
		return 0;
	}
}

int fdgc_valid_pass_fr(struct fdgc_info_pass *pass) { //last dose + 7 days OR tests < 72h OR recovery < 6 months
	if (!pass)
		return 0;
	if ( pass->cat_type == FDGC_CAT_V ) {
		return check_vaccine(pass, 7);
	} else if ( pass->cat_type == FDGC_CAT_T ) {
		return check_test(pass, 72);
	} else if ( pass->cat_type == FDGC_CAT_R ) {
		return check_recovery(pass, 182);
	} else {
		return 0;
	}
}


#ifdef ZBAR_SUPPORT
struct fdgc_info_pass *fdgc_get_pass_img(struct fdgc_context *plib, char *filename, int *err_code) {

/*	zbar_processor_t *processor=zbar_processor_create(0);
	if (zbar_processor_init(processor, NULL, 0))
		return NULL;
*/
/*	MagickWand *magickimg = NewMagickWand();
	printf("yo\n");
	if (!MagickReadImage(magickimg, filename)) {
//		zbar_process_destroy(processor);
		*err_code=FDGC_ZBAR_MAGICK;
		return NULL;
	}
	zbar_image_t *zimage = zbar_image_create();
	zbar_image_set_format(zimage, zbar_fourcc('Y','8','0','0'));
	int width = MagickGetImageWidth(magickimg);
        int height = MagickGetImageHeight(magickimg);
        zbar_image_set_size(zimage, width, height);
	
	size_t bloblen = width * height;
        unsigned char *blob = malloc(bloblen*4);
        zbar_image_set_data(zimage, blob, bloblen, zbar_image_free_data);
	printf("yo2\n");

        if(!MagickGetImagePixels(magickimg, 0, 0, width, height, "I", CharPixel, blob)) {
//		zbar_process_destroy(processor);
		zbar_image_destroy(zimage);
		DestroyMagickWand(magickimg);
		return NULL;
	}

	printf("yo3\n");
	zbar_processor_t *processor = zbar_processor_create(0);
	zbar_processor_init(processor, NULL, 0);
	zbar_process_image(processor, zimage);
	printf("yo4\n");

	const zbar_symbol_t *sym = zbar_image_first_symbol(zimage);
	printf("yo5\n");
	for(; sym; sym = zbar_symbol_next(sym)) {
		printf("yo7\n");
		zbar_symbol_type_t typ = zbar_symbol_get_type(sym);
		 printf("yo6\n");
	        if(typ == ZBAR_PARTIAL)
                	continue;
		char *qr_code = calloc(1, zbar_symbol_get_data_length(sym));
		memcpy(qr_code, zbar_symbol_get_data(sym), zbar_symbol_get_data_length(sym));
		printf("qr : %s\n", qr_code);
	}

	free(blob);
	zbar_image_destroy(zimage);
	DestroyMagickWand(magickimg);
	zbar_processor_destroy(processor);
	return NULL;*/

	zbar_image_scanner_t *scanner = NULL;
	FILE *file = fopen(filename, "rb");
	if (!file) {
		*err_code = FDGC_ZBAR_FILE_ERR;
		return NULL;
	}

	png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	setjmp(png_jmpbuf(png));
	png_infop info = png_create_info_struct(png);
	if (!info) {
		*err_code = FDGC_ZBAR_PNG_ERR;
		free(png);
		fclose(file);
		return NULL;
	}
	png_init_io(png, file);
	    png_read_info(png, info);
    /* configure for 8bpp grayscale input */
	int color = png_get_color_type(png, info);
	int bits = png_get_bit_depth(png, info);
	if(color & PNG_COLOR_TYPE_PALETTE)
	    png_set_palette_to_rgb(png);
	if(color == PNG_COLOR_TYPE_GRAY && bits < 8)
	    png_set_expand_gray_1_2_4_to_8(png);
	if(bits == 16)
	    png_set_strip_16(png);
	if(color & PNG_COLOR_MASK_ALPHA)
	    png_set_strip_alpha(png);
	if(color & PNG_COLOR_MASK_COLOR)
	    png_set_rgb_to_gray_fixed(png, 1, -1, -1);
	    /* allocate image */
	int width = png_get_image_width(png, info);
	int height = png_get_image_height(png, info);
	void *raw = malloc(width * height);
    	png_bytep rows[height];
    	int i;
    	for(i = 0; i < height; i++)
        	rows[i] = raw + (width * i);
    	png_read_image(png, rows);
	fclose(file);

	scanner = zbar_image_scanner_create();
	zbar_image_scanner_set_config(scanner, 0, ZBAR_CFG_ENABLE, 1);
	zbar_image_t *image = zbar_image_create();
	zbar_image_set_format(image, zbar_fourcc('Y','8','0','0'));
	zbar_image_set_size(image, width, height);
	zbar_image_set_data(image, raw, width * height, zbar_image_free_data);
	int n = zbar_scan_image(scanner, image);

	struct info_pass *res = NULL;

	const zbar_symbol_t *symbol = zbar_image_first_symbol(image);
	    for(; symbol; symbol = zbar_symbol_next(symbol)) {
        /* do something useful with results */
	        zbar_symbol_type_t typ = zbar_symbol_get_type(symbol);
	        const char *data = zbar_symbol_get_data(symbol);
		if ( typ == ZBAR_QRCODE ) 
			res = get_pass_string(plib, (char *)data, err_code);
//	        printf("decoded %s symbol \"%s\"\n",
//	               zbar_get_symbol_name(typ), data);
	    }

    /* clean up */
	zbar_image_destroy(image);
    	zbar_image_scanner_destroy(scanner);
	png_destroy_read_struct(&png, &info, NULL);

	if ( (!res) && (*err_code) )
		*err_code = FDGC_ZBAR_NO_QR;
    	return res;

}
#endif

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    /* out of memory! */
    return 0;
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

fdgc_certificates *update_certs_online(char *url, char *certs_file, int *err_code) {
	CURL *curl=curl_easy_init();
	if (!curl) {
		*err_code = FDGC_CURL_INIT_ERR;
		return NULL;
	}

	CURLcode res;
	struct MemoryStruct chunk;
	chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
	chunk.size = 0;    /* no data at this point */
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	if (res != CURLE_OK) {
		*err_code = FDGC_CURL_FETCH_ERR;
		free(chunk.memory);
		return NULL;
	}

	chunk.memory = realloc(chunk.memory, chunk.size+1);
	chunk.memory[chunk.size]=0;
	chunk.size++;

	char *sign, *core, *ptr;
	sign = chunk.memory;
	ptr = strchr(chunk.memory, '\n');
	if (!ptr) {
		*err_code = FDGC_CURL_FETCH_ERR;
		free(chunk.memory);
		return NULL;
	}
	*ptr=0;
	core = ptr+1;

	//TODO verif signature

	fdgc_certificates *rescert = parse_certificates_json(core, err_code);
	if (!rescert) {
		*err_code = FDGC_CURL_FETCH_ERR;
		free(chunk.memory);
		return NULL;
	}

	if ( certs_file ) {
		FILE *f = fopen(certs_file, "w");
		if (f) {					//Not writing to the cache isn't an error
			fwrite(core, strlen(core), 1, f);
			fclose(f);
		}
	}

	free(chunk.memory);

	return rescert;
}

int fdgc_init_pass_lib(struct fdgc_context *plib, char *certs_file, char *certs_url, int *err_code) {
	curl_global_init(CURL_GLOBAL_ALL);
	plib->certs_file = certs_file;
	fdgc_certificates *certs_cache = NULL;
	time_t certs_cache_last_update;
	if ( certs_file ) {
		struct stat st_file;
		if ( stat(certs_file, &st_file) == 0 ) {
			char *file_content = malloc(st_file.st_size+1);
			FILE *f = fopen(certs_file, "r");
			if ( fgets(file_content, st_file.st_size+1, f) ) {
				certs_cache = parse_certificates_json(file_content, err_code);
				certs_cache_last_update = st_file.st_mtime;
			}
			fclose(f);
			free(file_content);
		}
	}

	if (certs_url)
		plib->certs_url = strdup(certs_url);
	else
		plib->certs_url = strdup("https://de.dscg.ubirch.com/trustList/DSC/");
	plib->certs = update_certs_online(plib->certs_url, certs_file, err_code);
	plib->certs_last_update = time(NULL);

	if ( plib->certs ) {
		if ( certs_cache ) {
			destroy_certificates(certs_cache);
			free(certs_cache);
		}
	} else if ( certs_cache ) {
		plib->certs = certs_cache;
		plib->certs_last_update = certs_cache_last_update;		
	} else {
		*err_code = FDGC_NO_CERTS;
		return 0;
	}

	return 1;
}

void fdgc_free_pass_lib(struct fdgc_context *plib) {
	destroy_certificates(plib->certs);
	free(plib->certs_url);
	free(plib->certs);
}	


