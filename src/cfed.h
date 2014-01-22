/* cfed.h
 *
 * Hlavičky funkcí dostupných skrze API.
 * Definice nových datových typů.*/

#ifndef _CFED_H
#define _CFED_H

#define _GNU_SOURCE //vasprintf soucasti GNU rozsireni
#include <stdio.h>
#include <curl/curl.h> //kvuli drzeni curl_handle v contextu

/* vsechny vytvove typy maji jako 1. a posledni clen zarazku
 * pro jednoduche prochazeni, cleny _START lze take pouzit
 * jako inicializacni hodnoty*/

//idp authentication type
typedef enum cfed_e_authn_type {
    CFED_AUTHN_TYPE_START		= 0, //zarazka, jednoduche prochazeni
    CFED_AUTHN_TYPE_BASIC		= 1,  
    CFED_AUTHN_TYPE_X509		= 2,
    CFED_AUTHN_TYPE_FORMPASS		= 3,
    CFED_AUTHN_TYPE_END			= 4, // zarazka, inicialni hodnota
} cfed_e_authn_type_t;

//idp authentication type
typedef enum cfed_e_idp_type {
    CFED_IDP_TYPE_START			= 0, //zarazka
    CFED_IDP_TYPE_STANDARD           	= 1,
    CFED_IDP_TYPE_EXTENDED            	= 2,
    CFED_IDP_TYPE_END			= 3, // zarazka
} cfed_e_idp_type_t;

//idp authentication attributes
typedef enum cfed_e_authn_attrs {
    CFED_AUTHN_ATTR_START		= 0, //zarazka
    CFED_AUTHN_ATTR_UNAME           	= 1,
    CFED_AUTHN_ATTR_PASSWORD        	= 2,
    CFED_AUTHN_ATTR_END			= 3, //zarazka
} cfed_e_authn_attrs_t;

//atributes for idps and sps
typedef struct cfed_s_idp_attr {
    cfed_e_authn_attrs_t authn_attr;
    char *value;
} cfed_s_idp_attr_t;

/* hodnoty key z retezce key = "value" na radku konfiguracniho souboru */
typedef enum cfed_e_idp_key {
CFED_INIT_START                 = 0, //zarazka
CFED_INIT_NAME                  = 1,
CFED_INIT_URL                   = 2,
CFED_INIT_AUTHN_TYPE            = 3,
CFED_INIT_IDP_TYPE              = 4,
CFED_INIT_UNAME                 = 5,
CFED_INIT_PASSWORD              = 6,
CFED_INIT_END                   = 7, //zarazka
} cfed_e_idp_key_t;


/* konfigurace idp */
typedef struct cfed_s_idpconf {
        char *entity_id;          // jednoznacny popis idp... jako je na wayf -- "urn:mace:cesnet.cz:cztestfed:mnul.cz" 
        char *url;             
        cfed_e_authn_type_t *authn_type;         // autentizace basic,X509... seznam authn typu, ktere idp podporuje
        cfed_e_idp_type_t idp_type;         // standard, extended...
	cfed_s_idp_attr_t  **attrs;  		/* NULL-terminated list of attr */
} cfed_s_idpconf_t;

/* to same, ale pro SP */
typedef struct cfed_s_spconf {
	char *entity_id;
	char *url;
        cfed_s_idp_attr_t **attrs;  /* NULL-terminated list of attr */
} cfed_s_spconf_t;

typedef struct cfed_s_idpspconf_t {
	cfed_s_spconf_t **sps;
	cfed_s_idpconf_t **idps;
} cfed_s_idpspconf_t;

typedef struct cfed_s_result {
    char *raw;
    char *assertions;
    int authn_status;
} cfed_s_result_t;

typedef struct cfed_s_context {
	cfed_s_idpspconf_t *conf;
	char *error;
	CURL *curl_handle;
	cfed_s_result_t *result;	
/*	struct curl_slist *p_curlsl; // ukazatel na strukturu, do ktere libcurl dokaze ulozit info z hlavicek http, v nasem pripade cookies.
asi k nicemu curl se stara o cookies sam*/
} cfed_s_context_t;

/* struktura pro klíč z konf. souboru a funkci, která ho zpracovává */
typedef struct cfed_init_s_idp_command {
        cfed_e_idp_key_t idp_key;
	int (*handler) (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value);
} cfed_init_s_idp_command_t;

/* uzivatelovy authn. attributy + NULL-terminated list of authn_type methods */
typedef struct cfed_s_user_attrs {
	cfed_e_authn_type_t **authn_type;
	cfed_s_idp_attr_t **user_creds;
} cfed_s_user_attrs_t;

typedef struct cfed_s_authn_command {
	cfed_e_authn_type_t authn_type;
	int (*handler) (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, cfed_s_user_attrs_t *p_user_attrs,const char *next_url);
} cfed_s_authn_command_t;

/*  Inicializuje strukturu p_ctx hodnotami z conf_file_name,
 *  take provede inicializaci CURLu z curl_handle. Pri uspechu vraci 0, 
 *  jinak cele zaporne cislo n a nastavi chybovou zpravu do p_ctx->error.
 *  Uspesna inicializace CFED je nutna podminka pro beh programu. V pripade
 *  neuspesneho provedeni inicializace je doporuceno nepokracovat v 
 *  pouzivani knihovny */
int cfed_init (cfed_s_context_t *p_ctx, const char *conf_file_name);

/* cele kolecko SP-WAYF-IDP-SP */
int cfed_whole_round(cfed_s_context_t *p_ctx, const char *idpid, const char *spurl, cfed_s_user_attrs_t *p_user_attrs);

/*Na teto funkci lze demonstrovat realne pouziti knihovny pro prihlaseni do
 * federace identit (cfed_whole_round). Funkce se pomoci uzivatelsky autenti-
 * zacnich udaju z p_user_attrs prihlasi do federace eduID.cz ve ktere je
 * SP mizar, pomoci sveho IdP se jmenem idpid. Po prihlaseni do federace
 * posle SP svuj verejny klic a ziska zpet certifikat verejneho klice podepsany
 * SP. Certifikat ulozi do cert_file_name. Pr_key_file je pouze pripraveno
 * pro pozdejsi rozsireni funkce s vlastnim generovanim klice*/
int cfed_get_new_cert(cfed_s_context_t *p_ctx, const char *idpid, cfed_s_user_attrs_t *p_user_attrs, const char *cert_file_name, const char *pr_key_file);

/* vytahnuta funkcionalita ze cfed_whole_round 
 * simuluj presmerovani z WAYF na IdP a pokus se autentizovat uzivatele
 * zadanymi udaji. Je treba alespon 1 predtim projit cele kolecko pro 
 * daneho Idp */
int cfed_authn_only(cfed_s_context_t *p_ctx, const char *idpid, cfed_s_user_attrs_t *p_user_attrs);

/* vycisti po sobe */
void cfed_cleanup(cfed_s_context_t *p_ctx);

/* Do retezce err_msg ulozi popis chyby err_descr
 * v nasi impl. volat pro (&p_ctx->error, ...).
 * Pro prazdny err_descr pouzivat "".
 * Pri uspesnem provedeni bude err_msg dyn. alokovana pamet s 
 * puvodnim retezcem v *err_msg a err_descr oddelene strednikem.
 * Pri neuspechu ponecha puvodni err_msg (NULL pokud zadny nebyl)*/
void cfed_make_err_msg ( char **err_msg, const char *err_format, ...);

/* zkontroluje zda *p_mem drzi hodnotu NULL, pokud ne vola free(&)
 * a nastavi *p_mem na NULL*/
void cfed_free(cfed_s_context_t *p_ctx,void *p_mem);

void *cfed_malloc(cfed_s_context_t *p_ctx, size_t size);

#endif
