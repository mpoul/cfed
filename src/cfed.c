/* cfed.c
 *
 * základní soubor s definicemi funkcí knihovny*/

#include "cfed.h"
#include <string.h>
#include <stdarg.h>
#include <ctype.h>  //isspace()
#include <stdlib.h>  //realloc()
#include<unistd.h>
#include <curl/curl.h>
#include "cfed_spkigen.h"

/* Pro vypsani tajneho klice do souboru */
#define PEM_write_SPKI(fp,x) \
        PEM_ASN1_write((int (*)())i2d_NETSCAPE_SPKI,"SPKI",fp,\
                        (char *)x,NULL,NULL,0,NULL,NULL)
/**************************************************************************
 * prenos 
 *************************************************************************/
static char to_hex(char code);
static int cfed_call_sp(cfed_s_context_t *p_ctx,const char *next_url);
static int cfed_respond_wayf(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, char **next_url);
static int cfed_respond_idp_pwd(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, cfed_s_user_attrs_t *p_user_attrs, const char *next_url);
static int cfed_perform_authn(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, cfed_s_user_attrs_t *p_user_attrs,const char *next_url);
static int cfed_send_saml(cfed_s_context_t *p_ctx);

static int cfed_check_response_code(cfed_s_context_t *p_ctx, const long check_code);
static char *cfed_get_last_url(cfed_s_context_t *p_ctx);

static int cfed_get_form_creds (cfed_s_context_t *p_ctx, cfed_s_idp_attr_t  **p_attrs, const cfed_e_authn_attrs_t demand, char **retval);
static int cfed_set_sp_id(cfed_s_context_t *p_ctx,cfed_s_spconf_t *new_sp,const char *entity_id);
static int cfed_set_sp_url(cfed_s_context_t *p_ctx,cfed_s_spconf_t *new_sp,const char *url);
static cfed_s_spconf_t *cfed_new_sp(cfed_s_context_t *p_ctx);

static int cfed_set_authn_status(cfed_s_context_t *p_ctx);
static char * cfed_make_cert_request(cfed_s_context_t *p_ctx,const char *source);
static char *cfed_get_pub_key(cfed_s_context_t *p_ctx,FILE *tempfile);
/**************************************************************************
 *     base64 decoding 
 *************************************************************************/
static char *cfed_base64_decode(cfed_s_context_t *p_ctx, const char *src);
static char value(char c);
/**************************************************************************
 * * CALLBACK FUNKCE PRO PARSOVANI HTTP HLAVICEK A HTML STRANEK Z CURLU
 * ***************************************************************************/
static size_t cfed_clb_write(void *ptr, size_t size, size_t nmemb, void *stream);
static size_t cfed_clb_no_write(void *ptr, size_t size, size_t nmemb, void *stream);
static size_t cfed_clb_fnd_loc(void *ptr, size_t size, size_t nmemb, void *stream);
static size_t cfed_clb_get_response(void *ptr, size_t size, size_t nmemb, void *string);
/**************************************************************************
 *     URL-encoding 
 *************************************************************************/
static char to_hex(char code);
static char from_hex(char code);
static char *cfed_url_encode(cfed_s_context_t *p_ctx,const char *str);
static char *cfed_url_decode(cfed_s_context_t *p_ctx, char *str); 
/**************************************************************************
 * extrakce informaci target ze source formulare 
 *************************************************************************/
static char *cfed_extract_action (cfed_s_context_t *p_ctx,const char *source);
static char * cfed_extract_form_value (cfed_s_context_t *p_ctx, const char *source, const char *pattern);
/**************************************************************************
 * ziskej z kontextu hledanou entitu 
 *************************************************************************/
static cfed_s_idpconf_t *cfed_get_idp_struct (cfed_s_context_t *p_ctx, const char *idpid); 
static cfed_s_spconf_t *cfed_get_sp_struct (cfed_s_context_t *p_ctx, const char *spid); 
static cfed_s_spconf_t *cfed_get_sp_by_url (cfed_s_context_t *p_ctx, const char *spurl); 
/**************************************************************************
 * autentizace uzivatele u IdP 
 *************************************************************************/
static int cfed_find_idp_authn (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, cfed_e_authn_type_t to_find);
static cfed_s_authn_command_t *cfed_find_authn_command(cfed_s_context_t *p_ctx, cfed_e_authn_type_t *code);
/***************************************************************************/
#define KEY_FILE_LEN 200 //maximalni delka nacteneho radku ze souboru s klicem

/* Tabulka pro typ autentizace a prislusnou funkci, ktera se 
 * postara o komunikaci s idp pomoci daneho typu authn.
 * V teto je implementovano jen pro typ formpass, ostatni se
 * vyuzivaji zridka nebo vubec. Pro pozdejsi pridani novych typu
 * autentizace do knihovny, je nutne pouze vytvorit novou funkci pro
 * prislusny typ a dopnit ji do teto tabulky spolu s pridanim 
 * noveho typu autentizace do vyctoveho typu cfed_e_authn_type_t v 
 * hlavickovem souboru */
static cfed_s_authn_command_t commands[] = {
{ CFED_AUTHN_TYPE_FORMPASS, cfed_respond_idp_pwd, },
//{ CFED_AUTHN_TYPE_BASIC, cfed_respond_idp_bsc, },
//{ CFED_AUTHN_TYPE_X509, cfed_respond_idp_x509, },
{ 0, NULL },
};

/**************************************************************************
 *     DEFINICE 
 *************************************************************************/
	
/* v tabulce commands vyhledej podle code prislusnou strukturu authn_command a vrat ukazatel na ni*/
static cfed_s_authn_command_t *cfed_find_authn_command(cfed_s_context_t *p_ctx, cfed_e_authn_type_t *code)
{
	if (p_ctx == NULL)
		return NULL; 

	cfed_s_authn_command_t *c;
	for (c = commands; c->authn_type; c++) 
	{
		if (c->authn_type == (*code))
		return c;
	}

	cfed_make_err_msg (&(p_ctx->error), "cfed_find_authn_command: nelze nalezt prikaz pro zadany typ autenzizace");
	return NULL;
}

/**************************************************************************
 * Whole round - SP-wayf-IdP-SP
 * ***********************************************************************/
int cfed_whole_round (cfed_s_context_t *p_ctx, const char *idpid, const char *spurl, cfed_s_user_attrs_t *p_user_attrs)
{	
	if (p_ctx == NULL)
		return -1; 
	
	
	/* idp se kterym se prave pracuje */ 
	cfed_s_idpconf_t *current_idp = NULL;

	/* zkontroluj, zda existuje struktura cfed_s_idpconf,
 	*  ktera ma entity_id == idpid */
	current_idp = cfed_get_idp_struct(p_ctx, idpid);
	if (current_idp == NULL)
		goto error_out;

	if (cfed_call_sp(p_ctx, spurl))
		goto error_out;

	long check_code = 200;
	/*zkontroluj posledni navracenou hlavicku, pro neplatny kod ukonci kolo*/
	if (cfed_check_response_code(p_ctx,check_code))
		goto error_out;

	char *last_url = cfed_get_last_url(p_ctx);
	/*jestlize nedoslo k presmerovani a navratovy kod byl 200, pak muzu ke sluzbe
 	* pristoupit primo bez autentizace*/
	if (!strcmp(last_url, spurl))
		return 0;	
	
	if (cfed_respond_wayf(p_ctx, current_idp, &last_url))
		goto error_out;
	if (cfed_check_response_code(p_ctx, check_code))
		goto error_out;

	/*vytvor noveho SP*/
	cfed_s_spconf_t *new_sp = cfed_new_sp(p_ctx);
	if (new_sp == NULL)
		goto error_out;

	cfed_set_sp_id(p_ctx,new_sp, spurl);
	/* last_url je nyni adresa pro url, kterou bude mozne pozdeji vyuzit
 	* k simulaci chovani celeho kolecka pouze za ucelem kontoli autentizacnich
 	* atributu uzivate*/
	cfed_set_sp_url(p_ctx, new_sp, last_url);
	
	/* vytahni od uzivatele, jakou formu authn chce
 	* podle toho pak zavolej prislusnou funkci z tabulky */
	cfed_free (p_ctx, last_url);
	last_url = cfed_get_last_url(p_ctx);
	if (cfed_perform_authn(p_ctx, current_idp, p_user_attrs,last_url))
		goto error_out;

	if (cfed_send_saml(p_ctx))
		goto error_out;
	if (cfed_check_response_code(p_ctx, check_code))
		goto error_out;

	return 0;
	
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_whole_round: Chyba pri komunikaci");
		return -1;
}
/* vytahni od uzivatele, jakou formu authn chce
 * podle toho pak zavolej prislusnou funkci z tabulky
 * a autentizuj se u IdP */
static int cfed_perform_authn(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *current_idp, cfed_s_user_attrs_t *p_user_attrs,const char *last_url)
{
	if (p_ctx == NULL)
		return -1; 

        int i=0;
        cfed_s_authn_command_t *p_authn_command = NULL;
        while (p_user_attrs->authn_type[i] != NULL)
        {
                /* podporuje IdP pozadovany typ autentizace? */
                if (cfed_find_idp_authn (p_ctx, current_idp, *p_user_attrs->authn_type[i]))
                        goto error_out;
                p_authn_command = cfed_find_authn_command(p_ctx, p_user_attrs->authn_type[i]);
                if (p_authn_command == NULL)
                        goto error_out;
                /*odpovez Idp*/
                if (p_authn_command->handler(p_ctx, current_idp, p_user_attrs, last_url))
                {
                        i++;
                        cfed_make_err_msg (&(p_ctx->error), "cfed_perform_authn: chyba prenosu pri autentizaci, zkousim dalsi authn typ");
                        continue;
                }
                /*mensi hack - mozna predelat*/
                if (strstr(p_ctx->result->raw, "SAMLResponse"))
                        break;
                cfed_make_err_msg (&(p_ctx->error), "cfed_perform_authn: autentizace u idp nebyla uspesna, zkousim dalsi authn typ");
                i++;
        }
	if (p_user_attrs->authn_type[i] == NULL)
		goto error_out;
	long check_code = 200;
	if (cfed_check_response_code(p_ctx, check_code))
		goto error_out;
	if (p_ctx->result->raw == NULL)
		goto error_out;

	p_ctx->result->authn_status = 1;
	return 0;	
	error_out:
	cfed_make_err_msg (&(p_ctx->error), "cfed_perform_authn: pro zadny typ autentizace nebyla autentizace uspesna");
	return -1;	
}
/* Zjisti, zda IdP podporuje zadany typ autentizace to_find. 0 nalezena podpora
 * , ostatni nenalezena */
static int cfed_find_idp_authn (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, cfed_e_authn_type_t to_find)
{
	if (p_ctx == NULL)
		return -1; 

	while (*p_idp->authn_type != CFED_AUTHN_TYPE_END)
	{
		if (*p_idp->authn_type == to_find)
			return 0;
		p_idp->authn_type++;
	}
	cfed_make_err_msg (&(p_ctx->error), "cfed_find_idp_authn: IdP nepodporuje zadany typ autentizace %d", to_find);
	return -1;	
}

/* vytvor novy seznam sps, zachovej stavajici struktury spconf*/
static cfed_s_spconf_t *cfed_new_sp(cfed_s_context_t *p_ctx)
{
	/*najdi aktualni pocet sp*/
	unsigned int no_sp = 0;
	int i = 0;				//iterace
	if (p_ctx->conf->sps  != NULL)
		while (p_ctx->conf->sps[i] != NULL)
			i++;
	no_sp = i;
	/* alokuj misto pro novy seznam SP (pointery) */
        p_ctx->conf->sps = (cfed_s_spconf_t **) realloc(p_ctx->conf->sps, (no_sp + 2)*sizeof(cfed_s_spconf_t*));
        if (p_ctx->conf->sps == NULL)
                goto error_out;

        p_ctx->conf->sps[no_sp + 1] = NULL;
	
	/* alokuj misto pro novy SP (struktura) */
	p_ctx->conf->sps[no_sp]= (cfed_s_spconf_t *) cfed_malloc(p_ctx,sizeof(cfed_s_spconf_t));
        if (p_ctx->conf->sps[no_sp] == NULL)
                goto error_out;

	
	/*nastav na inicialni hodnoty*/
	p_ctx->conf->sps[no_sp]->entity_id = NULL;
	p_ctx->conf->sps[no_sp]->url = NULL;
	p_ctx->conf->sps[no_sp]->attrs = NULL;

        return p_ctx->conf->sps[no_sp];	
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_new_sp: nepodarilo se vytvorit noveho sp");
		return NULL;
}

/* asi pujde parametrizovat */
/* do new_sp nastav atribut spurl */
static int cfed_set_sp_id(cfed_s_context_t *p_ctx,cfed_s_spconf_t *new_sp, const char *entity_id)
{
	if (p_ctx == NULL)
		return -1;
	if (new_sp == NULL || entity_id == NULL)
		goto error_out; 

	unsigned int entity_id_len = 0;
	entity_id_len = strlen (entity_id);
	new_sp->entity_id = (char *)cfed_malloc(p_ctx, (entity_id_len + 1) * sizeof(char));
	if (new_sp->entity_id == NULL)
		goto error_out;
	strncpy(new_sp->entity_id, entity_id, entity_id_len+1);
	new_sp->entity_id[entity_id_len] = '\0';
	
	return 0;
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_set_sp_id: Chyba pri nataveni entity_id");
		return -1;
}

static int cfed_set_sp_url(cfed_s_context_t *p_ctx, cfed_s_spconf_t *new_sp, const char *url)
{
	if (p_ctx == NULL)
		return -1;
	if (new_sp == NULL || url == NULL)
		goto error_out; 

	unsigned int url_len = 0;
	url_len = strlen (url);
	new_sp->url = (char *)cfed_malloc(p_ctx, (url_len + 1) * sizeof(char));
	if (new_sp->url == NULL)
		goto error_out;
	strncpy(new_sp->url, url, url_len+1);
	new_sp->url[url_len] = '\0';
	
	return 0;
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_set_sp_url: Chyba pri nataveni sp_url");
		return -1;
}

/**************************************************************************
 * Contaktuje SP, necha se presmerovat na WAYF, adresu WAYF ulozi do
 * next_url. Vraci 0 pro uspesny prenos, ostatni neuspech. Za uspech se 
 * povazuje uspesne provedeni vsech casti funkce, hlavne prenosu, at uz 
 * navratovy kod v http hlavicce z tohoto prenosu byl jakykoliv 
 * (200, 301...). Kontrolu kodu v http hlavickach provadi nadrazena funkce
 * cfed_whole_round()
 * ***********************************************************************/
static int cfed_call_sp (cfed_s_context_t *p_ctx,const char *next_url)
{
	if (p_ctx == NULL)
		return -1; 

	/*mel bych jeste vytvorit kontrolu, zda zadana vracena stranka
 * 	obsahuje idp_id*/

	/* set URL */
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_URL, next_url))
		goto error_out;

	/* assign wanted string to this pointer -- header parsing*/
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEHEADER, stdout))
		goto error_out;
		
	/* do idpsrch prirad  */
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEDATA, stdout))

	/* send all data to the this fction */
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEFUNCTION, cfed_clb_no_write ))
		goto error_out;

	/* send all http headers to this fction */
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_HEADERFUNCTION, cfed_clb_no_write))
		goto error_out;
	

	/* perform the transfer*/
	if (curl_easy_perform(p_ctx->curl_handle))
	{	
		cfed_make_err_msg (&(p_ctx->error), "cfed_contact_sp: prenos neprobehl v poradku");
		return -1;
	}
	
	return 0;
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_contact_sp: Chyba pri nataveni curl_easy_setopt");
		return -1;
}


/**************************************************************************
 * Odpovi WAYF serveru, posle mu udaje o IdP podle p_idp (entity_id).
 * Adresu presmerovani, kterou dostane po uspesnem prenosu ulozi do next_url.
 * ***********************************************************************/
static int cfed_respond_wayf (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, char **next_url)
{
	if (p_ctx == NULL)
		return -1; 

	/*cast pro volitelnou kontrolu atributu na strane idp
 * 	char *formattrs_srch;

	from_attrs_srch = (char *) cfed_malloc(p_ctx, (strlen(idpid) + 1) * sizeof (char));
	strncpy (p_idpsrch, idpid, strlen(idpid));*/

	/*********************************************************
 	* Kdyz se zmeni formular v tele html z wayf, tak to dal nefunguje
 	* Je treba mit aktualni form_key a jejich pocet.
 	* dodelat idpid kontrolu, ze je v prislusne strukture a ze 
 	* je pripadne i na wayf serveru
 	* *******************************************************/

	char * form_key1 = "user_idp";
	int str_to_send_len = 0;
	str_to_send_len = strlen(p_idp->entity_id) + strlen(form_key1) + 1; //delka idpid + klice + '='
	char str_to_send[str_to_send_len + 1];  // string pro odeslani na wayf
	str_to_send [str_to_send_len] = '\0';
	
	strcpy (str_to_send, form_key1);
	strcat (str_to_send, "=");
	strcat (str_to_send, p_idp->entity_id);
	

	/* set URL */
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_URL, *next_url))
		goto error_out;
	
	/*  http header parsing
 	*   dodelat najiti adresy Idp*/
	cfed_free(p_ctx, *next_url);
	*next_url = NULL;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEHEADER, next_url))
		goto error_out;

	/* html parsing
 	*  volitelne kontrola idp_attrs v tele html stranky */
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEDATA, stdout))
		goto error_out;

	/* send all data to the function cfed_clb_no_write */
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEFUNCTION, cfed_clb_no_write))
		goto error_out;

	/* send all http headers to the function cfed_clb_write*/
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_HEADERFUNCTION, cfed_clb_fnd_loc)) 
		goto error_out;

	
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_POSTFIELDS, str_to_send))
		goto error_out;

	/*********************************************************/

	/* perform the transfer*/
	if (curl_easy_perform(p_ctx->curl_handle))
	{	
		cfed_make_err_msg (&(p_ctx->error), "cfed_respond_wayf: prenos neprobehl v poradku");
		return -1;
	}
	
	/* Volitelne kontorla attr na strane Idp*/
	
	/* z predchoziho prenosu nelze vycist adresu na wayf server */
	if (!next_url)
		return -1;

	return 0;
		
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_respond_wayf: Chyba pri nataveni curl_easy_setopt");
		return -1;
}


/**************************************************************************
 * Na adresu Idp z next_url posle uzivatelske autentizacni udaje z 
 * p_user_attrs formou vyplneni html formulare. Polozky formulare ziska z
 * p_idp. Uspech prenosu zavisi na spravnem vyplneni struktury p_ipd, 
 * tedy konfiguracniho souboru. Pri uspesne autentizace ulozi ziskanou html
 * stranku do p_ctx->result->raw.
 * ***********************************************************************/
static int cfed_respond_idp_pwd (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, cfed_s_user_attrs_t *p_user_attrs,const char *next_url)
{
	if (p_ctx == NULL)
		return -1; 

	/* ziskej idp atribut CFED_AUTHN_ATTR_UNAME do uname_attr */
	char *uname_attr = NULL; //nutno free() na konci fce
	if (cfed_get_form_creds (p_ctx, p_idp->attrs, CFED_AUTHN_ATTR_UNAME,  &uname_attr))
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_respond_idp: nenalezen atribut pro form. autentizaci");
		return -1;
	}
	/* ziskej idp atribut CFED_AUTHN_ATTR_PASSWORD do password_attr */
	char *password_attr = NULL; //nutno free(&) na konci fce
	if (cfed_get_form_creds (p_ctx, p_idp->attrs, CFED_AUTHN_ATTR_PASSWORD, &password_attr))
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_respond_idp: nenalezen atribut pro form. autentizaci");
		return -1;
	}
	/* ziskej uzivatelovo jmeno */
	char *user_uname = NULL; //nutno free() na konci fce
	if (cfed_get_form_creds (p_ctx, p_user_attrs->user_creds ,CFED_AUTHN_ATTR_UNAME, &user_uname))
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_respond_idp: nenalezeno uzivatelske jmeno pro form. autentizaci");
		return -1;
	}
	/* ziskej uzivatelovo heslo */
	char *user_password = NULL; //nutno free() na konci fce
	if (cfed_get_form_creds (p_ctx, p_user_attrs->user_creds ,CFED_AUTHN_ATTR_PASSWORD, &user_password))
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_respond_idp: nenalezeno uzivatelske heslo pro form. autentizaci");
		return -1;
	}

	/* vytvor retezec s credentials pro odeslani na IDP */
	unsigned int str_to_send_len = strlen(uname_attr) + strlen(user_uname) + strlen(password_attr) + strlen(user_password) + 3;
	char str_to_send[str_to_send_len + 1];
	str_to_send [str_to_send_len] = '\0';
	strcpy(str_to_send, uname_attr);
	strcat(str_to_send, "=");
	strcat(str_to_send, user_uname);
	strcat(str_to_send, "&");
	strcat(str_to_send, password_attr);
	strcat(str_to_send, "=");
	strcat(str_to_send, user_password);

	cfed_free(p_ctx, uname_attr);
	cfed_free(p_ctx, password_attr);
	cfed_free(p_ctx, user_uname);
	cfed_free(p_ctx, user_password);

	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_POSTFIELDS, str_to_send))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_URL, next_url))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEHEADER, stdout))
		goto error_out;
	/*odpoved od IdP pri autentizaci do raw*/
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEDATA, &p_ctx->result->raw))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEFUNCTION, cfed_clb_get_response))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_HEADERFUNCTION, cfed_clb_no_write)) 
		goto error_out;

	/* perform the transfer*/
	if (curl_easy_perform(p_ctx->curl_handle))
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_respond_idp: prenost neprobehl v poradku");
		return -1;
	}
		
	return 0;
	
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_respond_idp: Chyba pri nastaveni curl_easy_setopt");
		return -1;
}

/**************************************************************************
 * p_ctx->result->raw je html stranka s predvyplnenym formularem. cfed_send_saml 
 * extrahuje nutne atributy formulare (hlavne SAMLResponse) a vytvori z nich
 * retezec, ktery metodou POST posle na adresu SP (ziskanou z p_ctx->result->raw 
 * atributu formulare ACTION).
 * ***********************************************************************/
static int cfed_send_saml (cfed_s_context_t *p_ctx)
{
	if (p_ctx == NULL)
		return -1; 
	
	char *action = cfed_extract_action(p_ctx, p_ctx->result->raw);
	char *saml = cfed_extract_form_value(p_ctx, p_ctx->result->raw, "SAMLResponse");	
	
	if (action == NULL || saml == NULL)
	{
		cfed_free(p_ctx, action);
		cfed_free(p_ctx, saml);
		cfed_make_err_msg (&(p_ctx->error), "cfed_send_saml: nelze vycist");
		return -1;
	}

	/*aserce od IdP*/ /*prvne dekodovat a pak ulozit aserce!!!!!!!!!!!!!!!!!!!!!!!!!!!!! nebo ne? rozmyslet, dodelat*/
	p_ctx->result->assertions = saml;
	/*nastav do result status autentizace z assertions*/
	cfed_set_authn_status(p_ctx);
		
	char *target = cfed_extract_form_value(p_ctx, p_ctx->result->raw, "TARGET");	
	char target_name [11] ="TARGET";
	if (target == NULL)
	{
		/* je mozne, ze nova verze shibbolethu pouziva misto "TARGET"
 		*  "RelayState". Zkus extrakci znovu*/
		target= cfed_extract_form_value(p_ctx, p_ctx->result->raw, "RelayState");
		strncpy(target_name, "RelayState", 11);	
	}
	if (target == NULL)
	{
		cfed_free(p_ctx, saml);
		cfed_make_err_msg (&(p_ctx->error), "cfed_send_saml: nelze vycist");
		return -1;
	}
	
	char *saml_name ="SAMLResponse";

	char *url_encoded_saml = NULL;
	url_encoded_saml = cfed_url_encode(p_ctx, saml);

	/* delky dilcich atributu pro odeslani*/
	unsigned int saml_len = 0;
	saml_len=strlen(url_encoded_saml) + strlen(saml_name);	
	unsigned int target_len = 0;
	target_len=strlen(target) + strlen(target_name);
	
	/* spocitej delku retezce pro odeslani*/
	unsigned int str_to_send_len = 0;
	int sep_len = 3;	// 2x'=',1x'&'
	str_to_send_len = saml_len + target_len + sep_len; 
	char str_to_send[str_to_send_len + 1];  // string pro odeslani na SP
	str_to_send [str_to_send_len] = '\0';

	/* vytvor retezec pro odeslani */	
	strcpy(str_to_send, saml_name);
	strcat(str_to_send, "=");
	strcat(str_to_send, url_encoded_saml);
	strcat(str_to_send, "&");
	strcat(str_to_send, target_name);
	strcat(str_to_send, "=");
	strcat(str_to_send, target);
	
	cfed_free(p_ctx, target);
	cfed_free(p_ctx, url_encoded_saml);
	
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_POSTFIELDS, str_to_send))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_URL, action))
		goto error_out;
	
	cfed_free(p_ctx, action);
	
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEHEADER, stdout))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEDATA, stdout))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEFUNCTION, cfed_clb_no_write))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_HEADERFUNCTION, cfed_clb_no_write)) 
		goto error_out;

		
	/* perform the transfer*/
	if (curl_easy_perform(p_ctx->curl_handle))
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_send_saml: prenost neprobehl v poradku");
		return -1;
	}
		
	return 0;
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_send_saml: Chyba pri nastaveni curl_easy_setopt");
		return -1;
}

/*jeste upravit*/
static int cfed_set_authn_status(cfed_s_context_t *p_ctx)
{
	if (p_ctx == NULL)
		return -1; 

	/*rozkoduj assertions a dostan z nej authn. status*/
	char *decoded_assertions = cfed_base64_decode(p_ctx, p_ctx->result->assertions);
	if (strstr(decoded_assertions, "Value=\"saml1p:Success\""));
		p_ctx->result->authn_status = 1;
	return 0;
}

/*projdi vsechny sp, pro ktere uz probehlo kolecko
* vyber prvniho, jehoz cast url je idpid
* a jeho url pouzij pro pristup k IdP a autentizuj se,
* vysledek uloz do result */
int cfed_authn_only(cfed_s_context_t *p_ctx, const char *idpid, cfed_s_user_attrs_t *p_user_attrs)
{
/* vygeneruj casove razitko a umisti ho dovnitrn URL pro
 	*  kontaktovani IdP*/
	char * str_to_send = NULL;

	if (p_ctx == NULL)
		return -1;

	//stare-nevim const char *idpid_url_encoded = cfed_url_encode(p_ctx, idpid);
	cfed_s_idpconf_t *current_idp = cfed_get_idp_struct(p_ctx, idpid);
	if (current_idp == NULL)
		goto error_out;

		
	/* z idpid vytahni jen cast po 3. '/'*/
	unsigned int pattern_trunc_len = 0;
        unsigned int no_slash = 0;
        const char *current_pattern = idpid;
        /* spocitej delku pattern po treti '/' */
        while (*current_pattern != '\0' && no_slash < 3)
        {
                pattern_trunc_len++;
                current_pattern++;
                if (*current_pattern == '/')
                        no_slash++;
        }
        char *pattern_trunc = (char*) cfed_malloc(p_ctx, (pattern_trunc_len + 1)* sizeof(char));
        if (pattern_trunc == NULL)
                goto error_out;
        strncpy(pattern_trunc,idpid, pattern_trunc_len);
        pattern_trunc[pattern_trunc_len] = '\0';

	char * shire = "/idp/profile/Shibboleth/SSO?shire=https%3A%2F%2Fmizar.ics.muni.cz%2FShibboleth.sso%2FSAML%2FPOST&time=";
	char * sp_simul = "&target=cookie%3Aa952b34f&providerId=https%3A%2F%2Fmizar.ics.muni.cz%2Fshibboleth%2Fcztestfed%2Fsp";	
	/* simuluj prichod od SP vytvorenim adresy s aktualnim razitkem */
	asprintf(&str_to_send, "%s%s%ld%s", pattern_trunc, shire, time(NULL), sp_simul);

	cfed_free(p_ctx, pattern_trunc);
	pattern_trunc = NULL;
	
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_URL,str_to_send)) 
		goto error_out;
	
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEHEADER, stdout))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEDATA, stdout))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEFUNCTION, cfed_clb_no_write))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_HEADERFUNCTION, cfed_clb_no_write)) 
		goto error_out;
	/* perform the transfer*/
	if (curl_easy_perform(p_ctx->curl_handle))
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_authn_only: prenost neprobehl v poradku");
		return -1;
	}	
	
//DYNAM if (cfed_perform_authn(p_ctx, current_idp, p_user_attrs,p_sp->url))
/*NAPEVNO*/
	/*ziskej posledni pouzitou url a posli tam authn. udaje uzivatele*/
	char *idp_url = cfed_get_last_url(p_ctx);
	if (idp_url == NULL)
		goto error_out;
	if (cfed_perform_authn(p_ctx, current_idp, p_user_attrs, idp_url))
		goto error_out;
	if (!p_ctx->result->authn_status)
		goto error_out;

	cfed_free(p_ctx,str_to_send);
	return 0;
	
	error_out:
		cfed_free(p_ctx,str_to_send);
		cfed_make_err_msg (&(p_ctx->error), "cfed_authn_only: autentizace neprobehla v poradku");
		return -1;
}

static cfed_s_spconf_t *cfed_get_sp_by_url (cfed_s_context_t *p_ctx, const char *pattern)
{
	if (p_ctx == NULL)
		return NULL;

	if (p_ctx->conf->sps == NULL)
		goto error_out;
	
	cfed_s_spconf_t **p_sp = p_ctx->conf->sps;
	/* patern a *p_sp->url zkrat na domeny nejvyssiho radu mezi '/' a porovnej */
	unsigned int pattern_trunc_len = 0;
	unsigned int no_slash = 0;
	const char *current_pattern = pattern;
	/* spocitej delku pattern po treti '/' */
	while (*current_pattern != '\0' && no_slash < 3)
	{
		pattern_trunc_len++;
		current_pattern++;
		if (*current_pattern == '/')
			no_slash++;
	}
	char *pattern_trunc = (char*) cfed_malloc(p_ctx, (pattern_trunc_len + 1)* sizeof(char));
	if (pattern_trunc == NULL)
		goto error_out;
	strncpy(pattern_trunc,pattern, pattern_trunc_len);
	pattern_trunc[pattern_trunc_len] = '\0';
	
	char *spurl_trunc = (char*) cfed_malloc(p_ctx, (pattern_trunc_len + 1)* sizeof(char));
	if (spurl_trunc == NULL)
	{
		cfed_free(p_ctx, pattern_trunc);
		goto error_out;
	}
	while (*p_sp != NULL)
	{
		strncpy(spurl_trunc, (*p_sp)->url, pattern_trunc_len);
		spurl_trunc[pattern_trunc_len] = '\0';
		if (!strcmp(pattern_trunc, spurl_trunc))
		{
			cfed_free(p_ctx, pattern_trunc);
			cfed_free(p_ctx, spurl_trunc);
			return *p_sp;
		}
		p_sp++;
	}
	cfed_free(p_ctx, pattern_trunc);
	cfed_free(p_ctx, spurl_trunc);
	error_out:
	cfed_make_err_msg (&(p_ctx->error), "cfed_get_sp_by_url: podle zadaneho vzorku \"%s\" nenalezen odpojidajici SP", pattern);
	return NULL;
}

/*Na teto funkci lze demonstrovat realne pouziti knihovny pro prihlaseni do
 * federace identit (cfed_whole_round). Funkce se pomoci uzivatelsky autenti-
 * zacnich udaju z p_user_attrs prihlasi do federace eduID.cz ve ktere je
 * SP mizar, pomoci sveho IdP se jmenem idpid. Po prihlaseni do federace
 *  posle SP svuj verejny klic a ziska zpet certifikat verejneho klice podepsany
 *  SP. Certifikat ulozi do cert_file_name */
int cfed_get_new_cert(cfed_s_context_t *p_ctx, const char *idpid, cfed_s_user_attrs_t *p_user_attrs, const char *cert_file_name, const char *pr_key_file)
{
	if (p_ctx == NULL)
		return -1; 
	
	/* probehlo cele kolecko pro zadane sp_cert_url? */
	cfed_s_spconf_t *current_sp = NULL;
	current_sp = cfed_get_sp_struct(p_ctx,"https://mizar.ics.muni.cz/onlineca/cgi-bin/login-mozilla.cgi?ca=Aleph");
	if (current_sp == NULL)
		if (cfed_whole_round(p_ctx, idpid,"https://mizar.ics.muni.cz/onlineca/cgi-bin/login-mozilla.cgi?ca=Aleph", p_user_attrs))
			goto error_out;
	/* generuj par RSA klicu, pouzij pevny challange pro demonstraci */
	NETSCAPE_SPKI *spki=NULL;
	EVP_PKEY *pkey=NULL;
	cfed_gen_spki(&spki, &pkey);

	/* soukromy klic uloz do pr_key_file*/
	FILE *p_fp;
	if ((p_fp = fopen(pr_key_file, "w")) == NULL)
        {
                cfed_make_err_msg (&(p_ctx->error), "cfed_get_new_cert: nelze otevrit soubor pro ulozeni soukromeho klice");
                return -1;
        }
	chmod(pr_key_file, 0600);

	PEM_write_RSAPrivateKey(p_fp,pkey->pkey.rsa,NULL,NULL,0,NULL,NULL);
	fclose(p_fp);	
	//NETSCAPE_SPKI_free(spki);
	EVP_PKEY_free(pkey);

	/* do docasneho souboru odloz verejny klic*/
	FILE * tempfile = NULL;
	tempfile = tmpfile();
	if (tempfile == NULL)
        {
                cfed_make_err_msg (&(p_ctx->error), "cfed_get_new_cert: nelze otevrit docasny soubor");
                return -1;
        }
	PEM_write_SPKI(tempfile,spki);
	
	/*vytahni verejny klic ze souboru a orezej od nepotrebnych informaci*/
	char * key_from_tempfile = cfed_get_pub_key (p_ctx, tempfile);

	/*vytvor pozadavek na certifikat sveho klice*/
	char* key_to_send = cfed_make_cert_request(p_ctx, key_from_tempfile);
	cfed_free(p_ctx, key_from_tempfile);
	fclose(tempfile);

	if (key_to_send == NULL)
		goto error_out;
	FILE *p_fw;
	if ((p_fw = fopen(cert_file_name, "w")) == NULL)
        {
                cfed_make_err_msg (&(p_ctx->error), "cfed_get_new_cert: nelze otevrit soubor pro ulozeni certifikatu");
                return -1;
        }
	chmod(cert_file_name, 0664);

	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_URL, "https://mizar.ics.muni.cz/onlineca/cgi-bin/ns_key.cgi"))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_POSTFIELDS, key_to_send))
		goto error_out;
        if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEHEADER, stdout))
                goto error_out;
        if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_HEADERFUNCTION, cfed_clb_no_write))
                goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEDATA, p_fw))
		goto error_out;
	if (curl_easy_setopt(p_ctx->curl_handle, CURLOPT_WRITEFUNCTION, cfed_clb_write))
		goto error_out;

	/* perform the transfer*/
	if (curl_easy_perform(p_ctx->curl_handle))
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_get_new_cert: prenost neprobehl v poradku");
		return -1;
	}

	cfed_free(p_ctx, key_to_send);
	fclose(p_fw);
	long check_code = 200;
        /*zkontroluj posledni navracenou hlavicku, pro neplatny kod ukonci funkci*/
        if (cfed_check_response_code(p_ctx, check_code))
                goto error_out;

	return 0;
	
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_get_new_cert: chyba pri provadeni funkce");
		return -1;
}
static char *cfed_get_pub_key(cfed_s_context_t *p_ctx,FILE *tempfile)
{
	if (p_ctx == NULL)
		return NULL; 

	if (tempfile == NULL)
		goto error_out;

	char *line;                                     //nacitany radek
        line = (char *) cfed_malloc(p_ctx, KEY_FILE_LEN * sizeof(char));
        if (line == NULL)
                goto error_out;
        line[0] = '\0';                                         //pro jistotu
	rewind(tempfile);
	char * key = NULL;
       	unsigned int key_sum = 0;
	unsigned int line_len = 0;
	while(1)
        {
                /*nacti radek*/
                if (fgets(line, KEY_FILE_LEN, tempfile) == NULL)
                {       /*chyba pri nacitani radku*/
                        if (ferror(tempfile))
                        {
                                cfed_make_err_msg (&(p_ctx->error), "cfed_get_new_cert: nelze nacist radku z configuracniho souboru");
                                return NULL;

                        }
                        /*konec souboru, pokracuj za while cyklem*/
                        else if (feof(tempfile))
                                break;
                }
                if (line[0] == '-')
                        continue;
                /* k soucasnemu retezci s klicem pripoj nacteny retezec bez znaku noveho radku*/
        	line_len = strlen(line);
		line[line_len-1] = '\0';
		key_sum = (line_len) + key_sum;
		key = (char *) realloc(key, (key_sum + 1)*sizeof(char));
        	if (key == NULL)
        	{
                	cfed_free(p_ctx, key);
                	return NULL;
        	}
        	if (key_sum == line_len)
                	key[0] = '\0';
        	strcat (key, line);
        }

	cfed_free(p_ctx, line);
	return key;
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_get_pub_key: chyba pri provadeni funkce");
		return NULL;
		

}
static char * cfed_make_cert_request(cfed_s_context_t *p_ctx,const char *source)
{
	if (p_ctx == NULL)
		return NULL; 

	if (source == NULL)
		goto error_out;
	
	const char * pred = "ca=Aleph&SPKAC=";
	const char * po = "&reqEntry=&SUBMIT=Get+the+certificate";
		
	const char * source_urlenc = cfed_url_encode(p_ctx, source);

	int ret_string_len = strlen(source_urlenc) + strlen(pred) + strlen(po);

	char * ret_string = (char *) cfed_malloc(p_ctx, ret_string_len + sizeof(char));
	if (ret_string == NULL)
		goto error_out;
	ret_string[ret_string_len] = '\0';
        strcpy (ret_string, pred);
        strcat (ret_string, source_urlenc);
        strcat (ret_string, po);

	return ret_string;

	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_make_cert_request: chyba pri provadeni funkce");
		return NULL;
}

/* vypise retezec ptr o velikosti size*nmemb do stream 
 *  stream musi  byt (FILE *) korektne otevreny souborovy stream
 *  (stdout, stderr...), pokud written neni size*nmemb, 
 *  curl zpracuje chybu. */
static size_t cfed_clb_write(void *ptr, size_t size, size_t nmemb, void *stream)
{
	/* nasledujici komentar staci odstranit a posunout za rovnitko a budou
 * 	se vypisovat temer vsechny hlavicky a tela html pri vsech prenosech */

  int written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

static size_t cfed_clb_no_write(void *ptr, size_t size, size_t nmemb, void *stream)
{
	/* nasledujici komentar staci odstranit a posunout za rovnitko a budou
 * 	se vypisovat temer vsechny hlavicky a tela html pri vsech prenosech */

  int written = size*nmemb;//fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}


 /* V http hlavicce ptr najde url pro presmerovani (Location header)
 * prvni vyskyt !!! Je treba mit *stream == NULL.
 *   Url o velikosti nejvyse size*nmemb vypise do retezce stream.
 *   Stream zde je (char **), pri volani streamu predat &next_url */
static size_t cfed_clb_fnd_loc(void *ptr, size_t size, size_t nmemb, void *stream)
{
	char **p_stream = stream;
	if (*p_stream == NULL)
	{
		char http_header[size*nmemb];
		char *p_char;
		p_char = NULL;
		strncpy (http_header,ptr, (size*nmemb));
		p_char = strchr(http_header, 10);
		if (p_char != NULL)
			*p_char = '\0';
		p_char = strchr(http_header, 13);
		if (p_char != NULL)
			*p_char = '\0';
	
		/* Find Location header and set that url */
		if (strstr(http_header, "Location") != NULL) 
		{
			if ((p_char = strstr(http_header, "http")))
			{
				*p_stream = (char *)malloc((size*nmemb + 1) * sizeof(char));
				strncpy (*p_stream, p_char, (size*nmemb + 1));
			}
		}
	}
  int written = size*nmemb;//fwrite(ptr, size, nmemb, stdout);
  return written;
}

/* postupne dostava od CURLu casti odpovedi z prave probihajici prenosu
 * (prvni typicky size*nmemb = 8KB). Kusy (casto html stranky) sklada za sebou do
 * retezce stream*/
static size_t cfed_clb_get_response(void *ptr, size_t size, size_t nmemb, void *stream)
{	
  	char **p_stream = stream;
  	long int old_stream_len = 0;
  	if (*p_stream != NULL)
		old_stream_len = strlen(*p_stream);
	long int new_stream_len = size*nmemb + old_stream_len;
	
	*p_stream = (char *)realloc(*p_stream, (new_stream_len + 1) * sizeof(char));
  	if (*p_stream == NULL)
	{
		printf("chyba pridelovani pameti");
	}
	if (old_stream_len == 0)
		**p_stream='\0';
  	strncat(*p_stream, ptr, size*nmemb);
  	*(*p_stream + new_stream_len)='\0';

  int written = size*nmemb;//fwrite(ptr, size, nmemb, stdout);
  return written;
}

/* Z retezce source extrahuje hodnotu polozky formulare action.
 * Pokud takova v source neni, nechava action nezmeneny a vraci -1, jinak vraci 0*/
static char *cfed_extract_action (cfed_s_context_t *p_ctx,const char *source)
{
	if (p_ctx == NULL)
		return NULL; 

	char *action_start;
	char *action_current;
	action_current = NULL;
	action_start = NULL;
	int action_len = 0;
	
	/* Find form attr. action (url where SAML send to)  */
	if ( (action_start = strstr(source, "action")) != NULL) 
	{
			action_start = strchr(action_start, '"');
			action_start++;
			action_current = action_start;
			while (*action_current != '"')
			{
				action_len++;
				action_current++;	
			}
			
  			action_current = (char *)cfed_malloc(p_ctx, (action_len + 1) * sizeof(char));
			strncpy (action_current, action_start, (action_len));
			*(action_current + action_len) = '\0';
			return action_current;
	}
	
	cfed_make_err_msg (&(p_ctx->error), "cfed_extract_action: nenalezena polozka formulare s nazvem - action");
	return NULL;
} 

/* Z retezce source extrahuje hodnotu polozky formulare  nazvem pattern.
 * Pokud takova v source je, vracti ukazatel na ni, jinak vraci NULL.
 * Nutne uvolnit pamet ve volajici funkci*/
static char * cfed_extract_form_value (cfed_s_context_t *p_ctx, const char *source, const char *pattern)
{
	if (p_ctx == NULL)
		return NULL; 

	char *pat_start;
	char *pat_current;
	pat_current = NULL;
	pat_start = NULL;
	int pat_len = 0;
	
	if ((pat_start = strstr(source, pattern)) != NULL) 
	{
		if ((pat_start = strstr(pat_start, "value")))
		{
			pat_start = strchr(pat_start, '"');
			pat_start++;
			pat_current = pat_start;
			while (*pat_current != '"')
			{
				pat_len++;
				pat_current++;	
			}
  			pat_current = (char *)cfed_malloc(p_ctx, (pat_len + 1) * sizeof(char));
			strncpy (pat_current, pat_start, pat_len);
			*(pat_current + pat_len) = '\0';
			return pat_current;
		}
	}
	
	cfed_make_err_msg (&(p_ctx->error), "cfed_extract_saml: nenalezena polozka formulare s nazvem - %s", pattern);
	return NULL;
} 
/* funkce prohleda p_ctx a vrati ukazatel na strukturu podle idpid (prvni vyskyt).
 *  Pokud ta v poli neni, vraci NULL */
static cfed_s_idpconf_t *cfed_get_idp_struct (cfed_s_context_t *p_ctx, const char *idpid) 
{
	if (p_ctx == NULL)
		return NULL; 
	if (!p_ctx->conf || !p_ctx->conf->idps)
		goto error_out;
	
	int i=0;		//iterator
	/* prohledej vsechny cleny struktury a vrat idp podle idpid */
	for (i=0; p_ctx->conf->idps[i] != NULL; i++)
	{
		if (!strcmp (p_ctx->conf->idps[i]->entity_id, idpid))
		{
			return  p_ctx->conf->idps[i];
		}
	}
	error_out:	
	/* zadna polozka zadaneho jmena nenalezena*/
	cfed_make_err_msg (&(p_ctx->error), "cfed_get_idp_stuct: %s nenalezena", idpid);
	return NULL;
}

/* funkce prohleda p_ctx a vrati ukazatel na strukturu podle spid (prvni vyskyt).
 *  Pokud ta v poli neni, vraci NULL */
static cfed_s_spconf_t *cfed_get_sp_struct (cfed_s_context_t *p_ctx, const char *spid)
{
	if (p_ctx == NULL)
		return NULL; 
	if (!p_ctx->conf || !p_ctx->conf->sps)
		goto error_out;
	
	int i=0;		//iterator
	/* prohledej vsechny cleny struktury a vrat idp podle idpid */
	for (i=0; p_ctx->conf->sps[i] != NULL; i++)
	{
		if (!strcmp(p_ctx->conf->sps[i]->entity_id, spid))
		{
			return p_ctx->conf->sps[i];
		}
	}
	/* zadna polozka zadaneho jmena nenalezena*/
	error_out:	
	cfed_make_err_msg (&(p_ctx->error), "cfed_get_sp_stuct: %s nenalezena", spid);
	return NULL;
}

/* proskouma struktury podle p_attrs a pokud nalezne demand vrati prislusnou strukturu do retval*/	
static int cfed_get_form_creds (cfed_s_context_t *p_ctx, cfed_s_idp_attr_t  **p_attrs, const cfed_e_authn_attrs_t demand, char **retval)
{
	if (p_ctx == NULL)
		return -1; 

	int i = 0;	//iterace	
	for (i=0; p_attrs[i] != NULL; i++)
	{
		if ( p_attrs[i]->authn_attr == demand )
		{
			*retval = (char *) cfed_malloc(p_ctx, sizeof(char) * strlen(p_attrs[i]->value) + 1);
			if (*retval == NULL)
				return -1;
			strcpy (*retval, p_attrs[i]->value);
			return 0;	
		}
	}

	cfed_make_err_msg (&(p_ctx->error), "cfed_get_form_creds: nelze nalezt attribut uname");
	return -1;
}

/* do retezce err_msg ulozi popis chyby err_descr
 * v nasi impl. volat pro ( &p_ctx->error, ...)
 * pro prazdny err_descr pouzivat "" */
void cfed_make_err_msg (char **err_msg, const char *err_format, ...)
{
	/* ochrana pred kopirovanim z neplatne adresy */
	if (err_format == NULL)
		return;
	
	unsigned int err_msg_len = 0;
	/* ochrana pred kopirovanim z neplatne adresy */
	if (*err_msg != NULL)
		err_msg_len = strlen(*err_msg);

	/* generuj novy retezec s popisem aktualni chyby */
	va_list ap;
	char *new_msg = NULL;
	va_start(ap, err_format);
	int err_format_len = 0;
	err_format_len = vasprintf(&new_msg, err_format, ap);
	if (err_format_len < 1)
		return;

	/* k soucasnemu retezci s popisem chyb pripoj aktualni retezec */
	unsigned int err_msg_sum = err_format_len + err_msg_len;
	/* 2 tady kvuli oddelovaci ; a '\0' */
	*err_msg = (char *) realloc (*err_msg, (err_msg_sum + 2)*sizeof(char));
	if (*err_msg == NULL)
	{
		free(new_msg);			
		return;
	}
	if (err_msg_len == 0)
		(*err_msg)[0] = '\0';
	strcat (*err_msg, new_msg);
	strcat (*err_msg, ";");
	
	free(new_msg);			
}



/**************************************************************************
 * URL-encoding, decoding 
 * ***********************************************************************/

/* Converts an integer value to its hex character*/
static char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

/* Converts a hex character to its integer value */
static char from_hex(char ch)
{
        return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Returns a url-encoded version of str */
/*upravit velikost prideleni pameti u malloc*/
/* IMPORTANT: be sure to free() the returned string after use */
static char *cfed_url_encode(cfed_s_context_t *p_ctx,const char *str) 
{	
	if (p_ctx == NULL)
		return NULL; 

	const char *pstr = str;
	char *buf = cfed_malloc(p_ctx, strlen(str) * 3 + 1), *pbuf = buf;
	while (*pstr) 
	{
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') 
			*pbuf++ = *pstr;
		else if (*pstr == ' ') 
			*pbuf++ = '+';
		else 
			*pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
		pstr++;
	}
	*pbuf = '\0';
	return buf;
}

/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
static char *cfed_url_decode(cfed_s_context_t *p_ctx, char *str)
{
        if (p_ctx == NULL)
                return NULL;

        char *pstr = str, *buf = malloc(strlen(str) + 1), *pbuf = buf;
        while (*pstr)
        {
                if (*pstr == '%')
                {
                        if (pstr[1] && pstr[2])
                        {
                                *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
                                pstr += 2;
                        }
                }
                else if (*pstr == '+')
                {
                        *pbuf++ = ' ';
                }
                else
                {
                        *pbuf++ = *pstr;
                }

                pstr++;
        }
        *pbuf = '\0';
        return buf;
}
/**************************************************************************
 * BASE64-decoding 
 * ***********************************************************************/
/*rozkoduje zadany retezec*/
static const char  base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char value(char c)
{
	const char *p = strchr(base64_table, c);
	if(p) 
	{
		return p-base64_table;
	} 
	else 
	{
		return 0;
	}
}

static char *cfed_base64_decode(cfed_s_context_t *p_ctx, const char *src)
{
	if (src == NULL)
		goto error_out;

	unsigned int p_len = 0;
	p_len = strlen(src);		
	char *p = (char *)cfed_malloc(p_ctx, (p_len+1) * sizeof(char));
	char *p_start = p;
	if (!p)
		goto error_out;
    	while (*src != '\0')
     	{
          char a = value(src[0]);
          char b = value(src[1]);
          char c = value(src[2]);
          char d = value(src[3]);
          
	  *p++ = (a << 2) | (b >> 4);
          *p++ = (b << 4) | (c >> 2);
          *p++ = (c << 6) | d;
          
	  src += 4;
     	}
	*p = '\0';
      	return p_start;
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_base64_decode: chyba v prevodu retezce z BASE64 kodu");
		cfed_free(p_ctx, p_start);
		return NULL;
}
 /* ***********************************************************************/

/*ziskej posledni pouzitou url */
static char *cfed_get_last_url(cfed_s_context_t *p_ctx)
{
	if (p_ctx == NULL)
		return NULL; 
	
	char *last_url = NULL;
	char *new_url = NULL;
	curl_easy_getinfo(p_ctx->curl_handle, CURLINFO_EFFECTIVE_URL, &last_url);
	if (last_url != NULL)
	{
		unsigned int last_url_len = strlen(last_url);
		new_url = cfed_malloc(p_ctx, (last_url_len+1)*sizeof(char));
		if (new_url == NULL)
			goto error_out;
		strncpy(new_url, last_url, last_url_len + 1);
	}
	return new_url;
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_get_last_url: nelze precist ziskat posledni pouzitou url");
		return NULL;	
}


/* zkontroluje, zda posledni hlavicka s navratovym kodem mela hodnotu check_code */
static int cfed_check_response_code(cfed_s_context_t *p_ctx, const long check_code)
{
	if (p_ctx == NULL)
		return -1; 

	long response_code = 0;
	curl_easy_getinfo(p_ctx->curl_handle, CURLINFO_RESPONSE_CODE, &response_code);
	if (response_code == check_code)
		return 0;
	else
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_check_response_code: vraceny kod HTTP %ld neodpovida danemu %ld", response_code, check_code);
		return -1;
	}
}
/* bezpecnejsi uvolneni pameti s nastavenim err_msg*/
void cfed_free(cfed_s_context_t *p_ctx, void *p_mem)
{
	if (p_ctx == NULL)
		return; 

	if (p_mem != NULL)
		free(p_mem);
	else
		cfed_make_err_msg (&(p_ctx->error), "cfed_free: nelze uvolnit pamet NULL");
}

/* alokace  pameti s nastavenim err_msg */
void * cfed_malloc(cfed_s_context_t *p_ctx, size_t size)
{
	if (p_ctx == NULL)
		return NULL; 

	void *p_ret = NULL;	
	p_ret = malloc(size);
	if (p_ret != NULL)
		return p_ret;
	else
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_malloc: nezdarilo se pridelit pamet velikosti %zu", size);
		return NULL;
	}
}
