/* cfed_init.c
 *
 * Inicializace knihovny, alokace paměti pro struktury*/

#include "cfed.h"
#include <string.h>
#include <stdarg.h> 
#include <ctype.h>  //isspace()
#include <stdlib.h>  //realloc()

#define CONF_FILE_LEN 1024 //maximalni delka nacteneho radku z konfigur. souboru

static int cfed_init_skip_white(cfed_s_context_t *p_ctx, const char **line);
static int cfed_init_parse_line(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const unsigned char inside_braces, const char **line);
static int cfed_init_parse_kv(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *key, const char *value);
static char *cfed_init_extract_value(cfed_s_context_t *p_ctx, const char **line);
static char *cfed_init_extract_key(cfed_s_context_t *p_ctx, const char **line);
static int cfed_init_block_start(cfed_s_context_t *p_ctx, const unsigned int actual_idp_index, const unsigned char inside_braces);
static int cfed_init_block_end(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const unsigned char inside_braces);
static int cfed_check_idp(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp);
static int cfed_init_idpsp(cfed_s_context_t *p_ctx);
static int cfed_init_result(cfed_s_context_t *p_ctx);
static int cfed_init_new_idp(cfed_s_context_t *p_ctx, const unsigned int actual_idp_index);
static int cfed_curl_init (cfed_s_context_t *p_ctx);
static cfed_init_s_idp_command_t *cfed_find_idp_command(cfed_s_context_t *p_ctx, const char *code);
static int cfed_init_parse_name (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value);
static int cfed_init_parse_url (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value);
static int cfed_init_parse_authn_type (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value);
static int cfed_init_parse_idp_type (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value);
static int cfed_init_parse_uname (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value);
static int cfed_init_parse_password (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value);
static cfed_s_idp_attr_t *cfed_init_new_attr(cfed_s_context_t *p_ctx,cfed_s_idpconf_t *p_idp);

/* tabulka pro typ klice a prislusnou funkci, ktera se 
 * postara o inicializaci dane polozky ve strukture cfed_s_idpconf_t.*/
static cfed_init_s_idp_command_t commands[] = {
{ CFED_INIT_NAME, cfed_init_parse_name },
{ CFED_INIT_URL, cfed_init_parse_url, },
{ CFED_INIT_AUTHN_TYPE, cfed_init_parse_authn_type, },
{ CFED_INIT_IDP_TYPE, cfed_init_parse_idp_type, },
{ CFED_INIT_UNAME, cfed_init_parse_uname, },
{ CFED_INIT_PASSWORD, cfed_init_parse_password, },
{ 0, NULL },
};

/* pokud se bude chtit pozdeji pridat do vyctovych typu dalsi polozka,
 * je nutne prislusny string pridat i do prislusnych nasledujicich poli
 * pro vyhledavani ve vyctovych typech (nebo upraveny zkraceny pro
 * pohodlnejsi spravu konfiguracniho souboru), dulezite je zachovane poradi,
 * odpovidajici poradi v definici vyctoveho typu. Indexy prislusneho
 * zaznamu v poli jsou vsak oproti hodnotam ve vyctovem typu nizsi o 1
 * kvuli zarazkam ve vyctovem typu*/
static char* commands_to_string[] = { "CFED_INIT_NAME","CFED_INIT_URL","CFED_INIT_AUTHN_TYPE","CFED_INIT_IDP_TYPE","CFED_INIT_UNAME","CFED_INIT_PASSWORD"};

/* v tabulce commands vyhledej podle code prislusnou strukturu idp_command a vrat ukazatel na ni*/
static cfed_init_s_idp_command_t *cfed_find_idp_command(cfed_s_context_t *p_ctx, const char *code)
{
        if (p_ctx == NULL)
                return NULL;

        cfed_init_s_idp_command_t *c;
	int i = 0;
	
	/* zkonroluj  key je v tabulce commands */
        for (c = commands; c->idp_key; c++)
        {
                if (!strcmp(commands_to_string[i], code))
                	return c;
		i++;
        }


        cfed_make_err_msg (&(p_ctx->error), "cfed_find_idp_command: nelze nalezt prikaz pro zadany typ autenzizace");
        return NULL;
}

/* Inicializuje strukturu p_ctx hodnotami z conf_file_name,
 * take provede inicializaci CURLu z curl_handle. Pri uspechu vraci 0, 
 * jinak cele zaporne cislo n a nastavi chybovou zpravu do p_ctx->error.
 * Uspesna inicializace CFED je nutna podminka pro beh programu. V pripade
 * neuspesneho provedeni inicializace je doruceno nepokracovat v 
 * behu programu */
int cfed_init (cfed_s_context_t *p_ctx, const char *conf_file_name)
{
	/* kontrola vstupnich parametru */
	if (p_ctx == NULL)
		return -2;

	/* inicializace mista pro chybovou zpravu - musi predchazet
 	*  kontrole zbyv. parametru */
	p_ctx->error = NULL;

	/* kontrola vstupnich parametru */
	if (conf_file_name == NULL)
	{
		cfed_make_err_msg(&(p_ctx->error), "cfed_init: nevhodny vstupni parametr funkce");
		return -1;	
	}	

	/* inicializace *p_ctx clenu na NULL */
	p_ctx->conf = NULL;
        p_ctx->error = NULL;
        p_ctx->curl_handle = NULL;
        //asi k nicemu p_ctx->p_curlsl = NULL;
	
	/* otevri konfiguracni soubor conf_file_name*/
	FILE *fr;
	if ((fr = fopen(conf_file_name, "r")) == NULL)          
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_init: nelze otevrit configuracni soubor");
		return -1;
	}

	/* inicializace curl_handle a nastaveni CURLu*/
	if (cfed_curl_init(p_ctx))
		goto error_out;
	/*misto pro idpsp a inicializace clenu*/
	if (cfed_init_idpsp(p_ctx))
		goto error_out;

	/*misto pro result a inicializace clenu*/
	if (cfed_init_result(p_ctx))
		goto error_out;
		
	/* nacitej a zpracuj radky z conf. souboru dokud nenarazis na eof nebo nejakou chybu */
	char *line;					//nacitany radek
	line = (char *) cfed_malloc(p_ctx, CONF_FILE_LEN * sizeof(char));
	if (line == NULL)
		goto error_out;
	line[0] = '\0';						//pro jistotu

	unsigned char inside_braces = 0;			//priznak pro blok Idp v conf.
	unsigned int actual_idp_index = 0;				//index aktualniho idp
	while(1)
	{
		/*nacti radek*/
		if (fgets(line, CONF_FILE_LEN, fr) == NULL)
		{	/*chyba pri nacitani radku*/
			if (ferror(fr))
			{
				cfed_make_err_msg (&(p_ctx->error), "cfed_init: nelze nacist radku z configuracniho souboru");
				return -1;
		
			}
			/*konec souboru, pokracuj za while cyklem*/
			else if (feof(fr))
				break;
		}
		/*na radku se posouvej - vynech mezery az po 1. nebily znak*/
		if (cfed_init_skip_white(p_ctx, &line))	
			goto error_out; //chyba
		if (*line == '\0')
			continue; //prazdny radek

		/*radek je komentar*/
		if (*line == '#')
			continue;
		/* novy blok */
		else if (*line == '{')
		{
			if (!cfed_init_block_start(p_ctx, actual_idp_index, inside_braces))
				inside_braces = 1;
			else
				goto error_out; 
		}
		/* konec nacitani bloku atributu */
		else if (*line == '}')
		{
			if (!cfed_init_block_end(p_ctx, p_ctx->conf->idps[actual_idp_index], inside_braces))
			{
				inside_braces = 0;
				actual_idp_index++;	// block OK
			}
			else
				goto error_out;
		}
		/* jiny znak nez blokovy nebo komentar*/
		else
				/*parse line read*/
				if (cfed_init_parse_line(p_ctx, p_ctx->conf->idps[actual_idp_index], inside_braces, &line))
					goto error_out;	
	}

	return 0;
	
	error_out:
		cfed_cleanup(p_ctx);
		cfed_make_err_msg (&(p_ctx->error), "cfed_init: chyba zpracovani konfiguracniho souboru");
		return -1;


}
		
/* projdi line - zastav se na 1. nebilem znaku*/
/* nulu vracej pro korektni zastaveni - i na '\0'*/
static int cfed_init_skip_white(cfed_s_context_t *p_ctx, const char **line)
{	
	/* kontorla vstupnich parametru*/
	if (p_ctx == NULL)
		return -2;

	while (**line != '\0')
	{
		/* bily znak, posun */
		if (isspace(**line))
			(*line)++;
		else
			return 0;
	}

	return 0; //prazdny radek
}

/* na radku se nachazim na 1. nebilem znaku, zpracuj key = "value"
 * , pokud retezec nema tento tvar (nebo jiny prijatelny - vice mezer,tab...)
 * nebo key, value nejsou platne hodnoty, vrat zaporne cislo, jinak 0 a 
 * prirad key, value do prislusnych struktur pro IdP */
static int cfed_init_parse_line(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const unsigned char inside_braces, const char **line)
{
	/* kontorla vstupnich parametru*/
	if (p_ctx == NULL)
		return -2;
	
	/*nejsem v bloku*/
	if (!inside_braces)
		goto error_out;

	/* jsem v bloku a line ukazuje na prvni nebily znak,
 	*  pokud ma retezec tvar key = "value" nacti a zpracuj key*/
	char * key = cfed_init_extract_key(p_ctx, line);
	if (key == NULL)
		goto error_out;
	
	/* jsem v bloku a line ukazuje na znak rovnitko '=',
 	*  pokud ma retezec tvar key = "value" nacti a zpracuj value*/
	char * value = cfed_init_extract_value(p_ctx, line);
	if (value == NULL)
		goto error_out;

	/* zpracuj key, value*/
	if (cfed_init_parse_kv(p_ctx, p_idp, key, value))
		goto error_out;
	
		/*zavri konf_file_name DDDDDDDDDDDDDDDDDDDDDDDD*/
	return 0;
	
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_init_extract_value: nelze extrahovat hodnotu");
		return -1;
}

/* Parsuj key, value. Zkontroluj zda odpovidaji typy key a value
 * a prirad je do prislusnych struktur pro IdP */
static int cfed_init_parse_kv(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *key, const char *value)
{
	/* nova fce - podle nacteneho klice volej fce pro prirazeni hodnoty a klice do struktury contextu*/
               
	cfed_init_s_idp_command_t *p_idp_command = NULL;
        p_idp_command = cfed_find_idp_command(p_ctx, key);
	if (p_idp_command == NULL)
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_init_parse_kv: nepodarilo se zpracovat radek z conf. souboru");
		return -1;
	}	
        if (p_idp_command->handler(p_ctx, p_idp, value))
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_init_parse_kv: nepodarilo se zpracovat radek z conf. souboru");
		return -1;
	}	
	return 0;
}

/*z reztezce *line vytahne value a vrati ukazatel na tento retezec, neuspech vraci NULL */
static char *cfed_init_extract_value(cfed_s_context_t *p_ctx, const char **line)
{
	/* kontorla vstupnich parametru*/
	if (p_ctx == NULL)
		return NULL;


	const char *value_end = NULL;
	/* *line ukazuje na znak '=' v key="value" */
	(*line)++;
	if (**line != '"')
		cfed_init_skip_white(p_ctx, line);
	if (**line != '"')
		goto error_out; //po '=' a b. znacich nenasleduje '"'
	
	/* *line ukazuje na prvni znak '"' v key="value"*/	
	value_end = (*line);
	value_end++;
	while (*value_end != '\0')
	{
		if (*value_end == '"')
			break;
		value_end++;
	}

	if (*value_end == '\0')
		goto error_out; //nelze najit druhy znak '"'
				
	/* *line ukazuje na 1. value_end na 2. '"' */
	/*alokuj misto a vrat value*/
	unsigned int value_len = strlen(*line)-strlen(value_end) - 1;
	char * value = NULL;
	value =(char *) cfed_malloc(p_ctx, ((value_len + 1) * sizeof(char)));
	if (value == NULL)
		goto error_out;
	/*nastav *line na 1.znak value*/
	(*line)++;
	
	strncpy(value, *line, value_len);
	value[value_len] = '\0';

	*line = value_end;	
	return value;
	
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_init_extract_value: nelze extrahovat hodnotu");
		return NULL;
}

/*z reztezce *line vytahne key a vrati ukazatel na tento retezec, neuspech vraci NULL */
static char *cfed_init_extract_key(cfed_s_context_t *p_ctx, const char **line)
{
	/* kontorla vstupnich parametru*/
	if (p_ctx == NULL)
		return NULL;
	
	if (**line == '=')
		goto error_out; //retezec zacina '='

	const char *equal_sign = NULL;	
	const char *key_end = *line;
	
	/* najdi konec key*/
	while (*key_end != '\0')
	{
		/*nasel jsem konec key (za nim primo rovnitko, bez mezer mezi)*/
		if (*key_end == '=')
		{
			equal_sign = key_end;
			break;
		}
		/*nasel jsem konec key nasledovany bilymi znaky*/
		else if (isspace(*key_end))
		{
			/*zkontroluj zda za key a bilymi znaky lze najit '='*/
			equal_sign = key_end;
			if (cfed_init_skip_white(p_ctx, &equal_sign))
				goto error_out; //chyba zpracovani
			
			if (*equal_sign == '=')
				break; //nasel jsem rovnitko, oddelene od key b. znaky
			else				
			{
				goto error_out; // za key a b. znaky nenasleduje '='
			}
		}
		/*jsem uprostred key*/
		else
			key_end++;
	} //konec while

	/*key_end ukazuje o 1 znak za key, naprav to*/
	key_end--;

	/*alokuj misto, zkopiruj a vrat key*/
	unsigned int key_len = strlen(*line)-strlen(key_end) + 1;
	char * key = (char *) cfed_malloc(p_ctx, key_len + 1);
	if (key == NULL)
		goto error_out;
	strncpy(key, *line, key_len);
	key[key_len] = '\0';

	/* nastav pozici na radku na znak rovnitko '\=' */
	*line = equal_sign;	
	return key;
	
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_init_extract_key: nelze extrahovat klic");
		return NULL;
}

/* radek konfiguracniho souboru zacina znakem '{', pridel misto pro
 * novou strukturu idpconf a zarad ji do stavajiciho seznamu techto
 * struktur. 0 uschpech, ostatni neuspech*/
static int cfed_init_block_start(cfed_s_context_t *p_ctx, const unsigned int actual_idp_index, const unsigned char inside_braces)
{
	/* kontorla vstupnich parametru*/
	if (p_ctx == NULL)
		return -2;

	/*nejsem uvnitr slozenych zavorek, zacina blok pro noveho IdP*/
	if (!inside_braces)
		/*pridel misto pro noveho idp*/
		cfed_init_new_idp(p_ctx, actual_idp_index);
	else
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_init_block_start: chybi ukoncovaci znak '%c'", '}');
		return -1;
	}
	return 0;
}


/* radek konfiguracniho souboru zacina znakem '}' (krome bilych znaku),
 * zkontroluj vsechny nactene atributy IdP, pokud neodpovidaji,
 * smaz ze seznamu struktur zaznam o aktualnim IdP. 0 OK, ostatni neuspech*/
static int cfed_init_block_end(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const unsigned char inside_braces)
{
	/* kontorla vstupnich parametru*/
	if (p_ctx == NULL)
		return -2;
	
	if (inside_braces)
	{
		/*zkontroluj vsechny nactene hodnoty*/
		if (cfed_check_idp(p_ctx, p_idp))
		{
			cfed_make_err_msg (&(p_ctx->error), "cfed_init_block_end: nactene hodnoty neprosly kontrolou");
			return -1;
		}
	}
	else
	{
		cfed_make_err_msg (&(p_ctx->error), "cfed_init_block_end: chybi oteviraci znak '%c'", '{');
		return -1;
	}

	return 0;
}

/* zkontroluj prave nacteny blok atributu Idp DODELAT!!!!!!!!!!!!!!!!*/
static int cfed_check_idp(cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp)
{
	/* kontorla vstupnich parametru*/
	if (p_ctx == NULL)
		return -2;

	return 0;
}

/* alokace mista a inicializace struktury p_ctx->conf */
static int cfed_init_idpsp(cfed_s_context_t *p_ctx)
{
	/* kontrola vstupnich parametru*/
	if (p_ctx == NULL)
		return -2;

	/* alokuj misto pro strukturu cfed_s_idpspconf_t a nastav ukazatel z p_ctx */
	p_ctx->conf =(cfed_s_idpspconf_t*) cfed_malloc(p_ctx, sizeof(cfed_s_idpspconf_t));
	if (p_ctx->conf == NULL)
	{
		cfed_make_err_msg(&(p_ctx->error), "cfed_init_idpsp: chyba pridelovani pameti");
		return -1;
	}
	/*inicializuj cleny prave alokovane struktury na NULL */
	p_ctx->conf->sps = NULL;
	p_ctx->conf->idps = NULL;

	return 0;
}

/* alokace mista a inicializace struktury p_ctx->conf */
static int cfed_init_result(cfed_s_context_t *p_ctx)
{
	/* kontrola vstupnich parametru*/
	if (p_ctx == NULL)
		return -2;

	/* alokuj misto pro strukturu cfed_s_result_t a nastav ukazatel z p_ctx */
	p_ctx->result =(cfed_s_result_t*) cfed_malloc(p_ctx, sizeof(cfed_s_result_t));
	if (p_ctx->result == NULL)
	{
		cfed_make_err_msg(&(p_ctx->error), "cfed_init_result: chyba pridelovani pameti");
		return -1;
	}
	/*inicializuj cleny prave alokovane struktury na NULL */
	p_ctx->result->raw = NULL;
	p_ctx->result->assertions = NULL;
	p_ctx->result->authn_status = 0;

	return 0;
}

/* alokuj misto pro noveho IdP v seznamu struktur idpconf 
 * slo by udelat i bez predavani idp_indexu*/
static int cfed_init_new_idp(cfed_s_context_t *p_ctx, const unsigned int actual_idp_index)
{
	/* kontorla vstupnich parametru*/
	if (p_ctx == NULL)
		return -2;
	
	/* realokuj misto pro actual_idp_index + 2 pointeru*/
	p_ctx->conf->idps = (cfed_s_idpconf_t **) realloc(p_ctx->conf->idps, (actual_idp_index + 2) *sizeof(cfed_s_idpconf_t *));
	if (p_ctx->conf->idps == NULL)
	{
		cfed_make_err_msg(&(p_ctx->error), "cfed_init_new_idp: chyba pridelovani pameti");
		curl_easy_cleanup(p_ctx->curl_handle);
		return -1;
	}
	
	/*pro ulehceni zapisu*/
	cfed_s_idpconf_t** idpconf = p_ctx->conf->idps;

	/*inicializace noveho ukazatele - NULL terminated list*/
	idpconf[actual_idp_index + 1] = NULL;
		
	/*alokuj misto pro novou strukturu pro Idp a nastaveni aktualniho pointeru*/
	idpconf[actual_idp_index] = (cfed_s_idpconf_t *) cfed_malloc(p_ctx, sizeof(cfed_s_idpconf_t)); //ACUAL IDP zvetsit pri '}'
	if (idpconf[actual_idp_index] == NULL)
	{
		cfed_make_err_msg(&(p_ctx->error), "cfed_init: chyba pridelovani pameti");
		curl_easy_cleanup(p_ctx->curl_handle);
		return -1;
	}

	/*inicializace prvku struktury*/
	idpconf[actual_idp_index]->entity_id = NULL; 
	idpconf[actual_idp_index]->url = NULL; 
	idpconf[actual_idp_index]->attrs = NULL; 
	idpconf[actual_idp_index]->authn_type = NULL; 
	//jak na tuhle inicializaci?????? DODELAT!!!
	idpconf[actual_idp_index]->idp_type = CFED_IDP_TYPE_END;
	
	return 0;
}

/* inicializace CURLu, nastaveni curl handlu do contextu a globalni nastaveni CURLu*/
static int cfed_curl_init (cfed_s_context_t *p_ctx)
{
	/* kontorla vstupnich parametru*/
	if (p_ctx == NULL)
		return -2;
		
	//globalni inicializace curlu
	if (curl_global_init(CURL_GLOBAL_ALL)) 
		goto error_out;


	//inicializace easy interface a nastaveni handle
	p_ctx->curl_handle = curl_easy_init();
	if (p_ctx->curl_handle == NULL)
		goto error_out;
	
	CURL *c_handle = p_ctx->curl_handle; //zjednoduseni	

	/* noprogress meter */
	if ( curl_easy_setopt(c_handle, CURLOPT_NOPROGRESS, 1L))
		goto error_out;
	
	/*follow any Location: header*/
	if (curl_easy_setopt(c_handle, CURLOPT_FOLLOWLOCATION, 1))
		goto error_out;
	
	/* set Referer: header */
	if (curl_easy_setopt(c_handle, CURLOPT_AUTOREFERER, 1))
		goto error_out;
	
	/* COOKIE PARSER ON, cookiefile does not exist yet */
	if (curl_easy_setopt(c_handle, CURLOPT_COOKIEFILE, ""))
		goto error_out;
	
	/* verbose TESTOVANI - zrusit */
	if (curl_easy_setopt(c_handle, CURLOPT_VERBOSE, 0L))
		goto error_out;
	

	return 0;
	error_out:
		cfed_make_err_msg (&(p_ctx->error), "cfed_curl_init: chyba pri inicializaci CURL");
		return -1;
}

/*do p_idp->entity_id prirad hodnotu value, alokace pameti*/
static int cfed_init_parse_name (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value)
{
	/*kontrola vstupu*/
	if ( p_ctx == NULL )
		return -1;			
	
	/* radek obsahoval nekolik polozek pro jmeno IdP, spatny tvar*/
	if (p_idp->entity_id != NULL)
		goto error_out;

	unsigned int value_len = strlen(value);

	p_idp->entity_id =(char *) cfed_malloc(p_ctx, (value_len + 1)*sizeof(char));
	if (p_idp->entity_id == NULL)
		goto error_out;
	strncpy(p_idp->entity_id, value, value_len);
	p_idp->entity_id[value_len] = '\0';

	return 0;

	error_out:
                cfed_make_err_msg (&(p_ctx->error), "cfed_init_parse_name: nelze pridelit jmeno pro IdP");
                return -1;
}

/*do p_idp->url prirad hodnotu value, alokace pameti*/
static int cfed_init_parse_url (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value)
{
	/*kontrola vstupu*/
	if ( p_ctx == NULL )
		return -1;			
	
	/* radek obsahoval nekolik polozek pro jmeno IdP, spatny tvar*/
	if (p_idp->url != NULL)
		goto error_out;

	unsigned int value_len = strlen(value);

	p_idp->url =(char *) cfed_malloc(p_ctx, (value_len + 1)*sizeof(char));
	if (p_idp->url == NULL)
		goto error_out;
	strncpy(p_idp->url, value, value_len);
	p_idp->url[value_len] = '\0';

	return 0;

	error_out:
                cfed_make_err_msg (&(p_ctx->error), "cfed_init_parse_url: nelze pridelit jmeno pro IdP");
                return -1;
}

/*do p_idp->authn_type prida dalsi polozku do seznamu moznych authn. typu, alokace pameti*/
static int cfed_init_parse_authn_type (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value)
{
	/*kontrola vstupu*/
	if ( p_ctx == NULL )
		return -1;			
	
	unsigned int no_authn_type = 0; //dosavadni pocet typu authn pro daneho idp
	cfed_e_authn_type_t *actual_authn_type = NULL; //prochazeni typu authn

	for ( actual_authn_type = p_idp->authn_type; actual_authn_type != NULL; actual_authn_type++)
	{
		no_authn_type++;
	}
	
	cfed_e_authn_type_t actual_type = CFED_AUTHN_TYPE_END;
	
	/*zkontroluj, zda je value odpovidajici typ pro key*/
	if (!strcmp(value,"CFED_AUTHN_TYPE_BASIC"))
                actual_type = CFED_AUTHN_TYPE_BASIC;
	else if (!strcmp(value,"CFED_AUTHN_TYPE_X509"))
                actual_type = CFED_AUTHN_TYPE_X509;
        else if (!strcmp(value,"CFED_AUTHN_TYPE_FORMPASS"))
               actual_type = CFED_AUTHN_TYPE_FORMPASS;
        else
               goto error_out;

	/* alokuj misto pro novy seznam authn typu */
	p_idp->authn_type =(cfed_e_authn_type_t *) realloc(p_idp->authn_type, (no_authn_type + 2)*sizeof(cfed_e_authn_type_t));
	if (p_idp->authn_type == NULL)
		goto error_out;
	
	p_idp->authn_type[no_authn_type] = actual_type;
	p_idp->authn_type[no_authn_type + 1] = CFED_AUTHN_TYPE_END;
	
	return 0;

	error_out:
                cfed_make_err_msg (&(p_ctx->error), "cfed_init_parse_authn_type: nelze pridelit authn typy pro IdP");
                return -1;
}

/*do p_idp->idp_type priradi hodnotu value*/
static int cfed_init_parse_idp_type (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value)
{
	/*kontrola vstupu*/
	if ( p_ctx == NULL )
		return -1;			
	
	/* radek obsahoval nekolik polozek pro typ IdP, spatny tvar*/
	if (p_idp->idp_type != CFED_IDP_TYPE_END)
		goto error_out;

	/*zkontroluj, zda je value odpovidajici typ pro key*/
	if (!strcmp(value,"CFED_IDP_TYPE_STANDARD"))
                p_idp->idp_type = CFED_IDP_TYPE_STANDARD;
	else if (!strcmp(value,"CFED_IDP_TYPE_EXTENDED"))
                p_idp->idp_type = CFED_IDP_TYPE_EXTENDED;
        else
               goto error_out;
	
	return 0;

	error_out:
                cfed_make_err_msg (&(p_ctx->error), "cfed_init_parse_idp_type: nelze pridelit typ IdP");
                return -1;
}

/*do p_idp->url prirad hodnotu value, alokace pameti*/
static int cfed_init_parse_uname (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value)
{
	/*kontrola vstupu*/
	if ( p_ctx == NULL )
		return -1;			

	/* vytvorit novy idp atribut uname */
	cfed_s_idp_attr_t *new_attr = NULL;
	new_attr = cfed_init_new_attr(p_ctx, p_idp);
	if (new_attr == NULL)
		goto error_out;

	unsigned int value_len = strlen(value);

	/* alokuj misto na retezec */
	new_attr->value = (char *) cfed_malloc(p_ctx, (value_len + 1)*sizeof(char));
	if (new_attr->value == NULL)
		goto error_out;
	/* nastav retezec */
	strncpy(new_attr->value, value, value_len);
	new_attr->value[value_len] = '\0';

	/* nastav typ */
	new_attr->authn_attr = CFED_AUTHN_ATTR_UNAME;
	return 0;

	error_out:
                cfed_make_err_msg (&(p_ctx->error), "cfed_init_parse_uname: nelze pridelit uname pro IdP");
                return -1;
}
/* zkusit parametrizovat*/
/*do p_idp->url prirad hodnotu value, alokace pameti*/
static int cfed_init_parse_password (cfed_s_context_t *p_ctx, cfed_s_idpconf_t *p_idp, const char *value)
{
	/*kontrola vstupu*/
	if ( p_ctx == NULL )
		return -1;			
	
	/* vytvorit novy idp atribut uname */
	cfed_s_idp_attr_t *new_attr = NULL;
	new_attr = cfed_init_new_attr(p_ctx, p_idp);
	if (new_attr == NULL)
		goto error_out;
	
	unsigned int value_len = strlen(value);

	/* alokuj misto na retezec */
	new_attr->value = (char *) cfed_malloc(p_ctx, (value_len + 1)*sizeof(char));
	if (new_attr->value == NULL)
		goto error_out;
	/* nastav retezec */
	strncpy(new_attr->value, value, value_len);
	new_attr->value[value_len] = '\0';
	/* nastav typ */
	new_attr->authn_attr = CFED_AUTHN_ATTR_PASSWORD;
	
	return 0;

	error_out:
                cfed_make_err_msg (&(p_ctx->error), "cfed_init_parse_password: nelze pridelit password pro IdP");
                return -1;
}

/* alokuj misto pro novy idp atribut a nastav ukazatel na NULL 
 * vrat ukazatel na predposledni prazdnout strukturu, 
 * posledni je NULL. Pri neuspech vrat NULL */	
static cfed_s_idp_attr_t *cfed_init_new_attr(cfed_s_context_t *p_ctx,cfed_s_idpconf_t *p_idp)
{
	/*najdi aktualni pocet atributu*/
	unsigned int no_attrs = 0;
	int i = 0; //iterace
	if (p_idp->attrs != NULL)
		for (i = 0; p_idp->attrs[i] != NULL; i++)
			no_attrs++;

	/* alokuj misto pro novy seznam atributu (pointery) */
	p_idp->attrs = (cfed_s_idp_attr_t **) realloc(p_idp->attrs, (no_attrs + 2)*sizeof(cfed_s_idp_attr_t*));
	if (p_idp->attrs == NULL)
		goto error_out;
	
	/* alokuj misto pro novou strukturu */
	p_idp->attrs[no_attrs] = (cfed_s_idp_attr_t *) cfed_malloc(p_ctx,sizeof(cfed_s_idp_attr_t));
	if (p_idp->attrs[no_attrs] == NULL)
		goto error_out;
	
	p_idp->attrs[no_attrs + 1] = NULL;
	
	return p_idp->attrs[no_attrs];
	error_out:
                cfed_make_err_msg (&(p_ctx->error), "cfed_init_new_attr: nelze pridelit misto pro novy IdP atribut");
                return NULL;
}
