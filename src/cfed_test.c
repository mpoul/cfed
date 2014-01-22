/* cfed_test.c 
 *
 * šířitelné pod BSD licencí. Vlastník práv: Masarykova Univerzita
 *
 * slouzi k otestovani funkcnosti */

#include "cfed.h" //mel by se inkludovat 1.
#include <string.h>

static void cfed_print_sps(cfed_s_context_t *p_ctx);
static void cfed_print_idps(cfed_s_context_t *p_ctx);

int main(int argc, char *argv[])
{
	if (argc != 5)
	{
		printf("Spatny pocet argumentu. Pouziti: \n");
		printf("%s %s %s %s %s\n", argv[0], "IdP_id", "SP_id", "username", "password");
		printf("priklad: %s https://mizar.ics.muni.cz/onlineca/cgi-bin/login-mozilla.cgi?ca=Aleph https://idp2.ics.muni.cz/idp/shibboleth username password", argv[0]);
		return -1;
	}

	/* inicializuj struktury*/
        cfed_s_context_t s_context;  //struct. cfed_sctx
        if (cfed_init(&s_context, "cfed.conf"))
                printf("cfed_init skoncila chybou\n");
        cfed_print_idps(&s_context);	//ukaz zaznamy o vsech IDP
        cfed_s_user_attrs_t user_attrs;
        
	/* na otestovani 2 pointery na enum typ autentizace 3. NULL-term. */
        user_attrs.authn_type = (cfed_e_authn_type_t **)cfed_malloc(&s_context, 3 * sizeof(cfed_e_authn_type_t *));
        if (user_attrs.authn_type == NULL)
        {
                printf("nelze pridelit pamet pro pointer\n");
                return -1;
        }

        cfed_e_authn_type_t authn_type_formpass = CFED_AUTHN_TYPE_FORMPASS;
        user_attrs.authn_type[0] = &authn_type_formpass;
        cfed_e_authn_type_t authn_type_basic = CFED_AUTHN_TYPE_BASIC;
        user_attrs.authn_type[1] = &authn_type_basic;
        user_attrs.authn_type[2] = NULL;

        /* na otestovani 2 pointery na uzivatelovy credentials 3. NULL-term. */
        user_attrs.user_creds = (cfed_s_idp_attr_t **)cfed_malloc(&s_context, 3 * sizeof(cfed_s_idp_attr_t *));
        if (user_attrs.user_creds == NULL)
        {
                printf("nelze pridelit pamet pro pointer\n");
                return -1;
        }


	/*napln struktury*/
        cfed_s_idp_attr_t username;
	unsigned int uname_len=strlen(argv[3]);
        char uname [uname_len+1];
	strncpy(uname, argv[3], uname_len+1);
        username.authn_attr = CFED_AUTHN_ATTR_UNAME;
        username.value = uname;
        user_attrs.user_creds[0] = &username;

        cfed_s_idp_attr_t password;
	unsigned int pass_len=strlen(argv[4]);
        char pass [pass_len+1];
	strncpy(pass, argv[4], pass_len+1);
        password.authn_attr = CFED_AUTHN_ATTR_PASSWORD;
        password.value = pass;
        user_attrs.user_creds[1] = &password;
	
        user_attrs.authn_type[2] = NULL;


	/* pristup ke sluzbe */
       if (cfed_whole_round(&s_context, argv[1], argv[2], &user_attrs))
		printf("MAIN: cfed_whole_round skoncila chybou\n");
       else
		printf("\nCELE KOLO OK\n");
	/* vygeneruj par RSA klicu a ziskej certifikat verejneho klice*/ 
	if (cfed_get_new_cert(&s_context, "https://idp2.ics.muni.cz/idp/shibboleth", &user_attrs, "soubor_certifikat.txt", "soubor_soukromy"))
        	printf("\nnepodarilo se ziskat certifikat\n");
        else
		printf("\nCERTIFIKAT OK\n");
	/*vytahnuta funkcionalita, pouze zkontroluj authn udaje uzivatele u IdP (pevne SP v czTestFed)*/
	if (cfed_authn_only(&s_context, "https://idp2.ics.muni.cz/idp/shibboleth", &user_attrs))
		printf("\nNepodarilo se overit autentizacni informace\n");
	/* zkontroluj vysledek autentizace */
	if (s_context.result->authn_status)
		printf("\nAUTENTIZACE OK\n");

	/*vypis vsechny chybove hlasky*/
	if (s_context.error != NULL)
        	printf("\nerror msg:%s\n", s_context.error);
        cfed_cleanup(&s_context);
	cfed_free(&s_context, user_attrs.user_creds);
	cfed_free(&s_context, user_attrs.authn_type);
        return 0;
}

/* Vypise nactene informace o idps z prislusnych struktur*/
void cfed_print_idps(cfed_s_context_t *p_ctx)
{
        if (p_ctx == NULL)
                return;

        int i=0;
        int j=0;
        /* seznam idps je prazdny */
        if (p_ctx->conf->idps == NULL)
        {
                cfed_make_err_msg (&(p_ctx->error), "cfed_print_idps: seznam idps je prazdny\n");
                return;
        }
        while (p_ctx->conf->idps[i] != NULL )
        {
                puts(p_ctx->conf->idps[i]->entity_id);
                puts(p_ctx->conf->idps[i]->url);
                printf("auth_type %d\n", p_ctx->conf->idps[i]->authn_type[0]); /*dodelat pro cely seznam*/
                printf("idp_type %d\n", p_ctx->conf->idps[i]->idp_type);
                if (p_ctx->conf->idps[i]->attrs != NULL)
                        while (p_ctx->conf->idps[i]->attrs[j] != NULL)
                        {
                                puts(p_ctx->conf->idps[i]->attrs[j]->value);
                                j++;
                        }
                        j=0;
                        i++;
        }
}

/* To same, ale pro sps */
static void cfed_print_sps(cfed_s_context_t *p_ctx)
{
        if (p_ctx == NULL)
                return;

        int i=0;
        int j=0;
        /* seznam sps je prazdny*/
        if (p_ctx->conf->sps == NULL)
        {
                cfed_make_err_msg (&(p_ctx->error), "cfed_print_idps: seznam idps je prazdny\n");
                return;
        }
        while (p_ctx->conf->sps[i] != NULL )
        {
                puts(p_ctx->conf->sps[i]->entity_id);
                puts(p_ctx->conf->sps[i]->url);
                if (p_ctx->conf->sps[i]->attrs != NULL)
                        while (p_ctx->conf->sps[i]->attrs[j] != NULL)
                        {
                                puts(p_ctx->conf->sps[i]->attrs[j]->value);
                                j++;
                        }
                        j=0;
                        i++;
        }
}
