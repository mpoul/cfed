/* cfed_cleanup.c
 * 
 * vycisti si po sobe pouzite struktury*/

#include "cfed.h"
#include <stdlib.h>

static void cfed_cleanup_idps (cfed_s_context_t *p_ctx);
static void cfed_cleanup_sps (cfed_s_context_t *p_ctx);

void cfed_cleanup(cfed_s_context_t *p_ctx)
{
        if (p_ctx == NULL)
                return;


        cfed_cleanup_idps (p_ctx);
        cfed_cleanup_sps (p_ctx);
        if (p_ctx->conf != NULL)
         	free (p_ctx->conf);
        if (p_ctx->error != NULL)
            free (p_ctx->error);


	/*libcurl cleanup*/
	curl_easy_cleanup(p_ctx->curl_handle);
        
}
/* uvolni pamet po seznamu struktur sidpconf */
static void cfed_cleanup_idps (cfed_s_context_t *p_ctx)
{
        if (p_ctx == NULL)
                return;

        int i=0;
        int j=0;


        if (p_ctx->conf && p_ctx->conf->idps)
        {  while (p_ctx->conf->idps[i] != NULL )
           {
                if (p_ctx->conf->idps[i]->attrs != NULL)
                /* uvolni pamet po seznamu atributu */
                { while (p_ctx->conf->idps[i]->attrs[j] != NULL)
                  {
                        cfed_free(p_ctx, p_ctx->conf->idps[i]->attrs[j]->value);
                        cfed_free(p_ctx, p_ctx->conf->idps[i]->attrs[j]);
                        j++;
                  }
                  /* NULL terminated */
                  /*cfed_free(p_ctx, p_ctx->conf->idps[i]->attrs[j]);*/         
                  /* uvolni pamet po 1 strukture sidpconf */
                  cfed_free(p_ctx, p_ctx->conf->idps[i]->entity_id);
                  cfed_free(p_ctx, p_ctx->conf->idps[i]->url);
                  cfed_free(p_ctx, p_ctx->conf->idps[i]->attrs);
                  cfed_free(p_ctx, p_ctx->conf->idps[i]);
                }
                  j=0;
                  i++;
           }
/* smaz!!!! prozkoumej jeste.      cfed_free(p_ctx, p_ctx->conf->idps[i]);
 *            uvolni pamet po poli ukazatelu*/
           cfed_free(p_ctx, p_ctx->conf->idps);
           p_ctx->conf->idps=NULL;
        }
}

/* uvolni pamet po seznamu struktur spconf */
static void cfed_cleanup_sps (cfed_s_context_t *p_ctx)
{
        if (p_ctx == NULL)
                return;

        int i=0;
        int j=0;
        if (p_ctx->conf->sps != NULL)
        {  while (p_ctx->conf->sps[i] != NULL )
           {
                if (p_ctx->conf->sps[i]->attrs != NULL)
                /* uvolni pamet po seznamu atributu */
                { while (p_ctx->conf->sps[i]->attrs[j] != NULL)
                  {
                        cfed_free(p_ctx, p_ctx->conf->sps[i]->attrs[j]->value);
                        cfed_free(p_ctx, p_ctx->conf->sps[i]->attrs[j]);
                        j++;
                  }
                  /* NULL terminated */
                  /* cfed_free(p_ctx, p_ctx->conf->sps[i]->attrs[j]); */          
                  /* uvolni pamet po 1 strukture sidpconf */
                  cfed_free(p_ctx, p_ctx->conf->sps[i]->entity_id);
                  cfed_free(p_ctx, p_ctx->conf->sps[i]->url);
                  cfed_free(p_ctx, p_ctx->conf->sps[i]->attrs);
                  cfed_free(p_ctx, p_ctx->conf->sps[i]);
                }
                  j=0;
                  i++;
           }
/* smaz!!!!        cfed_free(p_ctx, p_ctx->conf->sps[i]);
 *            uvolni pamet po poli ukazatelu */
           cfed_free(p_ctx, p_ctx->conf->sps);
           p_ctx->conf->sps=NULL;
        }
}
