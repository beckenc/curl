/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/*
 * The Strict-Transport-Security header is defined in RFC 6797:
 * https://tools.ietf.org/html/rfc6797
 */
#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && defined(USE_HSTS)
#include <curl/curl.h>
#include "urldata.h"
#include "llist.h"
#include "hsts.h"
#include "curl_get_line.h"
#include "strcase.h"
#include "sendf.h"
#include "strtoofft.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifdef DEBUGBUILD
/* to play well with debug builds, we can *set* a fixed time this will
   return */
time_t deltatime; /* allow for "adjustments" for unit test purposes */
static time_t debugtime(void *unused)
{
  char *timestr = getenv("CURL_TIME");
  (void)unused;
  if(timestr) {
    unsigned long val = strtol(timestr, NULL, 10) + deltatime;
    return (time_t)val;
  }
  return time(NULL);
}
#define time(x) debugtime(x)
#endif

struct hsts *Curl_hsts_init(void)
{
  struct hsts *h = calloc(sizeof(struct hsts), 1);
  if(h) {
    Curl_llist_init(&h->list, NULL);
  }
  return h;
}

static void hsts_free(struct stsentry *e)
{
  free((char *)e->host);
  free(e);
}

void Curl_hsts_cleanup(struct hsts **hp)
{
  struct hsts *h = *hp;
  if(h) {
    struct Curl_llist_element *e;
    struct Curl_llist_element *n;
    for(e = h->list.head; e; e = n) {
      struct stsentry *sts = e->ptr;
      n = e->next;
      hsts_free(sts);
    }
    free(h);
    *hp = NULL;
  }
}

static struct stsentry *hsts_entry(void)
{
  return calloc(sizeof(struct stsentry), 1);
}

CURLcode Curl_hsts_parse(struct hsts *h, const char *hostname,
                         const char *header)
{
  const char *p = header;
  curl_off_t expires = 0;
  bool gotma = FALSE;
  bool gotinc = FALSE;
  bool subdomains = FALSE;
  struct stsentry *sts;
  time_t now = time(NULL);

  do {
    while(*p && ISSPACE(*p))
      p++;
    if(Curl_strncasecompare("max-age=", p, 8)) {
      bool quoted = FALSE;
      CURLofft offt;
      char *endp;

      if(gotma)
        return CURLE_BAD_FUNCTION_ARGUMENT;

      p += 8;
      while(*p && ISSPACE(*p))
        p++;
      if(*p == '\"') {
        p++;
        quoted = TRUE;
      }
      offt = curlx_strtoofft(p, &endp, 10, &expires);
      if(offt == CURL_OFFT_FLOW)
        expires = CURL_OFF_T_MAX;
      else if(offt)
        /* invalid max-age */
        return CURLE_BAD_FUNCTION_ARGUMENT;
      p = endp;
      if(quoted) {
        if(*p != '\"')
          return CURLE_BAD_FUNCTION_ARGUMENT;
        p++;
      }
      gotma = TRUE;
    }
    else if(Curl_strncasecompare("includesubdomains", p, 17)) {
      if(gotinc)
        return CURLE_BAD_FUNCTION_ARGUMENT;
      subdomains = TRUE;
      p += 17;
      gotinc = TRUE;
    }
    else {
      /* unknown directive, do a lame attempt to skip */
      while(*p && (*p != ';'))
        p++;
    }

    while(*p && ISSPACE(*p))
      p++;
    if(*p == ';')
      p++;
  } while (*p);

  if(!gotma)
    /* max-age is mandatory */
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(!expires) {
    /* remove the entry if present verbatim (without subdomain match) */
    sts = Curl_hsts(h, hostname, FALSE);
    if(sts) {
      Curl_llist_remove(&h->list, &sts->node, NULL);
      hsts_free(sts);
    }
    return CURLE_OK;
  }

  if(CURL_OFF_T_MAX - now < expires)
    /* would overflow, use maximum value */
    expires = CURL_OFF_T_MAX;
  else
    expires += now;

  /* check if it already exists */
  sts = Curl_hsts(h, hostname, FALSE);
  if(sts) {
    /* just update these fields */
    sts->expires = expires;
    sts->includeSubDomains = subdomains;
  }
  else {
    sts = hsts_entry();
    if(!sts)
      return CURLE_OUT_OF_MEMORY;

    sts->expires = expires;
    sts->includeSubDomains = subdomains;
    sts->host = strdup(hostname);
    if(!sts->host) {
      free(sts);
      return CURLE_OUT_OF_MEMORY;
    }
    Curl_llist_insert_next(&h->list, h->list.tail, sts, &sts->node);
  }

  return CURLE_OK;
}

/*
 * Return TRUE if the given host name is currently an HSTS one.
 *
 * The 'subdomain' argument tells the function if subdomain matching should be
 * attempted.
 */
struct stsentry *Curl_hsts(struct hsts *h, const char *hostname,
                           bool subdomain)
{
  if(h) {
    time_t now = time(NULL);
    size_t hlen = strlen(hostname);
    struct Curl_llist_element *e;
    struct Curl_llist_element *n;
    for(e = h->list.head; e; e = n) {
      struct stsentry *sts = e->ptr;
      n = e->next;
      if(sts->expires <= now) {
        /* remove expired entries */
        Curl_llist_remove(&h->list, &sts->node, NULL);
        hsts_free(sts);
        continue;
      }
      if(subdomain && sts->includeSubDomains) {
        size_t ntail = strlen(sts->host);
        if(ntail <= hlen) {
          size_t offs = hlen - ntail;
          if(Curl_strncasecompare(&hostname[offs], sts->host, ntail))
            return sts;
        }
      }
      else if(Curl_strcasecompare(hostname, sts->host))
        return sts;
    }
  }
  return NULL; /* no match */
}

#endif /* CURL_DISABLE_HTTP || USE_HSTS */
