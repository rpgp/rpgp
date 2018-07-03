/* Fake pinentry program for the OpenPGP test suite.
 *
 * Copyright (C) 2016 g10 code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

static FILE *log_stream;


static int
reply (const char *fmt, ...)
{
  int result;
  va_list ap;

  if (log_stream)
    {
      fprintf (log_stream, "> ");
      va_start (ap, fmt);
      vfprintf (log_stream, fmt, ap);
      va_end (ap);
    }
  va_start (ap, fmt);
  result = vprintf (fmt, ap);
  va_end (ap);

  fflush (stdout);
  return result;
}


/* Return the first line from FNAME, removing it from the file.  */
static char *
get_passphrase (const char *fname)
{
  char *passphrase = NULL;
  size_t fname_len;
  char *fname_new;
  FILE *source, *sink;
  char linebuf[80];

  fname_len = strlen (fname);
  fname_new = malloc (fname_len + 5);
  if (fname_new == NULL)
    {
      perror ("malloc");
      exit (1);
    }
  snprintf (fname_new, fname_len + 5, "%s.new", fname);

  source = fopen (fname, "r");
  if (! source)
    {
      perror (fname);
      exit (1);
    }

  sink = fopen (fname_new, "w");
  if (! sink)
    {
      perror (fname_new);
      exit (1);
    }

  while (fgets (linebuf, sizeof linebuf, source))
    {
      linebuf[sizeof linebuf - 1] = 0;
      if (passphrase == NULL)
        {
          passphrase = strdup (linebuf);
          if (passphrase == NULL)
            {
              perror ("strdup");
              exit (1);
            }
        }
      else
        fputs (linebuf, sink);
    }

  if (ferror (source))
    {
      perror (fname);
      exit (1);
    }

  if (ferror (sink))
    {
      perror (fname_new);
      exit (1);
    }

  fclose (source);
  fclose (sink);
  if (remove (fname))
    {
      fprintf (stderr, "Failed to remove %s: %s",
               fname, strerror (errno));
      exit (1);
    }

  if (rename (fname_new, fname))
    {
      fprintf (stderr, "Failed to rename %s to %s: %s",
               fname, fname_new, strerror (errno));
      exit (1);
    }

  free (fname_new);
  return passphrase;
}


#define whitespacep(p)   (*(p) == ' ' || *(p) == '\t' \
                          || *(p) == '\r' || *(p) == '\n')

/* rstrip line.  */
static void
rstrip (char *buffer)
{
  char *p;
  if (!*buffer)
    return; /* This is to avoid p = buffer - 1 */
  for (p = buffer + strlen (buffer) - 1; p >= buffer; p--)
    {
      if (! whitespacep (p))
        break;
      *p = 0;
    }
}


/* Skip over options in LINE.

   Blanks after the options are also removed.  Options are indicated
   by two leading dashes followed by a string consisting of non-space
   characters.  The special option "--" indicates an explicit end of
   options; all what follows will not be considered an option.  The
   first no-option string also indicates the end of option parsing. */
char *
skip_options (const char *line)
{
  while (whitespacep (line))
    line++;
  while (*line == '-' && line[1] == '-')
    {
      while (*line && !whitespacep (line))
        line++;
      while (whitespacep (line))
        line++;
    }
  return (char*) line;
}


/* Return a pointer to the argument of the option with NAME.  If such
   an option is not given, NULL is returned. */
char *
option_value (const char *line, const char *name)
{
  char *s;
  int n = strlen (name);

  s = strstr (line, name);
  if (s && s >= skip_options (line))
    return NULL;
  if (s && (s == line || whitespacep (s-1))
      && s[n] && (whitespacep (s+n) || s[n] == '='))
    {
      s += n + 1;
      s += strspn (s, " ");
      if (*s && !whitespacep(s))
        return s;
    }
  return NULL;
}

int
main (int argc, char **argv)
{
  char *args;
  char *option_user_data = NULL;
  int got_environment_user_data;
  char *logfile;
  char *passphrasefile;
  char *passphrase;

  /* We get our options via PINENTRY_USER_DATA.  */
  (void) argc, (void) argv;

  setvbuf (stdin, NULL, _IOLBF, BUFSIZ);
  setvbuf (stdout, NULL, _IOLBF, BUFSIZ);

  args = getenv ("PINENTRY_USER_DATA");
  got_environment_user_data = !!args;
  if (! args)
    args = "";

 restart:
  logfile = option_value (args, "--logfile");
  if (logfile)
    {
      char *p = logfile, more;
      while (*p && ! whitespacep (p))
        p++;
      more = !! *p;
      *p = 0;
      args = more ? p+1 : p;

      log_stream = fopen (logfile, "a");
      if (! log_stream)
        {
          perror (logfile);
          return 1;
        }
    }

  passphrasefile = option_value (args, "--passphrasefile");
  if (passphrasefile)
    {
      char *p = passphrasefile, more;
      while (*p && ! whitespacep (p))
        p++;
      more = !! *p;
      *p = 0;
      args = more ? p+1 : p;

      passphrase = get_passphrase (passphrasefile);
      if (! passphrase)
        {
          reply ("# Passphrasefile '%s' is empty.  Terminating.\n",
                 passphrasefile);
          return 1;
        }

      rstrip (passphrase);
    }
  else
    {
      passphrase = skip_options (args);
      if (*passphrase == 0)
        passphrase = "no PINENTRY_USER_DATA -- using default passphrase";
    }

  reply ("# fake-pinentry(%u) started.  Passphrase='%s'.\n",
         (unsigned int)getpid (), passphrase);
  reply ("OK - what's up?\n");

  while (! feof (stdin))
    {
      char buffer[1024];

      if (fgets (buffer, sizeof buffer, stdin) == NULL)
	break;

      if (log_stream)
        fprintf (log_stream, "< %s", buffer);

      rstrip (buffer);

#define OPT_USER_DATA	"OPTION pinentry-user-data="

      if (strncmp (buffer, "GETPIN", 6) == 0)
        reply ("D %s\n", passphrase);
      else if (strncmp (buffer, "BYE", 3) == 0)
	{
	  reply ("OK\n");
	  break;
	}
      else if (strncmp (buffer, OPT_USER_DATA, strlen (OPT_USER_DATA)) == 0)
        {
          if (got_environment_user_data)
            {
              reply ("OK - I already got the data from the environment.\n");
              continue;
            }

          if (log_stream)
            fclose (log_stream);
          log_stream = NULL;
          free (option_user_data);
          option_user_data = args = strdup (buffer + strlen (OPT_USER_DATA));
          goto restart;
        }

      reply ("OK\n");
    }

#undef OPT_USER_DATA

  reply ("# Connection terminated.\n");
  if (log_stream)
    fclose (log_stream);

  free (option_user_data);
  return 0;
}
