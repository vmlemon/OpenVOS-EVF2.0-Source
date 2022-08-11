/*  +++begin copyright+++ *******************************************  */
/*                                                                     */
/*  COPYRIGHT (c) 1995, 1996 Stratus Computer, Inc.                    */
/*  All Rights Reserved.                                               */
/*                                                                     */
/*  This program is the property of Stratus Computer, Inc.             */
/*  Permission is granted to use and modify this program.  Permission  */
/*  is granted to redistribute this program as long as this notice is  */
/*  intact, no fee is charged, and all original files are distributed  */
/*  intact.                                                            */
/*                                                                     */
/*  THIS INFORMATION IS PROVIDED ON AN "AS IS" BASIS WITHOUT WARRANTY  */
/*  OR SUPPORT OF ANY KIND.  STRATUS SPECIFICALLY DISCLAIMS ANY        */
/*  IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY           */
/*  PARTICULAR PURPOSE.  IN NO EVENT SHALL STRATUS COMPUTER OR ITS     */
/*  SUPPLIERS BE LIABLE FOR ANY DAMAGES WHATSOEVER INCLUDING DIRECT,   */
/*  INDIRECT, INCIDENTAL, CONSEQUENTIAL, LOSS OF BUSINESS PROFITS OR   */
/*  SPECIAL DAMAGES, EVEN IF STRATUS COMPUTER OR ITS SUPPLIERS HAVE    */
/*  BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.  SOME STATES DO   */
/*  NOT ALLOW THE EXCLUSION OR LIMITATION OF LIABILITY FOR             */
/*  CONSEQUENTIAL OR INCIDENTAL DAMAGES SO THE FOREGOING MAY NOT       */
/*  APPLY.  THIS DISCLAIMER APPLIES DESPITE ANY VERBAL                 */
/*  REPRESENTATIONS OF ANY KIND PROVIDED BY ANY STRATUS EMPLOYEE OR    */
/*  REPRESENTATIVE.                                                    */
/*                                                                     */
/*  +++end copyright+++ *********************************************  */

/*
 *   encode_vos_file - VOS Command Line wrapper for u$encode_vos_file()
 *
 *   Written by Tom Mallory, Stratus Computer, Inc
 *
 *   Modified 96-05-24 by mcp@admin.chcc.com to pull decode and encode into
 *                                           a single program module file
 *            96-03-09 by mcp@admin.chcc.com to add -base64
 *                                           and make ansi (cc) compatible
 *            96-01-25 by mcp@admin.chcc.com to add -output_sequential
 *                                           and allow destination to be a dir
 *   Notes:
 *
 *   This source, encode_vos_file, when compiled and bound, produces a single
 *   .pm file containing code for both encode_vos_file and decode_vos_file.
 *   Separate binding of decode_vos_file is not necessary; just copy or link
 *   encode_vos_file.pm to decode_vos_file.pm to obtain that functionality.
 *
 *   In situations where a compiled .pm file must be transported over a
 *   modem connection, it is only necessary to transfer encode_vos_file.pm,
 *   then copy the .pm to create decode_vos_file.pm at the destination site.
 *
 */

#include  <stdio.h>
#include  <stdlib.h>
#include  <string.h>                                                 /* ansi */

#include  "vostypes.h"
#include  "u$encode_vos_file.h"

#define   DIR_TYPE 2                                                  /* mcp */

static object_t     MyName = "encode_vos_file";

short               e$bad_pathname;                                   /* mcp */

void encode_vos_file()                                               /* ansi */
{
short     Code, Encode, Overwrite, TextFile, NoHeader, Options;
path_t    SourceFile, DestinationFile;
line_t    ErrorLine;
char      Source[300], Destination[300], ErrorText[300];

/*   --vv-- addition --vv--                                           /* mcp */

short     Sequential, Base64;
module_t  Module;
path_t    DestinationPath;
short     DestinationType;
char      *FileName, *Temp;

extern void s$error();
extern void s$get_arg();
extern void s$parse_command();
extern void s$where_path();
extern void decode_vos_file();

     /* Get command name from the entered commmand line */
     s$get_arg(&(short)0, &SourceFile, &Code);
     strcpy_nstr_vstr(Source, &SourceFile);

     /* Extract just the object_name part of the command line */
     FileName = strrchr(Source, '>');
     if (FileName != NULL)
        FileName++;                  /* Object Name part of pathname */
     else
        FileName = Source;           /* Simple Command */

     /* Check also for weird pathname tricks */
     Temp = strrchr(FileName, '<');
     if (Temp != NULL)
        FileName = Temp + 1;

     /* When accessed as decode_vos_file, go do that */
     if (!strncmp(FileName, "decode", 6))
     {
        decode_vos_file();
        return;
     }
/*   --^^-- endadd --^^--                                             /* mcp */

     s$parse_command(&MyName, &Code,
          &(line_t)"source_file:pathname, req", &SourceFile,
          &(line_t)"destination:pathname", &DestinationFile,
          &(line_t)"switch(encode),=0", &Encode,
          &(line_t)"switch(base64),=0", &Base64,                      /* mcp */
          &(line_t)"switch(file_is_text),=0", &TextFile,
          &(line_t)"switch(no_header),=0", &NoHeader,
          &(line_t)"switch(overwrite),=1", &Overwrite,
          &(line_t)"switch(output_sequential),=0", &Sequential,       /* mcp */
          &(object_t)"end");
     if (Code)
          return;

     strcpy_nstr_vstr(Source, &SourceFile);                          /* ansi */
     if (strlen_vstr(&DestinationFile))                              /* ansi */
          strcpy_nstr_vstr(Destination, &DestinationFile);           /* ansi */
     else strcpy(Destination, Source);

/*   --vv-- addition --vv--                                           /* mcp */

/*   when destination is a dir, put source object's name in it */

     if (strlen_vstr(&DestinationFile))  
     {
        s$where_path(&DestinationFile, &DestinationPath,
                     &DestinationType, &Module, &Code);
        if (!Code && DestinationType == DIR_TYPE)
        {
           FileName = strrchr(Source, '>'); /* After last dir */
           if (FileName == NULL)
           {
              s$error(&e$bad_pathname, &MyName, &SourceFile);
              return;
           }
           strcat_vstr_nstr(&DestinationPath, FileName);
           strcpy_nstr_vstr(Destination, &DestinationPath);
        }
     }
/*   --^^-- endadd --^^--                                             /* mcp */

     Options = 0;
     if (Encode)
          Options |= EVF_OPTION_ENCODE;
     if (Base64)                                                      /* mcp */
          Options |= EVF_OPTION_BASE64;                               /* mcp */
     if (TextFile) {
          Options |= EVF_OPTION_FILE_IS_TEXT;
/* mcp    if (NoHeader) */
          if (NoHeader && (!Sequential || Encode || Base64))          /* mcp */
               Options |= EVF_OPTION_NO_HEADER; /* Only if TextFile */
          }
     if (!Overwrite)
          Options |= EVF_OPTION_DONT_OVERWRITE;
     if (Sequential)                                                  /* mcp */
          Options |= EVF_OPTION_OUTPUT_SEQUENTIAL;                    /* mcp */

     u$encode_vos_file(Source, Destination, &Options, ErrorText, &Code);
     if (Code) {
          strcpy_vstr_nstr(&ErrorLine, ErrorText);                   /* ansi */
          s$error(&Code, &MyName, &ErrorLine);
          }
}
