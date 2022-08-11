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
 *   decode_vos_file - VOS Command Line wrapper for u$decode_vos_file()
 *
 *   Written by Tom Mallory, Stratus Computer, Inc
 *
 *   Modified 96-03-09 by mcp@admin.chcc.com to add -tell
 *                                           and make ansi (cc) compatible
 */

#include  <stdio.h>
#include  <stdlib.h>
#include  <string.h>                                                 /* ansi */

#include  "vostypes.h"
#include  "u$encode_vos_file.h"

static object_t     MyName = "decode_vos_file";

void decode_vos_file()                                               /* ansi */
{
extern void s$parse_command();                                       /* ansi */
extern void s$error();                                               /* ansi */

short     Code, Overwrite, Options;
short     Tell;                                                       /* mcp */
path_t    SourceFile, DestinationDir;
line_t    ErrorLine;
char      Source[300], Destination[300], ErrorText[300];

     s$parse_command(&MyName, &Code,
          &(line_t)"source_file:pathname, req", &SourceFile,
          &(line_t)"destination_dir:pathname", &DestinationDir,
          &(line_t)"switch(overwrite),=1", &Overwrite,
          &(line_t)"switch(tell),=0", &Tell,                          /* mcp */
          &(object_t)"end");
     if (Code)
          return;

     strcpy_nstr_vstr(Source, &SourceFile);                          /* ansi */
     strcpy_nstr_vstr(Destination, &DestinationDir);                 /* ansi */

     Options = 0;
     if (!Overwrite)
          Options |= EVF_OPTION_DONT_OVERWRITE;

     if (Tell)                                                        /* mcp */
          Options |= EVF_OPTION_TELL;                                 /* mcp */

     u$decode_vos_file(Source, Destination, &Options, ErrorText, &Code);
     if (Code) {
          strcpy_vstr_nstr(&ErrorLine, ErrorText);                   /* ansi */
          s$error(&Code, &MyName, &ErrorLine);
          }
}
