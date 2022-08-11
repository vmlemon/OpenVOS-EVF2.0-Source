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
      *   u$encode_vos_file() and u$decode_vos_file() are routines used to
      *   encapsulate/decapsulate and optionally encode/decode VOS files for
      *   transport to non-VOS systems possibly over a non 8-bit transport
      *   medium (i.e. SMTP).
      *
      *   Written By Tom Mallory, Stratus Computer, Inc  1995
      *
      *   Modified 96-05-02 by mcp@admin.chcc.com
      *      decode: better parsing of MIME headers from Netscape and aol
      *              MIME ignore spurious trailing cr and/or spaces
      *              improve -tell for use in unbundle macro
      *   Modified 96-03-09 by mcp@admin.chcc.com
      *              add MIME base64 translation type
      *              make ansi (cc) compatible
      *   Modified 96-01-20 by mcp@admin.chcc.com
      *      decode: fix intermittent e$file_format_error reading "end" line
      *              add source or destination pathname to error message text
      *              add seq_encoded translation type
      *      encode: fix encapsulate error on files with records >=32766 bytes
      *              fix adding .evf to destination when it is already there
      *              add -output_sequential, and seq_encoded translation type
      *              add source or destination pathname to error message text
      *              return unique error code for indexed and pipe files
      *
      *   Notes:
      *
      *   Encapsulation occurs only on VOS sequential and relative files.
      *   VOS fixed and stream files are supported, but no encapsulation is
      *   required.  A two byte length field is added before each record
      *   to indicate the size of the record.  The bytes are in big endian
      *   order (high byte, then low byte).  The end of the file is signaled
      *   by a length field equal to -1 (0xffff).
      *
      *   Optional encoding/decoding is performed in the same manner as the
      *   UNIX utilities uuencode and uudecode.  The file format is
      *   compatible, but if a VOS sequential or relative file is uuencoded,
      *   the resulting file will still have the encapsulation information
      *   in it.
      *
      *   Optional MIME base64 encoding/decoding is performed in the same
      *   manner as the MIME standard for internet mailers.  Standard MIME
      *   application/octet-stream file attachment headers are used, but a
      *   full email message (including subject lines, etc.) is not produced.
      *
      *   u$encode_vos_file writes an additional line to the output file before
      *   the uuencode 'begin' line to carry the extra information.  UNIX
      *   uudecode ignores all lines until it sees a line that starts with
      *   'begin' so the extra line won't hurt anything.
      *
      *   The extra line is formatted as follows:
      *
      *   VOS <file_name> <sequential|relative|fixed|stream> <record_size>
      *      [encapsulated|not_encapsulated]
      *      [encoded|not_encoded|seq_encoded|base64_encoded]
      *
      *   If other attributes are required to be preserved (queues, files
      *   with indexes, sparsely populated files, etc), then use the VOS save
      *   utility to write a save file to disk (it is a plain sequential
      *   file) and then use u$encode_vos_files to prepare the save file for
      *   transfer.
      *
      *   When decoding files, the VOS header is used to obtain the file org,
      *   record size, and original file name.  The original file name is
      *   recreated in the destination dir, even when the encoded file has
      *   been renamed.
      *
      *   The ENCODE and BASE64 options are compatible with uuencode and
      *   MIME base64 encoding as implemented on other systems.  When such
      *   files are decoded, the uuencode or MIME headers are used to
      *   reconstruct the file, since no VOS header will be present.
      *   The file org will always be "stream" and the file name will come
      *   from the headers, if one is present.  The uuencode header will
      *   always contain a file name, but MIME headers may or may not.  If
      *   no file name is found, one is constructed by dropping the last
      *   suffix from the encoded file's name, and adding .DECODE to it.
      *   If more than one file name is present in valid headers, the first
      *   one found is used.
      *
      *   OUTPUT SEQUENTIAL option
      *
      *   Unix systems, and unix-like utilities (such as gzip and ftp)
      *   treat all files as streams and require VOS files to be in stream
      *   file format.  The output (destination) file from encode_vos_file
      *   is normally stream to allow VOS files to pass through unix systems.
      *   The Stratus file transfer utility remote_request, however, does
      *   not handle stream files (see rsn-745 and css-1304 for details).
      *   The published avoidance for rsn-745 is to use SAVE to convert the
      *   stream file to sequential.  The output from SAVE, however, is very
      *   long (>20000 byte) records which can cause some modem connections
      *   to fail.  To allow output from gzip to be sent via RSN using
      *   remote_request, the OUTPUT SEQUENTIAL option can be used to make
      *   the destination a sequential file with short (61 byte) records.
      *
      *   When ENCODE or BASE64 is used, the output is short ascii records
      *   which can be stored equally well in a stream or sequential file.
      *   OUTPUT SEQUENTIAL produces no change in the data when ENCODE or
      *   BASE64 is used; the destination file is just changed to sequential.
      *
      *   When ENCODE and BASE64 are not used, the output is a continuous
      *   stream of bytes with no record separators.  This format is not
      *   compatible with a sequential file.  Using OUTPUT SEQUENTIAL in
      *   this instance breaks the data stream into arbitrary short records
      *   which are layed down into a sequential output file.  This format
      *   is called seq_encoding and does not expand the file size as much
      *   as using ENCODE or BASE64 because it does not convert binary data
      *   to ascii.
      *
      *   DESTINATION FILE FORMATS
      *
      *   There are 8 possible combinations of encapuslation/encoding layouts
      *   as follows:
      *
      *   Encapsulated                          
      *   yes = rel,seq   Uuencoded  MIME-Base64   -output_
      *   no  = fix,stm    -encode    -base64     sequential
      *   -------------   ----------   ------     ----------
      *        no             no         no           no        format 1
      *        no             yes        no         yes/no      format 2
      *        no             no         yes        yes/no      format 3
      *        yes            no         no           no        format 4
      *        yes            yes        no         yes/no      format 5
      *        yes            no         yes        yes/no      format 6
      *        no             no         no           yes       format 7
      *        yes            no         no           yes       format 8
      *
      *   (1) Not Encapsulated, Not Encoded (fixed or stream file, ENCODE
      *       option off, BASE64 option off, OUTPUT SEQUENTIAL option off):
      *
      *        <VOS Header>
      *        <raw file data until EOF>
      *
      *   (2) Not Encapsulated, Encoded (fixed or stream file, ENCODE option
      *       on, BASE64 option off, OUTPUT SEQUENTIAL option on or off):
      *
      *        <VOS Header>              | OUTPUT SEQUENTIAL option off
      *        <UUENCODE header>         | produces a stream destination file,
      *        <encoded file data>       | on produces a sequential file.
      *        <UUENCODED null record>   | Data contents are the same for
      *        <UUENCODE trailer>        | stream or seq destination file.
      *
      *   (3) Not Encapsulated, MIME Base64 Encoded (fixed or stream file,
      *       BASE64 option on, (ENCODE option ignored) OUTPUT SEQUENTIAL
      *       option on or off):
      *
      *        <VOS Header>              | OUTPUT SEQUENTIAL option off
      *        <MIME separator>          | produces a stream destination
      *        <MIME header>             | file.
      *        <MIME header>             |
      *        <MIME header>             | OUTPUT SEQUENTIAL on produces a
      *        <null record>             | sequential file.  Data contents
      *        <encoded file data>       | are the same for stream or seq
      *        <MIME separator>          | destination files.
      *
      *   (4) Encapsulated, Not Encoded (sequential or relative file, ENCODE
      *       option off, BASE64 option off, OUTPUT SEQUENTIAL option off):
      *
      *        <VOS Header>
      *        <record len><raw record data>...
      *        <record len == 0xffff>
      *
      *   (5) Encapsulated, Encoded (sequential or relative file, ENCODE
      *       option on, OUTPUT SEQUENTIAL option on or off):
      *
      *        <VOS Header>                   | OUTPUT SEQUENTIAL option off
      *        <UUENCODE header>              | produces a stream dest file,
      *        <encoded file data of          | on produces a sequential file.
      *             <record len><raw record data>...
      *             <record len == 0xffff>
      *        <UUENCODED null record>        | Data contents are the same for
      *        <UUENCODE trailer>             | stream or seq destination file.
      *
      *   (6) Encapsulated, MIME Base64 Encoded (sequential or relative file,
      *       BASE64 option on, (ENCODE option ignored) OUTPUT SEQUENTIAL
      *       option on or off):
      *
      *        <VOS Header>                   | OUTPUT SEQUENTIAL option off
      *        <MIME separator>               | produces a stream destination
      *        <MIME header>                  | file.
      *        <MIME header>                  |
      *        <MIME header>                  | OUTPUT SEQUENTIAL option on
      *        <null record>                  | produces a sequential file.
      *        <encoded file data of          |
      *             <record len><raw record data>...
      *             <record len == 0xffff>    | Data contents are the same for
      *        <MIME separator>               | stream or seq destination file.
      *
      *   (7) Not Encapsulated, Seq Encoded (fixed or stream file, ENCODE
      *       option off, BASE64 option off, OUTPUT SEQUENTIAL option on):
      *
      *        <VOS Header>
      *        <seq_encoded file data>
      *        <null record>
      *        <"end" trailer>
      *
      *   (8) Encapsulated, Seq Encoded (sequential or relative file, ENCODE
      *       option off, BASE64 option off, OUTPUT SEQUENTIAL option on):
      *
      *        <VOS Header>
      *        <seq_encoded file data of 
      *             <record len><raw record data>...
      *             <record len == 0xffff>
      *        <null record>
      *        <"end" trailer>
      *
      */

     /*   Constants */

#include  "system_io_constants.incl.c"                               /* ansi */
#include  "file_status_info.incl.c"                                  /* ansi */
#include  "vostypes.h"

#include  "u$encode_vos_file.h"

#include  <stdio.h>                                                  /* ansi */
#include  <string.h>
#include  <stdlib.h>
#include  <ctype.h>                                                   /* mcp */

#define   MAX_RECORD_SIZE               32767
#define   MAX_WORK_AREA_SIZE            256
#define   MAX_SOURCE_BYTES_PER_LINE     45
#define   MAX_DEST_BYTES_FOR_UUE        61                            /* mcp */
#define   MAX_DEST_BYTES_FOR_SEQ        61                            /* mcp */
#define   MAX_DEST_BYTES_FOR_B64        72                            /* mcp */

short     e$bad_pathname, e$invalid_file_type, e$file_exists, 
          e$object_not_found, e$no_alloc, e$end_of_file, e$file_format_error;

/* --vv-- addition --vv--                                                mcp */

extern void s$attach_port();
extern void s$close();
extern void s$delete_file();
extern void s$detach_port();
extern void s$expand_path();
extern void s$get_current_dir();
extern void s$get_file_status();
extern void s$open();
extern void s$read_raw();
extern void s$seq_open();
extern void s$seq_position();
extern void s$seq_read();
extern void s$seq_write();
extern void s$write_raw();

short     e$invalid_if_indexed, e$invalid_pipe_operation;
void      u$errcat(char *ErrorText, char *File);

static char Quote[2] = { '"', '\0' };
static char Base64[66] 
       ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/* --^^-- endadd --^^--                                                  mcp */

void u$encode_vos_file(char *Source, char *Destination, short *Options,
                       char *ErrorText, short *Code)
{
short     SrcPortId, DestPortId, Encapsulate, Encode, StreamFile;
/*
 * mcp  short     InputBytesLeft, PrevByte, State, OutputBytesUsed, EOFFound;
 */
short     PrevByte, State, OutputBytesUsed, EOFFound;                 /* mcp */
short unsigned                                                        /* mcp */
          InputBytesLeft;                                             /* mcp */
short     InputBytesProcessed, FileRecordSize, TreatFileAsText;
short     FileOrganization;
short     DestOrg, OutSeq, MaxDestBytesPerLine;                       /* mcp */
char      *InputBuffer, *OutputBuffer, *FileName, FileType[32], *FileExt;
char      *Next;
char      DestPath[300], EncodeType[20];                              /* mcp */
path_t    TempPath;
FILE_STATUS_STRUCT
          FileStatus;


     FileName = strrchr(Source, '>'); /* After last dir */
     if (FileName == NULL)
          FileName = strrchr(Source, '#'); /* No dir, after disk */
     if (FileName == NULL) {
          *Code = e$bad_pathname;
          strcpy(ErrorText, Source);
          return;
          }
     FileName++;

     strcpy_vstr_nstr(&TempPath, Source);                            /* ansi */

     /*   See what kind of file this is */

     FileStatus.version = FILE_STAT_VERSION_1;
     s$get_file_status(&TempPath, &FileStatus, Code);
     if (*Code) {
          strcpy(ErrorText, "s$get_file_status Source");
          u$errcat(ErrorText, Source);                                /* mcp */
          return;
          }

     /*
      *   Check organization.  Only allow FIXED, REL, SEQ, or Stream and
      *   not a pipe file.  Also don't allow indexes.
      */

     strcpy(FileType, "");
     Encapsulate = 0;
     StreamFile = 0;

     if (FileStatus.file_organization == FIXED_FILE)
          strcpy(FileType, "fixed");
     else 
     if (FileStatus.file_organization == RELATIVE_FILE) {
          strcpy(FileType, "relative");
          Encapsulate = 1;
          }
     else
     if (FileStatus.file_organization == SEQUENTIAL_FILE) {
          strcpy(FileType, "sequential");
          Encapsulate = 1;
          }
     else
     if (FileStatus.file_organization == STREAM_FILE) {
          StreamFile = 1;
          strcpy(FileType, "stream");
          }
     else {
          strcpy(ErrorText, "s$get_file_status Source");
          u$errcat(ErrorText, Source);                                /* mcp */
          *Code = e$invalid_file_type;
          return;
          }

     if (FileStatus.flags_struct.flags_bits.pipe_file) {
/*
 * mcp    strcpy(ErrorText, "s$get_file_status Source is a pipe file");
 * mcp    *Code = e$invalid_file_type;
 */
          strcpy(ErrorText, "s$get_file_status");                     /* mcp */
          u$errcat(ErrorText, Source);                                /* mcp */
          *Code = e$invalid_pipe_operation;                           /* mcp */
          return;
          }

     if (FileStatus.num_indexes) {
/*
 * mcp    strcpy(ErrorText, "s$get_file_status Source has indexes");
 * mcp    *Code = e$invalid_file_type;
 */
          strcpy(ErrorText, "s$get_file_status");                     /* mcp */
          u$errcat(ErrorText, Source);                                /* mcp */
          *Code = e$invalid_if_indexed;                               /* mcp */
          return;
          }

     s$seq_open(&TempPath, &(short)INPUT_TYPE, &SrcPortId, Code);
     if (*Code) {
          strcpy(ErrorText, "s$seq_open Source");
          u$errcat(ErrorText, Source);                                /* mcp */
          return;
          }
/*
 * ansi     FileRecordSize = FileStatus.max_record_size;
 */
     FileRecordSize =                                                /* ansi */
         FileStatus.flags_struct.flags_bits_overlay.max_record_size; /* ansi */
     FileOrganization = FileStatus.file_organization;

     /*
      *   Open the destination file for output as a stream file.  If the file
      *   exists, delete it first (unless overridden)
      */

     strcpy_vstr_nstr(&TempPath, Destination);                       /* ansi */

     /*   Add the EVF_EXTENSION to the destination file if it isn't there */

     if (strlen(Destination) > strlen(EVF_FILE_EXTENSION)) {
/*
 * mcp     FileExt = Destination + strlen(Destination) -
 * mcp                            strlen(EVF_FILE_EXTENSION) + 1;
 */
          FileExt = Destination + strlen(Destination) -               /* mcp */
                                  strlen(EVF_FILE_EXTENSION);         /* mcp */
          if (strcmp(FileExt, EVF_FILE_EXTENSION))
               strcat_vstr_nstr(&TempPath, EVF_FILE_EXTENSION);      /* ansi */
          }
     else strcat_vstr_nstr(&TempPath, EVF_FILE_EXTENSION);           /* ansi */
     strcpy_nstr_vstr(DestPath, &TempPath);                           /* mcp */
     
     FileStatus.version = FILE_STAT_VERSION_1;
     s$get_file_status(&TempPath, &FileStatus, Code);
     if (*Code == 0) {
          if (*Options & EVF_OPTION_DONT_OVERWRITE) {
               *Code = e$file_exists;
               strcpy_nstr_vstr(ErrorText, &TempPath);               /* ansi */
               return;
               }

          s$delete_file(&TempPath, Code);
          if (*Code) {
               strcpy(ErrorText, "s$delete_file Destination");
               u$errcat(ErrorText, DestPath);                         /* mcp */
               return;
               }
          }
     else if (*Code != e$object_not_found) {
               strcpy(ErrorText, "s$get_file_status Destination");
               u$errcat(ErrorText, DestPath);                         /* mcp */
               return;
               }

     s$attach_port(&(object_t)"", &TempPath, &(short)0, &DestPortId, Code);
     if (*Code) {
          strcpy(ErrorText, "s$attach_port Destination");
          u$errcat(ErrorText, DestPath);                              /* mcp */
          return;
          }

/* mcp
 *   s$open(&DestPortId, &(short)STREAM_FILE, &(short)0, &(short)OUTPUT_TYPE,
 */     
     OutSeq = (*Options & EVF_OPTION_OUTPUT_SEQUENTIAL);              /* mcp */
     if (OutSeq)                                                      /* mcp */
          DestOrg = SEQUENTIAL_FILE;                                  /* mcp */
     else DestOrg = STREAM_FILE;                                      /* mcp */
     s$open(&DestPortId, &DestOrg, &(short)0, &(short)OUTPUT_TYPE,    /* mcp */
            &(short)SET_LOCK_DONT_WAIT, &(short)SEQUENTIAL_MODE,
            &(object_t)"", Code);
     if (*Code) {
          strcpy(ErrorText, "s$open Destination");
          u$errcat(ErrorText, DestPath);                              /* mcp */
          return;
          }

     if (*Options & EVF_OPTION_ENCODE)
          Encode = 1;
     else Encode = 0;

     if (*Options & EVF_OPTION_BASE64)                                /* mcp */
          Encode = 3;                                                 /* mcp */

/*   setup seq_encoding if -output_sequential and not -encode         /* mcp */
     if (!Encode && OutSeq)                                           /* mcp */
          Encode = 2;                                                 /* mcp */

     InputBuffer = (char *) malloc(MAX_RECORD_SIZE + 10);
     if (InputBuffer == NULL) {
          *Code = e$no_alloc;
          return;
          }

     OutputBuffer = (char *) malloc(MAX_WORK_AREA_SIZE);
     if (OutputBuffer == NULL) {
          *Code = e$no_alloc;
          return;
          }

     TreatFileAsText = 0;

     if ((*Options & EVF_OPTION_FILE_IS_TEXT) &&
         (FileOrganization == SEQUENTIAL_FILE ||
          FileOrganization == RELATIVE_FILE)) {

          /*   Convert file to stream format as we go. */

          strcpy(FileType, "stream");
          Encapsulate = 0; /* No need to encapsulate now */
          TreatFileAsText = 1;
          }

     if ((*Options & EVF_OPTION_NO_HEADER) == 0) {
          /*
           *   Write the VOS header first
           */

          if (Encode == 0) strcpy(EncodeType, "not_encoded");         /* mcp */
          if (Encode == 1) strcpy(EncodeType, "encoded");             /* mcp */
          if (Encode == 2) strcpy(EncodeType, "seq_encoded");         /* mcp */
          if (Encode == 3) strcpy(EncodeType, "base64_encoded");      /* mcp */

          sprintf(OutputBuffer, "VOS %s %s %d %s %s\n", FileName, FileType,
                    FileRecordSize,
                    Encapsulate ? "encapsulated" : "not_encapsulated",
/*
 * mcp              Encode      ? "encoded"      : "not_encoded");    
 */
                    EncodeType);                                      /* mcp */

/*        We change all the s$write_raw's to s$seq_writes because     /* mcp */
/*        s$seq_write will work for both stream and sequential        /* mcp */
/*        files.  With s$seq_write, VOS supplies the \n when going    /* mcp */
/*        to a stream file, so we do not have to put it into the      /* mcp */
/*        buffer explicitly and we must be sure to exclude the \n     /* mcp */
/*        if it is already there.  For sequential files, each         /* mcp */
/*        s$seq_write creates a new record, which is what we want.    /* mcp */

/*
 * mcp    s$write_raw(&DestPortId, &(short)(strlen(OutputBuffer)),
 * mcp                   OutputBuffer, Code);
 */
          s$seq_write(&DestPortId, &(short)(strlen(OutputBuffer)-1),  /* mcp */
                         OutputBuffer, Code);                         /* mcp */
          if (*Code) {
               free(InputBuffer);
               free(OutputBuffer);
/* mcp         strcpy(ErrorText, "s$write_raw VOS Header");  */
               strcpy(ErrorText, "s$seq_write VOS Header");           /* mcp */
               u$errcat(ErrorText, DestPath);                         /* mcp */
               return;
               }
          }

     /*
      *   If we are encoding, write the uuencode (UNIX) header
      */

/*
 * mcp  if (Encode) {        
 * mcp    sprintf(OutputBuffer, "begin %o %s\n", 0777, FileName);
 * mcp    s$write_raw(&DestPortId, &(short)(strlen(OutputBuffer)),
 * mcp                OutputBuffer, Code);
 */

/*   this header is for uuencode only */                              /* mcp */
     if (Encode == 1) {                                               /* mcp */
          strcpy(OutputBuffer, "begin 777 ");                         /* mcp */
          strcat(OutputBuffer, FileName);                             /* mcp */
          s$seq_write(&DestPortId, &(short)(strlen(OutputBuffer)),    /* mcp */
                      OutputBuffer, Code);                            /* mcp */
          if (*Code) {
               free(InputBuffer);
               free(OutputBuffer);
/* mcp         strcpy(ErrorText, "s$write_raw UNIX Header");  */
               strcpy(ErrorText, "s$seq_write UNIX Header");          /* mcp */
               u$errcat(ErrorText, DestPath);                         /* mcp */
               return;
               }
          }

/*   --vv-- addition --vv--                                              mcp */
/*
--EVF
Content-Type: application/octet-stream; name="STRATUS.KBD"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="STRATUS.KBD"
*/
     if (Encode == 3) {
        s$seq_write(&DestPortId, &(short)5, "--EVF", Code);
        if (!*Code) {
          strcpy(OutputBuffer,"Content-Type: application/octet-stream; name=");
          strcat(OutputBuffer, Quote);
          strcat(OutputBuffer, FileName);
          strcat(OutputBuffer, Quote);
          s$seq_write(&DestPortId, &(short)(strlen(OutputBuffer)),
                      OutputBuffer, Code);
          }
        if (!*Code) {
          strcpy(OutputBuffer,"Content-Transfer-Encoding: base64");
          s$seq_write(&DestPortId, &(short)(strlen(OutputBuffer)),
                      OutputBuffer, Code);
          }
        if (!*Code) {
          strcpy(OutputBuffer,"Content-Disposition: attachment; filename=");
          strcat(OutputBuffer, Quote);
          strcat(OutputBuffer, FileName);
          strcat(OutputBuffer, Quote);
          s$seq_write(&DestPortId, &(short)(strlen(OutputBuffer)),
                      OutputBuffer, Code);
          }
        if (!*Code)
          s$seq_write(&DestPortId, &(short)0, " ", Code);

        if (*Code) {
             free(InputBuffer);
             free(OutputBuffer);
             strcpy(ErrorText, "s$seq_write BASE64 Header");
             u$errcat(ErrorText, DestPath);
             return;
             }
        }         /* if (Encode == 3) */

/*        --^^-- endadd --^^--                                           mcp */

#define   EncodeByte(c) ( (c) ? ( ((c) & 0x3f) + 0x20) : 0x60)
#define   DecodeByte(c) ( ((c) - 0x20) & 0x3f)
#define   WriteByte(c)  OutputBuffer[OutputBytesUsed++] = EncodeByte(c);

#define   WriteB64(c)   OutputBuffer[OutputBytesUsed++] = Base64[c];  /* mcp */

     State = 0;
     OutputBytesUsed = 1; /* Reserved for encode record header */
     MaxDestBytesPerLine = MAX_DEST_BYTES_FOR_UUE;                    /* mcp */

/*   --vv-- addition --vv--                                              mcp */

     if (Encode == 2) {   /* setup for seq_encoding */
        State = 3;
        OutputBytesUsed = 0;
        MaxDestBytesPerLine = MAX_DEST_BYTES_FOR_SEQ;
        }

     if (Encode == 3) {   /* setup for base64 mime encoding */
        State = 4;
        OutputBytesUsed = 0;
        MaxDestBytesPerLine = MAX_DEST_BYTES_FOR_B64;
        }

/*   --^^-- endadd --^^--                                                mcp */

     InputBytesProcessed = 0;
     EOFFound = 0;

     while(!EOFFound) {
          if (StreamFile)
               s$read_raw(&SrcPortId, &(short)MAX_RECORD_SIZE, InputBuffer,
                          InputBuffer+2, Code);
          else s$seq_read(&SrcPortId, &(short)MAX_RECORD_SIZE, InputBuffer,
                          InputBuffer+2, Code);
          if (*Code == e$end_of_file) {
               if (Encapsulate)
                    EOFFound = 1;
               else break;
               }
          else if (*Code) {
                    free(InputBuffer);
                    free(OutputBuffer);
                    strcpy(ErrorText, "s$seq_read Source");
                    u$errcat(ErrorText, Source);                      /* mcp */
                    return;
                    }

          if (Encapsulate) {
               if (EOFFound) { /* Add the EOF indicator */
                    InputBuffer[0] = 0xff;
                    InputBuffer[1] = 0xff;
                    InputBytesLeft = 2;
                    }
               else {
                    InputBytesLeft = *(short *)InputBuffer;
                    InputBytesLeft += 2;
                    }
               Next = InputBuffer;
               }
          else {
               InputBytesLeft = *(short *)InputBuffer;
               Next = InputBuffer + 2;
               if (TreatFileAsText) {
                    /*   Add newline to VOS file to make it a stream file */
                    InputBuffer[InputBytesLeft+2] = '\n';
                    InputBytesLeft++;
                    }
               }

          if (!Encode) {

/*             --vv-- addition --vv--                                    mcp */
              /*
               * Adding encapsulated length made the record >32767
               * bytes.  We write 2 bytes here, then the rest.
               */
               if (InputBytesLeft > MAX_RECORD_SIZE) {
                  s$write_raw(&DestPortId, &(short)2, Next, Code);
                  if (*Code) {
                       free(InputBuffer);
                       free(OutputBuffer);
                       strcpy(ErrorText, "s$write_raw Overflow");
                       u$errcat(ErrorText, DestPath);
                       return;
                       }
                  Next += 2;
                  InputBytesLeft -= 2;
                  }

/*             --^^-- endadd --^^--                                      mcp */

               s$write_raw(&DestPortId, &InputBytesLeft, Next, Code);
               if (*Code) {
                    free(InputBuffer);
                    free(OutputBuffer);
                    strcpy(ErrorText, "s$write_raw Destination");
                    u$errcat(ErrorText, DestPath);                    /* mcp */
                    return;
                    }
               continue;
               }

          /*
           *   Encode.
           *
           *   Converts a sequence of 3 8 bit bytes to a sequence of
           *   4 6 bit bytes.  Each output line consists of 45 input bytes
           *   encoded into 60 output bytes.  Each line starts with an
           *   encoded 'length' field ( from 1 to 45 before encoding) so that
           *   each full line is always 62 bytes long (including the \n).
           *
           *   Base64 (Mime) encoding also converts a sequence of 3 8 bit
           *   bytes to a sequence of 4 6 bit bytes.  Each output line
           *   consists of 54 input bytes encoded into 72 output bytes.
           *   Base64 encode does NOT use a length field, so all 72 output
           *   bytes represent data from the input file.  A special alphabet
           *   is used to encode the 64 possible 6-bit combinations so that
           *   the output contains only upper and lowercase alpha, numerics,
           *   and the characters + and / with = or == being used to fill out
           *   the last one or two bytes if the source file is not an even
           *   multiple of 3 in length.
           *
           *   For seq_encoding the source data characters are laid out into
           *   61 byte sequential records without translation.
           */

          while(InputBytesLeft--) {
/*
/* mcp         if (InputBytesProcessed == MAX_SOURCE_BYTES_PER_LINE) {
/* mcp              /* The line is full, Write the encode length byte at the
/* mcp              *  front, add a \n to the end, and write it to the file */
/* mcp
 * mcp              *OutputBuffer = EncodeByte(InputBytesProcessed);
 * mcp
 * mcp              OutputBuffer[61] = '\n';
 * mcp              OutputBuffer[62] = 0;   
 * mcp              s$write_raw(&DestPortId, &(short)(strlen(OutputBuffer)),
 * mcp                          OutputBuffer, Code);
 */
               /* --vv-- addition --vv--                                 mcp */

               if (OutputBytesUsed == MaxDestBytesPerLine) {
                    /* The line is full, Write the encode length
                    /* byte at the front (only if uuencoding),
                    /* and write it to the file */

                    if (Encode == 1)
                       *OutputBuffer = EncodeByte(InputBytesProcessed);

                    s$seq_write(&DestPortId, &OutputBytesUsed,
                                OutputBuffer, Code);

               /* --^^-- endadd --^^--                                   mcp */

                    if (*Code) {
                         free(InputBuffer);
                         free(OutputBuffer);
/* mcp                   strcpy(ErrorText, "s$write_raw Destination"); */
                         strcpy(ErrorText, "s$seq_write Destination");/* mcp */
                         u$errcat(ErrorText, DestPath);               /* mcp */
                         return;
                         }
                    OutputBytesUsed = 1;
                    if (Encode > 1) OutputBytesUsed = 0;              /* mcp */
                    InputBytesProcessed = 0;
                    }

               switch(State) {
                    case 0: /* First byte. Use High 6 bits of this byte */
                         WriteByte( ((*Next    >> 2) & 0x3f));
                         PrevByte = *Next;
                         Next++;
                         State = 1;
                         break;

                    case 1: /* Second byte.  Use Low 2 bits of last byte +
                             * High 4 bits of this byte */
                         WriteByte( ((PrevByte << 4) & 0x30) |
                                    ((*Next    >> 4) & 0x0F));
                         PrevByte = *Next;
                         Next++;
                         State = 2;
                         break;

                    case 2: /* Third byte.  Use Low 4 bits of last byte +
                             * High 2 bits of this byte.  Then do low 6
                             * bits of this byte. */
                         WriteByte( ((PrevByte << 2) & 0x3C) |
                                    ((*Next    >> 6) & 0x03));
                         WriteByte( ((*Next        ) & 0x3f));
                         PrevByte = *Next;
                         Next++;
                         State = 0;
                         break;

/*                       --vv-- addition --vv--                          mcp */

                    case 3: /* seq_encoding.  Put in whole byte. */
                         OutputBuffer[OutputBytesUsed++] = *Next++;
                         break;

                    case 4: /* First byte. Use High 6 bits of this byte */
                         WriteB64( ((*Next    >> 2) & 0x3f));
                         PrevByte = *Next;
                         Next++;
                         State = 5;
                         break;

                    case 5: /* Second byte.  Use Low 2 bits of last byte +
                             * High 4 bits of this byte */
                         WriteB64( ((PrevByte << 4) & 0x30) |
                                    ((*Next    >> 4) & 0x0F));
                         PrevByte = *Next;
                         Next++;
                         State = 6;
                         break;

                    case 6: /* Third byte.  Use Low 4 bits of last byte +
                             * High 2 bits of this byte.  Then do low 6
                             * bits of this byte. */
                         WriteB64( ((PrevByte << 2) & 0x3C) |
                                    ((*Next    >> 6) & 0x03));
                         WriteB64( ((*Next        ) & 0x3f));
                         PrevByte = *Next;
                         Next++;
                         State = 4;
                         break;

/*                       --^^-- endadd --^^--                            mcp */
                    }

               InputBytesProcessed++;
               }
          }

     /*
      *   Write the trailer (if any)
      */

     if (Encode) {
          /*   Finish the sequence (if any) */

          if (State == 1) {
               WriteByte( ((PrevByte << 4) & 0x30));
               PrevByte = 0;
               State = 2;
               }

          if (State == 2) {
               WriteByte( ((PrevByte << 2) & 0x3C));
               WriteByte(0);
               }

/*        --vv-- addition --vv--                                         mcp */

          if (State == 5) {
               WriteB64( ((PrevByte << 4) & 0x30));
               WriteB64(64);    /* trailing = */
               WriteB64(64);    /* trailing = */
               }

          if (State == 6) {
               WriteB64( ((PrevByte << 2) & 0x3C));
               WriteB64(64);    /* trailing = */
               }

/*       --^^-- endadd --^^--                                            mcp */

          /*   Write the last data line */
/*
 * mcp    *OutputBuffer = EncodeByte(InputBytesProcessed);
 * mcp
 * mcp    OutputBuffer[OutputBytesUsed] = '\n';
 * mcp    OutputBuffer[OutputBytesUsed+1] = 0;
 * mcp    s$write_raw(&DestPortId, &(short)(strlen(OutputBuffer)),
 * mcp                OutputBuffer, Code);
 */
          if (Encode == 1)                                            /* mcp */
             *OutputBuffer = EncodeByte(InputBytesProcessed);         /* mcp */
                                                                      /* mcp */
          if (InputBytesProcessed)                                    /* mcp */
             s$seq_write(&DestPortId, &OutputBytesUsed,               /* mcp */
                         OutputBuffer, Code);                         /* mcp */
          else                                                        /* mcp */
             *Code = 0; /* the file being encoded was empty */        /* mcp */

             if (*Code) {
               free(InputBuffer);
               free(OutputBuffer);
/* mcp         strcpy(ErrorText, "s$write_raw Destination"); */
               strcpy(ErrorText, "s$seq_write Destination");          /* mcp */
               u$errcat(ErrorText, DestPath);                         /* mcp */
               return;
               }
/*
 * mcp    sprintf(OutputBuffer, "%c\nend\n", EncodeByte('\0'));
 * mcp
 * mcp    s$write_raw(&DestPortId, &(short)(strlen(OutputBuffer)),
 * mcp                OutputBuffer, Code);
 */

/*        --vv-- addition --vv--                                         mcp */

          switch(Encode) {

               case 1:   /* uuencode */
                    *OutputBuffer = EncodeByte('\0');
                    OutputBytesUsed = 1;
                    s$seq_write(&DestPortId, &OutputBytesUsed,
                                OutputBuffer, Code);
                    if (!*Code)
                       s$seq_write(&DestPortId, &(short)3, "end", Code);
                    break;

               case 2:   /* seq encode */
                    OutputBytesUsed = 0;
                    s$seq_write(&DestPortId, &OutputBytesUsed,
                                OutputBuffer, Code);
                    if (!*Code)
                       s$seq_write(&DestPortId, &(short)3, "end", Code);
                    break;

               case 3:   /* base 64 mime encode */
                    s$seq_write(&DestPortId, &(short)7, "--EVF--", Code);
                    break;

               }  /* switch(Encode) */

/*             --^^-- endadd --^^--                                      mcp */

          if (*Code) {
               free(InputBuffer);
               free(OutputBuffer);
/* mcp         strcpy(ErrorText, "s$write_raw UNIX Trailer"); */
               strcpy(ErrorText, "s$seq_write ENCODE Trailer");       /* mcp */
               u$errcat(ErrorText, DestPath);                         /* mcp */
               return;
               }
          }       /* if (Encode) */
          
     s$close(&SrcPortId, &(short)0);
     s$close(&DestPortId, &(short)0);
     s$detach_port(&SrcPortId, &(short)0);
     s$detach_port(&DestPortId, &(short)0);
     free(InputBuffer);
     free(OutputBuffer);
     *Code = 0;
     return;
}

void u$decode_vos_file(char *Source, char *Destination, short *Options,
                       char *ErrorText, short *Code)
{
short     SrcPortId, DestPortId, Encapsulate, Encode, StreamFile;
short     InputBytesLeft, PrevByte, State, OutputBytesUsed, RealRecordSize;
short     InputBytesProcessed, FileOrganization, FileRecordSize;
short     RealBytesLeft, Work;
short     StartName, EOFFound, BlankLineFound;                        /* mcp */
short     TempOrganization, TempEncode, TempEncap, BadVOS;            /* mcp */
short     ContentHdr, ContLine, TellOpt, HaveVOS;                     /* mcp */
char      *InputBuffer, *OutputBuffer, FileName[33], FileType[32];
char      *Next, ScanEncapFlag[32], ScanEncodeFlag[32];
char      DestPath[300], ScanName[300], FromB64[256], ScanNum[32];    /* mcp */
char      TellHeader[300], SaveHeader[300];                           /* mcp */
path_t    TempPath;
FILE_STATUS_STRUCT
          FileStatus;
int       ScanRecordSize, ScanMode;

     strcpy_vstr_nstr(&TempPath, Source);                            /* ansi */

     s$seq_open(&TempPath, &(short)INPUT_TYPE, &SrcPortId, Code);
     if (*Code) {
          strcpy(ErrorText, "s$seq_open Source");
          u$errcat(ErrorText, Source);                                /* mcp */
          return;
          }

     InputBuffer = (char *) malloc(MAX_RECORD_SIZE + 10);
     if (InputBuffer == NULL) {
          *Code = e$no_alloc;
          return;
          }

     OutputBuffer = (char *) malloc(MAX_RECORD_SIZE + 10);
     if (OutputBuffer == NULL) {
          *Code = e$no_alloc;
          return;
          }

/*   --vv-- begin header rework --vv--                                   mcp */

     /*
      *   Look for either a VOS or a uuencode header (or both).
      *
      *   This header scan area is reworked for MIME encoded text.
      *   We want to be able to scan an unedited MIME email message
      *   and extract the base64 or uuencoded part without stumbling
      *   over other text which may appear in the message.  In particular
      *   we do not want to mistake VOS or "begin" in the text as a
      *   header.  For VOS headers, we check all the other fields;
      *   if any are invalid we discard the thing as just random text
      *   rather than reporting an error and dying.  If no other header
      *   is found, we report what was wrong with the VOS header, which
      *   is compatible with what the original version did.  For uuencode
      *   headers, we verify that the second field after "begin" is an
      *   octal number.  If it is not, we pretend we didn't see it and
      *   keep scanning.
      */

     FileOrganization =  0;
     ScanMode         = -1;
     Encode           = -1;
     EOFFound         =  0;
     BlankLineFound   =  0;
     Encapsulate      =  0;
     BadVOS           =  0;
     HaveVOS          =  0;
     ContentHdr       =  0;
     ContLine         =  0;
     *FileName        = '\0';
     *TellHeader      = '\0';
     *SaveHeader      = '\0';

     if (*Options & EVF_OPTION_TELL)
          TellOpt = 1;
     else TellOpt = 0;

     while(1) {
          s$seq_read(&SrcPortId, &(short)MAX_RECORD_SIZE, &InputBytesLeft,
                     InputBuffer, Code);
          if (*Code) {
               if (*Code == e$end_of_file && ScanMode == -3) {
                 /*
                  * We found the MIME base64 headers immediately before eof.
                  * This means some mailhandler moved the headers to the
                  * end from their usual place immediately preceding the
                  * base64 encoded data.  We rewind the file and start
                  * looking for a line which is composed entirely of base64
                  * legal characters and is long enough not to be a short
                  * text line.  Since blank is not a legal base64 char, a
                  * long line which is all legal chars (and no blanks) is a
                  * good candidate to be base64 encoded.  This algorithm is
                  * not perfect; it will miss very short encoded files.
                  * If we don't find a qualifying line, we will hit eof a
                  * second time and return here with ScanMode still set to
                  * -5.  We won't enter this section again, but will report
                  * a specific error and quit.
                  */
                  ScanMode = -5;
                  s$seq_position(&SrcPortId, &(short)POS_BEGINNING_OF_FILE,
                                 &(long)0, Code);
                  if (!*Code)
                     continue;   /* reread file from beginning */
                  }

               if (*Code != e$end_of_file)
                    strcpy(ErrorText, "s$seq_read finding headers");
               else
               if (ScanMode == -5) {
                    strcpy(ErrorText, "No base64 data after MIME headers");
                    *Code = e$file_format_error;
                    }
               else
               if (BadVOS && !HaveVOS)
                    /* ErrorText already contains an error message */
                    *Code = e$file_format_error;
               else
               if (Encode > 0) {
                    if (Encode == 3)
                       strcpy(ErrorText, "MIME Base64 ");
                    else
                       strcpy(ErrorText, "UUE ");
                    strcat(ErrorText, "header not after VOS header");
                    *Code = e$file_format_error;
                    }
               else {
                    strcpy(ErrorText, "No Header found.");
                    *Code = e$invalid_file_type;
                    }

               u$errcat(ErrorText, Source);
               free(InputBuffer);
               free(OutputBuffer);
               return;
               }        /* if (*Code) */

          /* truncate to prevent crash on files with long records */
          if (InputBytesLeft > 300)
             InputBytesLeft = 300;

          /* drop trailing garbage */
          while (InputBytesLeft && InputBuffer[InputBytesLeft-1] <= ' ')
             InputBytesLeft--;

          InputBuffer[InputBytesLeft] = 0; /* Terminate the String */

          if (ScanMode == -5) {
            /*
             * We found base64 headers at the end of the file and
             * are now looking for the base64 data which goes with
             * the wayward headers.  If this line qualifies, we
             * reposition so the next s$seq_read will reread this
             * record, and break out of the header-scan loop.
             * Otherwise we continue, reading another record.
             */
             if (InputBytesLeft >= 40 && InputBytesLeft % 4 == 0
                    && strspn(InputBuffer, Base64) == InputBytesLeft) {

                s$seq_position(&SrcPortId, &(short)POS_NUM_RECORDS_BACKWARD,
                               &(long)0, Code);

                break;   /* this line qualifies as beginning of base64 data */
                }
             continue;   /* this line did not qualify, go read another */
             }

         /*
          * Content- headers can have continuation lines.
          * Continuation lines begin with white space and are not all blank.
          */
          ContLine = (InputBytesLeft && isspace(*InputBuffer));

          if (!ContLine)
             ContentHdr = 0;

          if (InputBytesLeft >= 3 && strncmp(InputBuffer, "VOS", 3) == 0) {

               sscanf(InputBuffer, "VOS %s %s %s %s %s", ScanName, FileType,
                      ScanNum, ScanEncapFlag, ScanEncodeFlag);

               /*   Translate the FileType */

               if (strcmp(FileType, "sequential") == 0)
                    TempOrganization = SEQUENTIAL_FILE;
               else
               if (strcmp(FileType, "stream") == 0)
                    TempOrganization = STREAM_FILE;
               else
               if (strcmp(FileType, "fixed") == 0)
                    TempOrganization = FIXED_FILE;
               else
               if (strcmp(FileType, "relative") == 0)
                    TempOrganization = RELATIVE_FILE;
               else {
                    BadVOS = 1;
                    strcpy(ErrorText,
                           "Invalid File Organization in VOS header");
                    continue;
                    }

               if (strcmp(ScanEncapFlag, "encapsulated") == 0)
                    TempEncap = 1;
               else
               if (strcmp(ScanEncapFlag, "not_encapsulated") == 0)
                    TempEncap = 0;
               else {
                    BadVOS = 1;
                    strcpy(ErrorText,
                              "Invalid Encapsulation Flag in VOS header");
                    continue;
                    }

               if (strcmp(ScanEncodeFlag, "encoded") == 0)
                    TempEncode = 1;
               else
               if (strcmp(ScanEncodeFlag, "not_encoded") == 0)
                    TempEncode = 0;
               else
               if (strcmp(ScanEncodeFlag, "seq_encoded") == 0)
                    TempEncode = 2;
               else
               if (strcmp(ScanEncodeFlag,"base64_encoded") == 0)
                    TempEncode = 3;
               else {
                    BadVOS = 1;
                    strcpy(ErrorText, "Invalid Encode Flag in VOS header");
                    continue;
                    }

               if (strspn(ScanNum, "0123456789") < strlen(ScanNum)) {
                    BadVOS = 1;
                    strcpy(ErrorText,
                              "Invalid file record size in VOS header");
                    continue;
                    }

               if (HaveVOS) {
                    *Code = e$file_format_error;
                    free(InputBuffer);
                    free(OutputBuffer);
                    strcpy(ErrorText, "Duplicate VOS header in file");
                    u$errcat(ErrorText, Source);
                    return;
                    }

               /* VOS header passes all edits, load everything now */

               sscanf(ScanNum, "%d", &ScanRecordSize);
               FileRecordSize = ScanRecordSize;
               Encode = TempEncode;
               FileOrganization = TempOrganization;
               Encapsulate = TempEncap;
               ScanMode = -1;
               strcpy(FileName, ScanName);
               *ErrorText = '\0';
               BadVOS = 0;
               HaveVOS = 1;

               /* save header for -tell; set flag so it won't be overwritten */
               if (TellOpt) {
                  strcpy(TellHeader, InputBuffer);
                  TellOpt = 2;
                  }

               if (Encode == 0 || Encode == 2)
                    /*   Not encoded, don't look for a header */
                    break;

               continue;
               }          /* if ... strncmp(InputBuffer, "VOS", 3) */

          /* check for UNIX uuencode header */

          if (Encode != 3 && InputBytesLeft >= 6 &&
               strncmp(InputBuffer, "begin ", 6) == 0) {

               sscanf(InputBuffer, "begin %s %s", ScanNum, ScanName);

               /* reject if 2nd arg is not an octal number */
               if (strspn(ScanNum, "01234567") < strlen(ScanNum))
                  continue;

               /* use filename if no VOS header */
               if (!*FileName)
                  strcpy(FileName, ScanName);

               /* save header if -tell and if no VOS header */
               if (TellOpt == 1)
                  strcpy(TellHeader, InputBuffer);

               if (Encode == -1)
                  Encode = 1;
               break;
               }

           /* Skip the MIME stuff if VOS header specified uuencode */
           if (Encode == 1)
              continue;

          /*
           *   MIME headers are caseless, so we convert InputBuffer
           *   to lower case with temp storage in OutputBuffer
           */
          Next = InputBuffer;
          for (Work=0; Work <= InputBytesLeft; Work++) {
              OutputBuffer[Work] = tolower(*Next);
              Next++;
              }

         /*
          * MIME Base64 header. Text begins after next blank line.
          * Content-Transfer-Encoding: base64
          * Content-Transfer-Encoding:  base64
          */
          if (InputBytesLeft > 25 &&
             strncmp(OutputBuffer, "content-transfer-encoding", 25) == 0) {

              /* 
               * Look for "base64" after "content-transfer-encoding"
               * VOS10 does not have strstr so we must roll our own.
               */
               RealBytesLeft = InputBytesLeft-5;
               for (Work=25; Work < RealBytesLeft; Work++)
                   if (strncmp(OutputBuffer+Work, "base64", 6) == 0) {
                      Work=0;  /* found it */
                      break;
                      }
               if (!Work) {
                 /*
                  * This is the base64 header.  We set the Encode flag
                  * to indicate base64 encoding, and ScanMode to indicate
                  * that any filename or saved headers we have in-hand
                  * are the ones we want to keep.  If we don't have a
                  * filename yet, we will keep looking and will keep the
                  * first one we find.  Likewise for headers for -tell.
                  * If -tell is on, we save this header separately, and
                  * later will concatenate it onto the content-type header
                  * found before or after this one.
                  */
                  if (Encode == -1)
                     Encode = 3;
                  ScanMode = -3;
                  if (TellOpt == 1) 
                     strcpy(SaveHeader, OutputBuffer);
                  continue;
                  }          /* if (!Work) */
               }           /* content-transfer-encoding */

          if (ScanMode == -2 && !ContLine) {
              /*
               * This line is not the base64 header, and not a continuation
               * line.  If we have a filename, then it is associated with
               * a non-base64 part of the message, so we kill it here.
               * Likewise, if we saved a header for -tell, it is not the
               * one we want to keep.  If we have a VOS header, we never
               * should get here, because we don't set ScanMode to -2.
               */
               ScanMode = -4;   /* no filename but we have seen MIME headers */
               *FileName = '\0';
               *TellHeader = '\0';
               }

          /* Ignore MIME separator lines, which begin with - */
          if (InputBytesLeft && *InputBuffer == '-')
               continue;

         /*
          * Check for MIME Content-Type or Content-Disposition header
          * which sometimes, but not always, contains a filename which
          * follows the keywords name= or filename= and frequently,
          * but not always, is enclosed in double quotes.  The header
          * can have one or more continuation lines (which begin with
          * whitespace) which should be treated as if they were part
          * of the header line itself.  We save this filename if it is
          * on the header line or on a continuation line.  We later
          * discard the filename if the next or previous line is/was not
          * the base64 header.  If there was a VOS header then we use its
          * filename and don't care about this one.
          *
          * ScanMode == -1  We have not seen any MIME headers yet.
          * ScanMode == -2  We have seen a content-type header which
          *                 has been saved for -tell and which may
          *                 contain a filename.  We will discard both
          *                 the filename and the saved header is the
          *                 next header is not the base64 MIME header.
          * ScanMode == -3  We found the base64 MIME header.  We
          *                 will scan until the next blank line,
          *                 then start decoding.  If we find a
          *                 filename and don't already have one,
          *                 we will use it.  If we find a content-disp
          *                 header and we have not saved a header yet,
          *                 we save it for -tell.  Otherwise, contents
          *                 of subsequent headers are ignored.
          * ScanMode == -4  We had a content-type header, but have
          *                 discarded it (and any filename) because it
          *                 belonged to a non-base64 part of the MIME
          *                 message.
          * ScanMode == -5  We found the base64 MIME header, but it
          *                 did not precede the base64 encoded data
          *                 and was at the end of the file instead.
          *                 We have rewound the file and are now
          *                 searching for the base64 data which goes
          *                 with the wayward headers. (We never get
          *                 here when ScanMode=-5; this is processed
          *                 at an earlier point.)
          */
          if (InputBytesLeft > 12 && 
             (strncmp(OutputBuffer,"content-type",12) == 0) ||
             (strncmp(OutputBuffer,"content-disp",12) == 0) ) {

               /* indicate we are processing a content- header */
               ContentHdr = 1;

               /* skip the rest if we have a VOS header */
               if (HaveVOS)
                  continue;

               /* save first segment of header (before semicolon) for -tell */
               if (TellOpt == 1 && !*TellHeader) {
                  strcpy(TellHeader, OutputBuffer);
                  Next = strchr(TellHeader, ';');
                  if (Next != NULL)
                     *Next = '\0';
                  }
              /*
               * set flag to indicate that the saved header and any
               * associated filename are killable if we have not already
               * seen the base64 header.
               */
               if (ScanMode != -3)
                  ScanMode = -2;

               }   /* if (... strncmp(OutputBuffer,"content-type... */

          if (ContentHdr) {
              /*
               * This is a content- header, or a continuation line after
               * a content- header.  Skip the name search if we already
               * have a filename from VOS or prev MIME header.  Else
               * scan the line for "name=" and process the filename if
               * one is there.
               */
               if (*FileName)
                  continue;

               StartName=0;
               RealBytesLeft = InputBytesLeft-5;
               for (Work=0; Work < RealBytesLeft; Work++)
                   if (strncmp(OutputBuffer+Work, "name=", 5) == 0) {
                      StartName=Work+5;
                      break;
                      }

               /* process filename if "name=" was found */
               if (StartName) {

                  /* nudge past leading quote, if it's there */
                  if (InputBuffer[StartName] == '"')
                     StartName++;

                  /* Copy filename (and trailing stuff) into ScanName */
                  strcpy(ScanName, &InputBuffer[StartName]);

                  /* null out semicolon after the name, if it's there */
                  Next = strchr(ScanName, ';');
                  if (Next != NULL)
                     *Next = '\0';

                  /* null out the trailing quote if it's there */
                  Next = strrchr(ScanName, '"');
                  if (Next != NULL)
                     *Next = '\0';

                  /* truncate name at 32 chars and save it */
                  ScanName[32] = '\0';
                  strcpy(FileName, ScanName);
                  }                           /* if (StartName) */

               continue;
               }                          /* if (ContentHdr) */

          /* after MIME base64 header, keep reading until blank line */
          if (ScanMode == -3 && !InputBytesLeft)
             break;

          /*   Not a VOS or UUE or MIME header, keep reading... */
          }          /* while(1) */


     /* All headers have been read and acted upon at this point */


     /* Invert the MIME Base64 character set into FromB64 */
     if (Encode == 3) {
        memset(FromB64, 127, 256);
        for (Work = 0; Work < 64; Work++)
            FromB64[Base64[Work]] = Work;
        }

    /*
     *  Unix and other systems allow characters in filenames
     *  that VOS does not like.  Kill the name if it would
     *  be illegal for VOS.
     */
     strcpy_vstr_nstr(&TempPath, FileName);
     s$expand_path(&TempPath, &(object_t)"", &TempPath, Code);
     if (*Code || strchr(FileName, '*') != NULL)
        *FileName = '\0';

    /*
     *  If FileName is null at this point, it means that the
     *  MIME headers had no filename.  This appears to be
     *  legal and occurs from certain mailers.  We will
     *  create a file name from the source file's name by
     *  dropping the last extension and adding DECODE.
     */
     if (!*FileName) {
        Next = strrchr(Source, '>');
        Next++;
        strcpy(ScanName, Next);
        Next = strrchr(ScanName, '.');
        if (Next != NULL)
           *Next = '\0';
        strcat(ScanName, ".DECODE");
        ScanName[32] = '\0';
        strcpy(FileName, ScanName);
        }

     /* tell them the file name and encode-header if they asked for it */
     if (TellOpt) {
        if (*SaveHeader) {
           if (*TellHeader) strcat(TellHeader, "; ");
           strcat(TellHeader, SaveHeader);
           }
        s$seq_write(&(short)DEFAULT_OUTPUT_PORT_ID,
                    &(short)(strlen(FileName)), FileName, Code);
        s$seq_write(&(short)DEFAULT_OUTPUT_PORT_ID,
                    &(short)(strlen(TellHeader)), TellHeader, Code);
        }

    /* 
     * Quit now (without decoding) when destination is #null.
     * This allows a macro which has successfully decoded a file
     * to get the name and type of the extracted file by running
     * this program again with -tell and attach_default_output.
     */
     Next = strchr(Destination, '#');
     if (Next != NULL) {
        if (!strcmp(Next, "#null")) {
           s$close(&SrcPortId, Code);
           s$detach_port(&SrcPortId, Code);
           free(InputBuffer);
           free(OutputBuffer);
           return;
           }
        }

/*        --^^-- end header rework --^^--                                mcp */

     /*
      *   Open the destination file for output as described in the VOS header
      *   If no VOS header was found (i.e. it was only an UUE file, open the
      *   file as a stream file.  If the file exists, delete it first (unless
      *   overridden)
      */

     /*   Build the output path name */

     if (strlen(Destination) == 0)
          s$get_current_dir(&TempPath);
     else strcpy_vstr_nstr(&TempPath, Destination);                  /* ansi */

     strcat_vstr_nstr(&TempPath, ">");                               /* ansi */
     strcat_vstr_nstr(&TempPath, FileName);                          /* ansi */
     strcpy_nstr_vstr(DestPath, &TempPath);                           /* mcp */

     /*   See if the file exists */

     FileStatus.version = FILE_STAT_VERSION_1;
     s$get_file_status(&TempPath, &FileStatus, Code);
     if (*Code == 0) {
          if (*Options & EVF_OPTION_DONT_OVERWRITE) {
               *Code = e$file_exists;
               strcpy_nstr_vstr(ErrorText, &TempPath);               /* ansi */
               free(InputBuffer);
               free(OutputBuffer);
               return;
               }

          s$delete_file(&TempPath, Code);
          if (*Code) {
               strcpy(ErrorText, "s$delete_file Destination");
               u$errcat(ErrorText, DestPath);                         /* mcp */
               free(InputBuffer);
               free(OutputBuffer);
               return;
               }
          }
     else if (*Code != e$object_not_found) {
               strcpy(ErrorText, "s$get_file_status Destination");
               u$errcat(ErrorText, DestPath);                         /* mcp */
               free(InputBuffer);
               free(OutputBuffer);
               return;
               }

     s$attach_port(&(object_t)"", &TempPath, &(short)0, &DestPortId, Code);
     if (*Code) {
          strcpy(ErrorText, "s$attach_port Destination");
          u$errcat(ErrorText, DestPath);                              /* mcp */
          free(InputBuffer);
          free(OutputBuffer);
          return;
          }

     if (FileOrganization == 0) {
          /*   Only UUE header, for the file type to stream */
          FileOrganization = STREAM_FILE;
          FileRecordSize   = 0;
          }

     s$open(&DestPortId, &FileOrganization, &FileRecordSize,
            &(short)OUTPUT_TYPE, &(short)SET_LOCK_DONT_WAIT,
            &(short)SEQUENTIAL_MODE, &(object_t)"", Code);
     if (*Code) {
          strcpy(ErrorText, "s$open Destination");
          u$errcat(ErrorText, DestPath);                              /* mcp */
          free(InputBuffer);
          free(OutputBuffer);
          return;
          }

     if (FileOrganization == STREAM_FILE)
          FileRecordSize = 4096; /* arbitrary size to R/W */

     OutputBytesUsed = 0;
     InputBytesProcessed = 0;
     RealRecordSize = -2;

     while(1) {
          if (Encode == 0) {
               /*   Not encoded */
               if (Encapsulate == 0) {
                    /* Completely raw data.  Read until EOF */
                    s$read_raw(&SrcPortId, &FileRecordSize, InputBuffer,
                          InputBuffer+2, Code);
                    if (*Code == e$end_of_file)
                         break;
                    else if (*Code) {
                              free(InputBuffer);
                              free(OutputBuffer);
                              strcpy(ErrorText, "s$seq_read Source");
                              u$errcat(ErrorText, Source);            /* mcp */
                              return;
                              }
                    }
               else {
                    /*  Encapsulated, read the length and then the data */

                    /*   Read the 2 byte length */

                    s$read_raw(&SrcPortId, &(short)(sizeof(FileRecordSize)),
                               &InputBytesLeft, &FileRecordSize, Code);
                    if (*Code || InputBytesLeft != sizeof(FileRecordSize)) {
                         /* No errors are allowed.  EOF is already encapsulated
                          * so we should never read until EOF */
                         if (*Code == 0)
                              *Code = e$file_format_error;
                         strcpy(ErrorText, "s$seq_read reading length");
                         u$errcat(ErrorText, Source);                 /* mcp */
                         free(InputBuffer);
                         free(OutputBuffer);
                         return;
                         }

                    if (FileRecordSize == -1)
                         break; /* EOF */

                    /*   Read the data */

                    s$read_raw(&SrcPortId, &FileRecordSize,
                               &InputBytesLeft, InputBuffer, Code);
                    if (*Code || InputBytesLeft != FileRecordSize) {
                         /* No errors are allowed.  EOF is already handled
                          * so we should never read until EOF */
                         if (*Code == 0)
                              *Code = e$file_format_error;
                         strcpy(ErrorText, "s$seq_read reading data");
                         u$errcat(ErrorText, Source);                 /* mcp */
                         free(InputBuffer);
                         free(OutputBuffer);
                         return;
                         }
                    }
               }        /* if (Encode == 0) */
          else {        /* encoded */
               /* Encode, read a line as text */

               s$seq_read(&SrcPortId, &(short)MAX_RECORD_SIZE, &InputBytesLeft,
                          InputBuffer, Code);
               if (*Code) {
                    /* No errors are allowed.  EOF is already encoded
                     * so we should never read until EOF */

                    /* delay reporting EOF until last buffer flushed     mcp */
                    if (*Code == e$end_of_file) {                     /* mcp */
                       EOFFound=1;                                    /* mcp */
                       *Code = 0;                                     /* mcp */
                       InputBytesLeft = 0;                            /* mcp */
                       *InputBuffer = EncodeByte('\0');               /* mcp */
                       }                                              /* mcp */
                  else {                                              /* mcp */
                       strcpy(ErrorText, "s$seq_read reading data");
                       u$errcat(ErrorText, Source);                   /* mcp */
                       free(InputBuffer);
                       free(OutputBuffer);
                       return;
                       }                                              /* mcp */
                    }      /* if (*Code) */
               }           /* encoded */

          /*   Record is in.  Look at it. */

          if (Encode == 0) {
               if (Encapsulate == 0)  {
                    if (FileOrganization == STREAM_FILE)
                         s$write_raw(&DestPortId, InputBuffer,
                                     InputBuffer+2, Code);
                    else s$seq_write(&DestPortId, InputBuffer,
                                     InputBuffer+2, Code);
                    }
               else {
                    s$seq_write(&DestPortId, &FileRecordSize, InputBuffer,
                                Code);
                    }

               if (*Code) {
                    strcpy(ErrorText, "s$seq_write Destination");
                    u$errcat(ErrorText, DestPath);                    /* mcp */
                    free(InputBuffer);
                    free(OutputBuffer);
                    return;
                    }
               continue;
               }            /* if (Encode == 0) */

          /*   Decode the encoded line (Encapsualted or not) */

      /*
       * uuencode
       *
       * 1st byte is encoded length.
       * Trailing garbage is ignored because only the number of bytes
       * in the encoded length is processed. No need to trim.
       */
       if (Encode == 1) {                                             /* mcp */
          RealBytesLeft = DecodeByte(*InputBuffer);
          if (RealBytesLeft == 0)
               break;  /* EOF flag found */

          Next = InputBuffer + 1;
          InputBytesLeft--;
          State = 0;
          }                                                           /* mcp */

/*     --vv-- addition --vv--                                            mcp */

      /*
       * seq_encode
       *
       * No encoded length, each input byte = one output byte.
       * This is binary data; everything is significant, even trailing
       * blanks.
       */
       if (Encode == 2) {
          RealBytesLeft = InputBytesLeft;
          if (RealBytesLeft == 0)
               break;  /* EOF flag found-- empty line */
          Next = InputBuffer;
          State = 3;
          }

      /*
       * base64_encode
       *
       * No encoded length, 4 input bytes become 3 output bytes.
       * This is ascii data; we drop trailing blanks and any control
       * chars, such as cr or lf from funky transfer from pc.
       */
       if (Encode == 3) {
          while (InputBytesLeft && InputBuffer[InputBytesLeft-1] <= ' ')
             InputBytesLeft--;
          InputBuffer[InputBytesLeft] = 0;
          RealBytesLeft = (InputBytesLeft / 4) * 3;
          Next = InputBuffer;
          State = 4;
         /*
          * Check for end-of-data.  The variability of different vendors'
          * interpretation of the MIME "standard" makes this interesting.
          * A line beginning with a non-blank, non-base64 character is
          * a sure-fire termination.  Blank or null lines may be present
          * within the data (some mailers double-space encoded lines!) so
          * hitting a blank line in and of itself does not terminate until
          * we either encounter a non-blank, non-base64 char or eof.
          * Hitting eof is an error unless preceded by at least one blank
          * line (this reported later).
          */
          if (InputBytesLeft == 0) {
             if (EOFFound)          /* got EOF, we are done */
                break;
             BlankLineFound = 1;    /* blank line, keep reading */
             continue;
             }

         /*
          * If 1st char is not a base64 char; we are done.
          * Later we will report an error if the terminator
          * is not a dash (-).
          */
          if (FromB64[*Next] > 63)
             break;

         /*
          * 1st char is a valid base64 char.  We verify that the
          * number of chars in the record is divisible by 4, then
          * fall thru and continue decoding.
          */
          BlankLineFound = 0;
          if (InputBytesLeft % 4) {
             *Code = e$file_format_error;
             InputBuffer[32] = 0;
             sprintf(ErrorText,
                     "Base64 line is wrong size: %d \"%s\"",
                     InputBytesLeft, InputBuffer);
             u$errcat(ErrorText, Source);
             free(InputBuffer);
             free(OutputBuffer);
             return;
             }
          }        /* if (Encode == 3) */

/*        --^^-- endadd --^^--                                           mcp */

          while(RealBytesLeft) {

               if (InputBytesLeft <= 0) {
                    *Code = e$file_format_error;
                    strcpy(ErrorText, "UUE line is the wrong size");
                    u$errcat(ErrorText, Source);                      /* mcp */
                    free(InputBuffer);
                    free(OutputBuffer);
                    return;
                    }

               switch(State) {
                    case 0:
                         OutputBuffer[OutputBytesUsed++] =
                               (DecodeByte(*(Next+0)) << 2) |
                               (DecodeByte(*(Next+1)) >> 4);
                         State = 1;
                         break;

                    case 1:
                         OutputBuffer[OutputBytesUsed++] =
                               (DecodeByte(*(Next+1)) << 4) |
                               (DecodeByte(*(Next+2)) >> 2);
                         State = 2;
                         break;

                    case 2:
                         OutputBuffer[OutputBytesUsed++] =
                               (DecodeByte(*(Next+2)) << 6) |
                               (DecodeByte(*(Next+3))     );
                         InputBytesLeft -= 4;
                         Next += 4;
                         State = 0;
                         break;

/*                  --vv-- addition --vv--                               mcp */

                    case 3:
                         OutputBuffer[OutputBytesUsed++] = *Next++;
                         InputBytesLeft--;
                         break;

                    case 4:
                         OutputBuffer[OutputBytesUsed++] =
                               (FromB64[*(Next+0)] << 2) |
                               (FromB64[*(Next+1)] >> 4);
                         State = 5;
                         break;

                    case 5:
                         if (FromB64[*(Next+2)] < 64)
                            OutputBuffer[OutputBytesUsed++] =
                               (FromB64[*(Next+1)] << 4) |
                               (FromB64[*(Next+2)] >> 2);
                         State = 6;
                         break;

                    case 6:
                         if (FromB64[*(Next+3)] < 64)
                            OutputBuffer[OutputBytesUsed++] =
                               (FromB64[*(Next+2)] << 6) |
                               (FromB64[*(Next+3)]     );
                         InputBytesLeft -= 4;
                         Next += 4;
                         State = 4;
                         break;

/*                       --^^-- endadd --^^--                            mcp */

                    }    /* switch(State) */

               RealBytesLeft--;

               if (Encapsulate) {
                    if (RealRecordSize == -2) {
                         /*   We are reading the record size */
                         if (OutputBytesUsed == sizeof(RealRecordSize)) {
                              /* Transfer the record size */
                              RealRecordSize = *(short *)OutputBuffer;
                              OutputBytesUsed = 0;
                              if (RealRecordSize == -1)
                                   break; /* EOF */
                              }
                         }

                    if (OutputBytesUsed == RealRecordSize) {
                         /*  We have our record, write it & reset */
                         s$seq_write(&DestPortId, &RealRecordSize,
                                     OutputBuffer, Code);
                         RealRecordSize = -2;
                         OutputBytesUsed = 0;
                         }
                    }
               else { /* Not Encapsulated */
                    if (OutputBytesUsed == FileRecordSize) {
                         /*   Time to write what we have */
                         if (FileOrganization == STREAM_FILE)
                              s$write_raw(&DestPortId, &FileRecordSize,
                                          OutputBuffer, Code);
                         else s$seq_write(&DestPortId, &FileRecordSize,
                                          OutputBuffer, Code);
                         RealRecordSize = -2;
                         OutputBytesUsed = 0;
                         }
                    }

               if (*Code) {
                    strcpy(ErrorText, "s$seq_write Destination");
                    u$errcat(ErrorText, DestPath);                    /* mcp */
                    free(InputBuffer);
                    free(OutputBuffer);
                    return;
                    }

               }        /* while(RealBytesLeft) */
          }             /* while(1) */

     /*
      *   Check for/Write any pending bytes
      */

     if (Encode) {
         if (OutputBytesUsed) {
               /*   Flush the final buffer */

               if (Encapsulate) {
                    *Code = e$file_format_error;
                    strcpy(ErrorText, "Premature UUE EOF in encapsulated"
                                        " file");
                    u$errcat(ErrorText, Source);                      /* mcp */
                    free(InputBuffer);
                    free(OutputBuffer);
                    return;
                    }

               /*   Not encapsulated */

               if (FileOrganization == FIXED_FILE) {
                    *Code = e$file_format_error;
                    strcpy(ErrorText, "Premature UUE EOF found in fixed file");
                    u$errcat(ErrorText, Source);                      /* mcp */
                    free(InputBuffer);
                    free(OutputBuffer);
                    return;
                    }

               /*   Encoded stream file.  Flush the final buffer */

               s$write_raw(&DestPortId, &OutputBytesUsed, OutputBuffer, Code);
               if (*Code) {
                    strcpy(ErrorText, "s$seq_write Destination");
                    u$errcat(ErrorText, DestPath);                    /* mcp */
                    free(InputBuffer);
                    free(OutputBuffer);
                    return;
                    }
               }         /* if (OutputBytesUsed) */

          /*   Check for the 'end' line */
/*
 * mcp    s$seq_read(&SrcPortId, &(short)MAX_RECORD_SIZE, &InputBytesLeft,
 * mcp               InputBuffer, Code);
 * mcp    if (*Code) {
 * mcp         strcpy(ErrorText, "s$seq_read reading end record");
 * mcp         free(InputBuffer);
 * mcp         free(OutputBuffer);
 * mcp         return;
 * mcp         }
 * mcp
 * mcp    if (InputBytesLeft < 2 || strncmp(InputBuffer, "end")) {
 * mcp         *Code = e$file_format_error;
 * mcp         strcpy(ErrorText, "s$seq_read reading end record");
 * mcp         free(InputBuffer);
 * mcp         free(OutputBuffer);
 * mcp         return;
 * mcp         }
 */
          /* --vv-- addition --vv--                                      mcp */

         /*
          * Here is where we report an EOF encountered when more data
          * for decoding was expected.  We have written the last output
          * buffer so we have as much of the file as was decoded before
          * reporting this error.  If the EOF was preceded by one or more
          * blank lines (MIME only) then this is not an error.
          */
          if (EOFFound && !BlankLineFound) {
             *Code = e$end_of_file;
             strcpy(ErrorText, "s$seq_read reading data");
             u$errcat(ErrorText, Source);
             free(InputBuffer);
             free(OutputBuffer);
             return;
             }

         /*
          * Here is where we verify that the after-data termination line
          * is present and valid.  We include the first 32 chars of the
          * data-line causing the error in the error message.
          */
          switch(Encode) {

               case 1:   /* uuencode */

               case 2:   /* seq encode */
                   /*
                    * Both uuencode and seq_encode terminate with a null
                    * record (for uuencode it's a record with an encoded
                    * zero length) followed by the 3 characters: "end".
                    * The null record has already been read before coming
                    * here, but we must read the "end" line now.
                    */
                    s$seq_read(&SrcPortId, &(short)MAX_RECORD_SIZE,
                               &InputBytesLeft, InputBuffer, Code);
                    if (*Code)
                         strcpy(ErrorText, "Reading end record.");
                    else {
                         if (InputBytesLeft < 3 ||
                                strncmp(InputBuffer, "end", 3)) {
                            *Code = e$file_format_error;
                            InputBuffer[InputBytesLeft] = 0;
                            InputBuffer[32] = 0;
                            strcpy(ErrorText, "Expected: \"end\"  Got: ");
                            strcat(ErrorText, Quote);
                            strcat(ErrorText, InputBuffer);
                            strcat(ErrorText, Quote);
                            }
                         }
                    if (*Code) {
                       u$errcat(ErrorText, Source);
                       free(InputBuffer);
                       free(OutputBuffer);
                       return;
                       }
                    break;

               case 3:   /* base 64 mime encode */
                   /*
                    * MIME encoding expects a line beginning with - which
                    * serves as the terminating separator.  Null records
                    * may or may not precede the separator line.  If null
                    * records were present they have already been read and
                    * discarded, and the next record read before coming
                    * here.  EOF is also OK if it was preceded by one or
                    * more blank lines.  The error for EOF not preceded by
                    * blanks lines has already been reported before getting
                    * here, so EOF is OK at this point.
                    */
                    if (!EOFFound && *InputBuffer != '-') {
                      *Code = e$file_format_error;
                      InputBuffer[32] = 0;
                      strcpy(ErrorText,
                           "Expected: MIME --boundary-- record.  Got: ");
                      strcat(ErrorText, Quote);
                      strcat(ErrorText, InputBuffer);
                      strcat(ErrorText, Quote);
                      u$errcat(ErrorText, Source);
                      free(InputBuffer);
                      free(OutputBuffer);
                      return;
                      }
                    break;

               }  /* switch(Encode) */

/*        --^^-- endadd --^^--                                           mcp */

          }     /* if (Encode) */

     s$close(&SrcPortId, &(short)0);
     s$close(&DestPortId, &(short)0);
     s$detach_port(&SrcPortId, &(short)0);
     s$detach_port(&DestPortId, &(short)0);
     free(InputBuffer);
     free(OutputBuffer);
     *Code = 0;
     return;
}

void u$errcat(char *ErrorText, char *File)                            /* mcp */
{
     if (strlen(ErrorText) + strlen(File) < 299)
     {
        strcat(ErrorText, " ");
        strcat(ErrorText, File);
     }
     return;
}
