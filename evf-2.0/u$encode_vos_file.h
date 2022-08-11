/*
 *   Header for u$encode_vos_file() and u$decode_vos_file()
 *
 *   Modified 96-03-09 by mcp@admin.chcc.com to add base64 and tell
 *            96-01-03 by mcp@admin.chcc.com to add output_sequential
 *
 */

#define   EVF_OPTION_ENCODE             0x0001
#define   EVF_OPTION_DONT_OVERWRITE     0x0002
#define   EVF_OPTION_FILE_IS_TEXT       0x0004
#define   EVF_OPTION_NO_HEADER          0x0008
#define   EVF_OPTION_OUTPUT_SEQUENTIAL  0x0010                        /* mcp */
#define   EVF_OPTION_BASE64             0x0020                        /* mcp */
#define   EVF_OPTION_TELL               0x0020                        /* mcp */

#define   EVF_FILE_EXTENSION            ".evf"

void u$encode_vos_file(char *Source, char *Destination, short *Options,
                       char *ErrorText, short *Code);

void u$decode_vos_file(char *Source, char *Destination, short *Options,
                       char *ErrorText, short *Code);
