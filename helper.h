#ifndef HELPER_H
#define HELPER_H

void fail ( const char * format );

int dna_size ( char textname[] );

void load_files ( unsigned char **pattern, unsigned char *text, int m, int n, char patternname[], char textname[], int p_size );

void load_two_dimensional_files ( unsigned char **pattern, unsigned char **text, int m, int n, char pattern_filename[], char text_filename[] );

void load_two_dimensional_files_to_1d ( unsigned char **pattern, unsigned char *text, int m, int n, char pattern_filename[], char text_filename[] );

void create_dna_text ( int h_length, char filename[] );

void create_random_text ( int h_length, int alphabet, char filename[] );

void create_two_dimensional_files ( int pattern_size, int text_size, int alphabet, char pattern_filename[], char text_filename[] );

void create_two_dimensional_pattern ( int m, int alphabet, char pattern_filename[] );

void create_two_dimensional_text_with_hits ( int m, int n, char pattern_filename[], char text_filename[] );

void create_random_multiple_pattern ( int m, int p_size, int alphabet, char pattern_filename[] );

void create_multiple_pattern_with_hits ( int m, int n, int p_size, char text_filename[], char pattern_filename[] );

void sanitize_text ( int alphabet, char original_text_filename[], char sanitized_text_filename[] );

void remove_duplicate_pattern_rows ( int m, int p_size, int alphabet, char original_pattern_filename[], char updated_pattern_filename[] );

void printbinary ( int x, int d );

long power ( int base, int exponent );

void print_memory_usage( void );

int load_bmp ( unsigned char **text, int n );

int image_size ( char text_filename[] );

void create_bmp_pattern( unsigned char **text, unsigned char **pattern, int m );

#define MAX(a,b) (a>b)?a:b
#define MIN(a,b) (a<b)?a:b

#endif

