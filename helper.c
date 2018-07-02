/*A list of helper functions*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <time.h>

#include "helper.h"

void fail ( const char * format ) {

	printf("Error: %s", format);
	exit(1);
}

/*Returns the square of a number*/
long power ( int base, int exponent ) {

	int i;
	
	long power = base;
	
	for( i = 1; i < exponent; i++ )
		power = power * base;
	
	return power;
}

int dna_size ( char filename[] ) {

	int n;
	
	FILE *text_fp;
	
	text_fp = fopen( filename, "r" );
	
	if( text_fp == NULL )
		fail("helper_lib: could not open file\n");
	
	fseek( text_fp, 0, SEEK_END );
	
	n = ftell( text_fp );
	
	fclose( text_fp );
	return n;
	
}

void load_files ( unsigned char **pattern, unsigned char *text, int m, int n, char pattern_filename[], char text_filename[], int p_size ) {

	/* load_files supports loading of multiple patterns and single texts */
	
	FILE *fp;
	
	unsigned int i, j;
	
	/*Pattern loading*/
	fp = fopen ( pattern_filename, "r" );
	
	if( fp == NULL )
		fail("helper_lib: could not open file\n");
	
	//for( i = 0; i < p_size; i++ )
	//	fscanf( fp, "%s\n", &pattern[i][0] );
	
	for ( j = 0; j < p_size; j++ ) {
		for ( i = 0; i < m; i++ ) 
			pattern[j][i] = fgetc ( fp );
	
		//Dummy pull to discard "\n" at the end of each pattern
		fgetc ( fp );		
	}
		
	fclose ( fp );
	
	/*Text loading*/
	fp = fopen ( text_filename, "r" );
	
	if ( fp == NULL )
		fail("helper_lib: could not open file\n");
	
	for ( i = 0; i < n; i++ )
		text[i] = fgetc ( fp );

	fclose ( fp );
}

void load_two_dimensional_files ( unsigned char **pattern, unsigned char **text, int m, int n, char pattern_filename[], char text_filename[] ) {

	FILE *fp;
	
	unsigned int i, j;
	
	unsigned char c;
	
	/*Pattern loading*/
	fp = fopen( pattern_filename, "r" );
	
	if ( fp == NULL )
		fail("helper_lib: could not open file\n");
	
	for ( j = 0; j < m; j++ )
		for ( i = 0; i < m; i++ ) {
			c = fgetc ( fp );
			
			//On newline read again
			if ( c == 10 )
				c = fgetc ( fp );
	
			pattern[j][i] = c;
		}
	
	fclose ( fp );

	/*Text loading*/
	fp = fopen( text_filename, "r" );
	
	if ( fp == NULL )
		fail("helper_lib: could not open file\n");
	
	for ( j = 0; j < n; j++ )
		for ( i = 0; i < n; i++ ) {
			c = fgetc ( fp );
			
			//On newline read again
			if ( c == 10 )
				c = fgetc ( fp );
	
			text[j][i] = c;
		}
	
	fclose ( fp );
}

void load_two_dimensional_files_to_1d ( unsigned char **pattern, unsigned char *text, int m, int n, char pattern_filename[], char text_filename[] ) {

	FILE *fp;
	
	unsigned int i, j;
	
	unsigned char c;
	
	/*Pattern loading*/
	fp = fopen( pattern_filename, "r" );
	
	if ( fp == NULL )
		fail("helper_lib: could not open file\n");
	
	for ( j = 0; j < m; j++ )
		for ( i = 0; i < m; i++ ) {
			c = fgetc ( fp );
			
			//On newline read again
			if ( c == 10 )
				c = fgetc ( fp );
	
			pattern[j][i] = c;
		}
	
	fclose ( fp );

	/*Text loading*/
	fp = fopen( text_filename, "r" );
	
	if ( fp == NULL )
		fail("helper_lib: could not open file\n");
	
	for ( i = 0; i < n * n; i++ ) {
		c = fgetc ( fp );
			
		//On newline read again
		if ( c == 10 )
			c = fgetc ( fp );
	
		text[i] = c;
	}
	
	fclose ( fp );
}

void create_dna_file ( int h_length, char filename[] ) {

	char DNA[4] = {'a', 't', 'g', 'c' };
	
	FILE *fp;
	
	unsigned int i;
	
	srand( time( NULL ) );
	
	fp = fopen( filename, "w" );
	
	if( fp == NULL )
		fail("helper_lib: could not open file\n");
	
	//For grep compatibility we introduce a '\n' every 10000 characters
	for( i = 0; i < h_length; i++ ) {
		fputc( DNA[rand() % 4 ], fp );
		
		if( i % 10000 == 0 && i > 0 )
			fputc( 10, fp );
	}
	
	fclose( fp );
}

void create_random_text ( int h_length, int alphabet, char filename[] ) {

	FILE *fp;
	
	unsigned int i;
	
	srand( time( NULL ) );
	
	fp = fopen( filename, "w" );
	
	if( fp == NULL )
		fail("helper_lib: could not open file\n");
	
	//For grep compatibility we introduce a '\n' every 10000 characters
	for( i = 0; i < h_length; i++ ) {
		fputc( rand() % alphabet + 48, fp );
		
		if( i % 10000 == 0 && i > 0 )
			fputc( 10, fp );
	}
	
	fclose( fp );
}

void create_two_dimensional_text_with_hits ( int m, int n, char pattern_filename[], char text_filename[] ) {

	FILE *fp;
	
	unsigned int i, j, k, p_line = 0;
	
	unsigned char pattern[m][m], c;

	fp = fopen( pattern_filename, "r" );
	
	if( fp == NULL )
		fail("helper_lib: could not open file\n");
		
	//load pattern
	for ( j = 0; j < m; j++ )
		for ( i = 0; i < m; i++ ) {
			c = fgetc ( fp );
			
			//On newline read again
			if ( c == 10 )
				c = fgetc ( fp );
	
			pattern[j][i] = c;
		}
	
	fclose ( fp );
	
	//Creating text based on the pattern
	fp = fopen( text_filename, "w" );
	
	if( fp == NULL )
		fail("helper_lib: could not open file\n");
	
	//repeat pattern to file
	for ( i = 0; i < n; i++, p_line++ ) {
	
		if ( p_line >= m )
			p_line = 0;
		
		//repeat the p_line row of the pattern n/m times
		for ( j = 0; j < n / m; j++ )
			for ( k = 0; k < m; k++ )
				fputc( pattern[p_line][k], fp );

		//add padding chars to the end of each row		
		for ( k = 0; k < n % m; k++ )
			fputc( pattern[p_line][k], fp );
		
		//add a newline
		fprintf( fp, "\n" );
	}

	fclose ( fp );
}

void create_random_multiple_pattern ( int m, int p_size, int alphabet, char pattern_filename[] ) {

	FILE *fp;
	
	unsigned int i, j, c;
	
	srand ( time ( NULL ) );
	
	fp = fopen ( pattern_filename, "w" );
	
	if ( fp == NULL )
		fail ("Cannot open pattern\n" );

	for ( j = 0; j < p_size; j++ ) {
		for ( i = 0; i < m; i++ ) {
			
			c = rand() % alphabet;
			
			//Bugfix, do not allow 10 or 13 to be placed inside the pattern
			if ( c == 10 || c == 13 )
				c++;
			
			fputc ( c, fp );
		}
		
		fputc ( 10, fp );
	}
		
	fclose ( fp );
}

void create_multiple_pattern_with_hits ( int m, int n, int p_size, char text_filename[], char pattern_filename[] ) {

	FILE *fp;
	
	unsigned int i, j;

	unsigned char pattern[p_size][m], c;

	fp = fopen( text_filename, "r" );
	
	if ( fp == NULL )
		fail ("Cannot open text\n" );
	
	for ( i = 0; i < p_size; i++ )
		for ( j = 0; j < m; j++ ) {
		
			c = fgetc ( fp );

			pattern[i][j] = c;		
		}
		
	fclose ( fp );

	fp = fopen ( pattern_filename, "w" );
	
	if ( fp == NULL )
		fail ("Cannot open pattern\n" );
	
	for ( i = 0; i < p_size; i++ ) {
		for ( j = 0; j < m; j++ ) 
			fputc ( pattern[i][j], fp );
		fputc ( 10, fp );
	}
	
	fclose ( fp );
}

void create_two_dimensional_pattern ( int m, int alphabet, char pattern_filename[] ) {

	FILE *fp;
	
	unsigned int i, j, c;

	srand ( time( NULL ) );

	fp = fopen ( pattern_filename, "w" );
	
	if ( fp == NULL )
		fail("helper_lib: could not open file\n");
	
	for ( j = 0; j < m; j++ ) {
		
		for ( i = 0; i < m; i++ ) {
		
			c = rand() % alphabet;
			
			//Bugfix, do not allow 10 or 13 to be placed inside the pattern
			if ( c == 10 || c == 13 )
				c++;
			
			fputc ( c, fp );
		}
		
		fputc( 10, fp );
	}
	
	fclose ( fp );
}

void create_two_dimensional_files ( int pattern_size, int text_size, int alphabet, char pattern_filename[], char text_filename[] ) {

	FILE *text_fp, *pattern_fp;
	
	unsigned int i,j;
	
	/* initialize random seed: */
	srand( time( NULL ) );

	/*Creating pattern*/
	pattern_fp = fopen(pattern_filename, "w");
	
	if( pattern_fp == NULL )
		fail("helper_lib: could not open file\n");
	
	for ( j = 0; j < pattern_size; j++ ) {
		for ( i = 0; i < pattern_size; i++ )
			fputc ( rand() % alphabet, pattern_fp );
		fputc( 10, pattern_fp );
	}
		
	fclose( pattern_fp );

	/*Creating text*/
	text_fp = fopen(text_filename, "w");
	
	if( text_fp == NULL )
		fail("helper_lib: could not open file\n");
	
	for( j = 0; j < text_size; j++ ){
		for( i = 0; i < text_size; i++ )
			fputc ( rand() % alphabet, text_fp );
		fputc ( 10, text_fp );
	}
	
	fclose( text_fp );
}

/* Sanitize texts by removing newlines, spaces and out of alphabet characters */
void sanitize_text ( int alphabet, char original_text_filename[], char sanitized_text_filename[] ) {

	FILE *fp1, *fp2;

	unsigned char c;

	fp1 = fopen ( original_text_filename, "r");
	fp2 = fopen ( sanitized_text_filename, "w");

	while ( !feof( fp1 ) ) {
		c = fgetc ( fp1 );

		if ( c != 10 && c != 32 && c < 20 )
			fputc ( c, fp2 );	
	}

	fclose ( fp1 );
	fclose ( fp2 );
}

/* Remove duplicate pattern rows by replacing them with random patterns */
void remove_duplicate_pattern_rows ( int m, int p_size, int alphabet, char original_pattern_filename[], char updated_pattern_filename[] ) {

	unsigned int i, j, k;
	FILE *fp1, *fp2;
	
	int num;
	
	unsigned char pattern[p_size][m], c;
	
	unsigned int dup[p_size];
	
	memset ( dup, 0, p_size * sizeof ( unsigned int ) );

	fp1 = fopen ( original_pattern_filename, "r");
	
	if ( fp1 == NULL )
		fail ("Cannot open text\n" );

	//Load the patterns into an array	
	for ( i = 0; i < p_size; i++ )
		for ( j = 0; j < m; j++ ) {
		
			c = fgetc ( fp1 );

			pattern[i][j] = c;		
		}
		
	fclose ( fp1 );

	int duplicates = 0;
	
	//Locate duplicate rows
	for ( k = 0; k < p_size; k++ ) {
	
		//This row is already flagged as duplicate, skip it
		if ( dup[k] == 1 )
			continue;
	
		for ( i = k + 1; i < p_size; i++ ) {
			
			for ( j = 0; j < m; j++ )				
				if ( pattern[k][j] != pattern[i][j])
					break;
			
			if ( j == m )
				dup[i] = 1;
		}
	}
	
	for ( i = 0; i < p_size; i++)
		if ( dup[i] == 1 )
			duplicates++;
	
	printf("total duplicates: %i\n", duplicates);
/*	
	srand( time( NULL ) );	
	
	//Replace duplicate pattern rows with random generated
	for ( i = 0; i < p_size; i++ ) {
	
		if ( dup[i] == 1 ) {
							
			for ( j = 0; j < m; j++ ) {
			
				num = rand() % alphabet;
			
				//Bugfix, do not allow 10 or 13 to be placed inside the pattern
				if ( num == 10 || num == 13 )
					num++;
					
				pattern[i][j] = num;			
			}
		}
	}

	//Store the patterns to the new pattern set
	fp2 = fopen ( updated_pattern_filename, "w");
	
	for ( i = 0; i < p_size; i++ ) {
		for ( j = 0; j < m; j++ ) 
			fputc ( pattern[i][j], fp2 );
		fputc ( 10, fp2 );
	}
	
	fclose ( fp2 );
	*/
}

void printbinary ( int x, int d ) {

	//d specifies the number of bits to be printed
	
	char buffer[33];
	
	int index = 0;
	
	while( d > 0 ) {
		if (x & 1)
			buffer[index++] = '1';
		else
			buffer[index++] = '0';
		x >>= 1;
		d--;
	}
	while( index > 0 )
		printf("%c", buffer[--index]);
	
	printf("\n") ;
}

void print_memory_usage ( void ) {

	int i, j;
	
	char buffer[100];
	
	FILE *fp = fopen("/proc/self/statm", "r");
	
	if ( !fp )
		fail("Error, could not open /proc/self/statm!\n");
	
	printf("Memory:\t\t");
	
	for( i = 0; i < 100; i++ ) {
	
		if ( feof( fp ) )
			break;
		
		buffer[i] = fgetc( fp );
	}
	
	for( j = 0; j < i - 1; j++ )
		if( buffer[j] == 32 || ( buffer[j] >= 48 && buffer[j] <= 57 ) )
			printf("%c", buffer[j]);
	printf("\n");
	
	fclose( fp );
	
	exit( 0 );
}

/* Return the size of an image ( square only! ) */
int image_size ( char text_filename[] ) {

	FILE *text_fp;
	int i;
	int c[4];
	int dec_number = 0;
	
	text_fp = fopen( text_filename, "r" );

	fseek ( text_fp , 21 , SEEK_SET );
	
	for( i = 3; i >= 0; i--) {
		c[i] = fgetc (text_fp);
		if( i != 0 )
			dec_number += c[i] * power(16, i + 1);
		else
			dec_number += c[i];
		
		fseek ( text_fp , -2 , SEEK_CUR );
	}
	
	fclose( text_fp );
	
	return dec_number;
}

int load_bmp ( unsigned char **text, int n ) {

	FILE *text_fp;
	
	int i,j, k;
	int c[4];
	
	int dec_number = 0;
	
	/* Make sure this is a Windows NT BMP */
	text_fp = fopen("data/image.bmp", "r");
	fseek ( text_fp , 14 , SEEK_SET );
		
	if ( fgetc (text_fp) != 40 )
		fail("Wrong image type!\n");
	
	/* Seek to the start of the actual data */
	fseek ( text_fp , 56 , SEEK_SET );
	
	for ( k = 0; k < n; k++) {
		for ( j = 0; j < n; j++) {
		
			dec_number = 0;
			
			/* Convert each triplet into decimal and store them to the text array */
			for( i = 2; i >= 0; i--) {
				c[i] = fgetc (text_fp);
				//printf("%i\n", c[i]);
				if( i != 0 )
					dec_number += c[i] * power( 16, i + 1 );
				else
					dec_number += c[i];
					
				//printf("%i * %i ^ %i\n", c[i], power(16, i + 1 ), i + 1 );
				fseek ( text_fp , -2 , SEEK_CUR );
			}
			
			text[k][j] = dec_number;
			
			/* Move to the next triplet */
			fseek ( text_fp , 6 , SEEK_CUR );
		}
	}

	fclose( text_fp );

	return 0;
}


void create_bmp_pattern( unsigned char **text, unsigned char **pattern, int m ) {

	int i,j;

	for( j = 0; j < m; j++ )
		for( i = 0; i < m; i++ )
			pattern[j][i] = text[j][i];
}

