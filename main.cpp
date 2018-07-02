extern "C" {
	#include "ac/ac.h"
}

#include <cstring>
#include <string>

using std::string;

void usage( void )
{

	printf("Smatcher - Sequential two dimensional pattern matching toolkit using multiple pattern matching algorithms.\n");
	printf("Usage: <multiple algorithm> <2d algorithm> -m <m> -p_size <p_size> -n <n> -alphabet <alphabet>\n");
	printf ("-h,--help,\t\t print this help message\n");
	printf ("-c,\t\t create the data files\n");

	exit(0);
}

// Load multiple patterns and single texts
void load_files ( unsigned char **pattern, unsigned char *text, int m, int n, const string& pattern_filename, const string& text_filename, int p_size )
{
	// Pattern loading
	FILE *fp = fopen ( pattern_filename.c_str(), "r" );

	if( fp == NULL ) {
		printf("Could not open file\n");
	}

	//for( i = 0; i < p_size; i++ )
	//	fscanf( fp, "%s\n", &pattern[i][0] );

	for ( int j = 0; j < p_size; j++ ) {
		for ( int i = 0; i < m; i++ )
			pattern[j][i] = fgetc ( fp );

		//Dummy pull to discard "\n" at the end of each pattern
		fgetc ( fp );
	}

	fclose ( fp );

	// Text loading
	fp = fopen ( text_filename.c_str(), "r" );

	if ( fp == NULL ) {
		printf("helper_lib: could not open file\n");
	}

	for (int i = 0; i < n; i++) {
		text[i] = fgetc ( fp );
	}

	fclose (fp);
}

void multiac ( unsigned char **pattern, int m, unsigned char *text, int n, int p_size, int alphabet )
{
	struct ac_table *table = preproc_ac ( pattern, m, p_size, alphabet );

	int matches = search_ac ( text, n, table );

	free_ac ( table, alphabet );

	printf("search_ac matches \t%i\n", matches);
}

int main (int argc, char **argv)
{
	int m = 0, p_size = 0, n = 0, alphabet = 0, B = 3, create_data = 0;

	//Scan command line arguments
	for ( int i = 1; i < argc; i++ ) {

		if ( strcmp ( argv[i], "--help" ) == 0 || strcmp ( argv[i], "-h" ) == 0 )
			usage();

		if ( strcmp ( argv[i], "-m" ) == 0 ) {
			m = atoi ( argv[i + 1] );
		}

		if ( strcmp ( argv[i], "-n" ) == 0 ) {
			n = atoi ( argv[i + 1] );
		}

		if ( strcmp ( argv[i], "-p_size" ) == 0 ) {
			p_size = atoi ( argv[i + 1] );
		}

		if ( strcmp ( argv[i], "-alphabet" ) == 0 ) {
			alphabet = atoi ( argv[i + 1] );
		}

		if ( strcmp ( argv[i], "-c" ) == 0 ) {
			create_data = 1;
		}
	}

	if (m == 0 || n == 0 || p_size == 0 || alphabet == 0) {
		usage();
	}

	if (p_size > 100000) {
		printf("Only up to 100.000 patterns are supported\n");
	}

	//Determine path of pattern and text based on n
	const string pattern_filename = "pattern.txt";
	const string text_filename = "world192.txt";

	unsigned char *text = ( unsigned char * ) malloc ( sizeof ( unsigned char ) * n );

	if ( text == NULL ) {
		printf("Failed to allocate array\n");
	}

	unsigned char **pattern = ( unsigned char ** ) malloc ( p_size * sizeof ( unsigned char * ) );

	if ( pattern == NULL )
		printf("Failed to allocate array!\n");

	for ( int i = 0; i < p_size; i++ ) {
		pattern[i] = ( unsigned char * ) malloc ( m * sizeof ( unsigned char ) );

		if ( pattern[i] == NULL )
			printf("Failed to allocate array!\n");
	}

	load_files ( pattern, text, m, n, pattern_filename, text_filename, p_size );

	//////////////////////////AC implementation//////////////////////////
	if ( strcmp ( argv[1], "ac") == 0 ) {
		multiac ( pattern, m, text, n, p_size, alphabet );
	}

	//////////////////////////clean up phase//////////////////////////

	free ( text );

	for ( int i = 0; i < p_size; i++ ) {
		free( pattern[i] );
	}

	free ( pattern );

	return 0;
}
