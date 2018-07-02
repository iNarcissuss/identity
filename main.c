#include "smatcher.h"

void usage( void ) {

	printf("Smatcher - Sequential two dimensional pattern matching toolkit using multiple pattern matching algorithms.\n");
	printf("Usage: <multiple algorithm> <2d algorithm> -m <m> -p_size <p_size> -n <n> -alphabet <alphabet>\n");
	printf ("-h,--help,\t\t print this help message\n");
	printf ("-c,\t\t create the data files\n");

	exit(0);
}

void select_data_file ( unsigned int m, unsigned int n, unsigned int alphabet, char *pattern_filename, char *text_filename, int create_data ) {

	sprintf( pattern_filename, "pattern.txt", n, m, alphabet);

	switch ( n ) {
		case 4000000:
			if ( ( alphabet != 2 && alphabet != 8 ) )
				fail("For random texts, you must use an alphabet size of 2 or 8\n");

			if ( alphabet == 2 )
				sprintf( text_filename, "../data-multi/text/text2");
			else if ( alphabet == 8 )
				sprintf( text_filename, "../data-multi/text/text8");

			if ( create_data )
				create_multiple_pattern_with_hits ( m, n, 100000, text_filename, pattern_filename );

		break;

		case 2350122:
			if ( alphabet != 128 )
				fail("For english text, you must use an alphabet size of 128\n");

			sprintf ( text_filename, "./world192.txt");

			if ( create_data )
				create_multiple_pattern_with_hits ( m, n, 100000, text_filename, pattern_filename );

		break;

		case 4638690:
			if ( alphabet != 4 )
				fail("For DNA sequences, you must use an alphabet size of 4\n");

			sprintf ( text_filename, "../data-multi/text/E.coli2");

			if ( create_data )
				create_multiple_pattern_with_hits ( m, n, 100000, text_filename, pattern_filename );

		break;
		case 177660096:
			if ( alphabet != 20 )
				fail("For swiss-prot, you must use an alphabet size of 20\n");

			sprintf ( text_filename, "../data-multi/text/swiss-prot");

			if ( create_data )
				create_multiple_pattern_with_hits ( m, n, 100000, text_filename, pattern_filename );

		break;
		case 10830882:
			if ( alphabet != 20 )
				fail("For A_thaliana.faa, you must use an alphabet size of 20\n");

			sprintf ( text_filename, "../data-multi/text/A_thaliana.faa");

			if ( create_data )
				create_multiple_pattern_with_hits ( m, n, 100000, text_filename, pattern_filename );

		break;
		case 116237486:
			if ( alphabet != 4 )
				fail("For A_thaliana.fna, you must use an alphabet size of 4\n");

			sprintf ( text_filename, "../data-multi/text/A_thaliana.fna");

			if ( create_data )
				create_multiple_pattern_with_hits ( m, n, 100000, text_filename, pattern_filename );

		break;

		case 100:
			if ( alphabet != 2 )
				fail("The debug text uses a binary alphabet\n");

			sprintf ( text_filename, "../data-multi/text/debug");
			sprintf ( pattern_filename, "../data-multi/pattern/debug");

			break;
		default:
			fail("Please select an appropriate text size\n");
		break;
	}
}

void multiac ( unsigned char **pattern, int m, unsigned char *text, int n, int p_size, int alphabet ) {

	double t1, t2, t3, preproc_time = 0, search_time = 0, running_time = 0;
	int i, matches;

	struct ac_table *table;

	t1 = MPI_Wtime();

	table = preproc_ac ( pattern, m, p_size, alphabet );

	t2 = MPI_Wtime();

	matches = search_ac ( text, n, table );

	t3 = MPI_Wtime();

	preproc_time += ( t2 - t1 );

	search_time += ( t3 - t2 );

	running_time += ( t3 - t1 );

	free_ac ( table, alphabet );

	printf("search_ac matches \t%i\t preprocessing \t%.5f\t searching \t%.5f\t running \t%.5f\n", matches, preproc_time / 10, search_time / 10, running_time / 10 );
}

void multish ( unsigned char **pattern, int m, unsigned char *text, int n, int p_size, int alphabet ) {

	double t1, t2, t3, preproc_time = 0, search_time = 0, running_time = 0;
	int i, matches;

	struct ac_table *table;

	for ( i = 0; i < 10; i++ ) {

		int *bmBc = ( int * ) malloc ( alphabet * sizeof ( int ) );

		t1 = MPI_Wtime();

		//Preprocessing using the Horspool algorithm
		preBmBc ( pattern, m, p_size, alphabet, bmBc );

		//Creating the Set Horspool automaton AND translating the pattern into an 1D array of symbols
		table = preproc_sh ( pattern, m, p_size, alphabet );

		t2 = MPI_Wtime();

		matches = search_sh ( m, text, n, table, bmBc );

		t3 = MPI_Wtime();

		preproc_time += ( t2 - t1 );

		search_time += ( t3 - t2 );

		running_time += ( t3 - t1 );

		free ( bmBc );

		free_sh ( table, alphabet );
	}

	printf("search_sh matches \t%i\t preprocessing \t%.5f\t searching \t%.5f\t running \t%.5f\n", matches, preproc_time / 10, search_time / 10, running_time / 10 );
}

void multisbom ( unsigned char **pattern, int m, unsigned char *text, int n, int p_size, int alphabet ) {

	double t1, t2, t3, preproc_time = 0, search_time = 0, running_time = 0;
	int i, matches;

	struct sbom_table *table;

	for ( i = 0; i < 10; i++ ) {

		pointer_array = malloc ( p_size * m * sizeof ( struct sbom_state ) );

		t1 = MPI_Wtime();

		table = preproc_sbom ( pattern, m, p_size, alphabet );

		t2 = MPI_Wtime();

		matches = search_sbom ( pattern, m, text, n, table );

		t3 = MPI_Wtime();

		preproc_time += ( t2 - t1 );

		search_time += ( t3 - t2 );

		running_time += ( t3 - t1 );

		free_sbom ( table, m );

		free ( pointer_array );
	}

	printf("search_sbom matches \t%i\t preprocessing \t%.5f\t searching \t%.5f\t running \t%.5f\n", matches, preproc_time / 10, search_time / 10, running_time / 10 );
}

void multiwm ( unsigned char **pattern, int m, unsigned char *text, int n, int p_size, int alphabet, int B ) {

	double t1, t2, t3, preproc_time = 0, search_time = 0, running_time = 0;
	int i, matches;

	wu_determine_shiftsize ( alphabet );

	int *SHIFT;

	struct prefixArray *PREFIX;

	m_nBitsInShift = 2;

	for ( i = 0; i < 10; i++ ) {

		wu_init ( m, p_size, B, &SHIFT, &PREFIX );

		t1 = MPI_Wtime();

		preproc_wu ( pattern, m, p_size, alphabet, B, SHIFT, PREFIX );

		t2 = MPI_Wtime();

		matches = search_wu ( pattern, m, text, n, SHIFT, PREFIX );

		t3 = MPI_Wtime();

		preproc_time += ( t2 - t1 );

		search_time += ( t3 - t2 );

		running_time += ( t3 - t1 );

		wu_free ( &SHIFT, &PREFIX );
	}

	printf("search_wm matches \t%i\t preprocessing \t%.5f\t searching \t%.5f\t running \t%.5f\n", matches, preproc_time / 10, search_time / 10, running_time / 10 );
}

void multisog ( unsigned char **pattern, int m, unsigned char *text, int n, int p_size, int alphabet, int B ) {

	double t1, t2, t3, preproc_time = 0, search_time = 0, running_time = 0;
	int i, matches;

	#ifdef m8
		for ( i = 0; i < 10; i++ ) {

			sog_init8 ( p_size );

			t1 = MPI_Wtime();

			preproc_sog8 ( pattern, m, p_size );

			t2 = MPI_Wtime();

			matches = search_sog8 ( pattern, m, text, n, p_size, B );

			t3 = MPI_Wtime();

			preproc_time += ( t2 - t1 );

			search_time += ( t3 - t2 );

			running_time += ( t3 - t1 );

			sog_free8 ();
		}
	#endif
	#ifdef m16
		for ( i = 0; i < 10; i++ ) {

			sog_init16 ( p_size );

			t1 = MPI_Wtime();

			preproc_sog16 ( pattern, m, p_size );

			t2 = MPI_Wtime();

			matches = search_sog16 ( pattern, m, text, n, p_size, B );

			t3 = MPI_Wtime();

			preproc_time += ( t2 - t1 );

			search_time += ( t3 - t2 );

			running_time += ( t3 - t1 );

			sog_free16 ();
		}
	#endif
	#ifdef m32
		for ( i = 0; i < 10; i++ ) {

			sog_init32 ( p_size );

			t1 = MPI_Wtime();

			preproc_sog32 ( pattern, m, p_size );

			t2 = MPI_Wtime();

			matches = search_sog32 ( pattern, m, text, n, p_size, B );

			t3 = MPI_Wtime();

			preproc_time += ( t2 - t1 );

			search_time += ( t3 - t2 );

			running_time += ( t3 - t1 );

			sog_free32 ();
		}
	#endif

	printf("search_sog matches \t%i\t preprocessing \t%.5f\t searching \t%.5f\t running \t%.5f\n", matches, preproc_time / 10, search_time / 10, running_time / 10 );
}

int main ( int argc, char **argv ) {

	int m = 0, p_size = 0, n = 0, alphabet = 0, B = 3, create_data = 0;

	unsigned int i;

	char text_filename[100], pattern_filename[100];

	//Scan command line arguments
	for ( i = 1; i < argc; i++ ) {

		if ( strcmp ( argv[i], "--help" ) == 0 || strcmp ( argv[i], "-h" ) == 0 )
			usage();

		if ( strcmp ( argv[i], "-m" ) == 0 )
			m = atoi ( argv[i + 1] );

		if ( strcmp ( argv[i], "-n" ) == 0 )
			n = atoi ( argv[i + 1] );

		if ( strcmp ( argv[i], "-p_size" ) == 0 )
			p_size = atoi ( argv[i + 1] );

		if ( strcmp ( argv[i], "-alphabet" ) == 0 )
			alphabet = atoi ( argv[i + 1] );

		if ( strcmp ( argv[i], "-c" ) == 0 )
			create_data = 1;
	}

	if ( m == 0 || n == 0 || p_size == 0 || alphabet == 0 )
		usage();

	if ( p_size > 100000 )
		fail("Only up to 100.000 patterns are supported\n");

	//Determine path of pattern and text based on n
	select_data_file ( m, n, alphabet, &pattern_filename, &text_filename, create_data );

	unsigned char *text = ( unsigned char * ) malloc ( sizeof ( unsigned char ) * n );

	if ( text == NULL )
		fail("Failed to allocate array\n");

	unsigned char **pattern = ( unsigned char ** ) malloc ( p_size * sizeof ( unsigned char * ) );

	if ( pattern == NULL )
		fail("Failed to allocate array!\n");

	for ( i = 0; i < p_size; i++ ) {
		pattern[i] = ( unsigned char * ) malloc ( m * sizeof ( unsigned char ) );

		if ( pattern[i] == NULL )
			fail("Failed to allocate array!\n");
	}

	load_files ( pattern, text, m, n, pattern_filename, text_filename, p_size );

	//Initialize MPI
	MPI_Init ( &argc, &argv );

	/*for ( i = 0; i < 100; i++ )
		printf("%i ", text[i]);
	printf("\n");*/

	//////////////////////////AC implementation//////////////////////////
	if ( strcmp ( argv[1], "ac") == 0 )
		multiac ( pattern, m, text, n, p_size, alphabet );

	if ( strcmp ( argv[1], "sh") == 0 )
		multish ( pattern, m, text, n, p_size, alphabet );

	if ( strcmp ( argv[1], "sbom") == 0 )
		multisbom ( pattern, m, text, n, p_size, alphabet );

	if ( strcmp ( argv[1], "wm") == 0 )
		multiwm ( pattern, m, text, n, p_size, alphabet, B );

	if ( strcmp ( argv[1], "sog") == 0 ) {

		#ifdef m8
			if ( m != 8 )
				fail("Set the correct pattern size for SOG\n");
		#endif
		#ifdef m16
			if ( m != 16 )
				fail("Set the correct pattern size for SOG\n");
		#endif
		#ifdef m32
			if ( m != 32 )
				fail("Set the correct pattern size for SOG\n");
		#endif

		multisog ( pattern, m, text, n, p_size, alphabet, B );
	}


	//////////////////////////clean up phase//////////////////////////
	// finalize MPI
	MPI_Finalize();

	free ( text );

	for ( i = 0; i < p_size; i++ )
		free( pattern[i] );

	free ( pattern );

	return 0;
}
