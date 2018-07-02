#include "ac.h"
#include "list.h"

/// free an AC table from a given startnode (recursively)
void ac_free ( struct ac_state *state, int alphabet ) {

	int i;

	for ( i = 0; i < alphabet; i++ )
		if ( state->next[i] )
			ac_free ( state->next[i], alphabet );

	if ( state->output )
		free ( state->output );

	free ( state->next );
	free ( state );
}

/// initialize the empty-table
void ac_init ( struct ac_table *g, int alphabet ) {

	g->zerostate = NULL;
	g->patterncounter = 0;

	//Create the root note
	g->zerostate = malloc ( sizeof ( struct ac_state ) );

	if ( !g->zerostate )
		printf( "Could not allocate memory\n" );

	g->idcounter = 1;
	g->zerostate->id = 0;

	g->zerostate->output = NULL;

	g->zerostate->next = ( struct ac_state ** ) malloc ( alphabet * sizeof ( struct ac_state * ) );

	//Set all alphabet bytes of root node->next to 0
	memset ( g->zerostate->next, 0, alphabet * sizeof ( struct ac_state * ) );
}

/// free an entire AC table
void ac_destroy ( struct ac_table *in, int alphabet ) {

	int i;

	for ( i = 0; i < alphabet; i++ )
		if ( in->zerostate->next[i] && in->zerostate->next[i]->id > 0 ) {
			ac_free ( in->zerostate->next[i], alphabet );
			in->zerostate->next[i] = NULL;
		}
	free ( in->zerostate->next );
	free ( in->zerostate );
}

void ac_maketree ( struct ac_table *g, int alphabet ) {

	struct list *list = NULL;
	struct ac_state *state, *s, *cur;
	int i;

	// Set all NULL transitions of 0 state to point to itself
	for ( i = 0; i < alphabet; i++ ) {
		if ( !g->zerostate->next[i] )
			g->zerostate->next[i] = g->zerostate;
		else {
			list = list_append ( list, g->zerostate->next[i] );
			g->zerostate->next[i]->fail = g->zerostate;
		}
	}

	// Set fail() for depth > 0
	while ( list ) {

		cur = ( struct ac_state * )list->id;

		for ( i = 0; i < alphabet; i++ ) {

			s = cur->next[i];

			if ( s ) {

				list = list_append ( list, s );
				state = cur->fail;

				while ( !state->next[i] )
					state = state->fail;

				s->fail = state->next[i];

				//printf("state %i -> state %i\n", s->id, s->fail->id);
			}
			// Join outputs missing
		}
		list = list_pop ( list );
	}

	list_destroy ( list );
}

// Insert a string to the tree
void ac_addstring ( struct ac_table *g, unsigned int i, unsigned char *string, int m, int alphabet ) {

	struct ac_state *state, *next = NULL;
	int j, done = 0;

	// as long as next already exists follow them
	j = 0;
	state = g->zerostate;

	while ( !done && ( next = state->next[*( string + j )] ) != NULL ) {

		state = next;

		if ( j == m )
			done = 1;

		j++;

		//printf("character %c state: %i\n", *( string + j ), state->id);
	}

	// not done yet
	if ( !done ) {
		while ( j < m ) {
			// Create new state
			next = malloc ( sizeof ( struct ac_state ) );

			if ( !next )
				printf( "Could not allocate memory\n" );

			next->next = ( struct ac_state ** ) malloc ( alphabet * sizeof ( struct ac_state * ) );

			next->id = g->idcounter++;
			next->output = NULL;

			//printf("Created link from state %i to %i for character %c  (j = %i)\n", state->id, next->id, *( string + j ), j );

			//Set all alphabet bytes of the next node's->next to 0
			//This is the _extended_ Aho-Corasick algorithm. A complete automaton is used where all states
			//have an outgoing transition for every alphabet character of the alphabet
			memset ( next->next, 0, alphabet * sizeof ( struct ac_state * ) );

			state->next[*( string + j )] = next;
			state = next;

			//printf("character %c state: %i\n", *( string + j ), state->id);
			j++;
		}
	}

	//printf("	Currently at state %i\n", state->id);

	//After finishing with the previous characters of the keyword, add the terminal state if it does not exist
	if ( !state->output ) {

		//printf("	For pattern %i added the terminal state %i of %i\n", i, state->id, g->patterncounter);

		//allocate memory and copy *string to state->output
		state->output = ( unsigned char * ) malloc ( sizeof ( unsigned char ) * m );
		memcpy ( state->output, string, m );

		state->keywordline = g->patterncounter;

		g->patterncounter++;
	}
}

unsigned int search_ac ( unsigned char *text, int n, struct ac_table *table ) {

	struct ac_state *head = table->zerostate;
	struct ac_state *r, *s;

	int column, matches = 0;

	r = head;

	for ( column = 0; column < n; column++ ) {

		while ( ( s = r->next[*( text + column ) ] ) == NULL )
			r = r->fail;

		r = s;

		//printf("column %i r->id = %i text = %c\n", column, r->id, *( text + column ));

		if ( r->output != NULL ) {
			matches++;
			printf("match of %i at %i\n", r->keywordline, column);
		}
	}

	return matches;
}

struct ac_table *preproc_ac ( unsigned char **pattern, int m, int p_size, int alphabet ) {

	unsigned int i;

	struct ac_table *table;

	// allocate memory for the table

	table = malloc ( sizeof ( struct ac_table ) );

	if ( !table )
		printf( "Could not initialize table\n" );

	ac_init ( table, alphabet );

	for ( i = 0; i < p_size; i++ )
		ac_addstring ( table, i, pattern[i], m, alphabet );

	ac_maketree ( table, alphabet );

	return table;
}

void free_ac ( struct ac_table *table, int alphabet ) {

	ac_destroy ( table, alphabet );

	free ( table );
}
