#ifndef SMATCHER_H
#define SMATCHER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <mpi.h>

#include <string.h>
#include <unistd.h>
#include <obstack.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "helper.h"

//KMP
struct node {
	char label;
	int id;
	struct node* supply;
	struct node* next;
};

struct ac_state {
	unsigned int id;
	unsigned int keywordline;	//Remember which keyword row corresponds to the accepting word
	unsigned char *output;		//The output contains the whole keyword to be printed when a terminal state is encountered
	struct ac_state *fail;
	struct ac_state **next;
};

struct ac_table {
	unsigned int idcounter;
	unsigned int patterncounter;
	struct ac_state *zerostate;
};

struct sbom_state **pointer_array;

struct sbom_state {
	unsigned int id;
	unsigned int *F;		//Remember which keyword rows correspond to the accepting word
	unsigned int num;		//Store the number of different pattern rows that correspond to the same terminal state
	struct sbom_state *fail;
	struct sbom_state **next;
};

struct sbom_table {
	unsigned int idcounter;
	unsigned int patterncounter;
	struct sbom_state *zerostate;
};

//WM
struct prefixArray{
	int *value;	//The hash value of the B'-character prefix of a pattern
	int *index;	//The pattern number
	int size;	//How many patterns with the same prefix hash exist
};

unsigned short m_nBitsInShift;

unsigned int shiftsize;

//SOG
//Total number of 3 grams returned by the GET3GRAM macro
#define SIZE_3GRAM_TABLE 0x1000000
#define CHAR_WIDTH_3GRAM 8

#define GET3GRAM(address) ((((uint32_t) (address)[0])) + (((uint32_t)((address)[1])) << CHAR_WIDTH_3GRAM) + (((uint32_t)((address)[2])) << (CHAR_WIDTH_3GRAM << 1)))

//Bit masks used in 2-level hashing
static const uint8_t mask[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

uint8_t T8[SIZE_3GRAM_TABLE];
uint16_t T16[SIZE_3GRAM_TABLE];
uint32_t T32[SIZE_3GRAM_TABLE];

struct ac_table *preproc_ac ( unsigned char **, int, int, int );
unsigned search_ac ( unsigned char *, int, struct ac_table * );
void free_ac ( struct ac_table *, int );

struct ac_table *preproc_sh ( unsigned char **, int, int, int );
unsigned search_sh ( int, unsigned char *, int, struct ac_table *, int * );
void free_sh ( struct ac_table *, int );

struct sbom_table * preproc_sbom ( unsigned char **, int, int, int );
unsigned search_sbom ( unsigned char **, int, unsigned char *, int, struct sbom_table * );
void free_sbom ( struct sbom_table *, int );

void preproc_wu ( unsigned char **, int, int, int, int, int *, struct prefixArray * );
void wu_determine_shiftsize ( int );
void wu_init ( int, int, int, int **, struct prefixArray ** );
unsigned int search_wu ( unsigned char **, int, unsigned char *, int, int *, struct prefixArray * );
void wu_free ( int **, struct prefixArray ** );

void preproc_sog8 ( unsigned char **, int, int );
void sog_init8 ( int );
unsigned int search_sog8 ( unsigned char **, int, unsigned char *, int, int, int );
void sog_free8 ();

void preproc_sog16 ( unsigned char **, int, int );
void sog_init16 ( int );
unsigned int search_sog16 ( unsigned char **, int, unsigned char *, int, int, int );
void sog_free16 ();

void preproc_sog32 ( unsigned char **, int, int );
void sog_init32 ( int );
unsigned int search_sog32 ( unsigned char **, int, unsigned char *, int, int, int );
void sog_free32 ();

void preKmp ( int *, unsigned char *, int );

//void preBmGs ( unsigned char **, int, int [] );
void preBmBc ( unsigned char **, int, int, int, int * );

#endif
