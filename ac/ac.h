#ifndef AC_H_
#define AC_H_

struct ac_state {
  unsigned int id;
  unsigned int keywordline; //Remember which keyword row corresponds to the accepting word
  unsigned char *output;    //The output contains the whole keyword to be printed when a terminal state is encountered
  struct ac_state *fail;
  struct ac_state **next;
};

struct ac_table {
  unsigned int idcounter;
  unsigned int patterncounter;
  struct ac_state *zerostate;
};

struct ac_table *preproc_ac ( unsigned char **pattern, int m, int p_size, int alphabet );
struct Results search_ac ( unsigned char *text, int n, struct ac_table *table );
void free_ac ( struct ac_table *table, int alphabet );

struct Results {
  int matches;
  int pattern;
  int location;
};

 #endif