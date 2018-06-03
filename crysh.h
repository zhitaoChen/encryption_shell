#ifndef CRYSH_H
#define CRYSH_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>

#define AES_ROUNDS 1
#define VALID_ARGUMENTS 1
#define SALT_SIZE 8
#define ENCRY_FLAG_SIZE 8
#define MAX_PASSWORD_SIZE 32
#define MAX_PATH 4096
#define MAX_BUFFER_SIZE 1024

/* Shell do not support complex command, 
 * 10 is sufficent for the program. 
 */
#define MAX_ARGU_SIZE 10 

#define EXIT_ERROR 128
#define ERROR 127

#define READ_END 0
#define WRITE_END 1

#define KEY_SIZE 32
#define IV_SIZE 16
 
unsigned char*
decry(char*);

int 
exec(unsigned char*);

void
real_name(char *);

void 
open_file(char*, int* , int* );

int 
decry_and_exec(char*);

#endif // CRYSH_H