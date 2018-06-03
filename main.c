#include "crysh.h"

int
main(int argc, char* argv[]){
	if(argc > VALID_ARGUMENTS){
		printf("invalid arguments");
		return EXIT_ERROR;
	}

	char* buffer;

	buffer = (char *)malloc(sizeof(char) * MAX_BUFFER_SIZE);

	/* As soon as it is not a complex command, 
	 * the encrypted data will not too long.
	 */
	if(fgets(buffer, MAX_BUFFER_SIZE, stdin) == NULL){
		perror("cannot get data");
		return EXIT_ERROR;
	}

	return decry_and_exec(buffer);
}
