#include "crysh.h"

unsigned char*
decry(char* data){
	char* salt;
	char* password;
	unsigned char* plaintext;
	
	unsigned char key[KEY_SIZE];
	unsigned char iv[IV_SIZE];	
	int len;
	int plaintext_len;

	EVP_CIPHER_CTX *d_ctx;

	if((password = (char*)malloc(sizeof(char) * MAX_PASSWORD_SIZE + 1)) 
		== NULL){
		perror("malloc fail");
			
		return NULL;
	}

	if((password = getenv("CRYSH_PASSWORD")) == NULL){
		printf("password:\n");

		if(fgets(password, MAX_PASSWORD_SIZE, stdin) == NULL){
			printf("read password fail\n");
			
			return NULL;
		}
	}

	if(strncmp(data, "Salted__", sizeof("Salted__") - 1) != 0){
		printf("invalid encrypted format\n");
		
		return NULL;
	}

	if((salt = (char*)malloc(SALT_SIZE + 1)) == NULL){
		perror("malloc fail");
		
		return NULL;
	}

	if(strncpy(salt, data + ENCRY_FLAG_SIZE, SALT_SIZE) == NULL){
		printf("generate key fail\n");
		
		return NULL;
	}

	bzero(key, sizeof(key));
	bzero(iv, sizeof(iv));

	if(EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), (unsigned char*)salt, 
		(unsigned char*)password, strlen(password), 
			AES_ROUNDS, key, iv) == 0){
		perror("generate key fail");
		
		return NULL;
	}

	if((d_ctx = EVP_CIPHER_CTX_new()) == 0){
		perror("EVP_CIPHER_CTX_new");
		
		return NULL;
	}

  	if(EVP_DecryptInit(d_ctx, EVP_aes_256_cbc(), key, iv) == 0){
		perror("EVP_DecryptInit");
		
		return NULL;
	}

	/* decrypted text will always 
	 * not greater than encrypted text 
	 */
	if((plaintext = (unsigned char*)malloc(sizeof(unsigned char) * MAX_BUFFER_SIZE))
		 == NULL){
		perror("malloc fail");
		
		return NULL;
	}

	len = 0;
	bzero(plaintext, strlen(data));

	if(EVP_DecryptUpdate(d_ctx, plaintext, &len, 
		(unsigned char*)data + (SALT_SIZE + ENCRY_FLAG_SIZE), strlen(data) - (SALT_SIZE + ENCRY_FLAG_SIZE)) == 0){
		perror("EVP_DecryptUpdate");

		return NULL;
	}
	plaintext_len = len;

	(void)EVP_DecryptFinal_ex(d_ctx, plaintext + len, &len);

	plaintext_len += len;
	if(plaintext[plaintext_len - 1] == '\n')
		plaintext[plaintext_len - 1] = 0;
	else
		plaintext[plaintext_len] = 0;

	if(EVP_CIPHER_CTX_cleanup(d_ctx) == 0){
		perror("free failure");
	}
	
	free(salt);

	return plaintext;
}

void 
real_name(char* name){
	int space;
	int char_count;
	int i;

	for(i = 0, char_count = 0, space = 0; i < strlen(name); i++){
		if(name[i] == ' '){
			space++;
		}else{
			name[i - space] = name[i];
			char_count++;
		}
	}

	name[char_count] = 0;
}

void 
open_file(char* execute, int* fd_output, int* fd_error){
	char* file_flag;
	char* file_name;
	bool deal_output;
	bool deal_error;

	file_name = NULL;
	file_flag = NULL;

	deal_error = false;
	deal_output = false;

	*fd_output = -1;
	*fd_error = -1; 
	
	if((file_flag = (char *)malloc(MAX_BUFFER_SIZE)) == NULL){
		perror("malloc failure");
		return;
	}
	
	if((file_name = (char *)malloc(MAX_BUFFER_SIZE)) == NULL){
		perror("malloc failure");
		return;
	}

	/* It is possible that write output and error 
	 * in differents file.
	 */
	if((file_flag = strstr(execute, "2>>")) != NULL){
		deal_error = true;

		(void)strtok(execute, "2>>");
		
		file_name = strtok(NULL, "2>>");

		real_name(file_name);

		*fd_error = open(file_name, O_RDWR|O_APPEND|O_CREAT, 
			S_IRWXU|S_IRWXG|S_IRWXO);
	}else if((file_flag = strstr(execute, "2>")) != NULL){
		deal_error = true;

		(void)strtok(execute, "2>");
        
        	file_name = strtok(NULL, "2>");

        	real_name(file_name);

        	*fd_error = open(file_name, O_RDWR|O_CREAT, 
        		S_IRWXU|S_IRWXG|S_IRWXO);
    	}

    	if(deal_error == true && *fd_error < 0){
       		perror("fail to open file to log the error");
       		return;
    	}

	if((file_flag = strstr(execute, ">>")) != NULL){
		deal_output = true;

		(void)strtok(execute, ">>");
		
		if(file_flag[strlen(file_flag) - 1] == '2'){
			file_name = strtok(NULL, ">>");	
		}
        
		file_name = strtok(NULL, ">>");

		real_name(file_name);

        	*fd_output = open(file_name, O_RDWR|O_APPEND|O_CREAT,
        		S_IRWXU|S_IRWXG|S_IRWXO);
    	}else if((file_flag = strstr(execute, ">")) != NULL){
    		deal_output = true;

		(void)strtok(execute, ">");
        	file_name = strtok(NULL, ">");
        	
        	if(file_flag[strlen(file_flag) - 1] == '2'){
			file_name = strtok(NULL, ">>");	
		}

		real_name(file_name);

        	*fd_output = open(file_name, O_RDWR|O_CREAT,
        		S_IRWXU|S_IRWXG|S_IRWXO);
	}
		

	if(deal_output == true && *fd_output < 0){
       		perror("fail to open file to log the output");
       		return;
    	}
}

int 
exec(unsigned char* text){
	char* execute[MAX_BUFFER_SIZE];
	char* command;
	char* path;
	char* pathenv;
	char* arg[MAX_ARGU_SIZE];
	char* buffer;

	int buffer_bytes;

	int fd_output;
	int fd_error;

	int fd_pipe[2];
	int child_pid;
	
	int err_status;
	int out_status;
	int child_return_status;

	bool error;

	int i;
	int t;

	int exe_len; 

	error = false;
	buffer = NULL;
	path = NULL;
	pathenv = NULL;

	setuid(0);  

	exe_len = 0;

	execute[0] = strtok((char *)text, ";");
	while(execute[exe_len] != NULL){
		exe_len++;
		execute[exe_len] = strtok(NULL, ";");
	}

	for(t = 0; t < exe_len; t++){
		if(error == true){
			fprintf(stderr, "execute fail in: %s\n", execute[t - 1]);
			break;
		}

		open_file(execute[t], &fd_output, &fd_error);

		command = strtok(execute[t], ">");
		if(command[strlen(command) - 1] == '2'){
			command[strlen(command) - 1] = 0;
		}

		arg[0] = strtok(command, " ");
		for(i = 1; i < MAX_ARGU_SIZE; i++){
			if((arg[i] = strtok(NULL, " ")) == NULL)
				break;
		}
		arg[i] = 0;

		if(pipe(fd_pipe) == -1){
			perror("create pipeline failure");
			return EXIT_ERROR;
		}

		/* Send the data back to parent's buffer first,
		 * then choose to store data to file or not in
		 * parent process. That logical is more clearly than directly
		 * send data to file in child process.
		 */
		if((child_pid = fork()) == -1){
			perror("fork failure");
			return EXIT_ERROR;
		}else if(child_pid == 0){
			if(close(fd_pipe[READ_END]) == -1){
				perror("transfer data failure");
				return EXIT_ERROR;
			}

			if(fd_output != -1){
				out_status = dup2(fd_output, STDOUT_FILENO);
			}else{
				out_status = dup2(fd_pipe[WRITE_END], STDOUT_FILENO);
			}

			if(out_status == -1){
				perror("transfer data failure");
				return EXIT_ERROR;
			}

			if(fd_error != -1){
				err_status = dup2(fd_error, STDERR_FILENO);
			}else{
				err_status = dup2(fd_pipe[WRITE_END], STDERR_FILENO);
			}

			if(err_status == -1){
				perror("transfer data failure");
				return EXIT_ERROR;
			}

			path = getenv("PATH");
	    		pathenv = (char*)malloc(strlen(path) + sizeof("PATH="));
    			sprintf(pathenv, "PATH=%s", path);
    		
    			char* envp[] = {pathenv, NULL};

    			execvpe(arg[0], arg, envp);

    			fprintf(stderr, "execute error: %s\n", arg[0]);
			return EXIT_ERROR;
		}else{
			buffer = (char*)malloc(sizeof(char) * MAX_BUFFER_SIZE);

			if(close(fd_pipe[WRITE_END]) == -1){
				perror("transfer data failure");
				return EXIT_ERROR;
			}

			if(waitpid(child_pid, &child_return_status, 0) > 0){
				int exited = WIFEXITED(child_return_status);
				int exited_st = WEXITSTATUS(child_return_status);

				if(exited && !exited_st){
					error = false;
				}else{
					error = true;
				}
			}else{
				perror("execute fail");
			}

			while((buffer_bytes = read(fd_pipe[READ_END], buffer, MAX_BUFFER_SIZE)) != 0){
				if(buffer_bytes == -1){
					perror("read data failure");
					return EXIT_ERROR;
				}
				
				if(error == false)
					write(STDOUT_FILENO, buffer, buffer_bytes);
				else
					write(STDERR_FILENO, buffer, buffer_bytes);
			}
		}
	}

	if(setgid(getgid()) == -1){
		perror("drop privileges fail");
	}

	if(setuid(getuid()) == -1){
		perror("drop privileges fail");
	}

	free(pathenv);
	free(buffer);
	
	return child_return_status;
}

int 
decry_and_exec(char* data){
	unsigned char* plaintext;
	int st;

	plaintext = decry(data);
	if(plaintext == NULL){
		return EXIT_ERROR;
	}
	
	st = exec(plaintext);
	if(st == EXIT_ERROR)
		return EXIT_ERROR;
	else
		return st;
}
