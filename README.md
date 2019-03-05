# encryption_shell

Please check the manual page written by [Professor Schaumann](https://www.cs.stevens.edu/~jschauma/).

## The program still cannot work correctly, 

the parts (I think) I had done are:
1. extracted the key and iv from encrypted data correctly.
2. decrypted the data correctly based on key and iv.
3. executed the command used by pipe(2) and fork(2).

## Missing part:
	cannot read password from stdin.

## Chanllenge:
1. Cannot find EVP_BytesToKey(3),EVP_EncryptInit(3), etc. 
2. Hard to understand the meaning of EVP_BytesToKey(3).
3. Confuse about the decryption and encryption logical.
4. Confuse about the fork(2) return when debugging.
5. Cannot decry the data 
6. Cannot append the file

## Solve:
1. Install the libssl-dev
2. Find Openssl Wiki and other related material to try 
to understand the function meaning.
3. Similar solution as above, and figure out the logical, which is:
	#### (1) get rid of decryption and encryption, generate the key and iv first.
	#### (2) used key to decrypt and encry the data.
	#### (3) execute the extracted command.
4. Remember in class that fork(2) return the value twice.
5. Found that the function only decrypted the data directly! 
   So if we put the encryption flag "Salted__" and 8 bytes salt in it,
   the function EVP_DecryptUpdate will treat those characters as a part
   of encrypt data! So we need to ingore the flag and salt then decrypt
   the data.
6. Need to deal with the excrat whitespace and table space, etc.

## Other cases consider:
1. Invalid encryption data format, such as begin with "salt", "Salte__", etc. 
2. Insufficent encryption data size, such as only have "Salted__".
flag and 8 bytes salt.
3. The program should not have argument.
4. Password too long, if so then return a error.
5. Use "2>>" and ">>" in one command, program should save both the output and error in file respectily.
6. Encryption too long, if so then return a error.
7. Command has too many arguments, if so then return a error.
