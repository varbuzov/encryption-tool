# Command-line Encryption Tool

## Flag Description:
 -e	 		Encrypt mode 
 -d	 		Decrypt mode 
 -a 		Encrypt all files (skips .enc) 
ext			Encrypt files with specific extension (e.g. .txt)
key			Encryption key
 -r	 		Recursively scan subdirectories 
 -l		 	Delete original file after processing 
 -c	 		Choose algorithm: xor or rev 
 -w	        Generate a random key, save it to key.txt 
 OR 
 -h	        Help

## Usage examples:
*./encryptor -d myKey -c xor # Decrypt with XOR ./encryptor -e -a myKey -c xor -r -l* 
Encrypt all files recursively and delete originals 

*./encryptor -e .docx myKey -c rev* 
Encrypt .docx files using reverse 

*./encryptor -e -a myKey -c xor -r -l* 
Will NOT try to encrypt or delete itself! 

.*/encryptor -e -a -w -c xor -r -l* 
Encrypt all files with random key, save to key.txt recursively, and delete originals

## Compilation:
In Linux: 
*gcc ./encrypt-tool.cpp encryptor*
