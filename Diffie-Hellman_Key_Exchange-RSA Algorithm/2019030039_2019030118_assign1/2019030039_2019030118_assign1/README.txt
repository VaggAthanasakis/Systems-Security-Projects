Authors:
Athanasakis Evangelos
George Fragkogiannis

GCC Version:
gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0

-------------------------------------- Compilation --------------------------------------------
- In order to compile the 2 programs (DiffieHellman.c, RSA.c) you have to run the command make
- make will create 2 executable files, one for each .c file, the "dh_assign_1" and the "rsa_assign_1"
- make clean will delete these 2 executables

-------------------------------------- Diffie-Hellman Algorithm --------------------------------
The Diffie-Hellman (DH) algorithm is a key exchange algorithm that allows two parties to securely agree on a shared secret key,
which can be used for encryption and decryption.This implementation provides functions for DH key exchange.

The tool will receive the required arguments from the command line upon execution
as such:
Options:
-o path Path to output file
-p number Prime number
-g number Primitive Root for previous prime number
-a number Private key A
-b number Private key B
-h              This help message
                The argument -p will include the will be the public prime number.
                The argument -g will be the public primitive root of the previous prime number.
                The argument -a will be the private key of user A.
                The argument -b will be the private key of user B.

Example:
./dh_assign_1 -o output.txt -p 23 -g 9 -a 15 -b 2


-------------------------------------- RSA Algorithm --------------------------------
The RSA (Rivest–Shamir–Adleman) algorithm is a widely-used asymmetric encryption algorithm.
It provides a method for secure data transmission and encryption.
This implementation provides functions for key generation, encryption, and decryption using RSA.

The tool will receive the required arguments from the command line upon execution
as such:
Options:
-i path Path to the input file
-o path Path to the output file
-k path Path to the key file
-g length Perform RSA key-pair generation given a key length “length”
-d          Decrypt input and store results to output.
-e          Encrypt input and store results to output.
-a          Compare the performance of RSA encryption and decryption with three
            different key lengths (1024, 2048, 4096 key lengths) in terms of computational time.
-h          This help message
            The arguments “i”, “o” and “k” are always required when using “e” or “d”
            Using -i and a path the user specifies the path to the input file.
            Using -o and a path the user specifies the path to the output file.
            Using -k and a path the user specifies the path to the key file.
            Using -g the tool generates a public and a private key given a key length “length” and
            stores them to the public_length.key and private_length.key files respectively.
            Using -d the user specifies that the tool should read the ciphertext from the input file,
            decrypt it and then store the plaintext in the output file.
            Using -e the user specifies that the tool should read the plaintext from the input file,
            encrypt it and store the ciphertext in the output file.
            Using -a the user generates three distinct sets of public and private key pairs,
            allowing for a comparison of the encryption and decryption times for each.

Example:
./rsa_assign_1 -g “length”  -The tool will generate a public and a private key given a length “length” and store
                             them in the files public_length.key and private_length.key respectively.

Example:
./rsa_assign_1 -i plaintext.txt -o ciphertext.txt -k public_length.key -e  -The tool will retrieve the public key from the file public.key
                                                                            and use it to encrypt the data found in “plaintext.txt”
                                                                            and then store the ciphertext in “ciphertext.txt”.

Example:
./rsa_assign_1 -a performance.txt  -The tool will generate three distinct sets of public and private key pairs, each with
                                    different key lengths (1024, 2048, 4096). These key pairs will be saved in files
                                    named "public_1024.key," "private_1024.key," "public_2048.key," "private_2048.key,"
                                    "public_4096.key," and "private_4096.key." Afterward, it will encrypt and decrypt the
                                    contents of the "plaintext.txt" file using each key pair and record the time taken for
                                    each operation in the "performance.txt" file. This setup allows for a direct comparison
                                    of encryption and decryption times for each key length.

For the implementation of this algorithm, the GMP library was used in order to hanlde really large integer values.

* For ease of use, an input file (plain_text) with the input of the rsa algorithm is included.