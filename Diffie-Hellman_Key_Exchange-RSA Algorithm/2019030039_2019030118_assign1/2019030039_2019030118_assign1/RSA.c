#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <gmp.h>
#include <time.h>


/* Check if we have correct p,q lenghts */
void KeyLengthCheck(mpz_t p, mpz_t q, mpz_t length)
{
    // p and q should each be key_length/2
    // Convert mpz_t to a string in order to compare the length
    char *pStr = NULL;
    char *qStr = NULL;

    pStr = mpz_get_str(NULL, 10, p);
    qStr = mpz_get_str(NULL, 10, q);

    int pStrLength = (int)strlen(pStr);
    int qStrLength = (int)strlen(qStr);

    /////////////////////////////////////////////////////
    int two_integer = 2; // Your regular integer

    mpz_t two;
    mpz_init(two);

    // Convert the regular integer to an mpz_t
    mpz_set_si(two, two_integer);
    /////////////////////////////////////////////////////////////

    mpz_t halfLen;
    mpz_init(halfLen);
    mpz_div(halfLen, length, two);
    int HL = mpz_get_si(halfLen);
    //printf(" \n pStrLength = %d, qStrLength = %d, HL= %d", pStrLength, qStrLength, HL);
    if (pStrLength != HL || qStrLength != HL){
        fprintf(stderr, "p and q should each be key_length/2");
        exit(1);
    }

    mpz_clear(two);
}

/* function to calculate the proper prime e */
void eGenerator(mpz_t e, mpz_t lambda){
    mpz_init(e);

    mpz_set_ui(e,2);

    mpz_t mod;
    mpz_init(mod);
    mpz_mod(mod, e, lambda);
    
    mpz_t gcd;
    mpz_init(gcd);
    mpz_gcd(gcd, e, lambda);

    mpz_t tmp_prime;
    mpz_init(tmp_prime);

    while(mpz_cmp_ui(mod, 0) == 0 || mpz_cmp_ui(gcd, 1) != 0){
        //printf("In while");
        mpz_nextprime(tmp_prime, e);
        mpz_set(e,tmp_prime);

        mpz_mod(mod, e, lambda);
        mpz_gcd(gcd, e, lambda);

        if(mpz_cmp(e,lambda)>0){ // e must be < lambda
            fprintf(stderr,"\nProgram cannot find prime e...\n");
            exit(1);
        }

    }
}

/* Calculate Lambda */
void LambdaCalculate(mpz_t lambda, mpz_t p, mpz_t q){
    // Calculate lambda(n) = (p-1)*(q-1)
    mpz_init(lambda);

    mpz_t one;
    mpz_init(one);
    mpz_set_si(one, 1);

    mpz_t newQ;
    mpz_init(newQ);
    mpz_sub(newQ, q, one);

    mpz_t newP;
    mpz_init(newP);
    mpz_sub(newP, p, one);

    mpz_mul(lambda, newP, newQ);

    mpz_clear(one);
    mpz_clear(newQ);
    mpz_clear(newP);

    return;
}


/* Generate 2 random mpz_t numbers for p and q */
void create_mpz_t_with_digits(mpz_t result, unsigned int num_digits)
{
    int base = 2;
    //int base = 10;

    mpz_init(result); // Initialize the mpz_t variable

    // Determine the range for generating random numbers with the specified number of digits
    mpz_t lower_bound, upper_bound;
    mpz_init(lower_bound);
    mpz_init(upper_bound);

    mpz_ui_pow_ui(upper_bound, base, num_digits);
    mpz_ui_pow_ui(lower_bound, base, num_digits - 1);

    // Initialize and seed the random number generator with the current time
    gmp_randstate_t state;
    gmp_randinit_default(state);
    unsigned long seed = (unsigned long)time(NULL) + (unsigned long)clock();
    gmp_randseed_ui(state, seed);


    // Create a random mpz_t value within the specified range
    do{
        mpz_urandomm(result, state, upper_bound);
        
    } 
    while (mpz_cmp(result, lower_bound) < 0);
    //gmp_printf("Random mpz : %Zd\n", result);

    gmp_randclear(state); // Clear the random number generator state
    mpz_clear(lower_bound);
    mpz_clear(upper_bound);
}

/******************* Key Generation Function *********************/
void generateRSAKeyPair(int length){
    mpz_t zero, p, q;
    mpz_init(zero);
    mpz_init(p);
    mpz_init(q);
    mpz_set_si(zero, 0);

    printf("\nLength: %d, length/2: %d\n", length, length / 2);
    // create random prime p
    do{
        create_mpz_t_with_digits(p, length / 2);
    } 
    while (mpz_probab_prime_p(p, 30) == 0);

    // create random prime q != p
    do{
        create_mpz_t_with_digits(q, length / 2); // create random p
    } 
    while (mpz_probab_prime_p(q, 30) == 0 || mpz_cmp(p, q) == 0);

    /* Check if p,q are prime numbers, else exit */
    //gmp_printf("mpz_t p Value: %Zd\n", p);
    //gmp_printf("mpz_t q Value: %Zd\n", q);

    // Calculate n = p*q
    mpz_t n;
    mpz_init(n);
    mpz_mul(n, p, q);
    //gmp_printf("\nmpz_t n = : %Zd\n", n);

    // Calculate laambda(n)
    mpz_t lambda_n;
    // mpz_init(lambda_n);
    LambdaCalculate(lambda_n, p, q);

    //gmp_printf("\nmpz_t lambda_n = : %Zd\n", lambda_n);

    // find prime e
    mpz_t prime_e;
    mpz_init(prime_e);
    eGenerator(prime_e, lambda_n);
    //gmp_printf("\n mpz_t prime_e = : %Zd\n", prime_e);

    // Calculating d which is the modular inverse of (e, lambda).
    mpz_t d;
    mpz_init(d);
    mpz_invert(d, prime_e, lambda_n);
    //gmp_printf("\n mpz_t d = : %Zd\n", d);


    /* write data at key file */
    char* n_str=mpz_get_str(NULL, 10, n); 
    char* d_str=mpz_get_str(NULL, 10, d);
    char* e_str=mpz_get_str(NULL, 10, prime_e);

    char* public_keyFile = "public_";
    char* private_keyFile = "private_";
    char* keyStr = ".key";


    // calculate the name of the private key file--------------------------------------------------------------------
    int max_length_PrivateKeyFile = snprintf(NULL, 0, "%s%d%s",private_keyFile, length, keyStr);
     // Allocate memory for the new string
    char* privateKeyFileName = (char*)malloc(max_length_PrivateKeyFile + 1);    
    // Concatenate the strings and integer
    snprintf(privateKeyFileName, max_length_PrivateKeyFile + 1, "%s%d%s", private_keyFile, length, keyStr);


    // calculate the name of the public key file---------------------------------------------------------------------
    int max_length_PublicKeyFile = snprintf(NULL, 0, "%s%d%s",public_keyFile, length, keyStr);
     // Allocate memory for the new string
    char* publicKeyFileName = (char*)malloc(max_length_PublicKeyFile + 1);    
    // Concatenate the strings and integer
    snprintf(publicKeyFileName, max_length_PublicKeyFile + 1, "%s%d%s", public_keyFile, length, keyStr);


    FILE* keyFile;
    if((keyFile = fopen(publicKeyFileName,"w")) == NULL){
        fprintf(stderr,"Cannot Open Output File. Will terminate..");
        exit(1);
    }
    //fprintf(keyFile,"%ld %ld",mpz_get_ui(n), mpz_get_ui(d));
    fprintf(keyFile,"%s %s",mpz_get_str(NULL, 10, n), mpz_get_str(NULL, 10, d));
    fclose(keyFile);
    
    if((keyFile = fopen(privateKeyFileName,"w")) == NULL){
        fprintf(stderr,"Cannot Open Output File. Will terminate..");
        exit(1);
    }
    fprintf(keyFile,"%s %s",mpz_get_str(NULL, 10, n), mpz_get_str(NULL, 10, prime_e));
    fclose(keyFile);

    mpz_clears(p, q, NULL);
}

/******************* Data Encryption Function *********************/
void DataEncryption(char *plain_text_path, char *cipher_text_path, char *key_file_path){
    
    // Open the plain text file to read the message one character at a time
    FILE * plainText_file;
    if((plainText_file = fopen(plain_text_path,"r")) == NULL){
        fprintf(stderr,"\nCannot Open Plain Text File.. Terminate\n");
        exit(1);
    }

    // Open the cipher text file to write the encrypted message one character at a time
    FILE * cipherText_file;
    if((cipherText_file = fopen(cipher_text_path,"w")) == NULL){
        fprintf(stderr,"\nCannot Open Cipher Text File.. Terminate\n");
        exit(1);
    }

    // Open the key file in order to take the key for the encryption
    FILE * key_file;
    if((key_file = fopen(key_file_path,"r")) == NULL){
        fprintf(stderr,"\nCannot Open Key File.. Terminate\n");
        exit(1);
    }

    // Read the key from the file
    mpz_t n_retr,d_retr;
    mpz_init(n_retr);
    mpz_init(d_retr);

    if(gmp_fscanf(key_file,"%Zd %Zd",n_retr,d_retr) != 2){
        fprintf(stderr,"\nCannot retrieve key file values. Will terminate\n");
        exit(1);
    }

    // take every char of the plain text -> encrypt it -> store it at cipher text
    // we perform the encryption at the ascii value of the character
    int m;
    while ((m = fgetc(plainText_file)) != EOF) {
        //printf("Character: %c, ASCII value: %d\n", (char)m, m);

        // convert the ascii m value into a mpz_t value
        mpz_t m_retr;
        mpz_init(m_retr);
        mpz_set_si(m_retr, m);

        /* perform the encryption */
        mpz_t c_m;
        mpz_init(c_m);
        
        mpz_powm(c_m,m_retr,d_retr,n_retr);

        // store the encrypted message (mpz_t value) at cipher text file
        // store a space after in order to be used as a delimiter
        gmp_fprintf(cipherText_file,"%Zd ",c_m);
    }

    // close the files and clear the mpz_t values
    mpz_clears(n_retr,d_retr,NULL);

    fclose(plainText_file);
    fclose(cipherText_file);
    fclose(key_file);
}

/******************* Data Decryption Function *********************/
void DataDecryption(char *cipher_text_path, char *output_text_path, char *key_file_path){
    
    // Open the cipher text file to read the encrypted message one character at a time
    FILE * cipherText_file;
    if((cipherText_file = fopen(cipher_text_path,"r")) == NULL){
        fprintf(stderr,"\nCannot Open Cipher Text File.. Terminate\n");
        exit(1);
    }

    // Open the output text file to write the decrypted message one character at a time
    FILE * output_file;
    if((output_file = fopen(output_text_path,"w")) == NULL){
        fprintf(stderr,"\nCannot Open Output Text File.. Terminate\n");
        exit(1);
    }

    // Open the key file in order to take the key for the decryption
    FILE * key_file;
    if((key_file = fopen(key_file_path,"r")) == NULL){
        fprintf(stderr,"\nCannot Open Key File Text File.. Terminate\n");
        exit(1);
    }

    // Read the key from the file
    mpz_t n_retr,e_retr;
    mpz_init(n_retr);
    mpz_init(e_retr);

    if(gmp_fscanf(key_file,"%Zd %Zd",n_retr,e_retr) != 2){
        fprintf(stderr,"\nCannot retrieve key file values. Will terminate\n");
        exit(1);
    }

    // take each mpz_t value from the encrypted file
    mpz_t c_retr;
    mpz_init(c_retr);
    while(gmp_fscanf(cipherText_file,"%Zd ",&c_retr) == 1){
        mpz_t c_m_mod;
        mpz_init(c_m_mod);

        /* perform the decryption */
        mpz_powm(c_m_mod,c_retr,e_retr,n_retr);

        // store the decrypted message at output text file
        int str = mpz_get_si(c_m_mod);
        fprintf(output_file,"%c", (char)str);

    }
    mpz_clears(n_retr,e_retr,NULL);

    fclose(output_file);
    fclose(cipherText_file);
    fclose(key_file);

}

/* function to perform performance analysis for different key lengths */
void Performance_Analysis(char *plain_text_path){

    char * privateKeyFile_1024 = "private_1024.key";
    char * privateKeyFile_2048 = "private_2048.key";
    char * privateKeyFile_4096 = "private_4096.key";

    char * publicKeyFile_1024 = "public_1024.key";
    char * publicKeyFile_2048 = "public_2048.key";
    char * publicKeyFile_4096 = "public_4096.key";

    char * cipher_text_path = "cipher_text.txt";

    // Open a performance.txt where we store the computational time for each length
    FILE * fperform;
    if((fperform = fopen("performance.txt","w")) == NULL){
        fprintf(stderr,"\nCannot open performance.txt..Program will terminate.\n");
        exit(1);
    }

    // Key Length = 1024
    clock_t start1 = clock();       // start clock
    generateRSAKeyPair(1024);
    DataEncryption(plain_text_path,cipher_text_path,publicKeyFile_1024);
    DataDecryption(cipher_text_path,"Out_1024",privateKeyFile_1024);
    clock_t end1 = clock();          // stop clock

    // calculate total elapsed time and then write it to the file
    double total_time1 = ((double)(end1 - start1)) / CLOCKS_PER_SEC;
    printf("\nTime1 = %f\n",total_time1);
    fprintf(fperform,"KEY LENGTH: 1024 - TOTAL TIME: %f\n",total_time1);

    // Key Length = 2048
    clock_t start2 = clock();       // start clock
    generateRSAKeyPair(2048);
    DataEncryption(plain_text_path,cipher_text_path,publicKeyFile_2048);
    DataDecryption(cipher_text_path,"Out_2048",privateKeyFile_2048);
    clock_t end2 = clock();          // stop clock

    // calculate total elapsed time and then write it to the file
    double total_time2 = ((double)(end2 - start2)) / CLOCKS_PER_SEC;
    fprintf(fperform,"KEY LENGTH: 2048 - TOTAL TIME: %f\n",total_time2);

    // Key Length = 4096
    clock_t start3 = clock();       // start clock
    generateRSAKeyPair(4096);
    DataEncryption(plain_text_path,cipher_text_path,publicKeyFile_4096);
    DataDecryption(cipher_text_path,"Out_4096",privateKeyFile_4096);
    clock_t end3 = clock();          // stop clock

    // calculate total elapsed time and then write it to the file
    double total_time3 = ((double)(end3 - start3)) / CLOCKS_PER_SEC;
    fprintf(fperform,"KEY LENGTH: 4096 - TOTAL TIME: %f\n",total_time3);

}


int main(int argc, char *argv[]){

    mpz_t keyLength;
    mpz_init(keyLength);

    // default path file
    char *inPath = NULL;
    char *outPath = "output.txt";
    char *keyFile = NULL;

    for (int i = 1; i < argc; i++)
    {
        char *arg = argv[i];

        if (strcmp(arg, "-h") == 0)
        {
            printf("The arguments “i”, “o” and “k” are always required when using “e” or “d” \nUsing -i and a path the user specifies the path to the input file."
                   "Using -o and a path the user specifies the path to the output file.\n"
                   "Using -k and a path the user specifies the path to the key file.\n"
                   "Using -g the tool generates a public and a private key given a key length “length” and\n"
                   "stores them to the public_length.key and private_length.key files respectively.\n"
                   "Using -d the user specifies that the tool should read the ciphertext from the input file,\n"
                   "decrypt it and then store the plaintext in the output file.\n"
                   "Using -e the user specifies that the tool should read the plaintext from the input file,\n"
                   "encrypt it and store the ciphertext in the output file.\n"
                   "Using -a the user generates three distinct sets of public and private key pairs,\n"
                   "allowing for a comparison of the encryption and decryption times for each.\n");
        }
        /* change path to the input file */
        else if (strcmp(arg, "-i") == 0){
            i++;
            inPath = (char *)malloc(strlen(argv[i] + 1));
            strcpy(inPath, argv[i]);
            printf("New inPath= %s \n", inPath);
        }
        /* change path to the output file */
        else if (strcmp(arg, "-o") == 0){
            i++;
            outPath = (char *)malloc(strlen(argv[i] + 1));
            strcpy(outPath, argv[i]);
            printf("New outPath= %s \n", outPath);
        }
        /* change path to the key file */
        else if (strcmp(arg, "-k") == 0){
            i++;
            keyFile = (char *)malloc(strlen(argv[i] + 1));
            strcpy(keyFile, argv[i]);
            printf("New keyPath= %s \n", keyFile);
        }
        /* Perform RSA key-pair generation given a key length “length” */
        else if (strcmp(arg, "-g") == 0){
            i++;
            int length = atoi(argv[i]);
            generateRSAKeyPair(length);
            printf("Key length: %d\n", atoi(argv[i]));
        }
        /* Decrypt input and store results to output */
        else if (strcmp(arg, "-d") == 0){
            if(keyFile == NULL){
                fprintf(stderr,"\nkey file or input file not specified.. Program will terminate\n");
                exit(1);
            }
            // call decrypt function
            DataDecryption(inPath,outPath,keyFile);
        }
        /* Encrypt input and store results to output */
        else if (strcmp(arg, "-e") == 0){
            if(keyFile == NULL || inPath == NULL){
                fprintf(stderr,"\nkey file or input file not specified.. Program will terminate\n");
                exit(1);
            }
            // call encrypt function
            DataEncryption(inPath,outPath,keyFile);
        }
        /* Compare the performance of RSA encryption and decryption with three
           different key lengths (1024, 2048, 4096 key lengths) in terms of computational time.*/
        else if (strcmp(arg, "-a") == 0){
            if(inPath == NULL){
                Performance_Analysis("plain_text");
            }else{
                Performance_Analysis(inPath);
            }
        }
        // wrong user input
        else{
            fprintf(stderr, "\nWrong parameter. Program will terminate..\n");
            exit(1);
        }
    }

    return 0;
}
