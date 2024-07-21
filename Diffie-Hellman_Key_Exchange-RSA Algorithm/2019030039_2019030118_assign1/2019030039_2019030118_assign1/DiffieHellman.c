#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <gmp.h>

/* Computes the power of a number */
long long power(long long int base, long long int exponent) {
    int result = 1;

    for (int i = 0; i < exponent; i++) {
        result *= base;
    }

    return result;
}

/* Check if a number is prime */
bool is_prime(int num) {
    if (num <= 1) {
        return false;
    }

    if (num <= 3) {
        return true;
    }

    // Check for divisibility from 2 up to the square root of the number
    for (int i = 2; i <= sqrt(num); i++) {
        if (num % i == 0) {
            return false; // Number is divisible by i, so it's not prime
        }
    }

    return true; // Number is prime
}

// Function to calculate (a^b) % mod using fast exponentiation
long long fastPower(long long a, long long b, long long mod) {
    long long result = 1;
    a = a % mod;
    
    while (b > 0) {
        if (b % 2 == 1)
            result = (result * a) % mod;
        
        a = (a * a) % mod;
        b /= 2;
    }
    
    return result;
}

// Function to check if g is a primitive root modulo p
int isPrimitiveRoot(long long g, long long p) {
    if (g == 0 || g == 1)
        return 0;
        
    if(g>=p-1){
        return 0;
    }
        
    int m = p - 1;
    int phi_m = m; // Euler's totient function value for p-1
    
    // Factorize phi(m)
    for (int i = 2; i * i <= m; i++) {
        if (m % i == 0) {
            while (m % i == 0) {
                m /= i;
                phi_m /= i;
            }
            phi_m *= (i - 1);
        }
    }
    
    if (m > 1) {
        phi_m /= m;
        phi_m *= (m - 1);
    }
    
    for (int i = 2; i <= phi_m; i++) {
        if (fastPower(g, i, p) == 1) {
            return 0;
        }
    }
    
    return 1;
}
/************** main function ******************/
int main(int argc, char *argv[]){
    int primeNum;
    int generator;
    long long int privateA;
    long long int publicA;
    long long int privateB;
    long long int publicB;

    // default path file
    char *path = "output.txt";
    
    for (int i=1; i< argc; i++){
        char* arg = argv[i]; 

        if(strcmp(arg,"-h") == 0){
            printf("The argument -p will include the will be the public prime number.\nThe argument -g will be the public primitive root of the previous prime number.\nThe argument -a will be the private key of user A.\nThe argument -b will be the private key of user B. \n");
        }
        else if(strcmp(arg,"-o") == 0){
            i++;
            path = (char *)malloc(strlen(argv[i]+1));
            strcpy(path,argv[i]);
            //printf("New Path= %s \n",path);
        } 
        /* Prime Number */
        else if(strcmp(arg,"-p") == 0){
            i++;
            primeNum = atoi(argv[i]);
            /* if the user gives a non-prime number -> print an error message and terminate */
            if(is_prime(primeNum) == false){
                fprintf(stderr,"Non Prime Number Given! Program Will Terminate..\n");
                exit(1);
            }   
            //printf("Prime Number: %d \n",primeNum);
        }
        /* Primitive Root for previous prime number */
        else if(strcmp(arg,"-g") == 0){
            i++;
            generator = atoi(argv[i]);
            //printf("\ng= %d, p= %d\n",generator,primeNum);
            //printf("isPrimitiveRoot = %d\n",isPrimitiveRoot(generator, primeNum));
            if(isPrimitiveRoot(generator, primeNum) == 0){
                fprintf(stderr,"Not Primitive Root Of Prime Number. Program Will Terminate..\n");
                exit(1);
            }   
            //printf("Primitive Root: %d \n",generator);
        }
        /* Private key A */
        else if(strcmp(arg,"-a") == 0){
            i++;
            privateA = atoi(argv[i]);
           //printf("Private Key A: %lld\n",privateA);
        }
        /* Private key B */
        else if(strcmp(arg,"-b") == 0){
            i++;
            privateB = atoi(argv[i]);
            //printf("Private Key B: %lld\n",privateB);
        }
        else{
            fprintf(stderr,"\nWrong parameter. Program will terminate..");
            exit(1); 
        }

    }

    /* Checks */
    if(privateA>=primeNum || privateB >= primeNum){
        fprintf(stderr,"\nAlgorithm cannot function with provided private numbers (a and b need to be lower than the Prime Number)\n");
        exit(1);
    }

    /******* Computations  *******/
    publicA = fastPower(generator, privateA, primeNum);
    publicB = fastPower(generator, privateB, primeNum);
    
    long long int solution_Alice = fastPower(publicB, privateA,primeNum);
    long long int solution_Bob = fastPower(publicA, privateB,primeNum);

    //printf("\nAlice %lld, Bob %lld\n",solution_Alice,solution_Bob);
    if(solution_Alice == solution_Bob){
        /* write data at output file */
        FILE *file;
        if((file = fopen(path,"w")) == NULL){
            fprintf(stderr,"Cannot Open Output File. Will terminate..");
            exit(1);
        }
        fprintf(file,"<%lld>, <%lld>, <%lld>",publicA,publicB,solution_Alice);
        fclose(file);
    }
    
    return 0;
}
