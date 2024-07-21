#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#define ACCESS_TYPE_CREATE 0
#define ACCESS_TYPE_OPEN 1
#define ACCESS_TYPE_WRITE 2
#define BUFFER_SIZE 1024
#define LOG_FILE_NAME "file_logging.log"


// function to remove the last line of a file
void removeLastLine(FILE *file) {

    fseek(file, -1, SEEK_END); // Move one character before the end of the file

    long pos = ftell(file);

    // Move backward until a newline character is found
    while (pos > 0 && fgetc(file) != '\n') {
        fseek(file, --pos, SEEK_SET);
    }

    // Set the file size to the position of the last newline character
    ftruncate(fileno(file), pos);
}


/////////////////////////////////////////////////////////////////////////////////////////////
void fileFingerPrintCalculate(const char *path, unsigned char* hash_result){

	//FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char *, const char *);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	//to start, we open the file in binary read mode
	FILE *file = original_fopen(path, "rb");
	if (file == NULL) {
		fprintf(stderr,"Error opening file");
		exit(1);
	}

	// We create an EVP message digest context (mdctx) and specify the SHA-256 algorithm (md).
	// We initialize the digest context with the chosen algorithm.
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); 			// the context or state of the message digest algorithm 
	const EVP_MD *md = EVP_sha256();      			// specify the hash algorithm
	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {  //if initialization of digest context fails we free the struct 
        fprintf(stderr,"Error opening file");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        exit(1);
    }
	
	
	// Read the file in chunks of BUFFER_SIZE bytes and update the digest context with each chunk.
	unsigned char buffer[BUFFER_SIZE];
	size_t bytes_read;
	//unsigned char hash_result[EVP_MAX_MD_SIZE];

	while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) != 0) {
		if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
        fprintf(stderr,"Error updating SHA-256 digest");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        exit(1);
    	}
	}

	EVP_DigestFinal_ex(mdctx, hash_result, NULL);  // store the result of the hash into the hash_result

	//printf("\nHash Result: %02x/n",hash_result);
    EVP_MD_CTX_free(mdctx);

    fclose(file);  

}


void WriteLogs(uid_t uid, const char* path, char* filename, int day, int month, int year, int hours, int minutes, int seconds, int accessType, int actionDeniedFlag, unsigned char hash_result[]){

	//FILE *log_file = fopen(LOG_FILE_NAME, "w");
	FILE *(*original_fopen)(const char *, const char *);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	FILE *log_file = original_fopen(LOG_FILE_NAME,"a");

	//printf("\nOpening log file\n");	
	if (log_file == NULL) {
		fprintf(stderr,"Error opening log file");
		exit(1);
	}
	
	char * log_text = "Log: ";
	char * date_txt = "Date: ";	
	char * time_txt = "Time: ";
	char * access_Type_txt = "Access Type: ";
	
	
	// Writing uid	
	fprintf(log_file,"%s", log_text);
	fprintf(log_file," UID: %u\n", uid);

	// Writing File Path	
	fprintf(log_file,"%s", log_text);		
	fprintf(log_file," File Path: %s\n", path);

	// Writing File Name
	fprintf(log_file,"%s", log_text);
	fprintf(log_file," File Name: %s\n",filename);
	
	// Writing date in format "Log: Date: dd/mm/yyyy"
	fprintf(log_file,"%s %s %d/%d/%d\n", log_text,date_txt,day,month,year);
	
	// Writing Timestamp "Log: Time: %H:%M:%S"
	fprintf(log_file,"%s %s %d:%d:%d\n", log_text,time_txt,hours,minutes,seconds);

	// Writing The accessType
	fprintf(log_file, "%s %s %d\n",log_text,access_Type_txt,accessType );

	// Writing Is-action-denied flag
	char * action_flag_txt = "Is-action-denied flag: ";
	fprintf(log_file,"%s %s %d\n",log_text,action_flag_txt,actionDeniedFlag);

	// Writing File fingerprint
	fprintf(log_file,"%s File Fingerprint: ",log_text);
    for (int i = 0; i < EVP_MD_size(EVP_sha256()); i++) {		// EVP_MD_size is a function that takes a pointer to a hash algorithm and returns the size of the hash produced by that algorithm in bytes.
        //printf("%02x", hash_result[i]);	   	    // returns the size of the hash produced by that algorithm in bytes.
		//fwrite(&hash_result[i], sizeof(char), 1, log_file);
		fprintf(log_file,"%02x",hash_result[i]);
		//fprintf(log_file,"%s",hash_result[i]);

    }
	char * tmp = "\n\n";
	fprintf(log_file,"%s",tmp);
	
	fclose(log_file);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
/* Get the path of the file given the steam */
char* getFilePath(FILE* stream, char* path_result) {
	
    int fno;
    ssize_t r; 
	char proclnk[4095];

	if (stream != NULL){
		
        fno = fileno(stream);
        sprintf(proclnk, "/proc/self/fd/%d", fno);
        r = readlink(proclnk, path_result, 4095);
        if (r < 0)
        {
            //printf("failed to readlink\n");
            exit(1);
        }
        path_result[r] = '\0';
        /*printf("fp -> fno -> filename: %p -> %d -> %s\n",
                stream, fno, path_result);*/
    }
    return NULL;	
}

////////////////////////////////////////////////////////////////////////////////////////////////

FILE *fopen(const char *path, const char *mode){

	//printf("\nInside My fopen\n");

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char *, const char *);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	/* 1*/
	//printf("\nALL STEPS BEFORE 1\n");
	uid_t uid = getuid();
	
	/* 2*/
	//printf("\nALL STEPS BEFORE 2\n");
	char *filename = strrchr(path, '/');
	// If '/' is not found, use the original path
    if (filename == NULL) {
		filename =(char *)malloc(strlen(path) *sizeof(char) + 1);
		strcpy(filename,path);
    } else {
        // Move the pointer to the character after '/' so that the filename variable is only the name of the file we have opened 
        filename++;
    }

	//printf("\nALL STEPS BEFORE 3\n"); 
	/* 3 */
	// Convert the time to a struct tm
	time_t currentTime;
    time(&currentTime);
    struct tm *localTime = localtime(&currentTime);

	// Extract the date components
    int year = localTime->tm_year + 1900;  // Years since 1900
    int month = localTime->tm_mon + 1;     // Months start from 0
    int day = localTime->tm_mday;

	//printf("\nALL STEPS BEFORE 4\n");

	/* 4 */
    // Convert the time to a string
	int hours = localTime->tm_hour;
    int minutes = localTime->tm_min;
    int seconds = localTime->tm_sec;
	
	/* 5 */
	//printf("\nALL STEPS BEFORE 5\n");
	int accessType;
	// Check if the file exists, if the file exists that means that we want to open it -> AccessType = 1, else we want to create it, AccessType = 0
    if (access(path, F_OK) == 0) {//The F_OK constant is used to check for the existence of the file.
        // File Exists
		accessType = ACCESS_TYPE_OPEN;
    } else {
		//File does not exist and is created
		accessType = ACCESS_TYPE_CREATE;
    }

	//printf("\nALL STEPS BEFORE 6\n");
	/*6*/
	int actionDeniedFlag;
	// Read
	if(strcmp(mode, "r") == 0){
		if (access(path, R_OK) == 0) {
			// Read access granted to the file
			actionDeniedFlag = 0;
		} 
		// Read access denied to the file
		else {
			actionDeniedFlag = 1;
		}
	}
	// Write and Append
	else if (strcmp(mode,"r") == 0 || strcmp(mode,"a") == 0 ){
		if (access(path, W_OK) == 0) {
			// Write access granted to the file
			actionDeniedFlag = 0;
		} 
		// Write access denied to the file
		else {
			actionDeniedFlag = 1;
		}
	}
	// Read And Write
	else if(strcmp(mode,"r+") == 0  || strcmp(mode,"w+") == 0 ||strcmp(mode,"a+") == 0 ){
		if (access(path, R_OK) == 0 || access(path, W_OK) == 0) {
			// Read and Write access granted to the file
			actionDeniedFlag = 0;
		} 
		// Read/Write access denied to the file
		else {
			actionDeniedFlag = 1;
		}
	}
		
	/*7*/
	// We create an EVP message digest context (mdctx) and specify the SHA-256 algorithm (md).
	// We initialize the digest context with the chosen algorithm.
	//EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); 			// the context or state of the message digest algorithm 
	
	//const EVP_MD *md = EVP_sha256();      			// specify the hash algorithm
	
	unsigned char hash_result[EVP_MAX_MD_SIZE];
	fileFingerPrintCalculate(path, hash_result);
	
	// write the logs to the file*/
	
	WriteLogs(uid,path,filename,day,month,year,hours,minutes,seconds,accessType,actionDeniedFlag,hash_result);

	return original_fopen_ret;

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	/* 1*/
	uid_t uid = getuid();
	
	/* 2*/
	char filepath[4095];
	getFilePath(stream,filepath);

	char *filename = strrchr(filepath, '/');
	// If '/' is not found, use the original path
    if (filename == NULL) {
		strcpy(filename,filepath);
        //filename = path;
    } else {
        // Move the pointer to the character after '/' so that the filename variable is only the name of the file we have opened 
        filename++;
    }

	/* 3 */
	// Convert the time to a struct tm
	time_t currentTime;
    time(&currentTime);
    struct tm *localTime = localtime(&currentTime);

	// Extract the date components
    int year = localTime->tm_year + 1900;  // Years since 1900
    int month = localTime->tm_mon + 1;     // Months start from 0
    int day = localTime->tm_mday;
	
	/* 4 */
    // Convert the time to a string
	int hours = localTime->tm_hour;
    int minutes = localTime->tm_min;
    int seconds = localTime->tm_sec;

	/* 5 */
	int accessType = ACCESS_TYPE_WRITE;

	/*6*/
	
	// try to write to the file. if we write successfully then we have the permission
	int actionDeniedFlag;
	if(fprintf(stream,"\nTest write") > 0){
		removeLastLine(stream); // remove the "Test write" line that we just wrote
		// Write access granted to the file
		actionDeniedFlag = 0;
	}
	// Write access denied to the file
	else{
		actionDeniedFlag =1;
	}
	
	/*7*/
	// We create an EVP message digest context (mdctx) and specify the SHA-256 algorithm (md).
	// We initialize the digest context with the chosen algorithm.
	//EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); 			// the context or state of the message digest algorithm 
	//const EVP_MD *md = EVP_sha256();      			// specify the hash algorithm
	
	unsigned char hash_result[EVP_MAX_MD_SIZE];
	fileFingerPrintCalculate(filename, hash_result);
	////////////////////////////////////////////////////////////////////////////////
	
	WriteLogs(uid,filepath,filename,day,month,year,hours,minutes,seconds,accessType,actionDeniedFlag,hash_result);

	return original_fwrite_ret;
}