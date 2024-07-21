#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bits/getopt_core.h>

#define MIN_DENIED_ENTRIES 7

struct entry {

	int uid;		   /* user id (positive integer) */
	int access_type;   /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file;		   /* filename (string) */
	char *fingerprint; /* file fingerprint */
	char *path;

};


void usage(void) {
	printf(
		"\n"
		"usage:\n"
		"\t./monitor \n"
		"Options:\n"
		"-m, Prints malicious users\n"
		"-i <filename>, Prints table of users that modified "
		"the file <filename> and the number of modifications\n"
		"-h, Help message\n\n");

	exit(1);
}

//////////////////////////////////////////////////////////////////////////////////////
struct MaliciousUser {
    int uid;
    char files[50][50]; // holds the filenames of the files the user tried to access
	int filesCounter;
};
//////////////////////////////////////////////////////////////////////////////////////
/* Find the Unauthorised users that tried to access (without permission) 7 different files*/
void findMaliciousUsers(FILE *logFile, struct MaliciousUser arrayOfUsers[100]){
	char line[100];
	int uid;
	char fileName[50];
	int actionDeniedFlag;
	int i = 0;
	//int found =0;
	int foundUID=0;
	int foundFile=0;
	// initialise the array
	for (int k = 0; k < 100; k++) {
		arrayOfUsers[k].uid = 0;
		arrayOfUsers[k].filesCounter = 0;
    }


	// Read the file line by line
	while (fgets(line, sizeof(line), logFile) != NULL) {
		foundUID=0;
		foundFile=0;
        // Check if the search string is present in the current line
        if (strstr(line, "UID: ") != NULL) {
            //printf("String found in file: %s", line);
			sscanf(line, "Log:  UID: %d", &uid);

			//Move line for path
			fgets(line, sizeof(line), logFile) != NULL;

			//Move line to get file name
			fgets(line, sizeof(line), logFile) != NULL;
			sscanf(line, "Log:  File Name: %s", fileName);
			
			// move from date
			fgets(line, sizeof(line), logFile);
			
			// move from time
			fgets(line, sizeof(line), logFile);
			
			// move from access_type
			fgets(line, sizeof(line), logFile);
			
			// get action denied flag
			fgets(line, sizeof(line), logFile);
			sscanf(line,"Log:  Is-action-denied flag:  %d\n",&actionDeniedFlag);

			if(actionDeniedFlag == 1){ // then store the user to the array
				// Search if the uid already exists in the array
				for (int j = 0; j < 100; j++) {
        			if (arrayOfUsers[j].uid == uid) { // user already exists							
						//check if file is modified by user for the first time or if he has already modified it before
						foundUID=1;						
						for (int z = 0; z < arrayOfUsers[j].filesCounter; z++) {
        					if (strcmp(fileName, arrayOfUsers[j].files[z]) == 0) {
            					foundFile = 1;  // foundFile 1 if the file exists in the files array
        					}
    					}
						if (foundFile == 0){
							arrayOfUsers[j].filesCounter++;
							strcpy(arrayOfUsers[j].files[arrayOfUsers[j].filesCounter],fileName);
						}
        			}							
    			}
				
				if (foundUID == 0){						// user doesn't exist, so make new ent
					arrayOfUsers[i].uid = uid;
					arrayOfUsers[i].filesCounter ++;
					strcpy(arrayOfUsers[i].files[arrayOfUsers[i].filesCounter],fileName);
					i++;
				}
						
			}
        }		
    }
	return;	
	
}

///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

/* Function that prints the list of unauthorised users */
void list_unauthorized_accesses(FILE *log) {
	//int ArrayOfUsers[100][2];
	struct MaliciousUser ArrayOfUsers[100];
	findMaliciousUsers(log, ArrayOfUsers);	
	// print all the users that have tried to access files more that 7 times
	// and the permission was denied by the system
	for(int i = 0; i<100; i++){
		if(ArrayOfUsers[i].filesCounter > MIN_DENIED_ENTRIES){
			printf("\nUser: %d has been denied %d times", ArrayOfUsers[i].uid,ArrayOfUsers[i].filesCounter);			
		}
	}

	printf("\n");

	return;
}

/* Calculate the number of lines of a given file */
int CalculateFileLines(FILE *log){
	int lineCount = 0;
	char line[100];

    // Count lines in the file
  	char ch;
    while ((ch = fgetc(log)) != EOF) {
        if (ch == '\n') {
            lineCount++;
        }
    }

    fseek(log, 0, SEEK_SET);
	return lineCount;
}

///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////
void list_file_modifications(FILE *log, char *file_to_scan) {
	// calculate the log file lines
	int numOfLines = CalculateFileLines(log);
	numOfLines = numOfLines / 9;
	

	struct entry arrayOfEntries[numOfLines];
	// search the given file inside the log file
	char line[100];
	char buffer[1000];
	char fileName[20];
	int accessType = -1;
	int isActionDeniedFlag;
	int uid;
	int entry_counter = 0;

	while (fgets(line, sizeof(line), log) != NULL) {
        // Check if the searched file is present in the current line
        if (strstr(line, "Log:  UID: ") != NULL) {
			sscanf(line,"Log:  UID: %d\n",&arrayOfEntries[entry_counter].uid);			
			
			// do gets to move to the next line
			fgets(line, sizeof(line), log);			
			
			// get the filename
			fgets(line, sizeof(line), log);			
			arrayOfEntries[entry_counter].file = (char*)malloc(sizeof(char)*50);
			sscanf(line,"Log:  File Name: %s\n",arrayOfEntries[entry_counter].file);

			// move from date
			fgets(line, sizeof(line), log);
			
			// move from time
			fgets(line, sizeof(line), log);
			
			// get access_type
			fgets(line, sizeof(line), log);
			sscanf(line,"Log:  Access Type:  %d\n",&arrayOfEntries[entry_counter].access_type);

			// get action denied flag
			fgets(line, sizeof(line), log);
			sscanf(line,"Log:  Is-action-denied flag:  %d\n",&arrayOfEntries[entry_counter].action_denied);

			// get file fingerprint
			fgets(line, sizeof(line), log);
			arrayOfEntries[entry_counter].fingerprint = (char*)malloc(sizeof(char)*100);
			sscanf(line,"Log:  File Fingerprint: %s\n",arrayOfEntries[entry_counter].fingerprint);
			
					
			memset(line, 0, sizeof(line));		
			entry_counter ++;
			

		}
	}

	int numOfModificartions = 0;
	int numOfNewUsers = 0;
	char currentFingerprint[100];
	int resultTable[numOfLines][2];
	int found=0;
	for (int i = 0; i < numOfLines; i++) {
        for (int j = 0; j < 2; j++) {
			resultTable[i][j] =0;
        }
    }
	// Search for file modifications
	// File modifications have occured if the access_type = 2 && action_denied = 0 && we have different hash values
	int numElements = sizeof(arrayOfEntries) / sizeof(arrayOfEntries[0]);
	for (int i=0; i< numOfLines; i++){
		fflush(stdout);
		if(strcmp(arrayOfEntries[i].file, file_to_scan) == 0  && arrayOfEntries[i].access_type == 2 && arrayOfEntries[i].action_denied == 0){ // found the given file
			found = 0;
			// if at that entry, the user achieved to write to the file
			fflush(stdout);
			if(strcmp(currentFingerprint, arrayOfEntries[i].fingerprint) != 0){  // if we have different fingerprints, increase counter
				strcpy(currentFingerprint, arrayOfEntries[i].fingerprint);       // copy the new fingerprint at the current fingerprint
				// Checking if user that modified the file is new or has already modified it before
				// and raising the number of modifications he has made to the file by 1	
				for (int k = 0; k < numOfLines; k++) {
        			if (resultTable[k][0] == arrayOfEntries[i].uid) {
						resultTable[k][1]++; 
						found = 1;       			
        			}
    			}
				if (found == 0){ // the user does not already exist -> add him to the array
					resultTable[numOfNewUsers][0] = arrayOfEntries[i].uid;
					resultTable[numOfNewUsers][1]++;
					numOfNewUsers++;  // next free position of the array
				}
			}
		}
		
	}
	// print the number of times each user has modified the given file
	printf("\nFile name: %s\n",file_to_scan);	
	fflush(stdout);
	for(int i=0; i<numOfNewUsers; i++){
		printf("User: %d Number of Modifications: %d \n", resultTable[i][0],  resultTable[i][1]);
	}

	memset(resultTable, 0, sizeof(resultTable));	
	
}

///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[]) {

	//printf("\nInside monitor\n");

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch)
		{
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}
	}

	fclose(log);
	argc -= optind;
	argv += optind;

	return 0;
}
