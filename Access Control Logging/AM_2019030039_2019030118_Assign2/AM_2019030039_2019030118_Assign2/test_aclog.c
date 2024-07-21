#include <stdio.h>
#include <string.h>
#include <unistd.h>


int main() 
{
	int i;
	size_t bytes;
	FILE *file;

	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	/* example source code */
		//printf("\n OPENNING FILE--------------------artharthat");

	for (i = 0; i < 10; i++) {
		//printf("\n OPENNING FILE %s", filenames[i]);

		file = fopen(filenames[i], "a+");
		//file = fopen(filenames[i], "r");

		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}

	// open a file for reading and try to write to it
	for(int i=0; i<10; i++){
		FILE * testFile = fopen(filenames[i],"r");
		char toBeWritten[10] = "0123456789";
		fwrite(toBeWritten,strlen(toBeWritten),1,testFile);
		fclose(testFile);
	}


}
