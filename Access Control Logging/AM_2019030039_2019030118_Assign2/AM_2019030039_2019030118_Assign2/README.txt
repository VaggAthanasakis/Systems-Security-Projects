Authors:
Athanasakis Evangelos
George Fragkogiannis

GCC Version:
gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0

-------------------------------------- Compilation And General Info --------------------------------------------
- In order to test this program, firstly you have to run the command <<make all>> in order to compile logger.c, acmonitor.c and test_aclog.c 
- The Compilation of logger.c file gives us the logger.so file
- Then, you have to run the command <<make run>> in order to run the test_aclog and create/write in 10 files and try to write in  
  a file that was previously opened with read flag.
- logger.c must create a "file_logging.log" file and inside it, it must log all the events of file creation, file opening and file modification
- Then, ac_monitor takes as input the "file_logging.log" file and extracts info about malicious users, the number of times a specific malicious user
  has tried to open a specific file with no permission and the number of times a file got modified by each user.
- For this assignment, a “malicious user” is the user that tries to access multiple files without having the
  permission. For Step 2, when we refer to a “malicious user” we refer to the user that tries to access more
  than 7 different files without having the permission.

-------------------------------------- Step 1: Access Control Logging tool --------------------------------
In this step we created an .so library (shared library), the logger.c file, to add a custom implementation (override)
of fwrite and fopen functions of the standard c library. The functions logged information about the file being openned,
created or modified. The info logged were:
1. UID: The unique user ID assigned by the system to a user (hint: see getuid() function).
2. File name: The path and name of the accessed file.
3. Date: The date that the action occurred.
4. Timestamp: The time that the action occurred.
5. Access type: For file creation, the access type is 0. For file open, the access type is 1. For file
write, the access type is 2.
6. Is-action-denied flag: This field reports if the action was denied to the user with no access
privileges. It is 1 if the action was denied to the user, or 0 otherwise.
7. File fingerprint: The digital fingerprint of the file the time the event occurred. This digital
fingerprint is the hash value of the file contents 

More specificly, in fopen() before the original fopen() function executes we extract the info mentioned above and 
write it in the file_logging.log file in the following format:

Log:  UID: <id>
Log:  File Path: <path of file>
Log:  File Name: <name of file>
Log:  Date:  dd/mm/yyyy
Log:  Time:  hh:mm:ss
Log:  Access Type:  0/1/2 (Create -> 0, Open-> 1, Write -> 2)
Log:  Is-action-denied flag:  0/1 (0 if allowed 1 if access denied)
Log:  File Fingerprint: <file fingerprint/hash value>

NOTE: The same formatting is used for the logs of the fwrite function

Same thing happens with fwrite(), the information mentioned above is logged in the log file.
The only difference is that this time since we have the file stream as input, we need to use the 
stream to find the path to the file and the file's name. Again, the information about the file 
and the user is logged and then the original fwrite function executes.

---------------------------------- Step 2: Access Control Log Monitoring tool --------------------------------
- Here a log monitoring tool was developed, named “acmonitor.c”, which is responsible for monitoring the logs
  created by the Access Control Logging tool (Step 1). This log monitoring tool:
  1) Parse the log file generated in Step 1 and extract all incidents where malicious users tried to
     access multiple files without having permissions. As an output, the tool should print all users
     that tried to access more than 7 different files without having permissions
  2) Given a filename, the log monitoring tool tracks and reports all users that have accessed
     the specific file. By comparing the digital fingerprints/hash values, the log monitoring tool
     checks how many times the file was indeed modified. As an output, the log monitoring tool
     prints a table with the number of times each user has modified it.
- Tool Specification:
  The Access Control Log Monitoring tool (Step 2) receives the required arguments from the command
  line upon execution          
  Options: -m              Print malicious users
           -i <filename>   Prints table of users that modified the file given and the number of modifications
           -h              Prints help message


---------------------------------- Step 3: Test the Access Control Logging & Log Monitoring tools --------------------------------
-- In this step, a simple tool, named “test_aclog.c”, is used to test and demonstrate the above tasks.
   The “test_aclog.c” tool creates/opens/modifies files, in a way that it creates the conditions that the
   “acmonitor.c” tool searches for. For instance, it tries to open files without having the permission
   to do so (Step 2.1), and modify specific files (Step 2.2).

