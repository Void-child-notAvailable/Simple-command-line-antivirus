Antivirus Sample Program
This is a simple command-line antivirus program designed to scan, inspect, and monitor directories for malware. It also includes functionality for generating and unlocking encryption keys.

Author: 
    csd4616

Compilation:
To compile* the program, use the following command:
    make all 
or
    gcc /src/antivirus.c -I/usr/include -lssl -lcrypto -lcurl

To clean:
    make clean


Dependencies:
This program requires the following libraries:
OpenSSL (-lssl -lcrypto)
libcurl (-lcurl)


Scanning:
To scan a directory for malware based on the kozalibear attack(sha256/md5 hash,virus signature,bitcoin wallet**) use the following command:
./antivirus scan /path/to/directory

Inspecting:
To inspect a directory for malware and potential malicious links based on the response of the family.cloudflare dns server, use the following command:
./antivirus inspect /path/to/directory

Monitoring:
To monitor a directory for the kozalibear attack pattern, use the following command:
./antivirus monitor /path/to/directory

Key Generation:
To generate 10 shares based on Shamir's secret sharing scheme for a given key, use the following command:
./antivirus slice key

Key Unlocking:
To regain a key from three shares, use the following command***:
./antivirus unlock "(shareX1, shareY1)" "(shareX2, shareY2)" "(shareX3, shareY3)"


Sample tests:
./bin/antivirus scan scan_tests/
./bin/antivirus inspect inspect_tests/
./bin/antivirus monitor /path/
    touch a
    cat a           /// copy a
    touch a.locked  /// create a.locked
    nano a.locked   /// encrypt contents of a to a.locked
    rm a            /// remove a !!Warning!!
./bin/antivirus slice 12
./bin/antivirus unlock "(1,306)" "(3,1608)" "(10,13662)"


Notes:
* md5 and sha256 are depricated so warnings will show up during compilation
   
** Bitcoin wallet not checked properly in binary files
   
*** Proper input would be (x,y) but the command line is weird about the parenthesis so add the ""
