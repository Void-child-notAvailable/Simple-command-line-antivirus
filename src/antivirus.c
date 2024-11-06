#include "antivirusLibs.c"
//gcc antivirus.c -I/usr/include -lssl -lcrypto -lcurl -o antivirus
//./antivirus scan /home/val/Desktop/un/Target/
//./antivirus inspect /home/val/Desktop/un/Target/
//./antivirus monitor /home/val/Desktop/un/uwu/
//./antivirus slice 12
//./antivirus unlock "(1,306)" "(3,1608)" "(10,13662)"

int main(int argc, char* argv[]){
    if(argc==3 && strncmp(argv[1],"scan",5)==0){
        char* path=argv[2];
        DIR *d;
        if((d=opendir(path))==NULL){
            perror("Error opening path");
            exit(1);
        }
        printf("[INFO] Antivirus Scan started on dir %s\n\n",path);
        exploreDir(d,path,1);
        closedir(d);
        printf("\n[INFO] Antivirus Scan finished\nFiles scanned: %d\nFound %d infected\n",filesFound,infectedFiles);
    }
    else if(argc==3 && strncmp(argv[1],"inspect",8)==0){
        char* path=argv[2];
        DIR *d;
        if((d=opendir(path))==NULL){
            perror("Error opening path");
            exit(1);
        }
        printf("[INFO] Antivirus Scan started on dir %s\n\n",path);
        exploreDir(d,path,2);
        closedir(d);
        printf("\n[INFO] Antivirus Scan finished\nFiles scanned: %d\nLinks Found: %d\nFound %d malware domains\n",filesFound,domains,infectedFiles);
    }
    else if (argc==3 && strncmp(argv[1],"monitor",8)==0){
        char* path=argv[2];
        printf("[INFO] Antivirus Monitoring started on dir %s\n\n",path);
        monitor(path);
    }
    else if(argc==3 && strncmp(argv[1],"slice",6)==0){
        int a0=atoi(argv[2]);
        printf("[INFO] Generating shares for key %d\n",a0);
        split(a0);
    }
    else if (argc==5 && strncmp(argv[1],"unlock",7)==0){          //12 ./antivirus unlock (1,306) (3,1608) (10,13662)
        printf("[INFO] Generating key from 3 shares given\n");
        unlock(argv[2],argv[3],argv[4]);
    }else{
        printf("Invalid input, check README file for further info\n");
    }
    return 0;
}