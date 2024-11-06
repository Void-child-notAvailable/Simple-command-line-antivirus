#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <regex.h>
#include <curl/curl.h> 
#include <sys/inotify.h>
#include <sys/random.h>

#define DIR_TYPE 4 
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

typedef struct filelist {
    char *name; 
    int phase;
    struct filelist *next;  
}filelist;

int filesFound=0;
int infectedFiles=0;
int domains=0;
filelist *top=NULL;
filelist *bottom=NULL;

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////           Scan/Inspect Functs
/////////////////////////////////////////////////////////////////////////////////////////////////////////////



size_t checkoutput(void *ptr, size_t size, size_t nmemb, void *userdata) {
    if(strstr((char*)ptr,"EDE(")){      // EDE()  is short for extended dns errors, for the sake of this exercise i assume any error is an indicator of a virus                    // )
        infectedFiles++;
        printf("[Result]: Malware\n\n");
    }else{
        printf("[Result]: Safe\n\n");
    }

    return size * nmemb;
}

int isExe(char *path){
    struct stat fileStat;
    if (stat(path, &fileStat) < 0) {
        perror("Error getting file stats");
    }
    if (S_ISREG(fileStat.st_mode) && (fileStat.st_mode & S_IXUSR))
        return 1;
    else
        return 0;
}

void computePrefixFunction(const char* pattern, int prefix[], int pattern_length) {
    int k = 0;
    prefix[0] = 0;

    for (int i = 1; i < pattern_length; ++i) {
        while (k > 0 && pattern[k] != pattern[i]) {
            k = prefix[k - 1];
        }
        if (pattern[k] == pattern[i]) {
            k++;
        }
        prefix[i] = k;
    }
}

int searchPatternInFile(FILE *file, const char* pattern) {          /// https://www.scaler.com/topics/data-structures/kmp-algorithm/
    int pattern_length = strlen(pattern);
    int* prefix = (int*)malloc(sizeof(int) * pattern_length);

    computePrefixFunction(pattern, prefix, pattern_length);

    char ch;
    int k = 0;
    while ((ch = fgetc(file)) != EOF) {
        while (k > 0 && pattern[k] != ch) {
            k = prefix[k - 1];
        }
        if (pattern[k] == ch) {
            k++;
        }
        if (k == pattern_length) {
            free(prefix);
            return 1;
        }
    }

    free(prefix);
    return 0;
}

int searchBinPatternInFile(FILE *file, const unsigned char* pattern) {
    int pattern_length = sizeof(pattern);
    int* prefix = (int*)malloc(sizeof(int) * pattern_length);

    computePrefixFunction(pattern, prefix, pattern_length);

    unsigned char ch;
    int k = 0;
    while ((fread(&ch, sizeof(unsigned char), 1, file)) == 1) {
        while (k > 0 && pattern[k] != ch) {
            k = prefix[k - 1];
        }
        if (pattern[k] == ch) {
            k++;
        }
        if (k == pattern_length) {
            free(prefix);
            return 1;
        }
    }

    free(prefix);
    return 0;
}

void calcSha256(char* path){
    unsigned char sha256Res[SHA256_DIGEST_LENGTH];
    FILE *file = fopen(path, "rb");
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    char buffer[2048];
    size_t bytes;

    while((bytes=fread(buffer,1,sizeof(buffer),file))!=0){
        SHA256_Update(&ctx,buffer,bytes);
    }

    fclose(file);

    SHA256_Final(sha256Res,&ctx);
    char expectedSHA256[] = "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849";
    char sha256String[2 * SHA256_DIGEST_LENGTH + 1];

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&sha256String[i * 2], "%02x", (unsigned int)sha256Res[i]);
    }

    if (memcmp(sha256String, expectedSHA256, sizeof(expectedSHA256)) == 0) {
        // SHA256 matches
        infectedFiles++;
        printf("[WARN] SHA256 match:          %s\n", path);
    }
}

void calcMd5(char* path){
    unsigned char md5Res[MD5_DIGEST_LENGTH];
    FILE *file = fopen(path, "rb");
    MD5_CTX ctx;
    MD5_Init(&ctx);
    char buffer[2048];
    size_t bytes;

    while((bytes=fread(buffer,1,sizeof(buffer),file))!=0){
        MD5_Update(&ctx,buffer,bytes);
    }

    fclose(file);

    MD5_Final(md5Res,&ctx);
    char expectedMD5[] = "85578cd4404c6d586cd0ae1b36c98aca";
    char md5String[2 * MD5_DIGEST_LENGTH + 1];

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&md5String[i * 2], "%02x", (unsigned int)md5Res[i]);
    }

    if (memcmp(md5String, expectedMD5, sizeof(expectedMD5)) == 0) {
        // MD5 matches
        infectedFiles++;
        printf("[WARN] MD5 match:             %s\n", path);
    }
}

void checksig(char* path){
    FILE *file = fopen(path, "rb");
    unsigned char signature[] = {0x98, 0x1d, 0x00, 0x00, 0xec, 0x33, 0xff, 0xff,
                                    0xfb, 0x06, 0x00, 0x00, 0x00, 0x46, 0x0e, 0x10};
    if(searchBinPatternInFile(file,signature)==1){
        infectedFiles++;
        printf("[WARN] Virus Signature Match: %s\n", path);
    }
    fclose(file);
    return;
}

void checkbitcoin(char* path){
    FILE *file = fopen(path, "r");
    char *bitcoinwallet = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6";
    if(searchPatternInFile(file,bitcoinwallet)==1){
        infectedFiles++;
        printf("[WARN] Bitcoin Wallet match:  %s\n", path);
    }
    fclose(file);
}


void checkWebsite(char *url){
    CURL *curl;
    CURLcode code;
    curl = curl_easy_init();
    if (curl){
        struct curl_slist *slist = NULL;
        slist = curl_slist_append(slist,"accept:application/dns-json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

        char *cloudflareUrl = malloc(1024*sizeof(char));
        if (strncmp(url, "https://", 8) == 0) {
            snprintf(cloudflareUrl, 1024, "https://family.cloudflare-dns.com/dns-query?name=%s", url + 8);
        } else if (strncmp(url, "http://", 7) == 0) {
            snprintf(cloudflareUrl, 1024, "https://family.cloudflare-dns.com/dns-query?name=%s", url + 7);
        } else {
            snprintf(cloudflareUrl, 1024, "https://family.cloudflare-dns.com/dns-query?name=%s", url);
        }
        curl_easy_setopt(curl, CURLOPT_URL, cloudflareUrl);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,checkoutput);

        code = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}


void inspectExe(char *path){
    regex_t regex;
    regmatch_t match[16]; 
    int BUCKET=1024;
    char buff[BUCKET];
    int j=0;
    char *line = malloc(BUCKET*sizeof(char));
    int reti = regcomp(&regex, "(https?|www)\\S*?(\\.com|\\.gr)", 1);
    if (reti) {
        char error_message[100];
        regerror(reti, &regex, error_message, sizeof(error_message));
        fprintf(stderr, "Could not compile regex: %s\n", error_message);
        exit(1);
    }
    FILE *f = fopen(path, "rb");
    size_t bytesRead;
    while ((bytesRead = fread(buff, 1, 1024, f)) > 0) {
        for (size_t i = 0; i < bytesRead; i++) {
            if(buff[i]=='\n'){
                reti = regexec(&regex, line, 16, match, 0);
                if (!reti) {
                    char *url = line + match[0].rm_so; 
                    int url_length = match[0].rm_eo - match[0].rm_so; 
                    char extracted_url[url_length + 1]; 
                    snprintf(extracted_url, url_length + 1, "%s", url); 
                    printf("[INFO] Extracted URL: %s\nFrom executable in path:%s\n", extracted_url,path);
                    checkWebsite(extracted_url);
                    domains++;
                } else if (reti == REG_NOMATCH) {
                    
                } else {
                    regerror(reti, &regex, line, sizeof(line));
                    fprintf(stderr, "Regex match failed: %s\n", line);
                    exit(1);
                }
                j=0;
            }else if(buff[i]>=33 && buff[i]<=126){/// so, since binary files have all sorts of weird characters that mess up the string, i just need the ones that form a vaid url
                line[j++]=buff[i];
                if(j==BUCKET){
                    BUCKET+=BUCKET;
                    line = realloc(line, BUCKET*sizeof(char));
                }
            }else{
                line[j++]=' ';
                if(j==BUCKET){
                    BUCKET+=BUCKET;
                    line = realloc(line, BUCKET*sizeof(char));
                }
            }
        }
    }
    fclose(f);
    regfree(&regex);
}



void scan(char* path){
    calcSha256(path);
    calcMd5(path);
    checksig(path);
    checkbitcoin(path);     // TODO check for binary files
}

void inspect(char* path) {
    regex_t regex;
    regmatch_t match[32]; 
    char line[1024];
    int reti = regcomp(&regex, "(https?|www)\\S*?(\\.com|\\.gr)", 1);
    if (reti) {
        char error_message[100];
        regerror(reti, &regex, error_message, sizeof(error_message));
        fprintf(stderr, "Could not compile regex: %s\n", error_message);
        exit(1);
    }

    FILE *f = fopen(path,"r");
    while (fgets(line, sizeof(line), f)) {
        reti = regexec(&regex, line, 32, match, 0);
        if (!reti) {
            char *url = line + match[0].rm_so; 
            int url_length = match[0].rm_eo - match[0].rm_so; 
            char extracted_url[url_length + 1]; 
            snprintf(extracted_url, url_length + 1, "%s", url); 
            printf("[INFO] Extracted URL: %s\nFrom non-executable from path:%s\n", extracted_url,path);
            checkWebsite(extracted_url);
            domains++;
        } else if (reti == REG_NOMATCH) {
            
        } else {
            regerror(reti, &regex, line, sizeof(line));
            fprintf(stderr, "Regex match failed: %s\n", line);
            exit(1);
        }
    }
    fclose(f);
    regfree(&regex);
}


void exploreDir(DIR* d,char* path,int choice){
    struct dirent *dp;
    switch (choice){
        case 1:
            while((dp=readdir(d))!=NULL){
                if(strncmp(dp->d_name, ".",1) != 0 && strncmp(dp->d_name, "..",2) != 0) {
                    if(dp->d_type==DIR_TYPE){ /// folders
                        DIR *newdir;
                        char *newpath=malloc((strlen(path)+1+strlen(dp->d_name)+1)*sizeof(char));
                        snprintf(newpath,strlen(path)+1+strlen(dp->d_name)+1,"%s/%s",path,dp->d_name);
                        if((newdir=opendir(newpath))==NULL){
                            perror("Error opening path");
                            exit(1);
                        }
                        //printf("%s\n",dp->d_name);
                        exploreDir(newdir,newpath,1);
                        closedir(newdir);
                        free(newpath);
                    }else{      /// files
                        filesFound++;
                        char *newpath=malloc((strlen(path)+1+strlen(dp->d_name)+1)*sizeof(char));
                        snprintf(newpath,strlen(path)+1+strlen(dp->d_name)+1,"%s/%s",path,dp->d_name);
                        scan(newpath);
                        free(newpath);
                        //printf("\t%s\n",dp->d_name);
                    }
                }
            }
            break;
        case 2:
            while((dp=readdir(d))!=NULL){
                if(strncmp(dp->d_name, ".",1) != 0 && strncmp(dp->d_name, "..",2) != 0) {
                    if(dp->d_type==DIR_TYPE){ /// folders
                        DIR *newdir;
                        char *newpath=malloc((strlen(path)+1+strlen(dp->d_name)+1)*sizeof(char));
                        snprintf(newpath,strlen(path)+1+strlen(dp->d_name)+1,"%s/%s",path,dp->d_name);
                        if((newdir=opendir(newpath))==NULL){
                            perror("Error opening path");
                            exit(1);
                        }
                        exploreDir(newdir,newpath,2);
                        free(newpath);
                        closedir(newdir);
                    }else{      /// files
                        char *newpath=malloc((strlen(path)+1+strlen(dp->d_name)+1)*sizeof(char));
                        snprintf(newpath,strlen(path)+1+strlen(dp->d_name)+1,"%s/%s",path,dp->d_name);
                        if(isExe(newpath)){
                            inspectExe(newpath);
                        }else{
                            inspect(newpath);
                        }
                        free(newpath);
                        filesFound++;
                    }
                }
            }
            break;
    }
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////           Monitor Functs
/////////////////////////////////////////////////////////////////////////////////////////////////////////////

char *islocked(char *file){
    if(strlen(file)<=7){    // x.locked
        return NULL;
    }else{
        char *abadidea = &file[strlen(file)-7];     // =".locked"
        if(strncmp(abadidea,".locked",8)==0){
            //printf("\n\n__%s__",abadidea);
            file[strlen(file)-7]='\0';              // return x
            //printf("%s\n\n",file);
            return file;
        }
    }
    return NULL;
}

filelist *exists(char *file){
    filelist *ptr=top;
    int i=0;
    while (ptr!=NULL){
        if(strcmp(file,ptr->name)==0 && (strlen(file)==strlen(ptr->name))){
            //printf("Found %s in phase %d in pos %d with lens %ld %ld\n", ptr->name, ptr->phase,i,strlen(file),strlen(ptr->name));
            return ptr;
        }
        i++;
        ptr=ptr->next;
    }
    return NULL;
}

void checkPhase(char* file, int phase){
    char *filelocked;
    switch(phase){
        case 0:
            if(top == NULL){
                top=malloc(sizeof(filelist));
                top->name=malloc(strlen(file)*sizeof(char)+1);
                strncpy(top->name,file,strlen(file)+1);
                top->phase=1;
                top->next=NULL;
                bottom=top;
            }else{
                if (exists(file)!=NULL){
                    return;
                }else{
                    bottom->next=malloc(sizeof(filelist));
                    bottom=bottom->next;
                    bottom->name=malloc(strlen(file)*sizeof(char)+1);
                    strncpy(bottom->name,file,strlen(file)+1);
                    bottom->phase=1;
                    bottom->next=NULL;
                }
            }
            break;
        case 1:
            filelocked=islocked(file);
            if(filelocked!=NULL){     
                filelist *tmp=exists(file);
                if(tmp!=NULL && tmp->phase==1){
                    tmp->phase=2;
                }
            }
            break;
        case 2:
            filelocked=islocked(file);
            if(filelocked!=NULL){     
                filelist *tmp=exists(file);
                if(tmp!=NULL && tmp->phase==2){
                    tmp->phase=3;
                }
            }
            break;
        case 3:
            filelist *tmp2=exists(file);
            if(tmp2!=NULL && tmp2->phase==3){
                printf("[Warning] Attack detected on file %s\n",tmp2->name);
            }
            break;
    }
}

void monitor(char* path){   //https://stackoverflow.com/questions/13351172/inotify-file-in-c
    int fd, wd;
    char buffer[BUF_LEN];
    fd = inotify_init();
    if ( fd < 0 ) {
        perror( "inotify_init" );
    }
    wd = inotify_add_watch(fd, path, IN_OPEN | IN_MODIFY | IN_CREATE | IN_DELETE);
    if (wd == -1) {
        perror("inotify_add_watch");
        exit(EXIT_FAILURE);
    }

    while(1){
        ssize_t len = read(fd, buffer, BUF_LEN);
        if (len < 0) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        ssize_t i = 0;
        while (i < len) {
            struct inotify_event* event = (struct inotify_event*)&buffer[i];
            if (event->len) {
                if (event->mask & IN_DELETE)
                    printf("[INFO] File deleted: %s\n",event->name);
                    checkPhase(event->name,3);
                if (event->mask & IN_OPEN)
                    printf("[INFO] File oppened: %s\n",event->name);
                    checkPhase(event->name,0);
                if (event->mask & IN_CREATE)
                    checkPhase(event->name,1);
                    printf("[INFO] File created: %s\n",event->name);
                if (event->mask & IN_MODIFY)
                    checkPhase(event->name,2);
                    printf("[INFO] File modded: %s\n",event->name);
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////           Split/Unlock Functs
/////////////////////////////////////////////////////////////////////////////////////////////////////////////

void split(int a0){
    uint8_t  a2, a1;    //could also be uint16_t, uint32 or uint64 depending, I just didnt want the numbers to go too big for clarity & debugging purposes
    if(getrandom(&a1, sizeof(a1),0)==-1 || getrandom(&a2, sizeof(a2),0)==-1){
        perror("Error generating random bytes");
        exit(1);
    }
    //printf("%d %d\n",a2,a1);
    for (int i=1; i<11;i++){
        printf("(%d,%d)\n",i,a2*(i*i)+a1*i+a0);
    }
}

int *fix_input(char* inp){      
    int *share = malloc(2*sizeof(int));
    if(sizeof(inp)>5){          //(1,1) at least    
        char *tmp = malloc(9*sizeof(char));
        int i=1,j=0;
        while(inp[i]!=','&& j<9){
            tmp[j++]=inp[i++];
        }
        tmp[j]='\0';
        share[0]=atoi(tmp);
        i++;j=0;
        while(inp[i]!=')'&& j<9){
            tmp[j++]=inp[i++];
        }
        tmp[j]='\0';
        share[1]=atoi(tmp);
        free(tmp);
    }else{
        printf("Input miss, proper syntax in README");
        exit(1);
    }
    //printf("%d %d\n",share[0],share[1]);
    return share;
}

void unlock(char *s1,char *s2,char *s3){
    int *share0=fix_input(s1);
    int *share1=fix_input(s2);
    int *share2=fix_input(s3);

    int **all =malloc(3*sizeof(int*));
    all[0]=share0;all[1]=share1;all[2]=share2;
    int sum=0;
    double mult=1;
    for (int i=0;i<3;i++){
        for(int m=0;m<3;m++){
            if(m!=i){
                mult*=(double)all[m][0]/(all[m][0]-all[i][0]);
            }
        }
        sum+=all[i][1]*mult;
        mult=1;
    }

    printf("[Info] Encryption key is %d\n",sum);    ///  a and b should NOT be an output since it defeats the purpose of the cryptography
    free(share0);
    free(share1);
    free(share2);
    free(all);
}