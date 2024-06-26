#include"socks5.h"


// 解析规则文件
void parseHttpRules(struct Rules* rules, const char* fileName) {
    FILE* file = fopen(fileName, "r");
    if (file == NULL) {
        printf("Failed to open file: %s\n", fileName);
        return;
    }

    // initializeRules(rules);

    char line[256];
    memset(line, 0, sizeof line);
    if (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        // printf("line %s %d\n", line,strcmp(line, "ON"));
        if (strcmp(line, "ON") == 0) {
            rules->httpON = true;
        } else if (strcmp(line, "OFF") == 0) {
            rules->httpON = false;
        } else {
            printf("Invalid state: %s\n", line);
            fclose(file);
            return;
        }
    }

    int httpcount = 0;
    
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (httpcount < MAX_KEYWORDS) {
            rules->http[httpcount] = strdup(line);
            httpcount++;
        } else {
            printf("Max keywords limit reached\n");
            break;
        }
            
    } 
    

    fclose(file);
}


// 匹配http
bool matchHttp(const struct Rules* rules, int client_socket, char* buf) {
    char buf1[BUFFER_SIZE];
    memset(buf1,0, sizeof buf1);
    if(recv(client_socket, buf,BUFFER_SIZE, 0) == -1){
        return false;
    }
    if (!rules->httpON) {
        return false;
    }
    strcpy(buf1,buf);
    // printf("buf %s\n", buf1);
    char* line = strtok(buf1, "\r\n");
    while (line != NULL) {
        if (strstr(line, "Host: ")) {
            char* host = line + 6;
            printf("host : %s\n", host);
            for (int i = 0; i < MAX_KEYWORDS; i++) {
                if (rules->http[i] != NULL && strstr(host, rules->http[i])) {
                    return true;
                }
            }
            return false;
        }
        line = strtok(NULL, "\r\n");
    }

    return false;
}

