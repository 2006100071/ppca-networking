#include "socks5.h"

// 解析规则文件
void parseProgramRules(struct Rules* rules, const char* fileName) {
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
            rules->progON = true;
        } else if (strcmp(line, "OFF") == 0) {
            rules->progON = false;
        } else {
            printf("Invalid state: %s\n", line);
            fclose(file);
            return;
        }
    }

    int programcount = 0;
    
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (programcount < MAX_KEYWORDS) {
            rules->program[programcount] = strdup(line);
            programcount++;
        } else {
            printf("Max keywords limit reached\n");
            break;
        }
            
    } 
    

    fclose(file);
}



bool matchCmd(int port,struct Rules* rules) {
    char command[256];
    sprintf(command, "lsof -i :%d > 1.txt", port);
    system(command);

    FILE* file = fopen("1.txt", "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    int pid, fd;
    int dat[256];
    char line[4096];
    while (fgets(line, sizeof(line), file) != NULL) {
        // 使用sscanf解析内容
        if (sscanf(line, "%*s %d %*s %d", &pid, &fd) == 2) {
            printf("PID: %d, FD: %d\n", pid, fd);
            dat[fd] = pid;
        if (dat[fd] != 0) {
        char cmdline_command[256];
        sprintf(cmdline_command, "cat /proc/%d/cmdline", dat[fd]);
        // sprintf(cmdline_command, "cat /proc/%d/exe", dat[fd]);
        
        // system(cmdline_command);
            char output[4096];
            memset(output, 0, sizeof output);
            FILE* output_file = popen(cmdline_command, "r");
            printf("Command: %s\n", cmdline_command);
            if (output_file != NULL) {
                fgets(output, sizeof(output), output_file);
                
                pclose(output_file);
                
                for (int i = 0; i < MAX_KEYWORDS; i++) {
                    if(rules->program[i] != NULL && strstr(output, rules->program[i]) != NULL)
                    {
                        printf("Output: %s\n",output);
                        return true;
                    }
                    
                }
                printf("Output: %s don't have\n",output);
                fclose(file);
                return false;
                
            } else {
                printf("Failed to execute command\n");
            }
        } else {
            printf("No valid PID found for FD: %d\n", fd);
        }
        }
    }

    fclose(file);
     
    return false;
}