#include"socks5.h"


// 初始化规则
void initializeRules(struct Rules* rules) {
    rules->addrON = false;
    rules->progON = false;
    rules->httpON = false;
    for (int i = 0; i < MAX_KEYWORDS; i++) {
        rules->keywords[i] = NULL;
        rules->http[i] = NULL;
    }
    for (int i = 0; i < MAX_CIDRS; i++) {
        memset(&(rules->cidrs6[i]), 0, sizeof(struct in6_addr));
        memset(&(rules->cidrs4[i]), 0, sizeof(struct in_addr));
    }
}

// 解析规则文件
void parseRules(struct Rules* rules, const char* fileName) {
    FILE* file = fopen(fileName, "r");
    if (file == NULL) {
        printf("Failed to open file: %s\n", fileName);
        return;
    }

    initializeRules(rules);

    char line[256];
    if (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, "ON") == 0) {
            rules->addrON = true;
        } else if (strcmp(line, "OFF") == 0) {
            rules->addrON = false;
        } else {
            printf("Invalid state: %s\n", line);
            fclose(file);
            return;
        }
    }

    int keywordCount = 0;
    int cidrCount6 = 0;
    int cidrCount4 = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if ((strchr(line, ':') != NULL) || (strchr(line, '.') != NULL)) {  // 检查是否为 IPv6 地址
            struct in6_addr addr6;
            struct in_addr addr4;
            if (inet_pton(AF_INET6, line, &addr6) == 1) {
                if (cidrCount6 < MAX_CIDRS) {
                    rules->cidrs6[cidrCount6] = addr6;
                    cidrCount6++;
                } else {
                    printf("Max CIDRs limit reached\n");
                    break;
                }
            }else if (inet_pton(AF_INET, line, &addr4) == 1) {
                if (cidrCount4 < MAX_CIDRS) {
                    rules->cidrs4[cidrCount4] = addr4;
                    cidrCount4++;
                } else {
                    printf("Max CIDRs limit reached\n");
                    break;
                }
            } else {
                // printf("Invalid IPv6/4 address: %s\n", line);
                if (keywordCount < MAX_KEYWORDS) {
                rules->keywords[keywordCount] = strdup(line);
                keywordCount++;
                } else {
                    printf("Max keywords limit reached\n");
                    break;
                }
            }
        } 
    }

    fclose(file);
}

// 匹配 CIDR
bool matchCIDR(const struct Rules* rules, const char* ipAddress) {
    if (!rules->addrON) {
        return false;
    }

    struct in6_addr addr6;
    struct in_addr addr4;
    int flag6 = 0, flag4 = 0;
    if (inet_pton(AF_INET6, ipAddress, &addr6) != 1) {
        if (inet_pton(AF_INET, ipAddress, &addr4) != 1) {
            // printf("Invalid IP address: %s\n", ipAddress);
            return false;
        }
        flag4 = 1;
    }
    if(!flag4)flag6 = 1;

    if(flag4)
    {
        for (int i = 0; i < MAX_CIDRS; i++) {
            if (memcmp(&(rules->cidrs4[i]), &addr4, sizeof(struct in_addr)) == 0) {
                return true;
            }
        }
    }
    if(flag6)
    {
        for (int i = 0; i < MAX_CIDRS; i++) {
            if (memcmp(&(rules->cidrs6[i]), &addr6, sizeof(struct in6_addr)) == 0) {
                return true;
            }
        }
    }

    return false;
}

// 匹配关键字
bool matchKeyword(const struct Rules* rules, const char* text) {
    if (!rules->addrON) {
        return false;
    }

    for (int i = 0; i < MAX_KEYWORDS; i++) {
        if (rules->keywords[i] != NULL && strstr(text, rules->keywords[i]) != NULL) {
            return true;
        }
    }

    return false;
}

