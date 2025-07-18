#include "pork.h"
#include "tls_defines.h"

static inline __always_inline void* __get_thread() {
  return static_cast<void*>(__get_tls()[TLS_SLOT_THREAD_ID]);
}

int initialize_socket(struct sockaddr_in *address) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        return -1;
    }
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = INADDR_ANY;
    address->sin_port = htons(PORT);
    if (bind(socket_fd, (struct sockaddr *) address, sizeof(*address)) < 0) {
        return -1;
    }
    if (listen(socket_fd, 10) < 0) {
        return -1;
    }
    return socket_fd;
}

void fail_if_admin(const std::string &text) { // ## pass by value and not reference. if buffer was "a\x00ADMIN\x00" then text will be "a"
    if (text.find(STRONG_USERNAME) != std::string::npos) { // ## why not just strcmp? why is it bad that the username/note/password(?) contains "ADMIN"? - its the cpp way
        pthread_exit(nullptr);
    }
}

std::unique_ptr<char[]> recv_sized(int sock, uint8_t *size) {
    // Receiving a buffer with a custom size
    if (recv(sock, size, 1, 0) != 1) {
        close(sock);
        pthread_exit(nullptr);
    };
    if (*size == 0xff) {
        // No overflows allowed
        close(sock);
        pthread_exit(nullptr);
    }
    if (*size == 0) {
        return nullptr;
    }
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(*size + 1); // ## max size is 0xff
    buffer[*size] = '\0';
    int received = recv(sock, buffer.get(), *size, MSG_WAITALL);
    if (received != *size) {
        close(sock);
        pthread_exit(nullptr);
    }
    // Admin can log in locally, but not remotely
    fail_if_admin(buffer.get());
    return buffer;
}


void socket_send(int sock, const char *message) {
    uint8_t size = strlen(message);
    send(sock, &size, 1, 0);
    send(sock, message, size, 0);
}

void close_socket_and_send(int sock, const char *message) {
    if (message != nullptr) {
        socket_send(sock, message);
    }
    close(sock);
    pthread_exit(nullptr);
}

void hexdump_memory_sized(void *addr, int size) {
    unsigned char *p = (unsigned char *)addr;
    char line[100];  // Buffer to hold each line of output
    bool skipping = false;
    unsigned char last_line[16] = {0};
    
    LOGD(LOG_HEADER "Viewing stack:");
    for (int i = 0; i < size; i += 16) {
        bool same_as_last = (i > 0) && (memcmp(p + i, last_line, 16) == 0);
        
        if (same_as_last) {
            if (!skipping) {
                LOGD(LOG_HEADER "  ...");
                skipping = true;
            }
            continue;
        }
        
        skipping = false;
        memcpy(last_line, p + i, 16);
        
        char *ptr = line;
        ptr += sprintf(ptr, "%08lx  ", (unsigned long)(p + i));
        
        for (int j = 0; j < 16; j++) {
            if (i + j < size)
                ptr += sprintf(ptr, "%02x ", p[i + j]);
            else
                ptr += sprintf(ptr, "   ");
            
            if (j == 7)
                ptr += sprintf(ptr, " ");
        }
        
        ptr += sprintf(ptr, "|");
        for (int j = 0; j < 16 && i + j < size; j++) {
            ptr += sprintf(ptr, "%c", isprint(p[i + j]) ? p[i + j] : '.');
        }
        ptr += sprintf(ptr, "|");
        
        LOGD(LOG_HEADER "%s", line);
    }
    
    sprintf(line, "%08lx", (unsigned long)(p + size));
    LOGD(LOG_HEADER "%s", line);
}

void hexdump_memory(void *addr) {
    int size = 1024;
    hexdump_memory_sized(addr, size);
}

char *get_stack_safe() {
    LOGD(LOG_HEADER "get_stack_safe() gettid %u, syscall(__NR_gettid): %u, getpid: %u, syscall(__NR_getpid): %u, __get_tls(): %p, __get_thread(): %p", gettid(), syscall(__NR_gettid), getpid(), syscall(__NR_getpid), __get_tls(), __get_thread());
    // Getting the safe address from the stack
    pthread_t self = pthread_self();
    LOGD(LOG_HEADER "get_stack_safe() pthread_self() = %u", self);
    pthread_attr_t attr;
    LOGD(LOG_HEADER "get_stack_safe() pthread_getattr_np(self, &attr); = %u", pthread_getattr_np(self, &attr));
    LOGD(LOG_HEADER "get_stack_safe() attr = %u", attr);
    char *stack;
    size_t stack_size;
    // Getting the start of the stack page
    pthread_attr_getstack(&attr, reinterpret_cast<void **>(&stack), &stack_size);
    pthread_attr_destroy(&attr);
    stack = stack + STACK_OFFSET;
    /*LOGD(LOG_HEADER "Viewing stack:");
    for (uint32_t* s=((uint32_t*)stack); s<(((uint32_t*)stack)+(256/sizeof(uint32_t*))); s++){
        LOGD( "STACK: 0x%x: %s(%x)", s, s, *s);
    }*/

    hexdump_memory(stack);
    LOGD(LOG_HEADER "get_stack_safe() Trying to figure out if stacks are the same");
    size_t offset;
    void* addr;
    if (stack > (char*)&stack){
        offset = stack-(char*)&stack;
        addr = (void*)&stack;
    }
    else{
        offset = (char*)&stack - stack;
        addr = (void*)stack;
    }
    offset -= 16;
    //hexdump_memory_sized(addr, offset);
    LOGD(LOG_HEADER "get_stack_safe() stack: 0x%p, &stack: 0x%p, offset: %u", (void*)stack, (void*)&stack, offset);

    return stack;
}

const char *get_current_user() {
    // Getting the current user from the stack in a safe way
    const char *stack = get_stack_safe();

    return stack + strlen(stack) + 1;
}

void set_current_user(const std::string &username, const std::string &password) { // ## gets std::string but recv_sized() returns char[]
    LOGD(LOG_HEADER "set_current_user(username: \"%s\", password: \"%s\")", username.c_str(), password.c_str());
    // Setting the current user on the stack in a safe way
    char *stack = get_stack_safe();
    memcpy(stack, password.c_str(), password.length());
    *reinterpret_cast<char *>(stack + password.length()) = '\0'; // ## what if password length is empty? - emptiness check @ pork.cpp:104, and pork.cpp:38 - nullptr should lead to crash
    memcpy(stack + strlen(stack) + 1, username.c_str(), username.length()); // ## if called from logout() then the old creds will probably not be deleted, right?
    if (username.empty()) {
        LOGD(LOG_HEADER "set_current_user() - username empty");
        hexdump_memory(stack);
        // No need to null terminate the username
        return;
    }
    LOGD(LOG_HEADER "set_current_user() - username NOT empty");
    *reinterpret_cast<char *>(stack + strlen(stack) + 1 + username.length()) = '\0';
    hexdump_memory(stack);
}

void login(int sock) {
    uint8_t size; // ## unintialized stack variable? - yes, but isn't a vuln - not being read, just written to
    auto user = recv_sized(sock, &size);
    if (user == nullptr) {
        close_socket_and_send(sock, "Invalid username");
    }
    check_path(user.get());
    if (size > MAX_USERNAME_LENGTH) {
        close_socket_and_send(sock, "Username is too long");
    }
    auto password = recv_sized(sock, &size);
    set_current_user(user.get(), password.get()); // ## TODO: double check that .get() returns the raw pointer
    if (user_exists(user.get())) {
        if (!can_login(user.get(), get_stack_safe())) { // ## here too, why stack?
            close_socket_and_send(sock, "Invalid password");
        }
    } else {
        create_user(user.get(), get_stack_safe()); // ## why does it pass stack (which is supposedly password) and not simply the password ptr?
    }
}

void logout() {
    set_current_user("", ""); // ## set_current_user() does memcpy(), thus doesn't fully delete the old creds
}

void change_password(int sock) { // ## if i've set password as "a\x00ADMIN\x00" the username should be ADMIN, thus should i be eable to chhange admin password?
    uint8_t size;
    auto password = recv_sized(sock, &size);
    if (password == nullptr) {
        close_socket_and_send(sock, "You can't set an empty password");
    }
    set_current_user(get_current_user(), password.get());
    if (!user_exists(get_current_user())) {
        close_socket_and_send(sock, "User does not exist");
    }
    std::ofstream password_file(USERS_PATH / get_current_user() / PASSWORD_FILE, std::ios::out);
    password_file << password.get();
}

void create_note_action(int sock) {
    const char *user = get_current_user();
    if (user == nullptr || !user_exists(user)) {
        close_socket_and_send(sock, "User does not exist");
    }
    uint8_t size;
    auto note = recv_sized(sock, &size);
    if (note == nullptr) {
        note = std::make_unique<char[]>(1);
        note[0] = '\0';
    }
    create_note(user, note.get());
    if (get_notes_count(user) == HIGH_NUMBER_OF_NOTES && fork() != 0) { // ## why fork...
        LOGD(LOG_HEADER "create_note_action(sock = %d), INSIDE get_notes_count(user (%s)) == HIGH_NUMBER_OF_NOTES && fork() != 0, gettid: %u, PID: %u, syscall(__NR_gettid): %u", sock, user, gettid(), getpid(), syscall(__NR_gettid));
        pthread_exit(nullptr); // ## exists thread, not proc...
    }
    LOGD(LOG_HEADER "create_note_action(sock = %d), AFTER get_notes_count(user (%s)) == HIGH_NUMBER_OF_NOTES && fork() != 0, gettid: %u, PID: %u, syscall(__NR_gettid): %u", sock, user, gettid(), getpid(), syscall(__NR_gettid));
}

void delete_note_action(int sock) {
    const char *user = get_current_user();
    if (user == nullptr || !user_exists(user)) {
        close_socket_and_send(sock, "User does not exist");
    }
    uint8_t index;
    recv(sock, &index, 1, 0);
    delete_note(user, index);
}

void get_note_action(int sock) {
    const char *user = get_current_user();
    if (user == nullptr || !user_exists(user)) {
        close_socket_and_send(sock, "User does not exist");
    }
    uint8_t index;
    recv(sock, &index, 1, 0);
    socket_send(sock, get_note(user, index).c_str());
}

void *handle_client(int sock) {
    // Read message type:
    uint8_t buffer;
    if (recv(sock, &buffer, 1, 0) == -1) {
        close_socket_and_send(sock, "Failed to receive message type");
    }
    switch (buffer) {
        case LOGIN:
            LOGD(LOG_HEADER "LOGIN");
            login(sock);
            break;
        case LOGOUT:
            LOGD(LOG_HEADER "LOGOUT");
            logout();
            break;
        case CHANGE_PASSWORD:
            LOGD(LOG_HEADER "CHANGE_PASSWORD");
            change_password(sock);
            break;
        case CREATE_NOTE:
            LOGD(LOG_HEADER "CREATE_NOTE");
            create_note_action(sock);
            break;
        case DELETE_NOTE:
            LOGD(LOG_HEADER "DELETE_NOTE");
            delete_note_action(sock);
            break;
        case GET_NOTE:
            LOGD(LOG_HEADER "GET_NOTE");
            get_note_action(sock);
            break;
            // Let the client decide how to optimize the connection:
        case MOVE_TO_THREAD:
            LOGD(LOG_HEADER "MOVE_TO_THREAD");
            // Move the connection to a new thread
            pthread_t thread;
            pthread_create(&thread, nullptr, reinterpret_cast<thread_func_t>(handle_client),
                           reinterpret_cast<void *>(sock));
            // The current thread will exit
            pthread_exit(nullptr);
            break;
        case DISCONNECT:
            LOGD(LOG_HEADER "DISCONNECT");
            close(sock);
            return nullptr;
        default:
            LOGD(LOG_HEADER "default");
            socket_send(sock, "Invalid message type");
    }
    if (sock != -1) {
        return handle_client(sock);
    }
    return nullptr;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_pork_MainActivity_initialize(JNIEnv *env, jobject clazz) {
    if (fork() != 0) {
        // I don't want to block the UI thread
        return 0;
    }
    // Check if the users directory exists and create it if it doesn't
    if (mkdir(USERS_PATH.c_str(), 0777) == -1) {
        if (errno != EEXIST) {
            return -1;
        }
        // Users directory already exists;
    }
    create_user(STRONG_USERNAME, STRONG_PASSWORD);
    LOGD(LOG_HEADER "Java_com_pork_MainActivity_initialize() gettid: %u, PID: %u, syscall(__NR_gettid): %u", gettid(), getpid(), syscall(__NR_gettid));
    set_current_user(STRONG_USERNAME, STRONG_PASSWORD);
    if (get_notes_count(STRONG_USERNAME) == 0) {
        create_note(STRONG_USERNAME, CTF_FLAG);
    }
    // Erasing the password from the stack
    char *stack = get_stack_safe();
    memset(stack, 0, strlen(STRONG_PASSWORD));
    struct sockaddr_in address{};
    int socket_fd, sock;
    socklen_t addrlen = sizeof(address);
    if ((socket_fd = initialize_socket(&address)) == -1) {
        return -1;
    }
    LOGD(LOG_HEADER "Server started listening on port %d", PORT);
    while ((sock = accept(socket_fd, (struct sockaddr *) &address, &addrlen)) != -1) {
        // Connection accepted
        pthread_t thread;
        pthread_create(&thread, nullptr, reinterpret_cast<thread_func_t>(handle_client),
                       reinterpret_cast<void *>(sock));
    }
    LOGD(LOG_HEADER "Failed to accept connection, errno: %d", errno);
    return 0;
}
