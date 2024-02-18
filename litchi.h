#ifndef LITCHI_H_
#define LITCHI_H_

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#define TCHI_PATH_SEP "/"
typedef pid_t Pid;
typedef int Fd;
#else
#define WIN32_MEAN_AND_LEAN
#include "windows.h"
#include <process.h>
#define TCHI_PATH_SEP "\\"
typedef HANDLE Pid;
typedef HANDLE Fd;
#define WIN32_LEAN_AND_MEAN
#include "windows.h"
struct dirent {
  char d_name[MAX_PATH + 1];
};
typedef struct DIR DIR;
DIR *opendir(const char *dirpath);
struct dirent *readdir(DIR *dirp);
int closedir(DIR *dirp);
LPSTR GetLastErrorAsString(void);
#endif // _WIN32

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TCHI_FOREACH_ARRAY(type, elem, array, body)                            \
  for (size_t elem_##index = 0; elem_##index < array.count; ++elem_##index) {  \
    type *elem = &array.elems[elem_##index];                                   \
    body;                                                                      \
  }

typedef const char *TchiCstr;

int tchi_cstr_ends_with(TchiCstr cstr, TchiCstr postfix);
#define TCHI_ENDS_WITH(cstr, postfix) tchi_cstr_ends_with(cstr, postfix)

TchiCstr tchi_cstr_no_ext(TchiCstr path);
#define TCHI_NOEXT(path) tchi_cstr_no_ext(path)

typedef struct {
  TchiCstr *elems;
  size_t count;
} TchiCstrArray;

TchiCstrArray tchi_cstr_array_make(TchiCstr first, ...);
TchiCstrArray tchi_cstr_array_append(TchiCstrArray cstrs, TchiCstr cstr);
TchiCstr tchi_cstr_array_join(TchiCstr sep, TchiCstrArray cstrs);

#define TCHI_JOIN(sep, ...)                                                    \
  tchi_cstr_array_join(sep, tchi_cstr_array_make(__VA_ARGS__, NULL))
#define TCHI_CONCAT(...) TCHI_JOIN("", __VA_ARGS__)
#define TCHI_PATH(...) TCHI_JOIN(TCHI_PATH_SEP, __VA_ARGS__)
#define TCHI_GETCWD() tchi_path_get_current_dir()
#define TCHI_SETCWD(path) tchi_path_set_current_dir(path)

typedef struct {
  Fd read;
  Fd write;
} TchiPipe;

TchiPipe tchi_pipe_make(void);

typedef struct {
  TchiCstrArray line;
} TchiCmd;

Fd tchi_fd_open_for_read(TchiCstr path);
Fd tchi_fd_open_for_write(TchiCstr path);
void tchi_fd_close(Fd fd);
void tchi_pid_wait(Pid pid);
TchiCstr tchi_cmd_show(TchiCmd cmd);
Pid tchi_cmd_run_async(TchiCmd cmd, Fd *fdin, Fd *fdout);
void tchi_cmd_run_sync(TchiCmd cmd);

typedef struct {
  TchiCmd *elems;
  size_t count;
} TchiCmdArray;

#define TCHI_CMD(...)                                                          \
  do {                                                                         \
    TchiCmd cmd = {.line = tchi_cstr_array_make(__VA_ARGS__, NULL)};           \
    TCHI_INFO("CMD: %s", tchi_cmd_show(cmd));                                  \
    tchi_cmd_run_sync(cmd);                                                    \
  } while (0)

typedef enum {
  TCHI_CHAIN_TOKEN_END,
  TCHI_CHAIN_TOKEN_IN,
  TCHI_CHAIN_TOKEN_OUT,
  TCHI_CHAIN_TOKEN_CMD
} TchiChainTokenType;

typedef struct {
  TchiChainTokenType type;
  TchiCstrArray args;
} TchiChainToken;

#define TCHI_IN(path)                                                          \
  (TchiChainToken) {                                                           \
    .type = TCHI_CHAIN_TOKEN_IN, .args = tchi_cstr_array_make(path, NULL)      \
  }

#define TCHI_OUT(path)                                                         \
  (TchiChainToken) {                                                           \
    .type = TCHI_CHAIN_TOKEN_OUT, .args = tchi_cstr_array_make(path, NULL)     \
  }

#define TCHI_CHAIN_CMD(...)                                                    \
  (TchiChainToken) {                                                           \
    .type = TCHI_CHAIN_TOKEN_CMD,                                              \
    .args = tchi_cstr_array_make(__VA_ARGS__, NULL)                            \
  }

typedef struct {
  TchiCstr input_filepath;
  TchiCmdArray cmds;
  TchiCstr output_filepath;
} TchiChain;

TchiChain tchi_chain_build_from_tokens(TchiChainToken first, ...);
void tchi_chain_run_sync(TchiChain chain);
void tchi_chain_echo(TchiChain chain);

#define TCHI_CHAIN(...)                                                        \
  do {                                                                         \
    TchiChain chain =                                                          \
        tchi_chain_build_from_tokens(__VA_ARGS__, (TchiChainToken){0});        \
    tchi_chain_echo(chain);                                                    \
    tchi_chain_run_sync(chain);                                                \
  } while (0)

#ifndef TCHI_REBUILD_URSELF
#if _WIN32
#if defined(__GNUC__)
#define TCHI_REBUILD_URSELF(binary_path, source_path)                          \
  TCHI_CMD("gcc", "-o", binary_path, source_path)
#elif defined(__clang__)
#define TCHI_REBUILD_URSELF(binary_path, source_path)                          \
  TCHI_CMD("clang", "-o", binary_path, source_path)
#elif defined(_MSC_VER)
#define TCHI_REBUILD_URSELF(binary_path, source_path)                          \
  TCHI_CMD("cl.exe", source_path)
#endif
#else
#define TCHI_REBUILD_URSELF(binary_path, source_path)                          \
  TCHI_CMD("cc", "-o", binary_path, source_path)
#endif
#endif

#define TCHI_GO_REBUILD_URSELF(argc, argv)                                     \
  do {                                                                         \
    const char *source_path = __FILE__;                                        \
    assert(argc >= 1);                                                         \
    const char *binary_path = argv[0];                                         \
                                                                               \
    if (tchi_is_path1_modified_after_path2(source_path, binary_path)) {        \
      TCHI_RENAME(binary_path, TCHI_CONCAT(binary_path, ".old"));              \
      TCHI_REBUILD_URSELF(binary_path, source_path);                           \
      TchiCmd cmd = {                                                          \
          .line =                                                              \
              {                                                                \
                  .elems = (TchiCstr *)argv,                                   \
                  .count = argc,                                               \
              },                                                               \
      };                                                                       \
      TCHI_INFO("CMD: %s", tchi_cmd_show(cmd));                                \
      tchi_cmd_run_sync(cmd);                                                  \
      exit(0);                                                                 \
    }                                                                          \
  } while (0)

void tchi_rebuild_urself(const char *binary_path, const char *source_path);

int tchi_path_is_dir(TchiCstr path);
#define TCHI_IS_DIR(path) tchi_path_is_dir(path)

int tchi_path_exists(TchiCstr path);
#define TCHI_PATH_EXISTS(path) tchi_path_exists(path)

void tchi_path_mkdirs(TchiCstrArray path);
#define TCHI_MKDIRS(...)                                                       \
  do {                                                                         \
    TchiCstrArray path = tchi_cstr_array_make(__VA_ARGS__, NULL);              \
    TCHI_INFO("MKDIRS: %s", tchi_cstr_array_join(TCHI_PATH_SEP, path));        \
    tchi_path_mkdirs(path);                                                    \
  } while (0)

void tchi_path_rename(TchiCstr old_path, TchiCstr new_path);
#define TCHI_RENAME(old_path, new_path)                                        \
  do {                                                                         \
    TCHI_INFO("RENAME: %s -> %s", old_path, new_path);                         \
    tchi_path_rename(old_path, new_path);                                      \
  } while (0)

void tchi_path_rm(TchiCstr path);
#define TCHI_RM(path)                                                          \
  do {                                                                         \
    TCHI_INFO("RM: %s", path);                                                 \
    tchi_path_rm(path);                                                        \
  } while (0)

#define TCHI_FOREACH_FILE_IN_DIR(file, dirpath, body)                          \
  do {                                                                         \
    struct dirent *dp = NULL;                                                  \
    DIR *dir = opendir(dirpath);                                               \
    if (dir == NULL) {                                                         \
      TCHI_PANIC("could not open directory %s: %s", dirpath, strerror(errno)); \
    }                                                                          \
    errno = 0;                                                                 \
    while ((dp = readdir(dir))) {                                              \
      const char *file = dp->d_name;                                           \
      body;                                                                    \
    }                                                                          \
                                                                               \
    if (errno > 0) {                                                           \
      TCHI_PANIC("could not read directory %s: %s", dirpath, strerror(errno)); \
    }                                                                          \
                                                                               \
    closedir(dir);                                                             \
  } while (0)

#if defined(__GNUC__) || defined(__clang__)
#define LITCHI_PRINTF_FORMAT(STRING_INDEX, FIRST_TO_CHECK)                     \
  __attribute__((format(printf, STRING_INDEX, FIRST_TO_CHECK)))
#else
#define LITCHI_PRINTF_FORMAT(STRING_INDEX, FIRST_TO_CHECK)
#endif

void TCHI_VLOG(FILE *stream, TchiCstr tag, TchiCstr fmt, va_list args);
void TCHI_INFO(TchiCstr fmt, ...) LITCHI_PRINTF_FORMAT(1, 2);
void TCHI_WARN(TchiCstr fmt, ...) LITCHI_PRINTF_FORMAT(1, 2);
void TCHI_ERRO(TchiCstr fmt, ...) LITCHI_PRINTF_FORMAT(1, 2);
void TCHI_PANIC(TchiCstr fmt, ...) LITCHI_PRINTF_FORMAT(1, 2);

char *shift_args(int *argc, char ***argv);

#endif // LITCHI_H_

#ifdef LITCHI_IMPLEMENTATION

#ifdef _WIN32
LPSTR GetLastErrorAsString(void) {
  DWORD errorMessageId = GetLastError();
  assert(errorMessageId != 0);

  LPSTR messageBuffer = NULL;

  DWORD size = FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, errorMessageId, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPSTR)&messageBuffer, 0, NULL);

  return messageBuffer;
}

struct DIR {
  HANDLE hFind;
  WIN32_FIND_DATA data;
  struct dirent *dirent;
};

DIR *opendir(const char *dirpath) {
  assert(dirpath);

  char buffer[MAX_PATH];
  snprintf(buffer, MAX_PATH, "%s\\*", dirpath);

  DIR *dir = (DIR *)calloc(1, sizeof(DIR));

  dir->hFind = FindFirstFile(buffer, &dir->data);
  if (dir->hFind == INVALID_HANDLE_VALUE) {
    errno = ENOSYS;
    goto fail;
  }

  return dir;

fail:
  if (dir) { free(dir); }

  return NULL;
}

struct dirent *readdir(DIR *dirp) {
  assert(dirp);

  if (dirp->dirent == NULL) {
    dirp->dirent = (struct dirent *)calloc(1, sizeof(struct dirent));
  } else {
    if (!FindNextFile(dirp->hFind, &dirp->data)) {
      if (GetLastError() != ERROR_NO_MORE_FILES) { errno = ENOSYS; }

      return NULL;
    }
  }

  memset(dirp->dirent->d_name, 0, sizeof(dirp->dirent->d_name));

  strncpy(dirp->dirent->d_name, dirp->data.cFileName,
          sizeof(dirp->dirent->d_name) - 1);

  return dirp->dirent;
}

int closedir(DIR *dirp) {
  assert(dirp);

  if (!FindClose(dirp->hFind)) {
    errno = ENOSYS;
    return -1;
  }

  if (dirp->dirent) { free(dirp->dirent); }
  free(dirp);

  return 0;
}
#endif // _WIN32

TchiCstrArray tchi_cstr_array_append(TchiCstrArray cstrs, TchiCstr cstr) {
  TchiCstrArray result = {.count = cstrs.count + 1};
  result.elems = malloc(sizeof(result.elems[0]) * result.count);
  memcpy(result.elems, cstrs.elems, cstrs.count * sizeof(result.elems[0]));
  result.elems[cstrs.count] = cstr;
  return result;
}

int tchi_cstr_ends_with(TchiCstr cstr, TchiCstr postfix) {
  const size_t cstr_len = strlen(cstr);
  const size_t postfix_len = strlen(postfix);
  return postfix_len <= cstr_len &&
         strcmp(cstr + cstr_len - postfix_len, postfix) == 0;
}

TchiCstr tchi_cstr_no_ext(TchiCstr path) {
  size_t n = strlen(path);
  while (n > 0 && path[n - 1] != '.') {
    n -= 1;
  }

  if (n > 0) {
    char *result = malloc(n);
    memcpy(result, path, n);
    result[n - 1] = '\0';

    return result;
  } else {
    return path;
  }
}

TchiCstrArray tchi_cstr_array_make(TchiCstr first, ...) {
  TchiCstrArray result = {0};

  if (first == NULL) { return result; }

  result.count += 1;

  va_list args;
  va_start(args, first);
  for (TchiCstr next = va_arg(args, TchiCstr); next != NULL;
       next = va_arg(args, TchiCstr)) {
    result.count += 1;
  }
  va_end(args);

  result.elems = malloc(sizeof(result.elems[0]) * result.count);
  if (result.elems == NULL) {
    TCHI_PANIC("could not allocate memory: %s", strerror(errno));
  }
  result.count = 0;

  result.elems[result.count++] = first;

  va_start(args, first);
  for (TchiCstr next = va_arg(args, TchiCstr); next != NULL;
       next = va_arg(args, TchiCstr)) {
    result.elems[result.count++] = next;
  }
  va_end(args);

  return result;
}

TchiCstr tchi_cstr_array_join(TchiCstr sep, TchiCstrArray cstrs) {
  if (cstrs.count == 0) { return ""; }

  const size_t sep_len = strlen(sep);
  size_t len = 0;
  for (size_t i = 0; i < cstrs.count; ++i) {
    len += strlen(cstrs.elems[i]);
  }

  const size_t result_len = (cstrs.count - 1) * sep_len + len + 1;
  char *result = malloc(sizeof(char) * result_len);
  if (result == NULL) {
    TCHI_PANIC("could not allocate memory: %s", strerror(errno));
  }

  len = 0;
  for (size_t i = 0; i < cstrs.count; ++i) {
    if (i > 0) {
      memcpy(result + len, sep, sep_len);
      len += sep_len;
    }

    size_t elem_len = strlen(cstrs.elems[i]);
    memcpy(result + len, cstrs.elems[i], elem_len);
    len += elem_len;
  }
  result[len] = '\0';

  return result;
}

TchiPipe tchi_pipe_make(void) {
  TchiPipe pip = {0};

#ifdef _WIN32
  SECURITY_ATTRIBUTES saAttr = {0};
  saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  saAttr.bInheritHandle = TRUE;

  if (!CreatePipe(&pip.read, &pip.write, &saAttr, 0)) {
    PANIC("Could not create pipe: %s", GetLastErrorAsString());
  }
#else
  Fd pipefd[2];
  if (pipe(pipefd) < 0) {
    TCHI_PANIC("Could not create pipe: %s", strerror(errno));
  }

  pip.read = pipefd[0];
  pip.write = pipefd[1];
#endif // _WIN32

  return pip;
}

Fd tchi_fd_open_for_read(TchiCstr path) {
#ifndef _WIN32
  Fd result = open(path, O_RDONLY);
  if (result < 0) {
    TCHI_PANIC("Could not open file %s: %s", path, strerror(errno));
  }
  return result;
#else
  SECURITY_ATTRIBUTES saAttr = {0};
  saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  saAttr.bInheritHandle = TRUE;

  Fd result = CreateFile(path, GENERIC_READ, 0, &saAttr, OPEN_EXISTING,
                         FILE_ATTRIBUTE_READONLY, NULL);

  if (result == INVALID_HANDLE_VALUE) {
    TCHI_PANIC("Could not open file %s", path);
  }

  return result;
#endif // _WIN32
}

Fd tchi_fd_open_for_write(TchiCstr path) {
#ifndef _WIN32
  Fd result = open(path, O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (result < 0) {
    TCHI_PANIC("could not open file %s: %s", path, strerror(errno));
  }
  return result;
#else
  SECURITY_ATTRIBUTES saAttr = {0};
  saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  saAttr.bInheritHandle = TRUE;

  Fd result = CreateFile(path, GENERIC_WRITE, 0, &saAttr, CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL, NULL);

  if (result == INVALID_HANDLE_VALUE) {
    TCHI_PANIC("Could not open file %s: %s", path, GetLastErrorAsString());
  }

  return result;
#endif // _WIN32
}

void tchi_fd_close(Fd fd) {
#ifdef _WIN32
  CloseHandle(fd);
#else
  close(fd);
#endif // _WIN32
}

void tchi_pid_wait(Pid pid) {
#ifdef _WIN32
  DWORD result = WaitForSingleObject(pid, INFINITE);

  if (result == WAIT_FAILED) {
    TCHI_PANIC("could not wait on child process: %s", GetLastErrorAsString());
  }

  DWORD exit_status;
  if (GetExitCodeProcess(pid, &exit_status) == 0) {
    TCHI_PANIC("could not get process exit code: %lu", GetLastError());
  }

  if (exit_status != 0) {
    TCHI_PANIC("command exited with exit code %lu", exit_status);
  }

  CloseHandle(pid);
#else
  for (;;) {
    int wstatus = 0;
    if (waitpid(pid, &wstatus, 0) < 0) {
      TCHI_PANIC("could not wait on command (pid %d): %s", pid,
                 strerror(errno));
    }

    if (WIFEXITED(wstatus)) {
      int exit_status = WEXITSTATUS(wstatus);
      if (exit_status != 0) {
        TCHI_PANIC("command exited with exit code %d", exit_status);
      }

      break;
    }

    if (WIFSIGNALED(wstatus)) {
      TCHI_PANIC("command process was terminated by %s",
                 strsignal(WTERMSIG(wstatus)));
    }
  }

#endif // _WIN32
}

TchiCstr tchi_cmd_show(TchiCmd cmd) {
  return tchi_cstr_array_join(" ", cmd.line);
}

Pid tchi_cmd_run_async(TchiCmd cmd, Fd *fdin, Fd *fdout) {
#ifdef _WIN32
  STARTUPINFO siStartInfo;
  ZeroMemory(&siStartInfo, sizeof(siStartInfo));
  siStartInfo.cb = sizeof(STARTUPINFO);
  siStartInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  siStartInfo.hStdOutput = fdout ? *fdout : GetStdHandle(STD_OUTPUT_HANDLE);
  siStartInfo.hStdInput = fdin ? *fdin : GetStdHandle(STD_INPUT_HANDLE);
  siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

  PROCESS_INFORMATION piProcInfo;
  ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

  BOOL bSuccess =
      CreateProcess(NULL, tchi_cstr_array_join(" ", cmd.line), NULL, NULL, TRUE,
                    0, NULL, NULL, &siStartInfo, &piProcInfo);

  if (!bSuccess) {
    TCHI_PANIC("Could not create child process %s: %s\n", tchi_cmd_show(cmd),
               GetLastErrorAsString());
  }

  CloseHandle(piProcInfo.hThread);

  return piProcInfo.hProcess;
#else
  pid_t cpid = fork();
  if (cpid < 0) {
    TCHI_PANIC("Could not fork child process: %s: %s", tchi_cmd_show(cmd),
               strerror(errno));
  }

  if (cpid == 0) {
    TchiCstrArray args = tchi_cstr_array_append(cmd.line, NULL);

    if (fdin) {
      if (dup2(*fdin, STDIN_FILENO) < 0) {
        TCHI_PANIC("Could not setup stdin for child process: %s",
                   strerror(errno));
      }
    }

    if (fdout) {
      if (dup2(*fdout, STDOUT_FILENO) < 0) {
        TCHI_PANIC("Could not setup stdout for child process: %s",
                   strerror(errno));
      }
    }

    if (execvp(args.elems[0], (char *const *)args.elems) < 0) {
      TCHI_PANIC("Could not exec child process: %s: %s", tchi_cmd_show(cmd),
                 strerror(errno));
    }
  }

  return cpid;
#endif // _WIN32
}

void tchi_cmd_run_sync(TchiCmd cmd) {
  tchi_pid_wait(tchi_cmd_run_async(cmd, NULL, NULL));
}

static void
tchi_chain_set_input_output_files_or_count_cmds(TchiChain *chain,
                                                TchiChainToken token) {
  switch (token.type) {
    case TCHI_CHAIN_TOKEN_CMD: {
      chain->cmds.count += 1;
    } break;

    case TCHI_CHAIN_TOKEN_IN: {
      if (chain->input_filepath) {
        TCHI_PANIC("Input file path was already set");
      }

      chain->input_filepath = token.args.elems[0];
    } break;

    case TCHI_CHAIN_TOKEN_OUT: {
      if (chain->output_filepath) {
        TCHI_PANIC("Output file path was already set");
      }

      chain->output_filepath = token.args.elems[0];
    } break;

    case TCHI_CHAIN_TOKEN_END:
    default: {
      assert(0 && "unreachable");
      exit(1);
    }
  }
}

static void tchi_chain_push_cmd(TchiChain *chain, TchiChainToken token) {
  if (token.type == TCHI_CHAIN_TOKEN_CMD) {
    chain->cmds.elems[chain->cmds.count++] = (TchiCmd){.line = token.args};
  }
}

TchiChain tchi_chain_build_from_tokens(TchiChainToken first, ...) {
  TchiChain result = {0};

  tchi_chain_set_input_output_files_or_count_cmds(&result, first);
  va_list args;
  va_start(args, first);
  TchiChainToken next = va_arg(args, TchiChainToken);
  while (next.type != TCHI_CHAIN_TOKEN_END) {
    tchi_chain_set_input_output_files_or_count_cmds(&result, next);
    next = va_arg(args, TchiChainToken);
  }
  va_end(args);

  result.cmds.elems = malloc(sizeof(result.cmds.elems[0]) * result.cmds.count);
  if (result.cmds.elems == NULL) {
    TCHI_PANIC("could not allocate memory: %s", strerror(errno));
  }
  result.cmds.count = 0;

  tchi_chain_push_cmd(&result, first);

  va_start(args, first);
  next = va_arg(args, TchiChainToken);
  while (next.type != TCHI_CHAIN_TOKEN_END) {
    tchi_chain_push_cmd(&result, next);
    next = va_arg(args, TchiChainToken);
  }
  va_end(args);

  return result;
}

void tchi_chain_run_sync(TchiChain chain) {
  if (chain.cmds.count == 0) { return; }

  Pid *cpids = malloc(sizeof(Pid) * chain.cmds.count);

  TchiPipe pip = {0};
  Fd fdin = 0;
  Fd *fdprev = NULL;

  if (chain.input_filepath) {
    fdin = tchi_fd_open_for_read(chain.input_filepath);
    if (fdin < 0) {
      TCHI_PANIC("could not open file %s: %s", chain.input_filepath,
                 strerror(errno));
    }
    fdprev = &fdin;
  }

  for (size_t i = 0; i < chain.cmds.count - 1; ++i) {
    pip = tchi_pipe_make();

    cpids[i] = tchi_cmd_run_async(chain.cmds.elems[i], fdprev, &pip.write);

    if (fdprev) tchi_fd_close(*fdprev);
    tchi_fd_close(pip.write);
    fdprev = &fdin;
    fdin = pip.read;
  }

  {
    Fd fdout = 0;
    Fd *fdnext = NULL;

    if (chain.output_filepath) {
      fdout = tchi_fd_open_for_write(chain.output_filepath);
      if (fdout < 0) {
        TCHI_PANIC("could not open file %s: %s", chain.output_filepath,
                   strerror(errno));
      }
      fdnext = &fdout;
    }

    const size_t last = chain.cmds.count - 1;
    cpids[last] = tchi_cmd_run_async(chain.cmds.elems[last], fdprev, fdnext);

    if (fdprev) tchi_fd_close(*fdprev);
    if (fdnext) tchi_fd_close(*fdnext);
  }

  for (size_t i = 0; i < chain.cmds.count; ++i) {
    tchi_pid_wait(cpids[i]);
  }
}

void tchi_chain_echo(TchiChain chain) {
  printf("[INFO] CHAIN:");
  if (chain.input_filepath) { printf(" %s", chain.input_filepath); }

  TCHI_FOREACH_ARRAY(TchiCmd, cmd, chain.cmds,
                     { printf(" |> %s", tchi_cmd_show(*cmd)); });

  if (chain.output_filepath) { printf(" |> %s", chain.output_filepath); }

  printf("\n");
}

TchiCstr tchi_path_get_current_dir() {
#ifdef _WIN32
  DWORD nBufferLength = GetCurrentDirectory(0, NULL);
  if (nBufferLength == 0) {
    TCHI_PANIC("could not get current directory: %s", GetLastErrorAsString());
  }

  char *buffer = (char *)malloc(nBufferLength);
  if (GetCurrentDirectory(nBufferLength, buffer) == 0) {
    TCHI_PANIC("could not get current directory: %s", GetLastErrorAsString());
  }

  return buffer;
#else
  char *buffer = (char *)malloc(PATH_MAX);
  if (getcwd(buffer, PATH_MAX) == NULL) {
    TCHI_PANIC("could not get current directory: %s", strerror(errno));
  }

  return buffer;
#endif // _WIN32
}

void tchi_path_set_current_dir(TchiCstr path) {
#ifdef _WIN32
  if (!SetCurrentDirectory(path)) {
    TCHI_PANIC("could not set current directory to %s: %s", path,
               GetLastErrorAsString());
  }
#else
  if (chdir(path) < 0) {
    TCHI_PANIC("could not set current directory to %s: %s", path,
               strerror(errno));
  }
#endif // _WIN32
}

int tchi_path_exists(TchiCstr path) {
#ifdef _WIN32
  DWORD dwAttrib = GetFileAttributes(path);
  return (dwAttrib != INVALID_FILE_ATTRIBUTES);
#else
  struct stat statbuf = {0};
  if (stat(path, &statbuf) < 0) {
    if (errno == ENOENT) {
      errno = 0;
      return 0;
    }

    TCHI_PANIC("could not retrieve information about file %s: %s", path,
               strerror(errno));
  }

  return 1;
#endif
}

int tchi_path_is_dir(TchiCstr path) {
#ifdef _WIN32
  DWORD dwAttrib = GetFileAttributes(path);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
          (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
#else
  struct stat statbuf = {0};
  if (stat(path, &statbuf) < 0) {
    if (errno == ENOENT) {
      errno = 0;
      return 0;
    }

    TCHI_PANIC("could not retrieve information about file %s: %s", path,
               strerror(errno));
  }

  return S_ISDIR(statbuf.st_mode);
#endif // _WIN32
}

void tchi_path_rename(const char *old_path, const char *new_path) {
#ifdef _WIN32
  if (!MoveFileEx(old_path, new_path, MOVEFILE_REPLACE_EXISTING)) {
    TCHI_PANIC("could not rename %s to %s: %s", old_path, new_path,
               GetLastErrorAsString());
  }
#else
  if (rename(old_path, new_path) < 0) {
    TCHI_PANIC("could not rename %s to %s: %s", old_path, new_path,
               strerror(errno));
  }
#endif // _WIN32
}

void tchi_path_mkdirs(TchiCstrArray path) {
  if (path.count == 0) { return; }

  size_t len = 0;
  for (size_t i = 0; i < path.count; ++i) {
    len += strlen(path.elems[i]);
  }

  size_t seps_count = path.count - 1;
  const size_t sep_len = strlen(TCHI_PATH_SEP);

  char *result = malloc(len + seps_count * sep_len + 1);

  len = 0;
  for (size_t i = 0; i < path.count; ++i) {
    size_t n = strlen(path.elems[i]);
    memcpy(result + len, path.elems[i], n);
    len += n;

    if (seps_count > 0) {
      memcpy(result + len, TCHI_PATH_SEP, sep_len);
      len += sep_len;
      seps_count -= 1;
    }

    result[len] = '\0';

    if (mkdir(result, 0755) < 0) {
      if (errno == EEXIST) {
        errno = 0;
        TCHI_WARN("directory %s already exists", result);
      } else {
        TCHI_PANIC("could not create directory %s: %s", result,
                   strerror(errno));
      }
    }
  }
}

void tchi_path_rm(TchiCstr path) {
  if (TCHI_IS_DIR(path)) {
    TCHI_FOREACH_FILE_IN_DIR(file, path, {
      if (strcmp(file, ".") != 0 && strcmp(file, "..") != 0) {
        tchi_path_rm(TCHI_PATH(path, file));
      }
    });

    if (rmdir(path) < 0) {
      if (errno == ENOENT) {
        errno = 0;
        TCHI_WARN("directory %s does not exist", path);
      } else {
        TCHI_PANIC("could not remove directory %s: %s", path, strerror(errno));
      }
    }
  } else {
    if (unlink(path) < 0) {
      if (errno == ENOENT) {
        errno = 0;
        TCHI_WARN("file %s does not exist", path);
      } else {
        TCHI_PANIC("could not remove file %s: %s", path, strerror(errno));
      }
    }
  }
}

int tchi_is_path1_modified_after_path2(const char *path1, const char *path2) {
#ifdef _WIN32
  FILETIME path1_time, path2_time;

  Fd path1_fd = tchi_fd_open_for_read(path1);
  if (!GetFileTime(path1_fd, NULL, NULL, &path1_time)) {
    TCHI_PANIC("could not get time of %s: %s", path1, GetLastErrorAsString());
  }
  tchi_fd_close(path1_fd);

  Fd path2_fd = tchi_fd_open_for_read(path2);
  if (!GetFileTime(path2_fd, NULL, NULL, &path2_time)) {
    TCHI_PANIC("could not get time of %s: %s", path2, GetLastErrorAsString());
  }
  fd_close(path2_fd);

  return CompareFileTime(&path1_time, &path2_time) == 1;
#else
  struct stat statbuf = {0};

  if (stat(path1, &statbuf) < 0) {
    TCHI_PANIC("could not stat %s: %s\n", path1, strerror(errno));
  }
  int path1_time = statbuf.st_mtime;

  if (stat(path2, &statbuf) < 0) {
    TCHI_PANIC("could not stat %s: %s\n", path2, strerror(errno));
  }
  int path2_time = statbuf.st_mtime;

  return path1_time > path2_time;
#endif
}

void TCHI_VLOG(FILE *stream, TchiCstr tag, TchiCstr fmt, va_list args) {
  fprintf(stream, "[%s] ", tag);
  vfprintf(stream, fmt, args);
  fprintf(stream, "\n");
}

void TCHI_INFO(TchiCstr fmt, ...) {
  va_list args;
  va_start(args, fmt);
  TCHI_VLOG(stderr, "INFO", fmt, args);
  va_end(args);
}

void TCHI_WARN(TchiCstr fmt, ...) {
  va_list args;
  va_start(args, fmt);
  TCHI_VLOG(stderr, "WARN", fmt, args);
  va_end(args);
}

void TCHI_ERRO(TchiCstr fmt, ...) {
  va_list args;
  va_start(args, fmt);
  TCHI_VLOG(stderr, "ERRO", fmt, args);
  va_end(args);
}

void TCHI_PANIC(TchiCstr fmt, ...) {
  va_list args;
  va_start(args, fmt);
  TCHI_VLOG(stderr, "ERRO", fmt, args);
  va_end(args);
  exit(1);
}

char *tchi_shift_args(int *argc, char ***argv) {
  assert(*argc > 0);
  char *result = **argv;
  *argc -= 1;
  *argv += 1;
  return result;
}

#endif // LITCHI_IMPLEMENTATION
