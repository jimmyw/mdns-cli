#include "clip.h"

#include "util.h"

#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_CLIP 8192

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64(const unsigned char *in, size_t len, char *out, size_t outsz)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        if (o + 4 >= outsz)
            break;
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < len)
            v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < len)
            v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 0x3f];
        out[o++] = B64[(v >> 12) & 0x3f];
        out[o++] = i + 1 < len ? B64[(v >> 6) & 0x3f] : '=';
        out[o++] = i + 2 < len ? B64[v & 0x3f] : '=';
    }
    out[o] = '\0';
    return o;
}

/* The terminal's own clipboard escape. Inside tmux the sequence has to be
   wrapped for passthrough, and tmux only forwards it when set-clipboard is on. */
static void osc52(const char *text)
{
    char b64[MAX_CLIP * 4 / 3 + 8];
    base64((const unsigned char *)text, strlen(text), b64, sizeof b64);

    char seq[sizeof b64 + 64];
    int n;
    if (getenv("TMUX"))
        n = snprintf(seq, sizeof seq, "\033Ptmux;\033\033]52;c;%s\007\033\\", b64);
    else
        n = snprintf(seq, sizeof seq, "\033]52;c;%s\007", b64);
    if (n > 0) {
        ssize_t written = write(STDOUT_FILENO, seq, (size_t)n);
        (void)written;
    }
}

static bool in_path(const char *prog, char *out, size_t outsz)
{
    const char *path = getenv("PATH");
    if (!path)
        return false;
    while (*path) {
        const char *colon = strchr(path, ':');
        size_t len = colon ? (size_t)(colon - path) : strlen(path);
        if (len && len + strlen(prog) + 2 < outsz) {
            snprintf(out, outsz, "%.*s/%s", (int)len, path, prog);
            if (access(out, X_OK) == 0)
                return true;
        }
        if (!colon)
            break;
        path = colon + 1;
    }
    return false;
}

/* Hand the text to a clipboard helper over a pipe and do not wait for it. */
static bool spawn_helper(const char *prog, const char *arg, const char *text)
{
    char full[512];
    if (!in_path(prog, full, sizeof full))
        return false;

    /* Let the kernel reap the helper; nothing here cares about its exit. */
    signal(SIGCHLD, SIG_IGN);

    int fds[2];
    if (pipe(fds) != 0)
        return false;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    if (pid == 0) {
        dup2(fds[0], STDIN_FILENO);
        close(fds[0]);
        close(fds[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        if (arg)
            execl(full, prog, arg, (char *)NULL);
        else
            execl(full, prog, (char *)NULL);
        _exit(127);
    }
    close(fds[0]);
    size_t len = strlen(text);
    ssize_t w = write(fds[1], text, len); /* short enough to never block */
    close(fds[1]);
    return w == (ssize_t)len;
}

const char *clip_copy(const char *text)
{
    if (!text || !*text)
        return NULL;
    if (strlen(text) > MAX_CLIP)
        return NULL;

    osc52(text);

#ifdef __APPLE__
    if (spawn_helper("pbcopy", NULL, text))
        return "clipboard";
#else
    if (getenv("WAYLAND_DISPLAY") && spawn_helper("wl-copy", NULL, text))
        return "clipboard";
    if (getenv("DISPLAY")) {
        if (spawn_helper("xclip", "-selection", text))
            return "clipboard";
        if (spawn_helper("xsel", "--clipboard", text))
            return "clipboard";
    }
#endif
    /* No helper: the terminal may still have taken the OSC 52 sequence. */
    return "terminal";
}
