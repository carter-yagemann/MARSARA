package utils;

import event.SYSCALL;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class LibcHandlers {
    public static HashMap<String, Set<SYSCALL>> allowedSyscalls = new HashMap<>() {{
        put("gethostbyname", new HashSet<>(){{
            add(SYSCALL.OPENAT);
            add(SYSCALL.READ);
            add(SYSCALL.CONNECT);
            add(SYSCALL.CLOSE);
        }});
        put("setbuf", new HashSet<>(){{
            add(SYSCALL.OPENAT);
            add(SYSCALL.READ);
            add(SYSCALL.CLOSE);
        }});
        put("getpwnam", new HashSet<>(){{
            add(SYSCALL.CONNECT);
            add(SYSCALL.CLOSE);
            add(SYSCALL.READ);
            add(SYSCALL.OPENAT);
            add(SYSCALL.OPEN);
        }});
        put("setsockopt", new HashSet<>(){{
            add(SYSCALL.CONNECT);
            add(SYSCALL.CLOSE);
            add(SYSCALL.WRITE);
        }});
        put("endservent", new HashSet<>(){{
            add(SYSCALL.CONNECT);
            add(SYSCALL.CLOSE);
        }});
        put("getservent_r", new HashSet<>(){{
            add(SYSCALL.CONNECT);
            add(SYSCALL.CLOSE);
        }});
        put("getgrnam", new HashSet<>(){{
            add(SYSCALL.CONNECT);
            add(SYSCALL.CLOSE);
            add(SYSCALL.READ);
        }});
        put("initgroups", new HashSet<>(){{
            add(SYSCALL.OPENAT);
            add(SYSCALL.READ);
            add(SYSCALL.CLOSE);
        }});
    }};

    public static Set<SYSCALL> getAllowedSyscalls(String libcCall) {
        return allowedSyscalls.getOrDefault(libcCall, null);
    }
}
