package com.godpalace.jprotector;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.net.URL;

public class ProcessProtector {
    private static final ProcessProtector instance = new ProcessProtector();
    private static boolean isProtected = false;

    private static native void setProtect(int pid);
    private static native void UnProtect();

    public static int getCurrentProcessId() {
        String name = ManagementFactory.getRuntimeMXBean().getName();
        return Integer.parseInt(name.split("@")[0]);
    }

    private ProcessProtector() {
    }

    public static ProcessProtector getInstance() {
        return instance;
    }

    public void protect() {
        protect(getCurrentProcessId());
    }

    public void protect(int pid) {
        setProtect(pid);
        isProtected = true;
    }

    public void unprotect() {
        if (!isProtected)
            throw new RuntimeException("Process is not protected");

        UnProtect();
        isProtected = false;
    }

    public boolean isProtected() {
        return isProtected;
    }

    static {
        File dll = new File(System.getenv("TEMP"), "JProtector.dll");
        URL dllUrl = ProcessProtector.class.getResource("/JProtector.dll");

        if (dllUrl != null && !dll.exists()) {
            try {
                InputStream in = dllUrl.openStream();
                FileOutputStream out = new FileOutputStream(dll);

                byte[] buffer = new byte[10240];
                int len;
                while ((len = in.read(buffer)) != -1) {
                    out.write(buffer, 0, len);
                }

                in.close();
                out.close();
            } catch (Exception e) {
                throw new RuntimeException("Failed to load JProtector.dll", e);
            }
        }

        System.load(dll.getAbsolutePath());
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (isProtected) {
                UnProtect();
            }
        }));
    }
}
