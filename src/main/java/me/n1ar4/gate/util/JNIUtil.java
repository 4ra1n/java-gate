package me.n1ar4.gate.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * JNI Utils
 */
@SuppressWarnings("unused")
public class JNIUtil {
    private static final String lib = "java.library.path";

    /**
     * Make new JNI lib effective
     *
     * @return success or not
     */
    private static boolean deleteUrls() {
        try {
            final Field sysPathsField = ClassLoader.class.getDeclaredField("sys_paths");
            sysPathsField.setAccessible(true);
            sysPathsField.set(null, null);
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return false;
    }

    /**
     * Load JNI lib
     *
     * @param path dll path
     * @return success or not
     */
    public static boolean loadLib(String path) {
        Path p = Paths.get(path);
        if (!Files.exists(p)) {
            System.err.println("file not exist");
            return false;
        }
        if (Files.isDirectory(p)) {
            System.err.println("is a dir");
            return false;
        }
        String libDirAbsPath = Paths.get(p.toFile().getParent()).toAbsolutePath().toString();
        String originLib = System.getProperty(lib);
        originLib = originLib + String.format(";%s;", libDirAbsPath);
        System.setProperty(lib, originLib);
        if (!deleteUrls()) {
            System.err.println("load failed");
            return false;
        }
        String dll = p.toFile().getName().toLowerCase();
        if (!dll.endsWith(".dll")) {
            System.err.println("must be a dll file");
            return false;
        }
        String file = dll.split("\\.dll")[0].trim();
        System.out.println("load library: " + file);
        System.loadLibrary(file);
        return true;
    }

    /**
     * Write dll file to temp directory and load it
     *
     * @param filename dll file name in resources
     */
    public static void extractDll(String filename) {
        InputStream is = null;
        try {
            is = JNIUtil.class.getClassLoader().getResourceAsStream(filename);
            if (is == null) {
                System.err.println("error dll name");
                return;
            }
            Path dirPath = Files.createDirectories(Paths.get("java-gate-temp"));
            Path outputFile = dirPath.resolve(filename);

            if (!Files.exists(outputFile)) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                int nRead;
                byte[] data = new byte[16384];
                while ((nRead = is.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }
                Files.write(outputFile, buffer.toByteArray());
                System.out.println("temp dll: " + outputFile.toAbsolutePath());
            }

            boolean success = loadLib(outputFile.toAbsolutePath().toString());
            if (!success) {
                System.out.println("load lib failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
