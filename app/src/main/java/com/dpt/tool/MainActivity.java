package com.dpt.tool;

import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.TextUtils;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.textfield.TextInputEditText;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private TextInputEditText etApkPath;
    private MaterialButton btnStart;
    private TextView tvLog;
    private ScrollView logScrollView;
    
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etApkPath = findViewById(R.id.etApkPath);
        btnStart = findViewById(R.id.btnStart);
        tvLog = findViewById(R.id.tvLog);
        logScrollView = findViewById(R.id.logScrollView);

        btnStart.setOnClickListener(v -> {
            String path = etApkPath.getText().toString().trim();
            if (TextUtils.isEmpty(path)) {
                log("路径不能为空");
                return;
            }
            
            if (checkStoragePermission()) {
                showDisclaimerDialog(path);
            } else {
                showPermissionRequestDialog();
            }
        });
    }

    private boolean checkStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return Environment.isExternalStorageManager();
        }
        return true;
    }

    private void showPermissionRequestDialog() {
        new MaterialAlertDialogBuilder(this)
                .setTitle("权限申请")
                .setMessage("需要“所有文件访问权限”来保存解密后的资源文件。")
                .setCancelable(false)
                .setPositiveButton("去授权", (dialog, which) -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        try {
                            Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                            intent.addCategory(android.content.Intent.CATEGORY_DEFAULT);
                            intent.setData(Uri.parse(String.format("package:%s", getPackageName())));
                            startActivity(intent);
                        } catch (Exception e) {
                            Intent intent = new Intent();
                            intent.setAction(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                            startActivity(intent);
                        }
                    } else {
                        Toast.makeText(MainActivity.this, "请在系统设置中开启存储权限", Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void showDisclaimerDialog(final String path) {
        new MaterialAlertDialogBuilder(this)
                .setTitle("免责声明")
                .setMessage("本工具仅供安全分析与学习逆向技术使用。请勿用于非法破译或商业侵权行为，因使用本工具造成的任何后果由使用者自行承担。")
                .setCancelable(false)
                .setPositiveButton("同意并继续", (dialog, which) -> {
                    btnStart.setEnabled(false);
                    tvLog.setText("");
                    executor.execute(() -> startUnpackPipeline(path));
                })
                .setNegativeButton("不同意", null)
                .show();
    }

    private void log(String msg) {
        uiHandler.post(() -> {
            tvLog.append(msg + "\n");
            logScrollView.post(() -> logScrollView.fullScroll(ScrollView.FOCUS_DOWN));
        });
    }

        private void startUnpackPipeline(String apkPath) {
        File apkFile = new File(apkPath);
        if (!apkFile.exists()) {
            log("APK 文件不存在: " + apkPath);
            uiHandler.post(() -> btnStart.setEnabled(true));
            return;
        }
        
        
        if (apkFile.isDirectory()) {
            log("[-] 错误: 输入的是文件夹路径，请输入正确的 APK 文件路径！");
            uiHandler.post(() -> btnStart.setEnabled(true));
            return;
        }

        String apkDir = apkFile.getParent();
        
        
        String rawName = apkFile.getName();
        int dotIndex = rawName.lastIndexOf(".");
        String apkName = (dotIndex == -1) ? rawName : rawName.substring(0, dotIndex);
        
        String timestamp = new SimpleDateFormat("yyyy-MM-dd-HH", Locale.getDefault()).format(new Date());

        
        File workspace = new File(apkDir, "dpt_tmp_" + timestamp);
        File fixedDexDir = new File(workspace, "fixed_dexes");
        fixedDexDir.mkdirs();

        File finalZip = new File(apkDir, apkName + "-[" + timestamp + "]-函数抽离壳.zip");

        try {
            log("正在解压目标 APK...");
            unzip(apkFile, workspace);

            File classesDex = new File(workspace, "classes.dex");
            if (!classesDex.exists()) {
                log("未在根目录找到 classes.dex");
                return;
            }
            log("正在提取隐藏的 DEX 压缩包...");
            byte[] dexBytes = readFileToByteArray(classesDex);
            int zipLen = readIntBE(dexBytes, dexBytes.length - 4);
            byte[] pureDexZipData = new byte[zipLen];
            System.arraycopy(dexBytes, dexBytes.length - zipLen - 4, pureDexZipData, 0, zipLen);
            
            File pureDexZipFile = new File(workspace, "pure_dexes.zip");
            writeByteArrayToFile(pureDexZipFile, pureDexZipData);

            log("正在扫描 assets/vwwwwwvwww 下的 SO 文件...");
            File soRoot = new File(workspace, "assets" + File.separator + "vwwwwwvwww");
            byte[] aesKey = null;
            if (soRoot.exists()) {
                List<File> soFiles = new ArrayList<>();
                findFilesRecursive(soRoot, ".so", soFiles);
                for (File so : soFiles) {
                    aesKey = extractKeyFromSo(so);
                    if (aesKey != null) break;
                }
            }

            File configFile = new File(workspace, "assets" + File.separator + "d_shell_data_001");
            File insnsFile = new File(workspace, "assets" + File.separator + "OoooooOooo");

            int xorKey = 0;
            boolean isNewVersion = false;
            String shellVersionTip = "判定结果：【旧版函数抽离壳】";
            
            String appName = null;
            String acfName = null;
            String jniClsName = null;

            if (configFile.exists()) {
                isNewVersion = true;
                shellVersionTip = "判定结果：【新版函数抽离壳】";
                if (aesKey == null) {
                    log("[-] 发现新版配置文件，但未提取到匹配的 AES 密钥，停止运行。");
                    return;
                }
                byte[] configCipher = readFileToByteArray(configFile);
                byte[] decryptedConfig = decryptAES_CBC(configCipher, aesKey);
                String jsonStr = new String(decryptedConfig, "UTF-8").trim();
                jsonStr = jsonStr.substring(jsonStr.indexOf("{"), jsonStr.lastIndexOf("}") + 1);
                
                long rawXorKey = 0;
                if (jsonStr.contains("insns_xor_key")) {
                    rawXorKey = Long.parseLong(fetchJsonValue(jsonStr, "insns_xor_key"));
                } else {
                    rawXorKey = Long.parseLong(fetchJsonValue(jsonStr, "insnsXorKey"));
                }
                xorKey = (int) (rawXorKey & 0xFFFFFFFFL);

                
                appName = fetchJsonStringValue(jsonStr, "app_name");
                if (appName == null) appName = fetchJsonStringValue(jsonStr, "appName");
                
                acfName = fetchJsonStringValue(jsonStr, "acf_name");
                if (acfName == null) acfName = fetchJsonStringValue(jsonStr, "acfName");
                
                jniClsName = fetchJsonStringValue(jsonStr, "jni_cls_name");
                if (jniClsName == null) jniClsName = fetchJsonStringValue(jsonStr, "jniClsName");
            } else {
                log("[+] 未检测到 d_shell_data_001，判定为旧版本壳。将直接进行原样指令回填。");
                
                
                File oldAppFile = new File(workspace, "assets" + File.separator + "app_name");
                File oldAcfFile = new File(workspace, "assets" + File.separator + "app_acf");
                
                if (oldAppFile.exists()) {
                    appName = new String(readFileToByteArray(oldAppFile), "UTF-8").trim();
                }
                if (oldAcfFile.exists()) {
                    acfName = new String(readFileToByteArray(oldAcfFile), "UTF-8").trim();
                }
            }

            if (!insnsFile.exists()) {
                log("[-] 未找到被抽离的指令文件 OoooooOooo，停止运行。");
                return;
            }

            byte[] poolData = readFileToByteArray(insnsFile);
            ByteBuffer poolBuf = ByteBuffer.wrap(poolData).order(ByteOrder.LITTLE_ENDIAN);
            short version = poolBuf.getShort();
            short dexCount = poolBuf.getShort();
            poolBuf.position(4 + dexCount * 4);

            Map<Integer, Map<Integer, byte[]>> insnsDatabase = new HashMap<>();
            for (int d = 0; d < dexCount; d++) {
                int methodCount = poolBuf.getShort() & 0xFFFF;
                Map<Integer, byte[]> methodMap = new HashMap<>();
                for (int m = 0; m < methodCount; m++) {
                    int methodIdx = poolBuf.getInt();
                    int dataSize = poolBuf.getInt();
                    byte[] insnsData = new byte[dataSize];
                    poolBuf.get(insnsData);
                    methodMap.put(methodIdx, decryptInsnsBlock(insnsData, xorKey));
                }
                insnsDatabase.put(d, methodMap);
            }

            File pureExtractedDir = new File(workspace, "pure_extracted");
            unzip(pureDexZipFile, pureExtractedDir);

            List<File> innerDexFiles = new ArrayList<>();
            findFilesRecursive(pureExtractedDir, ".dex", innerDexFiles);
            
            Collections.sort(innerDexFiles, (f1, f2) -> {
                int n1 = getDexNumber(f1.getName());
                int n2 = getDexNumber(f2.getName());
                return Integer.compare(n1, n2);
            });

            List<String> logs = new ArrayList<>();
            for (int i = 0; i < innerDexFiles.size(); i++) {
                File srcDex = innerDexFiles.get(i);
                String newName = (i == 0) ? "classes.dex" : "classes" + (i + 1) + ".dex";
                File destDex = new File(fixedDexDir, newName);

                int origNum = getDexNumber(srcDex.getName());
                int mapIdx = (origNum == 0) ? 0 : origNum - 1;

                if (insnsDatabase.containsKey(mapIdx)) {
                    restoreSingleDex(srcDex, destDex, insnsDatabase.get(mapIdx));
                    logs.add(newName + " 修复成功");
                    log(newName + " 修复成功");
                } else {
                    copyFile(srcDex, destDex);
                    logs.add(newName + " 无抽取指令，直接复制");
                    log(newName + " 无抽取指令，直接复制");
                }
            }

            
            File readme = new File(fixedDexDir, "说明.txt");
            StringBuilder readmeContent = new StringBuilder();
            
            readmeContent.append("处理时间: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())).append("\n");
            readmeContent.append("壳版本类型: ").append(shellVersionTip).append("\n");
            
            if (isNewVersion) {
                readmeContent.append("AES 密钥: ").append(aesKey != null ? bytesToHex(aesKey) : "None").append("\n");
                readmeContent.append(String.format("指令异或密钥: 0x%X\n\n", xorKey));
                
                readmeContent.append("--- 解析结果 ---\n");
                readmeContent.append("软件入口类：").append(appName != null ? appName : "原软件无自定义入口类").append("\n");
                readmeContent.append("软件工厂类：").append(acfName != null ? acfName : "原软件无自定义工厂类").append("\n");
                readmeContent.append("加载类：").append(jniClsName != null ? jniClsName : "未检测到特征加载类").append("\n\n");
                
                if (jniClsName != null) {
                    readmeContent.append(String.format("invoke-static {}, L%s;->clinit()V\n", jniClsName));
                } else {
                    readmeContent.append("invoke-static {}, L替换/JniBridge;->clinit()V\n");
                }
                readmeContent.append("请将上述Smali代码替换为空\n");
                readmeContent.append("--------------------\n\n");
            } else {
                
                readmeContent.append("\n--- 原软件类解析结果 ---\n");
                readmeContent.append("软件入口类：").append(appName != null && !appName.isEmpty() ? appName : "原软件无自定义入口类").append("\n");
                readmeContent.append("软件工厂类：").append(acfName != null && !acfName.isEmpty() ? acfName : "原软件无自定义工厂类").append("\n");
                readmeContent.append("------------------------\n\n");
            }
            
            readmeContent.append("DEX 修复明细:\n");
            for (String l : logs) {
                readmeContent.append(" - ").append(l).append("\n");
            }

            PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(readme), "UTF-8"));
            writer.print(readmeContent.toString());
            writer.close();

            log("正在打包输出压缩包...");
            zipDirectory(fixedDexDir, finalZip);
            log("打包完成，输出路径:\n" + finalZip.getAbsolutePath());

            final String finalShowMsg = readmeContent.toString();
            uiHandler.post(() -> showResultDialog(finalShowMsg));

        } catch (Exception e) {
            log("运行崩溃: " + e.getMessage());
            e.printStackTrace();
        } finally {
            deleteDirRecursive(workspace);
            uiHandler.post(() -> btnStart.setEnabled(true));
        }
    }

    private void showResultDialog(String content) {
        ScrollView scrollView = new ScrollView(this);
        TextView textView = new TextView(this);
        int padding = (int) (16 * getResources().getDisplayMetrics().density);
        textView.setPadding(padding, padding, padding, padding);
        textView.setText(content);
        textView.setTextSize(14);
        textView.setTextColor(com.google.android.material.R.attr.colorOnSurface);
        scrollView.addView(textView);

        new MaterialAlertDialogBuilder(this)
                .setTitle("脱壳还原成功")
                .setView(scrollView)
                .setCancelable(false)
                .setPositiveButton("确定", null)
                .show();
    }

    private byte[] extractKeyFromSo(File soFile) throws Exception {
        byte[] elf = readFileToByteArray(soFile);
        if (elf.length < 52 || elf[0] != 0x7F || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F') return null;

        boolean is64 = (elf[4] == 2);
        ByteBuffer buf = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        long e_shoff = is64 ? buf.getLong(40) : buf.getInt(32) & 0xFFFFFFFFL;
        int e_shentsize = buf.getShort(is64 ? 58 : 46) & 0xFFFF;
        int e_shnum = buf.getShort(is64 ? 60 : 48) & 0xFFFF;
        int e_shstrndx = buf.getShort(is64 ? 62 : 50) & 0xFFFF;

        long shstrndx_off = e_shoff + ((long) e_shstrndx * e_shentsize);
        if (shstrndx_off + (is64 ? 32 : 24) > elf.length) return null;
        long shstr_file_off = is64 ? buf.getLong((int)shstrndx_off + 24) : buf.getInt((int)shstrndx_off + 16) & 0xFFFFFFFFL;

        for (int i = 0; i < e_shnum; i++) {
            long entry_off = e_shoff + ((long) i * e_shentsize);
            int name_index = buf.getInt((int)entry_off);
            
            int name_end = (int)shstr_file_off + name_index;
            if (name_end >= elf.length) continue;
            while (elf[name_end] != 0) name_end++;
            String secName = new String(elf, (int)shstr_file_off + name_index, name_end - ((int)shstr_file_off + name_index), "UTF-8");

            if (".data".equals(secName)) {
                long data_offset = is64 ? buf.getLong((int)entry_off + 24) : buf.getInt((int)entry_off + 16) & 0xFFFFFFFFL;
                long data_size = is64 ? buf.getLong((int)entry_off + 32) : buf.getInt((int)entry_off + 20) & 0xFFFFFFFFL;
                if (data_size >= 33 && (data_offset + 33 <= elf.length)) {
                    byte[] key = new byte[16];
                    System.arraycopy(elf, (int)data_offset + 17, key, 0, 16);
                    return key;
                }
            }
        }
        return null;
    }

    private void restoreSingleDex(File srcDex, File destDex, Map<Integer, byte[]> methodMap) throws Exception {
        byte[] dexBytes = readFileToByteArray(srcDex);
        ByteBuffer buf = ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN);

        int classDefsSize = buf.getInt(96);
        int classDefsOff = buf.getInt(100);

        for (int i = 0; i < classDefsSize; i++) {
            int classDataOff = buf.getInt(classDefsOff + i * 32 + 24);
            if (classDataOff == 0) continue;

            int[] offWrapper = { classDataOff };
            int s_size = readUleb128(dexBytes, offWrapper);
            int i_size = readUleb128(dexBytes, offWrapper);
            int d_size = readUleb128(dexBytes, offWrapper);
            int v_size = readUleb128(dexBytes, offWrapper);

            for (int k = 0; k < s_size + i_size; k++) {
                readUleb128(dexBytes, offWrapper);
                readUleb128(dexBytes, offWrapper);
            }

            offWrapper[0] = fillMethodsList(dexBytes, d_size, offWrapper[0], methodMap);
            fillMethodsList(dexBytes, v_size, offWrapper[0], methodMap);
        }

        fixDexHeaders(dexBytes);
        writeByteArrayToFile(destDex, dexBytes);
    }

    private int fillMethodsList(byte[] dexBytes, int size, int currentOffset, Map<Integer, byte[]> methodMap) {
        int[] offWrapper = { currentOffset };
        int methodIdx = 0;
        for (int i = 0; i < size; i++) {
            int idxDiff = readUleb128(dexBytes, offWrapper);
            readUleb128(dexBytes, offWrapper);
            int codeOff = readUleb128(dexBytes, offWrapper);
            methodIdx += idxDiff;

            if (codeOff != 0 && methodMap.containsKey(methodIdx)) {
                byte[] realCode = methodMap.get(methodIdx);
                System.arraycopy(realCode, 0, dexBytes, codeOff + 16, realCode.length);
            }
        }
        return offWrapper[0];
    }

    private byte[] decryptAES_CBC(byte[] cipherText, byte[] keyBytes) throws Exception {
        byte[] ivBytes = new byte[16];
        System.arraycopy(keyBytes, 0, ivBytes, 0, 16);
        ivBytes[3] = 47;
        ivBytes[9] = 118;

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(cipherText);
    }

    private byte[] decryptInsnsBlock(byte[] code, int xorKey) {
        if (xorKey == 0) return code;
        for (int i = 0; i < code.length; i++) {
            int shift = (i & 3) << 3;
            int keyByte = (xorKey >> shift) & 0xFF;
            code[i] ^= keyByte;
        }
        return code;
    }

    private int readUleb128(byte[] data, int[] offset) {
        int res = 0, shift = 0;
        while (true) {
            byte b = data[offset[0]++];
            res |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        return res;
    }

    private void fixDexHeaders(byte[] dexBytes) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(dexBytes, 32, dexBytes.length - 32);
        System.arraycopy(md.digest(), 0, dexBytes, 12, 20);

        Adler32 adler = new Adler32();
        adler.update(dexBytes, 12, dexBytes.length - 12);
        int checksum = (int) adler.getValue();
        ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN).putInt(8, checksum);
    }

    private int getDexNumber(String name) {
        Matcher m = Pattern.compile("classes(\\d*)\\.dex").matcher(name);
        if (m.matches()) {
            String g = m.group(1);
            return (g == null || g.isEmpty()) ? 0 : Integer.parseInt(g);
        }
        return 0;
    }

    private String fetchJsonValue(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*(-?\\d+)");
        Matcher m = p.matcher(json);
        if (m.find()) return m.group(1);
        return "0";
    }

    private String fetchJsonStringValue(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        if (m.find()) return m.group(1);
        return null;
    }

    private void unzip(File zipFile, File destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry;
            byte[] buffer = new byte[4096];
            while ((entry = zis.getNextEntry()) != null) {
                File f = new File(destDir, entry.getName());
                if (entry.isDirectory()) {
                    f.mkdirs();
                } else {
                    f.getParentFile().mkdirs();
                    try (FileOutputStream fos = new FileOutputStream(f)) {
                        int len;
                        while ((len = zis.read(buffer)) > 0) fos.write(buffer, 0, len);
                    }
                }
                zis.closeEntry();
            }
        }
    }

    private void zipDirectory(File dir, File zipFile) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFile))) {
            byte[] buffer = new byte[4096];
            File[] files = dir.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (f.isDirectory()) continue;
                    try (FileInputStream fis = new FileInputStream(f)) {
                        zos.putNextEntry(new ZipEntry(f.getName()));
                        int len;
                        while ((len = fis.read(buffer)) > 0) zos.write(buffer, 0, len);
                        zos.closeEntry();
                    }
                }
            }
        }
    }

    private void findFilesRecursive(File dir, String ext, List<File> res) {
        File[] list = dir.listFiles();
        if (list == null) return;
        for (File f : list) {
            if (f.isDirectory()) findFilesRecursive(f, ext, res);
            else if (f.getName().toLowerCase().endsWith(ext)) res.add(f);
        }
    }

    private byte[] readFileToByteArray(File file) throws IOException {
        byte[] b = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            int off = 0;
            while (off < b.length) {
                int read = fis.read(b, off, b.length - off);
                if (read == -1) break;
                off += read;
            }
        }
        return b;
    }

    private void writeByteArrayToFile(File file, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) { fos.write(data); }
    }

    private void copyFile(File src, File dest) throws IOException {
        try (InputStream in = new FileInputStream(src); OutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[4096]; int len;
            while ((len = in.read(buf)) > 0) out.write(buf, 0, len);
        }
    }

    private int readIntBE(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16) | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private void deleteDirRecursive(File file) {
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File c : files) deleteDirRecursive(c);
            }
        }
        file.delete();
    }
}
