package com.dpt.tool;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
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

    // 填入你编译后的正版签名哈希（大写格式）
    private static final String TARGET_SIGN_HASH = "D68F5385405B029EDF076FE34C2CA514794A4F5D9EA86CEDAC2C41133E9430F4";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etApkPath = findViewById(R.id.etApkPath);
        btnStart = findViewById(R.id.btnStart);
        tvLog = findViewById(R.id.tvLog);
        logScrollView = findViewById(R.id.logScrollView);

        // 顶层防篡改水印覆盖
        ViewGroup decorView = (ViewGroup) getWindow().getDecorView();
        WatermarkViewGroup watermarkOverlay = new WatermarkViewGroup(this, "本工具免费 付费皆被坑");
        decorView.post(() -> decorView.addView(watermarkOverlay, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)));

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

    /**
     * 高性能防遮挡防篡改纯画布水印
     */
    private static class WatermarkViewGroup extends View {
        private final String text;
        private final Paint paint;

        public WatermarkViewGroup(Context context, String text) {
            super(context);
            this.text = text;
            this.paint = new Paint();
            this.paint.setColor(Color.parseColor("#12000000")); 
            this.paint.setTextSize(38);
            this.paint.setStyle(Paint.Style.FILL);
            this.paint.setAntiAlias(true);
            this.paint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
            
            setClickable(false);
            setFocusable(false);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                setForceDarkAllowed(false);
            }
        }

        @Override
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            int width = getWidth();
            int height = getHeight();
            if (width <= 0 || height <= 0) return;

            canvas.save();
            canvas.rotate(-30, width / 2.0f, height / 2.0f);

            int side = (int) Math.sqrt(width * width + height * height);
            int stepX = 460; 
            int stepY = 290; 

            for (int x = -side; x < side; x += stepX) {
                for (int y = -side; y < side; y += stepY) {
                    canvas.drawText(text, x, y, paint);
                }
            }
            canvas.restore();
        }
    }

    /**
     * 规范化正版签名完整性校验
     */
    private boolean verifyEnvironmentIntegrity() {
        String currentSignHash = "";
        try {
            PackageManager pm = getPackageManager();
            PackageInfo pi;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pi = pm.getPackageInfo(getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
                if (pi.signingInfo != null) {
                    Signature[] sigs = pi.signingInfo.getApkContentsSigners();
                    if (sigs != null && sigs.length > 0) {
                        currentSignHash = bytesToHex(MessageDigest.getInstance("SHA-256").digest(sigs[0].toByteArray()));
                    }
                }
            } else {
                pi = pm.getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
                if (pi.signatures != null && pi.signatures.length > 0) {
                    currentSignHash = bytesToHex(MessageDigest.getInstance("SHA-256").digest(pi.signatures[0].toByteArray()));
                }
            }
        } catch (Exception ignored) {}

        if (!TARGET_SIGN_HASH.equalsIgnoreCase(currentSignHash)) {
            final String finalSign = currentSignHash;
            uiHandler.post(() -> {
                log("\n错误: 环境完整性校验失败");
                log("签名 SHA-256 检验失败: " + (finalSign.isEmpty() ? "null" : finalSign));
                Toast.makeText(MainActivity.this, "应用完整性校验失败，进程停止", Toast.LENGTH_LONG).show();
            });
            return false;
        }
        return true;
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
                    executor.execute(() -> {
                        if (verifyEnvironmentIntegrity()) {
                            startUnpackPipeline(path);
                        } else {
                            uiHandler.post(() -> btnStart.setEnabled(true));
                        }
                    });
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

        File finalZip = new File(apkDir, apkName + "-[" + timestamp + "]-自适应还原.zip");

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

            File assetsRoot = new File(workspace, "assets");
            byte[] aesKey = null;
            int xorKey = 0;
            String shellVersionTip = "未知";
            String appName = null;
            String acfName = null;
            String jniClsName = null;
            Map<Integer, Map<Integer, byte[]>> insnsDatabase = null;

            // ================= 阶段一：尝试优先解析【标准新版壳】 =================
            File standardSoRoot = new File(assetsRoot, "vwwwwwvwww");
            if (standardSoRoot.exists()) {
                List<File> soFiles = new ArrayList<>();
                findFilesRecursive(standardSoRoot, ".so", soFiles);
                for (File so : soFiles) {
                    aesKey = extractKeyFromSo(so);
                    if (aesKey != null) break;
                }
            }

            File configFile = new File(assetsRoot, "d_shell_data_001");
            File insnsFile = new File(assetsRoot, "OoooooOooo");

            if (configFile.exists() && aesKey != null) {
                try {
                    byte[] configCipher = readFileToByteArray(configFile);
                    byte[] decryptedConfig = decryptAES_CBC(configCipher, aesKey);
                    String jsonStr = new String(decryptedConfig, "UTF-8").trim();
                    jsonStr = jsonStr.substring(jsonStr.indexOf("{"), jsonStr.lastIndexOf("}") + 1);
                    
                    long rawXorKey = jsonStr.contains("insns_xor_key") ? 
                            Long.parseLong(fetchJsonValue(jsonStr, "insns_xor_key")) : 
                            Long.parseLong(fetchJsonValue(jsonStr, "insnsXorKey"));
                    xorKey = (int) (rawXorKey & 0xFFFFFFFFL);

                    appName = fetchJsonStringValue(jsonStr, "app_name");
                    if (appName == null) appName = fetchJsonStringValue(jsonStr, "appName");
                    acfName = fetchJsonStringValue(jsonStr, "acf_name");
                    if (acfName == null) acfName = fetchJsonStringValue(jsonStr, "acfName");
                    jniClsName = fetchJsonStringValue(jsonStr, "jni_cls_name");
                    if (jniClsName == null) jniClsName = fetchJsonStringValue(jsonStr, "jniClsName");

                    if (insnsFile.exists()) {
                        byte[] poolData = readFileToByteArray(insnsFile);
                        insnsDatabase = parseInsnsPool(poolData, xorKey, false);
                        if (insnsDatabase != null) {
                            shellVersionTip = "判定结果：【新版本】";
                        }
                    }
                } catch (Exception e) {
                    insnsDatabase = null; // 发生异常则清除，使逻辑顺延到下一阶段
                }
            }

            // ================= 阶段二：若新版未命中，尝试解析【标准旧版壳】 =================
            if (insnsDatabase == null) {
                File oldAppFile = new File(assetsRoot, "app_name");
                File oldAcfFile = new File(assetsRoot, "app_acf");
                
                // 旧版壳特征：无加密的 OoooooOooo 与明文特征配置资产
                if (insnsFile.exists() && (oldAppFile.exists() || oldAcfFile.exists() || !configFile.exists())) {
                    try {
                        if (oldAppFile.exists()) appName = new String(readFileToByteArray(oldAppFile), "UTF-8").trim();
                        if (oldAcfFile.exists()) acfName = new String(readFileToByteArray(oldAcfFile), "UTF-8").trim();
                        
                        byte[] poolData = readFileToByteArray(insnsFile);
                        // 旧版无指令流异或层，使用 xorKey = 0 进行正常读取
                        insnsDatabase = parseInsnsPool(poolData, 0, false);
                        if (insnsDatabase != null) {
                            shellVersionTip = "判定结果：【旧版本】";
                            aesKey = null; // 旧版无 AES 密钥层
                            xorKey = 0;
                        }
                    } catch (Exception e) {
                        insnsDatabase = null;
                    }
                }
            }

            // ================= 阶段三：若标准版本全失败，则启动【魔改资产自适应爆破】 =================
            if (insnsDatabase == null && assetsRoot.exists()) {
                log("[!] 标准特征未匹配，正在尝试...");
                List<File> allFiles = new ArrayList<>();
                findFilesRecursive(assetsRoot, "", allFiles);

                // 1. 全盘迭代抽取魔改 SO 内的底层密钥
                for (File f : allFiles) {
                    if (f.getName().toLowerCase().endsWith(".so")) {
                        byte[] scannedKey = extractKeyFromSo(f);
                        if (scannedKey != null) {
                            aesKey = scannedKey;
                            break;
                        }
                    }
                }

                if (aesKey != null) {
                    File detectedConfigFile = null;
                    // 2. 盲测寻找被魔改混淆重命名的 JSON 配置块
                    for (File assetFile : allFiles) {
                        if (assetFile.getName().toLowerCase().endsWith(".so")) continue;
                        try {
                            byte[] rawContent = readFileToByteArray(assetFile);
                            byte[] decryptedData = decryptAES_CBC(rawContent, aesKey);
                            if (decryptedData == null) continue;

                            String testStr = new String(decryptedData, "UTF-8").trim();
                            if (testStr.contains("{") && testStr.contains("}") && (testStr.contains("app_name") || testStr.contains("appName"))) {
                                testStr = testStr.substring(testStr.indexOf("{"), testStr.lastIndexOf("}") + 1);
                                
                                appName = fetchJsonStringValue(testStr, "app_name");
                                if (appName == null) appName = fetchJsonStringValue(testStr, "appName");
                                acfName = fetchJsonStringValue(testStr, "acf_name");
                                if (acfName == null) acfName = fetchJsonStringValue(testStr, "acfName");
                                jniClsName = fetchJsonStringValue(testStr, "jni_cls_name");
                                if (jniClsName == null) jniClsName = fetchJsonStringValue(testStr, "jniClsName");
                                
                                long rawXorStr = testStr.contains("insns_xor_key") ? 
                                        Long.parseLong(fetchJsonValue(testStr, "insns_xor_key")) : 
                                        Long.parseLong(fetchJsonValue(testStr, "insnsXorKey"));
                                xorKey = (int) (rawXorStr & 0xFFFFFFFFL);
                                
                                detectedConfigFile = assetFile;
                                shellVersionTip = "判定结果：【未知版本 (" + assetFile.getName() + ")】";
                                break;
                            }
                        } catch (Exception ignored) {}
                    }

                    // 3. 盲测寻找重定向或加深的指令流资产池
                    for (File assetFile : allFiles) {
                        if (assetFile.getName().toLowerCase().endsWith(".so") || assetFile.equals(detectedConfigFile)) continue;
                        try {
                            byte[] rawContent = readFileToByteArray(assetFile);
                            byte[] decryptedData;
                            try {
                                decryptedData = decryptAES_CBC(rawContent, aesKey);
                            } catch (Exception e) {
                                decryptedData = rawContent; // 兼顾未对指令块加外包 AES 的部分变体
                            }

                            if (decryptedData != null && decryptedData.length > 4) {
                                insnsDatabase = parseInsnsPool(decryptedData, xorKey, false);
                                if (insnsDatabase == null) {
                                    insnsDatabase = parseInsnsPool(decryptedData, xorKey, true); // 双切盲断模式
                                }
                                if (insnsDatabase != null) break;
                            }
                        } catch (Exception ignored) {}
                    }
                }
            }

            if (insnsDatabase == null) {
                log("[-] 错误: 无法匹配还原有效的加密或明文指令资产，停止运行。");
                return;
            }

            log("正在还原 DEX ...");
            File pureExtractedDir = new File(workspace, "pure_extracted");
            unzip(pureDexZipFile, pureExtractedDir);

            List<File> innerDexFiles = new ArrayList<>();
            findFilesRecursive(pureExtractedDir, ".dex", innerDexFiles);
            Collections.sort(innerDexFiles, (f1, f2) -> Integer.compare(getDexNumber(f1.getName()), getDexNumber(f2.getName())));

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
                    log("[+] " + newName + " 修复成功");
                } else {
                    copyFile(srcDex, destDex);
                    logs.add(newName + " 无抽取指令，直接复制");
                    log("[~] " + newName + " 无抽取指令，直接复制");
                }
            }

            File readme = new File(fixedDexDir, "说明.txt");
            StringBuilder readmeContent = new StringBuilder();
            readmeContent.append("分析时间: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())).append("\n");
            readmeContent.append(shellVersionTip).append("\n");
            readmeContent.append("AES 密钥: ").append(aesKey != null ? bytesToHex(aesKey) : "无").append("\n");
            readmeContent.append(String.format("指令异或密钥: 0x%X\n\n", xorKey));
            
            readmeContent.append("--- 解析结果 ---\n");
            readmeContent.append("软件入口类：").append(appName != null && !appName.isEmpty() ? appName : "原软件无自定义入口类").append("\n");
            readmeContent.append("软件工厂类：").append(acfName != null && !acfName.isEmpty() ? acfName : "原软件无自定义工厂类").append("\n");
            readmeContent.append("加载类：").append(jniClsName != null ? jniClsName : "未检测到特征加载类").append("\n\n");
            
            if (jniClsName != null) {
                readmeContent.append(String.format("请将下列 Smali 代码引用清除：\ninvoke-static {}, L%s;->clinit()V\n", jniClsName));
            } else {
                readmeContent.append("请清除对应的 JniBridge 初始化调用代码\n");
            }
            readmeContent.append("--------------------\n\n");
            
            readmeContent.append("DEX 修复明细:\n");
            for (String l : logs) readmeContent.append(" - ").append(l).append("\n");

            try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(readme), "UTF-8"))) {
                writer.print(readmeContent.toString());
            }

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

    /**
     * 解析和适配魔改壳特征指令流核心函数
     */
    private Map<Integer, Map<Integer, byte[]>> parseInsnsPool(byte[] poolData, int xorKey, boolean isNoHeaderMode) {
        try {
            Map<Integer, Map<Integer, byte[]>> insnsDatabase = new HashMap<>();
            ByteBuffer poolBuf = ByteBuffer.wrap(poolData).order(ByteOrder.LITTLE_ENDIAN);
            
            int dexCount = 0;
            if (isNoHeaderMode) {
                dexCount = poolBuf.getShort() & 0xFFFF;
            } else {
                poolBuf.getShort(); // 跳过主版本号
                dexCount = poolBuf.getShort() & 0xFFFF;
            }

            if (dexCount <= 0 || dexCount > 100 || (poolBuf.position() + dexCount * 4) > poolData.length) {
                return null;
            }

            poolBuf.position(poolBuf.position() + dexCount * 4); // 越过偏移表项

            for (int d = 0; d < dexCount; d++) {
                if (poolBuf.position() + 2 > poolData.length) return null;
                int methodCount = poolBuf.getShort() & 0xFFFF;
                
                Map<Integer, byte[]> methodMap = new HashMap<>();
                for (int m = 0; m < methodCount; m++) {
                    if (poolBuf.position() + 8 > poolData.length) return null;
                    int methodIdx = poolBuf.getInt();
                    int dataSize = poolBuf.getInt();
                    
                    if (dataSize < 0 || poolBuf.position() + dataSize > poolData.length) return null;
                    byte[] insnsData = new byte[dataSize];
                    poolBuf.get(insnsData);
                    
                    methodMap.put(methodIdx, decryptInsnsBlock(insnsData, xorKey));
                }
                insnsDatabase.put(d, methodMap);
            }
            return insnsDatabase;
        } catch (Exception e) {
            return null; 
        }
    }

    private void showResultDialog(String content) {
        ScrollView scrollView = new ScrollView(this);
        TextView textView = new TextView(this);
        int padding = (int) (16 * getResources().getDisplayMetrics().density);
        textView.setPadding(padding, padding, padding, padding);
        textView.setText(content);
        textView.setTextSize(14);
        
        TypedValue typedValue = new TypedValue();
        if (getTheme().resolveAttribute(com.google.android.material.R.attr.colorOnSurface, typedValue, true)) {
            textView.setTextColor(typedValue.data);
        } else {
            textView.setTextColor(Color.DKGRAY);
        }
        scrollView.addView(textView);

        new MaterialAlertDialogBuilder(this)
                .setTitle("还原成功")
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
            else if (ext.isEmpty() || f.getName().toLowerCase().endsWith(ext)) res.add(f);
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
