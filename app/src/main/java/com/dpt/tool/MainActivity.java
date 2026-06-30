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

import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.builder.MutableMethodImplementation;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.Reference;
import org.jf.dexlib2.immutable.ImmutableDexFile;
import org.jf.dexlib2.immutable.ImmutableClassDef;
import org.jf.dexlib2.immutable.ImmutableMethod;
import org.jf.dexlib2.Opcode;

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

    private static final String TARGET_SIGN_HASH = "D68F5385405B029EDF076FE34C2CA514794A4F5D9EA86CEDAC2C41133E9430F4";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etApkPath = findViewById(R.id.etApkPath);
        btnStart = findViewById(R.id.btnStart);
        tvLog = findViewById(R.id.tvLog);
        logScrollView = findViewById(R.id.logScrollView);

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
            for (int x = -side; x < side; x += 460) {
                for (int y = -side; y < side; y += 290) {
                    canvas.drawText(text, x, y, paint);
                }
            }
            canvas.restore();
        }
    }

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
                log("\n错误: 校验失败");
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
                            intent.addCategory(Intent.CATEGORY_DEFAULT);
                            intent.setData(Uri.parse(String.format("package:%s", getPackageName())));
                            startActivity(intent);
                        } catch (Exception e) {
                            Intent intent = new Intent();
                            intent.setAction(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                            startActivity(intent);
                        }
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
        if (!apkFile.exists() || apkFile.isDirectory()) {
            log("[-] 错误: APK 路径非法！");
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

        File finalZip = new File(apkDir, apkName + "-[" + timestamp + "]-还原.zip");

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
            File configFile = new File(assetsRoot, "d_shell_data_001");
            File insnsFile = new File(assetsRoot, "OoooooOooo");

            List<File> candidateSoFiles = new ArrayList<>();
            findFilesRecursive(assetsRoot, ".so", candidateSoFiles);

            byte[] finalAesKey = null;
            int xorKey = 0;
            String shellVersionTip = "未知";
            String appName = null;
            String acfName = null;
            String jniClsName = null;
            Map<Integer, Map<Integer, byte[]>> insnsDatabase = null;

            if (configFile.exists() && !candidateSoFiles.isEmpty()) {
                log("[*] 正在处理...");
                byte[] configCipher = readFileToByteArray(configFile);

                for (File so : candidateSoFiles) {
                    try {
                        byte[] testKey = extractKeyFromSo(so);
                        if (testKey == null || isZeroArray(testKey)) continue;

                        byte[] decryptedConfig = decryptAES_CBC(configCipher, testKey);
                        if (decryptedConfig != null && decryptedConfig.length > 0) {
                            String jsonStr = new String(decryptedConfig, "UTF-8").trim();
                            if (jsonStr.contains("{") && (jsonStr.contains("app_name") || jsonStr.contains("appName"))) {
                                finalAesKey = testKey;
                                log("[+] 成功命中有效密钥来源 SO: " + so.getName() + " | Key: " + bytesToHex(finalAesKey));
                                
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
                                break; 
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }

            if (finalAesKey != null && insnsFile.exists()) {
                try {
                    byte[] poolData = readFileToByteArray(insnsFile);
                    insnsDatabase = parseInsnsPool(poolData, xorKey, false);
                    if (insnsDatabase != null) {
                        shellVersionTip = "版本：新版";
                    }
                } catch (Exception e) {
                    insnsDatabase = null;
                }
            }

            if (insnsDatabase == null) {
                File oldAppFile = new File(assetsRoot, "app_name");
                File oldAcfFile = new File(assetsRoot, "app_acf");
                if (insnsFile.exists() && (oldAppFile.exists() || oldAcfFile.exists() || !configFile.exists())) {
                    try {
                        log("[*] 降级匹配旧版本无加密特征...");
                        if (oldAppFile.exists()) appName = new String(readFileToByteArray(oldAppFile), "UTF-8").trim();
                        if (oldAcfFile.exists()) acfName = new String(readFileToByteArray(oldAcfFile), "UTF-8").trim();
                        
                        byte[] poolData = readFileToByteArray(insnsFile);
                        insnsDatabase = parseInsnsPool(poolData, 0, false);
                        if (insnsDatabase != null) {
                            shellVersionTip = "版本：旧版";
                            finalAesKey = null;
                            xorKey = 0;
                        }
                    } catch (Exception e) {
                        insnsDatabase = null;
                    }
                }
            }

            if (insnsDatabase == null && assetsRoot.exists()) {
                log("[!] 开始处理...");
                List<File> allFiles = new ArrayList<>();
                findFilesRecursive(assetsRoot, "", allFiles);

                for (File f : allFiles) {
                    if (f.getName().toLowerCase().endsWith(".so")) {
                        try {
                            byte[] scannedKey = extractKeyFromSo(f);
                            if (scannedKey != null && !isZeroArray(scannedKey)) {
                                finalAesKey = scannedKey;
                                break;
                            }
                        } catch (Exception ignored) {}
                    }
                }

                if (finalAesKey != null) {
                    File detectedConfigFile = null;
                    for (File assetFile : allFiles) {
                        if (assetFile.getName().toLowerCase().endsWith(".so")) continue;
                        try {
                            byte[] rawContent = readFileToByteArray(assetFile);
                            byte[] decryptedData = decryptAES_CBC(rawContent, finalAesKey);
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
                                shellVersionTip = "版本：未知(" + assetFile.getName() + ")";
                                break;
                            }
                        } catch (Exception ignored) {}
                    }

                    for (File assetFile : allFiles) {
                        if (assetFile.getName().toLowerCase().endsWith(".so") || assetFile.equals(detectedConfigFile)) continue;
                        try {
                            byte[] rawContent = readFileToByteArray(assetFile);
                            byte[] decryptedData;
                            try {
                                decryptedData = decryptAES_CBC(rawContent, finalAesKey);
                            } catch (Exception e) {
                                decryptedData = rawContent; 
                            }

                            if (decryptedData != null && decryptedData.length > 4) {
                                insnsDatabase = parseInsnsPool(decryptedData, xorKey, false);
                                if (insnsDatabase == null) {
                                    insnsDatabase = parseInsnsPool(decryptedData, xorKey, true);
                                }
                                if (insnsDatabase != null) {
                                    log("[+] 处理成功: " + assetFile.getName());
                                    break;
                                }
                            }
                        } catch (Exception ignored) {}
                    }
                }
            }

            if (insnsDatabase == null) {
                log("[-] 错误: 无法解析，任务终止。");
                return;
            }

            log("正在还原Dex...");
            File pureExtractedDir = new File(workspace, "pure_extracted");
            unzip(pureDexZipFile, pureExtractedDir);

            List<File> innerDexFiles = new ArrayList<>();
            findFilesRecursive(pureExtractedDir, ".dex", innerDexFiles);
            Collections.sort(innerDexFiles, (f1, f2) -> Integer.compare(getDexNumber(f1.getName()), getDexNumber(f2.getName())));

            for (int i = 0; i < innerDexFiles.size(); i++) {
                File srcDex = innerDexFiles.get(i);
                String newName = (i == 0) ? "classes.dex" : "classes" + (i + 1) + ".dex";
                File destDex = new File(fixedDexDir, newName);

                int origNum = getDexNumber(srcDex.getName());
                int mapIdx = (origNum == 0) ? 0 : origNum - 1;

                if (insnsDatabase.containsKey(mapIdx)) {
                    restoreSingleDex(srcDex, destDex, insnsDatabase.get(mapIdx));
                    log("[+] " + newName + " 还原指令成功");
                } else {
                    copyFile(srcDex, destDex);
                    log("[~] " + newName + " 无抽取，直接复制");
                }
            }

            final String reportSummary = "分析时间: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date()) + "\n"
                    + shellVersionTip + "\n"
                    + "AES 密钥: " + (finalAesKey != null ? bytesToHex(finalAesKey) : "无") + "\n"
                    + String.format("指令异或密钥: 0x%X\n\n", xorKey)
                    + "--- 解析结果 ---\n"
                    + "软件入口类：" + (appName != null && !appName.isEmpty() ? appName : "原软件无自定义入口类") + "\n"
                    + "软件工厂类：" + (acfName != null && !acfName.isEmpty() ? acfName : "原软件无自定义工厂类") + "\n"
                    + "加载类：" + (jniClsName != null ? jniClsName : "未检测到特征加载类型") + "\n--------------------\n";

            writeByteArrayToFile(new File(fixedDexDir, "说明.txt"), reportSummary.getBytes("UTF-8"));

            final String targetCleanClass = jniClsName;
            
            if (targetCleanClass != null && !targetCleanClass.trim().isEmpty()) {
                uiHandler.post(() -> {
                    new MaterialAlertDialogBuilder(MainActivity.this)
                            .setTitle("是否尝试自动处理加载类")
                            .setMessage("检测到加载类为: " + targetCleanClass + "\n\n注意：不保证可用，可能由于各种原因导致处理失败。")
                            .setCancelable(false)
                            .setPositiveButton("处理清洗", (dialog, which) -> {
                                executor.execute(() -> {
                                    try {
                                        log("[*] 正在处理...");
                                        int totalCleaned = executeDexlib2Cleaning(fixedDexDir, targetCleanClass);

                                        log("处理成功，正在打包...");
                                        zipDirectory(fixedDexDir, finalZip);
                                        log("打包完成，输出路径:\n" + finalZip.getAbsolutePath());
                                        showResultDialog(reportSummary + "\n[处理状态]：共处理了 " + totalCleaned + " 个调用");
                                    } catch (Exception ex) {
                                        log("[-] 错误: " + ex.getMessage());
                                        ex.printStackTrace();
                                    }
                                });
                            })
                            .setNegativeButton("直接打包", (dialog, which) -> {
                                executor.execute(() -> {
                                    try {
                                        log("正在直接打包输出压缩包...");
                                        zipDirectory(fixedDexDir, finalZip);
                                        log("打包完成，输出路径:\n" + finalZip.getAbsolutePath());
                                        showResultDialog(reportSummary);
                                    } catch (Exception ex) {
                                        log("[-] 打包失败: " + ex.getMessage());
                                    }
                                });
                            })
                            .show();
                });
            } else {
                log("[*] 未找到加载类特征...");
                zipDirectory(fixedDexDir, finalZip);
                log("打包完成，输出路径:\n" + finalZip.getAbsolutePath());
                showResultDialog(reportSummary);
            }

        } catch (Exception e) {
            log("运行崩溃: " + e.getMessage());
            e.printStackTrace();
        } finally {
            uiHandler.post(() -> btnStart.setEnabled(true));
        }
    }

    private int executeDexlib2Cleaning(File dexFolder, String jniClsName) throws Exception {
        String smaliClassName = jniClsName.startsWith("L") ? jniClsName : "L" + jniClsName;
        if (!smaliClassName.endsWith(";")) smaliClassName += ";";

        File[] dexFiles = dexFolder.listFiles();
        if (dexFiles == null) return 0;

        int totalAllDexCleaned = 0;

        for (File f : dexFiles) {
            if (!f.getName().endsWith(".dex")) {
                continue; 
            }

            log("[*] 正在处理: " + f.getName());
            DexFile dexFile = DexFileFactory.loadDexFile(f, Opcodes.getDefault());
            Set<ClassDef> newClassDefs = new HashSet<>();
            boolean isDexModified = false;
            int totalCleanedInstructions = 0;

            for (ClassDef classDef : dexFile.getClasses()) {
                if (classDef.getType().equals(smaliClassName)) {
                    isDexModified = true;
                    log("[+] 处理中...");
                    continue; 
                }

                Set<Method> newMethods = new HashSet<>();
                boolean isClassModified = false;

                for (Method method : classDef.getMethods()) {
                    MethodImplementation impl = method.getImplementation();
                    if (impl == null) {
                        newMethods.add(method);
                        continue;
                    }

                    MutableMethodImplementation mutableImpl = new MutableMethodImplementation(impl);
                    boolean isMethodModified = false;
                    
                    List<org.jf.dexlib2.builder.BuilderInstruction> instructions = mutableImpl.getInstructions();
                    for (int idx = 0; idx < instructions.size(); idx++) {
                        org.jf.dexlib2.builder.BuilderInstruction inst = instructions.get(idx);
                        
                        if (inst instanceof ReferenceInstruction) {
                            Reference ref = ((ReferenceInstruction) inst).getReference();
                            String referencedClass = null;
                            
                            if (ref instanceof MethodReference) {
                                referencedClass = ((MethodReference) ref).getDefiningClass();
                            } else if (ref instanceof org.jf.dexlib2.iface.reference.TypeReference) {
                                referencedClass = ((org.jf.dexlib2.iface.reference.TypeReference) ref).getType();
                            } else if (ref instanceof org.jf.dexlib2.iface.reference.FieldReference) {
                                referencedClass = ((org.jf.dexlib2.iface.reference.FieldReference) ref).getDefiningClass();
                            }

                            if (referencedClass != null && referencedClass.equals(smaliClassName)) {
                                Opcode nopOpcode = Opcode.NOP;
                                mutableImpl.replaceInstruction(idx, new org.jf.dexlib2.builder.instruction.BuilderInstruction10x(nopOpcode));
                                isMethodModified = true;
                                isClassModified = true;
                                isDexModified = true;
                                totalCleanedInstructions++;
                            }
                        }
                    }

                    if (isMethodModified) {
                        newMethods.add(new ImmutableMethod(
                                method.getDefiningClass(), method.getName(), method.getParameters(),
                                method.getReturnType(), method.getAccessFlags(), method.getAnnotations(),
                                method.getHiddenApiRestrictions(), mutableImpl));
                    } else {
                        newMethods.add(method);
                    }
                }

                if (isClassModified) {
                    List<Method> directMethods = new ArrayList<>();
                    List<Method> virtualMethods = new ArrayList<>();
                    for (Method m : newMethods) {
                        if (org.jf.dexlib2.util.MethodUtil.isStatic(m) || org.jf.dexlib2.util.MethodUtil.isConstructor(m) || (m.getAccessFlags() & 0x0002) != 0) {
                            directMethods.add(m);
                        } else {
                            virtualMethods.add(m);
                        }
                    }

                    newClassDefs.add(new ImmutableClassDef(
                            classDef.getType(), 
                            classDef.getAccessFlags(), 
                            classDef.getSuperclass(),
                            classDef.getInterfaces(), 
                            classDef.getSourceFile(), 
                            classDef.getAnnotations(),
                            classDef.getStaticFields(), 
                            classDef.getInstanceFields(), 
                            directMethods, 
                            virtualMethods));
                } else {
                    newClassDefs.add(classDef);
                }
            }

            if (isDexModified) {
                DexFile outputDexFile = new ImmutableDexFile(dexFile.getOpcodes(), newClassDefs);
                DexFileFactory.writeDexFile(f.getAbsolutePath(), outputDexFile);
                log("[+] " + f.getName() + " 处理完成，共处理了 " + totalCleanedInstructions + " 处调用。");
                totalAllDexCleaned += totalCleanedInstructions;
            }
        }
        return totalAllDexCleaned;
    }

    private boolean isZeroArray(byte[] arr) {
        for (byte b : arr) {
            if (b != 0) return false;
        }
        return true;
    }

    private Map<Integer, Map<Integer, byte[]>> parseInsnsPool(byte[] poolData, int xorKey, boolean isNoHeaderMode) {
        try {
            Map<Integer, Map<Integer, byte[]>> insnsDatabase = new HashMap<>();
            ByteBuffer poolBuf = ByteBuffer.wrap(poolData).order(ByteOrder.LITTLE_ENDIAN);
            int dexCount = 0;
            if (isNoHeaderMode) {
                dexCount = poolBuf.getShort() & 0xFFFF;
            } else {
                poolBuf.getShort(); 
                dexCount = poolBuf.getShort() & 0xFFFF;
            }

            if (dexCount <= 0 || dexCount > 100 || (poolBuf.position() + dexCount * 4) > poolData.length) {
                return null;
            }
            poolBuf.position(poolBuf.position() + dexCount * 4); 

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
        uiHandler.post(() -> {
            ScrollView scrollView = new ScrollView(MainActivity.this);
            TextView textView = new TextView(MainActivity.this);
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

            new MaterialAlertDialogBuilder(MainActivity.this)
                    .setTitle("处理成功")
                    .setView(scrollView)
                    .setCancelable(false)
                    .setPositiveButton("完成", null)
                    .show();
        });
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
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1) sb.append('0');
            sb.append(hex);
        }
        return sb.toString().toUpperCase(Locale.getDefault());
    }
}
