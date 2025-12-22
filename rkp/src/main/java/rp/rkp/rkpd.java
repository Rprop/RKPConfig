package rp.rkp;

import android.annotation.SuppressLint;
import android.app.Application;
import android.content.AttributionSource;
import android.content.Context;
import android.content.pm.PackageManager;
import android.media.DeniedByServerException;
import android.media.MediaDrm;
import android.media.UnsupportedSchemeException;
import android.os.Build;
import android.os.Looper;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.Log;
import android.util.Pair;

import androidx.annotation.Keep;

import com.android.rkpdapp.GeekResponse;
import com.android.rkpdapp.RkpdException;
import com.android.rkpdapp.database.ProvisionedKey;
import com.android.rkpdapp.database.ProvisionedKeyDao;
import com.android.rkpdapp.database.RkpdDatabase;
import com.android.rkpdapp.interfaces.ServerInterface;
import com.android.rkpdapp.interfaces.ServiceManagerInterface;
import com.android.rkpdapp.interfaces.SystemInterface;
import com.android.rkpdapp.metrics.ProvisioningAttempt;
import com.android.rkpdapp.provisioner.Provisioner;
import com.android.rkpdapp.utils.Settings;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import co.nstant.in.cbor.CborException;
import dalvik.system.PathClassLoader;

// /system/bin/app_process -Djava.class.path=$(cmd package path rp.rkp | sed 's/^.\{8\}//') / --nice-name=com.android.rkpdapp rp.rkp.rkpd
@SuppressLint({"SoonBlockedPrivateApi", "PrivateApi", "DiscouragedPrivateApi"})
public class rkpd extends Application {
    private static final String TAG = "Rkpd";

    @Keep
    public static void main(String[] args) {
        final AtomicReference<Process> processRef = new AtomicReference<>();
        final AtomicInteger uidRef = new AtomicInteger(0);
        new Thread(() -> {
            try {
                Process process = Runtime.getRuntime().exec("logcat --pid=" + android.os.Process.myPid());
                processRef.set(process);
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (uidRef.get() != 0) System.out.println(line);
                    }
                }
                processRef.set(null);
                process.destroyForcibly();
            } catch (Throwable ignored) {
            }
        }).start();
        try {
            Looper.prepareMainLooper();

            Class<?> clsActivityThread = Class.forName("android.app.ActivityThread");
            Object activityThread = clsActivityThread.getDeclaredMethod("systemMain").invoke(null);
            Context systemContext = (Context) clsActivityThread.getDeclaredMethod("getSystemContext").invoke(activityThread);
            assert systemContext != null;
            String[] rkpList = new String[]{
                    "com.android.rkpdapp",
                    "com.google.android.rkpdapp",
                    // "com.android.remoteprovisioner",
                    // "com.google.android.remoteprovisioner",
            };
            Context rkpContext = null;
            for (String pkg : rkpList) {
                try {
                    rkpContext = systemContext.createPackageContext(pkg, 0);
                    break;
                } catch (PackageManager.NameNotFoundException ignored) {
                }
            }
            if (rkpContext == null) {
                Process process = processRef.get();
                if (process != null) {
                    process.destroyForcibly();
                }
                return;
            }
            final Context appContext = rkpContext;

            fixupGMSCore(clsActivityThread);

            rkpd application = new rkpd();
            application.attachBaseContext(appContext);

            if (BuildConfig.VERSION_CODE == 0) {
                Field mInitialApplication = clsActivityThread.getDeclaredField("mInitialApplication");
                mInitialApplication.setAccessible(true);
                mInitialApplication.set(activityThread, application);

                Field mAttributionSource = appContext.getClass().getDeclaredField("mAttributionSource");
                mAttributionSource.setAccessible(true);
                mAttributionSource.set(appContext, new AttributionSource.Builder(
                        appContext.getAttributionSource()).setPackageName(appContext.getPackageName()).build());
            }

            Field mPackageInfo = appContext.getClass().getDeclaredField("mPackageInfo");
            mPackageInfo.setAccessible(true);
            Object packageInfo = mPackageInfo.get(appContext);
            assert packageInfo != null;
            Field mApplication = packageInfo.getClass().getDeclaredField("mApplication");
            mApplication.setAccessible(true);
            mApplication.set(packageInfo, application);

            PathClassLoader cl = new PathClassLoader(
                    args[0],
                    appContext.getClassLoader());

            setParent(rkpd.class.getClassLoader(), cl);

            Field sInitialized = cl.loadClass("android.database.sqlite.SQLiteCompatibilityWalFlags").getDeclaredField("sInitialized");
            sInitialized.setAccessible(true);
            sInitialized.set(null, true);

            int uid = appContext.getApplicationInfo().uid;
            Runnable cleanup = () -> {
                if (uid > 0) {
                    fixupOwner(appContext.getDataDir(), uid);
                    fixupOwner(appContext.createDeviceProtectedStorageContext().getDataDir(), uid);
                }
                Process process = processRef.get();
                if (process != null) {
                    SystemClock.sleep(500);
                    process.destroyForcibly();
                }
            };

            if (args.length > 1 && "dump".equals(args[1])) {
                new Thread(() -> {
                    try {
                        ProvisionedKeyDao keyDao = RkpdDatabase.getDatabase(appContext).provisionedKeyDao();
                        if (keyDao != null) {
                            List<ProvisionedKey> allKeys = keyDao.getAllKeys();
                            if (allKeys != null) {
                                System.out.println("Total keys in pool: " + allKeys.size());
                                PackageManager packageManager = appContext.getPackageManager();
                                ArrayList<Pair<String, Instant>> assigned = new ArrayList<>();
                                for (ProvisionedKey pk : allKeys) {
                                    if (pk.keyId != null) {
                                        String pkg = null, label = null;
                                        try {
                                            pkg = packageManager.getNameForUid(pk.keyId);
                                            if (pkg != null) {
                                                label = packageManager.getApplicationLabel(
                                                        packageManager.getApplicationInfo(pkg, 0)
                                                ).toString();
                                            }
                                        } catch (Exception ignored) {
                                        }
                                        System.out.println("Key assigned by " + pk.clientUid + " to " + pk.keyId + '(' + pkg + "), exp=" + pk.expirationTime);
                                        if (pkg != null) {
                                            String irpcHal = "TEE";
                                            if (pk.irpcHal != null) {
                                                if (pk.irpcHal.endsWith("strongbox")) {
                                                    irpcHal = "STRONGBOX";
                                                } else if (pk.irpcHal.endsWith("avf")) {
                                                    irpcHal = "AVF";
                                                }
                                            }
                                            assigned.add(new Pair<>((label != null ? label : pkg) + '_' + irpcHal, pk.expirationTime));
                                        }
                                    }
                                }
                                if (Locale.getDefault().getLanguage().startsWith("zh")) {
                                    System.out.println("==== 远程密钥池可用数 ====");
                                    System.out.println(allKeys.size());
                                    System.out.println("==== 远程密钥分配记录 ====");
                                    for (int index = 0; index < assigned.size(); ++index) {
                                        Pair<String, Instant> pair = assigned.get(index);
                                        System.out.print((index + 1) + "." + pair.first);
                                        Instant now = Instant.now();
                                        if (now.isBefore(pair.second)) {
                                            Duration duration = Duration.between(now, pair.second);
                                            long days = duration.toDays();
                                            long hours = duration.toHours() % 24;
                                            System.out.println(", " + days + '天' + hours + "小时后过期");
                                        } else {
                                            System.out.println(", 已过期");
                                        }
                                    }
                                }
                            }
                        }
                        cleanup.run();
                    } catch (final Throwable tr) {
                        Log.e(TAG, "dump", tr);
                    }
                    System.exit(0);
                }).start();
            } else {
                Looper.getMainLooper().getQueue().addIdleHandler(() -> {
                    new Thread(() -> {
                        try {
                            uidRef.set(uid);
                            try {
                                new PeriodicProvisioner(appContext).doSynchronizedWork();
                            } catch (final Throwable tr) {
                                Log.e(TAG, "doSynchronizedWork", tr);
                            }
                            try {
                                new WidevineProvisioner().provisionWidevine();
                            } catch (final Throwable tr) {
                                Log.e(TAG, "provisionWidevine", tr);
                            }
                            cleanup.run();
                        } catch (final Throwable tr) {
                            Log.e(TAG, "core", tr);
                        }
                        System.exit(0);
                    }).start();
                    return false;
                });
            }
            Looper.loop();
        } catch (final Throwable tr) {
            Log.e(TAG, "main", tr);
            System.err.println(android.util.Log.getStackTraceString(tr));
        }
    }

    public static void setParent(ClassLoader cl, ClassLoader pcl) throws Exception {
        Field parent = ClassLoader.class.getDeclaredField("parent");
        parent.setAccessible(true);
        parent.set(cl, pcl);
    }

    private static void fixupGMSCore(Class<?> clsActivityThread) {
        try {
            Field sPackageManager = clsActivityThread.getDeclaredField("sPackageManager");
            sPackageManager.setAccessible(true);
            Object iPackageManager = sPackageManager.get(null);
            sPackageManager.set(null, Proxy.newProxyInstance(clsActivityThread.getClassLoader(),
                    new Class[]{Class.forName("android.content.pm.IPackageManager")},
                    (InvocationHandler) (proxy, method, args) -> {
                        String name = method.getName();
                        if ("hasSystemFeature".equals(name) &&
                                args.length > 0 && "cn.google.services".equals(args[0])) {
                            return false;
                        }
                        return method.invoke(iPackageManager, args);
                    }));
        } catch (final Throwable tr) {
            Log.e(TAG, "fixupGMSCore", tr);
        }
    }

    private static void fixupOwner(File f, int uid) {
        try {
            String path = f.getPath();
            StructStat stat = Os.stat(path);
            if (stat.st_uid == 0) {
                Os.chown(path, uid, uid);
            }
            if (OsConstants.S_ISDIR(stat.st_mode)) {
                File[] fs = f.listFiles();
                if (fs != null) {
                    for (File ff : fs) {
                        fixupOwner(ff, uid);
                    }
                }
            }
        } catch (ErrnoException ignored) {
        }
    }

    private static final class PeriodicProvisioner {
        private static final String TAG = "RkpdPeriodicProvisioner";

        private final Context mContext;
        private final ProvisionedKeyDao mKeyDao;

        public PeriodicProvisioner(Context context) {
            mContext = context;
            mKeyDao = RkpdDatabase.getDatabase(context).provisionedKeyDao();
        }

        public void doSynchronizedWork() {
            Log.i(TAG, "Waking up; checking provisioning state.");

            SystemInterface[] irpcs = ServiceManagerInterface.getAllInstances();
            if (irpcs.length == 0) {
                Log.i(TAG, "Stopping periodic provisioner: there are no IRPC HALs");
                return;
            }

            if (Settings.getDefaultUrl().isEmpty() || Settings.getUrl(mContext).isEmpty()) {
                Log.i(TAG, "Stopping periodic provisioner: system has no configured server endpoint");
                return;
            }

            try (ProvisioningAttempt metrics = ProvisioningAttempt.createScheduledAttemptMetrics(
                    mContext)) {
                // Clean up the expired keys
                mKeyDao.deleteExpiringKeys(Instant.now());

                // Fetch geek from the server and figure out whether provisioning needs to be stopped.
                GeekResponse response;
                try {
                    response = new ServerInterface(mContext, true).fetchGeekAndUpdate(metrics);
                } catch (Exception e) {
                    Log.e(TAG, "Error fetching configuration from the RKP server", e);
                    return;
                }

                if (response.numExtraAttestationKeys == 0) {
                    Log.i(TAG, "Disable provisioning and delete all keys.");

                    mKeyDao.deleteAllKeys();
                    metrics.setIsKeyPoolEmpty(true);
                    return;
                }

                Log.i(TAG, "Total services found implementing IRPC: " + irpcs.length);
                Provisioner provisioner = new Provisioner(mContext, mKeyDao, true);
                provisioner.clearBadAttestationKeys(response);

                final AtomicBoolean result = new AtomicBoolean(true);
                Arrays.stream(irpcs).parallel().forEach(irpc -> {
                    Log.i(TAG, "Starting provisioning for " + irpc);
                    try {
                        provisioner.provisionKeys(metrics, irpc, response);
                        Log.i(TAG, "Successfully provisioned " + irpc);
                    } catch (CborException e) {
                        Log.e(TAG, "Error parsing CBOR for " + irpc, e);
                        result.set(false);
                    } catch (InterruptedException | RkpdException e) {
                        Log.e(TAG, "Error provisioning keys for " + irpc, e);
                        result.set(false);
                    }
                });
                result.get();
            }
        }
    }

    private static final class WidevineProvisioner {
        private static final String TAG = "RkpdWidevine";
        private static final UUID WIDEVINE_UUID = new UUID(0xEDEF8BA979D64ACEL, 0xA3C827DCD51D21EDL);
        private static final byte[] EMPTY_BODY = new byte[0];
        private static final int TIMEOUT_MS = 20000;

        private static final Map<String, String> REQ_PROPERTIES = new HashMap<>();

        static {
            REQ_PROPERTIES.put("Accept", "*/*");
            REQ_PROPERTIES.put("User-Agent", buildUserAgentString());
            REQ_PROPERTIES.put("Content-Type", "application/json");
            REQ_PROPERTIES.put("Connection", "close");
        }

        private static String buildUserAgentString() {
            ArrayList<String> parts = new ArrayList<>();
            parts.add("AndroidRemoteProvisioner");
            parts.add(Build.BRAND);
            parts.add(Build.MODEL);
            parts.add(Build.TYPE);
            parts.add(Build.VERSION.INCREMENTAL);
            parts.add(Build.ID);
            return String.join("/", parts);
        }

        public void provisionWidevine() {
            try {
                final MediaDrm drm = new MediaDrm(WIDEVINE_UUID);
                final MediaDrm.ProvisionRequest request = drm.getProvisionRequest();
                final byte[] response = fetchWidevineCertificate(request);
                Log.i(TAG, "WV server returned " + response.length + " bytes");
                drm.provideProvisionResponse(response);
                drm.close();
            } catch (UnsupportedSchemeException e) {
                Log.e(TAG, "WV provisioning unsupported. Should not have been able to get here.", e);
                return;
            } catch (DeniedByServerException e) {
                Log.e(TAG, "WV server denied the provisioning request.", e);
                return;
            } catch (IOException e) {
                Log.e(TAG, "WV Provisioning failed.", e);
                return;
            } catch (Exception e) {
                Log.e(TAG, "Safety catch-all in case of an unexpected run time exception:", e);
                return;
            }
            Log.i(TAG, "Provisioning successful.");
        }

        private byte[] fetchWidevineCertificate(MediaDrm.ProvisionRequest req) throws IOException {
            final byte[] data = req.getData();
            final String normalUrl = req.getDefaultUrl();
            try {
                final String chinaUrl = normalUrl.replace(".com", ".cn");
                final String signedUrlChina = String.format(
                        "%s&signedRequest=%s",
                        chinaUrl,
                        new String(data));
                Log.i(TAG, "Provisioning with China URL " + chinaUrl);
                return sendNetworkRequest(signedUrlChina);
            } catch (SocketTimeoutException e) {
                Log.i(TAG, "Provisioning failed with China URL, retrying with normal URL.");
                final String signedUrl = String.format(
                        "%s&signedRequest=%s",
                        normalUrl,
                        new String(data));
                Log.i(TAG, "Provisioning with URL " + normalUrl);
                return sendNetworkRequest(signedUrl);
            }
        }

        private byte[] sendNetworkRequest(String url) throws IOException {
            HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
            con.setRequestMethod("POST");
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setConnectTimeout(TIMEOUT_MS);
            con.setReadTimeout(TIMEOUT_MS);
            con.setChunkedStreamingMode(0);
            for (Map.Entry<String, String> prop : REQ_PROPERTIES.entrySet()) {
                con.setRequestProperty(prop.getKey(), prop.getValue());
            }

            try (OutputStream os = con.getOutputStream()) {
                os.write(EMPTY_BODY);
            }
            if (con.getResponseCode() != 200) {
                Log.e(TAG, "Server request for WV certs failed. Error: " + con.getResponseCode());
                throw new IOException("Failed to request WV certs. Error: " + con.getResponseCode());
            }

            BufferedInputStream inputStream = new BufferedInputStream(con.getInputStream());
            ByteArrayOutputStream respBytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int read;
            while ((read = inputStream.read(buffer, 0, buffer.length)) != -1) {
                respBytes.write(buffer, 0, read);
            }
            byte[] respData = respBytes.toByteArray();
            if (respData.length == 0) {
                Log.e(TAG, "WV server returned an empty response.");
                throw new IOException("WV server returned an empty response.");
            }
            return respData;
        }
    }
}
