package rp.rkp;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.StrictMode;
import android.text.Editable;
import android.text.InputType;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.topjohnwu.superuser.NoShellException;
import com.topjohnwu.superuser.Shell;
import com.xuexiang.xui.adapter.simple.AdapterItem;
import com.xuexiang.xui.adapter.simple.XUISimpleAdapter;
import com.xuexiang.xui.utils.XToastUtils;
import com.xuexiang.xui.widget.button.CountDownButton;
import com.xuexiang.xui.widget.button.switchbutton.SwitchButton;
import com.xuexiang.xui.widget.dialog.DialogLoader;
import com.xuexiang.xui.widget.dialog.materialdialog.MaterialDialog;
import com.xuexiang.xui.widget.guidview.GuideCaseQueue;
import com.xuexiang.xui.widget.guidview.GuideCaseView;
import com.xuexiang.xui.widget.picker.XSeekBar;
import com.xuexiang.xui.widget.popupwindow.popup.XUISimplePopup;
import com.xuexiang.xui.widget.spinner.editspinner.EditSpinner;
import com.xuexiang.xui.widget.textview.LoggerTextView;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedList;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        ((TextView) findViewById(R.id.version)).setText(
                getString(R.string.version, BuildConfig.VERSION_NAME));

        final SharedPreferences sp = getSharedPreferences(BuildConfig.APPLICATION_ID, 0);
        final SwitchButton enable_rkpd = findViewById(R.id.enable_rkpd);
        final EditSpinner hostname = findViewById(R.id.hostname);
        final SwitchButton strongbox_rkp_only = findViewById(R.id.strongbox_rkp_only);
        final SwitchButton tee_rkp_only = findViewById(R.id.tee_rkp_only);
        final XSeekBar connect_timeout_millis = findViewById(R.id.connect_timeout_millis);
        enable_rkpd.setChecked(sp.getBoolean("enable", true));
        hostname.setText(sp.getString("hostname", Locale.getDefault().getLanguage().startsWith("zh") ?
                "remoteprovisioning.grapheneos.org" : "remoteprovisioning.googleapis.com"
        ));
        strongbox_rkp_only.setChecked(sp.getBoolean("strongbox", false));
        tee_rkp_only.setChecked(sp.getBoolean("tee", false));
        connect_timeout_millis.setDefaultValue(sp.getInt("timeout", 10));
        if (!getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            findViewById(R.id.strongbox_rkp_only_ll).setVisibility(View.GONE);
        }
        final AtomicReference<String> su = new AtomicReference<>(sp.getString("su", "su"));
        final LoggerTextView logger = findViewById(R.id.logger);
        logger.setLogFormatter(new LoggerTextView.DefaultLogFormatter() {
            private final FileOutputStream log = createLog();

            @Override
            public String format(String logContent, LoggerTextView.LogType logType) {
                String format = super.format(logContent, logType);
                if (log != null) {
                    try {
                        byte[] d = logContent.getBytes();
                        synchronized (log) {
                            log.write(d);
                            log.write('\n');
                        }
                    } catch (Exception ignored) {
                    }
                }
                return format;
            }
        });
        logger.setOnLongClickListener(view -> {
            CharSequence cs = logger.getText();
            if (cs == null) return false;
            getSystemService(ClipboardManager.class).setPrimaryClip(ClipData.newPlainText("rkp", cs));
            XToastUtils.success(getString(R.string.copy_to_clip));
            return false;
        });
        logger.logNormal('\n' + Build.FINGERPRINT);
        findViewById(R.id.load).setOnClickListener(view -> {
            ArrayList<String> output = new ArrayList<>();
            try (Shell shell = Shell.Builder.create().build(su.get())) {
                shell.newJob()
                        .add("getprop remote_provisioning.enable_rkpd")
                        .add("getprop remote_provisioning.hostname")
                        .add("getprop remote_provisioning.strongbox.rkp_only")
                        .add("getprop remote_provisioning.tee.rkp_only")
                        .add("getprop remote_provisioning.connect_timeout_millis")
                        .to(output)
                        .exec();
                logger.logNormal(Arrays.toString(output.toArray()));
                enable_rkpd.setChecked("true".equalsIgnoreCase(output.get(0)) || "1".equals(output.get(0)));
                hostname.setText(output.get(1));
                strongbox_rkp_only.setChecked("true".equalsIgnoreCase(output.get(2)) || "1".equals(output.get(2)));
                tee_rkp_only.setChecked("true".equalsIgnoreCase(output.get(3)) || "1".equals(output.get(3)));
                connect_timeout_millis.setDefaultValue(output.get(4).isEmpty() ? 0 : Integer.parseInt(output.get(4)) / 1000);
                boolean enable = enable_rkpd.isChecked();
                String host = hostname.getText().trim();
                boolean strongbox = strongbox_rkp_only.isChecked();
                boolean tee = tee_rkp_only.isChecked();
                int timeout = connect_timeout_millis.getSelectedNumber();
                sp.edit()
                        .putBoolean("enable", enable)
                        .putString("hostname", host)
                        .putBoolean("strongbox", strongbox)
                        .putBoolean("tee", tee)
                        .putInt("timeout", timeout)
                        .apply();
                logger.logSuccess(getString(R.string.tips_succeed, getViewText(view), ""));
            } catch (NoShellException e) {
                logger.logNormal(android.util.Log.getStackTraceString(e));
                logger.logError(getString(R.string.tips_su_failed, getViewText(view)));
            } catch (Exception e) {
                logger.logNormal(android.util.Log.getStackTraceString(e));
                logger.logError(getString(R.string.tips_failed, getViewText(view)));
            }
        });
        findViewById(R.id.apply).setOnClickListener(view -> {
            boolean enable = enable_rkpd.isChecked();
            String host = hostname.getText().trim();
            boolean strongbox = strongbox_rkp_only.isChecked();
            boolean tee = tee_rkp_only.isChecked();
            int timeout = connect_timeout_millis.getSelectedNumber();
            sp.edit()
                    .putBoolean("enable", enable)
                    .putString("hostname", host)
                    .putBoolean("strongbox", strongbox)
                    .putBoolean("tee", tee)
                    .putInt("timeout", timeout)
                    .apply();
            logger.logNormal(Arrays.toString(new Object[]{enable, host, strongbox, tee, timeout * 1000}));
            try (Shell shell = Shell.Builder.create().build(su.get())) {
                shell.newJob()
                        .add("setprop remote_provisioning.enable_rkpd " + enable)
                        .add("setprop remote_provisioning.hostname " + host)
                        .add("setprop remote_provisioning.strongbox.rkp_only " + (strongbox ? "true" : "''"))
                        .add("setprop remote_provisioning.tee.rkp_only " + (tee ? "true" : "''"))
                        .add("setprop remote_provisioning.connect_timeout_millis " + (timeout > 0 ? timeout * 1000 : "''"))
                        .exec();
                logger.logSuccess(getString(R.string.tips_succeed, getViewText(view), getString(R.string.apply_reboot_tips)));
            } catch (NoShellException e) {
                logger.logNormal(android.util.Log.getStackTraceString(e));
                logger.logError(getString(R.string.tips_su_failed, getViewText(view)));
            } catch (Exception e) {
                logger.logNormal(android.util.Log.getStackTraceString(e));
                logger.logError(getString(R.string.tips_failed, getViewText(view)));
            }
        });
        findViewById(R.id.apply).setOnLongClickListener(v -> {
            new MaterialDialog.Builder(v.getContext())
                    .title("SU PATH")
                    .content("Full path of the su executable")
                    .inputType(InputType.TYPE_CLASS_TEXT)
                    .input("/system/bin/su", su.get(), false, (dialog, input) -> {
                    })
                    .inputRange(2, 256)
                    .positiveText(R.string.clear_confirm)
                    .negativeText(R.string.clear_cancel)
                    .onPositive((dialog, which) -> {
                        EditText editText = dialog.getInputEditText();
                        if (editText == null) {
                            return;
                        }
                        Editable editable = editText.getText();
                        // noinspection SizeReplaceableByIsEmpty
                        if (editable == null || editable.length() == 0) {
                            return;
                        }
                        su.set(editable.toString());
                        sp.edit().putString("su", su.get()).apply();
                    })
                    .cancelable(false)
                    .show();
            return true;
        });
        findViewById(R.id.cls).setOnClickListener(view -> logger.clearLog());
        if (hasOPlusEngineerMode()) {
            findViewById(R.id.engineer).setOnClickListener(view -> {
                try (Shell shell = Shell.Builder.create().build(su.get())) {
                    shell.newJob()
                            .add("cmd activity start -n com.oplus.engineermode/.security.RPMBStatusActivity")
                            .exec();
                    logger.logSuccess(getString(R.string.tips_succeed, getViewText(view), ""));
                } catch (NoShellException e) {
                    logger.logNormal(android.util.Log.getStackTraceString(e));
                    logger.logError(getString(R.string.tips_su_failed, getViewText(view)));
                } catch (Exception e) {
                    logger.logNormal(android.util.Log.getStackTraceString(e));
                    logger.logError(getString(R.string.tips_failed, getViewText(view)));
                }
            });
        } else {
            findViewById(R.id.engineer).setVisibility(View.GONE);
        }
        findViewById(R.id.clear).setOnClickListener(view -> {
            DialogLoader.getInstance().showConfirmDialog(
                    view.getContext(),
                    getString(R.string.clear_title),
                    getString(R.string.clear_tips),
                    getString(R.string.clear_confirm),
                    (dialog, which) -> {
                        dialog.dismiss();
                        new Thread(() -> {
                            try (Shell shell = Shell.Builder.create().build(su.get())) {
                                shell.newJob()
                                        .add("cmd package clear com.android.rkpdapp")
                                        .add("cmd package clear com.google.android.rkpdapp")
                                        .add("cmd package clear io.github.vvb2060.keyattestation")
                                        .exec();
                                logger.logSuccess(getString(R.string.tips_succeed, getString(R.string.clear), ""));
                            } catch (NoShellException e) {
                                logger.logNormal(android.util.Log.getStackTraceString(e));
                                logger.logError(getString(R.string.tips_su_failed, getString(R.string.clear)));
                            } catch (Exception e) {
                                logger.logNormal(android.util.Log.getStackTraceString(e));
                                logger.logError(getString(R.string.tips_failed, getString(R.string.clear)));
                            }
                            cancelCountDown(view);
                        }).start();
                    },
                    getString(R.string.clear_cancel),
                    (dialog, which) -> {
                        logger.logWarning(getString(R.string.clear_cancel));
                        dialog.dismiss();
                        cancelCountDown(view);
                    }
            );
        });
        findViewById(R.id.renew).setOnClickListener(view -> {
            new Thread(() -> {
                ArrayList<String> output = new ArrayList<>();
                ArrayList<String> error = new ArrayList<>();
                try (Shell shell = Shell.Builder.create().build(su.get())) {
                    shell.newJob()
                            .add(buildExecShell(""))
                            .to(output, error)
                            .exec();
                    String status = "";
                    for (String s : output) {
                        if (s.contains("Total provisioned keys")) {
                            status = getString(R.string.csr_ok);
                            logger.logSuccess(s);
                        } else if (s.contains("Sufficient keys are available")) {
                            status = getString(R.string.no_csr_need);
                            logger.logWarning(s);
                        } else {
                            logger.logNormal(s);
                        }
                    }
                    if (error.isEmpty()) {
                        logger.logSuccess(getString(R.string.tips_succeed, getString(R.string.renew), status));
                    } else {
                        int limit = 18;
                        for (String s : error) {
                            logger.logError(s);
                            if (--limit <= 0) break;
                        }
                        logger.logError(getString(R.string.tips_failed, getString(R.string.renew)));
                    }
                } catch (NoShellException e) {
                    logger.logNormal(android.util.Log.getStackTraceString(e));
                    logger.logError(getString(R.string.tips_su_failed, getString(R.string.renew)));
                } catch (Exception e) {
                    logger.logNormal(android.util.Log.getStackTraceString(e));
                    logger.logError(getString(R.string.tips_failed, getString(R.string.renew)));
                }
                cancelCountDown(view);
            }).start();
        });
        findViewById(R.id.dump).setOnClickListener(view -> {
            new Thread(() -> {
                ArrayList<String> output = new ArrayList<>();
                ArrayList<String> error = new ArrayList<>();
                try (Shell shell = Shell.Builder.create().build(su.get())) {
                    shell.newJob()
                            .add("cmd remote_provisioning dump")
                            .add(buildExecShell("dump"))
                            .to(output, error)
                            .exec();
                    for (String s : output) {
                        logger.logNormal(s);
                    }
                    if (error.isEmpty()) {
                        logger.logSuccess(getString(R.string.tips_succeed, getString(R.string.dump), ""));
                    } else {
                        int limit = 18;
                        for (String s : error) {
                            logger.logError(s);
                            if (--limit <= 0) break;
                        }
                        logger.logError(getString(R.string.tips_failed, getString(R.string.dump)));
                    }
                } catch (NoShellException e) {
                    logger.logNormal(android.util.Log.getStackTraceString(e));
                    logger.logError(getString(R.string.tips_su_failed, getString(R.string.dump)));
                } catch (Exception e) {
                    logger.logNormal(android.util.Log.getStackTraceString(e));
                    logger.logError(getString(R.string.tips_failed, getString(R.string.dump)));
                }
                cancelCountDown(view);
            }).start();
        });
        findViewById(R.id.csr).setOnClickListener(view -> {
            final Popup.PopupCallback callback = type -> {
                ArrayList<String> output = new ArrayList<>();
                ArrayList<String> error = new ArrayList<>();
                try (Shell shell = Shell.Builder.create().build(su.get())) {
                    shell.newJob()
                            .add("cmd remote_provisioning csr --challenge 00000000000000000000000000000000 " + type)
                            .to(output, error)
                            .exec();
                    StringBuilder sb = new StringBuilder(1024);
                    for (String s : output) {
                        logger.logNormal(s);
                        sb.append(s.trim());
                    }
                    if (error.isEmpty()) {
                        logger.logSuccess(getString(R.string.tips_succeed, getString(R.string.csr), ""));
                    } else {
                        int limit = 18;
                        for (String s : error) {
                            logger.logError(s);
                            if (--limit <= 0) break;
                        }
                        logger.logError(getString(R.string.tips_failed, getString(R.string.csr)));
                    }
                    try {
                        ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getDecoder().decode(sb.toString()));
                        CborDecoder decoder = new CborDecoder(bais);
                        DataItem item;
                        // while ((item = decoder.decodeNext()) != null) {
                        if ((item = decoder.decodeNext()) != null) {
                            logger.logSuccess(item.toString());
                        }
                    } catch (Exception ignored) {
                    }
                } catch (NoShellException e) {
                    logger.logNormal(android.util.Log.getStackTraceString(e));
                    logger.logError(getString(R.string.tips_su_failed, getString(R.string.csr)));
                } catch (Exception e) {
                    logger.logNormal(android.util.Log.getStackTraceString(e));
                    logger.logError(getString(R.string.tips_failed, getString(R.string.csr)));
                }
                cancelCountDown(view);
            };
            new Popup(view, callback).show();
        });
        findViewById(R.id.certify).setOnClickListener(view -> {
            final Popup.PopupCallback callback = type -> {
                ArrayList<String> output = new ArrayList<>();
                ArrayList<String> error = new ArrayList<>();
                try (Shell shell = Shell.Builder.create().build(su.get())) {
                    shell.newJob()
                            .add("cmd remote_provisioning certify " + type)
                            .to(output, error)
                            .exec();
                    StringBuilder sb = new StringBuilder(1024);
                    for (String s : output) {
                        logger.logNormal(s);
                        sb.append(s.trim());
                    }
                    if (error.isEmpty()) {
                        logger.logSuccess(getString(R.string.tips_succeed, getString(R.string.certify), ""));
                    } else {
                        int limit = 18;
                        for (String s : error) {
                            logger.logError(s);
                            if (--limit <= 0) break;
                        }
                        logger.logError(getString(R.string.tips_failed, getString(R.string.certify)));
                    }
                    try {
                        String s = sb.toString();
                        String bp = "-----BEGIN CERTIFICATE-----";
                        String ep = "-----END CERTIFICATE-----";
                        int ib = 0, ie;
                        Base64.Decoder decoder = Base64.getDecoder();
                        CertificateFactory factory = CertificateFactory.getInstance("X.509");
                        LinkedList<X509Certificate> x509Certificates = new LinkedList<>();
                        while ((ib = s.indexOf(bp, ib)) >= 0 &&
                                (ie = s.indexOf(ep, ib += bp.length())) > 0) {
                            X509Certificate cert = (X509Certificate) factory.generateCertificate(
                                    new ByteArrayInputStream(decoder.decode(s.substring(ib, ie))));
                            x509Certificates.addFirst(cert);
                            ib = ie + ep.length();
                        }
                        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA);
                        for (X509Certificate cert : x509Certificates) {
                            logger.logSuccess("Certificate:");
                            logger.logSuccess("---- Subject=" + cert.getSubjectX500Principal());
                            logger.logSuccess("---- Issuer=" + cert.getIssuerX500Principal());
                            logger.logSuccess("---- NotBefore=" + format.format(cert.getNotBefore()));
                            logger.logSuccess("---- NotAfter=" + format.format(cert.getNotAfter()));
                        }
                    } catch (Exception ignored) {
                    }
                } catch (NoShellException e) {
                    logger.logNormal(android.util.Log.getStackTraceString(e));
                    logger.logError(getString(R.string.tips_su_failed, getString(R.string.certify)));
                } catch (Exception e) {
                    logger.logNormal(android.util.Log.getStackTraceString(e));
                    logger.logError(getString(R.string.tips_failed, getString(R.string.certify)));
                }
                cancelCountDown(view);
            };
            new Popup(view, callback).show();
        });
        checkSignatures();
        showTextGuide();
    }

    @Override
    protected void onRestoreInstanceState(@NonNull Bundle savedInstanceState) {
    }

    private void cancelCountDown(View view) {
        runOnUiThread(() -> {
            if (!isFinishing() && !isDestroyed()) {
                ((CountDownButton) view).cancelCountDown();
            }
        });
    }

    private String buildExecShell(String cmd) throws Exception {
        File exe = new File(getApplicationInfo().nativeLibraryDir, "librkp.so");
        File apk = new File(getCacheDir(), "rkpdapp.apk");
        try (InputStream inputStream = getAssets().open("rkpdapp.apk")) {
            if (apk.length() != inputStream.available()) {
                try (FileOutputStream outputStream = new FileOutputStream(apk, false)) {
                    inputStream.transferTo(outputStream);
                }
            }
        }
        return exe + " /system/bin/app_process -Djava.class.path='" + getApplicationInfo().publicSourceDir + "' / --nice-name=com.android.rkpdapp rp.rkp.rkpd '" + apk + "' " + cmd;
    }

    private void checkSignatures() {
        boolean matched = false;
        try {
            final PackageInfo info = getPackageManager().getPackageInfo(BuildConfig.APPLICATION_ID, PackageManager.GET_SIGNING_CERTIFICATES);
            final Signature[] signatures;
            final SigningInfo signingInfo = info.signingInfo;
            if (signingInfo == null) {
                signatures = null;
            } else if (signingInfo.hasMultipleSigners()) {
                signatures = signingInfo.getApkContentsSigners();
            } else {
                signatures = signingInfo.getSigningCertificateHistory();
            }
            if (signatures != null) {
                for (final Signature sign : signatures) {
                    if (ByteString.bytesToHex(sign.toByteArray()).equals("308202923082017a020101300d06092a864886f70d01010b0500300e310c300a060355040a0c03726b703020170d3235313132313037313233305a180f32303530313131353037313233305a300e310c300a060355040a0c03726b7030820122300d06092a864886f70d01010105000382010f003082010a0282010100a2fafcc729158007380e016b662cc93819d0761b21ad105ebbdb04c8f55f7b07e4473dff7af29d161ee81831658dfc5619894765cacaaae9bf6a6091d090da82d19fd3c6df124327c43d6c37ceaf5339d5cde12ffdf9c6ba8ef71c7fb47303296209f31d287654b40148e5281e2789e59faadbef8a07c1453dc9e67b24cc08ffcc3c41f9b9008e7128829737bccf089ce0f3477189889da968791a97552d8f407a5c1c05c5b5f6867c8a43917fee9b89366d03a1375e5c1aa330635b1401fbf1f28bb366036d6a3d1b01cfe027d2980dcf3cf3fb413425510fe3e08c0a6bb300ef630e3f62283b2d7e7c0031059994379422be5b909a12bde5fed1e42cd4066b0203010001300d06092a864886f70d01010b0500038201010025ef4a4a9cdb2d82e6b953a9c383bbba6d07d1f23fc66d330c30c7ce00ff1a16f8ac68553219cb2bdb4a3024ec35ac5682bae59d28f03b3b38130933b871175766fc1e1d79d34bf6ff9c78bb63856892aeb7cf3168df9528d2cb83baf2ec899bad2c8cfa5f0aaf9549890f20bf2a5ec2274db8e0fc44f24f915e58c046861e2d7782840f9cb83b0a0c376522bf6981f6a4ecd6eec6f307c46d4ddb009fbd642b3d587e351f37ca0bc79105a5d0da8c5cc2eb7d7ee83be768064bb490e0b70e9fda28caa279477626e3ef38b872ddb7fd2e559b476828d747e1a5250cd7f3cee491e39e86a3b7b6a150f671b9fb980867975351180b4c45f48354fc3bf415cf46")) {
                        matched = true;
                        break;
                    }
                }
            }
        } catch (final Exception ignored) {
        }
        if (!matched) {
            System.exit(0);
        }
    }

    private void showTextGuide() {
        if (GuideCaseView.isShowOnce(this, "rkp")) {
            return;
        }
        new GuideCaseQueue()
                .add(buildGuideCase(R.id.load, R.string.guide_tips_load))
                .add(buildGuideCase(R.id.apply, R.string.guide_tips_apply))
                .add(buildGuideCase(R.id.cls, R.string.guide_tips_cls))
                .add(buildGuideCase(R.id.clear, R.string.guide_tips_clear))
                .add(buildGuideCase(R.id.renew, R.string.guide_tips_renew))
                .add(buildGuideCase(R.id.dump, R.string.guide_tips_dump))
                .add(buildGuideCase(R.id.csr, R.string.guide_tips_csr))
                .add(buildGuideCase(R.id.certify, R.string.guide_tips_certify))
                .setCompleteListener(() -> {
                    GuideCaseView.setShowOnce(MainActivity.this, "rkp");
                    showWarning();
                })
                .show();
    }

    private void showWarning() {
        DialogLoader.getInstance().showTipDialog(this,
                getString(R.string.critical_warning),
                getString(R.string.critical_warning_tips),
                getString(R.string.critical_warning_confirm));
    }

    private CharSequence getViewText(View view) {
        if (view instanceof TextView tv) {
            return tv.getText();
        }
        return "";
    }

    private GuideCaseView buildGuideCase(int id, int action) {
        View view = findViewById(id);
        return new GuideCaseView.Builder(this)
                .title(getString(R.string.guide_tips, getViewText(view), getString(action)))
                .focusOn(view)
                .fitWindowsAuto()
                .titleStyle(com.xuexiang.xui.R.style.TextStyle_Title, -1)
                .build();
    }

    private boolean hasOPlusEngineerMode() {
        boolean hasOPlusEngineerMode = false;
        try {
            hasOPlusEngineerMode = switch (getPackageManager().getApplicationEnabledSetting("com.oplus.engineermode")) {
                case PackageManager.COMPONENT_ENABLED_STATE_DEFAULT,
                     PackageManager.COMPONENT_ENABLED_STATE_ENABLED -> true;
                case PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                     PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER,
                     PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED -> false;
                default -> false;
            };
        } catch (Exception ignored) {
        }
        return hasOPlusEngineerMode;
    }

    private FileOutputStream createLog() {
        StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder().build());
        StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().build());
        File log = new File(getExternalCacheDir(), "d.log");
        try {
            return new FileOutputStream(log, log.length() < 4 * 1024 * 1024);
        } catch (Exception ignored) {
        }
        return null;
    }

    private static final class Popup extends XUISimplePopup<Popup>
            implements XUISimplePopup.OnPopupItemClickListener, Runnable {
        private final View view;
        private final PopupCallback callback;
        private String type;

        public interface PopupCallback {
            void run(String type);
        }

        public Popup(final View view, final PopupCallback callback) {
            super(view.getContext(), new String[]{
                    "TEE",
                    "STRONGBOX",
                    "AVF",
            });
            this.view = view;
            this.callback = callback;
            create(0, this);
            setHasDivider(true);
        }

        public void show() {
            showDown(this.view);
        }

        @Override
        protected void onDismiss() {
            if (this.type == null) {
                ((CountDownButton) this.view).cancelCountDown();
            }
        }

        @Override
        public void onItemClick(XUISimpleAdapter adapter, AdapterItem item, int position) {
            switch (position) {
                case 0:
                    this.type = "default";
                    break;
                case 1:
                    this.type = "strongbox";
                    break;
                case 2:
                    this.type = "avf";
                    break;
                default:
                    return;
            }
            new Thread(this).start();
        }

        @Override
        public void run() {
            this.callback.run(this.type);
        }
    }
}