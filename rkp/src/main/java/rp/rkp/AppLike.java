package rp.rkp;

import android.app.Application;

public class AppLike extends Application {

    @Override
    public void onCreate() {
        super.onCreate();

        org.lsposed.hiddenapibypass.HiddenApiBypass.addHiddenApiExemptions("");
    }
}
