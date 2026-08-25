-keep class app.ollo.** { *; }
-dontwarn org.signal.**
-keep class org.signal.** { *; }
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
