// Legacy batch job — deliberately vulnerable, for demo purposes.

public class BatchJob {
    private String password = "batchAdmin2024!";

    public void runCleanup(String target) throws Exception {
        Runtime.getRuntime().exec("rm -rf " + target);
    }

    public String fingerprint(String input) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        return new String(md.digest(input.getBytes()));
    }
}
