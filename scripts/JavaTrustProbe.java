// SPDX-License-Identifier: AGPL-3.0-only
// Closed local protocol for CI trust-copy preparation and read-only verification.
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

class JavaTrustProbe {
    private static String digest(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static String encoded(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static KeyStore read(Path path, char[] password) throws Exception {
        return KeyStore.getInstance(path.toFile(), password);
    }

    private static Map<String, String> inventory(KeyStore store) throws Exception {
        Map<String, String> result = new TreeMap<>();
        for (String alias : Collections.list(store.aliases())) {
            if (!store.isCertificateEntry(alias)) {
                throw new IllegalArgumentException("Only trusted certificate entries are qualified");
            }
            result.put(alias, digest(store.getCertificate(alias).getEncoded()));
        }
        if (result.isEmpty()) {
            throw new IllegalArgumentException("An empty trust store is not qualified");
        }
        return result;
    }

    private static Map<String, String> attributes(KeyStore store, String alias) throws Exception {
        KeyStore.Entry entry = store.getEntry(alias, null);
        if (!(entry instanceof KeyStore.TrustedCertificateEntry)) {
            throw new IllegalArgumentException("Only trusted certificate entries are qualified");
        }
        Map<String, String> result = new TreeMap<>();
        for (KeyStore.Entry.Attribute attribute : entry.getAttributes()) {
            if (result.put(attribute.getName(), attribute.getValue()) != null) {
                throw new IllegalArgumentException("Duplicate entry attribute");
            }
        }
        return result;
    }

    private static void describe(Path path, char[] password) throws Exception {
        KeyStore store = read(path, password);
        System.out.println("TYPE\t" + store.getType());
        for (Map.Entry<String, String> entry : inventory(store).entrySet()) {
            System.out.println("CERT\t" + encoded(entry.getKey()) + "\t" + entry.getValue());
            for (var attribute : attributes(store, entry.getKey()).entrySet()) {
                System.out.println("ATTRIBUTE\t" + encoded(entry.getKey()) + "\t"
                    + encoded(attribute.getKey()) + "\t" + encoded(attribute.getValue()));
            }
        }
    }

    private static void filter(Path source, Path destination, String policy, char[] password) throws Exception {
        Set<String> blocked = new TreeSet<>();
        for (String value : policy.split(",")) {
            if (!value.matches("[0-9a-f]{64}") || !blocked.add(value)) {
                throw new IllegalArgumentException("Invalid root fingerprint policy");
            }
        }
        if (blocked.size() != 4 || source.toAbsolutePath().normalize().equals(destination.toAbsolutePath().normalize())) {
            throw new IllegalArgumentException("A separate destination and four roots are required");
        }
        String originalDigest = digest(Files.readAllBytes(source));
        KeyStore original = read(source, password);
        // A vendor may ship passwordless PKCS12 cacerts. A fresh destination
        // avoids inheriting that source's disabled integrity-MAC setting.
        KeyStore copy = KeyStore.getInstance(original.getType());
        copy.load(null, password);
        Map<String, String> expected = new TreeMap<>(inventory(original));
        for (String alias : new TreeSet<>(expected.keySet())) {
            if (blocked.contains(expected.get(alias))) {
                expected.remove(alias);
            } else {
                copy.setEntry(alias, original.getEntry(alias, null), null);
            }
        }
        if (expected.isEmpty()) {
            throw new IllegalArgumentException("Filtering must retain other trusted certificates");
        }
        try (var output = Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            copy.store(output, password);
        }
        KeyStore reloaded = read(destination, password);
        if (!inventory(reloaded).equals(expected)) {
            throw new IllegalStateException("A non-target alias or certificate changed");
        }
        for (String alias : expected.keySet()) {
            if (!attributes(original, alias).equals(attributes(reloaded, alias))) {
                throw new IllegalStateException("A non-target entry attribute changed");
            }
        }
        boolean integrityEnforced = false;
        try {
            read(destination, new char[0]);
        } catch (IOException | GeneralSecurityException expectedFailure) {
            integrityEnforced = true;
        }
        if (!integrityEnforced) {
            throw new IllegalStateException("The destination did not enforce password integrity");
        }
        if (!digest(Files.readAllBytes(source)).equals(originalDigest)) {
            throw new IllegalStateException("The original trust store changed");
        }
        describe(destination, password);
    }

    private static void effective() throws Exception {
        String selected = System.getProperty("javax.net.ssl.trustStore");
        if (selected == null || selected.isEmpty()) {
            throw new IllegalArgumentException("An explicit job-local trust store is required");
        }
        System.out.println("SELECTED\t" + encoded(selected));
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        Set<String> roots = new TreeSet<>();
        for (var manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509) {
                for (X509Certificate certificate : x509.getAcceptedIssuers()) {
                    roots.add(digest(certificate.getEncoded()));
                }
            }
        }
        if (roots.isEmpty()) {
            throw new IllegalStateException("The effective JSSE TrustManager has no trusted issuers");
        }
        for (String root : roots) {
            System.out.println("ROOT\t" + root);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 3 && args[0].equals("inventory")) {
            describe(Path.of(args[2]), args[1].toCharArray());
        } else if (args.length == 5 && args[0].equals("filter")) {
            filter(Path.of(args[2]), Path.of(args[3]), args[4], args[1].toCharArray());
        } else if (args.length == 1 && args[0].equals("effective")) {
            effective();
        } else {
            throw new IllegalArgumentException("Unknown trust probe operation");
        }
    }
}
