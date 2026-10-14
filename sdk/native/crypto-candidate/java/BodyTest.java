// SPDX-License-Identifier: AGPL-3.0-only
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.zrotext.candidate.CandidateBody;

public final class BodyTest {
    public static void main(String[] args) throws Exception {
        int count = 0;
        var hex = HexFormat.of();
        for (String line : Files.readAllLines(Path.of(args[0]))) {
            String[] row = line.split("\t", -1);
            String actual = "accept";
            try {
                String result = row[1].equals("text") ? CandidateBody.decode(hex.parseHex(row[5]))
                    : CandidateBody.open(hex.parseHex(row[2]), hex.parseHex(row[3]), hex.parseHex(row[4]), hex.parseHex(row[5]));
                if (!hex.formatHex(result.getBytes(StandardCharsets.UTF_8)).equals(row[7]))
                    throw new AssertionError(row[0] + ": plaintext mismatch");
            } catch (CandidateBody.BodyException error) { actual = error.reason; }
            if (!actual.equals(row[6])) throw new AssertionError(row[0] + ": " + actual + " expected " + row[6]);
            count++;
        }
        if (count < 47) throw new AssertionError("Incomplete candidate body corpus");
        System.out.println("Java candidate body: " + count + " cases passed");
    }
}
