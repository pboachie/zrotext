// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using Zrotext.Candidate;
int count = 0;
string? line;
while ((line = Console.ReadLine()) is not null)
{
    string[] row = line.Split('\t');
    string actual = "accept";
    try
    {
        string result = row[1] == "text" ? CandidateBody.Decode(Convert.FromHexString(row[5])) :
            CandidateBody.Open(Convert.FromHexString(row[2]), Convert.FromHexString(row[3]), Convert.FromHexString(row[4]), Convert.FromHexString(row[5]));
        if (Convert.ToHexString(Encoding.UTF8.GetBytes(result)).ToLowerInvariant() != row[7]) throw new Exception(row[0] + ": plaintext mismatch");
    }
    catch (BodyException error) { actual = error.Reason; }
    if (actual != row[6]) throw new Exception(row[0] + ": " + actual + " expected " + row[6]);
    count++;
}
if (count < 47) throw new Exception("Incomplete candidate body corpus");
Console.WriteLine($"C# candidate body: {count} cases passed");
