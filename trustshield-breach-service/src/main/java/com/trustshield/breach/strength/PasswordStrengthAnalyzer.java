package com.trustshield.breach.strength;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

/**
 * Structural password analysis, performed entirely locally.
 *
 * <h2>The claim this class is careful not to make</h2>
 *
 * <p>{@code theoreticalBits = length * log2(charsetSize)} is the standard
 * "password entropy" figure, and it is an <strong>upper bound that assumes the
 * password was generated uniformly at random from that alphabet</strong>. Human
 * passwords are not. {@code Password123!} scores about 79 bits by that formula
 * while being one of the first strings any real cracking dictionary tries.
 *
 * <p>Quoting the bits figure as though it measured resistance to attack is the
 * same category of error as claiming character-level Shannon entropy detects
 * algorithmically generated domains — see the note on
 * {@code UrlFeatureExtractor.shannonEntropy}. So this class reports the bits
 * figure explicitly labelled as an upper bound, and derives its actual
 * {@code weaknessScore} from detected structure instead: dictionary bases,
 * keyboard walks, repetition, dates, and leetspeak substitutions that dictionary
 * attacks already enumerate.
 *
 * <p>Nothing here is a substitute for the breach-corpus check. A password can be
 * structurally excellent and still be exposed because it leaked verbatim.
 */
@Component
public class PasswordStrengthAnalyzer {

    /** Assumed offline attack rate for the illustrative estimate: 10 billion guesses/sec. */
    private static final long ASSUMED_GUESSES_PER_SECOND = 10_000_000_000L;

    private static final Pattern DIGITS_ONLY = Pattern.compile("^\\d+$");
    private static final Pattern LETTERS_ONLY = Pattern.compile("^[A-Za-z]+$");
    private static final Pattern TRAILING_DIGITS = Pattern.compile("^(.*?)(\\d{1,4})([!@#$%^&*]?)$");
    private static final Pattern YEAR = Pattern.compile("(19[5-9]\\d|20[0-4]\\d)");

    /** Common keyboard rows and columns, used to spot walks in either direction. */
    private static final List<String> KEYBOARD_SEQUENCES = List.of(
            "qwertyuiop", "asdfghjkl", "zxcvbnm",
            "1234567890", "!@#$%^&*()",
            "1qaz", "2wsx", "3edc", "4rfv", "5tgb",
            "qazwsx", "qweasd", "zaqxsw"
    );

    /**
     * Very common base words. Deliberately short: this is a structural hint, not
     * a dictionary attack. The breach corpus check is what catches real reuse.
     */
    private static final Set<String> COMMON_BASES = Set.of(
            "password", "pass", "admin", "administrator", "root", "user", "guest",
            "login", "welcome", "secret", "letmein", "changeme", "default", "test",
            "qwerty", "iloveyou", "monkey", "dragon", "sunshine", "princess",
            "football", "baseball", "cricket", "superman", "batman", "master",
            "shadow", "freedom", "whatever", "trustno", "computer", "internet",
            "india", "bharat", "delhi", "mumbai", "chennai", "kolkata",
            "krishna", "ganesh", "namaste", "google", "facebook", "instagram"
    );

    /** Leetspeak reversals, applied before dictionary comparison. */
    private static final String[][] LEET = {
            {"@", "a"}, {"4", "a"}, {"8", "b"}, {"(", "c"}, {"3", "e"},
            {"6", "g"}, {"1", "i"}, {"!", "i"}, {"|", "i"}, {"0", "o"},
            {"$", "s"}, {"5", "s"}, {"7", "t"}, {"+", "t"}, {"2", "z"}
    };

    public StrengthAssessment analyze(String password) {
        if (password == null) {
            password = "";
        }

        boolean lower = password.chars().anyMatch(Character::isLowerCase);
        boolean upper = password.chars().anyMatch(Character::isUpperCase);
        boolean digit = password.chars().anyMatch(Character::isDigit);
        boolean symbol = password.chars().anyMatch(c -> !Character.isLetterOrDigit(c));

        int classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
        int charsetSize = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 32 : 0);

        double bits = (charsetSize <= 1 || password.isEmpty())
                ? 0.0
                : password.length() * (Math.log(charsetSize) / Math.log(2));

        List<StrengthAssessment.Weakness> weaknesses = findWeaknesses(password, classes);
        int score = weaknesses.stream()
                .mapToInt(StrengthAssessment.Weakness::penalty)
                .sum();

        return new StrengthAssessment(
                password.length(),
                classes,
                charsetSize,
                round2(bits),
                weaknesses,
                Math.min(100, score),
                ASSUMED_GUESSES_PER_SECOND,
                describeExhaustiveSearch(bits)
        );
    }

    private List<StrengthAssessment.Weakness> findWeaknesses(String password, int classes) {
        List<StrengthAssessment.Weakness> found = new ArrayList<>();
        String lower = password.toLowerCase(Locale.ROOT);

        if (password.isEmpty()) {
            found.add(new StrengthAssessment.Weakness(
                    "EMPTY", "No password provided.", 100));
            return found;
        }

        if (password.length() < 8) {
            found.add(new StrengthAssessment.Weakness("TOO_SHORT",
                    "Only " + password.length() + " characters. Under 8 is brute-forceable "
                            + "regardless of which characters are used.", 45));
        } else if (password.length() < 12) {
            found.add(new StrengthAssessment.Weakness("SHORT",
                    "Under 12 characters. Length contributes more to resistance than "
                            + "character variety does.", 20));
        }

        if (classes == 1) {
            found.add(new StrengthAssessment.Weakness("SINGLE_CHARACTER_CLASS",
                    "Uses only one kind of character, which shrinks the search space sharply.", 25));
        }

        if (DIGITS_ONLY.matcher(password).matches()) {
            found.add(new StrengthAssessment.Weakness("DIGITS_ONLY",
                    "All digits. A 10-digit numeric password has fewer combinations than "
                            + "a 6-character mixed one.", 30));
        }

        if (hasRepeatedRun(password, 3)) {
            found.add(new StrengthAssessment.Weakness("REPEATED_CHARACTERS",
                    "Contains a character repeated three or more times in a row.", 15));
        }

        if (hasSequentialRun(password, 4)) {
            found.add(new StrengthAssessment.Weakness("SEQUENTIAL_CHARACTERS",
                    "Contains a run of consecutive characters such as 1234 or abcd.", 20));
        }

        String walk = findKeyboardWalk(lower);
        if (walk != null) {
            found.add(new StrengthAssessment.Weakness("KEYBOARD_WALK",
                    "Contains the keyboard pattern \"" + walk + "\", which cracking tools "
                            + "enumerate before random strings.", 25));
        }

        String base = findCommonBase(lower);
        if (base != null) {
            found.add(new StrengthAssessment.Weakness("COMMON_BASE_WORD",
                    "Built on the common word \"" + base + "\". Dictionary attacks try these "
                            + "first, including with digits and symbols appended.", 35));
        }

        var trailing = TRAILING_DIGITS.matcher(password);
        if (trailing.matches() && !trailing.group(1).isEmpty()) {
            found.add(new StrengthAssessment.Weakness("WORD_PLUS_DIGITS",
                    "Follows the word-then-digits pattern. This is the single most common "
                            + "human password shape and is enumerated explicitly.", 20));
        }

        if (YEAR.matcher(password).find()) {
            found.add(new StrengthAssessment.Weakness("CONTAINS_YEAR",
                    "Contains what looks like a year. Years are a tiny search space "
                            + "and often guessable from public information.", 15));
        }

        if (!lower.equals(deLeet(lower)) && COMMON_BASES.contains(deLeet(lower).replaceAll("[^a-z]", ""))) {
            found.add(new StrengthAssessment.Weakness("LEETSPEAK_SUBSTITUTION",
                    "Character substitutions like @ for a and 0 for o are reversed "
                            + "automatically by cracking tools, so they add little.", 25));
        }

        if (found.isEmpty()) {
            found.add(new StrengthAssessment.Weakness("NONE",
                    "No structural weakness detected. This says nothing about whether the "
                            + "password has been exposed in a breach; that is a separate check.", 0));
        }
        return found;
    }

    private static boolean hasRepeatedRun(String s, int run) {
        int streak = 1;
        for (int i = 1; i < s.length(); i++) {
            streak = s.charAt(i) == s.charAt(i - 1) ? streak + 1 : 1;
            if (streak >= run) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasSequentialRun(String s, int run) {
        if (s.length() < run) {
            return false;
        }
        int ascending = 1;
        int descending = 1;
        for (int i = 1; i < s.length(); i++) {
            int delta = s.charAt(i) - s.charAt(i - 1);
            ascending = delta == 1 ? ascending + 1 : 1;
            descending = delta == -1 ? descending + 1 : 1;
            if (ascending >= run || descending >= run) {
                return true;
            }
        }
        return false;
    }

    private static String findKeyboardWalk(String lower) {
        for (String seq : KEYBOARD_SEQUENCES) {
            for (int len = Math.min(seq.length(), 4); len <= seq.length(); len++) {
                for (int start = 0; start + len <= seq.length(); start++) {
                    String fragment = seq.substring(start, start + len);
                    if (lower.contains(fragment)) {
                        return fragment;
                    }
                    String reversed = new StringBuilder(fragment).reverse().toString();
                    if (lower.contains(reversed)) {
                        return reversed;
                    }
                }
            }
        }
        return null;
    }

    private static String findCommonBase(String lower) {
        String letters = deLeet(lower).replaceAll("[^a-z]", "");
        for (String base : COMMON_BASES) {
            if (letters.contains(base)) {
                return base;
            }
        }
        return null;
    }

    private static String deLeet(String s) {
        String out = s;
        for (String[] pair : LEET) {
            out = out.replace(pair[0], pair[1]);
        }
        return out;
    }

    /**
     * Exhaustive-search time at {@link #ASSUMED_GUESSES_PER_SECOND}.
     *
     * <p>Stated as an upper bound on purpose. This is how long a uniformly random
     * password of the same shape would take; it is not a prediction for this
     * password, which structure may make far weaker.
     */
    private static String describeExhaustiveSearch(double bits) {
        if (bits <= 0) {
            return "instant";
        }
        // Expected work is half the keyspace: 2^(bits-1) guesses.
        double seconds = Math.pow(2, bits - 1) / ASSUMED_GUESSES_PER_SECOND;
        if (seconds < 1) {
            return "under a second";
        }
        if (seconds < 60) {
            return plural(Math.round(seconds), "second");
        }
        if (seconds < 3600) {
            return plural(Math.round(seconds / 60), "minute");
        }
        if (seconds < 86_400) {
            return plural(Math.round(seconds / 3600), "hour");
        }
        if (seconds < 31_557_600d) {
            return plural(Math.round(seconds / 86_400), "day");
        }
        double years = seconds / 31_557_600d;
        if (years < 1_000) {
            return plural(Math.round(years), "year");
        }
        if (years < 1e6) {
            return Math.round(years / 1_000) + " thousand years";
        }
        if (years < 1e9) {
            return Math.round(years / 1e6) + " million years";
        }
        return "longer than the age of the universe";
    }

    /**
     * Pluralises a unit.
     *
     * <p>Trivial, but the alternative was shipping "1 hours" onto a demo screen,
     * which was what the verification pass over this class actually produced.
     */
    private static String plural(long count, String unit) {
        return count + " " + unit + (count == 1 ? "" : "s");
    }

    private static double round2(double v) {
        return Math.round(v * 100.0) / 100.0;
    }
}
