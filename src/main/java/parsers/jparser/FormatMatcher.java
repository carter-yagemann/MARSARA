package parsers.jparser;

public interface FormatMatcher {
    /**
     * Check if the fmt specifier matches with the input line in
     *
     * @param fmt: The format specifier from the graph
     * @param in:  The input string to match with
     * @return number of constants in the match if any, 0 otherwise
     */
    int IsMatch(String fmt, String in);
}
