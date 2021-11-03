package utils;


import org.apache.commons.codec.binary.Hex;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CommonFunctions {

    // Group 1: key
    // Group 2: value
    private static final Pattern pattern_key_value = Pattern.compile("(\\w+)=\"*((?<=\")[^\"]+(?=\")|([^\\s]+))\"*");

    /**
     * Converts a string of the format [a="b" c=d e=f] into a map of key values
     * Any portions of the string not matching the pattern [a="b"] or [c=d] are ignored
     * <p>
     * Uses the pattern {@link #pattern_key_value pattern_key_value}
     *
     * @param messageData string to parse
     * @return a hashmap
     */
    public static Map<String, String> parseKeyValPairs(String messageData) {
        /*
         * Takes a string with keyvalue pairs and returns a Map Input e.g.
         * "key1=val1 key2=val2" etc. Input string validation is callee's
         * responsibility
         */
        Map<String, String> keyValPairs = new HashMap<String, String>();
        if (messageData == null || messageData.trim().isEmpty()) {
            return keyValPairs;
        }
        Matcher key_value_matcher = pattern_key_value.matcher(messageData);
        while (key_value_matcher.find()) {
            keyValPairs.put(key_value_matcher.group(1).trim(), key_value_matcher.group(2).trim());
        }
        return keyValPairs;
    }

    /**
     * Convenience wrapper function for Integer.parseInt. Suppresses the exception and returns
     * the given default value in that case
     *
     * @param string       string to parse
     * @param defaultValue value to return in case of exception
     * @return integer representation of the string
     */
    public static Integer parseInt(String string, Integer defaultValue) {
        try {
            return Integer.parseInt(string);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    /**
     * Convenience wrapper function for Long.parseLong. Suppresses the exception and returns
     * the given default value in that case
     *
     * @param str          string to parse
     * @param defaultValue value to return in case of exception
     * @return long representation of the string
     */
    public static Long parseLong(String str, Long defaultValue) {
        try {
            return Long.parseLong(str);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    /**
     * Convenience wrapper function for Double.parseDouble. Suppresses the exception and returns
     * the given default value in that case
     *
     * @param str          string to parse
     * @param defaultValue value to return in case of exception
     * @return double representation of the string
     */
    public static Double parseDouble(String str, Double defaultValue) {
        try {
            return Double.parseDouble(str);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    /**
     * Convenience function to get a map with keys converted to lowercase.
     * <p>
     * Responsibility of the caller to make sure that different keys don't
     * become the same after converted to lowercase.
     * <p>
     * Throws NPE if the map is the null
     *
     * @param map map to convert
     * @return a hashmap
     */
    public static <T> Map<String, T> makeKeysLowerCase(Map<String, T> map) {
        Map<String, T> resultMap = new HashMap<String, T>();
        for (Map.Entry<String, T> entry : map.entrySet()) {
            resultMap.put(entry.getKey().toLowerCase(), entry.getValue());
        }
        return resultMap;
    }

    /**
     * Convenience function to check if a string is null or is empty
     * <p>
     * The str argument is trimmed before the empty check
     *
     * @param str string to check
     * @return true if null or empty, otherwise false
     */
    public static boolean isNullOrEmpty(String str) {
        if (str == null) {
            return true;
        } else {
            return str.trim().isEmpty();
        }
    }

    /**
     * Decodes the hex string. Null if failed.
     *
     * @param hexString string in hex format
     * @return converted ascii string
     */
    public static String decodeHex(String hexString) {
        if (hexString == null) {
            return null;
        } else {
            try {
                return new String(Hex.decodeHex(hexString.toCharArray()));
            } catch (Exception e) {
                // ignore
                return null;
            }
        }
    }

    /**
     * Create hex string from ascii
     *
     * @param string
     * @return converted hex string
     */
    public static String encodeHex(String string) {
        return Hex.encodeHexString(String.valueOf(string).getBytes());
    }

}

