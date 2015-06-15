/*******************************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *******************************************************************************/
package com.yuaoq.ofbiz.base.util;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Misc String Utility Functions
 *
 */
public class StringUtil {

    public static final StringUtil INSTANCE = new StringUtil();
    private static final Logger Debug = LoggerFactory.getLogger(StringUtil.class);

    public static final String module = StringUtil.class.getName();


    /** OWASP ESAPI canonicalize strict flag; setting false so we only get warnings about double encoding, etc; can be set to true for exceptions and more security */
    public static final boolean esapiCanonicalizeStrict = false;


    public static final SimpleEncoder stringEncoder = new StringEncoder();

    private StringUtil() {
    }

    public static interface SimpleEncoder {
        public String encode(String original);
    }



    public static class StringEncoder implements SimpleEncoder {
        public String encode(String original) {
            if (original != null) {
                original = original.replace("\"", "\\\"");
            }
            return original;
        }
    }



    public static String internString(String value) {
        return value != null ? value.intern() : null;
    }



    /**
     * Creates a single string from a List of strings seperated by a delimiter.
     * @param list a list of strings to join
     * @param delim the delimiter character(s) to use. (null value will join with no delimiter)
     * @return a String of all values in the list seperated by the delimiter
     */
    public static String join(List<?> list, String delim) {
        if (list == null || list.size() < 1)
            return null;
        StringBuilder buf = new StringBuilder();
        Iterator<?> i = list.iterator();

        while (i.hasNext()) {
            buf.append(i.next());
            if (i.hasNext())
                buf.append(delim);
        }
        return buf.toString();
    }



    /**
     * Creates an encoded String from a Map of name/value pairs (MUST BE STRINGS!)
     * @param map The Map of name/value pairs
     * @return String The encoded String
     */
    public static String mapToStr(Map<? extends Object, ? extends Object> map) {
        if (map == null) return null;
        StringBuilder buf = new StringBuilder();
        boolean first = true;

        for (Map.Entry<? extends Object, ? extends Object> entry: map.entrySet()) {
            Object key = entry.getKey();
            Object value = entry.getValue();

            if (!(key instanceof String) || !(value instanceof String))
                continue;
            String encodedName = null;
            try {
                encodedName = URLEncoder.encode((String) key, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                Debug.error(e.getMessage(), module);
            }
            String encodedValue = null;
            try {
                encodedValue = URLEncoder.encode((String) value, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                Debug.error(e.getMessage(),module);
            }

            if (first)
                first = false;
            else
                buf.append("|");

            buf.append(encodedName);
            buf.append("=");
            buf.append(encodedValue);
        }
        return buf.toString();
    }
    


   
    /** Removes all spaces from a string */
    public static String removeSpaces(String str) {
        return removeRegex(str,"[\\ ]");
    }

    public static String toHexString(byte[] bytes) {
        return new String(Hex.encodeHex(bytes));
    }

    public static String cleanHexString(String str) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) != 32 && str.charAt(i) != ':') {
                buf.append(str.charAt(i));
            }
        }
        return buf.toString();
    }

    public static byte[] fromHexString(String str) {
        str = cleanHexString(str);
        try {
            return Hex.decodeHex(str.toCharArray());
        } catch (DecoderException e) {
            throw new GeneralRuntimeException(e);
        }
    }

    private static char[] hexChar = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    public static int convertChar(char c) {
        if ('0' <= c && c <= '9') {
            return c - '0' ;
        } else if ('a' <= c && c <= 'f') {
            return c - 'a' + 0xa ;
        } else if ('A' <= c && c <= 'F') {
            return c - 'A' + 0xa ;
        } else {
            throw new IllegalArgumentException("Invalid hex character: [" + c + "]");
        }
    }

    public static char[] encodeInt(int i, int j, char digestChars[]) {
        if (i < 16) {
            digestChars[j] = '0';
        }
        j++;
        do {
            digestChars[j--] = hexChar[i & 0xf];
            i >>>= 4;
        } while (i != 0);
        return digestChars;
    }

    /** Removes all non-numbers from str */
    public static String removeNonNumeric(String str) {
        return removeRegex(str,"[\\D]");
    }

    /** Removes all numbers from str */
    public static String removeNumeric(String str) {
        return removeRegex(str,"[\\d]");
    }

    /**
     * @param str
     * @param regex
     * Removes all matches of regex from a str
     */
    public static String removeRegex(String str, String regex) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(str);
        return matcher.replaceAll("");
    }

    /**
     * Add the number to the string, keeping (padding to min of original length)
     *
     * @return the new value
     */
    public static String addToNumberString(String numberString, long addAmount) {
        if (numberString == null) return null;
        int origLength = numberString.length();
        long number = Long.parseLong(numberString);
        return padNumberString(Long.toString(number + addAmount), origLength);
    }

    public static String padNumberString(String numberString, int targetMinLength) {
        StringBuilder outStrBfr = new StringBuilder(numberString);
        while (targetMinLength > outStrBfr.length()) {
            outStrBfr.insert(0, '0');
        }
        return outStrBfr.toString();
    }




    /**
     * Remove/collapse multiple newline characters
     *
     * @param str string to collapse newlines in
     * @return the converted string
     */
    public static String collapseNewlines(String str) {
        return collapseCharacter(str, '\n');
    }

    /**
     * Remove/collapse multiple spaces
     *
     * @param str string to collapse spaces in
     * @return the converted string
     */
    public static String collapseSpaces(String str) {
        return collapseCharacter(str, ' ');
    }

    /**
     * Remove/collapse multiple characters
     *
     * @param str string to collapse characters in
     * @param c character to collapse
     * @return the converted string
     */
    public static String collapseCharacter(String str, char c) {
        StringBuilder sb = new StringBuilder();
        char last = str.charAt(0);

        for (int i = 0; i < str.length(); i++) {
            char current = str.charAt(i);
            if (i == 0 || current != c || last != c) {
                sb.append(current);
                last = current;
            }
        }

        return sb.toString();
    }

    public static StringWrapper wrapString(String theString) {
        return makeStringWrapper(theString);
    }
    public static StringWrapper makeStringWrapper(String theString) {
        if (theString == null) return null;
        if (theString.length() == 0) return StringWrapper.EMPTY_STRING_WRAPPER;
        return new StringWrapper(theString);
    }


    public static StringBuilder append(StringBuilder sb, Iterable<? extends Object> iterable, String prefix, String suffix, String sep) {
        return append(sb, iterable, prefix, suffix, null, sep, null);
    }

    public static StringBuilder append(StringBuilder sb, Iterable<? extends Object> iterable, String prefix, String suffix, String sepPrefix, String sep, String sepSuffix) {
        Iterator<? extends Object> it = iterable.iterator();
        while (it.hasNext()) {
            if (prefix != null) sb.append(prefix);
            sb.append(it.next());
            if (suffix != null) sb.append(suffix);
            if (it.hasNext() && sep != null) {
                if (sepPrefix != null) sb.append(sepPrefix);
                sb.append(sep);
                if (sepSuffix != null) sb.append(sepSuffix);
            }
        }
        return sb;
    }

    /**
     * A super-lightweight object to wrap a String object. Mainly used with FTL templates
     * to avoid the general HTML auto-encoding that is now done through the Screen Widget.
     */
    public static class StringWrapper {
        public static final StringWrapper EMPTY_STRING_WRAPPER = new StringWrapper("");

        protected String theString;
        protected StringWrapper() { }
        public StringWrapper(String theString) {
            this.theString = theString;
        }

        /**
         * Fairly simple method used for the plus (+) base concatenation in Groovy.
         *
         * @param value
         * @return the wrapped string, plus the value
         */
        public String plus(Object value) {
            return this.theString + value;
        }

        /**
         * @return The String this object wraps.
         */
        @Override
        public String toString() {
            return this.theString;
        }
    }


}
