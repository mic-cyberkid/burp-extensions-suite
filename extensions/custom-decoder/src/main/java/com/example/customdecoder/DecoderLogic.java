package com.example.customdecoder;

import java.util.Base64;

public class DecoderLogic {
    public String decodeBase64(String input) {
        try {
            return new String(Base64.getDecoder().decode(input));
        } catch (Exception e) {
            return null;
        }
    }

    public String xorTransform(String input, byte key) {
        byte[] bytes = input.getBytes();
        byte[] output = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            output[i] = (byte) (bytes[i] ^ key);
        }
        return new String(output);
    }

    public String hexToString(String hex) {
        try {
            StringBuilder str = new StringBuilder();
            for (int i = 0; i < hex.length(); i += 2) {
                str.append((char) Integer.parseInt(hex.substring(i, i + 2), 16));
            }
            return str.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public String autoDetectAndDecode(String input) {
        // Try Hex first as it is more specific
        if (input.matches("^[0-9a-fA-F]+$") && input.length() % 2 == 0) {
            String hex = hexToString(input);
            if (hex != null && isPrintable(hex)) return "Hex: " + hex;
        }

        // Try Base64
        String b64 = decodeBase64(input);
        if (b64 != null && isPrintable(b64)) return "Base64: " + b64;

        return "No common encoding detected.";
    }

    private boolean isPrintable(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            // Limit to printable ASCII for auto-detection to reduce false positives
            if (c < 32 || c > 126) {
                if (c != 10 && c != 13 && c != 9) return false;
            }
        }
        return true;
    }
}
