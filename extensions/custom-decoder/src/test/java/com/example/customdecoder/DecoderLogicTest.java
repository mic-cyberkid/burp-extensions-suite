package com.example.customdecoder;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class DecoderLogicTest {
    private final DecoderLogic logic = new DecoderLogic();

    @Test
    public void testBase64() {
        assertEquals("hello", logic.decodeBase64("aGVsbG8="));
    }

    @Test
    public void testXor() {
        String input = "abc";
        byte key = 0x01;
        String encoded = logic.xorTransform(input, key);
        assertEquals(input, logic.xorTransform(encoded, key));
    }

    @Test
    public void testHex() {
        assertEquals("hello", logic.hexToString("68656c6c6f"));
    }

    @Test
    public void testAutoDetect() {
        assertEquals("Base64: Hello", logic.autoDetectAndDecode("SGVsbG8="));
        assertEquals("Hex: hello", logic.autoDetectAndDecode("68656c6c6f"));
    }
}
