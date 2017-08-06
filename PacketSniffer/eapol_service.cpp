//
//  eapol_service.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 8/5/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//
// This is a service called from LLC that:
// 1. takes care of EAPOL frames
// 2. gives a temporal key mapped to a DA/SA MAC address pair (order doesn't matter, just that two MACs match)

// 802.11 standard: math functions
// x||y means the x and y, except in code, where it sometimes is the short-circuiting Boolean
// L (S, F, N) is bits F to F+N–1 of the bit string S starting from the left

// In WPA-PSK, the PMK is the PSK
// Page 3416 of IEEE 802.11-2016 gives a pass-phrase to PSK example. Annex J has test vectors.
// PSK = PBKDF2(passPhrase, ssid, 4096, 256/8)
// PBKDF2 is defined here: https://www.ietf.org/rfc/rfc2898.txt
// http://jorisvr.nl/wpapsk.html gives a good overview


#include "eapol_service.h"
#include <stdio.h>
#include <string.h>

struct key_info_t
{
    // -- OCTET MSB --
    uint16_t key_MIC:1; // set to 1 if a MIC is in this EAPOL-Key frame and is set to 0 if this message contains no MIC
    uint16_t secure:1;
    uint16_t error:1;
    uint16_t request:1;
    uint16_t encrypted_key_data:1;
    uint16_t SMK_message:1;
    uint16_t reserved_B:2;
    // --------------
    
    // --- OCTET LSB ---
    uint16_t key_descriptor_version:3; // needed for knowing key MIC length
    uint16_t key_type:1; // The value 0 (Group/SMK) indicates the message is not part of a PTK derivation.
    // The value 1 (Pairwise) indicates the message is part of a PTK derivation.
    uint16_t reserved_A:2;
    uint16_t install:1;
    uint16_t key_Ack:1;
    //------------------
};

struct EAPOL_key_frame_t
{
    uint8_t protocol_version;
    uint8_t packet_type;
    uint16_t packet_body_length;
    uint8_t descriptor_type;
    
    // octets are LSB right to left
    // how it comes through: 00    08
    //                       MSB   LSB
    // so copy MSB first
    
    key_info_t key_info;
    
    uint16_t key_length; // defines the length in octets of the pairwise temporal key
    
    uint8_t key_replay_counter[8];

    uint8_t key_nonce[32]; // conveys the ANonce from the Authenticator and the SNonce from the Supplicant.
    uint8_t eapol_key_IV[16]; // contains the IV used with the KEK
    uint8_t key_RSC[8];
    uint8_t reserved[8];
    // --- not variable up until this point ---
    const u_char *key_MIC; // The length of this field depends on the negotiated AKM
    uint16_t key_data_length; // represents the length of the Key Data field in octets
    const u_char *key_data;
};

struct key_data_t
{
    uint8_t type;
    uint8_t length;
    uint8_t OUI[3];
    uint8_t data_type;
    const u_char *data;
};

void process_EAPOL_frame(const u_char *data_frame, uint16_t length)
{
    EAPOL_key_frame_t key_frame;
    
    
    // since the struct has a combination of different sizes
    // it is not packed, therefore you need to be careful
    // in making sure the memory is where you want it
    key_frame.protocol_version = data_frame[0];
    key_frame.packet_type = data_frame[1];
    key_frame.packet_body_length = (data_frame[2] << 8) | data_frame[3];
    key_frame.descriptor_type = data_frame[4];
    memcpy(&(key_frame.key_info), &(data_frame[5]), 2);
    key_frame.key_length = (data_frame[7] << 8) | data_frame[8];
    memcpy(key_frame.key_replay_counter, &(data_frame[9]), 8);
    memcpy(key_frame.key_nonce, &(data_frame[17]), 32);
    memcpy(key_frame.eapol_key_IV, &(data_frame[49]), 16);
    memcpy(key_frame.key_RSC, &(data_frame[65]), 8);
    memcpy(key_frame.reserved, &(data_frame[73]), 8);
    
    uint8_t key_descriptor_version = key_frame.key_info.key_descriptor_version;
    uint8_t key_MIC_octet_length = 0;
    
    if(key_descriptor_version == 1)
    {
        key_MIC_octet_length = 16;
    }
    else if(key_descriptor_version == 2)
    {
        key_MIC_octet_length = 16;
    }
    else if(key_descriptor_version == 3)
    {
        key_MIC_octet_length = 16;
    }
    
    const u_char *after_MIC_ptr;
    if(key_frame.key_info.key_MIC)
    { // has MIC
        key_frame.key_MIC = data_frame + 81;
        after_MIC_ptr = data_frame + 81 + key_MIC_octet_length;
    }
    else
    {
        key_frame.key_MIC = data_frame + 81;
        after_MIC_ptr = data_frame + 81 + key_MIC_octet_length;
    }
    
    memcpy(&(key_frame.key_data_length), after_MIC_ptr, 2);
    key_frame.key_data_length = (key_frame.key_data_length>>8) | (key_frame.key_data_length<<8); // correct endian to LSB
    
    key_frame.key_data = after_MIC_ptr + 2;
    
    
    key_data_t key_data;
    
    key_data.type = (key_frame.key_data)[0];
    key_data.length = (key_frame.key_data)[1];
    key_data.OUI[0] = (key_frame.key_data)[2];
    key_data.OUI[1] = (key_frame.key_data)[3];
    key_data.OUI[2] = (key_frame.key_data)[4];
    key_data.data_type = (key_frame.key_data)[5];
    key_data.data = key_frame.key_data + 6;
    

    uint8_t key_type = 0;
    
    if(key_data.OUI[0] == 0x00 && key_data.OUI[1] == 0x0F && key_data.OUI[2] == 0xAC)
    {
        if(key_data.data_type == 1 || key_data.data_type == 2)
        {
            key_type = ENCRYPT_TYPE_HMAC_SHA_1_128;
        }
        else if(key_data.data_type > 2 && key_data.data_type < 10)
        {
            key_type = ENCRYPT_TYPE_AES_128_CMAC;
        }
        else if(key_data.data_type == 11)
        {
            key_type = ENCRYPT_TYPE_HMAC_SHA_256;
        }
        else if(key_data.data_type == 12 || key_data.data_type == 13)
        {
            key_type = ENCRYPT_TYPE_HMAC_SHA_384;
        }
        else
        {
            key_type = ENCRYPT_TYPE_UNKNOWN;
        }
    }
    else
    {
        key_type = ENCRYPT_TYPE_UNKNOWN;
    }
    
}

/* pad string to 64 bytes and convert to 16 32-bit words */
uint32_t z[80] = {0};
uint32_t *stringtowords(char *s, uint8_t padi)
{
    for(uint8_t i = 0; i < 80; i++) z[i]=0;
    /* return a 80-word array for later use in the SHA1 code */
    uint8_t j = -1, k = 0;
    uint8_t n = strlen(s);
    for (uint16_t i = 0; i < 64; i++) {
        uint8_t c = 0;
        if (i < n) {
            c = (uint8_t)s[i];
        } else if (padi)
        {
            /* add 4-byte PBKDF2 block index and
             standard padding for the final SHA1 input block */
            if (i == n) c = (padi >> 24) & 0xff;
            else if (i == n + 1) c = (padi >> 16) & 0xff;
            else if (i == n + 2) c = (padi >> 8) & 0xff;
            else if (i == n + 3) c = padi & 0xff;
            else if (i == n + 4) c = 0x80;
        }
        if (k == 0) { j++; z[j] = 0; k = 32; }
        k -= 8;
        z[j] = z[j] | (c << k);
    }
    if (padi) z[15] = 8 * (64 + n + 4);
    return z;
}

/* compute the intermediate SHA1 state after processing just
 the 64-byte padded HMAC key */
uint32_t ss[5] = {0};
uint32_t *initsha(uint32_t *w, uint8_t padbyte) {
    
    uint32_t pw = (padbyte << 24) | (padbyte << 16) | (padbyte << 8) | padbyte;
    for (uint16_t t = 0; t < 16; t++) w[t] ^= pw;
    
    ss[0] = 0x67452301;
    ss[1] = 0xEFCDAB89;
    ss[2] = 0x98BADCFE;
    ss[3] = 0x10325476;
    ss[4] = 0xC3D2E1F0;
    
    uint32_t a = ss[0], b = ss[1], c = ss[2], d = ss[3], e = ss[4];
    uint32_t t;
    for (uint16_t k = 16; k < 80; k++) {
        t = w[k-3] ^ w[k-8] ^ w[k-14] ^ w[k-16];
        w[k] = (t<<1) | (t>>31);
    }
    for (uint16_t k = 0; k < 20; k++) {
        t = ((a<<5) | (a>>27)) + e + w[k] + 0x5A827999 + ((b&c)|((~b)&d));
        e = d; d = c; c = (b<<30) | (b>>2); b = a; a = t & 0xffffffff;
    }
    for (uint16_t k = 20; k < 40; k++) {
        t = ((a<<5) | (a>>27)) + e + w[k] + 0x6ED9EBA1 + (b^c^d);
        e = d; d = c; c = (b<<30) | (b>>2); b = a; a = t & 0xffffffff;
    }
    for (uint16_t k = 40; k < 60; k++) {
        t = ((a<<5) | (a>>27)) + e + w[k] + 0x8F1BBCDC + ((b&c)|(b&d)|(c&d));
        e = d; d = c; c = (b<<30) | (b>>2); b = a; a = t & 0xffffffff;
    }
    for (uint16_t k = 60; k < 80; k++) {
        t = ((a<<5) | (a>>27)) + e + w[k] + 0xCA62C1D6 + (b^c^d);
        e = d; d = c; c = (b<<30) | (b>>2); b = a; a = t & 0xffffffff;
    }
    ss[0] = (ss[0] + a) & 0xffffffff;
    ss[1] = (ss[1] + b) & 0xffffffff;
    ss[2] = (ss[2] + c) & 0xffffffff;
    ss[3] = (ss[3] + d) & 0xffffffff;
    ss[4] = (ss[4] + e) & 0xffffffff;
    return s;
}

void convert_WPA_to_PSK(char *password, char *SSID, uint8_t *output)
{
    /* compute the intermediate SHA1 state of the inner and outer parts
     of the HMAC algorithm after processing the padded HMAC key */
    uint32_t *hmac_istate = initsha(stringtowords(password, 0), 0x36);
    uint32_t *hmac_ostate = initsha(stringtowords(password, 0), 0x5c);
    
    /* output is created in blocks of 20 bytes at a time and collected
     in a string as hexadecimal digits */
    char hash[64] = {0};
    uint16_t i = 0;
    while (strlen(hash) < 64) {
        /* prepare 20-byte (5-word) output vector */
        uint32_t u[] = {0, 0, 0, 0, 0};
        /* prepare input vector for the first SHA1 update (salt + block number) */
        i++;
        uint32_t *w = stringtowords(SSID, i);
        /* iterate 4096 times an inner and an outer SHA1 operation */
        for (uint32_t j = 0; j < 2 * 4096; j++) {
            /* alternate inner and outer SHA1 operations */
            uint32_t *s = (j & 1) ? hmac_ostate : hmac_istate;
            /* inline the SHA1 update operation */
            uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
            var t;
            for (var k = 16; k < 80; k++) {
                t = w[k-3] ^ w[k-8] ^ w[k-14] ^ w[k-16];
                w[k] = (t<<1) | (t>>>31);
            }
            for (var k = 0; k < 20; k++) {
                t = ((a<<5) | (a>>>27)) + e + w[k] + 0x5A827999 + ((b&c)|((~b)&d));
                e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
            }
            for (var k = 20; k < 40; k++) {
                t = ((a<<5) | (a>>>27)) + e + w[k] + 0x6ED9EBA1 + (b^c^d);
                e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
            }
            for (var k = 40; k < 60; k++) {
                t = ((a<<5) | (a>>>27)) + e + w[k] + 0x8F1BBCDC + ((b&c)|(b&d)|(c&d));
                e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
            }
            for (var k = 60; k < 80; k++) {
                t = ((a<<5) | (a>>>27)) + e + w[k] + 0xCA62C1D6 + (b^c^d);
                e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
            }
            /* stuff the SHA1 output back into the input vector */
            w[0] = (s[0] + a) & 0xffffffff;
            w[1] = (s[1] + b) & 0xffffffff;
            w[2] = (s[2] + c) & 0xffffffff;
            w[3] = (s[3] + d) & 0xffffffff;
            w[4] = (s[4] + e) & 0xffffffff;
            if (j & 1) {
                /* XOR the result of each complete HMAC-SHA1 operation into u */
                u[0] ^= w[0]; u[1] ^= w[1]; u[2] ^= w[2]; u[3] ^= w[3]; u[4] ^= w[4];
            } else if (j == 0) {
                /* pad the new 20-byte input vector for subsequent SHA1 operations */
                w[5] = 0x80000000;
                for (var k = 6; k < 15; k++) w[k] = 0;
                w[15] = 8 * (64 + 20);
            }
        }
        /* convert output vector u to hex and append to output string */
        for (var j = 0; j < 5; j++)
            for (var k = 0; k < 8; k++) {
                var t = (u[j] >>> (28 - 4 * k)) & 0x0f;
                hash += (t < 10) ? t : String.fromCharCode(87 + t);
            }
    }
    
    /* return the first 32 key bytes as a hexadecimal string */
    return hash.substring(0, 64);
}

// JavaScript WPA -> PSK example
//function getWpaPskKeyFromPassphrase(pass, salt) {
//
//    /* pad string to 64 bytes and convert to 16 32-bit words */
//    function stringtowords(s, padi) {
//        /* return a 80-word array for later use in the SHA1 code */
//        var z = new Array(80);
//        var j = -1, k = 0;
//        var n = s.length;
//        for (var i = 0; i < 64; i++) {
//            var c = 0;
//            if (i < n) {
//                c = s.charCodeAt(i);
//            } else if (padi) {
//                /* add 4-byte PBKDF2 block index and
//                 standard padding for the final SHA1 input block */
//                if (i == n) c = (padi >>> 24) & 0xff;
//                else if (i == n + 1) c = (padi >>> 16) & 0xff;
//                else if (i == n + 2) c = (padi >>> 8) & 0xff;
//                else if (i == n + 3) c = padi & 0xff;
//                else if (i == n + 4) c = 0x80;
//            }
//            if (k == 0) { j++; z[j] = 0; k = 32; }
//            k -= 8;
//            z[j] = z[j] | (c << k);
//        }
//        if (padi) z[15] = 8 * (64 + n + 4);
//        return z;
//    }
//    
//    /* compute the intermediate SHA1 state after processing just
//     the 64-byte padded HMAC key */
//    function initsha(w, padbyte) {
//        var pw = (padbyte << 24) | (padbyte << 16) | (padbyte << 8) | padbyte;
//        for (var t = 0; t < 16; t++) w[t] ^= pw;
//        var s = [ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 ];
//        var a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
//        var t;
//        for (var k = 16; k < 80; k++) {
//            t = w[k-3] ^ w[k-8] ^ w[k-14] ^ w[k-16];
//            w[k] = (t<<1) | (t>>>31);
//        }
//        for (var k = 0; k < 20; k++) {
//            t = ((a<<5) | (a>>>27)) + e + w[k] + 0x5A827999 + ((b&c)|((~b)&d));
//            e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
//        }
//        for (var k = 20; k < 40; k++) {
//            t = ((a<<5) | (a>>>27)) + e + w[k] + 0x6ED9EBA1 + (b^c^d);
//            e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
//        }
//        for (var k = 40; k < 60; k++) {
//            t = ((a<<5) | (a>>>27)) + e + w[k] + 0x8F1BBCDC + ((b&c)|(b&d)|(c&d));
//            e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
//        }
//        for (var k = 60; k < 80; k++) {
//            t = ((a<<5) | (a>>>27)) + e + w[k] + 0xCA62C1D6 + (b^c^d);
//            e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
//        }
//        s[0] = (s[0] + a) & 0xffffffff;
//        s[1] = (s[1] + b) & 0xffffffff;
//        s[2] = (s[2] + c) & 0xffffffff;
//        s[3] = (s[3] + d) & 0xffffffff;
//        s[4] = (s[4] + e) & 0xffffffff;
//        return s;
//    }
//    
//    /* compute the intermediate SHA1 state of the inner and outer parts
//     of the HMAC algorithm after processing the padded HMAC key */
//    var hmac_istate = initsha(stringtowords(pass, 0), 0x36);
//    var hmac_ostate = initsha(stringtowords(pass, 0), 0x5c);
//    
//    /* output is created in blocks of 20 bytes at a time and collected
//     in a string as hexadecimal digits */
//    var hash = '';
//    var i = 0;
//    while (hash.length < 64) {
//        /* prepare 20-byte (5-word) output vector */
//        var u = [ 0, 0, 0, 0, 0 ];
//        /* prepare input vector for the first SHA1 update (salt + block number) */
//        i++;
//        var w = stringtowords(salt, i);
//        /* iterate 4096 times an inner and an outer SHA1 operation */
//        for (var j = 0; j < 2 * 4096; j++) {
//            /* alternate inner and outer SHA1 operations */
//            var s = (j & 1) ? hmac_ostate : hmac_istate;
//            /* inline the SHA1 update operation */
//            var a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
//            var t;
//            for (var k = 16; k < 80; k++) {
//                t = w[k-3] ^ w[k-8] ^ w[k-14] ^ w[k-16];
//                w[k] = (t<<1) | (t>>>31);
//            }
//            for (var k = 0; k < 20; k++) {
//                t = ((a<<5) | (a>>>27)) + e + w[k] + 0x5A827999 + ((b&c)|((~b)&d));
//                e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
//            }
//            for (var k = 20; k < 40; k++) {
//                t = ((a<<5) | (a>>>27)) + e + w[k] + 0x6ED9EBA1 + (b^c^d);
//                e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
//            }
//            for (var k = 40; k < 60; k++) {
//                t = ((a<<5) | (a>>>27)) + e + w[k] + 0x8F1BBCDC + ((b&c)|(b&d)|(c&d));
//                e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
//            }
//            for (var k = 60; k < 80; k++) {
//                t = ((a<<5) | (a>>>27)) + e + w[k] + 0xCA62C1D6 + (b^c^d);
//                e = d; d = c; c = (b<<30) | (b>>>2); b = a; a = t & 0xffffffff;
//            }
//            /* stuff the SHA1 output back into the input vector */
//            w[0] = (s[0] + a) & 0xffffffff;
//            w[1] = (s[1] + b) & 0xffffffff;
//            w[2] = (s[2] + c) & 0xffffffff;
//            w[3] = (s[3] + d) & 0xffffffff;
//            w[4] = (s[4] + e) & 0xffffffff;
//            if (j & 1) {
//                /* XOR the result of each complete HMAC-SHA1 operation into u */
//                u[0] ^= w[0]; u[1] ^= w[1]; u[2] ^= w[2]; u[3] ^= w[3]; u[4] ^= w[4];
//            } else if (j == 0) {
//                /* pad the new 20-byte input vector for subsequent SHA1 operations */
//                w[5] = 0x80000000;
//                for (var k = 6; k < 15; k++) w[k] = 0;
//                w[15] = 8 * (64 + 20);
//            }
//        }
//        /* convert output vector u to hex and append to output string */
//        for (var j = 0; j < 5; j++)
//            for (var k = 0; k < 8; k++) {
//                var t = (u[j] >>> (28 - 4 * k)) & 0x0f;
//                hash += (t < 10) ? t : String.fromCharCode(87 + t);
//            }
//    }
//    
//    /* return the first 32 key bytes as a hexadecimal string */
//    return hash.substring(0, 64);
//}



