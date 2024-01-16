#include <cstdlib>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

//////////////////////////////////////////////////////////////////////////////////
/////////////////////////XOR Encryption/Decryption////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////
// Szyfr XOR to algorytm szyfrowania, który wykorzystuje słowo kluczowe jako klucz i może być zapisany w następujący sposób
// Ci = Pi XOR Kj, gdzie Kj jest j-tą literą słowa kluczowego reprezentowaną w kodowaniu ASCII.
//
// Jeśli użyjesz klucza, który jest co najmniej tak długi, jak długość wiadomości, 
// szyfr XOR staje się znacznie silniejszy kryptograficznie niż w przypadku użycia powtarzającego się klucza. 
// Jeśli do wygenerowania takiego klucza używany jest generator liczb pseudolosowych, wynikiem jest szyfr strumieniowy.
// Jeśli do wygenerowania klucza zostanie użyty prawdziwie losowy generator liczb, wówczas mamy do czynienia z szyfrem Vernama, 
// jedynym systemem kryptograficznym, dla którego teoretycznie udowodniono absolutną siłę kryptograficzną.
//

// przykład szyfru XOR zaimplementowanego w języku C
void xorEncryptDecryptC(uint8_t* data, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// przykład szyfru XOR zaimplementowanego w ASM
void xorEncryptDecryptASM(uint8_t* data, size_t len, uint8_t key) {
    __asm {
        mov ecx, len
        mov esi, data
        movzx edi, key

        xor_loop :
        xor [esi], edi
            inc esi
            loop xor_loop
    }
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////Szyfr podstawieniowy/////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////

// Szyfr podstawieniowy to rodzaj algorytmu szyfrowania, w którym każdy znak tekstu jawnego jest zastępowany innym znakiem za pomocą klucza.
// Klucz definiuje jednoznaczne przyporządkowanie między znakami tekstu jawnego a odpowiadającymi im znakami zaszyfrowanymi.
// Istnieją różne rodzaje szyfrów podstawieniowych, takie jak szyfr Cezara, szyfr Vigenère'a, czy szyfr jednopodstawieniowy.

// Szyfr działa na zasadzie zamiany każdego znaku tekstu jawnego na odpowiadający mu znak zaszyfrowany według ustalonego klucza.
// To sprawia, że znak ten staje się nieczytelny dla osób, które nie posiadają klucza szyfrowania.
// Szyfry podstawieniowe są stosunkowo proste do zrozumienia i zaimplementowania, co sprawia, że są używane w edukacji i do celów demonstracyjnych.

// przykład szyfru podstawieniowy zaimplementowanego w C
void substitutionEncryptC(char* data, size_t len,
    const uint8_t* substitutionTable) {
    for (size_t i = 0; i < len; i++) {
        data[i] = substitutionTable[(uint8_t)data[i]];
    }
}

// przykład szyfru podstawieniowy zaimplementowanego w C
void substitutionDecryptC(char* data, size_t len,
    const uint8_t* substitutionTable) {
    for (size_t i = 0; i < len; i++) {
        uint8_t substitutedValue = data[i];

        for (uint8_t j = 0; j < 256; j++) {
            if (substitutionTable[j] == substitutedValue) {
                data[i] = j;
                break;
            }
        }
    }
}

// przykład szyfru podstawieniowy zaimplementowanego w ASM
void substitutionEncryptASM(char* data, size_t len,
    const uint8_t* substitutionTable) {
    __asm {
        mov ecx, len
        mov esi, data
        mov edi, substitutionTable

        substitution_encrypt_loop :
        movzx eax, byte ptr[esi]
            movzx eax, byte ptr[edi + eax]
            mov byte ptr[esi], al

            inc esi
            loop substitution_encrypt_loop
    }
}

// przykład szyfru podstawieniowy zaimplementowanego w ASM
void substitutionDecryptASM(char* data, size_t len,
    const uint8_t* substitutionTable) {
    __asm {
        mov ecx, len
        mov esi, data
        mov edi, substitutionTable

        substitution_decrypt_loop :
        movzx eax, byte ptr[esi]
            xor edx, edx

            search_in_table :
        cmp byte ptr[edi + edx], al
            je found
            inc edx
            cmp edx, 256
            jl search_in_table

            found :
        mov byte ptr[esi], dl

            inc esi
            loop substitution_decrypt_loop
    }
}

/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////Caesar Encryption/Decryption////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
// Szyfr Cezara – jedna z najprostszych technik szyfrowania. 
// Jest to rodzaj szyfru podstawieniowego, w którym każda litera tekstu niezaszyfrowanego zastępowana jest inną, oddaloną od niej o stałą liczbę pozycji w alfabecie, 
// literą (szyfr monoalfabetyczny), przy czym kierunek zamiany musi być zachowany. Nie rozróżnia się przy tym liter dużych i małych.
//
// Zasada działania polega na cyklicznym przesuwaniu alfabetu, a kluczem jest liczba liter, o które następuje przesunięcie.
// 
// Ogólny wzor:
// y=(x+k)mod n
// x=(y-k)mod n, gdzie
// x jest numerem sekwencyjnym znaku tekstu jawnego, 
// y - numer porządkowy znaku szyfrogramu, 
// n - potęga alfabetu 
// k - klucz
// Szyfr Cezara ma zbyt mało kluczy - o jeden mniej niż liter w alfabecie. Dlatego też łatwo jest go złamać metodą brute-force - 
// próbując wszystkich możliwych kluczy, aż do odszyfrowania rozpoznawalnego tekstu jawnego.

// przykład szyfru Cezara zaimplementowanego w języku C
void caesarEncryptDecryptC(uint8_t* data, size_t len, uint8_t shift) {
    for (size_t i = 0; i < len; i++) {
        data[i] = (data[i] + shift) % 256;
    }
}

// przykład szyfru Cezara zaimplementowanego w języku ASM
void caesarEncryptDecryptASM(uint8_t* data, size_t len, int8_t shift) {
    __asm {
        mov ecx, len
        mov esi, data
        movzx edi, shift

        caesar_loop :
        movzx eax, byte ptr[esi]
            add eax, edi
            cmp eax, 255
            jbe no_overflow
            sub eax, 256

            no_overflow :
            mov byte ptr[esi], al
            inc esi
            loop caesar_loop
    }
}


/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////Tiny Encryption Algorithm///////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
// TEA (Tiny Encryption Algorithm) – symetryczny szyfr blokowy opracowany przez Rogera Needhama i Davida Wheelera w 1994 roku.
// Szyfr oparty jest o Sieć Feistela i wykorzystuje operacje z mieszanych grup algebraicznych. 
// Cechuje się małą zajętością pamięci, dużą szybkością szyfrowania, wysoką odpornością na kryptoanalizę różnicową i zdolnością do pełnej dyfuzji już po sześciu rundach.
//
// Algorytm szyfrowania TEA opiera się na operacjach bitowych z 64-bitowym blokiem i ma 128-bitowy klucz szyfrowania. 
// Standardowa liczba rund sieci Feistel wynosi około 64 (32 cykle), jednak aby osiągnąć najlepszą wydajność lub szyfrowanie, 
// liczbę cykli można zmieniać od 8 (16 rund) do 64 (128 rund).
//
// Zaletami szyfru są prostota implementacji, niewielki rozmiar kodu i dość duża szybkość wykonania, a także możliwość optymalizacji wykonania na standardowych 
// procesorach 32-bitowych, ponieważ główne operacje to wyłączne LUB, przesunięcie bitowe i dodawanie modulo 232. Ponieważ algorytm nie wykorzystuje żadnych tabel podstawień, 
// a funkcja rundy jest dość prosta, algorytm wymaga co najmniej 16 cykli (32 rundy), aby osiągnąć efektywną dyfuzję, chociaż pełna dyfuzja jest osiągana w 6 cyklach (12 rund).
//
// Algorytm ma doskonałą odporność na kryptoanalizę liniową i wystarczająco dobrą odporność na kryptoanalizę różnicową. 
// Główną wadą tego algorytmu szyfrowania jest jego podatność na ataki z użyciem powiązanych kluczy.

// przykład szyfru TEA zaimplementowanego w C
void tea_encrypt_c(uint32_t msg[2], const uint32_t key[4]) {
    uint32_t y = msg[0];
    uint32_t z = msg[1];
    uint32_t k0 = key[0];
    uint32_t k1 = key[1];
    uint32_t k2 = key[2];
    uint32_t k3 = key[3];
    uint32_t sum = UINT32_C(0x9E3779B9);

    for (int i = 0; i < 32; i++) {
        y += (((z << 4) + k0) ^ (z + sum) ^ ((z >> 5) + k1));
        z += (((y << 4) + k2) ^ (y + sum) ^ ((y >> 5) + k3));
        sum += UINT32_C(0x9E3779B9);
    }

    msg[0] = y;
    msg[1] = z;
}

// przykład szyfru TEA zaimplementowanego w ASM
void tea_encrypt_ASM(uint32_t msg[2], const uint32_t key[4]) {
    __asm {
        mov eax, msg
        mov edx, key

        mov esi, [eax] // msg[0]
        mov edi, [eax + 4] // msg[1]

        mov ecx, 0x9E3779B9
        mov ebx, 0

        tea_encrypt_top:
        mov ebx, edi
            shl ebx, 4
            add ebx, [edx]
            lea eax, [edi + ecx]
            xor ebx, eax
            mov eax, edi
            shr eax, 5
            add eax, [edx + 4]
            xor ebx, eax
            add esi, ebx

            mov ebx, esi
            shl ebx, 4
            add ebx, [edx + 8]
            lea eax, [esi + ecx]
            xor ebx, eax
            mov eax, esi
            shr eax, 5
            add eax, [edx + 12]
            xor ebx, eax
            add edi, ebx

            add ecx, 0x9E3779B9
            cmp ecx, 0x6526B0D9
            jne tea_encrypt_top

            mov eax, msg
            mov[eax], esi
            mov[eax + 4], edi
    }
}

// przykład szyfru TEA zaimplementowanego w C
void tea_decrypt_c(uint32_t msg[2], const uint32_t key[4]) {
    uint32_t y = msg[0];
    uint32_t z = msg[1];
    uint32_t k0 = key[0];
    uint32_t k1 = key[1];
    uint32_t k2 = key[2];
    uint32_t k3 = key[3];
    uint32_t sum = UINT32_C(0xC6EF3720); 

    for (int i = 0; i < 32; i++) {
        z -= (((y << 4) + k2) ^ (y + sum) ^ ((y >> 5) + k3));
        y -= (((z << 4) + k0) ^ (z + sum) ^ ((z >> 5) + k1));
        sum -= UINT32_C(0x9E3779B9);
    }

    msg[0] = y;
    msg[1] = z;
}

// przykład szyfru TEA zaimplementowanego w ASM
void tea_decrypt_ASM(uint32_t msg[2], const uint32_t key[4]) {
    __asm {
        mov eax, msg
        mov edx, key

        mov esi, [eax]
        mov edi, [eax + 4]

        mov ecx, 0 
        mov ebx, 0xC6EF3720 // 32 rounds

        tea_decrypt_top:
        sub edi, ebx
            mov eax, edi
            shr eax, 5
            sub esi, [edx + 12]
            xor eax, esi
            sub eax, ecx
            shl esi, 4
            sub esi, [edx + 8]
            xor esi, eax

            sub esi, ebx
            mov eax, esi
            shr eax, 5
            sub edi, [edx + 4]
            xor eax, edi
            sub eax, ecx
            shl edi, 4
            sub edi, [edx]
            xor edi, eax

            sub ecx, 0x9E3779B9
            cmp ecx, 0xC6EF3720
            jne tea_decrypt_top

            mov eax, msg
            mov[eax], esi
            mov[eax + 4], edi
    }
}



//////////////////////////////////////////////////////////////////////////////////
/////////////////////////////Szyfr Vigenère’a/////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////
//
// Szyfr Vigenère'a to szyfr polialfabetyczny, który wykorzystuje słowo jako klucz.
// Ci = (Pi + Kj) mod 33, gdzie Kj jest j-tą literą słowa kluczowego, Pi jest i-tą literą słowa źródłowego.
// Należy on do grupy tzw. polialfabetycznych szyfrów podstawieniowych.
// Każdy z wierszy tablicy odpowiada szyfrowi Cezara, przy czym w pierwszym wierszu przesunięcie wynosi 0, w drugim 1 itd.
// Aby zaszyfrować pewien tekst, potrzebne jest słowo kluczowe. Słowo kluczowe jest tajne i mówi, z którego wiersza (lub kolumny) należy w danym momencie skorzystać.

// przykład szyfru Vigenère’a zaimplementowanego w C
void vigenereEncryptC(char* data, size_t len, const char* key) {
    size_t keyLen = strlen(key);
    for (size_t i = 0; i < len; i++) {
        data[i] = (data[i] + key[i % keyLen]) % 256;
    }
}

// przykład szyfru Vigenère’a zaimplementowanego w ASM
void vigenereEncryptASM(char* data, size_t len, const char* key) {
    __asm {
        mov ecx, len
        mov esi, data
        mov edi, key
        mov ebx, 0

        vigenere_encrypt_loop :
        movzx eax, byte ptr[esi]
            movzx edx, byte ptr[edi + ebx]
            add eax, edx
            movzx edx, byte ptr[edi]
            add edi, 1
            cmp edi, ebx
            jne no_wraparound
            mov edi, edx

            no_wraparound :
        mov byte ptr[esi], al
            inc esi
            inc ebx
            cmp ebx, ecx
            jl vigenere_encrypt_loop
    }
}

// przykład szyfru Vigenère’a zaimplementowanego w C
void vigenereDecryptC(char* data, size_t len, const char* key) {
    size_t keyLen = strlen(key);
    for (size_t i = 0; i < len; i++) {
        data[i] = (data[i] - key[i % keyLen] + 256) % 256;
    }
}

// przykład szyfru Vigenère’a zaimplementowanego w ASM
void vigenereDecryptASM(char* data, size_t len, const char* key) {
    __asm {
        mov ecx, len
        mov esi, data
        mov edi, key
        mov ebx, 0

        vigenere_decrypt_loop :
        movzx eax, byte ptr[esi]
            movzx edx, byte ptr[edi + ebx]
            sub eax, edx
            movzx edx, byte ptr[edi]
            add edi, 1
            cmp edi, ebx
            jne no_wraparound_decrypt
            mov edi, edx

            no_wraparound_decrypt :
        mov byte ptr[esi], al
            inc esi
            inc ebx
            cmp ebx, ecx
            jl vigenere_decrypt_loop
    }
}

int main() {
    char plaintext1[] = "Hello, World!";
    char plaintext2[] = "Hello, World!";
    size_t len1 = strlen(plaintext1);
    size_t len2 = strlen(plaintext2);

    // XOR Encryption
    uint8_t xorKey = 0xAB;
    xorEncryptDecryptC((uint8_t*)plaintext1, len1, xorKey);
    printf("XOR Encrypted: %s\n", plaintext1);
    xorEncryptDecryptASM((uint8_t*)plaintext2, len2, xorKey);
    printf("XOR Encrypted (ASM): %s\n", plaintext2);

    // XOR Decryption
    xorEncryptDecryptC((uint8_t*)plaintext1, len1, xorKey);
    printf("XOR Decrypted: %s\n", plaintext1);
    xorEncryptDecryptASM((uint8_t*)plaintext2, len2, xorKey);
    printf("XOR Decrypted (ASM): %s\n", plaintext2);

    char plaintext3[] = "Hello, Caesar!";
    char plaintext4[] = "Hello, Caesar!";
    size_t len3 = strlen(plaintext3); // Corrected variable
    size_t len4 = strlen(plaintext4); // Corrected variable

    // Caesar Encryption
    uint8_t caesarShift = 3; // Change this parameter for the shift
    caesarEncryptDecryptC((uint8_t*)plaintext3, len3, caesarShift);
    printf("Caesar Encrypted: %s\n", plaintext3);
    caesarEncryptDecryptASM((uint8_t*)plaintext4, len4, caesarShift);
    printf("Caesar Encrypted (ASM): %s\n", plaintext4);

    // Caesar Decryption
    caesarEncryptDecryptC((uint8_t*)plaintext3, len3, 256 - caesarShift);
    printf("Caesar Decrypted: %s\n", plaintext3);
    caesarEncryptDecryptASM((uint8_t*)plaintext4, len4, 256 - caesarShift);
    printf("Caesar Decrypted (ASM): %s\n", plaintext4);

    uint32_t teaMessage[] = { 0x01234567, 0x89ABCDEF }; // Example TEA message
    uint32_t teaKey[] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98,
                         0x76543210 }; // Example TEA key

    // TEA Encryption
    tea_encrypt_c(teaMessage, teaKey);
    printf("TEA Encrypted (C): 0x%08X 0x%08X\n", teaMessage[0], teaMessage[1]);

    uint32_t teaMessageASM[] = { 0x01234567, 0x89ABCDEF }; // Example TEA message
    tea_encrypt_ASM(teaMessageASM, teaKey);
    printf("TEA Encrypted (ASM): 0x%08X 0x%08X\n", teaMessageASM[0],
        teaMessageASM[1]);

    // TEA Decryption
    tea_decrypt_c(teaMessage, teaKey);
    printf("TEA Decrypted (C): 0x%08X 0x%08X\n", teaMessage[0], teaMessage[1]);

    tea_decrypt_c(teaMessageASM, teaKey);
    printf("TEA Decrypted (ASM): 0x%08X 0x%08X\n", teaMessageASM[0],
        teaMessageASM[1]);

    char vigenereText1[] = "Hello, Vigenere!";
    char vigenereText2[] = "Hello, Vigenere!";
    size_t vigenereLen = strlen(vigenereText1);

    // Vigenere Encryption
    char vigenereKey[] = "KEY";
    vigenereEncryptC(vigenereText1, vigenereLen, vigenereKey);
    printf("Vigenere Encrypted: %s\n", vigenereText1);
    vigenereEncryptASM(vigenereText2, vigenereLen, vigenereKey);
    printf("Vigenere Encrypted (ASM): %s\n", vigenereText2);

    // Vigenere Decryption
    vigenereDecryptC(vigenereText1, vigenereLen, vigenereKey);
    printf("Vigenere Decrypted: %s\n", vigenereText1);
    vigenereDecryptASM(vigenereText2, vigenereLen, vigenereKey);
    printf("Vigenere Decrypted (ASM): %s\n", vigenereText2);

    uint8_t substitutionTable[256];

    // Initialize substitution table (for demonstration purposes)
    for (int i = 0; i < 256; i++) {
        substitutionTable[i] = (uint8_t)i;
    }

    // Shuffle substitution table (for demonstration purposes)
    for (int i = 0; i < 256; i++) {
        int j = rand() % 256;
        uint8_t temp = substitutionTable[i];
        substitutionTable[i] = substitutionTable[j];
        substitutionTable[j] = temp;
    }

    char substitutionText1[] = "HELLO";
    char substitutionText2[] = "HELLO";
    size_t substitutionLen = strlen(substitutionText1);

    // Substitution Encryption
    substitutionEncryptC(substitutionText1, substitutionLen, substitutionTable);
    printf("Substitution Encrypted: %s\n", substitutionText1);

    // Substitution Decryption
    substitutionDecryptC(substitutionText1, substitutionLen, substitutionTable);
    printf("Substitution Decrypted: %s\n", substitutionText1);

    substitutionEncryptASM(substitutionText2, substitutionLen, substitutionTable);
    printf("Substitution Encrypted (ASM): %s\n", substitutionText2);

    substitutionDecryptASM(substitutionText2, substitutionLen, substitutionTable);
    printf("Substitution Decrypted (ASM): %s\n", substitutionText2);

    return 0;
}
