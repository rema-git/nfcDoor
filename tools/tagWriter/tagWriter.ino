/*
 *
 *  NFC tag writer
 *
 *  Reinhardt A.W. Maier, 2013
 *  rema@zaehlwerk.net
 *
 */

#include <Wire.h>
#include <Adafruit_NFCShield_I2C.h>

#define IRQ   (2)
#define RESET (3)

Adafruit_NFCShield_I2C nfc(IRQ, RESET);


// *********************************
// SET DATA HERE TO WRITE TO THE TAG
// *********************************

uint8_t passwd[16] = { 
  's', 'e', 'c', 'r', 'e', 't', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0};
uint8_t keyA[16] = { 
  0x1A, 0xFE, 0xFA, 0xF8, 0xFF, 0xFF,   // new KeyA
  0xFF, 0x07, 0x80, 0xFF,               // Access Bits, never change!!!
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; // KeyB, has no rights

// *********************************


void setup(void) {
  Serial.begin(115200);

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (! versiondata) {
    Serial.print("Didn't find PN53x board");
    while (1); // halt
  }
  // Got ok data, print it out!
  Serial.print("Found chip PN5"); 
  Serial.println((versiondata>>24) & 0xFF, HEX); 
  Serial.print("Firmware ver. "); 
  Serial.print((versiondata>>16) & 0xFF, DEC); 
  Serial.print('.'); 
  Serial.println((versiondata>>8) & 0xFF, DEC);

  // configure board to read RFID tags
  nfc.SAMConfig();

  Serial.println("Waiting for an ISO14443A Card ...");
}

void loop(void) {
  uint8_t success;
  uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0};
  uint8_t uidLength;
  uint8_t data[16];

  // Wait for an ISO14443A type cards (Mifare) -> blocking!
  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);

  if (success) {
    // display some basic information about the card
    Serial.println("Found an ISO14443A card");
    Serial.print("  UID Length: ");
    Serial.print(uidLength, DEC);
    Serial.println(" bytes");
    Serial.print("  UID Value: ");
    nfc.PrintHex(uid, uidLength);
    Serial.println("");

    if (uidLength == 4)
    {
      Serial.println("Seems to be a Mifare Classic card (4 byte UID)");


      //
      // AUTHENTICATE
      //
      Serial.println("Trying to authenticate block 4 with factory default KeyA");
      uint8_t keya_factory_default[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

      // block 4 (the first block of sector 1)
      success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, keya_factory_default);
        
        
      //
      // WRITE PASSWD
      //
      if (success)
      {
        Serial.println("Sector 1 (Blocks 4..7) has been authenticated");

        success = nfc.mifareclassic_WriteDataBlock (4, passwd);
        if (success)
        {
          // Data seems to have been written
          Serial.println("");
          Serial.println("Writing Block 4 succeded!");
        }
        else
        {
          Serial.println("ERROR: unable to write new passwd.");
          halt();
        }
        
        // Try to read the contents of block 4
        success = nfc.mifareclassic_ReadDataBlock(4, data);
        if (success)
        {
          Serial.println("Reading Block 4:");
          nfc.PrintHexChar(data, 16);
          Serial.println("");
        }
        else
        {
          Serial.println("ERROR: unable to read the requested block.");
          halt();
        }
      }


      //
      // WRITE NEW KEYA
      //
      if (success)
      {
        success = nfc.mifareclassic_WriteDataBlock (7, keyA);
        if (success)
        {
          // Data seems to have been written
          Serial.println("");
          Serial.println("Writing Block 7 succeded! New keyA written.");
        }
        else
        {
          Serial.println("ERROR: unable to write the new keyA.");
          halt();
        }
        
        // Try to read the contents of block 7
        success = nfc.mifareclassic_ReadDataBlock(7, data);
        if (success)
        {
          Serial.println("Reading Block 7 (keyA is blanked out):");
          nfc.PrintHexChar(data, 16);
          Serial.println("");
        }
        else
        {
          Serial.println("ERROR: unable to read the requested block.");
          halt();
        }
      }
      else
      {
        Serial.println("RERROR: authentication failed.");
        halt();
      }
    }
    else
    {
      Serial.println("ERROR: wrong card typ.");
      halt();
    }
  
}
  halt();
}

void halt(void) {
  Serial.println("");
  Serial.println("System halted!!! Please reboot!");
  Serial.println("");
  while(1);
}
