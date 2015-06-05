/*
 *
 *  NFC based door access system
 *
 *  Reinhardt A.W. Maier, 2013
 *  rema@zaehlwerk.net
 *
 */
#define IRQ      (2)
#define RESET    (8)
#define DOORPIN  (3)
#define LEDPIN   (10)
#define DOOROPENTIME (10000) // in ms

#include <Wire.h>
#include <Arduino.h>
#include <Adafruit_NFCShield_I2C.h>

struct keylist
{
  char name[30];
  uint8_t uid[4];
  uint8_t keyA[6];
  uint8_t passwd[16];
};

static keylist building01[] = {
  {{"Tester A"}
   ,{0xA1, 0xA1, 0xA1, 0xA1}
   ,{0x11, 0xFF, 0xFF, 0xF8, 0xFF, 0xFF}
   ,{'t', 'e', 's', 't', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
};

struct led_t {
  short cycle;                // number of runs
  unsigned short brightness;  // 0 = off pwm, 255 = full time on
  short fadeAmount;           // speed
} 
led = {1, 0, 1};

Adafruit_NFCShield_I2C nfc(IRQ, RESET);

boolean debug = false;
static int keylistlength = sizeof(building01) / (sizeof building01[0]);

void setup() {
  // pin modes
  pinMode(DOORPIN, OUTPUT);
  pinMode(LEDPIN, OUTPUT);
  digitalWrite(DOORPIN, LOW);

  // serial connection
  Serial.begin(115200);

  // nfc chip connection
  nfc.begin();
  uint32_t versiondata = nfc.getFirmwareVersion();
  nfc.SAMConfig();
  if (! versiondata) {
    Serial.print("Didn't find PN53x board. Halt!");
    while (1); // halt
  }
  Serial.print("Found chip PN5"); 
  Serial.println((versiondata>>24) & 0xFF, HEX); 
  Serial.print("Firmware ver. "); 
  Serial.print((versiondata>>16) & 0xFF, DEC); 
  Serial.print('.'); 
  Serial.println((versiondata>>8) & 0xFF, DEC);

  // print status
  ledStatus(6);
  Serial.println("Debug mode: OFF (type 'd' to enable)");
  Serial.println("Boot sequence completed. Ready to read a tag.");
  Serial.println("");
}

void loop() {
  uint8_t success = 0;
  uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0};
  uint8_t keyA[] = {0, 0, 0, 0, 0, 0, 0}; 
  uint8_t uidLength = 0;
  uint8_t passwd[16];
  char messsage;

  // wait until a tag enters rf field
  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);

  // analyse tag
  if(success){
    if(uidLength == 4) {
      int index = -1;
      index = getIndexByUid(uid);
      if(index >= 0) {
        getKeyAByIndex(index,keyA);
        success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, keyA);
        success = success + nfc.mifareclassic_ReadDataBlock(4, passwd);
        if(success == 2) {
          success = checkPasswdByIndex(index, passwd);
          if(success) {
            debugMeassage("OK:    door open!");
            openDoor();
          }
          else {
            ledStatus(2);
            debugMeassage("ERROR: tag contains wrong password.");
          }
        }
        else {
          ledStatus(3);
          debugMeassage("ERROR: authentification request failed.");
        }
      }
      else {
        ledStatus(4);
        debugMeassage("ERROR: tag is not in key list.");
      }
    }
    else {
      ledStatus(5);
      debugMeassage("ERROR: tag detection failed or wrong card typ.");
    }
    if(debug == true){
      Serial.println();
      Serial.print("UID Length: ");
      Serial.print(uidLength, DEC);
      Serial.println(" bytes");
      Serial.print("UID Value: ");
      nfc.PrintHex(uid, uidLength);
      Serial.println();
      Serial.println("...waiting...");
      Serial.println();
    }
    // anti latch-up
    delay(1000);
  }
}   

int8_t getIndexByUid(const byte * uid) {
  for (int index = 0; index < keylistlength; index++) {
    int correlation = 0;
    for (int n = 0; n < 4; n++) {
      if (uid[n] == building01[index].uid[n])
        correlation++;
      if(correlation == 4){
        debugMeassage("OK:    tag ID is known, name:");
        debugMeassage(building01[index].name);
        return index;
      }
    }
  }
  return -1;
}

void getKeyAByIndex(int index, uint8_t * keyA) {
  memcpy (keyA, building01[index].keyA, 7);
}

uint8_t checkPasswdByIndex(int index, uint8_t * passwd) {
  for (int n = 0; n < 16; n++) {
    if (passwd[n] != building01[index].passwd[n])
      return 0;
  }
  debugMeassage("OK:    password check passed.");
  return 1;
}

void openDoor() {
  ledStatus(1);
  digitalWrite(DOORPIN, HIGH);
  delay(DOOROPENTIME);     // duration of door opener in ms
  digitalWrite(DOORPIN, LOW);
  ledStatus(0);
}

void ledStatus(int led_code) {
  switch (led_code) {
  case 0:    // off
    digitalWrite(LEDPIN, LOW);
    break;
  case 1:    // on
    digitalWrite(LEDPIN, HIGH);
    break;
  case 2:    // error_passwd
    for(unsigned short m = 0; m <= 4; m++){
      for(unsigned short n = 0; n <= 3; n++){
        digitalWrite(LEDPIN, HIGH);
        delay(50);
        digitalWrite(LEDPIN, LOW);
        delay(25);
      }
      delay(250);
    }
    break;
  case 3:    // error_auth
    for(unsigned short m = 0; m <= 3; m++){
      for(unsigned short n = 0; n <= 3; n++){
        digitalWrite(LEDPIN, HIGH);
        delay(50);
        digitalWrite(LEDPIN, LOW);
        delay(25);
      }
      delay(250);
    }
    break;
  case 4:    // error_unknown_tag
    for(unsigned short m = 0; m <= 1; m++){
      for(unsigned short n = 0; n <= 3; n++){
        digitalWrite(LEDPIN, HIGH);
        delay(50);
        digitalWrite(LEDPIN, LOW);
        delay(25);
      }
      delay(250);
    }
    break;
  case 5:    // error_tag_typ
    for(unsigned short m = 0; m <= 2; m++){
      for(unsigned short n = 0; n <= 3; n++){
        digitalWrite(LEDPIN, HIGH);
        delay(50);
        digitalWrite(LEDPIN, LOW);
        delay(25);
      }
      delay(250);
    }
    break;
  case 6:    // bootup
    for(unsigned short n = 0; n <= 4; n++){
      digitalWrite(LEDPIN, HIGH);
      delay(120);
      digitalWrite(LEDPIN, LOW);
      delay(120);
    }
    break;
  case 9:   // fading
    if(led.cycle <= 0){
      analogWrite(LEDPIN, led.brightness);
      led.brightness = led.brightness + led.fadeAmount;
      if(led.brightness <= 0 || led.brightness >= 64)
        led.fadeAmount = -led.fadeAmount;
      if (led.fadeAmount < 0)
        led.cycle = 1000;
      if(led.fadeAmount > 0)
        led.cycle = 3000;
    }
    led.cycle--;
    break;
  }
}

void debugMeassage(const char *message){
  if (Serial.available() > 0) {
    int incomingByte = Serial.read();
    if (incomingByte == 'd') {
      debug = true;
      Serial.println("Debug mode: ON (type any key to disable)");      
    }
    else {
      debug = false;
      Serial.println("Debug mode: OFF (type 'd' to enable)");
    }
  }
  if(debug == true){
    Serial.println(message);
  }
}
