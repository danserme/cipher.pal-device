#include <Adafruit_NeoPixel.h>
#include <PulseSensorPlayground.h>
#include <Adafruit_SPIFlash.h>
#include <ArduinoJson.h>
#include <RTCZero.h>
#include <Crypto.h>
#include <AES.h>
#include <SHA256.h>

int minHB = 0, maxHB = 0, avgHB = 0, beats = 0, times = 0, id = 0;

#define WALLET_DATA_ADDR 0            
#define WALLET_CONFIG_ADDR 8388608    
#define WALLET_KEY_SIZE 42            
#define SYMMETRIC_KEY_ADDR (8388608 + 512)
#define SYMMETRIC_KEY_SIZE 64            
char walletKey[WALLET_KEY_SIZE + 1];   
uint8_t symmetricKey[SYMMETRIC_KEY_SIZE];
bool hasStoredWallet = false;
bool hasStoredSymmetricKey = false;

uint8_t randomAESKey[32];
bool hasGeneratedSessionKey = false;

byte iv[16];
bool hasInitializedEncryption = false;

RTCZero rtc;
const byte seconds = 0, minutes = 22, hours = 13;
const byte day = 12, month = 2, year = 25;

#define PIN 11
#define NUMPIXELS 1
Adafruit_NeoPixel strip(NUMPIXELS, PIN, NEO_GRB + NEO_KHZ800);

#define CLK 0
#define DT 1
#define SW 2

int counterCCW = 0, counterCW = 0, counterP = 0;
int currentStateCLK, lastStateCLK;
unsigned long lastButtonPress = 0, firstActivityTime = 0, duration = 0, lastActivityTime = 0;
const long timeout = 5000;

String received, startTime, endTime, curDate;
bool showed = false;

const int PulseWire1 = A3;
const int PulseWire2 = A10;
int Threshold = 550;
PulseSensorPlayground pulseSensor1;
PulseSensorPlayground pulseSensor2;

#define PIN_FLASH_CS 17
Adafruit_FlashTransport_SPI flashTransport(PIN_FLASH_CS, SPI1);
Adafruit_SPIFlash flash(&flashTransport);
uint32_t address = WALLET_DATA_ADDR;
uint32_t currentAddress = address;
int memorySize = 0;

void generateSessionKey() {
  for (int i = 0; i < 32; i++) {
    randomAESKey[i] = (uint8_t)random(256);
  }
  for (int i = 0; i < 16; i++) {
    iv[i] = randomAESKey[i];
  }
  hasGeneratedSessionKey = true;
  Serial.println("Generated new session encryption key");
}

bool checkStoredSymmetricKey() {
  uint8_t buffer[SYMMETRIC_KEY_SIZE];
  flash.readBuffer(SYMMETRIC_KEY_ADDR, buffer, SYMMETRIC_KEY_SIZE);
  bool valid = false;
  for (int i = 0; i < SYMMETRIC_KEY_SIZE; i++) {
    if (buffer[i] != 0 && buffer[i] != 0xFF) {
      valid = true;
      break;
    }
  }
  if (valid) {
    memcpy(symmetricKey, buffer, SYMMETRIC_KEY_SIZE);
    hasStoredSymmetricKey = true;
    Serial.println("Valid symmetric key found in storage");
    return true;
  }
  Serial.println("No valid symmetric key found");
  return false;
}

void initializeEncryption() {
  if (!hasStoredSymmetricKey) {
    Serial.println("Cannot initialize encryption without symmetric key");
    return;
  }
  generateSessionKey();
  hasInitializedEncryption = true;
  Serial.println("Asymmetric encryption initialized");
}

String encryptString(const String& input) {
  uint8_t aesKey[32];
  SHA256 sha256;
  const char* secretPhrase = "biotech_shared_key_";
  sha256.update((uint8_t*)secretPhrase, strlen(secretPhrase));
  sha256.update(symmetricKey, SYMMETRIC_KEY_SIZE);
  sha256.finalize(aesKey, sizeof(aesKey));

  for (int i = 0; i < 16; i++) {
    iv[i] = (uint8_t)random(256);
  }
  
  size_t inputLength = input.length();
  size_t paddedLength = ((inputLength + 15) / 16) * 16;
  byte* inputBuffer = new byte[paddedLength];
  memset(inputBuffer, 0, paddedLength);
  memcpy(inputBuffer, input.c_str(), inputLength);
  
  byte paddingValue = paddedLength - inputLength;
  for (size_t i = inputLength; i < paddedLength; i++) {
    inputBuffer[i] = paddingValue;
  }
  
  AES256 aes;
  aes.setKey(aesKey, 32);
  byte prevBlock[16];
  memcpy(prevBlock, iv, 16);
  for (size_t i = 0; i < paddedLength; i += 16) {
    for (int j = 0; j < 16; j++) {
      inputBuffer[i + j] ^= prevBlock[j];
    }
    aes.encryptBlock(inputBuffer + i, inputBuffer + i);
    memcpy(prevBlock, inputBuffer + i, 16);
  }
  
  String hexOutput = "";
  for (int i = 0; i < 16; i++) {
    char hex[3];
    sprintf(hex, "%02X", iv[i]);
    hexOutput += hex;
  }
  for (size_t i = 0; i < paddedLength; i++) {
    char hex[3];
    sprintf(hex, "%02X", inputBuffer[i]);
    hexOutput += hex;
  }
  
  delete[] inputBuffer;
  return hexOutput;
}

enum State {
  WAITING_FOR_WALLET,
  COLLECT,
  AUTHENTICATE,
  REGISTER_WALLET,
  SEND,
  DELETE
};
State currentState = WAITING_FOR_WALLET;

void initializeDataStructure() {
  byte buffer[256];
  memset(buffer, 0, sizeof(buffer));
  flash.readBuffer(address, buffer, sizeof(buffer));
  DynamicJsonDocument doc(256);
  DeserializationError error = deserializeJson(doc, buffer);
  if (error || !doc.containsKey("data")) {
    DynamicJsonDocument initDoc(256);
    initDoc.createNestedArray("data");
    memset(buffer, 0, sizeof(buffer));
    size_t bytesWritten = serializeJson(initDoc, buffer, sizeof(buffer));
    flash.eraseSector(address);
    if (flash.writeBuffer(address, buffer, bytesWritten)) {
      currentAddress = address + bytesWritten;
    }
  }
}

void setup() {
  strip.begin();
  Serial.begin(115200);
  while (!Serial) delay(10);
  delay(500);
  Serial.println("Serial started");

  rtc.begin();
  rtc.setTime(hours, minutes, seconds);
  rtc.setDate(day, month, year);

  pinMode(CLK, INPUT);
  pinMode(DT, INPUT);
  pinMode(SW, INPUT_PULLUP);
  lastStateCLK = digitalRead(CLK);

  pulseSensor1.analogInput(PulseWire1);
  pulseSensor1.setThreshold(Threshold);
  pulseSensor1.begin();

  pulseSensor2.analogInput(PulseWire2);
  pulseSensor2.setThreshold(Threshold);
  pulseSensor2.begin();

  if (!flash.begin()) {
    Serial.println("Could not find a valid SPI flash chip!");
  } else {
    memorySize = flash.size() / 1024;
    Serial.print("JEDEC ID: 0x");
    Serial.println(flash.getJEDECID(), HEX);
    Serial.print("Flash size: ");
    Serial.print(memorySize);
    Serial.println(" KB");

    checkStoredWallet();
    checkStoredSymmetricKey();

    if (hasStoredWallet && hasStoredSymmetricKey) {
      currentState = COLLECT;
      initializeEncryption();
      strip.setPixelColor(0, strip.Color(0, 255, 0));
      strip.show();
      initializeDataStructure();
    } else {
      currentState = WAITING_FOR_WALLET;
      strip.setPixelColor(0, strip.Color(255, 0, 0));
      strip.show();
    }
  }
}

void loop() {
  if (Serial.available()) {
    received = Serial.readStringUntil('\n');
    Serial.println(received);

    if (received == "C") {
      currentState = AUTHENTICATE;
    } else if (received == "S") {
      currentState = SEND;
    } else if (received == "D") {
      currentState = DELETE;
    } else if (received.startsWith("W:")) {
      String walletAddress = received.substring(2);
      currentState = REGISTER_WALLET;
      storeWalletAddress(walletAddress);
    } else if (received.startsWith("P:")) {
      String symmetricKeyHex = received.substring(2);
      storeSymmetricKey(symmetricKeyHex);
    } else if (received.startsWith("T:")) {
      updateDateTime(received.substring(2));
    } else {
      currentState = (hasStoredWallet && hasStoredSymmetricKey) ? COLLECT : WAITING_FOR_WALLET;
    }
  }

  switch (currentState) {
    case WAITING_FOR_WALLET: waitingForWallet(); break;
    case COLLECT: collect(); break;
    case AUTHENTICATE: authenticate(); break;
    case REGISTER_WALLET: delay(100); break;
    case SEND: send(counterCCW); break;
    case DELETE:
      clear();
      currentState = (hasStoredWallet && hasStoredSymmetricKey) ? COLLECT : WAITING_FOR_WALLET;
      break;
  }
}

void waitingForWallet() {
  strip.setPixelColor(0, strip.Color(255, 255, 0));
  strip.show();
  if (digitalRead(SW) == LOW && millis() - lastButtonPress > 500) {
    lastButtonPress = millis();
    currentState = AUTHENTICATE;
  }
}

void authenticate() {
  Serial.println("Checking account");
  strip.setPixelColor(0, strip.Color(255, 255, 0));
  strip.show();
  if (hasStoredWallet) {
    Serial.print("Y:");
    Serial.println(walletKey);
    Serial.println(hasStoredSymmetricKey ? "SYMKEY_OK" : "SYMKEY:NEEDED");
    currentState = hasStoredSymmetricKey ? COLLECT : WAITING_FOR_WALLET;
  } else {
    Serial.println("N");
    currentState = WAITING_FOR_WALLET;
  }
}

bool isValidEthereumAddress(const char* address) {
  if (strlen(address) != 42 || address[0] != '0' || address[1] != 'x') return false;
  for (int i = 2; i < 42; i++) {
    char c = address[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
      return false;
  }
  return true;
}

bool hexStringToBytes(const String& hexString, uint8_t* byteArray, size_t length) {
  if (hexString.length() != length * 2) return false;
  for (size_t i = 0; i < length; i++) {
    String byteString = hexString.substring(i * 2, i * 2 + 2);
    byteArray[i] = (uint8_t)strtol(byteString.c_str(), NULL, 16);
  }
  return true;
}

void checkStoredWallet() {
  char buffer[WALLET_KEY_SIZE + 1];
  memset(buffer, 0, sizeof(buffer));
  flash.readBuffer(WALLET_CONFIG_ADDR, (uint8_t*)buffer, WALLET_KEY_SIZE);
  buffer[WALLET_KEY_SIZE] = '\0';
  if (isValidEthereumAddress(buffer)) {
    strncpy(walletKey, buffer, WALLET_KEY_SIZE + 1);
    hasStoredWallet = true;
    Serial.print("Stored wallet found: ");
    Serial.println(walletKey);
  } else {
    hasStoredWallet = false;
    Serial.println("No stored wallet found or invalid wallet format");
    Serial.print("First bytes read: ");
    for (int i = 0; i < 10 && i < WALLET_KEY_SIZE; i++) {
      Serial.print((uint8_t)buffer[i], HEX);
      Serial.print(" ");
    }
    Serial.println();
  }
}

void storeWalletAddress(String address) {
  if (address.length() > 0 && address.length() <= WALLET_KEY_SIZE) {
    char buffer[WALLET_KEY_SIZE + 1];
    memset(buffer, 0, sizeof(buffer));
    address.toCharArray(buffer, WALLET_KEY_SIZE + 1);
    flash.eraseSector(WALLET_CONFIG_ADDR);
    delay(100);
    if (flash.writeBuffer(WALLET_CONFIG_ADDR, (uint8_t*)buffer, WALLET_KEY_SIZE)) {
      strncpy(walletKey, buffer, WALLET_KEY_SIZE + 1);
      hasStoredWallet = true;
      strip.setPixelColor(0, strip.Color(0, 255, 0));
      strip.show();
      Serial.print("Wallet address stored: ");
      Serial.println(walletKey);
      Serial.println("NEED_SYMKEY");
      Serial.print("OK");
      delay(100);
      currentState = WAITING_FOR_WALLET;
    } else {
      strip.setPixelColor(0, strip.Color(255, 0, 0));
      strip.show();
      Serial.println("Failed to write wallet address to flash");
      currentState = WAITING_FOR_WALLET;
    }
  } else {
    Serial.println("Invalid wallet address length");
    currentState = WAITING_FOR_WALLET;
  }
}

void storeSymmetricKey(String symmetricKeyHex) {
  if (symmetricKeyHex.length() == SYMMETRIC_KEY_SIZE * 2) {
    uint8_t keyBuffer[SYMMETRIC_KEY_SIZE];
    if (hexStringToBytes(symmetricKeyHex, keyBuffer, SYMMETRIC_KEY_SIZE)) {
      flash.eraseSector(SYMMETRIC_KEY_ADDR);
      delay(100);
      if (flash.writeBuffer(SYMMETRIC_KEY_ADDR, keyBuffer, SYMMETRIC_KEY_SIZE)) {
        memcpy(symmetricKey, keyBuffer, SYMMETRIC_KEY_SIZE);
        hasStoredSymmetricKey = true;
        initializeEncryption();
        strip.setPixelColor(0, strip.Color(0, 255, 0));
        strip.show();
        Serial.println("Symmetric key stored successfully");
        Serial.print("SYMKEY_OK");
        delay(500);
        currentState = COLLECT;
        initializeDataStructure();
      } else {
        strip.setPixelColor(0, strip.Color(255, 0, 0));
        strip.show();
        Serial.println("Failed to write symmetric key to flash");
        currentState = WAITING_FOR_WALLET;
      }
    } else {
      Serial.println("Invalid symmetric key format");
      currentState = WAITING_FOR_WALLET;
    }
  } else {
    Serial.println("Invalid symmetric key length");
    currentState = WAITING_FOR_WALLET;
  }
}

void collect() {
  if (!hasStoredWallet || !hasStoredSymmetricKey) {
    currentState = WAITING_FOR_WALLET;
    return;
  }
  unsigned long currentMillis = millis();
  strip.setPixelColor(0, strip.Color(0, 0, 255));
  strip.show();
  
  currentStateCLK = digitalRead(CLK);
  if (currentStateCLK != lastStateCLK && currentStateCLK == 1) {
    setActive();
    if (digitalRead(DT) != currentStateCLK) {
      counterCW++;
      Serial.println("cw");
    } else {
      counterCCW++;
      Serial.println("ccw");
    }
    heartBeat(1);
    lastActivityTime = currentMillis;
  }
  lastStateCLK = currentStateCLK;

  if (digitalRead(SW) == LOW) {
    setActive();
    if (millis() - lastButtonPress > 500) {
      lastButtonPress = millis();
      counterP++;
      Serial.println("check P");
    }
    heartBeat(2);
    lastActivityTime = currentMillis;
  }

  if ((currentMillis - lastActivityTime) > timeout && (counterP || counterCW || counterCCW)) {
    endSession();
  }

  if (!counterP && !counterCW && !counterCCW) {
    startTime = getTime();
    curDate = getDate();
  }
}

void send(int count) {
  if (!hasStoredWallet || !hasStoredSymmetricKey) {
    Serial.println("Missing wallet or symmetric key configuration. Cannot send data.");
    strip.setPixelColor(0, strip.Color(255, 0, 0));
    strip.show();
    delay(1000);
    currentState = WAITING_FOR_WALLET;
    return;
  }
  strip.setPixelColor(0, strip.Color(0, 255, 0));
  strip.show();
  if (!showed) {
    logFileData();
    showed = true;
  }
}

void clear() {
  strip.setPixelColor(0, strip.Color(255, 0, 0));
  strip.show();
  showed = false;
  id = 0;
  delay(50);
  flash.eraseSector(address);
  initializeDataStructure();
  hasGeneratedSessionKey = false;
  logFileData();
}

int readPulse(int sensorNumber) {
  if (sensorNumber == 1 && pulseSensor1.sawStartOfBeat())
    return pulseSensor1.getBeatsPerMinute();
  if (sensorNumber == 2 && pulseSensor2.sawStartOfBeat())
    return pulseSensor2.getBeatsPerMinute();
  return 0;
}

void heartBeat(int sensorNumber) {
  int hb = readPulse(sensorNumber);
  if (hb > 0) {
    times++;
    beats += hb;
    if (!minHB && !maxHB) {
      minHB = hb;
      maxHB = hb;
    } else if (hb > maxHB) {
      maxHB = hb;
    } else if (hb < minHB) {
      minHB = hb;
    }
    avgHB = beats / times;
  }
  Serial.print("avg:");
  Serial.print(avgHB);
  Serial.print(" max:");
  Serial.print(maxHB);
  Serial.print(" min:");
  Serial.print(minHB);
  Serial.print(" sensor:");
  Serial.println(sensorNumber);
}

void writeFile() {
  if (!hasStoredWallet || !hasStoredSymmetricKey) {
    Serial.println("Incomplete crypto setup. Cannot save data.");
    return;
  }
  generateSessionKey();
  DynamicJsonDocument sessionDoc(1024);
  sessionDoc["date"] = curDate;
  sessionDoc["startTime"] = startTime;
  sessionDoc["endTime"] = endTime;
  sessionDoc["duration"] = duration;
  sessionDoc["min"] = minHB;
  sessionDoc["max"] = maxHB;
  sessionDoc["avg"] = avgHB;
  sessionDoc["p"] = counterP;
  sessionDoc["ccw"] = counterCCW;
  sessionDoc["cw"] = counterCW;
  sessionDoc["id"] = id;

  String sessionString;
  serializeJson(sessionDoc, sessionString);
  Serial.print("Session JSON: ");
  Serial.println(sessionString);

  String encryptedSession = encryptString(sessionString);
  Serial.print("Encrypted session (hex): ");
  Serial.println(encryptedSession.substring(0, 40) + "...");

  DynamicJsonDocument mainDoc(8192);
  byte buffer[8192];
  memset(buffer, 0, sizeof(buffer));
  flash.readBuffer(address, buffer, sizeof(buffer));
  DeserializationError error = deserializeJson(mainDoc, buffer);
  if (error) {
    mainDoc.clear();
    mainDoc.createNestedArray("data");
  }

  JsonArray data = mainDoc["data"];
  if (data.isNull()) {
    data = mainDoc.createNestedArray("data");
  }
  JsonObject newEntry = data.createNestedObject();
  newEntry["encrypted"] = true;
  newEntry["data"] = encryptedSession;

  memset(buffer, 0, sizeof(buffer));
  size_t bytesWritten = serializeJson(mainDoc, buffer, sizeof(buffer));
  flash.eraseSector(address);
  if (flash.writeBuffer(address, buffer, bytesWritten)) {
    currentAddress = address + bytesWritten;
  } else {
    Serial.println("Failed to write data to flash.");
  }
}

void logFileData() {
  byte buffer[memorySize];
  memset(buffer, 0, sizeof(buffer));
  flash.readBuffer(address, buffer, currentAddress);
  Serial.println((char*)buffer);
}

void endSession() {
  duration = millis() - firstActivityTime;
  endTime = getTime();
  writeFile();
  id++;
  active = false;
  minHB = 0;
  maxHB = 0;
  avgHB = 0;
  beats = 0;
  times = 0;
  counterCCW = 0;
  counterCW = 0;
  counterP = 0;
}

String getTime() {
  return String(rtc.getHours()) + ":" + String(rtc.getMinutes()) + ":" + String(rtc.getSeconds());
}

String getDate() {
  return String(rtc.getDay()) + "." + String(rtc.getMonth()) + "." + String(rtc.getYear());
}

void updateDateTime(String dateTimeStr) {
  strip.setPixelColor(0, strip.Color(255, 165, 0));
  strip.show();
  dateTimeStr.trim();
  if (dateTimeStr.length() < 19) {
    Serial.println("Invalid date/time format. Expected: YYYY-MM-DD HH:MM:SS");
    return;
  }
  int year = dateTimeStr.substring(0, 4).toInt();
  int month = dateTimeStr.substring(5, 7).toInt();
  int day = dateTimeStr.substring(8, 10).toInt();
  int hours = dateTimeStr.substring(11, 13).toInt();
  int minutes = dateTimeStr.substring(14, 16).toInt();
  int seconds = dateTimeStr.substring(17, 19).toInt();
  if (year < 2000 || year > 2099 || month < 1 || month > 12 ||
      day < 1 || day > 31 || hours < 0 || hours > 23 ||
      minutes < 0 || minutes > 59 || seconds < 0 || seconds > 59) {
    Serial.println("Invalid date/time values. Please check your input.");
    return;
  }
  rtc.setTime(hours, minutes, seconds);
  rtc.setDate(day, month, year % 100);
  Serial.print("Date and time updated to: ");
  Serial.print(getDate());
  Serial.print(" ");
  Serial.println(getTime());
  strip.setPixelColor(0, strip.Color(0, 255, 0));
  strip.show();
  delay(500);
  if (currentState == COLLECT) {
    strip.setPixelColor(0, strip.Color(0, 0, 255));
  } else if (currentState == WAITING_FOR_WALLET) {
    strip.setPixelColor(0, strip.Color(255, 255, 0));
  }
  strip.show();
}

void setActive() {
  if (!active) {
    active = true;
    firstActivityTime = millis();
  }
}
