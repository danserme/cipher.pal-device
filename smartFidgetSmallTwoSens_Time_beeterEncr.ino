#include <Adafruit_NeoPixel.h>
#include <PulseSensorPlayground.h>
#include <Adafruit_SPIFlash.h>
#include <SPIMemory.h>
#include <ArduinoJson.h>
#include <RTCZero.h>
#include <Crypto.h>
#include <AES.h>
#include <SHA256.h>
#include <uECC.h>  // Added for elliptic curve cryptography

int minHB = 0, maxHB = 0, avgHB = 0, beats = 0, times = 0, id = 0;

// Flash storage for wallet key and symmetric key
#define WALLET_DATA_ADDR 0             // Main data starts after wallet config
#define WALLET_CONFIG_ADDR 8388608     // Sector for wallet config (8MB offset)
#define WALLET_KEY_SIZE 42             // Ethereum wallet address size (0x + 40 hex chars)
#define SYMMETRIC_KEY_ADDR 8388608 + 512  // Store symmetric key after wallet address
#define SYMMETRIC_KEY_SIZE 64             // Typical size for an ECC symmetric key
char walletKey[WALLET_KEY_SIZE + 1];   // +1 for null terminator
uint8_t symmetricKey[SYMMETRIC_KEY_SIZE];    // Buffer for storing symmetric key
bool hasStoredWallet = false;          // Track if we have a wallet stored
bool hasStoredSymmetricKey = false;       // Track if we have a symmetric key stored

// Random key generator for session encryption
uint8_t randomAESKey[32];             // Random AES key for each session
bool hasGeneratedSessionKey = false;  // Track if we generated a session key

// Encryption related variables
const struct uECC_Curve_t* curve = uECC_secp256k1();  // Use secp256k1 curve (same as Ethereum)
byte iv[16];                                          // Initialization vector for AES
bool hasInitializedEncryption = false;

//Time
RTCZero rtc;
/* Change these values to set the current initial time */
const byte seconds = 0;
const byte minutes = 22;
const byte hours = 13;

/* Change these values to set the current initial date */
const byte day = 12;
const byte month = 2;
const byte year = 25;  // Last two digits of the year

//NeoPixel
#define PIN 11
#define NUMPIXELS 1
Adafruit_NeoPixel strip(NUMPIXELS, PIN, NEO_GRB + NEO_KHZ800);

// Rotary Encoder
#define CLK 0
#define DT 1
#define SW 2

int counterCCW = 0;
int counterCW = 0;
int counterP = 0;
int currentStateCLK;
int lastStateCLK;
String currentDir = "";
unsigned long lastButtonPress = 0;
unsigned long firstActivityTime = 0;
unsigned long duration = 0;
bool active = false;
unsigned long lastActivityTime = 0;  // The last time the button was pressed
const long timeout = 5000;           // Activity timeout period (5 seconds)

enum Action {
  CCW,
  CW,
  P
};

Action act = CCW;

//State of the Device
enum State {
  WAITING_FOR_WALLET,  // New state to indicate waiting for wallet registration
  COLLECT,
  AUTHENTICATE,
  REGISTER_WALLET,
  SEND,
  DELETE
};

State currentState = WAITING_FOR_WALLET;  // Start in waiting state instead of COLLECT

String received, startTime, endTime, curDate;
bool showed = false;  //to track if data was shown to the user in this connection

// Pulse Sensor Inputs - Modified for two sensors
const int PulseWire1 = A3;   // Original sensor for rotary encoder
const int PulseWire2 = A10;  // New sensor for button press
int Threshold = 550;
PulseSensorPlayground pulseSensor1;  // Sensor for rotary encoder
PulseSensorPlayground pulseSensor2;  // Sensor for button press

//Flash memory
#define PIN_FLASH_CS 17
Adafruit_FlashTransport_SPI flashTransport(PIN_FLASH_CS, SPI1);
Adafruit_SPIFlash flash(&flashTransport);
uint32_t address = WALLET_DATA_ADDR;  // Start address for JSON data
uint32_t currentAddress = address;
int memorySize = 0;

// Generate a random AES key for the session
void generateSessionKey() {
  // Use hardware random number generator if available, or fallback to semi-random sources
  for (int i = 0; i < 32; i++) {
    randomAESKey[i] = (uint8_t)random(256);
  }

  // Use first 16 bytes for IV
  for (int i = 0; i < 16; i++) {
    iv[i] = randomAESKey[i];
  }

  hasGeneratedSessionKey = true;
  Serial.println("Generated new session encryption key");
}

// Check for stored symmetric key
bool checkStoredSymmetricKey() {
  uint8_t buffer[SYMMETRIC_KEY_SIZE];
  flash.readBuffer(SYMMETRIC_KEY_ADDR, buffer, SYMMETRIC_KEY_SIZE);

  // Verify the key looks valid (non-zero)
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

// Initialize encryption
void initializeEncryption() {
  if (!hasStoredSymmetricKey) {
    Serial.println("Cannot initialize encryption without symmetric key");
    return;
  }

  // Generate a new random AES key for this session
  generateSessionKey();

  hasInitializedEncryption = true;
  Serial.println("Asymmetric encryption initialized");
}

// Encrypt data using hybrid approach (symmetric key + AES)
String encryptString(const String& input) {
  // Derive the shared AES key from a fixed secret phrase and the stored wallet key.
  // (For example, if walletKey is "0xABCDEF...", then the shared key is SHA256("biotech_shared_key_0xabcdef..."))
  uint8_t aesKey[32];
  SHA256 sha256;
  const char* secretPhrase = "biotech_shared_key_";
  sha256.update((uint8_t*)secretPhrase, strlen(secretPhrase));
  sha256.update(symmetricKey, SYMMETRIC_KEY_SIZE);
  sha256.finalize(aesKey, sizeof(aesKey));

  // Generate a random IV (16 bytes)
  for (int i = 0; i < 16; i++) {
    iv[i] = (uint8_t)random(256);
  }
  
  // Calculate padded length (PKCS#7 padding)
  size_t inputLength = input.length();
  size_t paddedLength = ((inputLength + 15) / 16) * 16;
  byte* inputBuffer = new byte[paddedLength];
  memset(inputBuffer, 0, paddedLength);
  memcpy(inputBuffer, input.c_str(), inputLength);
  
  byte paddingValue = paddedLength - inputLength;
  for (size_t i = inputLength; i < paddedLength; i++) {
    inputBuffer[i] = paddingValue;
  }
  
  // Initialize AES with the derived key
  AES256 aes;
  aes.setKey(aesKey, 32);
  
  // Encrypt in CBC mode using the IV
  byte prevBlock[16];
  memcpy(prevBlock, iv, 16);
  for (size_t i = 0; i < paddedLength; i += 16) {
    // XOR current block with previous ciphertext (or IV for the first block)
    for (int j = 0; j < 16; j++) {
      inputBuffer[i + j] ^= prevBlock[j];
    }
    // Encrypt block
    aes.encryptBlock(inputBuffer + i, inputBuffer + i);
    // Set current block as previous block for next round
    memcpy(prevBlock, inputBuffer + i, 16);
  }
  
  // Build final output: [IV (16 bytes hex)][ciphertext (padded data in hex)]
  String hexOutput = "";
  // Append IV (each byte -> 2 hex chars)
  for (int i = 0; i < 16; i++) {
    char hex[3];
    sprintf(hex, "%02X", iv[i]);
    hexOutput += hex;
  }
  // Append ciphertext
  for (size_t i = 0; i < paddedLength; i++) {
    char hex[3];
    sprintf(hex, "%02X", inputBuffer[i]);
    hexOutput += hex;
  }
  
  delete[] inputBuffer;
  return hexOutput;
}


void setup() {
  strip.begin();
  Serial.begin(115200);
  while (!Serial) {
    delay(10);
  }
  delay(500);
  Serial.println("Serial started");

  //Configure time
  rtc.begin();
  rtc.setTime(hours, minutes, seconds);
  rtc.setDate(day, month, year);

  //Configure Rotary Encoder
  pinMode(CLK, INPUT);
  pinMode(DT, INPUT);
  pinMode(SW, INPUT_PULLUP);
  lastStateCLK = digitalRead(CLK);
  Serial.println("Rotary encoder started");

  // Configure both PulseSensor objects
  pulseSensor1.analogInput(PulseWire1);
  pulseSensor1.setThreshold(Threshold);
  pulseSensor1.begin();

  pulseSensor2.analogInput(PulseWire2);
  pulseSensor2.setThreshold(Threshold);
  pulseSensor2.begin();

  if (pulseSensor1.begin() && pulseSensor2.begin()) {
    Serial.println("We created two PulseSensor Objects!");
  }

  //Configure Flash Chip
  if (!flash.begin()) {
    Serial.println("Could not find a valid SPI flash chip!");
  } else {
    Serial.println("Found SPI flash chip!");
    memorySize = flash.size() / 1024;
    Serial.print("JEDEC ID: 0x");
    Serial.println(flash.getJEDECID(), HEX);
    Serial.print("Flash size: ");
    Serial.print(flash.size() / 1024);
    Serial.println(" KB");

    // Check if wallet key and symmetric key exist in flash
    checkStoredWallet();
    checkStoredSymmetricKey();

    // Set the initial state based on wallet and symmetric key presence
    if (hasStoredWallet && hasStoredSymmetricKey) {
      currentState = COLLECT;
      Serial.println("Wallet and symmetric key found, ready to collect data");

      // Initialize encryption
      initializeEncryption();

      // Show green light to indicate ready to collect
      strip.setPixelColor(0, strip.Color(0, 255, 0));
      strip.show();

      // Only initialize data structure if we have a wallet
      initializeDataStructure();
    } else {
      currentState = WAITING_FOR_WALLET;
      Serial.println("No wallet or symmetric key configured. Please set wallet first.");
      // Start with red light to indicate no wallet
      strip.setPixelColor(0, strip.Color(255, 0, 0));
      strip.show();
    }
  }
}

// Function to ensure we have a valid data structure in flash
void initializeDataStructure() {
  byte buffer[256];  // Small buffer to check structure
  memset(buffer, 0, sizeof(buffer));

  // Read the beginning of flash
  flash.readBuffer(address, buffer, sizeof(buffer));

  // Try parsing as JSON
  DynamicJsonDocument doc(256);
  DeserializationError error = deserializeJson(doc, buffer);

  // If not valid JSON or no data array, initialize structure
  if (error || !doc.containsKey("data")) {
    Serial.println("Initializing data structure...");
    DynamicJsonDocument initDoc(256);
    initDoc.createNestedArray("data");  // Create empty data array

    // Serialize and write
    memset(buffer, 0, sizeof(buffer));
    size_t bytesWritten = serializeJson(initDoc, buffer, sizeof(buffer));

    flash.eraseSector(address);
    if (flash.writeBuffer(address, buffer, bytesWritten)) {
      Serial.println("Data structure initialized");
      currentAddress = address + bytesWritten;
    } else {
      Serial.println("Failed to initialize data structure");
    }
  }
}

void loop() {
  static String serialCommand;
  if (Serial.available()) {
    received = Serial.readStringUntil('\n');
    Serial.println(received);

    if (received == "C") {  // C for Connection request
      // Respond with either Y (has wallet) or N (needs wallet)
      currentState = AUTHENTICATE;
    } else if (received == "S") {  // S for Send data
      currentState = SEND;
    } else if (received == "D") {  // D for Disconnect
      currentState = DELETE;
    } else if (received.startsWith("W:")) {  // W: prefix for wallet address
      // Store the wallet address and expect symmetric key next
      String walletAddress = received.substring(2);  // Remove "W:" prefix
      currentState = REGISTER_WALLET;                // Change to registration state
      storeWalletAddress(walletAddress);
    } else if (received.startsWith("P:")) {  // P: prefix for symmetric key
      // Store the symmetric key
      String symmetricKeyHex = received.substring(2);  // Remove "P:" prefix
      storeSymmetricKey(symmetricKeyHex);
    } else if (received.startsWith("T:")) {  // T: prefix for time/date update
      // Update the date and time
      updateDateTime(received.substring(2));  // Remove "T:" prefix
      // Continue with current state
    } else {
      // Only change to COLLECT if we have a wallet and symmetric key
      if (hasStoredWallet && hasStoredSymmetricKey) {
        currentState = COLLECT;
      } else {
        currentState = WAITING_FOR_WALLET;
      }
    }
  }

  switch (currentState) {
    case WAITING_FOR_WALLET:
      waitingForWallet();
      break;
    case COLLECT:
      collect();
      break;
    case AUTHENTICATE:
      authenticate();
      break;
    case REGISTER_WALLET:  // Handle registration state
      // Just wait here - storeWalletAddress will send the OK
      delay(100);  // Small delay to ensure serial communications are stable
      break;
    case SEND:
      send(counterCCW);
      break;
    case DELETE:
      clear();
      // After deletion, check if wallet and symmetric key exist before continuing collection
      if (hasStoredWallet && hasStoredSymmetricKey) {
        currentState = COLLECT;
      } else {
        currentState = WAITING_FOR_WALLET;
      }
      break;
  }
}

void waitingForWallet() {
  strip.setPixelColor(0, strip.Color(255, 255, 0));
  strip.show();

  // Check for button press to initiate authentication manually
  int btnState = digitalRead(SW);
  if (btnState == LOW) {
    if (millis() - lastButtonPress > 500) {
      lastButtonPress = millis();
      // Switch to authenticate state when button is pressed
      currentState = AUTHENTICATE;
    }
  }
}

void authenticate() {
  Serial.println("Checking");
  strip.setPixelColor(0, strip.Color(255, 255, 0));
  strip.show();
  Serial.println("Account");

  if (hasStoredWallet) {
    Serial.print("Y:");  // Yes, we have a stored wallet
    Serial.println(walletKey);

    // Also indicate if we have a symmetric key
    if (hasStoredSymmetricKey) {
      Serial.println("SYMKEY_OK");
    } else {
      Serial.println("SYMKEY:NEEDED");
    }

    // After a successful authentication, return to collection state if we have both keys
    if (hasStoredSymmetricKey) {
      currentState = COLLECT;
    } else {
      currentState = WAITING_FOR_WALLET;
    }
  } else {
    Serial.println("N");  // No, we need a wallet address
    // Stay in waiting state until we get a wallet
    currentState = WAITING_FOR_WALLET;
  }
}

// Function to check if a string is a valid Ethereum address
bool isValidEthereumAddress(const char* address) {
  // Ethereum address must be 42 characters (0x + 40 hex chars)
  if (strlen(address) != 42) {
    return false;
  }

  // Must start with "0x"
  if (address[0] != '0' || address[1] != 'x') {
    return false;
  }

  // Remaining characters must be valid hex (0-9, a-f, A-F)
  for (int i = 2; i < 42; i++) {
    char c = address[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
      return false;
    }
  }

  return true;
}

// Function to convert hex string to byte array
bool hexStringToBytes(const String& hexString, uint8_t* byteArray, size_t length) {
  if (hexString.length() != length * 2) {
    return false;
  }

  for (size_t i = 0; i < length; i++) {
    String byteString = hexString.substring(i * 2, i * 2 + 2);
    byteArray[i] = (uint8_t)strtol(byteString.c_str(), NULL, 16);
  }

  return true;
}

void checkStoredWallet() {
  // Create a buffer to read wallet data from flash
  char buffer[WALLET_KEY_SIZE + 1];
  memset(buffer, 0, sizeof(buffer));

  // Read the wallet data from flash memory
  flash.readBuffer(WALLET_CONFIG_ADDR, (uint8_t*)buffer, WALLET_KEY_SIZE);

  // Make sure the string is null-terminated
  buffer[WALLET_KEY_SIZE] = '\0';

  // Check if it's a valid Ethereum wallet address
  if (isValidEthereumAddress(buffer)) {
    // Copy into our wallet key variable
    strncpy(walletKey, buffer, WALLET_KEY_SIZE + 1);
    hasStoredWallet = true;

    Serial.print("Stored wallet found: ");
    Serial.println(walletKey);
  } else {
    hasStoredWallet = false;
    Serial.println("No stored wallet found or invalid wallet format");

    // Print the first few bytes for debugging
    Serial.print("First bytes read: ");
    for (int i = 0; i < 10 && i < WALLET_KEY_SIZE; i++) {
      Serial.print((uint8_t)buffer[i], HEX);
      Serial.print(" ");
    }
    Serial.println();
  }
}

void storeWalletAddress(String address) {
  // Store wallet address in flash memory
  if (address.length() > 0 && address.length() <= WALLET_KEY_SIZE) {
    // Create a buffer for the wallet address
    char buffer[WALLET_KEY_SIZE + 1];
    memset(buffer, 0, sizeof(buffer));

    // Copy the address to the buffer
    address.toCharArray(buffer, WALLET_KEY_SIZE + 1);

    // Erase the sector and write the wallet address
    flash.eraseSector(WALLET_CONFIG_ADDR);
    delay(100);  // Add delay after flash erase

    if (flash.writeBuffer(WALLET_CONFIG_ADDR, (uint8_t*)buffer, WALLET_KEY_SIZE)) {
      // Update local variable
      strncpy(walletKey, buffer, WALLET_KEY_SIZE + 1);
      hasStoredWallet = true;

      // Visual confirmation
      strip.setPixelColor(0, strip.Color(0, 255, 0));  // Green for success
      strip.show();

      Serial.print("Wallet address stored: ");
      Serial.println(walletKey);

      // Ask for symmetric key
      Serial.println("NEED_SYMKEY");

      // Send OK without newline for exact matching
      Serial.print("OK");
      delay(100);  // Small delay to ensure message is sent

      // Stay in waiting state until we get the symmetric key
      currentState = WAITING_FOR_WALLET;
    } else {
      // Visual error indication
      strip.setPixelColor(0, strip.Color(255, 0, 0));  // Red for failure
      strip.show();

      Serial.println("Failed to write wallet address to flash");
      currentState = WAITING_FOR_WALLET;
    }
  } else {
    Serial.println("Invalid wallet address length");
    currentState = WAITING_FOR_WALLET;
  }
}

// New function to store symmetric key
void storeSymmetricKey(String symmetricKeyHex) {
  // Validate and store symmetric key
  if (symmetricKeyHex.length() == SYMMETRIC_KEY_SIZE * 2) {  // Hex string is twice the byte length
    uint8_t keyBuffer[SYMMETRIC_KEY_SIZE];

    // Convert hex string to bytes
    if (hexStringToBytes(symmetricKeyHex, keyBuffer, SYMMETRIC_KEY_SIZE)) {
      // Erase sector and write symmetric key
      flash.eraseSector(SYMMETRIC_KEY_ADDR);
      delay(100);  // Add delay after flash erase

      if (flash.writeBuffer(SYMMETRIC_KEY_ADDR, keyBuffer, SYMMETRIC_KEY_SIZE)) {
        // Update local variable
        memcpy(symmetricKey, keyBuffer, SYMMETRIC_KEY_SIZE);
        hasStoredSymmetricKey = true;

        // Initialize encryption with the new symmetric key
        initializeEncryption();

        // Visual confirmation
        strip.setPixelColor(0, strip.Color(0, 255, 0));  // Green for success
        strip.show();

        Serial.println("Symmetric key stored successfully");

        // Send OK confirmation
        Serial.print("SYMKEY_OK");

        // Transition to COLLECT state now that we have both wallet and symmetric key
        delay(500);
        currentState = COLLECT;

        // Initialize data structure
        initializeDataStructure();
      } else {
        // Visual error indication
        strip.setPixelColor(0, strip.Color(255, 0, 0));  // Red for failure
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
  // First, verify we have a wallet and symmetric key - failsafe to prevent collection without proper setup
  if (!hasStoredWallet || !hasStoredSymmetricKey) {
    currentState = WAITING_FOR_WALLET;
    return;
  }

  unsigned long currentMillis = millis();
  strip.setPixelColor(0, strip.Color(0, 0, 255));  // Blue during active collection
  strip.show();

  // Read the current state of CLK
  currentStateCLK = digitalRead(CLK);

  // If last and current state of CLK are different, then pulse occurred
  // React to only 1 state change to avoid double count
  if (currentStateCLK != lastStateCLK && currentStateCLK == 1) {
    // If the DT state is different than the CLK state then
    // the encoder is rotating CCW so decrement
    setActive();
    if (digitalRead(DT) != currentStateCLK) {
      counterCW++;
      act = CW;
      Serial.println("cw");
    } else {
      // Encoder is rotating CCW so increment
      counterCCW++;
      act = CCW;
      Serial.println("ccw");
    }
    heartBeat(1);  // Use sensor 1 (on A3) for rotary encoder rotation
    lastActivityTime = currentMillis;
  }

  // Remember last CLK state
  lastStateCLK = currentStateCLK;

  int btnState = digitalRead(SW);
  if (btnState == LOW) {
    setActive();
    //if 50ms have passed since last LOW pulse, it means that the
    //button has been pressed, released and pressed again
    if (millis() - lastButtonPress > 500) {
      // Remember last button press event
      lastButtonPress = millis();
      counterP++;
      act = P;
      Serial.println("check P");
    }
    heartBeat(2);  // Use sensor 2 (on A11) for button press
    lastActivityTime = currentMillis;
  }

  if ((currentMillis - lastActivityTime) > timeout && counterP > 0) {
    endSession();
  } else if ((currentMillis - lastActivityTime) > timeout && counterCW > 0) {
    endSession();
  } else if ((currentMillis - lastActivityTime) > timeout && counterCCW > 0) {
    endSession();
  }

  if (!counterP && !counterCW && !counterCCW) {
    startTime = getTime();
    curDate = getDate();
  }
}

void send(int count) {
  // Check if we have a wallet and symmetric key before sending data
  if (!hasStoredWallet || !hasStoredSymmetricKey) {
    Serial.println("Missing wallet or symmetric key configuration. Cannot send data.");
    strip.setPixelColor(0, strip.Color(255, 0, 0));  // Red for error
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

  // Re-initialize the data structure
  initializeDataStructure();

  // Reset the session key for the next session
  hasGeneratedSessionKey = false;

  // Log the (now empty) data
  logFileData();
}

// Modified to accept a sensor number parameter
int readPulse(int sensorNumber) {
  if (sensorNumber == 1) {
    // Use first pulse sensor (rotary encoder)
    if (pulseSensor1.sawStartOfBeat()) {
      return pulseSensor1.getBeatsPerMinute();
    }
  } else {
    // Use second pulse sensor (button press)
    if (pulseSensor2.sawStartOfBeat()) {
      return pulseSensor2.getBeatsPerMinute();
    }
  }
  return 0;  // Return 0 if no beat detected
}

// Modified heartBeat function that accepts sensor number
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

//the function to write the values of the session
void writeFile() {
  // Safety check - don't write data if no proper cryptographic setup
  if (!hasStoredWallet || !hasStoredSymmetricKey) {
    Serial.println("Incomplete crypto setup. Cannot save data.");
    return;
  }

  // Make sure a new session key is generated for each session
  generateSessionKey();

  // First, create a JSON document for just this session
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

  // Serialize the session to a string
  String sessionString;
  serializeJson(sessionDoc, sessionString);

  Serial.print("Session JSON: ");
  Serial.println(sessionString);

  // Encrypt the session data with the hybrid approach
  String encryptedSession = encryptString(sessionString);

  Serial.print("Encrypted session (hex): ");
  Serial.println(encryptedSession.substring(0, 40) + "...");

  // Now read the main data structure from flash
  DynamicJsonDocument mainDoc(8192);  // Make sure this is large enough for your needs
  byte buffer[8192];
  memset(buffer, 0, sizeof(buffer));

  // Read existing JSON from flash
  flash.readBuffer(address, buffer, sizeof(buffer));
  DeserializationError error = deserializeJson(mainDoc, buffer);

  if (error) {
    Serial.print(F("deserializeJson() failed: "));
    Serial.println(error.c_str());
    // Reinitialize the document
    mainDoc.clear();
    mainDoc.createNestedArray("data");
  }

  // Get the data array
  JsonArray data = mainDoc["data"];
  if (data.isNull()) {
    data = mainDoc.createNestedArray("data");
  }

  // Add the encrypted session as a new object
  JsonObject newEntry = data.createNestedObject();
  newEntry["encrypted"] = true;
  newEntry["data"] = encryptedSession;

  // Serialize the main document back to the buffer
  memset(buffer, 0, sizeof(buffer));
  size_t bytesWritten = serializeJson(mainDoc, buffer, sizeof(buffer));

  // Write back to flash
  flash.eraseSector(address);
  if (flash.writeBuffer(address, buffer, bytesWritten)) {
    Serial.println(F("Data written to flash successfully."));
    currentAddress = address + bytesWritten;
  } else {
    Serial.println(F("Failed to write data to flash."));
  }
}

void logFileData() {
  byte buffer[memorySize];            // Ensure this buffer is large enough for your data
  memset(buffer, 0, sizeof(buffer));  // Clear the buffer

  // Read the data back from flash
  flash.readBuffer(address, buffer, currentAddress);
  // Serial.println(F("Data read from flash: "));
  Serial.println((char*)buffer);
}

void endSession() {
  // Serial.println("Session ended");
  duration = millis() - firstActivityTime;
  endTime = getTime();

  // Write the session data
  writeFile();

  // Increment ID for next session
  id++;

  // Reset session data
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
  String time = String(rtc.getHours()) + ":" + String(rtc.getMinutes()) + ":" + String(rtc.getSeconds());
  return time;
}

String getDate() {
  String date = String(rtc.getDay()) + "." + String(rtc.getMonth()) + "." + String(rtc.getYear());
  return date;
}

// Function to update date and time from serial input
// Expected format: "YYYY-MM-DD HH:MM:SS"
void updateDateTime(String dateTimeStr) {
  // Visual feedback that we're updating time
  strip.setPixelColor(0, strip.Color(255, 165, 0));  // Orange color while updating
  strip.show();

  // Trim any whitespace
  dateTimeStr.trim();

  // Check if the string is in the expected format
  if (dateTimeStr.length() < 19) {  // Basic length check
    Serial.println("Invalid date/time format. Expected: YYYY-MM-DD HH:MM:SS");
    return;
  }

  // Parse the date components
  int year = dateTimeStr.substring(0, 4).toInt();
  int month = dateTimeStr.substring(5, 7).toInt();
  int day = dateTimeStr.substring(8, 10).toInt();

  // Parse the time components
  int hours = dateTimeStr.substring(11, 13).toInt();
  int minutes = dateTimeStr.substring(14, 16).toInt();
  int seconds = dateTimeStr.substring(17, 19).toInt();

  // Validate the components
  if (year < 2000 || year > 2099 || month < 1 || month > 12 || day < 1 || day > 31 || hours < 0 || hours > 23 || minutes < 0 || minutes > 59 || seconds < 0 || seconds > 59) {
    Serial.println("Invalid date/time values. Please check your input.");
    return;
  }

  // Update the RTC with the new values
  // RTCZero uses last two digits of year
  rtc.setTime(hours, minutes, seconds);
  rtc.setDate(day, month, year % 100);  // Use only last two digits of year

  // Provide feedback
  Serial.print("Date and time updated to: ");
  Serial.print(getDate());
  Serial.print(" ");
  Serial.println(getTime());

  // Visual confirmation
  strip.setPixelColor(0, strip.Color(0, 255, 0));  // Green to indicate success
  strip.show();
  delay(500);  // Show green for half a second

  // Return to the appropriate color based on state
  if (currentState == COLLECT) {
    strip.setPixelColor(0, strip.Color(0, 0, 255));  // Blue during collection
  } else if (currentState == WAITING_FOR_WALLET) {
    strip.setPixelColor(0, strip.Color(255, 255, 0));  // Yellow while waiting for wallet
  }
  strip.show();
}

void setActive() {
  if (active == false) {
    active = true;
    firstActivityTime = millis();
  }
}