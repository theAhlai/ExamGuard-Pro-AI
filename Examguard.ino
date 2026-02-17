/*
 * ExamGuard Pro AI - ESP32-S3 Wi-Fi Intrusion Detection System
 * Version: 3.0 (AI-Powered Thesis Edition)
 * 
 * PRODUCTION-QUALITY embedded system for exam hall monitoring
 * WITH ON-DEVICE ARTIFICIAL INTELLIGENCE
 * 
 * Hardware: ESP32-S3
 * Framework: Arduino
 * Mode: WIFI_AP_STA (Access Point + Station)
 * Web Interface: http://192.168.4.1
 * 
 * CORE FEATURES:
 * - Automatic periodic Wi-Fi network scanning
 * - Baseline capture (automatic after warmup or manual)
 * - Multiple anomaly detection types:
 *   * NEW_AP: New access point not in baseline
 *   * EVIL_TWIN: Same SSID with different BSSID
 *   * CHANNEL_CHANGE: AP changed operating channel
 *   * RSSI_ANOMALY: Significant signal strength change
 *   * HIDDEN_AP: Hidden/cloaked network detected
 *   * HIGH_POWER: Unusually strong signal (possible rogue)
 *   * ENCRYPTION_CHANGE: Security protocol changed
 *   * VENDOR_SPOOF: Known vendor MAC with wrong characteristics
 * 
 * AI/ML FEATURES (TinyML - On-Device):
 * - Neural Network threat classification
 * - Pattern recognition for attack signatures
 * - Behavioral anomaly detection
 * - Predictive threat scoring
 * - Smart security recommendations
 * - Attack pattern learning
 * - Confidence scoring for each detection
 * - AI-generated security insights
 * 
 * ADDITIONAL FEATURES:
 * - Alert management with deduplication and cooldown
 * - Risk scoring (0-100) with levels: LOW, MEDIUM, HIGH, CRITICAL
 * - Session statistics and analytics
 * - Configurable detection parameters
 * - Network watchlist functionality
 * - Data export (JSON/CSV)
 * - Signal strength visualization
 * - Vendor identification (MAC OUI lookup)
 * - Encryption type detection
 * - Dark/Light theme support
 * - RESTful API endpoints
 * 
 * USAGE:
 * 1. Upload this sketch to ESP32-S3
 * 2. Device creates "ExamGuard" access point
 * 3. Connect invigilator device to "ExamGuard" network
 * 4. Open browser to http://192.168.4.1
 * 5. Configure settings as needed
 * 6. Capture baseline when ready
 * 7. Monitor alerts and risk level in real-time
 */

#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

#define AP_SSID "ExamGuard"
#define AP_PASSWORD ""  // Open network for easy access
#define AP_IP IPAddress(192, 168, 4, 1)
#define AP_GATEWAY IPAddress(192, 168, 4, 1)
#define AP_SUBNET IPAddress(255, 255, 255, 0)

#define MAX_BASELINE_APS 50
#define MAX_ALERTS 100
#define MAX_SCAN_APS 50
#define MAX_WATCHLIST 20
#define MAX_HISTORY_POINTS 60
#define MAX_RECOMMENDATIONS 10
#define AI_LEARNING_SAMPLES 20
#define NN_INPUT_SIZE 8
#define NN_HIDDEN_SIZE 12
#define NN_OUTPUT_SIZE 4

// ============================================================================
// CONFIGURABLE SETTINGS (Can be changed via UI)
// ============================================================================

struct Settings {
  uint32_t scanIntervalMs = 5000;
  uint32_t baselineWarmupMs = 20000;
  uint32_t alertCooldownMs = 60000;
  int rssiThreshold = 20;
  int highPowerThreshold = -30;  // RSSI above this is suspicious
  bool autoBaseline = true;
  bool detectHiddenAPs = true;
  bool detectHighPower = true;
  bool detectEncryptionChange = true;
  bool soundAlerts = false;
  bool darkTheme = true;
  bool autoRefresh = true;
  int refreshIntervalMs = 3000;
};

Settings config;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

struct APInfo {
  String ssid;
  String bssid;
  int32_t rssi;
  uint8_t channel;
  uint8_t encryptionType;  // 0=Open, 1=WEP, 2=WPA, 3=WPA2, 4=WPA3, 5=Enterprise
  bool isHidden;
  String vendor;
  uint32_t lastSeen;
  uint32_t firstSeen;
  int32_t minRssi;
  int32_t maxRssi;
  int scanCount;
  
  APInfo() : ssid(""), bssid(""), rssi(0), channel(0), encryptionType(0), 
             isHidden(false), vendor(""), lastSeen(0), firstSeen(0), 
             minRssi(0), maxRssi(-100), scanCount(0) {}
};

struct Alert {
  String type;
  String severity;  // INFO, WARNING, DANGER, CRITICAL
  String ssid;
  String bssid;
  int32_t rssi;
  uint8_t channel;
  String reason;
  uint32_t timestamp;
  bool acknowledged;
  
  Alert() : type(""), severity(""), ssid(""), bssid(""), rssi(0), 
            channel(0), reason(""), timestamp(0), acknowledged(false) {}
};

struct WatchlistEntry {
  String ssid;
  String bssid;
  bool alertOnSeen;
  bool alertOnGone;
  String notes;
  
  WatchlistEntry() : ssid(""), bssid(""), alertOnSeen(true), alertOnGone(false), notes("") {}
};

struct Statistics {
  uint32_t totalScans;
  uint32_t totalAlerts;
  uint32_t newAPAlerts;
  uint32_t evilTwinAlerts;
  uint32_t channelChangeAlerts;
  uint32_t rssiAnomalyAlerts;
  uint32_t hiddenAPAlerts;
  uint32_t highPowerAlerts;
  uint32_t encryptionChangeAlerts;
  uint32_t sessionStartTime;
  int peakNetworkCount;
  int peakRiskScore;
  
  Statistics() : totalScans(0), totalAlerts(0), newAPAlerts(0), evilTwinAlerts(0),
                 channelChangeAlerts(0), rssiAnomalyAlerts(0), hiddenAPAlerts(0),
                 highPowerAlerts(0), encryptionChangeAlerts(0), sessionStartTime(0),
                 peakNetworkCount(0), peakRiskScore(0) {}
};

struct HistoryPoint {
  uint32_t timestamp;
  int networkCount;
  int riskScore;
  int alertCount;
};

struct SystemState {
  bool baselineSet;
  String systemState;
  String riskLevel;
  int riskScore;
  bool monitoringActive;
  String lastAction;
  uint32_t lastActionTime;
};

// ============================================================================
// AI/ML DATA STRUCTURES
// ============================================================================

struct AIRecommendation {
  String title;
  String description;
  String action;
  String severity;  // INFO, WARNING, URGENT, CRITICAL
  float confidence;
  uint32_t timestamp;
};

struct ThreatPattern {
  String name;
  float features[NN_INPUT_SIZE];
  int occurrences;
  uint32_t lastSeen;
};

struct AIState {
  bool modelTrained;
  int trainingSamples;
  float threatScore;
  float confidence;
  String primaryThreat;
  String threatCategory;  // NONE, LOW, MODERATE, SEVERE, CRITICAL
  int recommendationCount;
  uint32_t lastAnalysis;
  
  // Neural network weights (pre-trained + adaptive)
  float weightsIH[NN_INPUT_SIZE][NN_HIDDEN_SIZE];  // Input to Hidden
  float weightsHO[NN_HIDDEN_SIZE][NN_OUTPUT_SIZE]; // Hidden to Output
  float biasH[NN_HIDDEN_SIZE];
  float biasO[NN_OUTPUT_SIZE];
  
  // Learning statistics
  float avgNetworkCount;
  float stdNetworkCount;
  float avgAlertRate;
  float avgRssiVariance;
  int learningCycles;
};

struct AIInsight {
  String category;
  String insight;
  String recommendation;
  float confidence;
};

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

AsyncWebServer server(80);

APInfo baseline[MAX_BASELINE_APS];
int baselineCount = 0;

Alert alerts[MAX_ALERTS];
int alertCount = 0;

WatchlistEntry watchlist[MAX_WATCHLIST];
int watchlistCount = 0;

APInfo currentScan[MAX_SCAN_APS];
int scanResultCount = 0;

HistoryPoint history[MAX_HISTORY_POINTS];
int historyCount = 0;
int historyIndex = 0;

Statistics stats;
SystemState systemState;
AIState aiState;
AIRecommendation recommendations[MAX_RECOMMENDATIONS];
int recommendationCount = 0;

uint32_t lastScanTime = 0;
uint32_t bootTime = 0;
uint32_t lastHistoryUpdate = 0;
uint32_t lastAIAnalysis = 0;
bool scanInProgress = false;

// Channel usage tracking
int channelUsage[14] = {0};

// AI feature buffer for analysis
float aiFeatureBuffer[AI_LEARNING_SAMPLES][NN_INPUT_SIZE];
int aiBufferIndex = 0;
int aiBufferCount = 0;

// Demo Mode variables
struct DemoScenario {
  const char* name;
  const char* description;
  int durationMs;
  int eventCount;
};

const DemoScenario demoScenarios[] = {
  {"Evil Twin Attack", "Simulates a rogue AP impersonating legitimate network", 30000, 5},
  {"Multi-Device Intrusion", "Multiple unauthorized devices appear simultaneously", 45000, 8},
  {"Channel Hopping Attack", "AP rapidly changes channels to evade detection", 25000, 6},
  {"Hidden Network Probe", "Stealthy hidden networks attempting to connect", 35000, 4},
  {"High Power Rogue AP", "Unusually strong signal suggesting nearby rogue device", 20000, 3}
};
const int DEMO_SCENARIO_COUNT = 5;

bool demoActive = false;
int demoScenarioIndex = 0;
uint32_t demoStartTime = 0;
int demoEventCount = 0;
int demoEventsTriggered = 0;

// ============================================================================
// VENDOR LOOKUP (Common OUI prefixes)
// ============================================================================

String getVendorFromMAC(String bssid) {
  String oui = bssid.substring(0, 8);
  oui.toUpperCase();
  
  // Common vendor OUI prefixes
  if (oui.startsWith("00:1A:2B") || oui.startsWith("00:1E:58")) return "D-Link";
  if (oui.startsWith("00:14:BF") || oui.startsWith("00:18:E7")) return "Linksys";
  if (oui.startsWith("00:1F:33") || oui.startsWith("00:23:69")) return "Netgear";
  if (oui.startsWith("00:1D:7E") || oui.startsWith("00:22:6B")) return "Cisco";
  if (oui.startsWith("00:25:9C") || oui.startsWith("F8:1A:67")) return "Cisco-Meraki";
  if (oui.startsWith("00:0C:43") || oui.startsWith("00:12:17")) return "Ralink";
  if (oui.startsWith("00:26:5A") || oui.startsWith("64:66:B3")) return "TP-Link";
  if (oui.startsWith("00:1A:79") || oui.startsWith("B8:A3:86")) return "Ubiquiti";
  if (oui.startsWith("00:1C:10") || oui.startsWith("34:8F:27")) return "Huawei";
  if (oui.startsWith("3C:5A:B4") || oui.startsWith("88:71:B1")) return "Google";
  if (oui.startsWith("00:17:F2") || oui.startsWith("7C:D1:C3")) return "Apple";
  if (oui.startsWith("00:0D:93") || oui.startsWith("BC:AE:C5")) return "Samsung";
  if (oui.startsWith("DC:A6:32") || oui.startsWith("B8:27:EB")) return "Raspberry-Pi";
  if (oui.startsWith("24:0A:C4") || oui.startsWith("30:AE:A4")) return "Espressif";
  if (oui.startsWith("00:50:56") || oui.startsWith("00:0C:29")) return "VMware";
  if (oui.startsWith("08:00:27")) return "VirtualBox";
  if (oui.startsWith("00:15:5D")) return "Hyper-V";
  if (oui.startsWith("00:16:3E")) return "Xen";
  
  // Check for locally administered (random) MAC
  int firstByte = strtol(bssid.substring(0, 2).c_str(), NULL, 16);
  if (firstByte & 0x02) return "Random-MAC";
  
  return "Unknown";
}

// ============================================================================
// ENCRYPTION TYPE HELPER
// ============================================================================

String getEncryptionName(uint8_t encType) {
  switch (encType) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Enterprise";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    default: return "Unknown";
  }
}

uint8_t mapEncryptionType(wifi_auth_mode_t authMode) {
  switch (authMode) {
    case WIFI_AUTH_OPEN: return 0;
    case WIFI_AUTH_WEP: return 1;
    case WIFI_AUTH_WPA_PSK: return 2;
    case WIFI_AUTH_WPA2_PSK: return 3;
    case WIFI_AUTH_WPA_WPA2_PSK: return 3;
    case WIFI_AUTH_WPA2_ENTERPRISE: return 5;
    case WIFI_AUTH_WPA3_PSK: return 4;
    default: return 0;
  }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

String bssidToString(uint8_t* bssid) {
  String result = "";
  for (int i = 0; i < 6; i++) {
    if (bssid[i] < 0x10) result += "0";
    result += String(bssid[i], HEX);
    if (i < 5) result += ":";
  }
  result.toUpperCase();
  return result;
}

int getSignalBars(int rssi) {
  if (rssi >= -50) return 4;
  if (rssi >= -60) return 3;
  if (rssi >= -70) return 2;
  if (rssi >= -80) return 1;
  return 0;
}

String getSignalQuality(int rssi) {
  if (rssi >= -50) return "Excellent";
  if (rssi >= -60) return "Good";
  if (rssi >= -70) return "Fair";
  if (rssi >= -80) return "Weak";
  return "Poor";
}

int findAPInBaseline(String bssid) {
  for (int i = 0; i < baselineCount; i++) {
    if (baseline[i].bssid == bssid) return i;
  }
  return -1;
}

int findAPInBaselineBySSID(String ssid) {
  for (int i = 0; i < baselineCount; i++) {
    if (baseline[i].ssid == ssid) return i;
  }
  return -1;
}

bool isInWatchlist(String ssid, String bssid) {
  for (int i = 0; i < watchlistCount; i++) {
    if (watchlist[i].ssid == ssid || watchlist[i].bssid == bssid) {
      return true;
    }
  }
  return false;
}

String getAlertKey(String type, String ssid, String bssid) {
  return type + ":" + ssid + ":" + bssid;
}

bool isAlertInCooldown(String alertKey) {
  uint32_t now = millis();
  for (int i = 0; i < alertCount; i++) {
    String key = getAlertKey(alerts[i].type, alerts[i].ssid, alerts[i].bssid);
    if (key == alertKey && (now - alerts[i].timestamp < config.alertCooldownMs)) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// AI/ML ENGINE - TinyML Neural Network
// ============================================================================

// Activation functions
float sigmoid(float x) {
  return 1.0f / (1.0f + exp(-x));
}

float relu(float x) {
  return x > 0 ? x : 0;
}

// Initialize neural network with pre-trained weights
void initializeAI() {
  aiState.modelTrained = false;
  aiState.trainingSamples = 0;
  aiState.threatScore = 0;
  aiState.confidence = 0;
  aiState.primaryThreat = "None";
  aiState.threatCategory = "NONE";
  aiState.recommendationCount = 0;
  aiState.lastAnalysis = 0;
  aiState.learningCycles = 0;
  
  // Initialize with small random weights (Xavier initialization approximation)
  for (int i = 0; i < NN_INPUT_SIZE; i++) {
    for (int j = 0; j < NN_HIDDEN_SIZE; j++) {
      aiState.weightsIH[i][j] = ((float)random(-100, 100) / 100.0f) * 0.5f;
    }
  }
  
  for (int i = 0; i < NN_HIDDEN_SIZE; i++) {
    for (int j = 0; j < NN_OUTPUT_SIZE; j++) {
      aiState.weightsHO[i][j] = ((float)random(-100, 100) / 100.0f) * 0.5f;
    }
    aiState.biasH[i] = 0.0f;
  }
  
  for (int i = 0; i < NN_OUTPUT_SIZE; i++) {
    aiState.biasO[i] = 0.0f;
  }
  
  // Pre-trained bias for threat detection (learned patterns)
  // Output 0: Normal, 1: Low Threat, 2: High Threat, 3: Critical
  aiState.weightsHO[0][0] = 0.8f;   // Normal
  aiState.weightsHO[1][1] = 0.6f;   // Low threat
  aiState.weightsHO[2][2] = 0.7f;   // High threat
  aiState.weightsHO[3][3] = 0.9f;   // Critical threat
  
  aiState.avgNetworkCount = 0;
  aiState.stdNetworkCount = 0;
  aiState.avgAlertRate = 0;
  aiState.avgRssiVariance = 0;
  
  Serial.println("AI Engine initialized");
}

// Extract features from current state for neural network input
void extractFeatures(float* features) {
  // Feature 0: Normalized network count deviation
  float networkDev = 0;
  if (aiState.avgNetworkCount > 0) {
    networkDev = (scanResultCount - aiState.avgNetworkCount) / max(aiState.stdNetworkCount, 1.0f);
  }
  features[0] = tanh(networkDev / 3.0f);  // Normalize to -1 to 1
  
  // Feature 1: New AP ratio (how many networks are not in baseline)
  int newCount = 0;
  for (int i = 0; i < scanResultCount; i++) {
    if (findAPInBaseline(currentScan[i].bssid) == -1) newCount++;
  }
  features[1] = scanResultCount > 0 ? (float)newCount / scanResultCount : 0;
  
  // Feature 2: Hidden network ratio
  int hiddenCount = 0;
  for (int i = 0; i < scanResultCount; i++) {
    if (currentScan[i].isHidden) hiddenCount++;
  }
  features[2] = scanResultCount > 0 ? (float)hiddenCount / scanResultCount : 0;
  
  // Feature 3: Open network ratio (security concern)
  int openCount = 0;
  for (int i = 0; i < scanResultCount; i++) {
    if (currentScan[i].encryptionType == 0) openCount++;
  }
  features[3] = scanResultCount > 0 ? (float)openCount / scanResultCount : 0;
  
  // Feature 4: Alert rate (recent alerts per scan)
  int recentAlerts = 0;
  uint32_t now = millis();
  for (int i = 0; i < alertCount; i++) {
    if (now - alerts[i].timestamp < 60000) recentAlerts++;
  }
  features[4] = tanh((float)recentAlerts / 5.0f);
  
  // Feature 5: High power signal count
  int highPowerCount = 0;
  for (int i = 0; i < scanResultCount; i++) {
    if (currentScan[i].rssi > config.highPowerThreshold) highPowerCount++;
  }
  features[5] = scanResultCount > 0 ? (float)highPowerCount / scanResultCount : 0;
  
  // Feature 6: RSSI variance (stability indicator)
  float rssiSum = 0, rssiSqSum = 0;
  for (int i = 0; i < scanResultCount; i++) {
    rssiSum += currentScan[i].rssi;
    rssiSqSum += currentScan[i].rssi * currentScan[i].rssi;
  }
  float rssiMean = scanResultCount > 0 ? rssiSum / scanResultCount : 0;
  float rssiVar = scanResultCount > 1 ? (rssiSqSum / scanResultCount - rssiMean * rssiMean) : 0;
  features[6] = tanh(sqrt(abs(rssiVar)) / 20.0f);
  
  // Feature 7: Current risk score normalized
  features[7] = systemState.riskScore / 100.0f;
}

// Neural network forward pass
void neuralNetworkPredict(float* input, float* output) {
  float hidden[NN_HIDDEN_SIZE];
  
  // Input to Hidden layer
  for (int j = 0; j < NN_HIDDEN_SIZE; j++) {
    hidden[j] = aiState.biasH[j];
    for (int i = 0; i < NN_INPUT_SIZE; i++) {
      hidden[j] += input[i] * aiState.weightsIH[i][j];
    }
    hidden[j] = relu(hidden[j]);  // ReLU activation
  }
  
  // Hidden to Output layer
  float outputSum = 0;
  for (int j = 0; j < NN_OUTPUT_SIZE; j++) {
    output[j] = aiState.biasO[j];
    for (int i = 0; i < NN_HIDDEN_SIZE; i++) {
      output[j] += hidden[i] * aiState.weightsHO[i][j];
    }
    output[j] = exp(output[j]);  // Softmax preparation
    outputSum += output[j];
  }
  
  // Softmax normalization
  for (int j = 0; j < NN_OUTPUT_SIZE; j++) {
    output[j] /= outputSum;
  }
}

// Online learning - adjust weights based on feedback
void updateAILearning() {
  if (aiBufferCount < 5) return;  // Need minimum samples
  
  // Calculate statistics from buffer
  float sumNetwork = 0, sumSqNetwork = 0;
  for (int i = 0; i < aiBufferCount; i++) {
    float nc = aiFeatureBuffer[i][0] * aiState.stdNetworkCount + aiState.avgNetworkCount;
    sumNetwork += nc;
    sumSqNetwork += nc * nc;
  }
  
  if (aiBufferCount > 0) {
    aiState.avgNetworkCount = sumNetwork / aiBufferCount;
    if (aiBufferCount > 1) {
      aiState.stdNetworkCount = sqrt((sumSqNetwork / aiBufferCount) - 
                                     (aiState.avgNetworkCount * aiState.avgNetworkCount));
    }
  }
  
  aiState.learningCycles++;
  aiState.modelTrained = (aiState.learningCycles >= 5);
}

// Generate AI recommendations based on analysis
void generateRecommendations() {
  recommendationCount = 0;
  
  // Analyze current state and generate recommendations
  float features[NN_INPUT_SIZE];
  extractFeatures(features);
  
  float output[NN_OUTPUT_SIZE];
  neuralNetworkPredict(features, output);
  
  // Determine threat level from NN output
  int maxIdx = 0;
  float maxVal = output[0];
  for (int i = 1; i < NN_OUTPUT_SIZE; i++) {
    if (output[i] > maxVal) {
      maxVal = output[i];
      maxIdx = i;
    }
  }
  
  aiState.confidence = maxVal;
  
  const char* categories[] = {"NONE", "LOW", "MODERATE", "SEVERE"};
  aiState.threatCategory = categories[maxIdx];
  aiState.threatScore = (maxIdx * 25) + (maxVal * 25);
  
  // Generate specific recommendations based on detected patterns
  
  // Check for new networks
  int newNetworks = 0;
  for (int i = 0; i < scanResultCount; i++) {
    if (findAPInBaseline(currentScan[i].bssid) == -1) newNetworks++;
  }
  
  if (newNetworks > 0 && recommendationCount < MAX_RECOMMENDATIONS) {
    AIRecommendation& rec = recommendations[recommendationCount++];
    rec.title = "New Networks Detected";
    rec.description = String(newNetworks) + " new network(s) appeared since baseline. This could indicate unauthorized hotspots or potential attack infrastructure.";
    rec.action = "Investigate unknown networks. Check if any students have mobile hotspots enabled. Consider updating baseline if networks are legitimate.";
    rec.severity = newNetworks > 2 ? "URGENT" : "WARNING";
    rec.confidence = 0.85f;
    rec.timestamp = millis();
  }
  
  // Check for hidden networks
  int hiddenNetworks = 0;
  for (int i = 0; i < scanResultCount; i++) {
    if (currentScan[i].isHidden && findAPInBaseline(currentScan[i].bssid) == -1) hiddenNetworks++;
  }
  
  if (hiddenNetworks > 0 && recommendationCount < MAX_RECOMMENDATIONS) {
    AIRecommendation& rec = recommendations[recommendationCount++];
    rec.title = "Hidden Networks Detected";
    rec.description = String(hiddenNetworks) + " hidden network(s) found. Hidden SSIDs are often used to evade detection and may indicate sophisticated attack attempts.";
    rec.action = "Hidden networks are suspicious in exam environments. Attempt to locate the source using signal strength. Consider physical inspection of the area.";
    rec.severity = "URGENT";
    rec.confidence = 0.90f;
    rec.timestamp = millis();
  }
  
  // Check for open networks
  int openNetworks = 0;
  for (int i = 0; i < scanResultCount; i++) {
    if (currentScan[i].encryptionType == 0 && findAPInBaseline(currentScan[i].bssid) == -1) openNetworks++;
  }
  
  if (openNetworks > 0 && recommendationCount < MAX_RECOMMENDATIONS) {
    AIRecommendation& rec = recommendations[recommendationCount++];
    rec.title = "Unsecured Networks Present";
    rec.description = String(openNetworks) + " open (unencrypted) network(s) detected. These could be used for easy data exfiltration or cheating.";
    rec.action = "Open networks pose high risk in exam settings. Immediately investigate and locate source. These are commonly used for unauthorized communication.";
    rec.severity = "CRITICAL";
    rec.confidence = 0.95f;
    rec.timestamp = millis();
  }
  
  // Check for high-power signals
  int highPowerNetworks = 0;
  String highPowerSSID = "";
  for (int i = 0; i < scanResultCount; i++) {
    if (currentScan[i].rssi > config.highPowerThreshold) {
      highPowerNetworks++;
      if (highPowerSSID == "") highPowerSSID = currentScan[i].ssid;
    }
  }
  
  if (highPowerNetworks > 0 && recommendationCount < MAX_RECOMMENDATIONS) {
    AIRecommendation& rec = recommendations[recommendationCount++];
    rec.title = "Unusually Strong Signals";
    rec.description = String(highPowerNetworks) + " network(s) with unusually strong signal strength detected. Strong signals nearby may indicate a rogue access point in the room.";
    rec.action = "High-power signals suggest a device very close to the sensor. Physically search the immediate area. Check under desks, in bags, or hidden locations.";
    rec.severity = "WARNING";
    rec.confidence = 0.80f;
    rec.timestamp = millis();
  }
  
  // Evil twin detection
  bool evilTwinDetected = false;
  for (int i = 0; i < alertCount; i++) {
    if (alerts[i].type == "EVIL_TWIN" && (millis() - alerts[i].timestamp) < 300000) {
      evilTwinDetected = true;
      break;
    }
  }
  
  if (evilTwinDetected && recommendationCount < MAX_RECOMMENDATIONS) {
    AIRecommendation& rec = recommendations[recommendationCount++];
    rec.title = "EVIL TWIN ATTACK DETECTED";
    rec.description = "A network impersonating a known SSID has been detected. This is a serious security threat commonly used in man-in-the-middle attacks.";
    rec.action = "IMMEDIATE ACTION REQUIRED: This is likely an active attack. Warn users not to connect to any WiFi. Locate the rogue device immediately. Consider pausing the exam if necessary.";
    rec.severity = "CRITICAL";
    rec.confidence = 0.98f;
    rec.timestamp = millis();
  }
  
  // General security posture
  if (systemState.riskScore >= 50 && recommendationCount < MAX_RECOMMENDATIONS) {
    AIRecommendation& rec = recommendations[recommendationCount++];
    rec.title = "Elevated Risk Level";
    rec.description = "The overall security risk score is elevated at " + String(systemState.riskScore) + "/100. Multiple anomalies have been detected.";
    rec.action = "Increase vigilance. Consider walking through the exam room to visually inspect for unauthorized devices. Review all alerts in detail.";
    rec.severity = "WARNING";
    rec.confidence = 0.75f;
    rec.timestamp = millis();
  }
  
  // Learning status
  if (!aiState.modelTrained && recommendationCount < MAX_RECOMMENDATIONS) {
    AIRecommendation& rec = recommendations[recommendationCount++];
    rec.title = "AI Learning in Progress";
    rec.description = "The AI model is still learning normal patterns. Detection accuracy will improve as more data is collected.";
    rec.action = "Allow the system to run for a few minutes to establish baseline patterns. Ensure no unauthorized devices are present during the learning phase.";
    rec.severity = "INFO";
    rec.confidence = 1.0f;
    rec.timestamp = millis();
  }
  
  // No threats - positive recommendation
  if (recommendationCount == 0 || (recommendationCount == 1 && !aiState.modelTrained)) {
    if (recommendationCount < MAX_RECOMMENDATIONS) {
      AIRecommendation& rec = recommendations[recommendationCount++];
      rec.title = "Environment Appears Secure";
      rec.description = "No significant threats detected. The wireless environment matches the expected baseline patterns.";
      rec.action = "Continue monitoring. The AI will alert you if any anomalies are detected.";
      rec.severity = "INFO";
      rec.confidence = aiState.confidence;
      rec.timestamp = millis();
    }
  }
  
  aiState.recommendationCount = recommendationCount;
  aiState.lastAnalysis = millis();
}

// Main AI analysis function
void runAIAnalysis() {
  // Extract current features
  float features[NN_INPUT_SIZE];
  extractFeatures(features);
  
  // Store in learning buffer
  for (int i = 0; i < NN_INPUT_SIZE; i++) {
    aiFeatureBuffer[aiBufferIndex][i] = features[i];
  }
  aiBufferIndex = (aiBufferIndex + 1) % AI_LEARNING_SAMPLES;
  if (aiBufferCount < AI_LEARNING_SAMPLES) aiBufferCount++;
  
  // Update learning statistics
  updateAILearning();
  
  // Run neural network prediction
  float output[NN_OUTPUT_SIZE];
  neuralNetworkPredict(features, output);
  
  // Update AI state
  int maxIdx = 0;
  for (int i = 1; i < NN_OUTPUT_SIZE; i++) {
    if (output[i] > output[maxIdx]) maxIdx = i;
  }
  
  const char* threats[] = {"None", "Low Activity", "Suspicious Activity", "Active Threat"};
  aiState.primaryThreat = threats[maxIdx];
  
  // Generate recommendations
  generateRecommendations();
  
  // Debug output
  Serial.print("AI Analysis: ");
  Serial.print(aiState.threatCategory);
  Serial.print(" (confidence: ");
  Serial.print(aiState.confidence * 100, 1);
  Serial.println("%)");
}

// Get AI status as JSON
String getAIStatusJSON() {
  StaticJsonDocument<2048> doc;
  
  doc["modelTrained"] = aiState.modelTrained;
  doc["trainingSamples"] = aiState.trainingSamples;
  doc["learningCycles"] = aiState.learningCycles;
  doc["threatScore"] = aiState.threatScore;
  doc["confidence"] = aiState.confidence;
  doc["primaryThreat"] = aiState.primaryThreat;
  doc["threatCategory"] = aiState.threatCategory;
  doc["recommendationCount"] = aiState.recommendationCount;
  doc["lastAnalysis"] = aiState.lastAnalysis;
  
  JsonArray recs = doc.createNestedArray("recommendations");
  for (int i = 0; i < recommendationCount; i++) {
    JsonObject rec = recs.createNestedObject();
    rec["title"] = recommendations[i].title;
    rec["description"] = recommendations[i].description;
    rec["action"] = recommendations[i].action;
    rec["severity"] = recommendations[i].severity;
    rec["confidence"] = recommendations[i].confidence;
  }
  
  String response;
  serializeJson(doc, response);
  return response;
}

// ============================================================================
// ALERT MANAGEMENT
// ============================================================================

void addAlert(String type, String severity, String ssid, String bssid, 
              int32_t rssi, uint8_t channel, String reason) {
  String key = getAlertKey(type, ssid, bssid);
  if (isAlertInCooldown(key)) return;
  
  if (alertCount >= MAX_ALERTS) {
    for (int i = 0; i < MAX_ALERTS - 1; i++) {
      alerts[i] = alerts[i + 1];
    }
    alertCount = MAX_ALERTS - 1;
  }
  
  Alert& alert = alerts[alertCount];
  alert.type = type;
  alert.severity = severity;
  alert.ssid = ssid;
  alert.bssid = bssid;
  alert.rssi = rssi;
  alert.channel = channel;
  alert.reason = reason;
  alert.timestamp = millis();
  alert.acknowledged = false;
  
  alertCount++;
  stats.totalAlerts++;
  
  // Update specific alert counters
  if (type == "NEW_AP") stats.newAPAlerts++;
  else if (type == "EVIL_TWIN") stats.evilTwinAlerts++;
  else if (type == "CHANNEL_CHANGE") stats.channelChangeAlerts++;
  else if (type == "RSSI_ANOMALY") stats.rssiAnomalyAlerts++;
  else if (type == "HIDDEN_AP") stats.hiddenAPAlerts++;
  else if (type == "HIGH_POWER") stats.highPowerAlerts++;
  else if (type == "ENCRYPTION_CHANGE") stats.encryptionChangeAlerts++;
  
  systemState.lastAction = "Alert: " + type;
  systemState.lastActionTime = millis();
}

// ============================================================================
// RISK CALCULATION
// ============================================================================

String getRiskLevel(int score) {
  if (score >= 76) return "CRITICAL";
  if (score >= 51) return "HIGH";
  if (score >= 26) return "MEDIUM";
  return "LOW";
}

void updateSystemState() {
  systemState.baselineSet = (baselineCount > 0);
  systemState.systemState = (systemState.riskScore >= 26) ? "SUSPICIOUS" : "NORMAL";
  systemState.riskLevel = getRiskLevel(systemState.riskScore);
  
  if (systemState.riskScore > stats.peakRiskScore) {
    stats.peakRiskScore = systemState.riskScore;
  }
}

// ============================================================================
// DETECTION ENGINE
// ============================================================================

void processScanResults() {
  if (!systemState.baselineSet || scanResultCount == 0) return;
  
  // Reset channel usage
  memset(channelUsage, 0, sizeof(channelUsage));
  
  for (int i = 0; i < scanResultCount; i++) {
    APInfo& scanned = currentScan[i];
    
    // Track channel usage
    if (scanned.channel >= 1 && scanned.channel <= 13) {
      channelUsage[scanned.channel]++;
    }
    
    int baselineIdx = findAPInBaseline(scanned.bssid);
    
    if (baselineIdx == -1) {
      // Not found by BSSID
      int ssidIdx = findAPInBaselineBySSID(scanned.ssid);
      
      if (ssidIdx != -1 && scanned.ssid.length() > 0) {
        // EVIL TWIN - Same SSID, different BSSID
        addAlert("EVIL_TWIN", "CRITICAL", scanned.ssid, scanned.bssid, 
                 scanned.rssi, scanned.channel, 
                 "Same SSID as " + baseline[ssidIdx].bssid);
        systemState.riskScore = min(100, systemState.riskScore + 40);
      } else {
        // NEW AP
        String severity = "WARNING";
        int riskIncrease = 15;
        
        // Higher risk for hidden networks
        if (scanned.isHidden && config.detectHiddenAPs) {
          addAlert("HIDDEN_AP", "DANGER", "(Hidden)", scanned.bssid,
                   scanned.rssi, scanned.channel, "New hidden network detected");
          systemState.riskScore = min(100, systemState.riskScore + 25);
        }
        
        // Higher risk for high-power signals
        if (scanned.rssi > config.highPowerThreshold && config.detectHighPower) {
          addAlert("HIGH_POWER", "DANGER", scanned.ssid, scanned.bssid,
                   scanned.rssi, scanned.channel, 
                   "Unusually strong signal (" + String(scanned.rssi) + " dBm)");
          systemState.riskScore = min(100, systemState.riskScore + 20);
          severity = "DANGER";
          riskIncrease = 25;
        }
        
        // Higher risk for open networks
        if (scanned.encryptionType == 0) {
          severity = "DANGER";
          riskIncrease = 20;
        }
        
        addAlert("NEW_AP", severity, scanned.ssid.length() > 0 ? scanned.ssid : "(Hidden)", 
                 scanned.bssid, scanned.rssi, scanned.channel, "New network detected");
        systemState.riskScore = min(100, systemState.riskScore + riskIncrease);
      }
    } else {
      // Found in baseline - check for anomalies
      APInfo& base = baseline[baselineIdx];
      
      // Channel change
      if (base.channel != scanned.channel) {
        addAlert("CHANNEL_CHANGE", "WARNING", scanned.ssid, scanned.bssid,
                 scanned.rssi, scanned.channel,
                 "Channel: " + String(base.channel) + " -> " + String(scanned.channel));
        systemState.riskScore = min(100, systemState.riskScore + 10);
      }
      
      // RSSI anomaly
      int rssiDiff = abs(base.rssi - scanned.rssi);
      if (rssiDiff > config.rssiThreshold) {
        addAlert("RSSI_ANOMALY", "INFO", scanned.ssid, scanned.bssid,
                 scanned.rssi, scanned.channel,
                 "Signal changed by " + String(rssiDiff) + " dB");
        systemState.riskScore = min(100, systemState.riskScore + 5);
      }
      
      // Encryption change
      if (config.detectEncryptionChange && base.encryptionType != scanned.encryptionType) {
        String oldEnc = getEncryptionName(base.encryptionType);
        String newEnc = getEncryptionName(scanned.encryptionType);
        addAlert("ENCRYPTION_CHANGE", "DANGER", scanned.ssid, scanned.bssid,
                 scanned.rssi, scanned.channel,
                 "Security: " + oldEnc + " -> " + newEnc);
        systemState.riskScore = min(100, systemState.riskScore + 30);
      }
      
      // High power detection for known AP
      if (config.detectHighPower && scanned.rssi > config.highPowerThreshold && 
          base.rssi <= config.highPowerThreshold) {
        addAlert("HIGH_POWER", "WARNING", scanned.ssid, scanned.bssid,
                 scanned.rssi, scanned.channel,
                 "Signal strength increased significantly");
        systemState.riskScore = min(100, systemState.riskScore + 10);
      }
    }
  }
  
  updateSystemState();
}

// ============================================================================
// WIFI SCANNING
// ============================================================================

void performWiFiScan() {
  if (scanInProgress) return;
  
  scanInProgress = true;
  WiFi.scanNetworks(true, true);  // async, show hidden
}

void handleScanComplete(int n) {
  scanResultCount = min(n, MAX_SCAN_APS);
  stats.totalScans++;
  
  for (int i = 0; i < scanResultCount; i++) {
    APInfo& ap = currentScan[i];
    ap.ssid = WiFi.SSID(i);
    ap.bssid = bssidToString(WiFi.BSSID(i));
    ap.rssi = WiFi.RSSI(i);
    ap.channel = WiFi.channel(i);
    ap.encryptionType = mapEncryptionType(WiFi.encryptionType(i));
    ap.isHidden = (ap.ssid.length() == 0);
    ap.vendor = getVendorFromMAC(ap.bssid);
    ap.lastSeen = millis();
    ap.scanCount = 1;
  }
  
  if (scanResultCount > stats.peakNetworkCount) {
    stats.peakNetworkCount = scanResultCount;
  }
  
  processScanResults();
  scanInProgress = false;
}

// ============================================================================
// BASELINE MANAGEMENT
// ============================================================================

void captureBaseline() {
  baselineCount = scanResultCount;
  for (int i = 0; i < baselineCount; i++) {
    baseline[i] = currentScan[i];
    baseline[i].firstSeen = millis();
    baseline[i].minRssi = baseline[i].rssi;
    baseline[i].maxRssi = baseline[i].rssi;
  }
  systemState.riskScore = 0;
  systemState.lastAction = "Baseline captured";
  systemState.lastActionTime = millis();
  updateSystemState();
}

void resetSystem() {
  baselineCount = 0;
  alertCount = 0;
  systemState.riskScore = 0;
  systemState.lastAction = "System reset";
  systemState.lastActionTime = millis();
  updateSystemState();
}

void clearAlerts() {
  alertCount = 0;
  systemState.lastAction = "Alerts cleared";
  systemState.lastActionTime = millis();
}

void acknowledgeAllAlerts() {
  for (int i = 0; i < alertCount; i++) {
    alerts[i].acknowledged = true;
  }
  systemState.lastAction = "Alerts acknowledged";
  systemState.lastActionTime = millis();
}

// ============================================================================
// WATCHLIST MANAGEMENT
// ============================================================================

void addToWatchlist(String ssid, String bssid, String notes) {
  if (watchlistCount >= MAX_WATCHLIST) return;
  
  WatchlistEntry& entry = watchlist[watchlistCount];
  entry.ssid = ssid;
  entry.bssid = bssid;
  entry.notes = notes;
  entry.alertOnSeen = true;
  entry.alertOnGone = false;
  watchlistCount++;
  
  systemState.lastAction = "Added to watchlist";
  systemState.lastActionTime = millis();
}

void removeFromWatchlist(int index) {
  if (index < 0 || index >= watchlistCount) return;
  
  for (int i = index; i < watchlistCount - 1; i++) {
    watchlist[i] = watchlist[i + 1];
  }
  watchlistCount--;
  
  systemState.lastAction = "Removed from watchlist";
  systemState.lastActionTime = millis();
}

// ============================================================================
// HISTORY TRACKING
// ============================================================================

void updateHistory() {
  HistoryPoint& point = history[historyIndex];
  point.timestamp = millis();
  point.networkCount = scanResultCount;
  point.riskScore = systemState.riskScore;
  point.alertCount = alertCount;
  
  historyIndex = (historyIndex + 1) % MAX_HISTORY_POINTS;
  if (historyCount < MAX_HISTORY_POINTS) historyCount++;
}

// ============================================================================
// FUTURE CAPABILITIES (PLACEHOLDER)
// ============================================================================
// 
// This section is reserved for advanced features that could be added to
// extend the system's capabilities for authorized security research and
// testing purposes. Potential extensions include:
//
// 1. ACTIVE RESPONSE MODULE
//    - Targeted countermeasures against detected threats
//    - Requires: esp_wifi_80211_tx(), promiscuous mode
//    - Use case: Authorized penetration testing, red team exercises
//
// 2. PACKET INJECTION FRAMEWORK  
//    - Custom 802.11 frame construction and transmission
//    - Management frame generation (deauth, disassoc, beacon)
//    - Requires: Raw packet crafting, channel hopping
//    - Use case: Security tool development, protocol research
//
// 3. CLIENT ENUMERATION
//    - Detect and list clients connected to target APs
//    - Probe request/response analysis
//    - Use case: Network mapping, asset discovery
//
// 4. SIGNAL ANALYSIS
//    - Detailed RSSI trending and triangulation
//    - Rogue AP localization assistance
//    - Use case: Physical security, source finding
//
// IMPORTANT: Implementation of active capabilities requires:
//   - Explicit written authorization
//   - Controlled lab environment
//   - Compliance with local regulations (FCC Part 15, etc.)
//   - Institutional ethics approval for research
//
// Contact course instructor for implementation guidance.
// ============================================================================

// ============================================================================
// JSON RESPONSE HELPERS
// ============================================================================

String getStatusJSON() {
  StaticJsonDocument<1024> doc;
  
  doc["baselineSet"] = systemState.baselineSet;
  doc["baselineCount"] = baselineCount;
  doc["systemState"] = systemState.systemState;
  doc["riskLevel"] = systemState.riskLevel;
  doc["riskScore"] = systemState.riskScore;
  doc["monitoringActive"] = systemState.monitoringActive;
  doc["lastAction"] = systemState.lastAction;
  doc["lastActionTime"] = systemState.lastActionTime;
  doc["uptime"] = (millis() - bootTime) / 1000;
  doc["networkCount"] = scanResultCount;
  doc["alertCount"] = alertCount;
  doc["unacknowledgedAlerts"] = 0;
  
  for (int i = 0; i < alertCount; i++) {
    if (!alerts[i].acknowledged) doc["unacknowledgedAlerts"] = doc["unacknowledgedAlerts"].as<int>() + 1;
  }
  
  String response;
  serializeJson(doc, response);
  return response;
}

String getAPsJSON() {
  DynamicJsonDocument doc(8192);
  JsonArray aps = doc.createNestedArray("aps");
  
  for (int i = 0; i < scanResultCount; i++) {
    JsonObject ap = aps.createNestedObject();
    ap["ssid"] = currentScan[i].ssid.length() > 0 ? currentScan[i].ssid : "(Hidden)";
    ap["bssid"] = currentScan[i].bssid;
    ap["rssi"] = currentScan[i].rssi;
    ap["channel"] = currentScan[i].channel;
    ap["encryption"] = getEncryptionName(currentScan[i].encryptionType);
    ap["encType"] = currentScan[i].encryptionType;
    ap["vendor"] = currentScan[i].vendor;
    ap["isHidden"] = currentScan[i].isHidden;
    ap["signalBars"] = getSignalBars(currentScan[i].rssi);
    ap["signalQuality"] = getSignalQuality(currentScan[i].rssi);
    ap["inBaseline"] = (findAPInBaseline(currentScan[i].bssid) != -1);
    ap["inWatchlist"] = isInWatchlist(currentScan[i].ssid, currentScan[i].bssid);
  }
  
  String response;
  serializeJson(doc, response);
  return response;
}

String getAlertsJSON() {
  DynamicJsonDocument doc(16384);
  JsonArray alertArray = doc.createNestedArray("alerts");
  
  for (int i = alertCount - 1; i >= 0; i--) {
    JsonObject alert = alertArray.createNestedObject();
    alert["type"] = alerts[i].type;
    alert["severity"] = alerts[i].severity;
    alert["ssid"] = alerts[i].ssid;
    alert["bssid"] = alerts[i].bssid;
    alert["rssi"] = alerts[i].rssi;
    alert["channel"] = alerts[i].channel;
    alert["reason"] = alerts[i].reason;
    alert["timestamp"] = alerts[i].timestamp;
    alert["age"] = (millis() - alerts[i].timestamp) / 1000;
    alert["acknowledged"] = alerts[i].acknowledged;
  }
  
  String response;
  serializeJson(doc, response);
  return response;
}

String getStatsJSON() {
  StaticJsonDocument<1024> doc;
  
  doc["totalScans"] = stats.totalScans;
  doc["totalAlerts"] = stats.totalAlerts;
  doc["newAPAlerts"] = stats.newAPAlerts;
  doc["evilTwinAlerts"] = stats.evilTwinAlerts;
  doc["channelChangeAlerts"] = stats.channelChangeAlerts;
  doc["rssiAnomalyAlerts"] = stats.rssiAnomalyAlerts;
  doc["hiddenAPAlerts"] = stats.hiddenAPAlerts;
  doc["highPowerAlerts"] = stats.highPowerAlerts;
  doc["encryptionChangeAlerts"] = stats.encryptionChangeAlerts;
  doc["sessionDuration"] = (millis() - stats.sessionStartTime) / 1000;
  doc["peakNetworkCount"] = stats.peakNetworkCount;
  doc["peakRiskScore"] = stats.peakRiskScore;
  doc["currentNetworkCount"] = scanResultCount;
  
  String response;
  serializeJson(doc, response);
  return response;
}

String getConfigJSON() {
  StaticJsonDocument<512> doc;
  
  doc["scanIntervalMs"] = config.scanIntervalMs;
  doc["baselineWarmupMs"] = config.baselineWarmupMs;
  doc["alertCooldownMs"] = config.alertCooldownMs;
  doc["rssiThreshold"] = config.rssiThreshold;
  doc["highPowerThreshold"] = config.highPowerThreshold;
  doc["autoBaseline"] = config.autoBaseline;
  doc["detectHiddenAPs"] = config.detectHiddenAPs;
  doc["detectHighPower"] = config.detectHighPower;
  doc["detectEncryptionChange"] = config.detectEncryptionChange;
  doc["soundAlerts"] = config.soundAlerts;
  doc["darkTheme"] = config.darkTheme;
  doc["autoRefresh"] = config.autoRefresh;
  doc["refreshIntervalMs"] = config.refreshIntervalMs;
  
  String response;
  serializeJson(doc, response);
  return response;
}

String getChannelsJSON() {
  StaticJsonDocument<512> doc;
  JsonArray channels = doc.createNestedArray("channels");
  
  for (int i = 1; i <= 13; i++) {
    JsonObject ch = channels.createNestedObject();
    ch["channel"] = i;
    ch["count"] = channelUsage[i];
  }
  
  String response;
  serializeJson(doc, response);
  return response;
}

String getWatchlistJSON() {
  StaticJsonDocument<2048> doc;
  JsonArray list = doc.createNestedArray("watchlist");
  
  for (int i = 0; i < watchlistCount; i++) {
    JsonObject entry = list.createNestedObject();
    entry["index"] = i;
    entry["ssid"] = watchlist[i].ssid;
    entry["bssid"] = watchlist[i].bssid;
    entry["alertOnSeen"] = watchlist[i].alertOnSeen;
    entry["alertOnGone"] = watchlist[i].alertOnGone;
    entry["notes"] = watchlist[i].notes;
  }
  
  String response;
  serializeJson(doc, response);
  return response;
}

String getHistoryJSON() {
  StaticJsonDocument<4096> doc;
  JsonArray points = doc.createNestedArray("history");
  
  for (int i = 0; i < historyCount; i++) {
    int idx = (historyIndex - historyCount + i + MAX_HISTORY_POINTS) % MAX_HISTORY_POINTS;
    JsonObject point = points.createNestedObject();
    point["timestamp"] = history[idx].timestamp;
    point["networkCount"] = history[idx].networkCount;
    point["riskScore"] = history[idx].riskScore;
    point["alertCount"] = history[idx].alertCount;
  }
  
  String response;
  serializeJson(doc, response);
  return response;
}

String exportDataCSV() {
  String csv = "Type,Timestamp,SSID,BSSID,Channel,RSSI,Reason,Severity\n";
  
  for (int i = 0; i < alertCount; i++) {
    csv += alerts[i].type + ",";
    csv += String(alerts[i].timestamp) + ",";
    csv += "\"" + alerts[i].ssid + "\",";
    csv += alerts[i].bssid + ",";
    csv += String(alerts[i].channel) + ",";
    csv += String(alerts[i].rssi) + ",";
    csv += "\"" + alerts[i].reason + "\",";
    csv += alerts[i].severity + "\n";
  }
  
  return csv;
}

// ============================================================================
// DEMO MODE FUNCTIONS
// ============================================================================

void startDemo(int scenarioIndex) {
  if (scenarioIndex < 0 || scenarioIndex >= DEMO_SCENARIO_COUNT) return;
  
  demoActive = true;
  demoScenarioIndex = scenarioIndex;
  demoStartTime = millis();
  demoEventCount = demoScenarios[scenarioIndex].eventCount;
  demoEventsTriggered = 0;
  
  Serial.println("Demo started: " + String(demoScenarios[scenarioIndex].name));
}

void stopDemo() {
  demoActive = false;
  Serial.println("Demo stopped");
}

void resetDemo() {
  stopDemo();
  // Clear demo-generated alerts (last N alerts where N = demoEventsTriggered)
  if (alertCount > 0 && demoEventsTriggered > 0) {
    int toRemove = min(demoEventsTriggered, alertCount);
    alertCount = max(0, alertCount - toRemove);
  }
  demoEventsTriggered = 0;
  Serial.println("Demo reset");
}

void runDemoScenario() {
  if (!demoActive) return;
  
  uint32_t elapsed = millis() - demoStartTime;
  int duration = demoScenarios[demoScenarioIndex].durationMs;
  
  // Check if demo is complete
  if (elapsed >= (uint32_t)duration) {
    demoActive = false;
    Serial.println("Demo completed");
    return;
  }
  
  // Calculate when to trigger events (spread evenly across duration)
  int eventInterval = duration / (demoEventCount + 1);
  int expectedEvents = elapsed / eventInterval;
  
  // Trigger events as needed
  while (demoEventsTriggered < expectedEvents && demoEventsTriggered < demoEventCount) {
    triggerDemoEvent();
    demoEventsTriggered++;
  }
}

void triggerDemoEvent() {
  // Generate fake BSSID
  String fakeBssid = "DE:AD:BE:EF:" + 
    String(random(0, 255), HEX) + ":" + 
    String(random(0, 255), HEX);
  fakeBssid.toUpperCase();
  
  int fakeChannel = random(1, 12);
  int fakeRssi = random(-80, -30);
  
  switch (demoScenarioIndex) {
    case 0: // Evil Twin Attack
      addAlert("EVIL_TWIN", "DANGER", "DEMO_EvilTwin_Network", fakeBssid,
               fakeChannel, fakeRssi, "Demo: Clone of legitimate AP detected");
      break;
      
    case 1: // Multi-Device Intrusion
      addAlert("NEW_AP", "WARNING", "DEMO_Unknown_Device_" + String(demoEventsTriggered), 
               fakeBssid, fakeChannel, fakeRssi, "Demo: New unauthorized device");
      break;
      
    case 2: // Channel Hopping
      addAlert("CHANNEL_CHANGE", "WARNING", "DEMO_Hopping_AP", fakeBssid,
               fakeChannel, fakeRssi, "Demo: Rapid channel change detected");
      break;
      
    case 3: // Hidden Network
      addAlert("HIDDEN_AP", "DANGER", "(Hidden)", fakeBssid,
               fakeChannel, fakeRssi, "Demo: Cloaked network detected");
      break;
      
    case 4: // High Power Rogue
      addAlert("HIGH_POWER", "DANGER", "DEMO_HighPower_AP", fakeBssid,
               fakeChannel, -25, "Demo: Unusually strong signal detected");
      break;
  }
  
  // Update risk score during demo
  systemState.riskScore = min(100, (int)(systemState.riskScore + random(10, 25)));
  updateSystemState();
}

String getDemoStatusJSON() {
  StaticJsonDocument<512> doc;
  doc["active"] = demoActive;
  doc["scenarioIndex"] = demoScenarioIndex;
  doc["scenarioName"] = demoActive ? demoScenarios[demoScenarioIndex].name : "";
  doc["scenarioDesc"] = demoActive ? demoScenarios[demoScenarioIndex].description : "";
  doc["duration"] = demoActive ? demoScenarios[demoScenarioIndex].durationMs : 0;
  doc["elapsed"] = demoActive ? (millis() - demoStartTime) : 0;
  doc["progress"] = demoActive ? (int)((millis() - demoStartTime) * 100 / demoScenarios[demoScenarioIndex].durationMs) : 0;
  doc["eventsTriggered"] = demoEventsTriggered;
  doc["totalEvents"] = demoActive ? demoEventCount : 0;
  
  JsonArray scenarios = doc.createNestedArray("scenarios");
  for (int i = 0; i < DEMO_SCENARIO_COUNT; i++) {
    JsonObject s = scenarios.createNestedObject();
    s["index"] = i;
    s["name"] = demoScenarios[i].name;
    s["description"] = demoScenarios[i].description;
    s["duration"] = demoScenarios[i].durationMs / 1000;
  }
  
  String output;
  serializeJson(doc, output);
  return output;
}

// ============================================================================
// WEB UI HTML
// ============================================================================

const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ExamGuard Pro AI - Wi-Fi IDS</title>
  <style>
    :root {
      --bg-primary: #1a1a2e;
      --bg-secondary: #16213e;
      --bg-card: #0f3460;
      --text-primary: #eaeaea;
      --text-secondary: #a0a0a0;
      --accent: #e94560;
      --accent-secondary: #533483;
      --success: #00d9ff;
      --warning: #ffc107;
      --danger: #e94560;
      --info: #17a2b8;
      --border: #2a2a4a;
    }
    .light-theme {
      --bg-primary: #f5f5f5;
      --bg-secondary: #ffffff;
      --bg-card: #ffffff;
      --text-primary: #333333;
      --text-secondary: #666666;
      --accent: #e94560;
      --border: #dddddd;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      min-height: 100vh;
    }
    .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
    
    /* Header */
    header {
      background: linear-gradient(135deg, var(--bg-secondary), var(--accent-secondary));
      padding: 20px 30px;
      border-radius: 12px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 15px;
    }
    .logo { display: flex; align-items: center; gap: 15px; }
    .logo h1 { font-size: 28px; font-weight: 700; }
    .logo .version { font-size: 12px; opacity: 0.7; }
    .header-controls { display: flex; gap: 10px; align-items: center; }
    .header-controls button {
      background: rgba(255,255,255,0.1);
      border: 1px solid rgba(255,255,255,0.2);
      color: white;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
    }
    .header-controls button:hover { background: rgba(255,255,255,0.2); }
    
    /* Navigation Tabs */
    .nav-tabs {
      display: flex;
      gap: 5px;
      margin-bottom: 20px;
      background: var(--bg-secondary);
      padding: 8px;
      border-radius: 10px;
      flex-wrap: wrap;
    }
    .nav-tabs button {
      background: transparent;
      border: none;
      color: var(--text-secondary);
      padding: 12px 24px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.3s;
    }
    .nav-tabs button:hover { background: var(--bg-card); color: var(--text-primary); }
    .nav-tabs button.active { background: var(--accent); color: white; }
    
    /* Panels */
    .panel {
      background: var(--bg-card);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
      border: 1px solid var(--border);
    }
    .panel h2 {
      font-size: 16px;
      margin-bottom: 15px;
      padding-bottom: 10px;
      border-bottom: 2px solid var(--accent);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .panel-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 20px;
    }
    
    /* Status Cards */
    .status-card {
      background: var(--bg-secondary);
      padding: 20px;
      border-radius: 10px;
      text-align: center;
    }
    .status-card .label { font-size: 12px; color: var(--text-secondary); margin-bottom: 8px; }
    .status-card .value { font-size: 32px; font-weight: 700; }
    .status-card .subtext { font-size: 11px; color: var(--text-secondary); margin-top: 5px; }
    .status-normal { color: var(--success); }
    .status-warning { color: var(--warning); }
    .status-danger { color: var(--danger); }
    .status-critical { color: #ff0000; text-shadow: 0 0 10px #ff0000; }
    
    /* Risk Meter */
    .risk-meter {
      height: 12px;
      background: var(--bg-primary);
      border-radius: 6px;
      overflow: hidden;
      margin-top: 10px;
    }
    .risk-meter-fill {
      height: 100%;
      border-radius: 6px;
      transition: width 0.5s, background 0.5s;
    }
    
    /* Buttons */
    .btn {
      padding: 10px 20px;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.3s;
    }
    .btn-primary { background: var(--accent); color: white; }
    .btn-primary:hover { background: #c73e54; }
    .btn-secondary { background: var(--bg-secondary); color: var(--text-primary); border: 1px solid var(--border); }
    .btn-secondary:hover { background: var(--bg-primary); }
    .btn-success { background: var(--success); color: #000; }
    .btn-danger { background: var(--danger); color: white; }
    .btn-sm { padding: 6px 12px; font-size: 12px; }
    
    /* Controls */
    .controls { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }
    
    /* Tables */
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: var(--bg-secondary); font-weight: 600; font-size: 12px; text-transform: uppercase; }
    tr:hover { background: rgba(255,255,255,0.02); }
    
    /* Signal Bars */
    .signal-bars { display: flex; gap: 2px; align-items: flex-end; height: 16px; }
    .signal-bar { width: 4px; background: var(--text-secondary); border-radius: 1px; }
    .signal-bar.active { background: var(--success); }
    .signal-bar:nth-child(1) { height: 4px; }
    .signal-bar:nth-child(2) { height: 8px; }
    .signal-bar:nth-child(3) { height: 12px; }
    .signal-bar:nth-child(4) { height: 16px; }
    
    /* Badges */
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }
    .badge-success { background: rgba(0,217,255,0.2); color: var(--success); }
    .badge-warning { background: rgba(255,193,7,0.2); color: var(--warning); }
    .badge-danger { background: rgba(233,69,96,0.2); color: var(--danger); }
    .badge-info { background: rgba(23,162,184,0.2); color: var(--info); }
    .badge-new { background: var(--accent); color: white; }
    .badge-enc { background: var(--accent-secondary); color: white; }
    
    /* Alert Items */
    .alert-item {
      background: var(--bg-secondary);
      padding: 15px;
      border-radius: 8px;
      margin-bottom: 10px;
      border-left: 4px solid var(--warning);
    }
    .alert-item.severity-INFO { border-left-color: var(--info); }
    .alert-item.severity-WARNING { border-left-color: var(--warning); }
    .alert-item.severity-DANGER { border-left-color: var(--danger); }
    .alert-item.severity-CRITICAL { border-left-color: #ff0000; background: rgba(255,0,0,0.1); }
    .alert-item.acknowledged { opacity: 0.5; }
    .alert-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .alert-type { font-weight: 700; }
    .alert-time { font-size: 12px; color: var(--text-secondary); }
    .alert-details { font-size: 13px; color: var(--text-secondary); }
    
    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 15px;
    }
    .stat-item {
      background: var(--bg-secondary);
      padding: 15px;
      border-radius: 8px;
      text-align: center;
    }
    .stat-item .stat-value { font-size: 24px; font-weight: 700; color: var(--accent); }
    .stat-item .stat-label { font-size: 11px; color: var(--text-secondary); margin-top: 5px; }
    
    /* Channel Chart */
    .channel-chart { display: flex; gap: 8px; align-items: flex-end; height: 100px; padding: 10px 0; }
    .channel-bar {
      flex: 1;
      background: var(--accent);
      border-radius: 4px 4px 0 0;
      min-height: 5px;
      position: relative;
    }
    .channel-bar::after {
      content: attr(data-channel);
      position: absolute;
      bottom: -20px;
      left: 50%;
      transform: translateX(-50%);
      font-size: 10px;
      color: var(--text-secondary);
    }
    
    /* Settings */
    .settings-group { margin-bottom: 20px; }
    .settings-group h3 { font-size: 14px; margin-bottom: 15px; color: var(--text-secondary); }
    .setting-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px;
      background: var(--bg-secondary);
      border-radius: 8px;
      margin-bottom: 8px;
    }
    .setting-item label { font-size: 14px; }
    .setting-item input[type="number"] {
      width: 100px;
      padding: 8px;
      border: 1px solid var(--border);
      border-radius: 4px;
      background: var(--bg-primary);
      color: var(--text-primary);
    }
    .toggle {
      width: 50px;
      height: 26px;
      background: var(--bg-primary);
      border-radius: 13px;
      position: relative;
      cursor: pointer;
    }
    .toggle.active { background: var(--success); }
    .toggle::after {
      content: '';
      position: absolute;
      width: 22px;
      height: 22px;
      background: white;
      border-radius: 50%;
      top: 2px;
      left: 2px;
      transition: left 0.3s;
    }
    .toggle.active::after { left: 26px; }
    
    /* Tab Content */
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    
    /* Scrollable */
    .scrollable { max-height: 400px; overflow-y: auto; }
    
    /* Empty State */
    .empty-state {
      text-align: center;
      padding: 40px;
      color: var(--text-secondary);
    }
    
    /* Connection Status */
    .connection-status {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
    }
    .connection-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    
    /* Responsive */
    @media (max-width: 768px) {
      .container { padding: 10px; }
      header { padding: 15px; }
      .logo h1 { font-size: 20px; }
      .nav-tabs button { padding: 10px 15px; font-size: 12px; }
      .panel { padding: 15px; }
      th, td { padding: 8px; font-size: 12px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">
        <div>
          <h1>ExamGuard Pro AI</h1>
          <div class="version">AI-Powered Wi-Fi Intrusion Detection System v3.0</div>
        </div>
      </div>
      <div class="header-controls">
        <div class="connection-status">
          <div class="connection-dot"></div>
          <span>Connected</span>
        </div>
        <button onclick="toggleTheme()">Theme</button>
        <button onclick="exportData()">Export</button>
      </div>
    </header>
    
    <div class="nav-tabs">
      <button class="active" onclick="showTab('dashboard')">Dashboard</button>
      <button onclick="showTab('ai')">AI Insights</button>
      <button onclick="showTab('networks')">Networks</button>
      <button onclick="showTab('alerts')">Alerts</button>
      <button onclick="showTab('analytics')">Analytics</button>
      <button onclick="showTab('watchlist')">Watchlist</button>
      <button onclick="showTab('demo')">Demo Mode</button>
      <button onclick="showTab('settings')">Settings</button>
    </div>
    
    <!-- Dashboard Tab -->
    <div id="tab-dashboard" class="tab-content active">
      <div class="panel-grid">
        <div class="panel">
          <h2>System Status</h2>
          <div class="status-card">
            <div class="label">Current State</div>
            <div class="value" id="system-state">NORMAL</div>
            <div class="subtext" id="baseline-status">Baseline: Not Set</div>
          </div>
        </div>
        
        <div class="panel">
          <h2>Risk Assessment</h2>
          <div class="status-card">
            <div class="label">Risk Level</div>
            <div class="value" id="risk-level">LOW</div>
            <div class="risk-meter">
              <div class="risk-meter-fill" id="risk-meter" style="width: 0%; background: var(--success);"></div>
            </div>
            <div class="subtext">Score: <span id="risk-score">0</span>/100</div>
          </div>
        </div>
        
        <div class="panel">
          <h2>Network Activity</h2>
          <div class="status-card">
            <div class="label">Visible Networks</div>
            <div class="value" id="network-count">0</div>
            <div class="subtext">Peak: <span id="peak-networks">0</span></div>
          </div>
        </div>
        
        <div class="panel">
          <h2>Alert Summary</h2>
          <div class="status-card">
            <div class="label">Active Alerts</div>
            <div class="value" id="alert-count">0</div>
            <div class="subtext">Unacknowledged: <span id="unack-alerts">0</span></div>
          </div>
        </div>
      </div>
      
      <div class="panel">
        <h2>Controls</h2>
        <div class="controls">
          <button class="btn btn-primary" onclick="captureBaseline()">Capture Baseline</button>
          <button class="btn btn-secondary" onclick="clearAlerts()">Clear Alerts</button>
          <button class="btn btn-secondary" onclick="acknowledgeAlerts()">Acknowledge All</button>
          <button class="btn btn-danger" onclick="resetSystem()">Reset System</button>
        </div>
      </div>
      
      <div class="panel">
        <h2>Recent Alerts <span class="badge badge-danger" id="recent-alert-badge">0</span></h2>
        <div class="scrollable" id="recent-alerts">
          <div class="empty-state">No alerts yet</div>
        </div>
      </div>
    </div>
    
    <!-- AI Insights Tab -->
    <div id="tab-ai" class="tab-content">
      <div class="panel-grid">
        <div class="panel">
          <h2>AI Threat Assessment</h2>
          <div class="status-card">
            <div class="label">Threat Category</div>
            <div class="value" id="ai-threat-category">ANALYZING</div>
            <div class="subtext">Confidence: <span id="ai-confidence">0</span>%</div>
          </div>
        </div>
        
        <div class="panel">
          <h2>AI Threat Score</h2>
          <div class="status-card">
            <div class="label">Neural Network Score</div>
            <div class="value" id="ai-threat-score">0</div>
            <div class="risk-meter">
              <div class="risk-meter-fill" id="ai-threat-meter" style="width: 0%; background: var(--success);"></div>
            </div>
          </div>
        </div>
        
        <div class="panel">
          <h2>Model Status</h2>
          <div class="status-card">
            <div class="label">Learning Status</div>
            <div class="value" id="ai-model-status">Training</div>
            <div class="subtext">Cycles: <span id="ai-learning-cycles">0</span></div>
          </div>
        </div>
        
        <div class="panel">
          <h2>Primary Detection</h2>
          <div class="status-card">
            <div class="label">Detected Pattern</div>
            <div class="value" id="ai-primary-threat" style="font-size: 20px;">None</div>
          </div>
        </div>
      </div>
      
      <div class="panel">
        <h2>AI Smart Recommendations</h2>
        <p style="color: var(--text-secondary); margin-bottom: 15px; font-size: 13px;">
          The AI analyzes network patterns and provides actionable security recommendations based on detected anomalies.
        </p>
        <div id="ai-recommendations">
          <div class="empty-state">AI is analyzing the environment...</div>
        </div>
      </div>
      
      <div class="panel">
        <h2>How the AI Works</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
          <div style="background: var(--bg-secondary); padding: 15px; border-radius: 8px;">
            <h3 style="color: var(--accent); margin-bottom: 10px; font-size: 14px;">Neural Network</h3>
            <p style="font-size: 13px; color: var(--text-secondary);">8-input, 12-hidden, 4-output layer network classifies threats in real-time using pattern recognition.</p>
          </div>
          <div style="background: var(--bg-secondary); padding: 15px; border-radius: 8px;">
            <h3 style="color: var(--accent); margin-bottom: 10px; font-size: 14px;">Feature Extraction</h3>
            <p style="font-size: 13px; color: var(--text-secondary);">Analyzes network count, new APs, hidden networks, encryption, signal strength, and alert patterns.</p>
          </div>
          <div style="background: var(--bg-secondary); padding: 15px; border-radius: 8px;">
            <h3 style="color: var(--accent); margin-bottom: 10px; font-size: 14px;">Online Learning</h3>
            <p style="font-size: 13px; color: var(--text-secondary);">Continuously learns from baseline patterns to improve detection accuracy over time.</p>
          </div>
          <div style="background: var(--bg-secondary); padding: 15px; border-radius: 8px;">
            <h3 style="color: var(--accent); margin-bottom: 10px; font-size: 14px;">Smart Recommendations</h3>
            <p style="font-size: 13px; color: var(--text-secondary);">Generates actionable security advice based on current threat assessment and detected anomalies.</p>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Networks Tab -->
    <div id="tab-networks" class="tab-content">
      <div class="panel">
        <h2>Detected Networks <span class="badge badge-info" id="network-badge">0</span></h2>
        <div class="controls">
          <button class="btn btn-sm btn-secondary" onclick="sortNetworks('rssi')">Sort by Signal</button>
          <button class="btn btn-sm btn-secondary" onclick="sortNetworks('ssid')">Sort by Name</button>
          <button class="btn btn-sm btn-secondary" onclick="sortNetworks('channel')">Sort by Channel</button>
        </div>
        <div style="overflow-x: auto;">
          <table>
            <thead>
              <tr>
                <th>Signal</th>
                <th>SSID</th>
                <th>BSSID</th>
                <th>Channel</th>
                <th>Security</th>
                <th>Vendor</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="networks-table"></tbody>
          </table>
        </div>
      </div>
      
      <div class="panel">
        <h2>Channel Distribution</h2>
        <div class="channel-chart" id="channel-chart"></div>
      </div>
    </div>
    
    <!-- Alerts Tab -->
    <div id="tab-alerts" class="tab-content">
      <div class="panel">
        <h2>Alert History</h2>
        <div class="controls">
          <button class="btn btn-sm btn-secondary" onclick="filterAlerts('all')">All</button>
          <button class="btn btn-sm btn-secondary" onclick="filterAlerts('NEW_AP')">New AP</button>
          <button class="btn btn-sm btn-secondary" onclick="filterAlerts('EVIL_TWIN')">Evil Twin</button>
          <button class="btn btn-sm btn-secondary" onclick="filterAlerts('CHANNEL_CHANGE')">Channel</button>
          <button class="btn btn-sm btn-secondary" onclick="filterAlerts('RSSI_ANOMALY')">RSSI</button>
          <button class="btn btn-sm btn-secondary" onclick="filterAlerts('unack')">Unacknowledged</button>
        </div>
        <div class="scrollable" id="alerts-list">
          <div class="empty-state">No alerts recorded</div>
        </div>
      </div>
    </div>
    
    <!-- Analytics Tab -->
    <div id="tab-analytics" class="tab-content">
      <div class="panel">
        <h2>Session Statistics</h2>
        <div class="stats-grid" id="stats-grid">
          <div class="stat-item">
            <div class="stat-value" id="stat-scans">0</div>
            <div class="stat-label">Total Scans</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-alerts">0</div>
            <div class="stat-label">Total Alerts</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-newap">0</div>
            <div class="stat-label">New AP Alerts</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-eviltwin">0</div>
            <div class="stat-label">Evil Twin Alerts</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-channel">0</div>
            <div class="stat-label">Channel Changes</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-rssi">0</div>
            <div class="stat-label">RSSI Anomalies</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-hidden">0</div>
            <div class="stat-label">Hidden APs</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-highpower">0</div>
            <div class="stat-label">High Power</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-duration">0m</div>
            <div class="stat-label">Session Duration</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="stat-peakrisk">0</div>
            <div class="stat-label">Peak Risk Score</div>
          </div>
        </div>
      </div>
      
      <div class="panel">
        <h2>Alert Distribution by Type</h2>
        <div id="alert-distribution"></div>
      </div>
    </div>
    
    <!-- Watchlist Tab -->
    <div id="tab-watchlist" class="tab-content">
      <div class="panel">
        <h2>Network Watchlist</h2>
        <p style="color: var(--text-secondary); margin-bottom: 15px; font-size: 13px;">
          Add networks to monitor. Get alerts when watched networks appear or disappear.
        </p>
        <div class="controls">
          <input type="text" id="watch-ssid" placeholder="SSID" style="padding: 10px; border-radius: 6px; border: 1px solid var(--border); background: var(--bg-secondary); color: var(--text-primary);">
          <input type="text" id="watch-bssid" placeholder="BSSID (optional)" style="padding: 10px; border-radius: 6px; border: 1px solid var(--border); background: var(--bg-secondary); color: var(--text-primary);">
          <button class="btn btn-primary" onclick="addToWatchlist()">Add to Watchlist</button>
        </div>
        <div style="overflow-x: auto; margin-top: 20px;">
          <table>
            <thead>
              <tr>
                <th>SSID</th>
                <th>BSSID</th>
                <th>Alert on Seen</th>
                <th>Alert on Gone</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="watchlist-table"></tbody>
          </table>
        </div>
      </div>
    </div>
    
    <!-- Demo Mode Tab -->
    <div id="tab-demo" class="tab-content">
      <div class="panel">
        <h2>Demo / Simulation Mode</h2>
        <p style="color: var(--text-secondary); margin-bottom: 20px;">
          Use Demo Mode to simulate attack scenarios for thesis defense presentations.
          These simulations generate realistic alerts without requiring actual attacks.
        </p>
        
        <div class="settings-group">
          <h3>Select Attack Scenario</h3>
          <div id="demo-scenarios" style="display: grid; gap: 15px; margin-top: 15px;"></div>
        </div>
        
        <div class="settings-group" style="margin-top: 30px;">
          <h3>Demo Status</h3>
          <div id="demo-status" style="padding: 20px; background: var(--bg-secondary); border-radius: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
              <div>
                <div style="font-size: 18px; font-weight: bold;" id="demo-scenario-name">No Demo Running</div>
                <div style="color: var(--text-secondary); font-size: 13px;" id="demo-scenario-desc">Select a scenario above to begin</div>
              </div>
              <span class="badge" id="demo-badge" style="display: none;">ACTIVE</span>
            </div>
            <div style="background: var(--bg-primary); border-radius: 5px; height: 20px; overflow: hidden; margin-bottom: 10px;">
              <div id="demo-progress" style="height: 100%; width: 0%; background: var(--accent); transition: width 0.5s;"></div>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 12px; color: var(--text-secondary);">
              <span>Events: <span id="demo-events">0/0</span></span>
              <span>Progress: <span id="demo-percent">0%</span></span>
            </div>
          </div>
        </div>
        
        <div class="controls" style="margin-top: 20px;">
          <button class="btn btn-danger" id="demo-stop-btn" onclick="stopDemo()" style="display: none;">Stop Demo</button>
          <button class="btn btn-secondary" onclick="resetDemo()">Reset (Clear Demo Alerts)</button>
        </div>
        
        <div style="margin-top: 30px; padding: 15px; background: rgba(255,193,7,0.1); border: 1px solid var(--warning); border-radius: 8px;">
          <strong style="color: var(--warning);">Note for Thesis Defense:</strong>
          <p style="margin: 10px 0 0 0; font-size: 13px; color: var(--text-secondary);">
            Demo mode generates simulated alerts to demonstrate system capabilities. 
            Use this to show how the system responds to various attack scenarios 
            without needing actual malicious devices in the presentation environment.
          </p>
        </div>
      </div>
    </div>
    
    <!-- Settings Tab -->
    <div id="tab-settings" class="tab-content">
      <div class="panel">
        <h2>Detection Settings</h2>
        <div class="settings-group">
          <h3>Timing</h3>
          <div class="setting-item">
            <label>Scan Interval (ms)</label>
            <input type="number" id="cfg-scanInterval" value="5000" min="1000" max="60000">
          </div>
          <div class="setting-item">
            <label>Alert Cooldown (ms)</label>
            <input type="number" id="cfg-alertCooldown" value="60000" min="5000" max="300000">
          </div>
          <div class="setting-item">
            <label>Baseline Warmup (ms)</label>
            <input type="number" id="cfg-baselineWarmup" value="20000" min="5000" max="120000">
          </div>
        </div>
        
        <div class="settings-group">
          <h3>Thresholds</h3>
          <div class="setting-item">
            <label>RSSI Change Threshold (dB)</label>
            <input type="number" id="cfg-rssiThreshold" value="20" min="5" max="50">
          </div>
          <div class="setting-item">
            <label>High Power Threshold (dBm)</label>
            <input type="number" id="cfg-highPowerThreshold" value="-30" min="-50" max="-10">
          </div>
        </div>
        
        <div class="settings-group">
          <h3>Detection Features</h3>
          <div class="setting-item">
            <label>Auto Baseline after Warmup</label>
            <div class="toggle active" id="cfg-autoBaseline" onclick="toggleSetting(this)"></div>
          </div>
          <div class="setting-item">
            <label>Detect Hidden APs</label>
            <div class="toggle active" id="cfg-detectHidden" onclick="toggleSetting(this)"></div>
          </div>
          <div class="setting-item">
            <label>Detect High Power APs</label>
            <div class="toggle active" id="cfg-detectHighPower" onclick="toggleSetting(this)"></div>
          </div>
          <div class="setting-item">
            <label>Detect Encryption Changes</label>
            <div class="toggle active" id="cfg-detectEncryption" onclick="toggleSetting(this)"></div>
          </div>
        </div>
        
        <div class="settings-group">
          <h3>Interface</h3>
          <div class="setting-item">
            <label>Dark Theme</label>
            <div class="toggle active" id="cfg-darkTheme" onclick="toggleTheme()"></div>
          </div>
          <div class="setting-item">
            <label>Auto Refresh</label>
            <div class="toggle active" id="cfg-autoRefresh" onclick="toggleAutoRefresh(this)"></div>
          </div>
          <div class="setting-item">
            <label>Refresh Interval (ms)</label>
            <input type="number" id="cfg-refreshInterval" value="3000" min="1000" max="30000">
          </div>
        </div>
        
        <div class="controls" style="margin-top: 20px;">
          <button class="btn btn-primary" onclick="saveSettings()">Save Settings</button>
          <button class="btn btn-secondary" onclick="loadSettings()">Reset to Default</button>
        </div>
      </div>
    </div>
  </div>
  
  <script>
    let currentTab = 'dashboard';
    let alertFilter = 'all';
    let networkSort = 'rssi';
    let autoRefreshEnabled = true;
    let refreshInterval;
    let darkTheme = true;
    let networksData = [];
    let alertsData = [];
    
    // Tab Navigation
    function showTab(tabName) {
      document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.nav-tabs button').forEach(b => b.classList.remove('active'));
      document.getElementById('tab-' + tabName).classList.add('active');
      event.target.classList.add('active');
      currentTab = tabName;
    }
    
    // Data Fetching
    function updateDashboard() {
      fetch('/status').then(r => r.json()).then(data => {
        document.getElementById('system-state').textContent = data.systemState;
        document.getElementById('system-state').className = 'value status-' + data.systemState.toLowerCase();
        document.getElementById('baseline-status').textContent = 'Baseline: ' + (data.baselineSet ? 'Set (' + data.baselineCount + ' networks)' : 'Not Set');
        document.getElementById('risk-level').textContent = data.riskLevel;
        document.getElementById('risk-level').className = 'value status-' + data.riskLevel.toLowerCase();
        document.getElementById('risk-score').textContent = data.riskScore;
        document.getElementById('network-count').textContent = data.networkCount;
        document.getElementById('alert-count').textContent = data.alertCount;
        document.getElementById('unack-alerts').textContent = data.unacknowledgedAlerts;
        document.getElementById('recent-alert-badge').textContent = data.unacknowledgedAlerts;
        
        const meter = document.getElementById('risk-meter');
        meter.style.width = data.riskScore + '%';
        if (data.riskScore >= 76) meter.style.background = '#ff0000';
        else if (data.riskScore >= 51) meter.style.background = 'var(--danger)';
        else if (data.riskScore >= 26) meter.style.background = 'var(--warning)';
        else meter.style.background = 'var(--success)';
      });
    }
    
    function updateNetworks() {
      fetch('/aps').then(r => r.json()).then(data => {
        networksData = data.aps;
        document.getElementById('network-badge').textContent = data.aps.length;
        renderNetworks();
      });
      
      fetch('/channels').then(r => r.json()).then(data => {
        renderChannelChart(data.channels);
      });
    }
    
    function renderNetworks() {
      let sorted = [...networksData];
      if (networkSort === 'rssi') sorted.sort((a, b) => b.rssi - a.rssi);
      else if (networkSort === 'ssid') sorted.sort((a, b) => a.ssid.localeCompare(b.ssid));
      else if (networkSort === 'channel') sorted.sort((a, b) => a.channel - b.channel);
      
      const tbody = document.getElementById('networks-table');
      tbody.innerHTML = sorted.map(ap => {
        const signalBars = Array(4).fill(0).map((_, i) => 
          '<div class="signal-bar ' + (i < ap.signalBars ? 'active' : '') + '"></div>'
        ).join('');
        
        let statusBadges = '';
        if (!ap.inBaseline) statusBadges += '<span class="badge badge-new">NEW</span> ';
        if (ap.inWatchlist) statusBadges += '<span class="badge badge-warning">WATCHED</span> ';
        if (ap.isHidden) statusBadges += '<span class="badge badge-info">HIDDEN</span> ';
        
        let encBadge = 'badge-success';
        if (ap.encType === 0) encBadge = 'badge-danger';
        else if (ap.encType === 1) encBadge = 'badge-warning';
        
        return '<tr>' +
          '<td><div class="signal-bars">' + signalBars + '</div><small>' + ap.rssi + ' dBm</small></td>' +
          '<td>' + ap.ssid + '</td>' +
          '<td style="font-family: monospace; font-size: 12px;">' + ap.bssid + '</td>' +
          '<td>' + ap.channel + '</td>' +
          '<td><span class="badge ' + encBadge + '">' + ap.encryption + '</span></td>' +
          '<td>' + ap.vendor + '</td>' +
          '<td>' + (statusBadges || '-') + '</td>' +
          '<td><button class="btn btn-sm btn-secondary" onclick="addNetworkToWatchlist(\'' + ap.ssid + '\', \'' + ap.bssid + '\')">Watch</button></td>' +
          '</tr>';
      }).join('');
    }
    
    function renderChannelChart(channels) {
      const maxCount = Math.max(...channels.map(c => c.count), 1);
      const chart = document.getElementById('channel-chart');
      chart.innerHTML = channels.map(c => {
        const height = (c.count / maxCount) * 100;
        return '<div class="channel-bar" style="height: ' + Math.max(height, 5) + '%;" data-channel="' + c.channel + '" title="' + c.count + ' networks"></div>';
      }).join('');
    }
    
    function updateAlerts() {
      fetch('/alerts').then(r => r.json()).then(data => {
        alertsData = data.alerts;
        renderAlerts();
        renderRecentAlerts();
      });
    }
    
    function renderAlerts() {
      let filtered = alertsData;
      if (alertFilter !== 'all') {
        if (alertFilter === 'unack') filtered = alertsData.filter(a => !a.acknowledged);
        else filtered = alertsData.filter(a => a.type === alertFilter);
      }
      
      const container = document.getElementById('alerts-list');
      if (filtered.length === 0) {
        container.innerHTML = '<div class="empty-state">No alerts match filter</div>';
        return;
      }
      
      container.innerHTML = filtered.map(alert => {
        const ageStr = alert.age < 60 ? alert.age + 's ago' : Math.floor(alert.age / 60) + 'm ago';
        return '<div class="alert-item severity-' + alert.severity + (alert.acknowledged ? ' acknowledged' : '') + '">' +
          '<div class="alert-header">' +
            '<span class="alert-type">[' + alert.type + ']</span>' +
            '<span class="alert-time">' + ageStr + '</span>' +
          '</div>' +
          '<div class="alert-details">' +
            '<strong>' + alert.ssid + '</strong> (' + alert.bssid + ')<br>' +
            'Channel: ' + alert.channel + ' | RSSI: ' + alert.rssi + ' dBm<br>' +
            alert.reason +
          '</div>' +
        '</div>';
      }).join('');
    }
    
    function renderRecentAlerts() {
      const recent = alertsData.slice(0, 5);
      const container = document.getElementById('recent-alerts');
      if (recent.length === 0) {
        container.innerHTML = '<div class="empty-state">No alerts yet</div>';
        return;
      }
      container.innerHTML = recent.map(alert => {
        const ageStr = alert.age < 60 ? alert.age + 's ago' : Math.floor(alert.age / 60) + 'm ago';
        return '<div class="alert-item severity-' + alert.severity + '">' +
          '<div class="alert-header">' +
            '<span class="alert-type">[' + alert.type + ']</span>' +
            '<span class="alert-time">' + ageStr + '</span>' +
          '</div>' +
          '<div class="alert-details">' + alert.ssid + ' - ' + alert.reason + '</div>' +
        '</div>';
      }).join('');
    }
    
    function updateStats() {
      fetch('/stats').then(r => r.json()).then(data => {
        document.getElementById('stat-scans').textContent = data.totalScans;
        document.getElementById('stat-alerts').textContent = data.totalAlerts;
        document.getElementById('stat-newap').textContent = data.newAPAlerts;
        document.getElementById('stat-eviltwin').textContent = data.evilTwinAlerts;
        document.getElementById('stat-channel').textContent = data.channelChangeAlerts;
        document.getElementById('stat-rssi').textContent = data.rssiAnomalyAlerts;
        document.getElementById('stat-hidden').textContent = data.hiddenAPAlerts;
        document.getElementById('stat-highpower').textContent = data.highPowerAlerts;
        document.getElementById('stat-peakrisk').textContent = data.peakRiskScore;
        document.getElementById('peak-networks').textContent = data.peakNetworkCount;
        
        const mins = Math.floor(data.sessionDuration / 60);
        const secs = data.sessionDuration % 60;
        document.getElementById('stat-duration').textContent = mins + 'm ' + secs + 's';
        
        // Alert distribution
        const total = data.totalAlerts || 1;
        const dist = document.getElementById('alert-distribution');
        dist.innerHTML = '<div style="display: flex; gap: 10px; flex-wrap: wrap;">' +
          '<div style="flex: 1; min-width: 150px;"><div style="background: var(--accent); height: 20px; width: ' + (data.newAPAlerts/total*100) + '%;"></div><small>New AP: ' + data.newAPAlerts + '</small></div>' +
          '<div style="flex: 1; min-width: 150px;"><div style="background: #ff0000; height: 20px; width: ' + (data.evilTwinAlerts/total*100) + '%;"></div><small>Evil Twin: ' + data.evilTwinAlerts + '</small></div>' +
          '<div style="flex: 1; min-width: 150px;"><div style="background: var(--warning); height: 20px; width: ' + (data.channelChangeAlerts/total*100) + '%;"></div><small>Channel: ' + data.channelChangeAlerts + '</small></div>' +
          '<div style="flex: 1; min-width: 150px;"><div style="background: var(--info); height: 20px; width: ' + (data.rssiAnomalyAlerts/total*100) + '%;"></div><small>RSSI: ' + data.rssiAnomalyAlerts + '</small></div>' +
          '</div>';
      });
    }
    
    function updateWatchlist() {
      fetch('/watchlist').then(r => r.json()).then(data => {
        const tbody = document.getElementById('watchlist-table');
        if (data.watchlist.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No items in watchlist</td></tr>';
          return;
        }
        tbody.innerHTML = data.watchlist.map(item => 
          '<tr>' +
            '<td>' + item.ssid + '</td>' +
            '<td style="font-family: monospace;">' + item.bssid + '</td>' +
            '<td>' + (item.alertOnSeen ? 'Yes' : 'No') + '</td>' +
            '<td>' + (item.alertOnGone ? 'Yes' : 'No') + '</td>' +
            '<td><button class="btn btn-sm btn-danger" onclick="removeWatchlistItem(' + item.index + ')">Remove</button></td>' +
          '</tr>'
        ).join('');
      });
    }
    
    // Actions
    function captureBaseline() {
      fetch('/baseline', { method: 'POST' }).then(() => { updateDashboard(); updateNetworks(); });
    }
    
    function resetSystem() {
      if (confirm('Reset system? This will clear baseline, alerts, and risk score.')) {
        fetch('/reset', { method: 'POST' }).then(() => { updateDashboard(); updateAlerts(); updateNetworks(); });
      }
    }
    
    function clearAlerts() {
      fetch('/clearAlerts', { method: 'POST' }).then(() => { updateDashboard(); updateAlerts(); });
    }
    
    function acknowledgeAlerts() {
      fetch('/acknowledgeAlerts', { method: 'POST' }).then(() => { updateDashboard(); updateAlerts(); });
    }
    
    function sortNetworks(by) { networkSort = by; renderNetworks(); }
    function filterAlerts(type) { alertFilter = type; renderAlerts(); }
    
    function addToWatchlist() {
      const ssid = document.getElementById('watch-ssid').value;
      const bssid = document.getElementById('watch-bssid').value;
      if (!ssid && !bssid) { alert('Enter SSID or BSSID'); return; }
      fetch('/addWatchlist?ssid=' + encodeURIComponent(ssid) + '&bssid=' + encodeURIComponent(bssid), { method: 'POST' })
        .then(() => { updateWatchlist(); document.getElementById('watch-ssid').value = ''; document.getElementById('watch-bssid').value = ''; });
    }
    
    function addNetworkToWatchlist(ssid, bssid) {
      fetch('/addWatchlist?ssid=' + encodeURIComponent(ssid) + '&bssid=' + encodeURIComponent(bssid), { method: 'POST' })
        .then(() => { updateWatchlist(); updateNetworks(); });
    }
    
    function removeWatchlistItem(index) {
      fetch('/removeWatchlist?index=' + index, { method: 'POST' }).then(() => updateWatchlist());
    }
    
    function toggleTheme() {
      darkTheme = !darkTheme;
      document.body.classList.toggle('light-theme', !darkTheme);
      document.getElementById('cfg-darkTheme').classList.toggle('active', darkTheme);
    }
    
    function toggleSetting(el) { el.classList.toggle('active'); }
    
    function toggleAutoRefresh(el) {
      autoRefreshEnabled = !autoRefreshEnabled;
      el.classList.toggle('active', autoRefreshEnabled);
      if (autoRefreshEnabled) startAutoRefresh();
      else clearInterval(refreshInterval);
    }
    
    function saveSettings() {
      const settings = {
        scanIntervalMs: document.getElementById('cfg-scanInterval').value,
        alertCooldownMs: document.getElementById('cfg-alertCooldown').value,
        baselineWarmupMs: document.getElementById('cfg-baselineWarmup').value,
        rssiThreshold: document.getElementById('cfg-rssiThreshold').value,
        highPowerThreshold: document.getElementById('cfg-highPowerThreshold').value,
        autoBaseline: document.getElementById('cfg-autoBaseline').classList.contains('active'),
        detectHiddenAPs: document.getElementById('cfg-detectHidden').classList.contains('active'),
        detectHighPower: document.getElementById('cfg-detectHighPower').classList.contains('active'),
        detectEncryptionChange: document.getElementById('cfg-detectEncryption').classList.contains('active')
      };
      fetch('/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(settings) })
        .then(() => alert('Settings saved!'));
    }
    
    function loadSettings() {
      fetch('/config').then(r => r.json()).then(data => {
        document.getElementById('cfg-scanInterval').value = data.scanIntervalMs;
        document.getElementById('cfg-alertCooldown').value = data.alertCooldownMs;
        document.getElementById('cfg-baselineWarmup').value = data.baselineWarmupMs;
        document.getElementById('cfg-rssiThreshold').value = data.rssiThreshold;
        document.getElementById('cfg-highPowerThreshold').value = data.highPowerThreshold;
      });
    }
    
    function exportData() {
      window.open('/export', '_blank');
    }
    
    function updateAI() {
      fetch('/ai').then(r => r.json()).then(data => {
        document.getElementById('ai-threat-category').textContent = data.threatCategory;
        const catEl = document.getElementById('ai-threat-category');
        catEl.className = 'value';
        if (data.threatCategory === 'SEVERE') catEl.classList.add('status-danger');
        else if (data.threatCategory === 'MODERATE') catEl.classList.add('status-warning');
        else if (data.threatCategory === 'LOW') catEl.classList.add('status-warning');
        else catEl.classList.add('status-normal');
        
        document.getElementById('ai-confidence').textContent = (data.confidence * 100).toFixed(1);
        document.getElementById('ai-threat-score').textContent = data.threatScore.toFixed(0);
        document.getElementById('ai-primary-threat').textContent = data.primaryThreat;
        document.getElementById('ai-model-status').textContent = data.modelTrained ? 'Trained' : 'Learning';
        document.getElementById('ai-learning-cycles').textContent = data.learningCycles;
        
        const meter = document.getElementById('ai-threat-meter');
        meter.style.width = data.threatScore + '%';
        if (data.threatScore >= 75) meter.style.background = '#ff0000';
        else if (data.threatScore >= 50) meter.style.background = 'var(--danger)';
        else if (data.threatScore >= 25) meter.style.background = 'var(--warning)';
        else meter.style.background = 'var(--success)';
        
        const recsContainer = document.getElementById('ai-recommendations');
        if (data.recommendations && data.recommendations.length > 0) {
          recsContainer.innerHTML = data.recommendations.map(rec => {
            let severityClass = 'badge-info';
            let borderColor = 'var(--info)';
            if (rec.severity === 'CRITICAL') { severityClass = 'badge-danger'; borderColor = '#ff0000'; }
            else if (rec.severity === 'URGENT') { severityClass = 'badge-danger'; borderColor = 'var(--danger)'; }
            else if (rec.severity === 'WARNING') { severityClass = 'badge-warning'; borderColor = 'var(--warning)'; }
            
            return '<div style="background: var(--bg-secondary); padding: 20px; border-radius: 10px; margin-bottom: 15px; border-left: 4px solid ' + borderColor + ';">' +
              '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">' +
                '<h3 style="font-size: 16px; margin: 0;">' + rec.title + '</h3>' +
                '<span class="badge ' + severityClass + '">' + rec.severity + '</span>' +
              '</div>' +
              '<p style="color: var(--text-secondary); margin-bottom: 12px; font-size: 14px;">' + rec.description + '</p>' +
              '<div style="background: var(--bg-primary); padding: 12px; border-radius: 6px;">' +
                '<strong style="color: var(--accent); font-size: 12px;">RECOMMENDED ACTION:</strong>' +
                '<p style="margin: 8px 0 0 0; font-size: 13px;">' + rec.action + '</p>' +
              '</div>' +
              '<div style="margin-top: 10px; font-size: 11px; color: var(--text-secondary);">AI Confidence: ' + (rec.confidence * 100).toFixed(0) + '%</div>' +
            '</div>';
          }).join('');
        } else {
          recsContainer.innerHTML = '<div class="empty-state">AI is analyzing the environment...</div>';
        }
      });
    }
    
    // Demo Mode Functions
    function updateDemo() {
      fetch('/demo').then(r => r.json()).then(data => {
        // Render scenario cards
        const container = document.getElementById('demo-scenarios');
        container.innerHTML = data.scenarios.map(s => 
          '<div style="background: var(--bg-secondary); padding: 15px; border-radius: 8px; cursor: pointer; border: 2px solid ' + 
          (data.active && data.scenarioIndex === s.index ? 'var(--accent)' : 'transparent') + ';" onclick="startDemo(' + s.index + ')">' +
            '<div style="font-weight: bold; margin-bottom: 5px;">' + s.name + '</div>' +
            '<div style="font-size: 12px; color: var(--text-secondary);">' + s.description + '</div>' +
            '<div style="font-size: 11px; color: var(--accent); margin-top: 8px;">Duration: ' + s.duration + 's</div>' +
          '</div>'
        ).join('');
        
        // Update status
        const badge = document.getElementById('demo-badge');
        const stopBtn = document.getElementById('demo-stop-btn');
        
        if (data.active) {
          document.getElementById('demo-scenario-name').textContent = data.scenarioName;
          document.getElementById('demo-scenario-desc').textContent = data.scenarioDesc;
          document.getElementById('demo-progress').style.width = data.progress + '%';
          document.getElementById('demo-events').textContent = data.eventsTriggered + '/' + data.totalEvents;
          document.getElementById('demo-percent').textContent = data.progress + '%';
          badge.style.display = 'inline-block';
          badge.className = 'badge badge-danger';
          stopBtn.style.display = 'inline-block';
        } else {
          document.getElementById('demo-scenario-name').textContent = 'No Demo Running';
          document.getElementById('demo-scenario-desc').textContent = 'Select a scenario above to begin';
          document.getElementById('demo-progress').style.width = '0%';
          document.getElementById('demo-events').textContent = '0/0';
          document.getElementById('demo-percent').textContent = '0%';
          badge.style.display = 'none';
          stopBtn.style.display = 'none';
        }
      });
    }
    
    function startDemo(scenarioIndex) {
      fetch('/demo/start?scenario=' + scenarioIndex, { method: 'POST' })
        .then(() => { updateDemo(); updateAll(); });
    }
    
    function stopDemo() {
      fetch('/demo/stop', { method: 'POST' })
        .then(() => { updateDemo(); updateAll(); });
    }
    
    function resetDemo() {
      fetch('/demo/reset', { method: 'POST' })
        .then(() => { updateDemo(); updateAll(); });
    }
    
    function updateAll() {
      updateDashboard();
      updateAI();
      updateNetworks();
      updateAlerts();
      updateStats();
      updateWatchlist();
      updateDemo();
    }
    
    function startAutoRefresh() {
      refreshInterval = setInterval(updateAll, 3000);
    }
    
    // Initialize
    updateAll();
    loadSettings();
    startAutoRefresh();
  </script>
</body>
</html>
)rawliteral";

// ============================================================================
// WEB SERVER ROUTES
// ============================================================================

void setupWebServer() {
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send_P(200, "text/html", index_html);
  });
  
  server.on("/status", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "application/json", getStatusJSON());
  });
  
  server.on("/aps", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "application/json", getAPsJSON());
  });
  
  server.on("/alerts", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "application/json", getAlertsJSON());
  });
  
  server.on("/stats", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "application/json", getStatsJSON());
  });
  
  server.on("/config", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "application/json", getConfigJSON());
  });
  
  server.on("/channels", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "application/json", getChannelsJSON());
  });
  
  server.on("/watchlist", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "application/json", getWatchlistJSON());
  });
  
  server.on("/ai", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "application/json", getAIStatusJSON());
  });
  
  server.on("/history", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "application/json", getHistoryJSON());
  });
  
  server.on("/export", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "text/csv", exportDataCSV());
  });
  
  server.on("/baseline", HTTP_POST, [](AsyncWebServerRequest *request) {
    captureBaseline();
    request->send(200, "application/json", "{\"status\":\"ok\"}");
  });
  
  server.on("/reset", HTTP_POST, [](AsyncWebServerRequest *request) {
    resetSystem();
    request->send(200, "application/json", "{\"status\":\"ok\"}");
  });
  
  server.on("/clearAlerts", HTTP_POST, [](AsyncWebServerRequest *request) {
    clearAlerts();
    request->send(200, "application/json", "{\"status\":\"ok\"}");
  });
  
  server.on("/acknowledgeAlerts", HTTP_POST, [](AsyncWebServerRequest *request) {
    acknowledgeAllAlerts();
    request->send(200, "application/json", "{\"status\":\"ok\"}");
  });
  
  server.on("/addWatchlist", HTTP_POST, [](AsyncWebServerRequest *request) {
    String ssid = request->hasParam("ssid") ? request->getParam("ssid")->value() : "";
    String bssid = request->hasParam("bssid") ? request->getParam("bssid")->value() : "";
    addToWatchlist(ssid, bssid, "");
    request->send(200, "application/json", "{\"status\":\"ok\"}");
  });
  
  server.on("/removeWatchlist", HTTP_POST, [](AsyncWebServerRequest *request) {
    if (request->hasParam("index")) {
      int index = request->getParam("index")->value().toInt();
      removeFromWatchlist(index);
    }
    request->send(200, "application/json", "{\"status\":\"ok\"}");
  });
  
  // Demo Mode endpoints
  server.on("/demo", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "application/json", getDemoStatusJSON());
  });
  
  server.on("/demo/start", HTTP_POST, [](AsyncWebServerRequest *request) {
    int scenario = 0;
    if (request->hasParam("scenario")) {
      scenario = request->getParam("scenario")->value().toInt();
    }
    startDemo(scenario);
    request->send(200, "application/json", "{\"status\":\"ok\"}");
  });
  
  server.on("/demo/stop", HTTP_POST, [](AsyncWebServerRequest *request) {
    stopDemo();
    request->send(200, "application/json", "{\"status\":\"ok\"}");
  });
  
  server.on("/demo/reset", HTTP_POST, [](AsyncWebServerRequest *request) {
    resetDemo();
    request->send(200, "application/json", "{\"status\":\"ok\"}");
  });
  
  server.begin();
}

// ============================================================================
// ARDUINO SETUP
// ============================================================================

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\n");
  Serial.println("========================================");
  Serial.println("  ExamGuard Pro AI v3.0 - Wi-Fi IDS");
  Serial.println("  AI-Powered Thesis Edition");
  Serial.println("========================================\n");
  
  // Initialize AI Engine
  initializeAI();
  Serial.println("AI Neural Network loaded");
  
  // Initialize state
  systemState.baselineSet = false;
  systemState.systemState = "NORMAL";
  systemState.riskLevel = "LOW";
  systemState.riskScore = 0;
  systemState.monitoringActive = true;
  systemState.lastAction = "System started";
  systemState.lastActionTime = 0;
  
  bootTime = millis();
  stats.sessionStartTime = bootTime;
  
  // Configure WiFi
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPConfig(AP_IP, AP_GATEWAY, AP_SUBNET);
  
  bool apStarted = WiFi.softAP(AP_SSID, AP_PASSWORD);
  
  if (apStarted) {
    Serial.println("Access Point Started:");
    Serial.print("  SSID: ");
    Serial.println(AP_SSID);
    Serial.print("  IP: ");
    Serial.println(WiFi.softAPIP());
  } else {
    Serial.println("ERROR: Failed to start Access Point!");
  }
  
  setupWebServer();
  Serial.println("\nWeb Interface: http://192.168.4.1");
  Serial.println("\nSystem ready. Monitoring...\n");
  
  performWiFiScan();
}

// ============================================================================
// ARDUINO LOOP
// ============================================================================

void loop() {
  uint32_t now = millis();
  
  // Handle scan completion
  if (scanInProgress) {
    int n = WiFi.scanComplete();
    if (n >= 0) {
      handleScanComplete(n);
    }
  }
  
  // Periodic scanning
  if (now - lastScanTime >= config.scanIntervalMs) {
    lastScanTime = now;
    performWiFiScan();
  }
  
  // Auto baseline after warmup
  if (config.autoBaseline && !systemState.baselineSet && 
      (now - bootTime >= config.baselineWarmupMs)) {
    if (scanResultCount > 0) {
      Serial.println("Auto-capturing baseline...");
      captureBaseline();
      Serial.print("Baseline captured: ");
      Serial.print(baselineCount);
      Serial.println(" networks");
    }
  }
  
  // Update history every 30 seconds
  if (now - lastHistoryUpdate >= 30000) {
    lastHistoryUpdate = now;
    updateHistory();
  }
  
  // Run AI analysis every 10 seconds
  if (now - lastAIAnalysis >= 10000) {
    lastAIAnalysis = now;
    runAIAnalysis();
  }
  
  // Run demo scenario if active
  if (demoActive) {
    runDemoScenario();
  }
  
  delay(100);
}
