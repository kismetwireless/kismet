// Radview CPS and Spectrum reporting handling for basic Arduino or Arduino-compatible
// microcontroller.
//
// The radview operates on 5v signalling, with 5v *analog* signalling for spectrum 
// reporting; select a microcontroller accordingly.
// 
// Spectrum reports are sent as the past second of spectral data; a consumer should 
// add these to a rolling graph of the desired depth.
//
// The radview reports a count event as a pulse on the digital pin, and the energy
// level of the pulse as an analog value at the same time. 
//
// We use a serial baud rate of 1000000
//
// (C) 2024 Michael Kershaw / Dragorn <dragorn@kismetwireless.net>
// Licensed under GPL 2.0 or newer

// Analog pin must be connected to the Radview spectrum pin
// Digital pin must be connected to the Radview pulse pin
const int analog_pin = A0;
const int digital_pin = 2;

// How often do we report the CPS/Spectrum arrays; changing this has implications for
// the cps rolling average, so probably don't.
const unsigned long report_ms = 1000;

// Report a rolling average of the counts-per-second to smooth weird spikes
const int cps_average_num = 5;

volatile unsigned int cps_readings[cps_average_num];
volatile unsigned int cps_index = 0; 

// Spectrum over the past second
volatile unsigned int gamma_spectrum[512];

volatile unsigned long last_output_ms = 0;

void intr_pulse();
void print_report();

#define FASTADC 1
#define sbi(sfr, bit) (_SFR_BYTE(sfr) |= _BV(bit))
#define cbi(sfr, bit) (_SFR_BYTE(sfr) &= ~_BV(bit))

void setup() {
  // Fast ADC mode on Arduino atmega hw
#if FASTADC
  sbi(ADCSRA, ADPS2);
  sbi(ADCSRA, ADPS1);
  cbi(ADCSRA, ADPS0);
#endif

  memset(cps_readings, 0, sizeof(unsigned int) * cps_average_num);
  memset(gamma_spectrum, 0, sizeof(unsigned int) * 512);

  pinMode(analog_pin, INPUT);

  Serial.begin(1000000);

  last_output_ms = millis();

  attachInterrupt(digitalPinToInterrupt(digital_pin), intr_pulse, RISING);
}

void loop() {
  unsigned long current_ms = millis();

  if (current_ms - last_output_ms >= report_ms) {
    last_output_ms = current_ms;
    print_report();
  }
}

void intr_pulse() {
  int analog_value;

  // Update current CPS slot
  cps_readings[cps_index]++;

  // Sample the analog signal and make sure the pulse was high for the duration of the
  // sample; this means our micro must be able to sample quickly enough.  The exact pulse 
  // duration of the radview is not known.
  if (digitalRead(digital_pin) == HIGH) {
    analog_value = analogRead(analog_pin);

    // Confirm pulse is still on
    if (digitalRead(digital_pin) == HIGH) {
      gamma_spectrum[analog_value / 2]++;
    }
  }
}

char print_buffer[64];

void print_report() {
  noInterrupts();

  float cps_avg = 0;
  unsigned int cps_total = 0;
  unsigned int i_val;

  // Unroll the loop
  cps_total += cps_readings[0];
  cps_total += cps_readings[1];
  cps_total += cps_readings[2];
  cps_total += cps_readings[3];
  cps_total += cps_readings[4];
  
  cps_avg = (float) cps_total / (float) cps_average_num;
  i_val = cps_avg * 10;

  cps_index = (cps_index + 1) % cps_average_num;
  cps_readings[cps_index] = 0;

  snprintf(print_buffer, 64, "{\"cps\": %u.%u, \"spectrum\": [", (unsigned int) cps_avg, i_val);
  Serial.print(print_buffer);
  
  Serial.print(gamma_spectrum[0]);
  gamma_spectrum[0] = 0;
  for (unsigned int i = 1; i < 500; i++) {
    Serial.print(",");
    Serial.print(gamma_spectrum[i]);
    gamma_spectrum[i] = 0;
  }
  Serial.println("]}");

  interrupts();
}
