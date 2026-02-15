#!/bin/sh
# Airspy R2 / HydraSDR -- 12-bit ADC, 10 MHz max, via SoapySDR
#
# Gain range: 0-45 dB (3 stages: LNA 0-15, MIX 0-15, VGA 0-15)
# Recommended: 25-35 dB. Higher gains overload the ADC and raise the
# noise floor, reducing sensitivity. Tested sweet spot: 30 dB.
#
# Too low (18 dB):  weak signals missed, low burst rate
# Optimal (30 dB):  best burst rate and UW pass rate (78%)
# Too high (45 dB): ADC overload, 4x fewer bursts detected
#
# With external bias tee:
#   iridium-sniffer -l -i soapy-0 --soapy-gain=30
#
# With built-in bias tee (if supported):
#   iridium-sniffer -l -i soapy-0 -B --soapy-gain=30

exec iridium-sniffer -l -i soapy-0 --soapy-gain=30 --web "$@"
