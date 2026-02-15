#!/bin/sh
# RTL-SDR (via SoapySDR) -- 8-bit ADC, 2.4 MHz max
#
# Gain range: 0-50 dB (varies by tuner chip)
# Recommended: 40 dB
#
# Limited to 2.4 MHz bandwidth, covering only a fraction of the
# 10.5 MHz Iridium band. Expect significantly fewer bursts than
# wideband receivers. Still useful for basic monitoring.
#
# The R820T/R820T2 tuner covers up to ~1766 MHz, which reaches
# the Iridium band. The R828D and FC0012/FC0013 tuners do not.
#
# Use a lower sample rate since the default 10 MHz exceeds RTL-SDR limits:
#   ./iridium-sniffer -l -i soapy-0 -r 2400000 --soapy-gain=40

exec ./iridium-sniffer -l -i soapy-0 -r 2400000 --soapy-gain=40 --web "$@"
