/*
  USB Sentinel - Master YARA Rules Index
  Combines USB Worms, Ransomware, InfoStealers, and LOLBins evasion rules.
*/

include "./usb_worms.yar"
include "./ransomware.yar"
include "./infostealers.yar"
include "./lolbins_evasion.yar"

