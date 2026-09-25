/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "phy_meshtastic.h"
#include "manuf.h"

kis_meshtastic_phy::kis_meshtastic_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("Meshtastic");

    datasourcetracker =
        Globalreg::fetch_mandatory_global_as<datasource_tracker>();

    model_tlora_v2 = Globalreg::globalreg->manufdb->make_manuf("T-Lora v2");
    model_tlora_v1 = Globalreg::globalreg->manufdb->make_manuf("T-Lora v1");
    model_tlora_v2_1_1p6 = Globalreg::globalreg->manufdb->make_manuf("T-Lora v2.1-1.6");
    model_tbeam = Globalreg::globalreg->manufdb->make_manuf("T-Beam");
    model_heltec_v2_0 = Globalreg::globalreg->manufdb->make_manuf("Heltec v2.0");
    model_tbeam_v0p7 = Globalreg::globalreg->manufdb->make_manuf("T-Beam v0.7");
    model_t_echo = Globalreg::globalreg->manufdb->make_manuf("T-Echo");
    model_tlora_v1_1p3 = Globalreg::globalreg->manufdb->make_manuf("T-Lora v1-1.3");
    model_rak4631 = Globalreg::globalreg->manufdb->make_manuf("RAK4631");
    model_heltec_v2_1 = Globalreg::globalreg->manufdb->make_manuf("Heltec v2.1");
    model_heltec_v1 = Globalreg::globalreg->manufdb->make_manuf("Heltec v1");
    model_lilygo_tbeam_s3_core = Globalreg::globalreg->manufdb->make_manuf("LilyGo T-Beam S3 Core");
    model_rak11200 = Globalreg::globalreg->manufdb->make_manuf("RAK11200");
    model_nano_g1 = Globalreg::globalreg->manufdb->make_manuf("Nano G1");
    model_tlora_v2_1_1p8 = Globalreg::globalreg->manufdb->make_manuf("T-Lora v2 1-1.8");
    model_tlora_t3_s3 = Globalreg::globalreg->manufdb->make_manuf("T-Lora t3-s3");
    model_nano_g1_explorer = Globalreg::globalreg->manufdb->make_manuf("Nano G1 Explorer");
    model_nano_g2_ultra = Globalreg::globalreg->manufdb->make_manuf("Nano G2 Ultra");
    model_lora_type = Globalreg::globalreg->manufdb->make_manuf("Lora Type");
    model_station_g1 = Globalreg::globalreg->manufdb->make_manuf("Station G1");
    model_rak11310 = Globalreg::globalreg->manufdb->make_manuf("RAK11310");
    model_senselora_s3 = Globalreg::globalreg->manufdb->make_manuf("SenseLora S3");
    model_canaryone = Globalreg::globalreg->manufdb->make_manuf("CanaryOne");
    model_rp2040_lora = Globalreg::globalreg->manufdb->make_manuf("RP2040 Lora");
    model_station_g2 = Globalreg::globalreg->manufdb->make_manuf("Station G2");
    model_lora_relay_v1 = Globalreg::globalreg->manufdb->make_manuf("Lora Relay v1");
    model_nrf52840dk = Globalreg::globalreg->manufdb->make_manuf("NRF52840dk");
    model_ppr = Globalreg::globalreg->manufdb->make_manuf("PPR");
    model_genieblocks = Globalreg::globalreg->manufdb->make_manuf("GenieBlocks");
    model_nrf52_unknown = Globalreg::globalreg->manufdb->make_manuf("NRF52 Unknown");
    model_portuino = Globalreg::globalreg->manufdb->make_manuf("Portuino");
    model_android_sim = Globalreg::globalreg->manufdb->make_manuf("Android Sim");
    model_diy_v1 = Globalreg::globalreg->manufdb->make_manuf("DIY v1");
    model_nrf52840_pca10059 = Globalreg::globalreg->manufdb->make_manuf("NRF52840 PCA10059");
    model_dr_dev = Globalreg::globalreg->manufdb->make_manuf("Dr Dev");
    model_m5stack = Globalreg::globalreg->manufdb->make_manuf("m5stack");
    model_heltec_v3 = Globalreg::globalreg->manufdb->make_manuf("Heltec v3");
    model_heltec_wsl_v3 = Globalreg::globalreg->manufdb->make_manuf("Heltec WSL v3");
    model_betafpv_2400_tx = Globalreg::globalreg->manufdb->make_manuf("BetaFPV 2400 tx");
    model_betafpv_900_nano_tx = Globalreg::globalreg->manufdb->make_manuf("BetaFPV 900 Nano tx");
    model_rpi_pico = Globalreg::globalreg->manufdb->make_manuf("RPi Pico");
    model_heltec_wireless_tracker = Globalreg::globalreg->manufdb->make_manuf("Heltec Wireless Tracker");
    model_heltec_wireless_paper = Globalreg::globalreg->manufdb->make_manuf("Heltec Wireless Paper");
    model_t_deck = Globalreg::globalreg->manufdb->make_manuf("T-Deck");
    model_t_watch_s3 = Globalreg::globalreg->manufdb->make_manuf("T-Watch s3");
    model_picomputer_s3 = Globalreg::globalreg->manufdb->make_manuf("Picomputer s3");
    model_heltec_ht62 = Globalreg::globalreg->manufdb->make_manuf("Heltec ht62");
    model_ebyte_esp32_s3 = Globalreg::globalreg->manufdb->make_manuf("Ebyte ESP32 s3");
    model_esp32_s3_pico = Globalreg::globalreg->manufdb->make_manuf("ESP32 s3 pico");
    model_chatter2 = Globalreg::globalreg->manufdb->make_manuf("Chatter2");
    model_heltec_wireless_paper_v1_0 = Globalreg::globalreg->manufdb->make_manuf("Heltec Wireless Paper v1.0");
    model_heltec_wireless_tracker_v1_0 = Globalreg::globalreg->manufdb->make_manuf("Heltec Wireless Tracker v1.0");

}
