/**
 * \file netbiosplugin.h
 * \brief Plugin for parsing netbios traffic.
 * \author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#ifndef NETBIOSPLUGIN_H
#define NETBIOSPLUGIN_H

#include <string>

#include "fields.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"

using namespace std;

/**
 * \brief Flow record extension header for storing parsed NETBIOS packets.
 */
struct RecordExtNETBIOS : RecordExt {

   RecordExtNETBIOS() : RecordExt(netbios)
   {
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
       // TODO
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
        // TODO
        return 0;
   }
};

/**
 * \brief Flow cache plugin for parsing NETBIOS packets.
 */
class NETBIOSPlugin : public FlowCachePlugin
{
public:
   NETBIOSPlugin(const options_t &module_options);
   NETBIOSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();
   bool include_basic_flow_fields();

private:
   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
};

#endif

