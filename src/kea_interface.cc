/*
 *
 * Copyright (2019) Petr Ospalý <petr@ospalax.cz>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */


#include "h/kea_interface.h"


/* Header section */

#include <hooks/hooks.h>
#include <cc/data.h>
#include <util/strutil.h>
#include <dhcpsrv/subnet.h>

#include "h/functions.h"

using namespace isc::dhcp;
using namespace isc::hooks;
using namespace isc::data;
using namespace isc::util;

// Kea has reversed boolean values...
int KEA_SUCCESS = 0;
int KEA_FAILURE = 1;

// Hook can be loaded but it may be disabled...
bool kea_onelease4_enabled = true;

// Optional ONElease subnet list
std::vector<isc::dhcp::Subnet4Ptr> kea_onelease4_subnets;

// By default all prefixes are accepted or only specific first two bytes...
std::vector<uint8_t> kea_onelease4_byte_prefix;

// Debug log (if enabled)
std::fstream debug_logfile;


/* Code section */

extern "C" {

    // the only mandatory function - don't change!
    int version() {
        return (KEA_HOOKS_VERSION);
    }

    // when library is loaded (on kea start for example)
    // from the doc:
    // "load" must 0 on success and non-zero on error. The hooks framework will
    // abandon the loading of the library if "load" returns an error status.
    int load(LibraryHandle& handle) {
        // these are parameters in the config (all have defaults...)
        // for example:
        // "parameters": {
        //     "enabled": true,
        //     "byte-prefix": "",
        //     "subnets": [],
        //     "logger-name": "kea-onelease-dhcp4",
        //     "debug": true,
        //     "debug-logfile": "/var/log/kea-onelease-dhcp4-debug.log"
        // }
        ConstElementPtr param_enabled = handle.getParameter("enabled");
        ConstElementPtr param_byte_prefix = handle.getParameter("byte-prefix");
        ConstElementPtr param_subnets = handle.getParameter("subnets");
        ConstElementPtr param_logger_name = handle.getParameter("logger-name");
        ConstElementPtr param_debug = handle.getParameter("debug");
        ConstElementPtr param_debug_logfile = handle.getParameter("debug-logfile");

        // set defaults
        bool debug = false;
        std::string debug_filename = "/var/log/kea-onelease-dhcp4-debug.log";
        std::string logger_name = "kea-onelease-dhcp4";

        // check parameters

        if (param_enabled)
        {
            if (param_enabled->getType() != Element::boolean) {
                isc_throw(isc::BadValue,
                          "Parameter 'enabled' must be a boolean!");
            }
            kea_onelease4_enabled = param_enabled->boolValue();
        }

        if (param_byte_prefix)
        {
            if (param_byte_prefix->getType() != Element::string) {
                isc_throw(isc::BadValue,
                          "Parameter 'byte-prefix' must be a string!");
            }
            isc::util::str::decodeFormattedHexString(
                    param_byte_prefix->stringValue(),
                    kea_onelease4_byte_prefix);

            // validate prefix
            if (!((kea_onelease4_byte_prefix.size() == 0)
                || (kea_onelease4_byte_prefix.size() == 2)))
            {
                isc_throw(isc::BadValue,
                          "Wrong byte prefix - should be zero or two bytes!");
            }
        }

        if (param_subnets)
        {
            if (param_subnets->getType() != Element::list) {
                isc_throw(isc::BadValue,
                          "Parameter 'subnets' must be a list!");
            }

            // validate subnet prefix
            for (size_t i = 0; i < param_subnets->size(); i++) {
                std::string subnet_str = param_subnets->get(i)->stringValue();

                std::pair<isc::asiolink::IOAddress, uint8_t> parsed =
                    parse_subnet_prefix(subnet_str);
                if (!parsed.first.isV4() || parsed.first.isV4Zero() ||
                    (parsed.second > 32) || (parsed.second == 0)) {
                    isc_throw(isc::BadValue,
                            "unable to parse invalid IPv4 prefix "
                            << subnet_str);
                } else {
                    // append a new subnet structure to the global onelease
                    // subnet list
                    kea_onelease4_subnets.push_back(
                            create_subnet4(subnet_str));
                }
            }
        }

        if (param_debug)
        {
            if (param_debug->getType() != Element::boolean) {
                isc_throw(isc::BadValue,
                          "Parameter 'debug' must be a boolean!");
            }
            debug = param_debug->boolValue();
        }

        if (param_debug_logfile)
        {
            if (param_debug_logfile->getType() != Element::string) {
                isc_throw(isc::BadValue,
                          "Parameter 'debug-logfile' must be a string!");
            }
            debug_filename = param_debug_logfile->stringValue();
        }

        if (param_logger_name)
        {
            if (param_logger_name->getType() != Element::string) {
                isc_throw(isc::BadValue,
                          "Parameter 'logger-name' must be a string!");
            }
            logger_name = param_logger_name->stringValue();
        }

        // Are we debugging?
        if (debug)
        {
            debug_logfile.open(debug_filename,
                           std::fstream::out | std::fstream::app);

            // let's dump a testing message to the debug log
            debug_logfile \
                << "DEBUG> [KEA-DHCP4 STARTED]: " << logger_name \
                << "\n" \
                << "DEBUG> onelease hook: " << \
                    std::string(kea_onelease4_enabled \
                            ? "ENABLED" : "DISABLED") \
                << "\n";

            // to guard against a crash, we'll flush the output stream
            flush(debug_logfile);

            return (debug_logfile ? KEA_SUCCESS : KEA_FAILURE);
        }

        return KEA_SUCCESS;
    }

    // when library is unloaded (on kea shutdown for example)
    // from the doc:
    // As with "load", a zero value must be returned on success and a non-zero
    // value on an error. The hooks framework will record a non-zero status
    // return as an error in the current Kea log but otherwise ignore it.
    int unload() {
        if (debug_logfile) {
            // closing debug log with last message
            debug_logfile \
                << "DEBUG> [KEA-DHCP4 ENDED]" \
                << "\n\n";

            debug_logfile.close();
        }

        return (KEA_SUCCESS);
    }

}


// These are helper functions and they do not need to be inside extern C
// linkage...

std::pair<isc::asiolink::IOAddress, uint8_t>
parse_subnet_prefix(const std::string& prefix)
{
    auto pos = prefix.find('/');
    if ((pos == std::string::npos) ||
        (pos == prefix.size() - 1) ||
        (pos == 0)) {
        isc_throw(isc::BadValue, "unable to parse invalid prefix " << prefix);
    }

    try {
        isc::asiolink::IOAddress address(prefix.substr(0, pos));
        int length = boost::lexical_cast<int>(prefix.substr(pos + 1));
        return (std::make_pair(address, static_cast<int>(length)));

    } catch (...) {
        isc_throw(isc::BadValue, "unable to parse invalid prefix " << prefix);
    }
}


// last line

