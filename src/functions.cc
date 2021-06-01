/*
 *
 * Copyright (2019) Petr Ospalý <petr@ospalax.cz>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */


#include "h/functions.h"


/* Header section */

#include <dhcpsrv/subnet.h>
#include <dhcpsrv/lease.h>
#include <asiolink/io_address.h>

#include <string>

using namespace isc::dhcp;


/* Code section */

isc::dhcp::Subnet4Ptr create_subnet4(const std::string subnet_str)
{
    size_t pos = subnet_str.find("/");
    isc::asiolink::IOAddress addr(subnet_str.substr(0, pos));
    size_t len = boost::lexical_cast<unsigned int>(subnet_str.substr(pos + 1));

    return (isc::dhcp::Subnet4Ptr(new isc::dhcp::Subnet4(addr, len, 1000, 2000, 3000, 1)));
}


// last line

