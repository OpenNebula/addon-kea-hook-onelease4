/*
 *
 * Copyright (2019) Petr Ospalý <petr@ospalax.cz>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#ifndef SAFEGUARD__FUNCTIONS_H_HEADER__
#define SAFEGUARD__FUNCTIONS_H_HEADER__
// do not put any code BEFORE these two lines


#include <dhcpsrv/subnet.h>

#include <vector>

// Returns Kea structure representing the subnet (smartpointer)
isc::dhcp::Subnet4Ptr create_subnet4(const std::string subnet_str);


// do not put any code AFTER this line
#endif // SAFEGUARD__FUNCTIONS_H_HEADER__

