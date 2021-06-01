/*
 *
 * Copyright (2019) Petr Ospalý <petr@ospalax.cz>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#ifndef SAFEGUARD__ONELEASE_H_HEADER__
#define SAFEGUARD__ONELEASE_H_HEADER__
// do not put any code BEFORE these two lines


#include <hooks/hooks.h>
#include <dhcpsrv/subnet.h>
#include <dhcpsrv/lease.h>

#include <vector>
#include <exception>

// My exceptions
class EmptyIPv4Str : public std::exception
{
   virtual const char * what () const throw ()
   {
      return "Empty IPv4 address string!";
   }
};

class NonMatchingSubnet : public std::exception
{
   virtual const char * what () const throw ()
   {
      return "ONElease address does not match with subnet parameter!";
   }
};

// Here we do all the 'onelease' assignment work
int kea_onelease4(isc::hooks::CalloutHandle& handle,
                  isc::dhcp::Subnet4Ptr subnet4_ptr,
                  isc::dhcp::Lease4Ptr lease4_ptr,
                  const std::string callout_name);

// Checks and compares the byte prefix with the HW address
bool match_byte_prefix(const std::vector<uint8_t> &byte_prefix,
                       const std::vector<uint8_t> &hw_addr);

// Check if our ONE lease address is within the ONE subnet
// (if ONE subnet is not used then it always returns true)
bool is_onelease4_in_range(const isc::asiolink::IOAddress &ip_addr,
                           const std::vector<isc::dhcp::Subnet4Ptr> &subnets);

// Print out the ONE lease subnets as a one string
std::string print_onelease4_subnets(
        const std::vector<isc::dhcp::Subnet4Ptr> &subnets);


// do not put any code AFTER this line
#endif // SAFEGUARD__ONELEASE_H_HEADER__

