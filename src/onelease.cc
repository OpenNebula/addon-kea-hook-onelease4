/*
 *
 * Copyright (2019) Petr Ospalý <petr@ospalax.cz>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */


#include "h/onelease.h"


/* Header section */

#include <hooks/hooks.h>
#include <dhcp/pkt4.h>
#include <dhcpsrv/subnet.h>
#include <dhcpsrv/lease.h>
#include <asiolink/io_address.h>

#include <string>

#include "h/kea_interface.h"
#include "h/functions.h"

using namespace isc::dhcp;
using namespace isc::hooks;


/* Code section */

extern "C" {

    // This callout is called at the "pkt4_receive" hook.
    // Args:
    //  name: query4, type: isc::dhcp::Pkt4Ptr, direction: in/out
    int pkt4_receive(CalloutHandle& handle) {
        // if hook is disabled and debug_logfile is not opened then we can skip
        // this and any other callout...
        if (!(kea_onelease4_enabled || debug_logfile))
            return KEA_SUCCESS;

        // A pointer to the packet is passed to the callout via a "boost" smart
        // pointer. The include file "pkt4.h" typedefs a pointer to the Pkt4
        // object as Pkt4Ptr.  Retrieve a pointer to the object.
        Pkt4Ptr query4_ptr;
        handle.getArgument("query4", query4_ptr);

        // Point to the hardware address.
        HWAddrPtr hwaddr_ptr = query4_ptr->getHWAddr();

        // Context

        // Store the text form of the hardware address in the context to pass
        // to the next callout.
        std::string hwaddr_str = hwaddr_ptr->toText();
        handle.setContext("hwaddr_str", hwaddr_str);

        // Store the last four bytes of the HW address as an ip address which
        // is created by simple conversion from said HW address - or leave it
        // empty if it does not match byte prefix...
        std::string oneaddr_str = "";
        if (match_byte_prefix(kea_onelease4_byte_prefix, hwaddr_ptr->hwaddr_))
        {
            for (unsigned int i = 2; i < hwaddr_ptr->hwaddr_.size(); ++i) {
                oneaddr_str += std::to_string(hwaddr_ptr->hwaddr_[i]);
                oneaddr_str += (i + 1) < hwaddr_ptr->hwaddr_.size() ? "." : "";
            }
        }
        handle.setContext("oneaddr_str", oneaddr_str);

        return (KEA_SUCCESS);
    };

    // This callout is called at the "lease4_select" hook.
    // Args:
    //  name: query4, type: isc::dhcp::Pkt4Ptr, direction: in
    //  name: subnet4, type: isc::dhcp::Subnet4Ptr, direction: in
    //  name: fake_allocation, type: bool, direction: in
    //  name: lease4, type: isc::dhcp::Lease4Ptr, direction: in/out
    int lease4_select(CalloutHandle& handle) {
        // If not enabled then do nothing...
        if (!(kea_onelease4_enabled))
            return KEA_SUCCESS;

        // Pkt4Ptr query4_ptr;      // IN
        Subnet4Ptr subnet4_ptr;     // IN
        Lease4Ptr lease4_ptr;       // IN/OUT
        // bool fake_allocation;    // IN (I don't have use for it for now)

        return kea_onelease4(handle, subnet4_ptr, lease4_ptr, "lease4_select");
    }

    // This callout is called at the "lease4_renew" hook.
    // Args:
    //  name: query4, type: isc::dhcp::Pkt4Ptr, direction: in
    //  name: subnet4, type: isc::dhcp::Subnet4Ptr, direction: in
    //  name: clientid, type: isc::dhcp::ClientId, direction: in
    //  name: hwaddr, type: isc::dhcp::HWAddr, direction: in
    //  name: lease4, type: isc::dhcp::Lease4Ptr, direction: in/out
    int lease4_renew(CalloutHandle& handle) {
        // If not enabled then do nothing...
        if (!(kea_onelease4_enabled))
            return KEA_SUCCESS;

        // This callout is practically the same as for the lease4_select...

        Subnet4Ptr subnet4_ptr;     // IN
        Lease4Ptr lease4_ptr;       // IN/OUT

        return kea_onelease4(handle, subnet4_ptr, lease4_ptr, "lease4_renew");
    }

    // This callout is called at the "pkt4_send" hook.
    // Args:
    //  name: response4, type: isc::dhcp::Pkt4Ptr, direction: in/out
    //  name: query4, type: isc::dhcp::Pkt4Ptr, direction: in
    int pkt4_send(CalloutHandle& handle) {
        // if hook is disabled and debug_logfile is not opened then we can skip
        // this and any other callout...
        if (!(kea_onelease4_enabled || debug_logfile))
            return KEA_SUCCESS;

        std::string hwaddr_str;
        std::string oneaddr_str;

        // I am being defensive here and I will use try..catch even though the
        // context should have been set...
        try {
            handle.getContext("hwaddr_str", hwaddr_str);
            handle.getContext("oneaddr_str", oneaddr_str);

            Pkt4Ptr response4_ptr;
            handle.getArgument("response4", response4_ptr);

            // Get the string form of the IP address.
            std::string ipaddr_str = response4_ptr->getYiaddr().toText();

            if (debug_logfile)
            {
                // Write the information to the log file.
                debug_logfile \
                    << "DEBUG> pkt4_send [OK]:" \
                    << " HW address: '" << hwaddr_str << "'" \
                    << ", ONE HW/IP: '" << oneaddr_str << "'" \
                    << ", Leased IP: '" << ipaddr_str << "'" \
                    << "\n";

                // to guard against a crash, we'll flush the output stream
                flush(debug_logfile);
            }
        } catch (const NoSuchCalloutContext&) {
            // No such element in the per-request context (hwaddr_str, oneaddr_str)
        }

        return (KEA_SUCCESS);
    }

}


// These are helper functions and they do not need to be inside extern C
// linkage...

int kea_onelease4(CalloutHandle& handle,
                  Subnet4Ptr subnet4_ptr,
                  Lease4Ptr lease4_ptr,
                  const std::string callout_name)
{
    // read the current state
    handle.getArgument("subnet4", subnet4_ptr);
    handle.getArgument("lease4", lease4_ptr);

    // I am being defensive here and I will use try..catch even though the
    // context should have been set...
    std::string hwaddr_str;
    std::string oneaddr_str;
    try {
        handle.getContext("hwaddr_str", hwaddr_str);
        handle.getContext("oneaddr_str", oneaddr_str);

        // Check ONE address if it is acceptable
        if (oneaddr_str.empty())
            throw EmptyIPv4Str();

        // Try to convert string into IPv4 representation
        isc::asiolink::IOAddress
            oneaddr = isc::asiolink::IOAddress(oneaddr_str);

        // Do not apply hook if ONE subnet restriction is invalid
        if (!is_onelease4_in_range(oneaddr, kea_onelease4_subnets))
            throw NonMatchingSubnet();

        // The inRange() test is actually redundant because it is also done
        // in the method inPool() but I know that only because I looked
        // into the implementation - and that can change so I am defensive
        // here...
        if (subnet4_ptr->inRange(oneaddr) &&
            subnet4_ptr->inPool(Lease::TYPE_V4, oneaddr))
        {
            // OK - ONE address can be assigned

            // Actually there is (currently) no way how to simply find out
            // if some address was already leased - Kea's allocator just go
            // from the lowest pool address up and keep note which one it
            // allocated the last time - but that is insufficiant - we would
            // have to go to lease file (memfile, postgres, cassandra etc.)
            // to search if new address is free or keep it in our own
            // structure during the lifetime of the hook (load->unload).
            //
            // But we can cheat here in our case because:
            // 1. our ONE address is in the right subnet and the right pool
            // 2. our ONE address is based on the HW/MAC address
            // 3. HW/MAC address should be unique
            //
            // We can (with good enough amount of confidence) say that this
            // address (which we calculated from MAC) is owned by only one
            // device, the one which is currently trying to get a lease...

            // save original ip address
            std::string origipaddr_str = lease4_ptr->addr_.toText();

            // modified lease
            lease4_ptr->addr_ = oneaddr;
            std::string lease_str = lease4_ptr->toText();

            if (debug_logfile)
            {
                // Write the information to the log file.
                debug_logfile \
                    << "DEBUG> " << callout_name << " [OK]:" \
                    << " HW address: '" << hwaddr_str << "'" \
                    << ", ONE HW/IP: '" << oneaddr_str << "'" \
                    << ", Original IP lease: '" << origipaddr_str << "'" \
                    << ", Actual lease:\n" << lease_str \
                    << "\n";

                // to guard against a crash, we'll flush the output stream
                flush(debug_logfile);
            }
        } else {
            // We reject this packet because the ONE address cannot fit the
            // range or any of the pools...
            handle.setStatus(CalloutHandle::NEXT_STEP_SKIP);
            lease4_ptr->decline(0);

            if (debug_logfile)
            {
                // Write the information to the log file.
                debug_logfile \
                    << "DEBUG> " << callout_name << " [REJECTED]:" \
                    << " ONE address mismatches with range/pool:" \
                    << " HW address: '" << hwaddr_str << "'" \
                    << ", ONE HW/IP: '" << oneaddr_str << "'" \
                    << "\n";

                // to guard against a crash, we'll flush the output stream
                flush(debug_logfile);
            }
        }
    } catch (const NoSuchCalloutContext&) {
        // No such element in the per-request context (hwaddr_str, oneaddr_str)
    } catch (const EmptyIPv4Str&) {
        if (debug_logfile)
        {
            // Write the information to the log file.
            debug_logfile \
                << "DEBUG> " << callout_name << " [SKIPPED]:" \
                << " ONE address is empty (non-matching byte prefix):" \
                << " HW address: '" << hwaddr_str << "'" \
                << "\n";

            // to guard against a crash, we'll flush the output stream
            flush(debug_logfile);
        }
    } catch (const NonMatchingSubnet&) {
        if (debug_logfile)
        {
            // Write the information to the log file.
            debug_logfile \
                << "DEBUG> " << callout_name << " [SKIPPED]:" \
                << " ONE address is not in the hook's subnet range:" \
                << " HW address: '" << hwaddr_str << "'" \
                << ", ONE HW/IP: '" << oneaddr_str << "'" \
                << ", ONE subnets: '" << \
                print_onelease4_subnets(kea_onelease4_subnets) << "'" \
                << "\n";

            // to guard against a crash, we'll flush the output stream
            flush(debug_logfile);
        }
    }

    return (KEA_SUCCESS);
}

bool match_byte_prefix(const std::vector<uint8_t> &byte_prefix,
                       const std::vector<uint8_t> &hw_addr)
{
    // no byte prefix was configured - we are accepting all...
    if (byte_prefix.size() == 0)
        return true;

    // byte prefix should be only two bytes long, but maybe in the future we
    // will want to match more bytes...
    for (unsigned int i = 0; i < byte_prefix.size(); ++i) {
        if (byte_prefix[i] != hw_addr[i])
            return false;
    }

    return true;
}

bool is_onelease4_in_range(const isc::asiolink::IOAddress &ip_addr,
                           const std::vector<isc::dhcp::Subnet4Ptr> &subnets)
{
    // is onelease subnet list parameter used?
    if (subnets.empty())
        return true;

    // compare the address with every subnet in the list...
    for (size_t i = 0; i < subnets.size(); i++)
        if (subnets[i]->inRange(ip_addr))
            return true;

    return false;
}

std::string print_onelease4_subnets(
        const std::vector<isc::dhcp::Subnet4Ptr> &subnets)
{
    // are there any subnets?
    if (subnets.empty())
        return "";

    // concatenate all subnets
    std::string subnets_str = "";
    for (size_t i = 0; i < subnets.size(); i++) {
        if (! subnets_str.empty())
            subnets_str += ", ";

        subnets_str += subnets[i]->toText();
    }

    return subnets_str;
}


// last line

