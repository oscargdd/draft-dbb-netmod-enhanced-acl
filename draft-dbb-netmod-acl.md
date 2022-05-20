---
title: Extensions to the Access Control Lists (ACLs) YANG Model
abbrev: Enhanced ACLs 
docname: draft-dbb-netmod-acl-latest


stand_alone: true

ipr: trust200902
area: ops
wg: netmod
kw: Internet-Draft
cat: standard

coding: utf-8
pi: [toc, sortrefs, symrefs]

author:
 -
    fullname: Oscar Gonzalez de Diose
    organization: Telefonica
    email: oscar.gonzalezdedios@telefonica.com
author:
 -
    fullname: Samier Barguil
    organization: Telefonica
    email: samier.barguilgiraldo.ext@telefonica.com

author:
 -
    fullname: Mohamed Boucadair
    organization: Orange
    email: mohamed.boucadair@orange.com


--- abstract

RFC 8519 defines a YANG data model for Access Control Lists
(ACLs). This document discusses a set of extensions that fix many of
the limitations of the ACL model as initially defined in RFC 8519. 


--- middle

# Introduction
{{!RFC8519}} defines Acces control lists (ACLs) as a
user-ordered set of filtering rules. The model targets the
configuration of the filtering behaviour of a device. However, the
model structure, as defined in {{!RFC8519}}, suffers from a set of limitations. This
document describes these limitations and proposes an enhanced ACL
structure. 

The motivation of such enhanced ACL structure is discussed in detail in (#ps). 

When managing ACLs, it is common for network operators to group
matching elements in pre-defined sets. The consolidation into matches
allows reducing the number of rules, especially in large scale
networks. If it is needed, for example, to find a match against 100
IP addresses (or prefixes), a single rule will suffice rather than creating
individual Access Control Entries (ACEs) for each IP address (or prefix). In
doing so, implementations would optimize the performance of matching
lists vs multiple rules matching.
  
The enhanced ACL structure is also meant to facilitate the management of
network operators. Instead of entering the IP address or port number
literals, using user-named lists decouples the creation of the rule
from the management of the sets. Hence, it is possible to remove/add
 entries to the list without redefining the (parent) ACL
rule.

In addition, the notion of Access Control List (ACL) and defined sets
 is generalized so that it is not device-specific as per {{!RFC8519}}.  ACLs
 and defined sets may be defined at network / administrative domain level
 and associated to devices. This approach facilitates the reusability across multiple
  network elements. For example, managing the IP prefix sets from a network
   level makes it easier to maintain by the security groups.   

Network operators maintain sets of IP prefixes that are related to each other,
e.g., deny-lists or accept-lists that are associated with those provided by a
 VPN customer. These lists are maintained and manipulated by security expert teams.
    

Note that ACLs are used locally in devices but are triggered by other
tools such as DDoS mitigation {{!RFC9132}} or BGP Flow Spec {{!RFC8955}}
{{!RFC8956}}. Therefore, supporting means to easily map to the filtering rules conveyed in
messages triggered by  hese tools is valuable from a network operation standpoint.

## Terminology

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when they appear in this
document, are to be interpreted as described in {{!RFC2119}}.

The terminology for describing YANG modules is defined in {{!RFC7950}}.
The meaning of the symbols in the tree diagrams is defined in
{{!RFC8340}}.
   

In adition to the terms defined in {{!RFC8519}}, this document makes use of the following terms: 
   
- Defined set: Refers to reusable description of one or multiple information elements (e.g., IP address, IP prefix, port number, ICMP type). 

# Approach

This first version of the document does not include on purpose any YANG module. This is because the authors are seeking a work direction from the netmod WG whether the missing features can be accomplished by means of augmentations or whether an ACL-bis document is more appropriate. 

Future versions of the document will include a YANG module that will reflect the WG feedback. A network wide module, in adition to the device module, might be required. The decision on whether a single module is sufficient to handle both device and network levels or two separate ones will be based on WG feedback.


# Problem Statement & Gap Analysis {#ps}

## Suboptimal Configuration: Lack of Manipulating Lists of Prefixes

IP prefix related data nodes, e.g., "destination-ipv4-network"
or "destination-ipv6-network", do not allow manipulating a list of IP
prefixes, which may lead to manipulating large files. The same issue
is encountered when ACLs have to be in place to mitigate DDoS
attacks (e.g., {{!RFC9132}} when a set of sources are involved in such
an attack. The situation is even worse when both a list of sources
and destination prefixes are involved.

(#example) shows an example of the required ACL configuration for filtering traffic from two prefixes. 

{#example}

~~~~~~~~~~~
{
  "ietf-access-control-list:acls": {
    "acl": [
      {
        "name": "first-prefix",
        "type": "ipv6-acl-type",
        "aces": {
          "ace": [
            {
              "name": "my-test-ace",
              "matches": {
                "ipv6": {
                  "destination-ipv6-network": 
                    "2001:db8:6401:1::/64",
                  "source-ipv6-network": 
                    "2001:db8:1234::/96",
                  "protocol": 17,
                  "flow-label": 10000
                },
                "udp": {
                  "source-port": {
                    "operator": "lte",
                    "port": 80
                  },
                  "destination-port": {
                    "operator": "neq",
                    "port": 1010
                  }
                }
              },
              "actions": {
                "forwarding": "accept"
              }
            }
          ]
        }
      },
      {
        "name": "second-prefix",
        "type": "ipv6-acl-type",
        "aces": {
          "ace": [
            {
              "name": "my-test-ace",
              "matches": {
                "ipv6": {
                  "destination-ipv6-network": 
                    "2001:db8:6401:c::/64",
                  "source-ipv6-network": 
                    "2001:db8:1234::/96",
                  "protocol": 17,
                  "flow-label": 10000
                },
                "udp": {
                  "source-port": {
                    "operator": "lte",
                    "port": 80
                  },
                  "destination-port": {
                    "operator": "neq",
                    "port": 1010
                  }
                }
              },
              "actions": {
                "forwarding": "accept"
              }
            }
          ]
        }
      }
    ]
  }
}
~~~~~~~~~~~
{: #example title=Example Illustrating Sub-optimal Use of the ACL Model with a Prefix List}

Such configuration is suboptimal for both: 
- Network controllers that need to manipulate large files. All or a subset fo this configuration will need to be passed to the undelrying network devices.
- Devices may receive such confirguration and thus will need to maintain it locally. 

(#example_1) depicts an example of an optimized strcuture:


~~~~~~~~~~~
{
  "ietf-access-control-list:acls": {
    "acl": [
      {
        "name": "prefix-list-support",
        "type": "ipv6-acl-type",
        "aces": {
          "ace": [
            {
              "name": "my-test-ace",
              "matches": {
                "ipv6": {
                  "destination-ipv6-network": [
                    "2001:db8:6401:1::/64",
                    "2001:db8:6401:c::/64"
                  ],
                  "source-ipv6-network": 
                    "2001:db8:1234::/96",
                  "protocol": 17,
                  "flow-label": 10000
                },
                "udp": {
                  "source-port": {
                    "operator": "lte",
                    "port": 80
                  },
                  "destination-port": {
                    "operator": "neq",
                    "port": 1010
                  }
                }
              },
              "actions": {
                "forwarding": "accept"
              }
            }
          ]
        }
      }
    ]
  }
}
~~~
{: #example_1 title=Example Illustrating Optimal Use of the ACL Model in a Network Context.}


## Manageability: Impossibility to Use Aliases or Defined Sets

The same approach as the one discussed for IP prefixes can be generalized by introduing the concept of "aliases" or "defined sets". 

The defined sets are reusable definitions across several ACLs. Each category is modelled in YANG as a list of parameters related to the class it represents. The following sets can be considered:

-  Prefix sets: Used to create lists of IPv4 or IPv6 prefixes. 
-  Protocol sets: Used to create a list of protocols. 
-  Port number sets: Used to create lists of TCP or UDP port values (or any other transport protocol that makes uses of port numbers). The identity of the protcols is identified by the protocol set, if present. Otherwise, a set apply to any protocol. 
-  ICMP sets: Uses to create lists of ICMP-based filters. This applies only when the protocol is set to ICMP or ICMPv6.

A candidate structure is shown in #example_sets:

{#example_sets}
~~~ ascii-art
     +--rw defined-sets
     |  +--rw prefix-sets
     |  |  +--rw prefix-set* [name mode]
     |  |     +--rw name        string
     |  |     +--rw mode        enumeration
     |  |     +--rw ip-prefix*   inet:ip-prefix
     |  +--rw port-sets
     |  |  +--rw port-set* [name]
     |  |     +--rw name    string
     |  |     +--rw port*   inet:port-number
     |  +--rw protocol-sets
     |  |  +--rw protocol-set* [name]
     |  |     +--rw name             string
     |  |     +--rw protocol-name*   identityref
     |  +--rw icmp-type-sets
     |     +--rw icmp-type-set* [name]
     |        +--rw name     string
     |        +--rw types* [type]
     |           +--rw type              uint8
     |           +--rw code?             uint8
     |           +--rw rest-of-header?   binary
~~~
Figure: Examples of Defined Sets.

## Bind ACLs to Devices, Not Only Interfaces

In the context of network management, an ACL may be enforced in many network locations. As such, the ACL module should allow binding an ACL to multiple devices, not only (abstract) interfaces. 

The ACL name must, thus, be unique at the scale of the network, but still the same name may be used in many devices when enforcing node-specific ACLs. 

## Partial or Lack of IPv4/IPv6 Fragment Handling

{{!RFC8519}} does not support fragment handling capability for IPv6 but
offers a partial support for IPv4 by means of 'flags'.  Nevertheless,
the use of 'flags' is problematic since it does not allow a bitmask
to be defined.  For example, setting other bits not covered by the
'flags' filtering clause in a packet will allow that packet to get
through (because it won't match the ACE).  
   
Defining a new IPv4/IPv6 matching field called 'fragment' is thus required to efficiently handle fragment-related filtering rules. Some examples to illustrate how 'fragment' can be used are provided below.
   
(#example_2) shows the content of a candidate POST request to allow the traffic destined to 198.51.100.0/24 and UDP port number 53, but to drop all fragmented
packets.  The following ACEs are defined (in this order):

* "drop-all-fragments" ACE: discards all fragments.
* "allow-dns-packets" ACE: accepts DNS packets destined to 198.51.100.0/24.


~~~~~~~~~~~
TBD
~~~~~~~~~~~
{: #example_2 title=Example Illustrating Canddiate Filtering of IPv4 Fragmented Packets.} 

(#example_3) shows an example of the body of a candidate POST request to allow the traffic destined to 2001:db8::/32 and UDP port number 53, but to drop all fragmented packets. The following ACEs are defined (in this order):

* "drop-all-fragments" ACE: discards all fragments (including atomic fragments). That is, IPv6 packets that include a Fragment header (44) are dropped.
* "allow-dns-packets" ACE: accepts DNS packets destined to 2001:db8::/32.

{#example_3}
~~~~~~~~~~~
TBD2
~~~~~~~~~~~
Figure: Example Illustrating Canddiate Filtering of IPv6 Fragmented Packets.

## Suboptimal TCP Flags Handling

{{!RFC8519}} allows including flags in the TCP match fields, however that strcuture does not support matching operations as those supported in BGP Flow Spec. Definig this field to be defined as a flag bitmask together with a set of operations is meant to efficiently handle TCP flags filtering rules. Some examples to illustrate the use of such field are discussed below.
   
(#example_4) shows an example of a candidate request to install a filter to discard incoming TCP messages having all flags unset.
   
{#example_4}
~~~~~~~~~~~
 TBD 3
~~~~~~~~~~~
Figure: Example to Deny TCP Null Attack Messages   
   
## Rate-Limit Action 

 {{!RFC8519}} specifies that forwarding actions can be 'accept' (i.e., accept matching
   traffic), 'drop' (i.e., drop matching traffic without sending any
   ICMP error message), or 'reejct' (i.e., drop matching traffic and send an ICMP error message to the source). Howover, there are situations where the matching traffic can be accepted, but with a rate-limit policy. Such capability is not currently supported by the ACL model. 
   
(#example_5) shows a candidate ACL example to rate-limit incoming SYNs during a SYN flood attack.
   
~~~~~~~~~~~
  {
     "ietf-access-control-list:acls": {
       "acl": [{
         "name": "tcp-flags-example-with-rate-limit",
         "aces": {
           "ace": [{
             "name": "rate-limit-syn",
             "matches": {
               "tcp": {
                 "flags-bitmask": {
                   "operator": "match",
                   "bitmask": 2
                 }
               }
             },
             "actions": {
               "forwarding": "accept",
               "rate-limit": "20.00"
             }
           }]
         }
       }]
     }
   }
~~~~~~~~~~~
{:#example_5 title=Example Rate-Limit Incoming TCP SYNs}

## Payload-based Filtering

Some transport protocols use existing protocols (e.g., TCP or UDP) as substrate. The match criteria for such protocols may rely upon the 'protocol' under 'l3', TCP/UDP match criteria, part of the TCP/UDP payload, or a combination thereof. {{!RFC8519}} does not support matching based on the payload.

Likewise, the current version of the ACL model does not support filetering of encapsulated traffic.

## Reuse the ACLs Content Across Several Devices 

Having a global network view of the ACLs is highly valuable for service providers. An ACL could be defined and applied
following the hierarchy of the network topology. So, an ACL can be
defined at the network level and, then, that same ACL can be used (or referenced to)
in several devices (including termination points) within the same network. 

This network/device ACLs differentiation introduces several new
requirements, e.g.:

* An ACL name can be used at both network and device levels. 
* An ACL content updated at the network level should imply 
  a transaction that updates the relevant content in all the nodes using this
  ACL.
* ACLs defined at the device level have a local meaning for the specific node. 
* A device can be associated with a router, a VRF, a
  logical system, or a virtual node. ACLs can be applied in physical and
  logical infrastructure. 

# Overall Module Structure  

## Enhanced ACL

{#enh-acl-tree}
~~~~~~~~~~~
module: ietf-acl-enh
  augment /ietf-acl:acls/ietf-acl:acl/ietf-acl:aces/ietf-acl:ace
            /ietf-acl:matches:
    +--rw (payload)?
       +--:(prefix-pattern)
          +--rw prefix-pattern {match-on-payload}?
             +--rw offset?       identityref
             +--rw offset-end?   uint64
             +--rw operator?     operator
             +--rw prefix?       binary
  augment /ietf-acl:acls/ietf-acl:acl/ietf-acl:aces/ietf-acl:ace
            /ietf-acl:matches/ietf-acl:l3/ietf-acl:ipv4:
    +--rw fragment
       +--rw operator?   operator
       +--rw type?       fragment-type
  augment /ietf-acl:acls/ietf-acl:acl/ietf-acl:aces/ietf-acl:ace
            /ietf-acl:matches/ietf-acl:l3/ietf-acl:ipv6:
    +--rw fragment
       +--rw operator?   operator
       +--rw type?       fragment-type
  augment /ietf-acl:acls/ietf-acl:acl/ietf-acl:aces/ietf-acl:ace
            /ietf-acl:matches/ietf-acl:l4/ietf-acl:tcp:
    +--rw flags-bitmask
       +--rw operator?   operator
       +--rw bitmask?    uint16
  augment /ietf-acl:acls/ietf-acl:acl/ietf-acl:aces/ietf-acl:ace
            /ietf-acl:actions:
    +--rw rate-limit?   decimal64
~~~~~~~~~~~

## TBA

# YANG Modules

## Enhanced ACL

{#enh-acl}
~~~~~~~~~~~
module ietf-acl-enh {
  yang-version 1.1;
  namespace "urn:ietf:params:xml:ns:yang:ietf-acl-enh";
  prefix enh-acl;

  import ietf-access-control-list {
    prefix ietf-acl;
  }

  organization
    "IETF NETMOD Working Group";
  contact
    "WG Web:   <https://datatracker.ietf.org/wg/netmod/>
     WG List:  <mailto:netmod@ietf.org>

     Author:    Mohamed Boucadair
               <mailto:mohamed.boucadair@orange.com>
     Author:    Samier Barguil
               <mailto:samier.barguilgiraldo.ext@telefonica.com>
     Author:    Oscar Gonzalez de Dios
               <mailto:oscar.gonzalezdedios@telefonica.com>";
  description
    "This module contains YANG definitions for enhanced ACLs.

     Copyright (c) 2021 IETF Trust and the persons identified as
     authors of the code.  All rights reserved.

     Redistribution and use in source and binary forms, with or
     without modification, is permitted pursuant to, and subject
     to the license terms contained in, the Simplified BSD License
     set forth in Section 4.c of the IETF Trust's Legal Provisions
     Relating to IETF Documents
     (http://trustee.ietf.org/license-info).

     This version of this YANG module is part of RFC XXXX; see
     the RFC itself for full legal notices.";

  revision 2021-12-07 {
    description
      "Initial revision.";
    reference
      "RFC XXXX: xxxxx";
  }

  feature match-on-payload {
    description
      "Match based on a pattern is supported.";
  }

  identity offset-type {
    description
      "Base identity for payload offset type.";
  }

  identity layer3 {
    base offset-type;
    description
      "IP header.";
  }

  identity layer4 {
    base offset-type;
    description
      "Transport header (e.g., TCP or UDP).";
  }

  identity payload {
    base offset-type;
    description
      "Transport payload. For example, this represents the beginning
       of the TCP data right after any TCP options.";
  }

  typedef operator {
    type bits {
      bit not {
        position 0;
        description
          "If set, logical negation of operation.";
      }
      bit match {
        position 1;
        description
          "Match bit.  If set, this is a bitwise match operation
           defined as '(data & value) == value'; if unset, (data &
           value) evaluates to TRUE if any of the bits in the value
           mask are set in the data , i.e., '(data & value) != 0'.";
      }
    }
    description
      "How to apply the defined bitmask.";
  }

  typedef fragment-type {
    type bits {
      bit df {
        position 0;
        description
          "Don't fragment bit for IPv4.
           Must be set to 0 when it appears in an IPv6 filter.";
      }
      bit isf {
        position 1;
        description
          "Is a fragment.";
      }
      bit ff {
        position 2;
        description
          "First fragment.";
      }
      bit lf {
        position 3;
        description
          "Last fragment.";
      }
    }
    description
      "Different fragment types to match against.";
  }

  grouping tcp-flags {
    description
      "Operations on TCP flags.";
    leaf operator {
      type operator;
      default "match";
      description
        "How to interpret the TCP flags.";
    }
    leaf bitmask {
      type uint16;
      description
        "Bitmask values can be encoded as a 1- or 2-byte bitmask.
         When a single byte is specified, it matches byte 13
         of the TCP header, which contains bits 8 though 15
         of the 4th 32-bit word.  When a 2-byte encoding is used,
         it matches bytes 12 and 13 of the TCP header with
         the bitmask fields corresponding to the TCP data offset
         field being ignored for purposes of matching.";
    }
  }

  grouping fragment-fields {
    description
      "Operations on fragment types.";
    leaf operator {
      type operator;
      default "match";
      description
        "How to interpret the fragment type.";
    }
    leaf type {
      type fragment-type;
      description
        "What fragment type to look for.";
    }
  }

  grouping payload {
    description
      "Operations on payload match.";
    leaf offset {
      type identityref {
        base offset-type;
      }
      description
        "Indicates the payload offset.";
    }
    leaf offset-end {
      type uint64;
      description
        "Indicates the number of bytes to cover when
         performing the prefix match.";
    }
    leaf operator {
      type operator;
      default "match";
      description
        "How to interpret the prefix match.";
    }
    leaf prefix {
      type binary;
      description
        "The pattern to match against.";
    }
  }

  augment "/ietf-acl:acls/ietf-acl:acl/ietf-acl:aces"
        + "/ietf-acl:ace/ietf-acl:matches" {
    description
      "Add a new match types.";
    choice payload {
      description
        "Match a prefix pattern.";
      container prefix-pattern {
        if-feature "match-on-payload";
        description
          "Rule to perform payload-based match.";
        uses payload;
      }
    }
  }

  augment "/ietf-acl:acls/ietf-acl:acl/ietf-acl:aces"
        + "/ietf-acl:ace/ietf-acl:matches/ietf-acl:l3/ietf-acl:ipv4" {
    description
      "Handle non-initial and initial fragments for IPv4 packets.";
    container fragment {
      description
        "Indicates how to handle IPv4 fragments.";
      uses fragment-fields;
    }
  }

  augment "/ietf-acl:acls/ietf-acl:acl/ietf-acl:aces"
        + "/ietf-acl:ace/ietf-acl:matches/ietf-acl:l3/ietf-acl:ipv6" {
    description
      "Handle non-initial and initial fragments for IPv6 packets.";
    container fragment {
      description
        "Indicates how to handle IPv6 fragments.";
      uses fragment-fields;
    }
  }

  augment "/ietf-acl:acls/ietf-acl:acl/ietf-acl:aces"
        + "/ietf-acl:ace/ietf-acl:matches/ietf-acl:l4/ietf-acl:tcp" {
    description
      "Handle TCP flags.";
    container flags-bitmask {
      description
        "Indicates how to handle TCP flags.";
      uses tcp-flags;
    }
  }

  augment "/ietf-acl:acls/ietf-acl:acl/ietf-acl:aces"
        + "/ietf-acl:ace/ietf-acl:actions" {
    description
      "rate-limit action.";
    leaf rate-limit {
      when "/ietf-acl:acls/ietf-acl:acl/ietf-acl:aces/"
         + "ietf-acl:ace/ietf-acl:actions/"
         + "ietf-acl:forwarding = 'ietf-acl:accept'" {
        description
          "rate-limit valid only when accept action is used.";
      }
      type decimal64 {
        fraction-digits 2;
      }
      description
        "rate-limit traffic.";
    }
  }
}
~~~~~~~~~~~

# Security Considerations (TBC)
 
The YANG modules specified in this document define a schema for data
   that is designed to be accessed via network management protocol such
   as NETCONF {{!RFC6241}} or RESTCONF {{!RFC8040}}.  The lowest NETCONF layer
   is the secure transport layer, and the mandatory-to-implement secure
   transport is Secure Shell (SSH) {{!RFC6242}}.  The lowest RESTCONF layer
   is HTTPS, and the mandatory-to-implement secure transport is TLS
   {{!RFC8446}}.
   
The Network Configuration Access Control Model (NACM) {{!RFC8341}} provides the means to restrict access for particular NETCONF or RESTCONF users to a preconfigured subset of all available NETCONF or RESTCONF protocol operations and content. 

There are a number of data nodes defined in this YANG module that are writable/creatable/deletable (i.e., config true, which is the default). These data nodes may be considered sensitive or vulnerable in some network environments. Write operations (e.g., edit-config) to these data nodes without proper protection can have a negative effect on network operations. These are the subtrees and data nodes and their sensitivity/vulnerability: 

- TBC

Some of the readable data nodes in this YANG module may be considered sensitive or vulnerable in some network environments. It is thus important to control read access (e.g., via get, get-config, or notification) to these data nodes. These are the subtrees and data nodes and their sensitivity/vulnerability: 

- TBC


# IANA Considerations

## URI Registration (TBC)

   This document requests IANA to register the following URI in the "ns"
   subregistry within the "IETF XML Registry" {{!RFC3688}}:
~~~
         URI: urn:ietf:params:xml:ns:yang:xxx
         Registrant Contact: The IESG.
         XML: N/A; the requested URI is an XML namespace.
~~~

## YANG Module Name Registration (TBC)

This document requests IANA to register the following YANG module in
   the "YANG Module Names" subregistry {{!RFC6020}} within the "YANG
   Parameters" registry.
~~~
         name: xxxx
         namespace: urn:ietf:params:xml:ns:yang:ietf-xxx
         maintained by IANA: N
         prefix: xxxx
         reference: RFC XXXX
~~~



--- back

# Acknowledgements

Many thanks to Jon Shallow and Miguel Cros for the discussion when preparing this draft. 
