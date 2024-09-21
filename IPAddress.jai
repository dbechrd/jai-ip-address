/*
A standalone IP address module, for parsing, comparing and converting IP addresses to and from strings.

This module was originally a native Jai port of the Address class in Glenn Fielder's yojimbo library, as of this commit:
https://github.com/mas-bandwidth/yojimbo/blob/c6c02dfec105b36b9cbefd82f86f11f894f6de51/source/yojimbo_address.cpp

It has been completely rewritten from scratch, with many features added, including significant validation improvements.
*/

#module_parameters(
    ENABLE_LOGGING := false
);

IPType :: enum u8 {
    None;  // Not an address. Set by the default constructor.
    IPv4;  // An IPv4 address, eg: "146.95.129.237"
    IPv6;  // An IPv6 address, eg: "48d9:4a08:b543:ae31:89d8:3226:b92c:cbba"
};

/*
An IP address and port number.

Supports both IPv4 and IPv6 addresses.
Identifies where a packet came from, and where a packet should be sent.
*/
IPAddress :: struct {
    type: IPType;       // The address type: IPv4 or IPv6.
    port: u16;          // The IP port. Valid for IPv4 and IPv6 address types. Host byte order.
    data: union {
        v4: [4] u8;   // IPv4 address data. Valid if type is IPv4. Network byte order.
        v6: [8] u16;  // IPv6 address data. Valid if type is IPv6. Network byte order.
    };
}

/*
Converts a canonical IPv4 string (e.g. "127.0.0.1" or "127.0.0.1:80") to an IPAddress.

Implementation inspired by: https://git.musl-libc.org/cgit/musl/tree/src/network/inet_pton.c
*/
address_init_v4 :: (str: string) -> address: IPAddress, remainder: string {
    address := IPAddress.{ type = .IPv4 };
    remainder: string;

    octet_start := 0;
    for octet: 0..3 {
        digits := 0;
        value := 0;
        for 0..2 {
            if octet_start + digits == str.count
                break;

            c := str[octet_start + digits];
            if !is_digit(c)
                break;

            value *= 10;
            value += c - #char "0";
            digits += 1;
        }

        if digits == 0 {
            if octet_start == str.count {
                address_log(.VERBOSE_ONLY, "Premature end-of-string in octet % while parsing '%' as an IPv4 address. Expected digit (0-9).\n", octet + 1, str);
                return .{}, str;
            } else {
                address_log(.ERROR, "Unexpected character '%' in octet % while parsing '%' as an IPv4 address. Expected digit (0-9).\n", string.{ 1, str.data + octet_start }, octet + 1, str);
                return .{}, str;
            }
        }
        if digits > 1 && str[octet_start] == #char "0" {
            // Note: Some tools (such as `ping` on Windows) will accept leading zeros and interpret the octect as
            // an octal (base-8) number. This seems exceptionally stupid and confusing to me, so let's just throw an error.
            address_log(.VERBOSE_ONLY, "Illegal leading zero(s) in octet % ('%') while parsing '%' as an IPv4 address.\n", octet + 1, string.{ digits, str.data + octet_start }, str);
            return .{}, str;
        }
        if value > 255 {
            address_log(.VERBOSE_ONLY, "Out-of-range value '%' in octet % ('%') while parsing '%' as an IPv4 address. Expected octet in range (0-255).\n", value, octet + 1, string.{ digits, str.data + octet_start }, str);
            return .{}, str;
        }

        address.data.v4[octet] = cast(u8) value;

        if octet == 3 {
            // Success!
            remainder = str;
            advance(*remainder, octet_start + digits);
            break;
        }

        if octet_start + digits == str.count {
            address_log(.VERBOSE_ONLY, "Premature end-of-string after octet % ('%') while parsing '%' as an IPv4 address. Expected dot (.) separator.\n", octet + 1, string.{ digits, str.data + octet_start }, str);
            return .{}, str;
        }
        if str[octet_start + digits] != #char "." {
            address_log(.VERBOSE_ONLY, "Unexpected character '%' after octet % ('%') while parsing '%' as an IPv4 address. Expected dot (.) separator.\n", string.{ 1, str.data + octet_start + digits }, octet + 1, string.{ digits, str.data + octet_start }, str);
            return .{}, str;
        }
        octet_start += digits + 1;  // discard octet and dot separator
    }

    before_port_remainder := remainder;

    // Attempt to parse a valid port number from the remainder string
    if remainder.count > 1 && remainder[0] == #char ":" {
        advance(*remainder, 1);
        port, success, port_remainder := to_integer(remainder);
        if success {
            if port >= 0 && port <= 0xffff {
                address.port = cast(u16) port;
                return address, port_remainder;
            } else {
                address_log(.VERBOSE_ONLY, "Found what looked like a port ('%') after the colon while parsing '%' as an IPv4 address, but it was out of range. Port must be in range 0-65535, inclusive.\n", port, str);
            }
        }
    }

    // If no port was found, return the address without a port and the original remainder string
    return address, before_port_remainder;
}

/*
Converts a canonical IPv4 string (e.g. "127.0.0.1" or "127.0.0.1:80") to an IPAddress.

This overload allows you to specific the port explicitly, which will override any port found in the string.
We will still parse and validate the entire string though, for consistency, so if the string contains an
invalid port number, etc., you will still get an error.

See the `address_init_v4 :: (str: string)` overload for more information about valid address strings.
*/
address_init_v4 :: (str: string, port: u16) -> result: IPAddress, remainder: string {
    address, remainder := address_init_v4(str);
    if address.type == .IPv4 {
        address.port = port;
    }
    return address, remainder;
}

/*
Create an IPv4 address.

@param address Array of four address fields for the IPv4 address.
@param port The port number (host byte order).
*/
address_init_v4 :: (ipv4: [4] u8, port: u16 = 0) -> IPAddress {
    address := IPAddress.{
        type = .IPv4,
        data.v4 = ipv4,
        port = port
    };
    return address;
}

/*
Create an IPv4 address.

IMPORTANT: Pass in port in Host byte order. The address class handles the conversion to network order for you.

@param a The first field of the IPv4 address.
@param b The second field of the IPv4 address.
@param c The third field of the IPv4 address.
@param d The fourth field of the IPv4 address.
@param port The IPv4 port (host byte order).
*/
address_init_v4 :: (a: u8, b: u8, c: u8, d: u8, port: u16 = 0) -> IPAddress {
    address := IPAddress.{
        type = .IPv4,
        data.v4[0] = a,
        data.v4[1] = b,
        data.v4[2] = c,
        data.v4[3] = d,
        port = port
    };
    return result;
}

/*
Converts a canonical IPv6 string to an IPAddress. E.g.:

    "2001:db8:0000:0000:0000:0000:7777:8888"

We also handle the double-colon compression syntax for contiguous zeros; i.e."2001:db8::7777:8888" will result
in the same byte array as the full version of the address above. E.g.:

    "2001:db8::7777:8888"

If you'd like to provide a port via the string (as opposed to specifying it explicitly using the overload below),
then you MUST provide a bracketed IPv6 address. E.g.:

    "[2001:db8:0000:0000:0000:0000:7777:8888]:80"
    "[2001:db8::7777:8888]:80"

You MUST NOT provide a bracketed IPv6 address without a colon separator and port number.

We DO NOT handle IPv4-mapped IPv6 addresses in string format (e.g. "::ffff:127.0.0.1"). If you would like to create
such an address, call `address_init_v4` with the IPv4 portion of the string, check for success, then pass the resulting
buffer of bytes to `address_init_v6(ipv4: IPAddress)` to create an IPv4-mapped IPv6 address.

Implementation inspired by: https://git.musl-libc.org/cgit/musl/tree/src/network/inet_pton.c
Some examples of other valid IPv6 variants:

    2001:db8:0:0:1:0:0:1
    2001:0db8:0:0:1:0:0:1
    2001:db8::1:0:0:1
    2001:db8::0:1:0:0:1
    2001:0db8::1:0:0:1
    2001:db8:0:0:1::1
    2001:db8:0000:0:1::1
    2001:DB8:0:0:1::1

    See https://datatracker.ietf.org/doc/html/rfc5952#section-1 for more context.
*/
address_init_v6 :: (str: string) -> result: IPAddress, remainder: string {
    hexval :: (c: u8) -> int {
        if c == {
            case #char "0"; return 0;
            case #char "1"; return 1;
            case #char "2"; return 2;
            case #char "3"; return 3;
            case #char "4"; return 4;
            case #char "5"; return 5;
            case #char "6"; return 6;
            case #char "7"; return 7;
            case #char "8"; return 8;
            case #char "9"; return 9;
            case #char "A"; #through; case #char "a"; return 10;
            case #char "B"; #through; case #char "b"; return 11;
            case #char "C"; #through; case #char "c"; return 12;
            case #char "D"; #through; case #char "d"; return 13;
            case #char "E"; #through; case #char "e"; return 14;
            case #char "F"; #through; case #char "f"; return 15;
        }
        return -1;
    }

    s := str;
    address := IPAddress.{ type = .IPv6 };

    // Note: I'm calling double-colons, which eat an arbitrary number of IPv6 segments, the "worm" because they are
    // stretchy like a worm, force the parser to accept all kinds of garbage inputs (which I've dubbed "worm food"),
    // and can be represented as an emoji in discord via ":worm:" (which is what I imagine when I see a double colon
    // in an IPv6 address).
    //
    // And now, I present, the worm dance: "1111:2222:worm:6666:7777".
    worm_segment: int = -1;

    if s.count < 2 {
        address_log(.VERBOSE_ONLY, "Unable to parse '%' as an IPv6 address. Not enough characters.\n", str);
        return .{}, str;
    }

    bracketed := false;
    if s[0] == #char "[" {
        advance(*s, 1);
        bracketed = true;
    }

    if s.count < 2 {
        address_log(.VERBOSE_ONLY, "Unable to parse '%' as an IPv6 address. Not enough characters.\n", str);
        return .{}, str;
    }

    if s[0] == #char ":" {
        if s[1] != #char ":" {
            address_log(.VERBOSE_ONLY, "Unexpected character '%' in segment 1 while parsing '%' as an IPv6 address. Addresses starting with a colon (:) must start with a double colon (::).\n", string.{ 1, s.data }, str);
            return .{}, str;
        }

        if s.count == 2 {
            if bracketed {
                // If an address starts with `[::` then hits end-of-string, it is not valid.
                address_log(.VERBOSE_ONLY, "Premature end-of-string in bracketed unspecified address while parsing '%' as an IPv6 address. Expected closing square bracket (]) followed by a port number.\n", str);
                return .{}, str;
            }

            // "::" is the IPv6 "unspecified address" (all zeros), and is perfectly valid.
            return address, "";
        }

        // discard first colon of "::"
        advance(*s, 1);
    }

    segment := 0;
	while segment <= 7 {
		if s.count > 0 && s[0] == #char ":" && worm_segment < 0 {
			worm_segment = segment;
			address.data.v6[segment] = 0;

            // discard second colon of "::"
            advance(*s, 1);

            if segment == 7 {
                break;
            }
            segment += 1;
			continue;
		}

        segment_start := pointer_diff(s.data, str.data);
        digits := 0;
        value := 0;
        for 0..3 {
            if !s.count break;

            hex_value := hexval(s[0]);
            if hex_value < 0
                break;

            value *= 16;
            value += hex_value;

            digits += 1;
            advance(*s, 1);
        }

		if digits == 0 {
            if worm_segment >= 0 {
                // We're in :worm: mode, anything goes in :worm: mode.
                // Backtrack the last colon we read and assume it is part of the remainder string, UNLESS it's
                // part of a trailing (::).
                if worm_segment < segment - 1 {
                    s.data -= 1;
                    s.count += 1;
                }
                segment -= 1;
                break;
            }

            if !s.count {
                address_log(.VERBOSE_ONLY, "Premature end-of-string in segment % while parsing '%' as an IPv6 address. Expected hex digit (0-F).\n", segment + 1, str);
                return .{}, str;
            } else {
                address_log(.VERBOSE_ONLY, "Unexpected character '%' in segment % while parsing '%' as an IPv6 address. Expected hex digit (0-F).\n", string.{ 1, str.data + segment_start }, segment + 1, str);
                return .{}, str;
            }
        }

        address.data.v6[segment] = cast(u16) value;

        if segment == 7 {
            break;
        }

		if !s.count {
            if worm_segment >= 0 {
                // We reached a premature end-of-string, but the :worm: makes everything valid! It can stretch and fill
                // the gaps with its worm-like body.
                break;
            } else {
                address_log(.VERBOSE_ONLY, "Premature end-of-string after segment % ('%') while parsing '%' as an IPv6 address. Expected colon (:) separator.\n", segment + 1, string.{ digits, str.data + segment_start }, str);
                return .{}, str;
            }
        }

		if s[0] != #char ":" {
            if worm_segment >= 0 {
                // The next character isn't a delimiter, like we expect, but it's okay the :worm: is here to save the day!
                break;
            } else {
                address_log(.VERBOSE_ONLY, "Unexpected character '%' after segment % ('%') while parsing '%' as an IPv6 address. Expected colon (:) separator.\n", string.{ 1, s.data }, segment + 1, string.{ digits, str.data + segment_start }, str);
                return .{}, str;
            }
        }

		advance(*s, 1);  // discard ':' separator
        segment += 1;
	}

    // Fill the :worm: hole with zeroes and shift the other segments accordingly.
    // Note: If worm_segment is the last segment we read, we don't need to shift anything
    // (the code would work in that case, but why run it?)
	if worm_segment >= 0 && worm_segment < segment {
        // input | before fix-up     -> after fix-up      | debugger info
        //--------------------------------------------------------------------------------
        // ::F:F | [0,F,F,0,0,0,0,0] -> [0:0:0:0:0:0:F:F] | worm_segment = 0, segment = 3
        // F::F  | [F,0,F,0,0,0,0,0] -> [F:0:0:0:0:0:0:F] | worm_segment = 1, segment = 3
        // F::   | [F,0,0,0,0,0,0,0] -> [F:0:0:0:0:0:0:0] | worm_segment = 1, segment = 2
        tail_start := worm_segment + 1;
        tail_length := segment - tail_start + 1;
        dest := 8 - tail_length;
        for < tail_length-1..0 {
            address.data.v6[dest + it] = address.data.v6[tail_start + it];
            address.data.v6[tail_start + it] = 0;
        }
	}

    if bracketed {
        if !s.count {
            address_log(.VERBOSE_ONLY, "Premature end-of-string while parsing '%' as a bracketed IPv6 address. Expected closing bracket (]), then colon (:), then port number.\n", str);
            return .{}, str;
        } else if s[0] != #char "]" {
            address_log(.VERBOSE_ONLY, "Unexpected character '%' while parsing '%' as a bracketed IPv6 address. Expected closing bracket (]) then colon (:), then port number.\n", string.{ 1, s.data }, str);
            return .{}, str;
        }
        advance(*s, 1);  // discard ']'

        if !s.count {
            address_log(.VERBOSE_ONLY, "Premature end-of-string while parsing '%' as a bracketed IPv6 address. Expected colon (:), then port number.\n", str);
            return .{}, str;
        } else if s[0] != #char ":" {
            address_log(.VERBOSE_ONLY, "Unexpected character '%' while parsing '%' as a bracketed IPv6 address. Expected colon (:), then port number.\n", string.{ 1, s.data }, str);
            return .{}, str;
        }
        advance(*s, 1);  // discard ':' port separator

        if !s.count {
            address_log(.VERBOSE_ONLY, "Premature end-of-string while parsing '%' as a bracketed IPv6 address. Expected a port number after the colon (:).\n", str);
            return .{}, str;
        }

        // Attempt to parse a valid port number from the remainder string
        port, success, port_remainder := to_integer(s);
        if success {
            if port >= 0 && port <= 0xffff {
                address.port = cast(u16) port;
                return address, port_remainder;
            } else {
                address_log(.VERBOSE_ONLY, "Found what looked like a port ('%') after the colon while parsing '%' as a bracketed IPv6 address, but it was out of range. Port must be in range 0-65535, inclusive.\n", port, str);
                return .{}, str;
            }
        } else {
            address_log(.VERBOSE_ONLY, "Unexpected character '%' while parsing '%' as a bracketed IPv6 address. Expected a port number after the colon (:).\n", string.{ 1, s.data }, str);
            return .{}, str;
        }
    } else {
        if s.count > 0 {
            if s[0] == #char ":" {
                address_log(.VERBOSE_ONLY, "Sanity check failure while parsing '%' as an IPv6 address. We don't allow the remainder string to start with a colon (:) in unbracketed IPv6 addresses, because it's extremely likely to be an error in practice.\n", str);
                return .{}, str;
            } else if hexval(s[0]) >= 0 {
                address_log(.VERBOSE_ONLY, "Sanity check failure while parsing '%' as an IPv6 address. We don't allow the remainder string to start with a hex character ('%') in unbracketed IPv6 addresses, because it's extremely likely to be an error in practice.\n", str, string.{ 1, s.data });
                return .{}, str;
            }
        }

        // Not a bracketed IPv6 adddress, so it cannot legally contain a port number. Return the address on its own.
        return address, s;
    }
}

/*
Converts a canonical IPv6 string (e.g. "2001:db8:0000:0000:0000:0000:7777:8888") to an IPAddress.

This overload allows you to specific the port explicitly, which will override any port found in the string.
We will still parse and validate the entire string though, for consistency, so if the string contains an
invalid port number, missing bracket, etc. you will still get an error.

See the `address_init_v6 :: (str: string)` overload for more information about valid address strings.
*/
address_init_v6 :: (str: string, port: u16) -> result: IPAddress, remainder: string {
    address, remainder := address_init_v6(str);
    if address.type == .IPv6 {
        address.port = port;
    }
    return address, remainder;
}

/*
Create an IPv6 address.
IMPORTANT: Pass in address fields and the port in host byte order. The address class handles the conversion to network order for you.

@param address Array of 8 16 bit address fields for the IPv6 address (host byte order).
@param port The IPv6 port (host byte order).
*/
address_init_v6 :: (ipv6: [8] u16, port: u16 = 0) -> IPAddress {
    address := IPAddress.{
        type = .IPv6,
        data.v6 = ipv6,
        port = port
    };
    return address;
}

/*
Create an IPv6 address.
IMPORTANT: Pass in address fields and the port in host byte order. The address class handles the conversion to network order for you.

@param a First field of the IPv6 address (host byte order).
@param b Second field of the IPv6 address (host byte order).
@param c Third field of the IPv6 address (host byte order).
@param d Fourth field of the IPv6 address (host byte order).
@param e Fifth field of the IPv6 address (host byte order).
@param f Sixth field of the IPv6 address (host byte order).
@param g Seventh field of the IPv6 address (host byte order).
@param h Eighth field of the IPv6 address (host byte order).
@param port The port number (host byte order).
*/
address_init_v6 :: (a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16, port: u16 = 0) -> IPAddress {
    address := IPAddress.{
        type = .IPv6,
        data.v6[0] = a,
        data.v6[1] = b,
        data.v6[2] = c,
        data.v6[3] = d,
        data.v6[4] = e,
        data.v6[5] = f,
        data.v6[6] = g,
        data.v6[7] = h,
        port = port
    };
    return address;
}

/*
Converts an IPv4 address to its corresponding IPv4-mapped IPv6 address.

For example, the string "127.0.0.1" can be converted to an IPv4 address by calling `address_init_v4`.
After checking for success, the resulting address can be passed into this function to convert it to an IPv6
address that is equivalent to the result of calling `address_init_v6("::FFFF:7F00:1")`, where 7F00:0001
is the hexademical representation of 127.0.0.1, and the preceding FFFF denotes an IPv4-mapped IPv6 address as
described in RFC 4291 Section 2.5.5.2 (https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2).
*/
address_init_v6 :: (ipv4: IPAddress) -> IPAddress {
    assert(ipv4.type == .IPv4);

    if (ipv4.type != .IPv4) {
        return .{};
    }

    ipv6: IPAddress;
    ipv6.type = .IPv6;
    ipv6.port = ipv4.port;
    ipv6.data.v6[5] = 0xFFFF;
    ipv6.data.v6[6] = (cast(u16) ipv4.data.v4[0]) << 8 | ipv4.data.v4[1];
    ipv6.data.v6[7] = (cast(u16) ipv4.data.v4[2]) << 8 | ipv4.data.v4[3];
    return ipv6;
}

/*
Converts an IPv4 *or* IPv6 string to an IPAddress, by auto-detecting which type it is. Auto-detection
is essentially free for IPv4 addresses, but a bit more expensive for IPv6 addresses, because the parser
will first attempt to parse the string as IPv4, then parse IPv6 if the IPv4 parse fails. If you know
that your address string is always an IPv6 address, use address_init_v6() instead.
*/
address_init_auto_detect :: (str: string) -> address: IPAddress, remainder: string {
    address, remainder := address_init_v4(str);
    if address.type == .IPv4 {
        return address, remainder;
    }
    address, remainder = address_init_v6(str);
    return address, remainder;
}

/*
Converts the address to a human-readable string.
This does not include port. Read that from the IPAddress struct yourself if you want it.
This also doesn't collapse zeroes in IPv6 addresses using :: syntax right now.
*/
address_to_string :: (using address: IPAddress, canonical := false) -> string {
    if type == {
        case .IPv4;
            a := data.v4[0];
            b := data.v4[1];
            c := data.v4[2];
            d := data.v4[3];

            builder: String_Builder;

            print_to_builder(*builder, "%.%.%.%", a, b, c, d);
            if port != 0 {
                print_to_builder(*builder, ":%", port);
            }

            str := builder_to_string(*builder);
            return str;
        case .IPv6;
            digits := ifx canonical then 4 else 1;
            words := cast,force([8] u16) data.v6;

            builder: String_Builder;

            if port != 0 {
                append(*builder, "[");
            }
            print_to_builder(*builder, "%:%:%:%:%:%:%:%",
                formatInt(words[0], 16, digits),
                formatInt(words[1], 16, digits),
                formatInt(words[2], 16, digits),
                formatInt(words[3], 16, digits),
                formatInt(words[4], 16, digits),
                formatInt(words[5], 16, digits),
                formatInt(words[6], 16, digits),
                formatInt(words[7], 16, digits),
            );
            if port != 0 {
                print_to_builder(*builder, "]:%", port);
            }

            str := builder_to_string(*builder);
            return str;
        case;
            return "(ADDRESS_NONE)";
    }
}

/*
Is this a loopback address?
Corresponds to an IPv4 address of "127.*.*.*", or an IPv6 address of "::1".

@returns True if this is the loopback address.
*/
address_is_loopback :: (using address: IPAddress) -> bool {
    return (
        type == .IPv4
        && data.v4[0] == 127
    ) || (
        type == .IPv6
        && data.v6[0] == 0
        && data.v6[1] == 0
        && data.v6[2] == 0
        && data.v6[3] == 0
        && data.v6[4] == 0
        && data.v6[5] == 0
        && data.v6[6] == 0
        && data.v6[7] == 0x0001
    );
}

/*
Is this an IPv6 link local address?
Corresponds to the first field of the address being 0xfe80

@returns True if this address is a link local IPv6 address.
*/
address_is_link_local :: (using address: IPAddress) -> bool {
    assert(type == .IPv6);

    return type == .IPv6 && data.v6[0] == 0xfe80;
}

/*
Is this an IPv6 site local address?
Corresponds to the first field of the address being 0xfec0

@returns True if this address is a site local IPv6 address.
*/
address_is_site_local :: (using address: IPAddress) -> bool {
    assert(type == .IPv6);

    return type == .IPv6 && data.v6[0] == 0xfec0;
}

/*
Is this an IPv6 multicast address?
Corresponds to the first field of the IPv6 address being 0xff00

@returns True if this address is a multicast IPv6 address.
*/
address_is_multicast :: (using address: IPAddress) -> bool {
    assert(type == .IPv6);

    return type == .IPv6 && data.v6[0] == 0xff00;
}

/*
Is this in IPv6 global unicast address?
Corresponds to any IPv6 address that is not any of the following: Link Local, Site Local, Multicast or Loopback.

@returns True if this is a global unicast IPv6 address.
*/
address_is_global_unicast :: (using address: IPAddress) -> bool {
    assert(type == .IPv6);

    return type == .IPv6
        && !address_is_link_local(address)
        && !address_is_site_local(address)
        && !address_is_multicast(address)
        && !address_is_loopback(address);
}

/*
Check if two addresses are logically equivalent (same type, address and port).
*/
operator == :: (a: IPAddress, b: IPAddress) -> bool {
    if a.type != b.type return false;
    if a.port != b.port return false;
    if #complete a.type == {
        case .None;
            return true;
        case .IPv4;
            return array_equal(a.data.v4, b.data.v4);
        case .IPv6;
            return array_equal(a.data.v6, b.data.v6);
    }
}

// ----------------------------------------------------------------

// Anyone can call this to the run the tests.
address_test :: () {
    address_tests_running = true;
    defer address_tests_running = false;
    run_tests();
}

// ----------------------------------------------------------------

#scope_file

// When true, disables normal logging. We set this to true while running our test
// cases because we use the address parser in a way that is expected to fail.
address_tests_running := false;

// Last log message that would have been written. This can be used to assert that
// a particular error message would have been logged for a given failure case.
address_last_log_message: string;

#import "Basic";

array_equal :: (a: [$N] $T, b: [N] T) -> bool {
    return !memcmp(a.data, b.data, a.count);
}

pointer_diff :: (a: *$T, b: *$U) -> s64 #expand {
    return cast(s64)((cast(*u8) a) - (cast(*u8) b));
}

address_log :: (flags: Log_Flags, format_string: string, args: .. Any, loc := #caller_location) {
    if !ENABLE_LOGGING && !address_tests_running {
        // user doesn't want the logs
        return;
    }

    builder: String_Builder;

    append(*builder, "[IPAddress] ");
    print_to_builder(*builder, format_string, ..args);

    s := builder_to_string(*builder,, temp);
    if !s.count return;

    if address_tests_running {
        // record the message that would have been logged for the test assert
        address_last_log_message = s;
        // then silence it, because we generate a lot of errors on purpose during testing
        return;
    }

    info := Log_Info.{
        source_identifier = context.log_source_identifier,
        location          = loc,
        common_flags      = flags,
        user_flags        = 0,
        section           = null
    };
    context.logger(s, context.logger_data, info);
}

run_tests :: () {
    test_ip :: (type: IPType, s: string, port: int = -1, expected_address: IPAddress, expected_remainder: string = "", expected_log: string = "") {
        ip: IPAddress;
        remainder: string;

        address_last_log_message = .{};
        if #complete type == {
            case .None;
                assert(false, "You must select a valid IPType to test.");
            case .IPv4;
                if port >= 0 {
                    ip, remainder = address_init_v4(s, cast(u16) port);
                } else {
                    ip, remainder = address_init_v4(s);
                }
            case .IPv6;
                if port >= 0 {
                    ip, remainder = address_init_v6(s, cast(u16) port);
                } else {
                    ip, remainder = address_init_v6(s);
                }
        }

        PASS_MSG :: #string EOS
[SUCCESS] % "%"
EOS

        FAIL_MSG :: #string EOS
*** FAILURE ***

While trying to parse "%" as %.
┌──────────────────────────────────────┐
│ Expected                             │
└──────────────────────────────────────┘
%
"%"
"%"
┌──────────────────────────────────────┐
│ Actual                               │
└──────────────────────────────────────┘
%
"%"
"%"

EOS

        pass := ip == expected_address && remainder == expected_remainder && address_last_log_message == expected_log;
        if pass {
            #if ENABLE_LOGGING {
                log(PASS_MSG, type, s);
            }
        } else {
            log(FAIL_MSG, s, type,
                address_to_string(expected_address, canonical=true), expected_remainder, expected_log,
                address_to_string(ip, canonical=true), remainder, address_last_log_message
            );
        }
    }

    log("\n--- IPAddress ------------------------------------------------------------------\n");
    log("Running tests...\n");

    //--- ipv4 tests ----------------------------------------------------------

    // premature end-of-string in octet
    test_ip(.IPv4, "",       -1, .{}, "",       "[IPAddress] Premature end-of-string in octet 1 while parsing '' as an IPv4 address. Expected digit (0-9).\n");
    test_ip(.IPv4, "1.",     -1, .{}, "1.",     "[IPAddress] Premature end-of-string in octet 2 while parsing '1.' as an IPv4 address. Expected digit (0-9).\n");
    test_ip(.IPv4, "1.0.",   -1, .{}, "1.0.",   "[IPAddress] Premature end-of-string in octet 3 while parsing '1.0.' as an IPv4 address. Expected digit (0-9).\n");
    test_ip(.IPv4, "1.0.0.", -1, .{}, "1.0.0.", "[IPAddress] Premature end-of-string in octet 4 while parsing '1.0.0.' as an IPv4 address. Expected digit (0-9).\n");

    // unexpected character in octet
    test_ip(.IPv4, "?1.1.1.1", -1, .{}, "?1.1.1.1", "[IPAddress] Unexpected character '?' in octet 1 while parsing '?1.1.1.1' as an IPv4 address. Expected digit (0-9).\n");
    test_ip(.IPv4, "1?.1.1.1", -1, .{}, "1?.1.1.1", "[IPAddress] Unexpected character '?' after octet 1 ('1') while parsing '1?.1.1.1' as an IPv4 address. Expected dot (.) separator.\n");
    test_ip(.IPv4, "1.?1.1.1", -1, .{}, "1.?1.1.1", "[IPAddress] Unexpected character '?' in octet 2 while parsing '1.?1.1.1' as an IPv4 address. Expected digit (0-9).\n");
    test_ip(.IPv4, "1.1?.1.1", -1, .{}, "1.1?.1.1", "[IPAddress] Unexpected character '?' after octet 2 ('1') while parsing '1.1?.1.1' as an IPv4 address. Expected dot (.) separator.\n");
    test_ip(.IPv4, "1.1.?1.1", -1, .{}, "1.1.?1.1", "[IPAddress] Unexpected character '?' in octet 3 while parsing '1.1.?1.1' as an IPv4 address. Expected digit (0-9).\n");
    test_ip(.IPv4, "1.1.1?.1", -1, .{}, "1.1.1?.1", "[IPAddress] Unexpected character '?' after octet 3 ('1') while parsing '1.1.1?.1' as an IPv4 address. Expected dot (.) separator.\n");
    test_ip(.IPv4, "1.1.1.?1", -1, .{}, "1.1.1.?1", "[IPAddress] Unexpected character '?' in octet 4 while parsing '1.1.1.?1' as an IPv4 address. Expected digit (0-9).\n");

    // illegal leading zeros
    test_ip(.IPv4, "01",        -1, .{}, "01",        "[IPAddress] Illegal leading zero(s) in octet 1 ('01') while parsing '01' as an IPv4 address.\n");
    test_ip(.IPv4, "1.01",      -1, .{}, "1.01",      "[IPAddress] Illegal leading zero(s) in octet 2 ('01') while parsing '1.01' as an IPv4 address.\n");
    test_ip(.IPv4, "1.1.01",    -1, .{}, "1.1.01",    "[IPAddress] Illegal leading zero(s) in octet 3 ('01') while parsing '1.1.01' as an IPv4 address.\n");
    test_ip(.IPv4, "1.1.1.01",  -1, .{}, "1.1.1.01",  "[IPAddress] Illegal leading zero(s) in octet 4 ('01') while parsing '1.1.1.01' as an IPv4 address.\n");
    test_ip(.IPv4, "001",       -1, .{}, "001",       "[IPAddress] Illegal leading zero(s) in octet 1 ('001') while parsing '001' as an IPv4 address.\n");
    test_ip(.IPv4, "1.001",     -1, .{}, "1.001",     "[IPAddress] Illegal leading zero(s) in octet 2 ('001') while parsing '1.001' as an IPv4 address.\n");
    test_ip(.IPv4, "1.1.001",   -1, .{}, "1.1.001",   "[IPAddress] Illegal leading zero(s) in octet 3 ('001') while parsing '1.1.001' as an IPv4 address.\n");
    test_ip(.IPv4, "1.1.1.001", -1, .{}, "1.1.1.001", "[IPAddress] Illegal leading zero(s) in octet 4 ('001') while parsing '1.1.1.001' as an IPv4 address.\n");

    // out-of-range octet value
    test_ip(.IPv4, "256.0.0.0", -1, .{}, "256.0.0.0", "[IPAddress] Out-of-range value '256' in octet 1 ('256') while parsing '256.0.0.0' as an IPv4 address. Expected octet in range (0-255).\n");
    test_ip(.IPv4, "0.256.0.0", -1, .{}, "0.256.0.0", "[IPAddress] Out-of-range value '256' in octet 2 ('256') while parsing '0.256.0.0' as an IPv4 address. Expected octet in range (0-255).\n");
    test_ip(.IPv4, "0.0.256.0", -1, .{}, "0.0.256.0", "[IPAddress] Out-of-range value '256' in octet 3 ('256') while parsing '0.0.256.0' as an IPv4 address. Expected octet in range (0-255).\n");
    test_ip(.IPv4, "0.0.0.256", -1, .{}, "0.0.0.256", "[IPAddress] Out-of-range value '256' in octet 4 ('256') while parsing '0.0.0.256' as an IPv4 address. Expected octet in range (0-255).\n");

    // premature end-of-string instead of separator
    test_ip(.IPv4, "1",     -1, .{}, "1",     "[IPAddress] Premature end-of-string after octet 1 ('1') while parsing '1' as an IPv4 address. Expected dot (.) separator.\n");
    test_ip(.IPv4, "1.0",   -1, .{}, "1.0",   "[IPAddress] Premature end-of-string after octet 2 ('0') while parsing '1.0' as an IPv4 address. Expected dot (.) separator.\n");
    test_ip(.IPv4, "1.0.0", -1, .{}, "1.0.0", "[IPAddress] Premature end-of-string after octet 3 ('0') while parsing '1.0.0' as an IPv4 address. Expected dot (.) separator.\n");

    // unexpected character instead of separator
    test_ip(.IPv4, "1?0.0.1", -1, .{}, "1?0.0.1", "[IPAddress] Unexpected character '?' after octet 1 ('1') while parsing '1?0.0.1' as an IPv4 address. Expected dot (.) separator.\n");
    test_ip(.IPv4, "1.0?0.1", -1, .{}, "1.0?0.1", "[IPAddress] Unexpected character '?' after octet 2 ('0') while parsing '1.0?0.1' as an IPv4 address. Expected dot (.) separator.\n");
    test_ip(.IPv4, "1.0.0?1", -1, .{}, "1.0.0?1", "[IPAddress] Unexpected character '?' after octet 3 ('0') while parsing '1.0.0?1' as an IPv4 address. Expected dot (.) separator.\n");

    // port out of range warnings (valid in IPv4, because the parser allows "garbage" at the end of the string)
    // maybe we should add a "strict" mode that doesn't allow accept these inputs? meh.
    test_ip(.IPv4, "1.2.3.4:-1",    -1, .{ type = .IPv4, data.v4 = .[1, 2, 3, 4]}, ":-1",    "[IPAddress] Found what looked like a port ('-1') after the colon while parsing '1.2.3.4:-1' as an IPv4 address, but it was out of range. Port must be in range 0-65535, inclusive.\n");
    test_ip(.IPv4, "1.2.3.4:65536", -1, .{ type = .IPv4, data.v4 = .[1, 2, 3, 4]}, ":65536", "[IPAddress] Found what looked like a port ('65536') after the colon while parsing '1.2.3.4:65536' as an IPv4 address, but it was out of range. Port must be in range 0-65535, inclusive.\n");

    // valid addresses
    test_ip(.IPv4, "127.0.0.1",    -1, .{ type = .IPv4, data.v4 = .[127, 0, 0, 1] });
    test_ip(.IPv4, "127.0.0.1:0",  -1, .{ type = .IPv4, data.v4 = .[127, 0, 0, 1], port = 0 });
    test_ip(.IPv4, "127.0.0.1:80", -1, .{ type = .IPv4, data.v4 = .[127, 0, 0, 1], port = 80 });

    // valid addresses with explicit port overrides
    test_ip(.IPv4, "127.0.0.1",    80, .{ type = .IPv4, data.v4 = .[127, 0, 0, 1], port = 80 });
    test_ip(.IPv4, "127.0.0.1:22", 80, .{ type = .IPv4, data.v4 = .[127, 0, 0, 1], port = 80 });
    test_ip(.IPv4, "127.0.0.1:0",  80, .{ type = .IPv4, data.v4 = .[127, 0, 0, 1], port = 80 });
    test_ip(.IPv4, "127.0.0.1:80",  0, .{ type = .IPv4, data.v4 = .[127, 0, 0, 1], port = 0 });

    //--- ipv6 tests ----------------------------------------------------------

    // not enough characters
    test_ip(.IPv6, "",   -1, .{}, "",   "[IPAddress] Unable to parse '' as an IPv6 address. Not enough characters.\n");
    test_ip(.IPv6, "1",  -1, .{}, "1",  "[IPAddress] Unable to parse '1' as an IPv6 address. Not enough characters.\n");
    test_ip(.IPv6, ":",  -1, .{}, ":",  "[IPAddress] Unable to parse ':' as an IPv6 address. Not enough characters.\n");
    test_ip(.IPv6, "[",  -1, .{}, "[",  "[IPAddress] Unable to parse '[' as an IPv6 address. Not enough characters.\n");
    test_ip(.IPv6, "[:", -1, .{}, "[:", "[IPAddress] Unable to parse '[:' as an IPv6 address. Not enough characters.\n");

    // cannot start with colon unless double colon
    test_ip(.IPv6, ":1:2:3", -1, .{}, ":1:2:3", "[IPAddress] Unexpected character ':' in segment 1 while parsing ':1:2:3' as an IPv6 address. Addresses starting with a colon (:) must start with a double colon (::).\n");

    // premature end-of-string in segment
    test_ip(.IPv6, "1:", -1, .{}, "1:", "[IPAddress] Premature end-of-string in segment 2 while parsing '1:' as an IPv6 address. Expected hex digit (0-F).\n");

    // unexpected character in segment
    test_ip(.IPv6, "1:?", -1, .{}, "1:?", "[IPAddress] Unexpected character '?' in segment 2 while parsing '1:?' as an IPv6 address. Expected hex digit (0-F).\n");

    // premature end-of-string instead of separator
    test_ip(.IPv6, "1:2", -1, .{}, "1:2", "[IPAddress] Premature end-of-string after segment 2 ('2') while parsing '1:2' as an IPv6 address. Expected colon (:) separator.\n");

    // unexpected character instead of separator
    test_ip(.IPv6, "1:2?", -1, .{}, "1:2?", "[IPAddress] Unexpected character '?' after segment 2 ('2') while parsing '1:2?' as an IPv6 address. Expected colon (:) separator.\n");

    // bad bracketed addresses
    test_ip(.IPv6, "[::",        -1, .{}, "[::",        "[IPAddress] Premature end-of-string in bracketed unspecified address while parsing '[::' as an IPv6 address. Expected closing square bracket (]) followed by a port number.\n");
    test_ip(.IPv6, "[::]",       -1, .{}, "[::]",       "[IPAddress] Premature end-of-string while parsing '[::]' as a bracketed IPv6 address. Expected colon (:), then port number.\n");
    test_ip(.IPv6, "[::]:",      -1, .{}, "[::]:",      "[IPAddress] Premature end-of-string while parsing '[::]:' as a bracketed IPv6 address. Expected a port number after the colon (:).\n");
    test_ip(.IPv6, "[::]:?",     -1, .{}, "[::]:?",     "[IPAddress] Unexpected character '?' while parsing '[::]:?' as a bracketed IPv6 address. Expected a port number after the colon (:).\n");

    // port out of range (invalid in IPv6, because bracketed addresses *must* have a valid port)
    test_ip(.IPv6, "[::]:-1",    -1, .{}, "[::]:-1",    "[IPAddress] Found what looked like a port ('-1') after the colon while parsing '[::]:-1' as a bracketed IPv6 address, but it was out of range. Port must be in range 0-65535, inclusive.\n");
    test_ip(.IPv6, "[::]:65536", -1, .{}, "[::]:65536", "[IPAddress] Found what looked like a port ('65536') after the colon while parsing '[::]:65536' as a bracketed IPv6 address, but it was out of range. Port must be in range 0-65535, inclusive.\n");

    // sanity check failures (these *could* be parsed successfully, but in the interest of sanity, we don't allow them)
    test_ip(.IPv6, "0:1:2::4:?",   -1, .{}, "0:1:2::4:?",   "[IPAddress] Sanity check failure while parsing '0:1:2::4:?' as an IPv6 address. We don't allow the remainder string to start with a colon (:) in unbracketed IPv6 addresses, because it's extremely likely to be an error in practice.\n");
    test_ip(.IPv6, "0:1:2::4444F", -1, .{}, "0:1:2::4444F", "[IPAddress] Sanity check failure while parsing '0:1:2::4444F' as an IPv6 address. We don't allow the remainder string to start with a hex character ('F') in unbracketed IPv6 addresses, because it's extremely likely to be an error in practice.\n");

    // valid addresses
    test_ip(.IPv6, "::",              -1, .{ type = .IPv6 });
    test_ip(.IPv6, "::1:2:3:4",       -1, .{ type = .IPv6, data.v6 = .[0, 0, 0, 0, 1, 2, 3, 4] });
    test_ip(.IPv6, "0:1:2:3:4:5:6:7", -1, .{ type = .IPv6, data.v6 = .[0, 1, 2, 3, 4, 5, 6, 7] });
    test_ip(.IPv6, "0:1:2:3:4:5:6::", -1, .{ type = .IPv6, data.v6 = .[0, 1, 2, 3, 4, 5, 6, 0] });
    test_ip(.IPv6, "0:1:2::?",        -1, .{ type = .IPv6, data.v6 = .[0, 1, 2, 0, 0, 0, 0, 0] }, "?");
    test_ip(.IPv6, "0:1:2::4?",       -1, .{ type = .IPv6, data.v6 = .[0, 1, 2, 0, 0, 0, 0, 4] }, "?");
    test_ip(.IPv6, "0:1:2::4:5?",     -1, .{ type = .IPv6, data.v6 = .[0, 1, 2, 0, 0, 0, 4, 5] }, "?");

    // valid bracketed addresses (with mandatory port number)
    test_ip(.IPv6, "[::]:80",              -1, .{ type = .IPv6, port = 80 });
    test_ip(.IPv6, "[::1:2:3:4]:80",       -1, .{ type = .IPv6, data.v6 = .[0, 0, 0, 0, 1, 2, 3, 4], port = 80 });
    test_ip(.IPv6, "[0:1:2:3:4:5:6:7]:80", -1, .{ type = .IPv6, data.v6 = .[0, 1, 2, 3, 4, 5, 6, 7], port = 80 });
    test_ip(.IPv6, "[0:1:2:3:4:5:6::]:80", -1, .{ type = .IPv6, data.v6 = .[0, 1, 2, 3, 4, 5, 6, 0], port = 80 });
    test_ip(.IPv6, "[0:1:2::]:80?",        -1, .{ type = .IPv6, data.v6 = .[0, 1, 2, 0, 0, 0, 0, 0], port = 80 }, "?");
    test_ip(.IPv6, "[0:1:2::4]:80?",       -1, .{ type = .IPv6, data.v6 = .[0, 1, 2, 0, 0, 0, 0, 4], port = 80 }, "?");
    test_ip(.IPv6, "[0:1:2::4:5]:80?",     -1, .{ type = .IPv6, data.v6 = .[0, 1, 2, 0, 0, 0, 4, 5], port = 80 }, "?");

    // valid addresses with explicit port overrides
    test_ip(.IPv6, "::",              80, .{ type = .IPv6, port = 80 });
    test_ip(.IPv6, "::1:2:3:4",       80, .{ type = .IPv6, data.v6 = .[0, 0, 0, 0, 1, 2, 3, 4], port = 80 });
    test_ip(.IPv6, "::1:2:3:4",       0,  .{ type = .IPv6, data.v6 = .[0, 0, 0, 0, 1, 2, 3, 4], port = 0 });
    test_ip(.IPv6, "::1:2:3:4?",      80, .{ type = .IPv6, data.v6 = .[0, 0, 0, 0, 1, 2, 3, 4], port = 80 }, "?");

    // valid bracketed addresses (with mandatory port number), and explicit port overrides
    test_ip(.IPv6, "[::]:22",         80, .{ type = .IPv6, port = 80 });
    test_ip(.IPv6, "[::1:2:3:4]:22",  80, .{ type = .IPv6, data.v6 = .[0, 0, 0, 0, 1, 2, 3, 4], port = 80 });
    test_ip(.IPv6, "[::1:2:3:4]:0",   80, .{ type = .IPv6, data.v6 = .[0, 0, 0, 0, 1, 2, 3, 4], port = 80 });
    test_ip(.IPv6, "[::1:2:3:4]:80?", 0,  .{ type = .IPv6, data.v6 = .[0, 0, 0, 0, 1, 2, 3, 4], port = 0 }, "?");

    log("Passed!\n");
}
