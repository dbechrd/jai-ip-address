![image](https://github.com/user-attachments/assets/5b3a6b41-470f-4b40-ad5d-8f31d9378ec0)

A standalone IP address module, for parsing, comparing and converting IP addresses to and from strings.

This module was originally a native Jai port of the Address class in Glenn Fielder's yojimbo library, as of this commit:
https://github.com/mas-bandwidth/yojimbo/blob/c6c02dfec105b36b9cbefd82f86f11f894f6de51/source/yojimbo_address.cpp

It has been completely rewritten from scratch, with many features added, including significant error handling improvements.

Example usage:
```
address_v4 := address_init_v4("127.0.0.1:80");
print("%\n%\n", address_v4, address_to_string(address_v4));

address_v6 := address_init_v6("[::1]:80");
print("%\n%\n", address_v6, address_to_string(address_v6));
```

See the source code for more details!
