# NTP

A simple NTP client implementation in Go that can query time from NTP servers.

This implementation includes:

1. A complete NTP client that follows RFC 5905 protocol specifications
2. Proper handling of NTP packet structure and binary encoding
3. Error handling and timeout settings
4. Support for multiple NTP servers
5. Conversion between NTP and Unix timestamps

Key features:

* Uses UDP for communication on port 123
* Implements NTP version 4
* Handles both seconds and fractional parts of timestamps
* Includes proper error handling and timeouts
* Supports multiple NTP servers for redundancy