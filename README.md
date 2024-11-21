# Sniff Spoof

Sniff Spoof is a C-based project designed for network analysis and manipulation, an example for MITM attack. The project includes functionalities to:
- Sniff network traffic on a specified interface.
- Filter packets based on specific criteria, such as protocol type.
- Spoof ICMP packets to simulate network behavior.

## Features
1. **Packet Sniffing**:
   - Uses the `pcap` library to capture network packets.
   - Filters packets to focus on specific protocols (e.g. ICMP).
   - Logs packet details into a text file for further analysis.

2. **ICMP Packet Spoofing**:
   - Constructs and sends custom ICMP packets.
   - Simulates ICMP echo requests (ping) with fake source addresses.
   - Sends responses to real network members.

3. **Integration**:
   - Combines sniffing and spoofing functionalities to analyze and manipulate network behavior in real-time.

## Usage
### Prerequisites
- GCC or any C compiler.
- `pcap` library installed on your system.
- Root privileges to run the program (required for packet sniffing).

### Setup
1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/sniff-spoof.git
   ```
2. Navigate to the project directory:
   ```bash
   cd sniff-spoof
   ```
3. Compile the code:
   ```bash
   gcc -o sniff-spoof Spoofer_Sniffer.c -lpcap
   ```

### Run
- Start the attack:
   ```bash
   sudo ./sniff-spoof
   ```

### Example Outputs
- Sniffed packets are logged in a text file, showing:
  - Source and destination addresses.
  - Protocol types and additional metadata.

- Spoofed ICMP requests and responses visible in Wireshark or other packet analysis tools.

## File Structure
- `Sniffer.c`: Handles packet sniffing using the `pcap` library.
- `Spoofer.c`: Contains logic for constructing and sending spoofed packets.
- `Spoofer_Sniffer.c`: Integrates sniffing and spoofing functionalities together, and implementin MITM.

## References
- [pcap Documentation](https://www.tcpdump.org/pcap.html)
- [Raw Sockets Guide](https://linux.die.net/man/3/socket)
- [ICMP Protocol Overview](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes. Ensure that your code adheres to the existing style and includes appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

This project was developed as part of an academic assignment to practice advanced Python, Cyber and Network programming concepts.

## Author

**Halel Itzhaki**

For any questions or suggestions, please feel free to contact me.
